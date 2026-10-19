use super::{
    ConnectionGuard, PostgresControlStore,
    admin_broker_session::{LocalAdminProof, observe_local_session},
    admin_upstream_session::observe_upstream_roles,
    bounded_deadline, insert_admin_session, load_admin_session, storage_error, timeout_error,
};
use crate::{
    AdminCookieLogout, AdminCookieLogoutDisposition, AdminCookieReadSession,
    AdminCookieSessionError as Error, AdminCookieSessionLimits, AdminCookieSessionPolicy,
    AdminSession, ControlError, FlowPurpose, IssuedAdminCookie, LocalAuthPolicy, NewAdminSession,
    PreparedAdminLogin, SessionClaimRoles, SessionPrincipal, SessionProfile, SystemAction,
    SystemPermission, UpstreamBearerVerifier, VerifiedUpstreamLogin,
    admin_cookie_session::{CookieClock, CookieWindow, decode_secret, new_secret},
    flow::now_micros,
};
use broker_security::{LocalAuthBinding, TokenKind};
use broker_store::time::TimestampMicros;
use sqlx_core::connection::Connection;
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

struct CookieData {
    profile: SessionProfile,
    principal: SessionPrincipal,
    roles: Vec<String>,
    permissions: Vec<SystemPermission>,
}
enum CookieIdentity {
    Local(CookieData),
    Federated { data: CookieData, claims: bool },
}
pub(super) struct CookieObservation {
    pub(super) proof: CookieReadProof,
    pub(super) csrf: Zeroizing<String>,
    pub(super) window: CookieWindow,
}
// Closed identity variants stay private to trusted crate-internal SQL observers.
pub(crate) struct CookieReadProof(CookieIdentity);
impl CookieReadProof {
    pub(crate) fn local(
        profile: SessionProfile,
        principal: SessionPrincipal,
        roles: Vec<String>,
        permissions: Vec<SystemPermission>,
    ) -> Self {
        Self(CookieIdentity::Local(CookieData {
            profile,
            principal,
            roles,
            permissions,
        }))
    }
    pub(crate) fn federated(
        profile: SessionProfile,
        principal: SessionPrincipal,
        roles: Vec<String>,
        permissions: Vec<SystemPermission>,
        claims: bool,
    ) -> Self {
        Self(CookieIdentity::Federated {
            data: CookieData {
                profile,
                principal,
                roles,
                permissions,
            },
            claims,
        })
    }
    fn data(&self) -> &CookieData {
        match &self.0 {
            CookieIdentity::Local(data) | CookieIdentity::Federated { data, .. } => data,
        }
    }
    pub(crate) fn profile(&self) -> &SessionProfile {
        &self.data().profile
    }
    pub(crate) fn principal(&self) -> &SessionPrincipal {
        &self.data().principal
    }
    pub(crate) fn roles(&self) -> &[String] {
        &self.data().roles
    }
    pub(crate) fn permissions(&self) -> &[SystemPermission] {
        &self.data().permissions
    }
    pub(crate) fn role_source(&self) -> &'static str {
        match self.0 {
            CookieIdentity::Federated { claims: true, .. } => "claims",
            _ => "database",
        }
    }
}
pub struct PostgresAdminCookieSessions<'s, 'v> {
    store: &'s PostgresControlStore,
    upstream: Option<&'v UpstreamBearerVerifier>,
    limits: AdminCookieSessionLimits,
    policy: AdminCookieSessionPolicy,
}
impl fmt::Debug for PostgresAdminCookieSessions<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresAdminCookieSessions([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn admin_cookie_sessions<'s, 'v>(
        &'s self,
        limits: AdminCookieSessionLimits,
        policy: AdminCookieSessionPolicy,
        upstream: Option<&'v UpstreamBearerVerifier>,
    ) -> Result<PostgresAdminCookieSessions<'s, 'v>, ControlError> {
        limits.validate()?;
        policy.validate()?;
        if limits.metadata.max_lifetime < policy.session_ttl {
            return Err(ControlError::Configuration);
        }
        Ok(PostgresAdminCookieSessions {
            store: self,
            upstream,
            limits,
            policy,
        })
    }
}
fn gate(end: Instant, window: &CookieWindow) -> Result<(), Error> {
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    window.check()?;
    Ok(())
}
fn absolute(micros: i64) -> Result<SystemTime, ControlError> {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_micros(
            u64::try_from(micros).map_err(|_| ControlError::Clock)?,
        ))
        .ok_or(ControlError::Clock)
}
fn cookie_metadata(session: &AdminSession) -> Result<(), Error> {
    if session.principal().issuer == "local" && session.claimed_roles().is_some() {
        return Err(Error::Unauthorized);
    }
    if session.principal().issuer != "local" && session.principal().local_user_revision != 0 {
        return Err(ControlError::CorruptSession.into());
    }
    decode_secret(session.csrf_token()).map_err(|_| ControlError::CorruptSession)?;
    Ok(())
}
fn cookie_observer_error(error: Error) -> crate::AdminBrokerSessionError {
    match error {
        Error::Control(error) => crate::AdminBrokerSessionError::Control(error),
        Error::Forbidden => crate::AdminBrokerSessionError::Forbidden,
        _ => crate::BrokerAccessError::InvalidToken.into(),
    }
}
pub(crate) fn validate_federated(
    profile: &SessionProfile,
    principal: &SessionPrincipal,
    claims: Option<&SessionClaimRoles>,
    limits: crate::AdminBrokerSessionLimits,
) -> Result<(), Error> {
    let l = limits.identity;
    if profile.subject.len() > l.subject_bytes.get()
        || principal.username.len() > l.username_bytes.get()
        || claims.is_some_and(|c| {
            c.roles.len() > l.roles.get()
                || c.roles
                    .iter()
                    .any(|r| !crate::identity::safe_identity_segment(r, l.role_bytes.get()))
        })
    {
        return Err(Error::Unauthorized);
    }
    let bytes = serde_json::to_vec(&serde_json::json!({
        "subject":profile.subject,"issuer":principal.issuer,"username":principal.username,
        "name":profile.name,"email":profile.email,"organization":principal.organization,"teams":principal.teams
    })).map_err(|_| ControlError::CorruptIdentity)?;
    if bytes.len() > limits.profile_json_bytes.get() {
        return Err(ControlError::IdentityLimitExceeded.into());
    }
    Ok(())
}
async fn delete(
    connection: &mut sqlx_postgres::PgConnection,
    hash: &str,
) -> Result<(), ControlError> {
    if sqlx_core::query::query("DELETE FROM public.admin_sessions WHERE token_hash=$1")
        .bind(hash)
        .execute(connection)
        .await
        .map_err(storage_error)?
        .rows_affected()
        != 1
    {
        return Err(ControlError::Storage);
    }
    Ok(())
}
impl PostgresAdminCookieSessions<'_, '_> {
    pub(super) fn hash(&self, raw: &str) -> Result<String, Error> {
        decode_secret(raw).map_err(|_| Error::MalformedCookie)?;
        self.store
            .digester
            .token(TokenKind::AdminSession, raw.as_bytes())
            .map(|v| v.to_sql_hex())
            .map_err(|_| Error::Unauthorized)
    }
    fn upstream_gate(
        &self,
        proof: &VerifiedUpstreamLogin,
        end: Instant,
        window: &CookieWindow,
    ) -> Result<(), Error> {
        gate(end, window)?;
        let verifier = self.upstream.ok_or(Error::Unauthorized)?;
        if proof.purpose() != FlowPurpose::Admin {
            return Err(Error::Unauthorized);
        }
        proof.check(verifier).map_err(|error| match error {
            ControlError::InvalidFlow => Error::Unauthorized,
            other => Error::Control(other),
        })
    }
    pub async fn issue_upstream(
        &self,
        proof: VerifiedUpstreamLogin,
        original: Instant,
    ) -> Result<IssuedAdminCookie, Error> {
        let original = original.min(proof.original());
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let clock = CookieClock::capture();
        let expiry = TimestampMicros::try_from(
            clock
                .utc()
                .checked_add(self.policy.session_ttl)
                .ok_or(ControlError::Clock)?,
        )
        .map_err(|_| ControlError::Clock)?
        .as_i64();
        let window = clock.window(absolute(expiry)?)?;
        self.upstream_gate(&proof, end, &window)?;
        let raw = new_secret()?;
        let hash = self.hash(&raw)?;
        let profile = SessionProfile {
            subject: proof.profile().subject.clone(),
            name: proof.profile().name.clone(),
            email: proof.profile().email.clone(),
        };
        let principal = SessionPrincipal {
            issuer: proof.issuer().to_owned(),
            username: proof.username().to_owned(),
            organization: proof.organization().to_owned(),
            teams: proof.teams().to_vec(),
            local_user_revision: 0,
        };
        let claims = match (proof.role_selector(), proof.claim_roles()) {
            (Some(selector), Some(roles)) => Some(SessionClaimRoles {
                selector: selector.to_owned(),
                roles: roles.to_vec(),
            }),
            (None, None) => None,
            _ => return Err(Error::Unauthorized),
        };
        let session = NewAdminSession::new(
            profile,
            principal,
            new_secret()?,
            claims,
            absolute(expiry)?,
            &self.limits.metadata,
        )?;
        validate_federated(
            session.profile(),
            session.principal(),
            session.claimed_roles(),
            self.limits.authorization,
        )?;
        let json = session.validate(&self.limits.metadata)?;
        let subject = format!(
            "{}|{}",
            session.principal().issuer,
            session.profile().subject
        );
        let commit_started = AtomicBool::new(false);
        let wait = end.min(window.expiry().1).min(proof.expires_mono());
        let outcome = tokio::time::timeout_at(wait.into(), async {
            self.upstream_gate(&proof, end, &window)?;
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            observe_upstream_roles(
                &mut tx,
                &subject,
                session.claimed_roles().map(|c| c.roles.as_slice()),
                self.limits.authorization,
                SystemAction::SessionRead,
                || {
                    self.upstream_gate(&proof, end, &window)
                        .map_err(cookie_observer_error)
                },
            )
            .await?;
            self.upstream_gate(&proof, end, &window)?;
            let created = now_micros()?;
            if expiry <= created || expiry - created > self.limits.metadata.lifetime_micros()? {
                return Err(ControlError::InvalidSession.into());
            }
            insert_admin_session(&mut tx, &hash, &session, json, expiry, created).await?;
            self.upstream_gate(&proof, end, &window)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok::<_, Error>(())
        })
        .await
        .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
        if matches!(outcome, Err(Error::Control(ControlError::OutcomeUncertain))) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        self.upstream_gate(&proof, end, &window)?;
        outcome?;
        let result = IssuedAdminCookie {
            raw,
            window,
            original,
        };
        result.check()?;
        Ok(result)
    }
    pub async fn issue_local(
        &self,
        prepared: PreparedAdminLogin,
        policy: &LocalAuthPolicy,
        original: Instant,
    ) -> Result<IssuedAdminCookie, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let clock = CookieClock::capture();
        let login = prepared.login;
        login
            .verify_binding(&self.store.digester, LocalAuthBinding::AdminLogin)
            .map_err(|_| Error::Unauthorized)?;
        if login.observed_at().as_i64()
            > TimestampMicros::try_from(clock.utc())
                .map_err(|_| ControlError::Clock)?
                .as_i64()
            || (policy.required && !login.factor_verified)
        {
            return Err(Error::Unauthorized);
        }
        let expiry = clock
            .utc()
            .checked_add(self.policy.session_ttl)
            .ok_or(ControlError::Clock)?;
        let expiry = TimestampMicros::try_from(expiry)
            .map_err(|_| ControlError::Clock)?
            .as_i64();
        let window = clock.window(absolute(expiry)?)?;
        let raw = new_secret()?;
        let csrf = new_secret()?;
        let hash = self.hash(&raw)?;
        let commit_started = AtomicBool::new(false);
        let outcome = tokio::time::timeout_at(end.min(window.expiry().1).into(), async {
            gate(end, &window)?;
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            // Match the LOCAL password-change order: user before session parent.
            sqlx_core::query::query(
                "SELECT subject FROM public.local_users WHERE subject=$1 FOR SHARE",
            )
            .bind(login.subject())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage_error)?;
            let (profile, principal, _, _) = observe_local_session(
                &mut tx,
                self.store,
                &LocalAdminProof::Login(&login, &window),
                self.limits.authorization,
                SystemAction::SessionRead,
                end,
            )
            .await?;
            let session = NewAdminSession::new(
                profile,
                principal,
                csrf,
                None,
                absolute(expiry)?,
                &self.limits.metadata,
            )?;
            let json = session.validate(&self.limits.metadata)?;
            let created = now_micros()?;
            if expiry <= created || expiry - created > self.limits.metadata.lifetime_micros()? {
                return Err(ControlError::InvalidSession.into());
            }
            insert_admin_session(&mut tx, &hash, &session, json, expiry, created).await?;
            gate(end, &window)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok::<_, Error>(())
        })
        .await
        .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
        if matches!(outcome, Err(Error::Control(ControlError::OutcomeUncertain))) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        gate(end, &window)?;
        outcome?;
        let result = IssuedAdminCookie {
            raw,
            window,
            original,
        };
        result.check()?;
        Ok(result)
    }
    pub async fn read(
        &self,
        raw: &str,
        original: Instant,
    ) -> Result<AdminCookieReadSession, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let clock = CookieClock::capture();
        let hash = self.hash(raw)?;
        let commit_started = AtomicBool::new(false);
        let outcome = tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            // This is only a bounded locator/lock, never authentication. Recheck after parent lock.
            let observation = self
                .observe_cookie(&mut tx, &hash, &clock, SystemAction::SessionRead, end)
                .await;
            if matches!(
                observation,
                Err(Error::Control(ControlError::SessionExpired))
            ) {
                delete(&mut tx, &hash).await?;
                if Instant::now() >= end {
                    return Err(ControlError::Deadline.into());
                }
                commit_started.store(true, Ordering::Relaxed);
                tx.commit()
                    .await
                    .map_err(|_| ControlError::OutcomeUncertain)?;
                guard.confirmed();
                return Err(ControlError::SessionExpired.into());
            }
            let observation = observation?;
            let wait_end = end.min(observation.window.expiry().1);
            let committed = tokio::time::timeout_at(wait_end.into(), async {
                gate(end, &observation.window)?;
                commit_started.store(true, Ordering::Relaxed);
                tx.commit()
                    .await
                    .map_err(|_| ControlError::OutcomeUncertain)?;
                Ok::<_, Error>(())
            })
            .await
            .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
            if committed.is_ok() {
                guard.confirmed();
            }
            if matches!(
                committed,
                Err(Error::Control(ControlError::OutcomeUncertain))
            ) {
                return Err(ControlError::OutcomeUncertain.into());
            }
            gate(end, &observation.window)?;
            committed?;
            Ok(AdminCookieReadSession {
                proof: observation.proof,
                csrf: observation.csrf,
                window: observation.window,
                original,
            })
        })
        .await
        .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
        if matches!(outcome, Err(Error::Control(ControlError::OutcomeUncertain))) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        let result = outcome?;
        result.check()?;
        Ok(result)
    }
    // Authentication/current action are observed on the caller's transaction,
    // before its projection. This sealed value is not a reusable action lease.
    pub(super) async fn observe_cookie(
        &self,
        connection: &mut sqlx_postgres::PgConnection,
        hash: &str,
        clock: &CookieClock,
        action: SystemAction,
        end: Instant,
    ) -> Result<CookieObservation, Error> {
        let locked_subject=sqlx_core::query_scalar::query_scalar::<_,Option<String>>(
            "SELECT CASE WHEN octet_length(u.subject)::bigint<=$2 THEN u.subject END FROM public.local_users u JOIN public.admin_sessions s ON s.subject=u.subject JOIN public.admin_session_principals p ON p.token_hash=s.token_hash WHERE s.token_hash=$1 AND p.issuer='local' FOR SHARE OF u")
            .bind(hash).bind(self.limits.authorization.identity.subject_bytes.get() as i64)
            .fetch_optional(&mut *connection).await.map_err(storage_error)?.flatten();
        let session = load_admin_session(connection, hash, &self.limits.metadata)
            .await?
            .ok_or(Error::Unauthorized)?;
        cookie_metadata(&session)?;
        let window = clock.window(absolute(session.expires_at().as_i64())?)?;
        if window.check().is_err() {
            return Err(ControlError::SessionExpired.into());
        }
        let local = session.principal().issuer == "local";
        if local && locked_subject.as_deref() != Some(session.profile().subject.as_str()) {
            return Err(Error::Unauthorized);
        }
        let selected_roles = if local {
            None
        } else {
            match self
                .upstream
                .and_then(|v| v.cookie_role_selector(&session.principal().issuer))
                .ok_or(Error::Unauthorized)?
            {
                None => None,
                Some(selector) => Some(
                    session
                        .claimed_roles()
                        .filter(|c| c.selector == selector)
                        .ok_or(Error::Unauthorized)?
                        .roles
                        .as_slice(),
                ),
            }
        };
        if !local {
            validate_federated(
                session.profile(),
                session.principal(),
                if selected_roles.is_some() {
                    session.claimed_roles()
                } else {
                    None
                },
                self.limits.authorization,
            )?;
        }
        let wait = end.min(window.expiry().1);
        let outcome = tokio::time::timeout_at(wait.into(), async {
            if local {
                let (profile, principal, roles, permissions) = observe_local_session(
                    connection,
                    self.store,
                    &LocalAdminProof::Cookie(&session, &window),
                    self.limits.authorization,
                    action,
                    end,
                )
                .await?;
                Ok::<_, Error>(CookieReadProof::local(
                    profile,
                    principal,
                    roles,
                    permissions,
                ))
            } else {
                let subject = format!(
                    "{}|{}",
                    session.principal().issuer,
                    session.profile().subject
                );
                let (roles, permissions) = observe_upstream_roles(
                    connection,
                    &subject,
                    selected_roles,
                    self.limits.authorization,
                    action,
                    || gate(end, &window).map_err(cookie_observer_error),
                )
                .await?;
                let profile = SessionProfile {
                    subject: session.profile().subject.clone(),
                    name: session.profile().name.clone(),
                    email: session.profile().email.clone(),
                };
                let p = session.principal();
                let principal = SessionPrincipal {
                    issuer: p.issuer.clone(),
                    username: p.username.clone(),
                    organization: p.organization.clone(),
                    teams: p.teams.clone(),
                    local_user_revision: 0,
                };
                Ok(CookieReadProof::federated(
                    profile,
                    principal,
                    roles,
                    permissions,
                    selected_roles.is_some(),
                ))
            }
        })
        .await
        .unwrap_or_else(|_| Err(ControlError::Deadline.into()));
        gate(end, &window)?;
        Ok(CookieObservation {
            proof: outcome?,
            csrf: Zeroizing::new(session.csrf_token().to_owned()),
            window,
        })
    }
    pub(super) async fn read_admin<'a>(
        &self,
        raw: &str,
        request: crate::AdminReadRequest<'_>,
        limits: crate::AdminReadLimits,
        original: Instant,
    ) -> Result<crate::AdminReadResult<'a>, crate::AdminReadError> {
        use crate::{
            AdminReadError as ReadError,
            admin_read::{ReadWitness, cookie_authorization},
        };
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let clock = CookieClock::capture();
        let hash = self.hash(raw).map_err(cookie_authorization)?;
        let commit_started = AtomicBool::new(false);
        let outcome = tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            // Cookie reads lock the current LOCAL user and parent; READ ONLY
            // would be incompatible with those locks and expiry cleanup.
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            let observation = self
                .observe_cookie(&mut tx, &hash, &clock, request.kind().action(), end)
                .await;
            if matches!(
                observation,
                Err(Error::Control(ControlError::SessionExpired))
            ) {
                delete(&mut tx, &hash).await?;
                if Instant::now() >= end {
                    return Err(ControlError::Deadline.into());
                }
                commit_started.store(true, Ordering::Relaxed);
                tx.commit()
                    .await
                    .map_err(|_| ControlError::OutcomeUncertain)?;
                guard.confirmed();
                return Err(ReadError::Authorization(cookie_authorization(
                    Error::Control(ControlError::SessionExpired),
                )));
            }
            let observation = observation.map_err(cookie_authorization)?;
            let wait = end.min(observation.window.expiry().1);
            let result = tokio::time::timeout_at(wait.into(), async {
                let payload = super::admin_read::projection(
                    &mut tx,
                    &request,
                    limits,
                    observation.proof.profile(),
                    observation.proof.principal(),
                    wait,
                )
                .await?;
                gate(end, &observation.window).map_err(cookie_authorization)?;
                commit_started.store(true, Ordering::Relaxed);
                tx.commit()
                    .await
                    .map_err(|_| ControlError::OutcomeUncertain)?;
                Ok::<_, ReadError>(payload)
            })
            .await
            .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
            if result.is_ok() {
                guard.confirmed();
            }
            if matches!(
                result,
                Err(ReadError::Authorization(
                    crate::AdminBrokerSessionError::Control(ControlError::OutcomeUncertain)
                ))
            ) {
                return Err(ControlError::OutcomeUncertain.into());
            }
            gate(end, &observation.window).map_err(cookie_authorization)?;
            let payload = result?;
            let result = crate::AdminReadResult {
                witness: ReadWitness::Cookie {
                    _proof: observation.proof,
                    window: observation.window,
                },
                original: end,
                body: payload.body,
                revision: payload.revision,
            };
            result.check()?;
            Ok(result)
        })
        .await
        .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
        if matches!(
            outcome,
            Err(ReadError::Authorization(
                crate::AdminBrokerSessionError::Control(ControlError::OutcomeUncertain)
            ))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        outcome
    }
    pub async fn logout(
        &self,
        raw: &str,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminCookieLogout, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let clock = CookieClock::capture();
        let hash = self.hash(raw)?;
        let commit_started = AtomicBool::new(false);
        let outcome = tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            let session = load_admin_session(&mut tx, &hash, &self.limits.metadata).await?;
            let disposition = match session {
                None => AdminCookieLogoutDisposition::Absent,
                Some(session) => {
                    cookie_metadata(&session)?;
                    let window = clock.window(absolute(session.expires_at().as_i64())?)?;
                    let expired = window.check().is_err();
                    if !expired {
                        let stored = decode_secret(session.csrf_token())
                            .map_err(|_| ControlError::CorruptSession)?;
                        let supplied = decode_secret(csrf.ok_or(Error::CsrfFailed)?)
                            .map_err(|_| Error::CsrfFailed)?;
                        if !bool::from(stored.as_ref().ct_eq(supplied.as_ref())) {
                            return Err(Error::CsrfFailed);
                        }
                    }
                    delete(&mut tx, &hash).await?;
                    if expired {
                        AdminCookieLogoutDisposition::Expired
                    } else {
                        AdminCookieLogoutDisposition::Revoked
                    }
                }
            };
            if Instant::now() >= end {
                return Err(ControlError::Deadline.into());
            }
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok::<_, Error>(AdminCookieLogout {
                original,
                disposition,
            })
        })
        .await
        .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
        if matches!(outcome, Err(Error::Control(ControlError::OutcomeUncertain))) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        let result = outcome?;
        result.check()?;
        Ok(result)
    }
}
