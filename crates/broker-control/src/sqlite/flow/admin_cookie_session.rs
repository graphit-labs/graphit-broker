use super::{
    SqliteControlStore,
    admin_local_observer::{self, LocalProof},
    session,
};
use crate::{
    AdminCookieLogout, AdminCookieLogoutDisposition, AdminCookieReadSession,
    AdminCookieSessionError as Error, AdminCookieSessionLimits, AdminCookieSessionPolicy,
    AdminSession, ControlError, FlowPurpose, IssuedAdminCookie, LocalAuthPolicy, NewAdminSession,
    PreparedAdminLogin, SessionClaimRoles, SessionPrincipal, SessionProfile, SystemAction,
    UpstreamBearerVerifier, VerifiedUpstreamLogin,
    admin_cookie_session::{CookieClock, CookieWindow, decode_secret, new_secret},
    flow::now_micros,
    service::CookieReadProof,
    sqlite::executor::Work,
};
use broker_security::{LocalAuthBinding, TokenKind};
use broker_store::time::TimestampMicros;
use rusqlite::Transaction;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// A borrowed LOCAL cookie producer, bound to the genuine private store.
/// It provides no upstream issuance or authenticated federated read.
/// ~~~compile_fail
/// use broker_control::{SqliteControlStore, SqliteLocalAdminCookieSessions, AdminCookieSessionLimits, AdminCookieSessionPolicy};
/// fn escape(s: SqliteControlStore, l: AdminCookieSessionLimits, p: AdminCookieSessionPolicy) -> SqliteLocalAdminCookieSessions<'static> {
///     s.local_admin_cookie_sessions(l, p).unwrap()
/// }
/// ~~~
/// ~~~compile_fail
/// fn require<T: Clone>() {} require::<broker_control::SqliteLocalAdminCookieSessions<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require<T: Default>() {} require::<broker_control::SqliteLocalAdminCookieSessions<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require<T: serde::de::DeserializeOwned>() {} require::<broker_control::SqliteLocalAdminCookieSessions<'static>>();
/// ~~~
pub struct SqliteLocalAdminCookieSessions<'s> {
    store: &'s SqliteControlStore,
    limits: AdminCookieSessionLimits,
    policy: AdminCookieSessionPolicy,
}
impl fmt::Debug for SqliteLocalAdminCookieSessions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalAdminCookieSessions([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn local_admin_cookie_sessions(
        &self,
        limits: AdminCookieSessionLimits,
        policy: AdminCookieSessionPolicy,
    ) -> Result<SqliteLocalAdminCookieSessions<'_>, ControlError> {
        limits.validate()?;
        policy.validate()?;
        if limits.metadata.max_lifetime < policy.session_ttl {
            return Err(ControlError::Configuration);
        }
        Ok(SqliteLocalAdminCookieSessions {
            store: self,
            limits,
            policy,
        })
    }
}
fn gate(work: &Work, end: Instant, window: &CookieWindow) -> Result<(), Error> {
    work.check().map_err(ControlError::from)?;
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
fn delete(tx: &Transaction<'_>, work: &Work, hash: &str) -> Result<(), Error> {
    if tx
        .execute("DELETE FROM admin_sessions WHERE token_hash=?1", [hash])
        .map_err(|e| ControlError::from(work.sql(e)))?
        != 1
    {
        return Err(ControlError::Storage.into());
    }
    Ok(())
}

/// Reobserves a cookie from SQL inside the caller's physical transaction.
pub(super) struct CookieObserver<'a> {
    limits: AdminCookieSessionLimits,
    upstream: Option<&'a UpstreamBearerVerifier>,
    action: SystemAction,
    clock: &'a CookieClock,
    end: Instant,
}
pub(super) enum ObservedAdminCookie {
    Active(Box<CookieObservation>),
    Expired(CookieWindow),
}
pub(super) struct CookieObservation {
    proof: CookieReadProof,
    window: CookieWindow,
    csrf: Zeroizing<String>,
}
impl CookieObservation {
    pub(super) fn window(&self) -> &CookieWindow {
        &self.window
    }
    pub(super) fn csrf_matches(&self, supplied: Option<&str>) -> Result<bool, ControlError> {
        let stored = decode_secret(&self.csrf).map_err(|_| ControlError::CorruptSession)?;
        let Some(supplied) = supplied.and_then(|v| decode_secret(v).ok()) else {
            return Ok(false);
        };
        Ok(bool::from(stored.as_ref().ct_eq(supplied.as_ref())))
    }
    pub(super) fn into_witness(self) -> crate::admin_read::ReadWitness<'static> {
        crate::admin_read::ReadWitness::Cookie {
            _proof: self.proof,
            window: self.window,
        }
    }
}
impl<'a> CookieObserver<'a> {
    pub(super) fn new(
        limits: AdminCookieSessionLimits,
        upstream: Option<&'a UpstreamBearerVerifier>,
        action: SystemAction,
        clock: &'a CookieClock,
        end: Instant,
    ) -> Self {
        Self {
            limits,
            upstream,
            action,
            clock,
            end,
        }
    }
    pub(super) fn observe(
        &self,
        tx: &Transaction<'_>,
        work: &Work,
        hash: &str,
        cutoff: &mut Option<(SystemTime, Instant)>,
    ) -> Result<ObservedAdminCookie, crate::AdminBrokerSessionError> {
        use crate::admin_read::cookie_authorization;
        let session = session::load(tx, work, hash, &self.limits.metadata)?
            .ok_or_else(|| cookie_authorization(Error::Unauthorized))?;
        cookie_metadata(&session).map_err(cookie_authorization)?;
        let window = self
            .clock
            .window(absolute(session.expires_at().as_i64())?)?;
        *cutoff = Some(window.expiry());
        if window.check().is_err() {
            return Ok(ObservedAdminCookie::Expired(window));
        }
        let wait = self.end.min(window.expiry().1);
        let proof = if session.principal().issuer == "local" {
            let (profile, principal, roles, permissions) = admin_local_observer::observe(
                tx,
                work,
                LocalProof::Cookie(&session, &window),
                self.limits.authorization,
                self.action,
                wait,
            )?;
            CookieReadProof::local(profile, principal, roles, permissions)
        } else {
            let selector = self
                .upstream
                .as_ref()
                .and_then(|v| v.cookie_role_selector(&session.principal().issuer))
                .ok_or_else(|| cookie_authorization(Error::Unauthorized))?;
            let selected = match selector {
                None => None,
                Some(selector) => Some(
                    session
                        .claimed_roles()
                        .filter(|c| c.selector == selector)
                        .ok_or_else(|| cookie_authorization(Error::Unauthorized))?
                        .roles
                        .as_slice(),
                ),
            };
            crate::service::admin_cookie_session::validate_federated(
                session.profile(),
                session.principal(),
                if selected.is_some() {
                    session.claimed_roles()
                } else {
                    None
                },
                self.limits.authorization,
            )
            .map_err(cookie_authorization)?;
            let subject = format!(
                "{}|{}",
                session.principal().issuer,
                session.profile().subject
            );
            let (roles, permissions) = super::admin_upstream_session::observe_roles(
                tx,
                work,
                &subject,
                selected,
                self.limits.authorization,
                self.action,
                || gate(work, self.end, &window).map_err(cookie_observer_error),
            )?;
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
            CookieReadProof::federated(profile, principal, roles, permissions, selected.is_some())
        };
        Ok(ObservedAdminCookie::Active(Box::new(CookieObservation {
            proof,
            window,
            csrf: Zeroizing::new(session.csrf_token().to_owned()),
        })))
    }
}
pub(super) fn cookie_hash(store: &SqliteControlStore, raw: &str) -> Result<String, Error> {
    decode_secret(raw).map_err(|_| Error::MalformedCookie)?;
    store
        .digester
        .token(TokenKind::AdminSession, raw.as_bytes())
        .map(|h| h.to_sql_hex())
        .map_err(|_| Error::Unauthorized)
}

impl SqliteLocalAdminCookieSessions<'_> {
    fn hash(&self, raw: &str) -> Result<String, Error> {
        cookie_hash(self.store, raw)
    }
    pub async fn issue_local(
        &self,
        prepared: PreparedAdminLogin,
        policy: &LocalAuthPolicy,
        original: Instant,
    ) -> Result<IssuedAdminCookie, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
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
        let limits = self.limits;
        let result = self
            .store
            .executor
            .execute(end, move |owner, work| {
                Ok((|| -> Result<IssuedAdminCookie, Error> {
                    gate(work, end, &window)?;
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let (profile, principal, _, _) = admin_local_observer::observe(
                        &tx,
                        work,
                        LocalProof::Login(&login, &window),
                        limits.authorization,
                        SystemAction::SessionRead,
                        end,
                    )?;
                    let session = NewAdminSession::new(
                        profile,
                        principal,
                        csrf,
                        None,
                        absolute(expiry)?,
                        &limits.metadata,
                    )?;
                    let json = session.validate(&limits.metadata)?;
                    let created = now_micros()?;
                    if expiry <= created || expiry - created > limits.metadata.lifetime_micros()? {
                        return Err(ControlError::InvalidSession.into());
                    }
                    session::insert(&tx, work, &hash, &session, json, expiry, created)?;
                    gate(work, end, &window)?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok(IssuedAdminCookie {
                        raw,
                        window,
                        original,
                    })
                })())
            })
            .await
            .map_err(ControlError::from)?;
        if matches!(result, Err(Error::Control(ControlError::OutcomeUncertain))) {
            return result;
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        let result = result?;
        result.check()?;
        Ok(result)
    }
    pub async fn read(
        &self,
        raw: &str,
        original: Instant,
    ) -> Result<AdminCookieReadSession, Error> {
        self.read_with_upstream(raw, None, original).await
    }
    async fn read_with_upstream(
        &self,
        raw: &str,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
        original: Instant,
    ) -> Result<AdminCookieReadSession, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let clock = CookieClock::capture();
        let hash = self.hash(raw)?;
        let limits = self.limits;
        let result = self
            .store
            .executor
            .execute(end, move |owner, work| {
                let mut cutoff = None;
                let outcome = (|| -> Result<AdminCookieReadSession, Error> {
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let session = session::load(&tx, work, &hash, &limits.metadata)?
                        .ok_or(Error::Unauthorized)?;
                    cookie_metadata(&session)?;
                    let window = clock.window(absolute(session.expires_at().as_i64())?)?;
                    cutoff = Some(window.expiry());
                    if window.check().is_err() {
                        delete(&tx, work, &hash)?;
                        work.commit(tx).map_err(ControlError::from)?;
                        return Err(ControlError::SessionExpired.into());
                    }
                    let proof = if session.principal().issuer == "local" {
                        let (profile, principal, roles, permissions) =
                            admin_local_observer::observe(
                                &tx,
                                work,
                                LocalProof::Cookie(&session, &window),
                                limits.authorization,
                                SystemAction::SessionRead,
                                end,
                            )?;
                        CookieReadProof::local(profile, principal, roles, permissions)
                    } else {
                        let selector = upstream
                            .as_ref()
                            .and_then(|v| v.cookie_role_selector(&session.principal().issuer))
                            .ok_or(Error::Unauthorized)?;
                        let selected = match selector {
                            None => None,
                            Some(selector) => Some(
                                session
                                    .claimed_roles()
                                    .filter(|c| c.selector == selector)
                                    .ok_or(Error::Unauthorized)?
                                    .roles
                                    .as_slice(),
                            ),
                        };
                        crate::service::admin_cookie_session::validate_federated(
                            session.profile(),
                            session.principal(),
                            if selected.is_some() {
                                session.claimed_roles()
                            } else {
                                None
                            },
                            limits.authorization,
                        )?;
                        let subject = format!(
                            "{}|{}",
                            session.principal().issuer,
                            session.profile().subject
                        );
                        let (roles, permissions) = super::admin_upstream_session::observe_roles(
                            &tx,
                            work,
                            &subject,
                            selected,
                            limits.authorization,
                            SystemAction::SessionRead,
                            || gate(work, end, &window).map_err(cookie_observer_error),
                        )?;
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
                        CookieReadProof::federated(
                            profile,
                            principal,
                            roles,
                            permissions,
                            selected.is_some(),
                        )
                    };
                    let csrf = Zeroizing::new(session.csrf_token().to_owned());
                    gate(work, end, &window)?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok(AdminCookieReadSession {
                        proof,
                        csrf,
                        window,
                        original,
                    })
                })();
                Ok((cutoff, outcome))
            })
            .await;
        if matches!(
            &result,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok((_, Err(Error::Control(ControlError::OutcomeUncertain))))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        let (cutoff, outcome) = result.map_err(ControlError::from)?;
        if cutoff.is_some_and(|(utc, mono)| SystemTime::now() >= utc || Instant::now() >= mono) {
            return Err(ControlError::SessionExpired.into());
        }
        let result = outcome?;
        result.check()?;
        Ok(result)
    }

    pub(super) async fn read_admin(
        &self,
        raw: &str,
        request: crate::AdminReadRequest<'_>,
        read_limits: crate::AdminReadLimits,
        original: Instant,
    ) -> Result<crate::AdminReadResult<'static>, crate::AdminReadError> {
        self.read_admin_with_upstream(raw, request, read_limits, None, original)
            .await
    }
    async fn read_admin_with_upstream(
        &self,
        raw: &str,
        request: crate::AdminReadRequest<'_>,
        read_limits: crate::AdminReadLimits,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
        original: Instant,
    ) -> Result<crate::AdminReadResult<'static>, crate::AdminReadError> {
        use crate::{AdminReadError as ReadError, admin_read::cookie_authorization};
        read_limits.validate()?;
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let clock = CookieClock::capture();
        let hash = self.hash(raw).map_err(cookie_authorization)?;
        let request = super::admin_read::OwnedRequest::capture(request, read_limits)?;
        let limits = self.limits;
        let observed = self
            .store
            .executor
            .execute(end, move |owner, work| {
                let mut cutoff = None;
                let outcome = (|| -> Result<crate::AdminReadResult<'static>, ReadError> {
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let request = request.borrow();
                    let observation = match CookieObserver::new(
                        limits,
                        upstream.as_deref(),
                        request.kind().action(),
                        &clock,
                        end,
                    )
                    .observe(&tx, work, &hash, &mut cutoff)?
                    {
                        ObservedAdminCookie::Expired(window) => {
                            cutoff = Some(window.expiry());
                            delete(&tx, work, &hash).map_err(cookie_authorization)?;
                            work.commit(tx).map_err(ControlError::from)?;
                            return Err(cookie_authorization(Error::Control(
                                ControlError::SessionExpired,
                            ))
                            .into());
                        }
                        ObservedAdminCookie::Active(observation) => observation,
                    };
                    cutoff = Some(observation.window().expiry());
                    let wait = end.min(observation.window().expiry().1);
                    let projected = super::admin_read::projection(
                        &tx,
                        work,
                        &request,
                        read_limits,
                        observation.proof.profile(),
                        observation.proof.principal(),
                        wait,
                    );
                    if matches!(
                        &projected,
                        Err(ReadError::Authorization(
                            crate::AdminBrokerSessionError::Control(ControlError::OutcomeUncertain)
                        ))
                    ) {
                        return Err(ControlError::OutcomeUncertain.into());
                    }
                    gate(work, end, observation.window()).map_err(cookie_authorization)?;
                    let payload = projected?;
                    work.commit(tx).map_err(ControlError::from)?;
                    let result = crate::AdminReadResult {
                        witness: observation.into_witness(),
                        original: end,
                        body: payload.body,
                        revision: payload.revision,
                    };
                    result.check()?;
                    Ok(result)
                })();
                Ok((cutoff, outcome))
            })
            .await;
        // A missing physical COMMIT acknowledgement takes precedence over final clocks.
        if matches!(
            &observed,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok((
                    _,
                    Err(ReadError::Authorization(
                        crate::AdminBrokerSessionError::Control(ControlError::OutcomeUncertain)
                    ))
                ))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        let (cutoff, outcome) = observed.map_err(ControlError::from)?;
        // Captured cutoffs classify a late negative; they never replace the retained proof.
        if cutoff.is_some_and(|(utc, mono)| SystemTime::now() >= utc || Instant::now() >= mono) {
            return Err(cookie_authorization(Error::Control(ControlError::SessionExpired)).into());
        }
        let result = outcome?;
        result.check()?;
        Ok(result)
    }

    pub async fn logout(
        &self,
        raw: &str,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminCookieLogout, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let clock = CookieClock::capture();
        let hash = self.hash(raw)?;
        let csrf = csrf
            .filter(|s| s.len() == 43)
            .map(|s| Zeroizing::new(s.to_owned()));
        let limits = self.limits;
        let result = self
            .store
            .executor
            .execute(end, move |owner, work| {
                Ok((|| -> Result<AdminCookieLogout, Error> {
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let session = session::load(&tx, work, &hash, &limits.metadata)?;
                    let disposition = match session {
                        None => AdminCookieLogoutDisposition::Absent,
                        Some(session) => {
                            cookie_metadata(&session)?;
                            let window = clock.window(absolute(session.expires_at().as_i64())?)?;
                            let expired = window.check().is_err();
                            if !expired {
                                let stored = decode_secret(session.csrf_token())
                                    .map_err(|_| ControlError::CorruptSession)?;
                                let supplied = decode_secret(
                                    csrf.as_ref().map(|s| s.as_str()).ok_or(Error::CsrfFailed)?,
                                )
                                .map_err(|_| Error::CsrfFailed)?;
                                if !bool::from(stored.as_ref().ct_eq(supplied.as_ref())) {
                                    return Err(Error::CsrfFailed);
                                }
                            }
                            delete(&tx, work, &hash)?;
                            if expired {
                                AdminCookieLogoutDisposition::Expired
                            } else {
                                AdminCookieLogoutDisposition::Revoked
                            }
                        }
                    };
                    work.check().map_err(ControlError::from)?;
                    if Instant::now() >= end {
                        return Err(ControlError::Deadline.into());
                    }
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok(AdminCookieLogout {
                        original,
                        disposition,
                    })
                })())
            })
            .await
            .map_err(ControlError::from)?;
        if matches!(result, Err(Error::Control(ControlError::OutcomeUncertain))) {
            return result;
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        let result = result?;
        result.check()?;
        Ok(result)
    }
}

fn cookie_observer_error(error: Error) -> crate::AdminBrokerSessionError {
    match error {
        Error::Control(e) => crate::AdminBrokerSessionError::Control(e),
        Error::Forbidden => crate::AdminBrokerSessionError::Forbidden,
        _ => crate::BrokerAccessError::InvalidToken.into(),
    }
}
/// Complete cookie owner retaining the configured trust owner for H2.
/// The explicit LOCAL view remains available without a federated capability.
/// ```compile_fail
/// fn escape(s: &broker_control::SqliteControlStore,l:broker_control::AdminCookieSessionLimits,p:broker_control::AdminCookieSessionPolicy)->broker_control::SqliteAdminCookieSessions<'static> {
///     s.admin_cookie_sessions(l,p,None).unwrap()
/// }
/// ```
pub struct SqliteAdminCookieSessions<'s> {
    local: SqliteLocalAdminCookieSessions<'s>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
}
impl fmt::Debug for SqliteAdminCookieSessions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteAdminCookieSessions([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn admin_cookie_sessions(
        &self,
        limits: AdminCookieSessionLimits,
        policy: AdminCookieSessionPolicy,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
    ) -> Result<SqliteAdminCookieSessions<'_>, ControlError> {
        Ok(SqliteAdminCookieSessions {
            local: self.local_admin_cookie_sessions(limits, policy)?,
            upstream,
        })
    }
}
fn upstream_gate(
    proof: &VerifiedUpstreamLogin,
    verifier: &UpstreamBearerVerifier,
    end: Instant,
    window: &CookieWindow,
) -> Result<(), Error> {
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    window.check()?;
    if proof.purpose() != FlowPurpose::Admin {
        return Err(Error::Unauthorized);
    }
    proof.check(verifier).map_err(|e| match e {
        ControlError::InvalidFlow => Error::Unauthorized,
        e => Error::Control(e),
    })
}
impl SqliteAdminCookieSessions<'_> {
    pub(super) async fn read_admin(
        &self,
        raw: &str,
        request: crate::AdminReadRequest<'_>,
        limits: crate::AdminReadLimits,
        original: Instant,
    ) -> Result<crate::AdminReadResult<'static>, crate::AdminReadError> {
        self.local
            .read_admin_with_upstream(raw, request, limits, self.upstream.clone(), original)
            .await
    }
    pub async fn issue_local(
        &self,
        prepared: PreparedAdminLogin,
        policy: &LocalAuthPolicy,
        original: Instant,
    ) -> Result<IssuedAdminCookie, Error> {
        self.local.issue_local(prepared, policy, original).await
    }
    pub async fn read(
        &self,
        raw: &str,
        original: Instant,
    ) -> Result<AdminCookieReadSession, Error> {
        self.local
            .read_with_upstream(raw, self.upstream.clone(), original)
            .await
    }
    pub async fn logout(
        &self,
        raw: &str,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminCookieLogout, Error> {
        self.local.logout(raw, csrf, original).await
    }
    pub async fn issue_upstream(
        &self,
        proof: VerifiedUpstreamLogin,
        original: Instant,
    ) -> Result<IssuedAdminCookie, Error> {
        let original = original.min(proof.original());
        let end = self
            .local
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let verifier = self.upstream.clone().ok_or(Error::Unauthorized)?;
        let clock = CookieClock::capture();
        let expiry = TimestampMicros::try_from(
            clock
                .utc()
                .checked_add(self.local.policy.session_ttl)
                .ok_or(ControlError::Clock)?,
        )
        .map_err(|_| ControlError::Clock)?
        .as_i64();
        let window = clock.window(absolute(expiry)?)?;
        upstream_gate(&proof, &verifier, end, &window)?;
        let raw = new_secret()?;
        let csrf = new_secret()?;
        let hash = self.local.hash(&raw)?;
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
            (Some(s), Some(r)) => Some(SessionClaimRoles {
                selector: s.to_owned(),
                roles: r.to_vec(),
            }),
            (None, None) => None,
            _ => return Err(Error::Unauthorized),
        };
        let limits = self.local.limits;
        let session = NewAdminSession::new(
            profile,
            principal,
            csrf,
            claims,
            absolute(expiry)?,
            &limits.metadata,
        )?;
        crate::service::admin_cookie_session::validate_federated(
            session.profile(),
            session.principal(),
            session.claimed_roles(),
            limits.authorization,
        )?;
        let json = session.validate(&limits.metadata)?;
        let proof_expiry = proof.expires_mono();
        let wait = end.min(window.expiry().1).min(proof_expiry);
        // Keep both authentication and cookie windows through the real COMMIT acknowledgement.
        let observed = self
            .local
            .store
            .executor
            .execute(wait, move |owner, work| {
                let outcome = (|| -> Result<IssuedAdminCookie, Error> {
                    gate(work, end, &window)?;
                    upstream_gate(&proof, &verifier, end, &window)?;
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let subject = format!(
                        "{}|{}",
                        session.principal().issuer,
                        session.profile().subject
                    );
                    super::admin_upstream_session::observe_roles(
                        &tx,
                        work,
                        &subject,
                        session.claimed_roles().map(|c| c.roles.as_slice()),
                        limits.authorization,
                        SystemAction::SessionRead,
                        || {
                            gate(work, end, &window).map_err(cookie_observer_error)?;
                            upstream_gate(&proof, &verifier, end, &window)
                                .map_err(cookie_observer_error)
                        },
                    )?;
                    let created = now_micros()?;
                    if expiry <= created || expiry - created > limits.metadata.lifetime_micros()? {
                        return Err(ControlError::InvalidSession.into());
                    }
                    session::insert(&tx, work, &hash, &session, json, expiry, created)?;
                    gate(work, end, &window)?;
                    upstream_gate(&proof, &verifier, end, &window)?;
                    work.commit(tx).map_err(ControlError::from)?;
                    upstream_gate(&proof, &verifier, end, &window)?;
                    Ok(IssuedAdminCookie {
                        raw,
                        window,
                        original: end,
                    })
                })();
                Ok((proof, verifier, outcome))
            })
            .await;
        if matches!(
            &observed,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok((_, _, Err(Error::Control(ControlError::OutcomeUncertain))))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        if Instant::now() >= proof_expiry {
            return Err(ControlError::Expired.into());
        }
        let (proof, verifier, outcome) = observed.map_err(ControlError::from)?;
        proof.check(&verifier).map_err(|e| match e {
            ControlError::InvalidFlow => Error::Unauthorized,
            e => Error::Control(e),
        })?;
        let result = outcome?;
        result.check()?;
        Ok(result)
    }
}
