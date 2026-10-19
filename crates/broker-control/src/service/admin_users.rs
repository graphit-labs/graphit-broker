use super::{
    ConnectionGuard, PostgresAdminCookieSessions, PostgresControlStore,
    admin_broker_session::{LocalAdminProof, observe_local_session},
    admin_cookie_session::CookieObservation,
    admin_rbac::{another_admin, lock_admin},
    admin_upstream_session::{observe_upstream_roles, validate_profile},
    bounded_deadline, storage_error, timeout_error,
};
use crate::{
    AdminBrokerSessionError, AdminBrokerSessionLimits, AdminReadAuthentication,
    AdminUsersError as Error, AdminUsersLimits, AdminUsersRequest, AdminUsersResult,
    BrokerAccessError, ControlError, LocalPasswordEngine, LocalPasswordVerificationError,
    SystemAction, VerifiedBrokerAccess, VerifiedLocalBearer,
    admin_cookie_session::{CookieClock, decode_secret},
    admin_read::{ReadWitness, cookie_authorization},
    admin_users::validation::values,
    flow::now_micros,
    identity::{safe_identity_segment, valid_identity_subject},
    upstream_oidc::VerifiedUpstreamBearer,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_security::TokenKind;
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use futures_util::TryStreamExt;
use serde::Serialize;
use sqlx_core::{connection::Connection, row::Row};
use sqlx_postgres::PgConnection;
use std::{
    collections::BTreeSet,
    fmt,
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub struct PostgresAdminUsers<'s> {
    store: &'s PostgresControlStore,
    engine: &'s LocalPasswordEngine,
    limits: &'s AdminUsersLimits,
}
impl fmt::Debug for PostgresAdminUsers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresAdminUsers([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn admin_users<'s>(
        &'s self,
        engine: &'s LocalPasswordEngine,
        limits: &'s AdminUsersLimits,
    ) -> Result<PostgresAdminUsers<'s>, ControlError> {
        limits.validate()?;
        Ok(PostgresAdminUsers {
            store: self,
            engine,
            limits,
        })
    }
}
fn check(end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    Ok(())
}
fn uncertain<T>(result: &Result<T, Error>) -> bool {
    matches!(
        result,
        Err(Error::Authorization(AdminBrokerSessionError::Control(
            ControlError::OutcomeUncertain
        )))
    )
}

// Retains genuine factors between the initial pre-KDF observation and the final
// transaction. Each observation reads its own current action; it is not a lease.
enum Actor<'s, 'a, 'v> {
    Broker(VerifiedBrokerAccess<'a>),
    Opaque(VerifiedLocalBearer),
    Upstream(VerifiedUpstreamBearer),
    Cookie {
        sessions: PostgresAdminCookieSessions<'s, 'v>,
        hash: String,
        clock: CookieClock,
        observed: Option<Box<CookieObservation>>,
    },
}
impl<'s, 'a, 'v> Actor<'s, 'a, 'v> {
    fn check(&self, end: Instant) -> Result<(), Error> {
        check(end)?;
        match self {
            Self::Broker(proof) => proof.check().map_err(AdminBrokerSessionError::from)?,
            Self::Opaque(proof) => crate::admin_local_bearer_session::check_authentication(proof)?,
            Self::Upstream(proof) => proof.check()?,
            Self::Cookie {
                observed: Some(observation),
                ..
            } => observation
                .window
                .check()
                .map_err(|e| cookie_authorization(e.into()))?,
            Self::Cookie { observed: None, .. } => {}
        }
        Ok(())
    }
    fn end(&self, end: Instant) -> Instant {
        match self {
            Self::Broker(proof) => end.min(proof.authentication_expiry().1),
            Self::Opaque(proof) => end.min(proof.authentication_expiry().1),
            Self::Upstream(proof) => end.min(proof.expires_mono()),
            Self::Cookie {
                observed: Some(observation),
                ..
            } => end.min(observation.window.expiry().1),
            Self::Cookie { observed: None, .. } => end,
        }
    }
    async fn observe(
        &mut self,
        connection: &mut PgConnection,
        store: &PostgresControlStore,
        limits: AdminBrokerSessionLimits,
        action: SystemAction,
        csrf: Option<&str>,
        end: Instant,
    ) -> Result<(), Error> {
        self.check(end)?;
        match self {
            Self::Broker(proof) => {
                local_actor(
                    connection,
                    store,
                    &LocalAdminProof::Broker(proof),
                    limits,
                    action,
                    end,
                )
                .await?
            }
            Self::Opaque(proof) => {
                local_actor(
                    connection,
                    store,
                    &LocalAdminProof::Opaque(proof),
                    limits,
                    action,
                    end,
                )
                .await?
            }
            Self::Upstream(proof) => {
                let subject = format!("{}|{}", proof.issuer(), proof.profile().subject);
                observe_upstream_roles(
                    connection,
                    &subject,
                    proof.claim_roles(),
                    limits,
                    action,
                    || {
                        if Instant::now() >= end {
                            return Err(ControlError::Deadline.into());
                        }
                        proof.check()
                    },
                )
                .await?;
            }
            Self::Cookie {
                sessions,
                hash,
                clock,
                observed,
            } => {
                let observation = sessions
                    .observe_cookie(connection, hash, clock, action, end)
                    .await
                    .map_err(cookie_authorization)?;
                observation
                    .window
                    .check()
                    .map_err(|e| cookie_authorization(e.into()))?;
                if !matches!(action, SystemAction::UsersRead) {
                    let stored = decode_secret(&observation.csrf)
                        .map_err(|_| ControlError::CorruptSession)?;
                    let supplied = decode_secret(csrf.ok_or(Error::CsrfFailed)?)
                        .map_err(|_| Error::CsrfFailed)?;
                    if !bool::from(stored.as_ref().ct_eq(supplied.as_ref())) {
                        return Err(Error::CsrfFailed);
                    }
                }
                if let Some(current) = observed {
                    **current = observation;
                } else {
                    *observed = Some(Box::new(observation));
                }
            }
        }
        self.check(end)
    }
    fn witness(self) -> Result<ReadWitness<'a>, Error> {
        match self {
            Self::Broker(p) => Ok(ReadWitness::Broker(p)),
            Self::Opaque(p) => Ok(ReadWitness::Opaque(p)),
            Self::Upstream(p) => Ok(ReadWitness::Upstream(p)),
            Self::Cookie {
                observed: Some(p), ..
            } => {
                let p = *p;
                Ok(ReadWitness::Cookie {
                    _proof: p.proof,
                    window: p.window,
                })
            }
            Self::Cookie { observed: None, .. } => Err(ControlError::Configuration.into()),
        }
    }
}
async fn local_actor(
    connection: &mut PgConnection,
    store: &PostgresControlStore,
    proof: &LocalAdminProof<'_, '_>,
    limits: AdminBrokerSessionLimits,
    action: SystemAction,
    end: Instant,
) -> Result<(), Error> {
    let username = proof.username(limits)?;
    sqlx_core::query::query("SELECT username FROM public.local_users WHERE username=$1 FOR SHARE")
        .bind(username)
        .fetch_optional(&mut *connection)
        .await
        .map_err(storage_error)?;
    observe_local_session(connection, store, proof, limits, action, end).await?;
    Ok(())
}
impl<'s> PostgresAdminUsers<'s> {
    pub async fn execute<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminUsersRequest<'_>,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminUsersResult<'a>, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let cookie_upstream;
        let mut actor = match authentication {
            AdminReadAuthentication::Broker { verifier, proof } => {
                proof.check().map_err(AdminBrokerSessionError::from)?;
                if !proof.owned_by(verifier) {
                    return Err(
                        AdminBrokerSessionError::from(BrokerAccessError::InvalidToken).into(),
                    );
                }
                Actor::Broker(proof)
            }
            AdminReadAuthentication::Opaque {
                raw,
                audience,
                identity_json_bytes,
                required_scopes,
            } => Actor::Opaque(
                self.store
                    .local_bearer_verifier(audience, identity_json_bytes)
                    .map_err(crate::admin_local_bearer_session::verification_error)?
                    .verify(raw, required_scopes, end)
                    .await
                    .map_err(crate::admin_local_bearer_session::verification_error)?,
            ),
            AdminReadAuthentication::Upstream { raw, verifier } => {
                let proof = verifier.verify(raw, end).await?;
                validate_profile(&proof, self.limits.authorization, end)?;
                Actor::Upstream(proof)
            }
            AdminReadAuthentication::Cookie {
                raw,
                limits,
                policy,
                upstream,
            } => {
                let a = limits.authorization;
                let b = self.limits.authorization;
                if a.profile_json_bytes != b.profile_json_bytes
                    || [
                        a.identity.username_bytes,
                        a.identity.subject_bytes,
                        a.identity.role_bytes,
                        a.identity.roles,
                        a.identity.rows,
                    ] != [
                        b.identity.username_bytes,
                        b.identity.subject_bytes,
                        b.identity.role_bytes,
                        b.identity.roles,
                        b.identity.rows,
                    ]
                {
                    return Err(ControlError::Configuration.into());
                }
                cookie_upstream = upstream;
                let sessions =
                    self.store
                        .admin_cookie_sessions(limits, policy, cookie_upstream.as_deref())?;
                let hash = sessions.hash(raw).map_err(cookie_authorization)?;
                Actor::Cookie {
                    sessions,
                    hash,
                    clock: CookieClock::capture(),
                    observed: None,
                }
            }
        };
        let hash = if let Some(password) = request.password() {
            self.transaction(&mut actor, &request, csrf, None, true, end)
                .await?;
            actor.check(end)?;
            Some(
                self.engine
                    .hash(password, actor.end(end))
                    .await
                    .map_err(|e| match e {
                        LocalPasswordVerificationError::Control(e) => Error::from(e),
                        _ => request.error(),
                    })?,
            )
        } else {
            None
        };
        let output = self
            .transaction(
                &mut actor,
                &request,
                csrf,
                hash.as_deref().map(String::as_str),
                false,
                end,
            )
            .await?;
        actor.check(end)?;
        let result = AdminUsersResult {
            witness: actor.witness()?,
            original: end,
            status: output.status,
            body: output.body,
        };
        result.check()?;
        Ok(result)
    }
    async fn transaction(
        &self,
        actor: &mut Actor<'_, '_, '_>,
        request: &AdminUsersRequest<'_>,
        csrf: Option<&str>,
        hash: Option<&str>,
        preflight: bool,
        end: Instant,
    ) -> Result<Output, Error> {
        actor.check(end)?;
        let commit_started = AtomicBool::new(false);
        let outcome = tokio::time::timeout_at(actor.end(end).into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            if !matches!(request, AdminUsersRequest::Credentials { .. }) {
                lock_admin(&mut tx).await?;
            }
            actor
                .observe(
                    &mut tx,
                    self.store,
                    self.limits.authorization,
                    request.action(),
                    csrf,
                    end,
                )
                .await?;
            let applied = tokio::time::timeout_at(actor.end(end).into(), async {
                let output = if preflight {
                    preflight_user(&mut tx, request).await?;
                    Output::empty(204)
                } else {
                    apply(&mut tx, self.store, self.limits, request, hash, end).await?
                };
                actor.check(end)?;
                commit_started.store(true, Ordering::Relaxed);
                tx.commit()
                    .await
                    .map_err(|_| ControlError::OutcomeUncertain)?;
                Ok::<_, Error>(output)
            })
            .await
            .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
            if uncertain(&applied) {
                return Err(ControlError::OutcomeUncertain.into());
            }
            if applied.is_ok() {
                guard.confirmed();
            }
            actor.check(end)?;
            applied
        })
        .await
        .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
        if uncertain(&outcome) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        actor.check(end)?;
        outcome
    }
}
struct Output {
    status: u16,
    body: Zeroizing<Vec<u8>>,
}
impl Output {
    fn empty(status: u16) -> Self {
        Self {
            status,
            body: Zeroizing::new(Vec::new()),
        }
    }
}
struct JsonBody {
    bytes: Zeroizing<Vec<u8>>,
    cap: usize,
}
impl Write for JsonBody {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.cap.saturating_sub(self.bytes.len()) {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| std::io::Error::other("administrative response allocation"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(
    value: &impl Serialize,
    maximum: usize,
    status: u16,
    error: Error,
) -> Result<Output, Error> {
    let mut out = JsonBody {
        bytes: Zeroizing::new(Vec::new()),
        cap: maximum,
    };
    serde_json::to_writer(&mut out, value).map_err(|_| error)?;
    Ok(Output {
        status,
        body: out.bytes,
    })
}
fn timestamp(value: i64) -> Result<String, Error> {
    DateTime::<Utc>::from_timestamp_micros(value)
        .filter(|d| value >= 0 && d.year() <= 9999)
        .map(|d| d.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        .ok_or_else(|| ControlError::CorruptIdentity.into())
}

struct User {
    username: String,
    subject: String,
    kind: String,
    phc: Zeroizing<String>,
    enabled: bool,
    change: bool,
    revision: i64,
}
async fn target(
    connection: &mut PgConnection,
    username: &str,
    error: Error,
    write: bool,
) -> Result<User, Error> {
    let username = username.trim();
    if !safe_identity_segment(username, 128) {
        return Err(error);
    }
    let query = if write {
        sqlx_core::query::query(
            "SELECT CASE WHEN octet_length(username)<=128 THEN username END,CASE WHEN octet_length(subject)<=512 THEN subject END,CASE WHEN octet_length(identity_kind)<=16 THEN identity_kind END,CASE WHEN octet_length(password_hash)<=512 THEN password_hash END,enabled::bigint,password_change_required::bigint,revision FROM public.local_users WHERE username=$1 FOR UPDATE",
        )
    } else {
        sqlx_core::query::query(
            "SELECT CASE WHEN octet_length(username)<=128 THEN username END,CASE WHEN octet_length(subject)<=512 THEN subject END,CASE WHEN octet_length(identity_kind)<=16 THEN identity_kind END,CASE WHEN octet_length(password_hash)<=512 THEN password_hash END,enabled::bigint,password_change_required::bigint,revision FROM public.local_users WHERE username=$1 FOR SHARE",
        )
    };
    let row = query
        .bind(username)
        .fetch_optional(connection)
        .await
        .map_err(storage_error)?
        .ok_or(error)?;
    let text = |i| -> Result<String, ControlError> {
        row.try_get::<Option<String>, _>(i)
            .map_err(|_| ControlError::CorruptIdentity)?
            .ok_or(ControlError::CorruptIdentity)
    };
    let user = User {
        username: text(0)?,
        subject: text(1)?,
        kind: text(2)?,
        phc: Zeroizing::new(text(3)?),
        enabled: match row
            .try_get::<i64, _>(4)
            .map_err(|_| ControlError::CorruptIdentity)?
        {
            0 => false,
            1 => true,
            _ => return Err(ControlError::CorruptIdentity.into()),
        },
        change: match row
            .try_get::<i64, _>(5)
            .map_err(|_| ControlError::CorruptIdentity)?
        {
            0 => false,
            1 => true,
            _ => return Err(ControlError::CorruptIdentity.into()),
        },
        revision: row.try_get(6).map_err(|_| ControlError::CorruptIdentity)?,
    };
    if !safe_identity_segment(&user.username, 128)
        || !valid_identity_subject(&user.subject, 512)
        || !matches!(user.kind.as_str(), "human" | "service")
        || user.revision < 1
        || user.kind == "service" && (!user.phc.is_empty() || user.change)
    {
        return Err(ControlError::CorruptIdentity.into());
    }
    Ok(user)
}
async fn preflight_user(
    connection: &mut PgConnection,
    request: &AdminUsersRequest<'_>,
) -> Result<(), Error> {
    match request {
        AdminUsersRequest::Create(input) => {
            let kind = if input.kind.is_empty() {
                "human"
            } else {
                input.kind.as_str()
            };
            values(input, kind, true, request.error())?;
        }
        AdminUsersRequest::Update {
            username,
            user: input,
        } => {
            let current = target(connection, username, request.error(), true).await?;
            let kind = if input.kind.is_empty() {
                current.kind.as_str()
            } else {
                input.kind.as_str()
            };
            let value = values(input, kind, false, request.error())?;
            if value.subject != current.subject || value.kind != current.kind {
                return Err(request.error());
            }
        }
        _ => return Err(ControlError::Configuration.into()),
    }
    Ok(())
}
async fn replace_roles(
    connection: &mut PgConnection,
    subject: &str,
    roles: &BTreeSet<&str>,
    now: i64,
    error: Error,
) -> Result<(), Error> {
    let canonical = format!("local|{subject}");
    sqlx_core::query::query("DELETE FROM public.role_assignments WHERE subject=$1")
        .bind(&canonical)
        .execute(&mut *connection)
        .await
        .map_err(|_| error)?;
    for &role in roles {
        sqlx_core::query::query(
            "INSERT INTO public.role_assignments(subject,role,created_at) VALUES($1,$2,$3)",
        )
        .bind(&canonical)
        .bind(role)
        .bind(now)
        .execute(&mut *connection)
        .await
        .map_err(|_| error)?;
    }
    Ok(())
}
async fn last_admin(
    connection: &mut PgConnection,
    subject: &str,
    error: Error,
) -> Result<(), Error> {
    let canonical = format!("local|{subject}");
    let assigned: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.role_assignments WHERE subject=$1 AND role='admin')",
    )
    .bind(&canonical)
    .fetch_one(&mut *connection)
    .await
    .map_err(storage_error)?;
    if assigned {
        another_admin(connection, &canonical)
            .await
            .map_err(|e| match e {
                crate::AdminRbacError::Authorization(e) => Error::Authorization(e),
                _ => error,
            })?;
    }
    Ok(())
}
async fn invalidate(
    connection: &mut PgConnection,
    subject: &str,
    now: i64,
    end: Instant,
) -> Result<(), Error> {
    super::local_auth::invalidate_local_user(connection, subject, false, now, end)
        .await
        .map_err(|e| match e {
            crate::LocalAuthError::Control(e) => Error::from(e),
            _ => ControlError::Storage.into(),
        })
}

async fn apply(
    connection: &mut PgConnection,
    store: &PostgresControlStore,
    limits: &AdminUsersLimits,
    request: &AdminUsersRequest<'_>,
    hash: Option<&str>,
    end: Instant,
) -> Result<Output, Error> {
    check(end)?;
    let error = request.error();
    match request {
        AdminUsersRequest::Create(input) => {
            let kind = if input.kind.is_empty() {
                "human"
            } else {
                input.kind.as_str()
            };
            let user = values(input, kind, true, error)?;
            let phc = if kind == "human" {
                hash.ok_or(error)?
            } else {
                ""
            };
            let teams = serde_json::to_string(&user.teams).map_err(|_| error)?;
            let now = now_micros()?;
            sqlx_core::query::query("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$11)").bind(user.username).bind(user.subject).bind(kind).bind(phc).bind(user.name).bind(user.email).bind(user.organization).bind(teams).bind(i16::from(user.enabled)).bind(i16::from(kind=="human")).bind(now).execute(&mut *connection).await.map_err(|_|error)?;
            replace_roles(connection, user.subject, &user.roles, now, error).await?;
            Ok(Output::empty(201))
        }
        AdminUsersRequest::Update {
            username,
            user: input,
        } => {
            let current = target(connection, username, error, true).await?;
            let kind = if input.kind.is_empty() {
                current.kind.as_str()
            } else {
                input.kind.as_str()
            };
            let user = values(input, kind, false, error)?;
            if user.subject != current.subject || user.kind != current.kind {
                return Err(error);
            }
            if !user.enabled || !user.roles.contains("admin") {
                last_admin(connection, &current.subject, error).await?;
            }
            let revision = current.revision.checked_add(1).ok_or(error)?;
            let teams = serde_json::to_string(&user.teams).map_err(|_| error)?;
            let phc = hash.unwrap_or(&current.phc);
            let change = kind == "human"
                && (current.change || input.password_change_required || hash.is_some());
            let now = now_micros()?;
            let changed=sqlx_core::query::query("UPDATE public.local_users SET username=$1,password_hash=$2,name=$3,email=$4,organization=$5,teams_json=$6,enabled=$7,password_change_required=$8,revision=$9,updated_at=$10 WHERE username=$11 AND subject=$12 AND revision=$13").bind(user.username).bind(phc).bind(user.name).bind(user.email).bind(user.organization).bind(teams).bind(i16::from(user.enabled)).bind(i16::from(change)).bind(revision).bind(now).bind(&current.username).bind(&current.subject).bind(current.revision).execute(&mut *connection).await.map_err(|_|error)?.rows_affected();
            if changed != 1 {
                return Err(error);
            }
            replace_roles(connection, &current.subject, &user.roles, now, error).await?;
            invalidate(connection, &current.subject, now, end).await?;
            Ok(Output::empty(204))
        }
        AdminUsersRequest::Delete { username } => {
            let current = target(connection, username, error, true).await?;
            last_admin(connection, &current.subject, error).await?;
            let now = now_micros()?;
            invalidate(connection, &current.subject, now, end).await?;
            sqlx_core::query::query("DELETE FROM public.admin_sessions s USING public.admin_session_principals p WHERE s.token_hash=p.token_hash AND s.subject=$1 AND p.issuer='local'").bind(&current.subject).execute(&mut *connection).await.map_err(|_|error)?;
            sqlx_core::query::query(
                "DELETE FROM public.local_tokens WHERE subject=$1 AND local_user_revision>=1",
            )
            .bind(&current.subject)
            .execute(&mut *connection)
            .await
            .map_err(|_| error)?;
            sqlx_core::query::query("DELETE FROM public.role_assignments WHERE subject=$1")
                .bind(format!("local|{}", current.subject))
                .execute(&mut *connection)
                .await
                .map_err(|_| error)?;
            let changed = sqlx_core::query::query(
                "DELETE FROM public.local_users WHERE username=$1 AND subject=$2 AND revision=$3",
            )
            .bind(&current.username)
            .bind(&current.subject)
            .bind(current.revision)
            .execute(&mut *connection)
            .await
            .map_err(|_| error)?
            .rows_affected();
            if changed != 1 {
                return Err(error);
            }
            Ok(Output::empty(204))
        }
        AdminUsersRequest::ResetMfa { username } => {
            let current = target(connection, username, error, true).await?;
            if current.kind != "human" {
                return Err(error);
            }
            let revision = current.revision.checked_add(1).ok_or(error)?;
            let now = now_micros()?;
            for sql in [
                "DELETE FROM public.local_mfa WHERE subject=$1",
                "DELETE FROM public.local_mfa_recovery_codes WHERE subject=$1",
            ] {
                sqlx_core::query::query(sql)
                    .bind(&current.subject)
                    .execute(&mut *connection)
                    .await
                    .map_err(|_| error)?;
            }
            sqlx_core::query::query("UPDATE public.local_users SET revision=$1,updated_at=$2 WHERE username=$3 AND subject=$4 AND revision=$5").bind(revision).bind(now).bind(&current.username).bind(&current.subject).bind(current.revision).execute(&mut *connection).await.map_err(|_|error)?;
            invalidate(connection, &current.subject, now, end).await?;
            Ok(Output::empty(204))
        }
        AdminUsersRequest::Credentials { username } => {
            let current =
                target(connection, username, Error::ServiceIdentityNotFound, false).await?;
            if current.kind != "service" {
                return Err(Error::ServiceIdentityNotFound);
            }
            inventory(
                connection,
                &current.subject,
                limits.response_json_bytes.get(),
                end,
            )
            .await
        }
        AdminUsersRequest::IssueCredential { username, input } => {
            let current =
                target(connection, username, Error::ServiceIdentityNotFound, true).await?;
            if current.kind != "service" {
                return Err(Error::ServiceIdentityNotFound);
            }
            if !current.enabled {
                return Err(error);
            }
            let client = if input.client_id.trim().is_empty() {
                current.username.as_str()
            } else {
                input.client_id.trim()
            };
            if !safe_identity_segment(client, 128) {
                return Err(Error::InvalidCredential);
            }
            let seconds = if input.expires_in == 0 {
                limits.service_credential_max_ttl.as_secs().min(90 * 86400)
            } else {
                u64::try_from(input.expires_in).map_err(|_| Error::InvalidCredential)?
            };
            if seconds < 3600 || seconds > limits.service_credential_max_ttl.as_secs() {
                return Err(Error::InvalidCredential);
            }
            let now = now_micros()?;
            let expires = now
                .checked_add(
                    i64::try_from(seconds)
                        .map_err(|_| Error::InvalidCredential)?
                        .checked_mul(1_000_000)
                        .ok_or(Error::InvalidCredential)?,
                )
                .ok_or(Error::InvalidCredential)?;
            let expires_at = timestamp(expires)?;
            let scopes = input
                .scopes
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<BTreeSet<_>>();
            let scopes_json = serde_json::to_string(&scopes).map_err(|_| error)?;
            let mut bytes = Zeroizing::new([0u8; 32]);
            getrandom::fill(bytes.as_mut()).map_err(|_| Error::CredentialGenerationFailed)?;
            let raw = Zeroizing::new(format!("gb_sc_{}", URL_SAFE_NO_PAD.encode(bytes.as_ref())));
            let mut id = [0u8; 12];
            getrandom::fill(&mut id).map_err(|_| Error::CredentialGenerationFailed)?;
            let id = URL_SAFE_NO_PAD.encode(id);
            let digest = Zeroizing::new(
                store
                    .digester
                    .token(TokenKind::ServiceCredential, raw.as_bytes())
                    .map_err(|_| Error::CredentialGenerationFailed)?
                    .to_sql_hex(),
            );
            #[derive(Serialize)]
            struct Principal<'a> {
                issuer: &'a str,
                subject: &'a str,
                username: &'a str,
                auth_method: &'a str,
                local_user_revision: i64,
            }
            let principal = serde_json::to_string(&Principal {
                issuer: "local",
                subject: &current.subject,
                username: &current.username,
                auth_method: "service-credential",
                local_user_revision: current.revision,
            })
            .map_err(|_| error)?;
            sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,'service',$3,'',$4,$5,$6,'',$7,$8,'',$9,$10,$9)").bind(digest.as_str()).bind(&id).bind(&current.subject).bind(principal).bind(client).bind(&limits.service_credential_audience).bind(scopes_json).bind(current.revision).bind(now).bind(expires).execute(&mut *connection).await.map_err(|_|error)?;
            #[derive(Serialize)]
            struct Issued<'a> {
                id: &'a str,
                token: &'a str,
                token_type: &'a str,
                expires_at: &'a str,
                scopes: &'a BTreeSet<&'a str>,
            }
            encode(
                &Issued {
                    id: &id,
                    token: &raw,
                    token_type: "Bearer",
                    expires_at: &expires_at,
                    scopes: &scopes,
                },
                limits.response_json_bytes.get(),
                201,
                error,
            )
        }
        AdminUsersRequest::RevokeCredential { username, id } => {
            let current =
                target(connection, username, Error::ServiceIdentityNotFound, true).await?;
            if current.kind != "service" {
                return Err(Error::ServiceIdentityNotFound);
            }
            if !safe_identity_segment(id, 128) {
                return Err(error);
            }
            let now = now_micros()?;
            let changed=sqlx_core::query::query("UPDATE public.local_tokens SET revoked_at=$1 WHERE subject=$2 AND token_kind='service' AND token_id=$3 AND local_user_revision>=1 AND revoked_at IS NULL").bind(now).bind(&current.subject).bind(id).execute(connection).await.map_err(|_|error)?.rows_affected();
            if changed != 1 {
                return Err(error);
            }
            Ok(Output::empty(204))
        }
    }
}
#[derive(Serialize)]
struct Credential<'a> {
    id: &'a str,
    client_id: &'a str,
    scopes: Vec<String>,
    created_at: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<String>,
}
async fn inventory(
    connection: &mut PgConnection,
    subject: &str,
    maximum: usize,
    end: Instant,
) -> Result<Output, Error> {
    let error = Error::CredentialsReadFailed;
    let mut out = JsonBody {
        bytes: Zeroizing::new(Vec::new()),
        cap: maximum,
    };
    out.write_all(b"{\"credentials\":[").map_err(|_| error)?;
    let mut first = true;
    let mut rows=sqlx_core::query::query("SELECT token_id,client_id,CASE WHEN octet_length(scopes_json)<=$2 THEN scopes_json END,created_at,expires_at,revoked_at FROM public.local_tokens WHERE subject=$1 AND token_kind='service' AND local_user_revision>=1 ORDER BY created_at,token_id").bind(subject).bind(maximum as i64).fetch(connection);
    while let Some(row) = rows.try_next().await.map_err(|_| error)? {
        check(end)?;
        let id: &str = row.try_get(0).map_err(|_| error)?;
        let client: &str = row.try_get(1).map_err(|_| error)?;
        let scopes: Option<&str> = row.try_get(2).map_err(|_| error)?;
        let scopes: Vec<String> = serde_json::from_str(scopes.ok_or(error)?).map_err(|_| error)?;
        if !safe_identity_segment(id, 128)
            || !safe_identity_segment(client, 128)
            || scopes.iter().any(|s| s.is_empty() || s.trim() != s)
            || scopes.windows(2).any(|s| s[0] >= s[1])
        {
            return Err(error);
        }
        let created: i64 = row.try_get(3).map_err(|_| error)?;
        let expiry: i64 = row.try_get(4).map_err(|_| error)?;
        let revoked: Option<i64> = row.try_get(5).map_err(|_| error)?;
        if expiry <= created {
            return Err(error);
        }
        let credential = Credential {
            id,
            client_id: client,
            scopes,
            created_at: timestamp(created)?,
            expires_at: timestamp(expiry)?,
            revoked_at: revoked.map(timestamp).transpose()?,
        };
        if !first {
            out.write_all(b",").map_err(|_| error)?;
        }
        first = false;
        serde_json::to_writer(&mut out, &credential).map_err(|_| error)?;
    }
    out.write_all(b"]}").map_err(|_| error)?;
    Ok(Output {
        status: 200,
        body: out.bytes,
    })
}
