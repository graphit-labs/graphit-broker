use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    AdminBrokerSession, AdminBrokerSessionError as Error, AdminBrokerSessionLimits,
    BrokerAccessError, BrokerAccessVerifier, ControlError, LocalIdentityKind, SessionPrincipal,
    SessionProfile, SystemAction, SystemPermission, VerifiedBrokerAccess, VerifiedLocalBearer,
    identity::{safe_identity_segment, valid_identity_subject},
};
use futures_util::TryStreamExt;
use serde::Serialize;
use sqlx_core::{connection::Connection, row::Row};
use std::{
    collections::BTreeSet,
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

// One statement observes the identity, profile, assignments and definitions together.
const SELECT: &str = r#"SELECT
 CASE WHEN octet_length(u.username)::bigint<=$1 THEN u.username END,
 CASE WHEN octet_length(u.subject)::bigint<=$2 THEN u.subject END,
 CASE WHEN octet_length(u.identity_kind)<=16 THEN u.identity_kind END,
 u.enabled::bigint,u.revision,
 CASE WHEN octet_length(u.name)<=2048 AND octet_length(u.name)::bigint<=$4 THEN u.name END,
 CASE WHEN octet_length(u.email)<=2048 AND octet_length(u.email)::bigint<=$4 THEN u.email END,
 CASE WHEN octet_length(u.organization)<=2048 AND octet_length(u.organization)::bigint<=$4 THEN u.organization END,
 CASE WHEN octet_length(u.teams_json)::bigint<=$4 THEN u.teams_json END,
 CASE WHEN octet_length(a.role)::bigint<=$3 THEN a.role END,
 CASE WHEN octet_length(p.action)<=128 THEN p.action END,
 a.role IS NOT NULL,p.role IS NOT NULL,u.password_change_required::bigint
 FROM public.local_users u
 LEFT JOIN LATERAL (SELECT role FROM public.role_assignments WHERE subject='local|'||u.subject UNION SELECT 'user') a ON TRUE
 LEFT JOIN public.roles r ON r.name=a.role LEFT JOIN public.role_permissions p ON p.role=r.name
 WHERE u.username=$5 ORDER BY a.role,p.action LIMIT $6"#;

#[derive(Serialize)]
struct ProfileProjection<'a> {
    subject: &'a str,
    username: &'a str,
    name: &'a str,
    email: &'a str,
    organization: &'a str,
    teams: &'a [String],
}
pub struct PostgresAdminBrokerSessions<'s, 'v> {
    store: &'s PostgresControlStore,
    verifier: &'v BrokerAccessVerifier,
    limits: AdminBrokerSessionLimits,
}
impl fmt::Debug for PostgresAdminBrokerSessions<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresAdminBrokerSessions([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn admin_broker_sessions<'s, 'v>(
        &'s self,
        verifier: &'v BrokerAccessVerifier,
        limits: AdminBrokerSessionLimits,
    ) -> Result<PostgresAdminBrokerSessions<'s, 'v>, ControlError> {
        limits.validate()?;
        Ok(PostgresAdminBrokerSessions {
            store: self,
            verifier,
            limits,
        })
    }
}
impl<'v> PostgresAdminBrokerSessions<'_, 'v> {
    /// Authenticate first; username is only a locator, never the LOCAL binding.
    pub async fn read(
        &self,
        proof: VerifiedBrokerAccess<'v>,
        original: Instant,
    ) -> Result<AdminBrokerSession<'v>, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        proof.check()?;
        if !proof.owned_by(self.verifier) {
            final_gate(&LocalAdminProof::Broker(&proof), end)?;
            return Err(BrokerAccessError::InvalidToken.into());
        }
        let (profile, principal, roles, permissions) = read_local_session(
            self.store,
            LocalAdminProof::Broker(&proof),
            self.limits,
            end,
        )
        .await?;
        let result = AdminBrokerSession {
            proof,
            original,
            profile,
            principal,
            roles,
            permissions,
        };
        result.check()?;
        Ok(result)
    }
}
pub(super) enum LocalAdminProof<'p, 'v> {
    Broker(&'p VerifiedBrokerAccess<'v>),
    Opaque(&'p VerifiedLocalBearer),
    Login(
        &'p crate::CompletedLocalLogin,
        &'p crate::admin_cookie_session::CookieWindow,
    ),
    Cookie(
        &'p crate::AdminSession,
        &'p crate::admin_cookie_session::CookieWindow,
    ),
}
impl LocalAdminProof<'_, '_> {
    pub(super) fn check(&self) -> Result<(), Error> {
        match self {
            Self::Broker(proof) => proof.check().map_err(Into::into),
            Self::Opaque(proof) => crate::admin_local_bearer_session::check_authentication(proof),
            Self::Login(_, window) | Self::Cookie(_, window) => window.check().map_err(Into::into),
        }
    }
    pub(super) fn authentication_expiry(&self) -> (std::time::SystemTime, Instant) {
        match self {
            Self::Broker(p) => p.authentication_expiry(),
            Self::Opaque(p) => p.authentication_expiry(),
            Self::Login(_, window) | Self::Cookie(_, window) => window.expiry(),
        }
    }
    pub(super) fn username(&self, limits: AdminBrokerSessionLimits) -> Result<String, Error> {
        let username = match self {
            Self::Broker(proof) => proof.username(),
            Self::Opaque(proof) => Some(proof.current_local_user().username()),
            Self::Login(login, _) => Some(login.username()),
            Self::Cookie(session, _) => Some(session.principal().username.as_str()),
        };
        username
            .filter(|v| safe_identity_segment(v, limits.identity.username_bytes.get()))
            .map(str::to_owned)
            .ok_or_else(|| self.identity_unavailable())
    }
    fn identity_unavailable(&self) -> Error {
        match self {
            Self::Broker(_) => Error::Forbidden,
            Self::Opaque(_) | Self::Login(_, _) | Self::Cookie(_, _) => {
                BrokerAccessError::InvalidToken.into()
            }
        }
    }
    fn bind(
        &self,
        store: &PostgresControlStore,
        subject: &str,
        kind: &str,
        enabled: i64,
        revision: i64,
    ) -> Result<(), Error> {
        let matches = match self {
            Self::Broker(proof) => {
                let pseudonym = store
                    .digester
                    .oidc_subject(b"local", subject.as_bytes())
                    .map_err(|_| ControlError::CorruptIdentity)?;
                enabled == 1 && pseudonym.as_str() == proof.subject()
            }
            Self::Opaque(proof) => {
                let current = proof.current_local_user();
                let expected_kind = match current.kind() {
                    LocalIdentityKind::Human => "human",
                    LocalIdentityKind::Service => "service",
                };
                enabled == 1
                    && subject == current.subject()
                    && revision == current.revision()
                    && kind == expected_kind
            }
            Self::Login(login, _) => {
                enabled == 1
                    && kind == "human"
                    && subject == login.subject()
                    && revision == login.revision()
            }
            Self::Cookie(session, _) => {
                enabled == 1
                    && kind == "human"
                    && subject == session.profile().subject
                    && revision == session.principal().local_user_revision
            }
        };
        if matches {
            Ok(())
        } else {
            Err(self.identity_unavailable())
        }
    }
}
// Both consumers retain their genuine private authentication value while this
// shared statement observes the current LOCAL profile and SQL administrative roles.
pub(super) async fn read_local_session(
    store: &PostgresControlStore,
    proof: LocalAdminProof<'_, '_>,
    limits: AdminBrokerSessionLimits,
    end: Instant,
) -> Result<
    (
        SessionProfile,
        SessionPrincipal,
        Vec<String>,
        Vec<SystemPermission>,
    ),
    Error,
> {
    final_gate(&proof, end)?;
    let commit_started = AtomicBool::new(false);
    let wait_end = end.min(proof.authentication_expiry().1);
    let outcome = tokio::time::timeout_at(wait_end.into(), async {
        let mut guard = ConnectionGuard(Some(store.pool.acquire().await.map_err(storage_error)?));
        let mut tx = guard
            .connection()?
            .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            .await
            .map_err(storage_error)?;
        let (profile, principal, roles, permissions) = observe_local_session(
            &mut tx,
            store,
            &proof,
            limits,
            SystemAction::SessionRead,
            end,
        )
        .await?;
        commit_started.store(true, Ordering::Relaxed);
        tx.commit()
            .await
            .map_err(|_| ControlError::OutcomeUncertain)?;
        guard.confirmed();
        Ok((profile, principal, roles, permissions))
    })
    .await
    .unwrap_or_else(|_| Err(Error::Control(timeout_error(&commit_started))));
    // The actual COMMIT ambiguity is never relabelled as rollback, expiry or timeout.
    if matches!(outcome, Err(Error::Control(ControlError::OutcomeUncertain))) {
        return Err(ControlError::OutcomeUncertain.into());
    }
    final_gate(&proof, end)?;
    let (profile, principal, roles, permissions) = outcome?;
    Ok((profile, principal, roles, permissions))
}
pub(super) type LocalSessionData = (
    SessionProfile,
    SessionPrincipal,
    Vec<String>,
    Vec<SystemPermission>,
);
pub(super) async fn observe_local_session(
    connection: &mut sqlx_postgres::PgConnection,
    store: &PostgresControlStore,
    proof: &LocalAdminProof<'_, '_>,
    limits: AdminBrokerSessionLimits,
    action: SystemAction,
    end: Instant,
) -> Result<LocalSessionData, Error> {
    final_gate(proof, end)?;
    let username = proof.username(limits)?;
    let mut data = None;
    let mut roles = BTreeSet::new();
    let mut permissions = Vec::new();
    {
        let mut stream = sqlx_core::query::query(SELECT)
            .bind(limits.identity.username_bytes.get() as i64)
            .bind(limits.identity.subject_bytes.get() as i64)
            .bind(limits.identity.role_bytes.get() as i64)
            .bind(limits.profile_json_bytes.get() as i64)
            .bind(&username)
            .bind((limits.identity.rows.get() + 1) as i64)
            .fetch(&mut *connection);
        let mut count = 0usize;
        while let Some(row) = stream.try_next().await.map_err(storage_error)? {
            count += 1;
            if count > limits.identity.rows.get() {
                return Err(ControlError::IdentityLimitExceeded.into());
            }
            proof.check()?;
            let text = |index| {
                row.try_get::<Option<&str>, _>(index)
                    .map_err(|_| ControlError::CorruptIdentity)?
                    .ok_or(ControlError::CorruptIdentity)
            };
            // Profile fields repeat in the join, but are decoded/allocated only once.
            if data.is_none() {
                let current_username = text(0)?;
                let subject = text(1)?;
                let kind = text(2)?;
                let enabled: i64 = row.try_get(3).map_err(|_| ControlError::CorruptIdentity)?;
                let revision: i64 = row.try_get(4).map_err(|_| ControlError::CorruptIdentity)?;
                if current_username != username
                    || !safe_identity_segment(
                        current_username,
                        limits.identity.username_bytes.get(),
                    )
                    || !valid_identity_subject(subject, limits.identity.subject_bytes.get())
                    || !matches!(kind, "human" | "service")
                    || !matches!(enabled, 0 | 1)
                    || revision < 1
                {
                    return Err(ControlError::CorruptIdentity.into());
                }
                proof.bind(store, subject, kind, enabled, revision)?;
                if matches!(
                    proof,
                    LocalAdminProof::Login(_, _) | LocalAdminProof::Cookie(_, _)
                ) {
                    let password_change: i64 =
                        row.try_get(13).map_err(|_| ControlError::CorruptIdentity)?;
                    if !matches!(password_change, 0 | 1) {
                        return Err(ControlError::CorruptIdentity.into());
                    }
                    if password_change != 0 {
                        return Err(proof.identity_unavailable());
                    }
                }
                let profile_field = |index| -> Result<String, ControlError> {
                    let value = text(index)?;
                    if value.chars().count() > 512 {
                        return Err(ControlError::CorruptIdentity);
                    }
                    Ok(value.to_owned())
                };
                let teams: Vec<String> =
                    serde_json::from_str(text(8)?).map_err(|_| ControlError::CorruptIdentity)?;
                let teams: Vec<String> = teams
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let profile = SessionProfile {
                    subject: subject.to_owned(),
                    name: profile_field(5)?,
                    email: profile_field(6)?,
                };
                let principal = SessionPrincipal {
                    issuer: "local".into(),
                    username: current_username.to_owned(),
                    organization: profile_field(7)?,
                    teams,
                    local_user_revision: revision,
                };
                let encoded = serde_json::to_vec(&ProfileProjection {
                    subject: &profile.subject,
                    username: &principal.username,
                    name: &profile.name,
                    email: &profile.email,
                    organization: &principal.organization,
                    teams: &principal.teams,
                })
                .map_err(|_| ControlError::CorruptIdentity)?;
                if encoded.len() > limits.profile_json_bytes.get() {
                    return Err(ControlError::IdentityLimitExceeded.into());
                }
                data = Some((profile, principal));
            }
            let role_present: bool = row.try_get(11).map_err(|_| ControlError::CorruptRbac)?;
            let action_present: bool = row.try_get(12).map_err(|_| ControlError::CorruptRbac)?;
            let role = row
                .try_get::<Option<&str>, _>(9)
                .map_err(|_| ControlError::CorruptRbac)?
                .ok_or(ControlError::CorruptRbac)?;
            if !role_present || !safe_identity_segment(role, limits.identity.role_bytes.get()) {
                return Err(ControlError::CorruptRbac.into());
            }
            if !roles.contains(role) {
                if roles.len() >= limits.identity.roles.get() {
                    return Err(ControlError::IdentityLimitExceeded.into());
                }
                roles.insert(role.to_owned());
            }
            let action = row
                .try_get::<Option<&str>, _>(10)
                .map_err(|_| ControlError::CorruptRbac)?;
            match (action_present, action) {
                (false, None) => {}
                (true, Some(action)) => {
                    let permission =
                        SystemPermission::stored(action).ok_or(ControlError::CorruptRbac)?;
                    if !permissions.contains(&permission) {
                        permissions.push(permission);
                    }
                }
                _ => return Err(ControlError::CorruptRbac.into()),
            }
        }
    }
    let (profile, principal) = data.ok_or_else(|| proof.identity_unavailable())?;
    if !permissions.contains(&SystemPermission::All)
        && !permissions.contains(&SystemPermission::Action(action))
    {
        return Err(Error::Forbidden);
    }
    permissions.sort_unstable_by_key(|p| p.as_str());
    proof.check()?;
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    Ok((profile, principal, roles.into_iter().collect(), permissions))
}

fn final_gate(proof: &LocalAdminProof<'_, '_>, end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    proof.check()?;
    Ok(())
}
