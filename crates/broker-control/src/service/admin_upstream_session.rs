use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    AdminBrokerSessionError as Error, AdminBrokerSessionLimits, AdminUpstreamSession,
    BrokerAccessError, ControlError, SystemAction, SystemPermission, UpstreamBearerVerifier,
    identity::safe_identity_segment, upstream_oidc::VerifiedUpstreamBearer,
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

// Current assignments (only when claims are not authoritative) and definitions
// share one statement snapshot. No local_users/profile row authenticates an issuer.
const SELECT: &str = r#"WITH selected AS (
 SELECT role FROM public.role_assignments WHERE subject=$1 AND $2::text[] IS NULL
 UNION SELECT unnest($2::text[]) UNION SELECT 'user'
 ) SELECT CASE WHEN octet_length(s.role)::bigint<=$3 THEN s.role END,
 CASE WHEN octet_length(p.action)<=128 THEN p.action END,p.role IS NOT NULL
 FROM selected s LEFT JOIN public.roles r ON r.name=s.role
 LEFT JOIN public.role_permissions p ON p.role=r.name ORDER BY s.role,p.action LIMIT $4"#;
#[derive(Serialize)]
struct ProfileProjection<'a> {
    subject: &'a str,
    issuer: &'a str,
    username: &'a str,
    name: &'a str,
    email: &'a str,
    organization: &'a str,
    teams: &'a [String],
}
pub struct PostgresAdminUpstreamSessions<'s, 'v> {
    store: &'s PostgresControlStore,
    verifier: &'v UpstreamBearerVerifier,
    limits: AdminBrokerSessionLimits,
}
impl fmt::Debug for PostgresAdminUpstreamSessions<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresAdminUpstreamSessions([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn admin_upstream_sessions<'s, 'v>(
        &'s self,
        verifier: &'v UpstreamBearerVerifier,
        limits: AdminBrokerSessionLimits,
    ) -> Result<PostgresAdminUpstreamSessions<'s, 'v>, ControlError> {
        limits.validate()?;
        Ok(PostgresAdminUpstreamSessions {
            store: self,
            verifier,
            limits,
        })
    }
}
fn gate(proof: &VerifiedUpstreamBearer, end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    proof.check()
}
pub(super) async fn observe_upstream_roles(
    connection: &mut sqlx_postgres::PgConnection,
    subject: &str,
    claim_roles: Option<&[String]>,
    limits: AdminBrokerSessionLimits,
    action: SystemAction,
    mut gate: impl FnMut() -> Result<(), Error>,
) -> Result<(Vec<String>, Vec<SystemPermission>), Error> {
    let l = limits.identity;
    gate()?;
    let mut roles = BTreeSet::new();
    let mut permissions = Vec::new();
    {
        let mut stream = sqlx_core::query::query(SELECT)
            .bind(subject)
            .bind(claim_roles)
            .bind(l.role_bytes.get() as i64)
            .bind((l.rows.get() + 1) as i64)
            .fetch(&mut *connection);
        let mut count = 0usize;
        while let Some(row) = stream.try_next().await.map_err(storage_error)? {
            count += 1;
            if count > l.rows.get() {
                return Err(ControlError::IdentityLimitExceeded.into());
            }
            gate()?;
            let role: Option<&str> = row.try_get(0).map_err(|_| ControlError::CorruptRbac)?;
            let role = role
                .filter(|r| safe_identity_segment(r, l.role_bytes.get()))
                .ok_or(ControlError::CorruptRbac)?;
            roles.insert(role.to_owned());
            if roles.len() > l.roles.get() {
                return Err(ControlError::IdentityLimitExceeded.into());
            }
            let has_permission: bool = row.try_get(2).map_err(|_| ControlError::CorruptRbac)?;
            if has_permission {
                let action: Option<&str> = row.try_get(1).map_err(|_| ControlError::CorruptRbac)?;
                let permission = action
                    .and_then(SystemPermission::stored)
                    .ok_or(ControlError::CorruptRbac)?;
                if !permissions.contains(&permission) {
                    permissions.push(permission);
                }
            }
        }
    }
    gate()?;
    if !permissions.contains(&SystemPermission::All)
        && !permissions.contains(&SystemPermission::Action(action))
    {
        return Err(Error::Forbidden);
    }
    permissions.sort_unstable_by_key(|p| p.as_str());
    Ok((roles.into_iter().collect(), permissions))
}
impl PostgresAdminUpstreamSessions<'_, '_> {
    pub async fn read(&self, raw: &str, original: Instant) -> Result<AdminUpstreamSession, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let proof = self.verifier.verify(raw, end).await?;
        gate(&proof, end)?;
        validate_profile(&proof, self.limits, end)?;
        let subject = format!("{}|{}", proof.issuer(), proof.profile().subject);
        let commit_started = AtomicBool::new(false);
        let wait = end.min(proof.expires_mono());
        let outcome = tokio::time::timeout_at(wait.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
                .await
                .map_err(storage_error)?;
            let (roles, permissions) = observe_upstream_roles(
                &mut tx,
                &subject,
                proof.claim_roles(),
                self.limits,
                SystemAction::SessionRead,
                || gate(&proof, end),
            )
            .await?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok((roles, permissions))
        })
        .await
        .unwrap_or_else(|_| Err(Error::Control(timeout_error(&commit_started))));
        if matches!(outcome, Err(Error::Control(ControlError::OutcomeUncertain))) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        gate(&proof, end)?;
        let (roles, permissions) = outcome?;
        let result = AdminUpstreamSession {
            proof,
            original,
            roles,
            permissions,
        };
        result.check()?;
        Ok(result)
    }
}

pub(crate) fn validate_profile(
    proof: &VerifiedUpstreamBearer,
    limits: AdminBrokerSessionLimits,
    end: Instant,
) -> Result<(), Error> {
    let l = limits.identity;
    let profile = proof.profile();
    let bytes = serde_json::to_vec(&ProfileProjection {
        subject: &profile.subject,
        issuer: proof.issuer(),
        username: proof.username(),
        name: &profile.name,
        email: &profile.email,
        organization: proof.organization(),
        teams: proof.teams(),
    })
    .map_err(|_| ControlError::CorruptIdentity)?;
    gate(proof, end)?;
    if bytes.len() > limits.profile_json_bytes.get() {
        return Err(ControlError::IdentityLimitExceeded.into());
    }
    if proof.profile().subject.len() > l.subject_bytes.get()
        || proof.username().len() > l.username_bytes.get()
        || proof.claim_roles().is_some_and(|r| {
            r.len() > l.roles.get()
                || r.iter()
                    .any(|r| !safe_identity_segment(r, l.role_bytes.get()))
        })
    {
        return Err(BrokerAccessError::InvalidToken.into());
    }
    Ok(())
}
