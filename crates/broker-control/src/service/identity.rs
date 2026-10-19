use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    ControlError, IdentityReadLimits, LocalIdentityKind, LocalIdentityRead, LocalIdentityReference,
    LocalIdentitySnapshot, LocalIdentityUnavailable, SystemPermission,
    identity::{safe_identity_segment, valid_identity_subject},
};
use futures_util::TryStreamExt;
use sqlx_core::{connection::Connection, row::Row};
use std::{
    collections::BTreeSet,
    fmt,
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const IDENTITY_SELECT: &str = "SELECT CASE WHEN pg_catalog.octet_length(u.username)::bigint<=$1 THEN u.username END,CASE WHEN pg_catalog.octet_length(u.subject)::bigint<=$2 THEN u.subject END,CASE WHEN pg_catalog.octet_length(u.identity_kind)<=16 THEN u.identity_kind END,u.enabled::bigint,u.revision,CASE WHEN pg_catalog.octet_length(a.role)::bigint<=$3 THEN a.role END,CASE WHEN pg_catalog.octet_length(p.action)<=128 THEN p.action END,a.role IS NOT NULL,p.role IS NOT NULL FROM public.local_users u LEFT JOIN (SELECT role FROM public.role_assignments WHERE subject=$4 UNION SELECT 'user' AS role) a ON TRUE LEFT JOIN public.roles r ON r.name=a.role LEFT JOIN public.role_permissions p ON p.role=r.name WHERE u.username=$5 ORDER BY a.role,p.action LIMIT $6";

/// A data-only reader borrowed from the existing PostgreSQL control owner.
pub struct PostgresLocalIdentities<'a> {
    owner: &'a PostgresControlStore,
    limits: IdentityReadLimits,
}
impl fmt::Debug for PostgresLocalIdentities<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresLocalIdentities([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn local_identities(
        &self,
        mut limits: IdentityReadLimits,
    ) -> Result<PostgresLocalIdentities<'_>, ControlError> {
        limits.validate().map_err(|_| ControlError::Configuration)?;
        row_limit(limits.rows)?;
        let bound = |value: NonZeroUsize, cap: usize| {
            NonZeroUsize::new(value.get().min(cap)).ok_or(ControlError::Configuration)
        };
        limits.username_bytes = bound(limits.username_bytes, 128)?;
        limits.subject_bytes = bound(limits.subject_bytes, 512)?;
        limits.role_bytes = bound(limits.role_bytes, 128)?;
        Ok(PostgresLocalIdentities {
            owner: self,
            limits,
        })
    }
}
fn row_limit(rows: NonZeroUsize) -> Result<i64, ControlError> {
    rows.get()
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(ControlError::Configuration)
}
struct FetchedIdentity {
    username: String,
    subject: String,
    kind: LocalIdentityKind,
    enabled: bool,
    revision: i64,
}
impl PostgresLocalIdentities<'_> {
    /// Revalidate a reference whose consumer has already authenticated its local caller.
    /// The returned SQL snapshot does not confer authentication or a policy lease.
    pub async fn read(
        &self,
        reference: &LocalIdentityReference<'_>,
        caller: Instant,
    ) -> Result<LocalIdentityRead, ControlError> {
        let end = bounded_deadline(caller, self.owner.budgets.operation_timeout)?;
        reference
            .validate(&self.limits)
            .map_err(|_| ControlError::InvalidIdentity)?;
        let canonical = format!("local|{}", reference.subject());
        let limit = row_limit(self.limits.rows)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.owner.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
                .await
                .map_err(storage_error)?;
            let mut fetched = None::<FetchedIdentity>;
            let mut roles = BTreeSet::<String>::new();
            let mut permissions = Vec::<SystemPermission>::new();
            {
                let query = sqlx_core::query::query(IDENTITY_SELECT)
                    .bind(self.limits.username_bytes.get() as i64)
                    .bind(self.limits.subject_bytes.get() as i64)
                    .bind(self.limits.role_bytes.get() as i64)
                    .bind(&canonical)
                    .bind(reference.username())
                    .bind(limit);
                let mut stream = query.fetch(&mut *tx);
                let mut rows = 0usize;
                while let Some(row) = stream.try_next().await.map_err(storage_error)? {
                    rows += 1;
                    if rows > self.limits.rows.get() {
                        return Err(ControlError::IdentityLimitExceeded);
                    }
                    let identity_text = |index| -> Result<&str, ControlError> {
                        row.try_get::<Option<&str>, _>(index)
                            .map_err(|_| ControlError::CorruptIdentity)?
                            .ok_or(ControlError::CorruptIdentity)
                    };
                    let username = identity_text(0)?;
                    let subject = identity_text(1)?;
                    let kind = match identity_text(2)? {
                        "human" => LocalIdentityKind::Human,
                        "service" => LocalIdentityKind::Service,
                        _ => return Err(ControlError::CorruptIdentity),
                    };
                    let enabled = row
                        .try_get::<i64, _>(3)
                        .map_err(|_| ControlError::CorruptIdentity)?;
                    let revision = row
                        .try_get::<i64, _>(4)
                        .map_err(|_| ControlError::CorruptIdentity)?;
                    if !safe_identity_segment(username, self.limits.username_bytes.get())
                        || username != reference.username()
                        || !valid_identity_subject(subject, self.limits.subject_bytes.get())
                        || !matches!(enabled, 0 | 1)
                        || revision < 1
                    {
                        return Err(ControlError::CorruptIdentity);
                    }
                    if let Some(first) = &fetched {
                        if first.username != username
                            || first.subject != subject
                            || first.kind != kind
                            || first.enabled != (enabled == 1)
                            || first.revision != revision
                        {
                            return Err(ControlError::CorruptIdentity);
                        }
                    } else {
                        fetched = Some(FetchedIdentity {
                            username: username.to_owned(),
                            subject: subject.to_owned(),
                            kind,
                            enabled: enabled == 1,
                            revision,
                        });
                    }
                    let role_present = row
                        .try_get::<bool, _>(7)
                        .map_err(|_| ControlError::CorruptRbac)?;
                    let action_present = row
                        .try_get::<bool, _>(8)
                        .map_err(|_| ControlError::CorruptRbac)?;
                    let role = row
                        .try_get::<Option<&str>, _>(5)
                        .map_err(|_| ControlError::CorruptRbac)?
                        .ok_or(ControlError::CorruptRbac)?;
                    if !role_present || !safe_identity_segment(role, self.limits.role_bytes.get()) {
                        return Err(ControlError::CorruptRbac);
                    }
                    if !roles.contains(role) {
                        if roles.len() == self.limits.roles.get() {
                            return Err(ControlError::IdentityLimitExceeded);
                        }
                        roles.insert(role.to_owned());
                    }
                    let action = row
                        .try_get::<Option<&str>, _>(6)
                        .map_err(|_| ControlError::CorruptRbac)?;
                    match (action_present, action) {
                        (false, None) => {}
                        (true, Some(action)) => {
                            let permission = SystemPermission::stored(action)
                                .ok_or(ControlError::CorruptRbac)?;
                            if !permissions.contains(&permission) {
                                permissions.push(permission);
                            }
                        }
                        _ => return Err(ControlError::CorruptRbac),
                    }
                }
            }
            permissions.sort_unstable_by_key(|permission| permission.as_str());
            let result = match fetched {
                None => LocalIdentityRead::Unavailable(LocalIdentityUnavailable::Missing),
                Some(value) if !value.enabled => {
                    LocalIdentityRead::Unavailable(LocalIdentityUnavailable::Disabled)
                }
                Some(value) if value.subject != reference.subject() => {
                    LocalIdentityRead::Unavailable(LocalIdentityUnavailable::SubjectChanged)
                }
                Some(value) if value.revision != reference.revision() => {
                    LocalIdentityRead::Unavailable(LocalIdentityUnavailable::RevisionChanged)
                }
                Some(value) => LocalIdentityRead::Current(LocalIdentitySnapshot {
                    username: value.username,
                    subject: value.subject,
                    kind: value.kind,
                    revision: value.revision,
                    roles: roles.into_iter().collect(),
                    permissions,
                }),
            };
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok(result)
        })
        .await
        .map_err(|_| timeout_error(&commit_started))?
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn postgres_identity_limit_requires_signed_limit_sentinel() {
        assert_eq!(row_limit(NonZeroUsize::new(1).unwrap()), Ok(2));
        assert_eq!(
            row_limit(NonZeroUsize::MAX),
            Err(ControlError::Configuration)
        );
    }
    #[test]
    fn postgres_identity_projection_excludes_credentials_and_errors_are_finite() {
        for excluded in [
            "password_hash",
            "teams_json",
            "email",
            "organization",
            "FOR UPDATE",
        ] {
            assert!(!IDENTITY_SELECT.contains(excluded));
        }
        assert!(IDENTITY_SELECT.contains("a.role IS NOT NULL,p.role IS NOT NULL"));
        for (error, message) in [
            (
                ControlError::InvalidIdentity,
                "invalid local identity reference",
            ),
            (
                ControlError::CorruptIdentity,
                "corrupt local identity metadata",
            ),
            (ControlError::CorruptRbac, "corrupt system role metadata"),
            (
                ControlError::IdentityLimitExceeded,
                "local identity read limit exceeded",
            ),
        ] {
            assert_eq!(error.to_string(), message);
        }
    }
}
