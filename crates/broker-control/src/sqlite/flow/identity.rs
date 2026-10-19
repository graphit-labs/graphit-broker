use super::SqliteControlStore;
use crate::{
    ControlError, IdentityReadLimits, LocalIdentityKind, LocalIdentityRead, LocalIdentityReference,
    LocalIdentitySnapshot, LocalIdentityUnavailable, SystemPermission,
    identity::{safe_identity_segment, valid_identity_subject},
    sqlite::executor::Work,
};
use rusqlite::{Transaction, params};
use std::{collections::BTreeSet, fmt, num::NonZeroUsize, time::Instant};

const IDENTITY_SELECT: &str = "SELECT CASE WHEN length(CAST(u.username AS BLOB))<=?1 THEN u.username END,CASE WHEN length(CAST(u.subject AS BLOB))<=?2 THEN u.subject END,CASE WHEN length(CAST(u.identity_kind AS BLOB))<=16 THEN u.identity_kind END,u.enabled,u.revision,CASE WHEN length(CAST(a.role AS BLOB))<=?3 THEN a.role END,CASE WHEN length(CAST(p.action AS BLOB))<=128 THEN p.action END,a.role IS NOT NULL,p.role IS NOT NULL FROM local_users u LEFT JOIN (SELECT role FROM role_assignments WHERE subject=?4 UNION SELECT 'user' AS role) a ON TRUE LEFT JOIN roles r ON r.name=a.role LEFT JOIN role_permissions p ON p.role=r.name WHERE u.username=?5 ORDER BY a.role COLLATE BINARY,p.action COLLATE BINARY LIMIT ?6";

/// Borrowed current SQL identity data, never authentication or an authorization lease.
/// A view cannot outlive its store.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore, limits: broker_control::IdentityReadLimits)
///     -> broker_control::SqliteLocalIdentities<'static> { store.local_identities(limits).unwrap() }
/// ```
pub struct SqliteLocalIdentities<'a> {
    owner: &'a SqliteControlStore,
    limits: IdentityReadLimits,
}
impl fmt::Debug for SqliteLocalIdentities<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalIdentities([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn local_identities(
        &self,
        mut limits: IdentityReadLimits,
    ) -> Result<SqliteLocalIdentities<'_>, ControlError> {
        limits.validate().map_err(|_| ControlError::Configuration)?;
        row_limit(limits.rows)?;
        limits.username_bytes = NonZeroUsize::new(limits.username_bytes.get().min(128))
            .ok_or(ControlError::Configuration)?;
        limits.subject_bytes = NonZeroUsize::new(limits.subject_bytes.get().min(512))
            .ok_or(ControlError::Configuration)?;
        limits.role_bytes = NonZeroUsize::new(limits.role_bytes.get().min(128))
            .ok_or(ControlError::Configuration)?;
        Ok(SqliteLocalIdentities {
            owner: self,
            limits,
        })
    }
}
fn row_limit(rows: NonZeroUsize) -> Result<i64, ControlError> {
    rows.get()
        .checked_add(1)
        .and_then(|n| i64::try_from(n).ok())
        .ok_or(ControlError::Configuration)
}
impl SqliteLocalIdentities<'_> {
    pub async fn read(
        &self,
        reference: &LocalIdentityReference<'_>,
        caller: Instant,
    ) -> Result<LocalIdentityRead, ControlError> {
        reference
            .validate(&self.limits)
            .map_err(|_| ControlError::InvalidIdentity)?;
        let username = reference.username().to_owned();
        let subject = reference.subject().to_owned();
        let revision = reference.revision();
        let limits = self.limits;
        self.owner
            .executor
            .execute(caller, move |owner, work| {
                let tx = owner.begin(work)?;
                let result = read_identity(&tx, work, &username, &subject, revision, limits);
                match result {
                    Ok(value) => {
                        work.commit(tx)?;
                        Ok(Ok(value))
                    }
                    Err(error) => {
                        work.check()?;
                        Ok(Err(error))
                    }
                }
            })
            .await
            .map_err(ControlError::from)?
    }
}
struct FetchedIdentity {
    username: String,
    subject: String,
    kind: LocalIdentityKind,
    enabled: bool,
    revision: i64,
}
fn read_identity(
    tx: &Transaction<'_>,
    work: &Work,
    username: &str,
    subject: &str,
    revision: i64,
    limits: IdentityReadLimits,
) -> Result<LocalIdentityRead, ControlError> {
    let canonical = format!("local|{subject}");
    let mut statement = tx
        .prepare(IDENTITY_SELECT)
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let mut rows = statement
        .query(params![
            limits.username_bytes.get() as i64,
            limits.subject_bytes.get() as i64,
            limits.role_bytes.get() as i64,
            canonical,
            username,
            row_limit(limits.rows)?
        ])
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let mut fetched = None::<FetchedIdentity>;
    let mut roles = BTreeSet::<String>::new();
    let mut permissions = Vec::<SystemPermission>::new();
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(|e| ControlError::from(work.sql(e)))? {
        work.check().map_err(ControlError::from)?;
        count += 1;
        if count > limits.rows.get() {
            return Err(ControlError::IdentityLimitExceeded);
        }
        let text = |index| {
            row.get_ref(index)
                .map_err(|_| ControlError::CorruptIdentity)?
                .as_str()
                .map_err(|_| ControlError::CorruptIdentity)
        };
        let found_username = text(0)?;
        let found_subject = text(1)?;
        let kind = match text(2)? {
            "human" => LocalIdentityKind::Human,
            "service" => LocalIdentityKind::Service,
            _ => return Err(ControlError::CorruptIdentity),
        };
        let enabled: i64 = row.get(3).map_err(|_| ControlError::CorruptIdentity)?;
        let found_revision: i64 = row.get(4).map_err(|_| ControlError::CorruptIdentity)?;
        if !safe_identity_segment(found_username, limits.username_bytes.get())
            || found_username != username
            || !valid_identity_subject(found_subject, limits.subject_bytes.get())
            || !matches!(enabled, 0 | 1)
            || found_revision < 1
        {
            return Err(ControlError::CorruptIdentity);
        }
        if let Some(first) = &fetched {
            if first.username != found_username
                || first.subject != found_subject
                || first.kind != kind
                || first.enabled != (enabled == 1)
                || first.revision != found_revision
            {
                return Err(ControlError::CorruptIdentity);
            }
        } else {
            fetched = Some(FetchedIdentity {
                username: found_username.to_owned(),
                subject: found_subject.to_owned(),
                kind,
                enabled: enabled == 1,
                revision: found_revision,
            });
        }
        let role_present: bool = row.get(7).map_err(|_| ControlError::CorruptRbac)?;
        let action_present: bool = row.get(8).map_err(|_| ControlError::CorruptRbac)?;
        let role = row
            .get_ref(5)
            .map_err(|_| ControlError::CorruptRbac)?
            .as_str()
            .map_err(|_| ControlError::CorruptRbac)?;
        if !role_present || !safe_identity_segment(role, limits.role_bytes.get()) {
            return Err(ControlError::CorruptRbac);
        }
        if !roles.contains(role) {
            if roles.len() == limits.roles.get() {
                return Err(ControlError::IdentityLimitExceeded);
            }
            roles.insert(role.to_owned());
        }
        let action = row
            .get::<_, Option<String>>(6)
            .map_err(|_| ControlError::CorruptRbac)?;
        match (action_present, action) {
            (false, None) => {}
            (true, Some(action)) => {
                let permission =
                    SystemPermission::stored(&action).ok_or(ControlError::CorruptRbac)?;
                if !permissions.contains(&permission) {
                    permissions.push(permission);
                }
            }
            _ => return Err(ControlError::CorruptRbac),
        }
    }
    permissions.sort_unstable_by_key(|p| p.as_str());
    Ok(match fetched {
        None => LocalIdentityRead::Unavailable(LocalIdentityUnavailable::Missing),
        Some(value) if !value.enabled => {
            LocalIdentityRead::Unavailable(LocalIdentityUnavailable::Disabled)
        }
        Some(value) if value.subject != subject => {
            LocalIdentityRead::Unavailable(LocalIdentityUnavailable::SubjectChanged)
        }
        Some(value) if value.revision != revision => {
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
    })
}
