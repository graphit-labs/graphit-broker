use super::super::{
    MySqlControlError, RequiredCapability, Result,
    bootstrap::CommitState,
    capability::{Operation, identity_select},
    config,
    executor::native_error,
};
use super::MySqlControlStore;
use crate::{
    IdentityReadLimits, LocalIdentityKind, LocalIdentityRead, LocalIdentityReference,
    LocalIdentitySnapshot, LocalIdentityUnavailable, SystemPermission,
    identity::{safe_identity_segment, valid_identity_subject},
};
use futures_util::TryStreamExt;
use sqlx_core::{row::Row, sql_str::AssertSqlSafe};
use std::{fmt, num::NonZeroUsize, time::Instant};

pub struct MySqlLocalIdentities<'a> {
    owner: &'a MySqlControlStore,
    limits: IdentityReadLimits,
}
impl fmt::Debug for MySqlLocalIdentities<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MySqlLocalIdentities([REDACTED])")
    }
}
impl MySqlControlStore {
    pub fn local_identities(
        &self,
        mut limits: IdentityReadLimits,
    ) -> Result<MySqlLocalIdentities<'_>> {
        limits
            .validate()
            .map_err(|_| MySqlControlError::Configuration)?;
        let bound = |value: NonZeroUsize, cap: usize| {
            NonZeroUsize::new(value.get().min(cap)).ok_or(MySqlControlError::Configuration)
        };
        limits.username_bytes = bound(limits.username_bytes, 128)?;
        limits.subject_bytes = bound(limits.subject_bytes, 512)?;
        limits.role_bytes = bound(limits.role_bytes, 128)?;
        limits.rows = bound(limits.rows, self.config.catalog.rows_per_category.get())?;
        Ok(MySqlLocalIdentities {
            owner: self,
            limits,
        })
    }
}
struct FetchedIdentity {
    username: String,
    subject: String,
    kind: LocalIdentityKind,
    enabled: bool,
    revision: i64,
}
impl FetchedIdentity {
    fn matches(&self, other: &Self) -> bool {
        self.username == other.username
            && self.subject == other.subject
            && self.kind == other.kind
            && self.enabled == other.enabled
            && self.revision == other.revision
    }
}
impl MySqlLocalIdentities<'_> {
    /// Revalidates only a reference from a consumer that already authenticated its caller.
    /// Returned permissions are a fetched SQL snapshot, never an authentication or policy lease.
    pub async fn read(
        &self,
        reference: &LocalIdentityReference<'_>,
        caller: Instant,
    ) -> Result<LocalIdentityRead> {
        let end = config::deadline(caller, self.owner.config.admission.budgets.operation)?;
        reference
            .validate(&self.limits)
            .map_err(|_| MySqlControlError::InvalidIdentity)?;
        let canonical = format!("local|{}", reference.subject());
        let limit = u64::try_from(
            self.limits
                .rows
                .get()
                .checked_add(1)
                .ok_or(MySqlControlError::Configuration)?,
        )
        .map_err(|_| MySqlControlError::Configuration)?;
        let username_cap = u64::try_from(self.limits.username_bytes.get())
            .map_err(|_| MySqlControlError::Configuration)?;
        let subject_cap = u64::try_from(self.limits.subject_bytes.get())
            .map_err(|_| MySqlControlError::Configuration)?;
        let role_cap = u64::try_from(self.limits.role_bytes.get())
            .map_err(|_| MySqlControlError::Configuration)?;
        let commit = CommitState::new();
        tokio::time::timeout_at(end.into(),async {
            let mut lease=self.owner.operation(end,Operation::ReadLocalIdentity).await?;
            let database=config::identifier(&lease.observation.database,lease.work.limits.statement_bytes.get())?;
            let sql=identity_select(&database,false);
            lease.work.statement(&sql)?;
            let mut fetched=None::<FetchedIdentity>;
            let mut roles=Vec::<String>::new();
            let mut permissions=Vec::<SystemPermission>::new();
            {
                let query=sqlx_core::query::query(AssertSqlSafe(sql))
                    .bind(username_cap).bind(subject_cap).bind(role_cap).bind(&canonical)
                    .bind(reference.username()).bind(limit);
                let mut stream=query.fetch(&mut lease.connection);
                let mut rows=0usize;
                while let Some(row)=stream.try_next().await.map_err(|error| native_error(&error,RequiredCapability::Select))? {
                    rows=rows.checked_add(1).ok_or(MySqlControlError::IdentityLimitExceeded)?;
                    if rows>self.limits.rows.get() { return Err(MySqlControlError::IdentityLimitExceeded); }
                    // Scalar bytes come from actual native fields, not a type-size estimate.
                    for index in [3,4,7,8] {
                        let raw=row.try_get_unchecked::<Option<&[u8]>,_>(index)
                            .map_err(|_|MySqlControlError::CorruptIdentity)?
                            .ok_or(MySqlControlError::CorruptIdentity)?;
                        lease.work.bytes(raw.len())?;
                    }
                    let username=lease.work.text(&row,0,self.limits.username_bytes.get())?.ok_or(MySqlControlError::CorruptIdentity)?;
                    let subject=lease.work.text(&row,1,self.limits.subject_bytes.get())?.ok_or(MySqlControlError::CorruptIdentity)?;
                    let kind=lease.work.text(&row,2,16)?.ok_or(MySqlControlError::CorruptIdentity)?;
                    let enabled=row.try_get::<i64,_>(3).map_err(|_|MySqlControlError::CorruptIdentity)?;
                    let revision=row.try_get::<i64,_>(4).map_err(|_|MySqlControlError::CorruptIdentity)?;
                    if !safe_identity_segment(&username,self.limits.username_bytes.get())
                        || username!=reference.username()
                        || !valid_identity_subject(&subject,self.limits.subject_bytes.get())
                        || !matches!(enabled,0|1) || revision<1
                    { return Err(MySqlControlError::CorruptIdentity); }
                    let kind=match kind.as_str() {
                        "human"=>LocalIdentityKind::Human,"service"=>LocalIdentityKind::Service,
                        _=>return Err(MySqlControlError::CorruptIdentity),
                    };
                    let current=FetchedIdentity { username,subject,kind,enabled:enabled==1,revision };
                    if let Some(first)=&fetched {
                        if !first.matches(&current) { return Err(MySqlControlError::CorruptIdentity); }
                    } else { fetched=Some(current); }
                    let role_present=row.try_get::<i64,_>(7).map_err(|_|MySqlControlError::CorruptRbac)?;
                    let action_present=row.try_get::<i64,_>(8).map_err(|_|MySqlControlError::CorruptRbac)?;
                    if role_present!=1 || !matches!(action_present,0|1) { return Err(MySqlControlError::CorruptRbac); }
                    let role=lease.work.text(&row,5,self.limits.role_bytes.get())?.ok_or(MySqlControlError::CorruptRbac)?;
                    if !safe_identity_segment(&role,self.limits.role_bytes.get()) { return Err(MySqlControlError::CorruptRbac); }
                    if !roles.contains(&role) {
                        if roles.len()==self.limits.roles.get() { return Err(MySqlControlError::IdentityLimitExceeded); }
                        roles.push(role);
                    }
                    let action=lease.work.text(&row,6,128)?;
                    match (action_present,action) {
                        (0,None)=>{},
                        (1,Some(action))=>{
                            let permission=SystemPermission::stored(&action).ok_or(MySqlControlError::CorruptRbac)?;
                            if !permissions.contains(&permission) { permissions.push(permission); }
                        },
                        _=>return Err(MySqlControlError::CorruptRbac),
                    }
                }
            }
            roles.sort_unstable();
            permissions.sort_unstable_by_key(|permission|permission.as_str());
            let result=match fetched {
                None=>LocalIdentityRead::Unavailable(LocalIdentityUnavailable::Missing),
                Some(value) if !value.enabled=>LocalIdentityRead::Unavailable(LocalIdentityUnavailable::Disabled),
                Some(value) if value.subject!=reference.subject()=>LocalIdentityRead::Unavailable(LocalIdentityUnavailable::SubjectChanged),
                Some(value) if value.revision!=reference.revision()=>LocalIdentityRead::Unavailable(LocalIdentityUnavailable::RevisionChanged),
                Some(value)=>LocalIdentityRead::Current(LocalIdentitySnapshot { username:value.username,subject:value.subject,kind:value.kind,revision:value.revision,roles,permissions }),
            };
            tracing::trace!(target:"broker_control::mysql::identity_snapshot_fetched","local identity SQL snapshot fetched");
            lease.unchanged().await?;
            tracing::trace!(target:"broker_control::mysql::identity_commit_starting","local identity read commit starting");
            commit.commit(&mut lease).await?;
            drop(lease);
            Ok(result)
        }).await.map_err(|_|commit.timeout(false))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_projection_is_closed_and_shared_with_probe() {
        let sql = identity_select("`db`", false);
        let probe = identity_select("`db`", true);
        for source in [&sql, &probe] {
            for name in [
                "local_users",
                "role_assignments",
                "roles",
                "role_permissions",
            ] {
                assert!(source.contains(&format!("`db`.`{name}`")));
            }
            for excluded in [
                "password_hash",
                "teams_json",
                "email",
                "organization",
                "name,",
                "FOR UPDATE",
                "INSERT",
                "DELETE",
            ] {
                assert!(!source.contains(excluded));
            }
            assert!(source.contains("UNION SELECT 'user' AS role"));
            assert!(source.contains("CAST(a.role IS NOT NULL AS SIGNED)"));
            assert!(source.contains("CAST(p.action IS NOT NULL AS SIGNED)"));
        }
        assert_eq!(sql.matches('?').count(), 6);
        assert_eq!(probe.matches('?').count(), 0);
        assert!(probe.contains("AND FALSE"));
        for (error, text) in [
            (
                MySqlControlError::InvalidIdentity,
                "invalid local identity reference",
            ),
            (
                MySqlControlError::CorruptIdentity,
                "corrupt local identity metadata",
            ),
            (
                MySqlControlError::CorruptRbac,
                "corrupt system role metadata",
            ),
            (
                MySqlControlError::IdentityLimitExceeded,
                "local identity read limit exceeded",
            ),
        ] {
            assert_eq!(error.to_string(), text);
        }
    }
}
