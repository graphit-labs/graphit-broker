use super::SqliteControlStore;
use crate::{
    AdminBrokerSessionError as Error, AdminBrokerSessionLimits, AdminUpstreamSession,
    BrokerAccessError, ControlError, SystemAction, SystemPermission, UpstreamBearerVerifier,
    identity::safe_identity_segment, sqlite::executor::Work,
};
use rusqlite::{Transaction, params};
use std::{collections::BTreeSet, fmt, time::Instant};

/// A federated session view borrowing its SQLite owner and F1 verifier.
/// ```compile_fail
/// fn escape<'v>(s: &broker_control::SqliteControlStore,v: &'v broker_control::UpstreamBearerVerifier,l: broker_control::AdminBrokerSessionLimits)->broker_control::SqliteAdminUpstreamSessions<'static,'v> {
///     s.admin_upstream_sessions(v,l).unwrap()
/// }
/// ```
pub struct SqliteAdminUpstreamSessions<'s, 'v> {
    store: &'s SqliteControlStore,
    verifier: &'v UpstreamBearerVerifier,
    limits: AdminBrokerSessionLimits,
}
impl fmt::Debug for SqliteAdminUpstreamSessions<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteAdminUpstreamSessions([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn admin_upstream_sessions<'s, 'v>(
        &'s self,
        verifier: &'v UpstreamBearerVerifier,
        limits: AdminBrokerSessionLimits,
    ) -> Result<SqliteAdminUpstreamSessions<'s, 'v>, ControlError> {
        limits.validate()?;
        Ok(SqliteAdminUpstreamSessions {
            store: self,
            verifier,
            limits,
        })
    }
}
// Claims Some([]) deliberately excludes database assignments. Both paths add user.
const SELECT: &str = "WITH selected AS (
 SELECT role FROM role_assignments WHERE subject=?1 AND ?2 IS NULL
 UNION SELECT value FROM json_each(?2) UNION SELECT 'user'
 ) SELECT CASE WHEN typeof(s.role)='text' AND length(CAST(s.role AS BLOB))<=?3 THEN s.role END,
 CASE WHEN typeof(p.action)='text' AND length(CAST(p.action AS BLOB))<=128 THEN p.action END,
 p.role IS NOT NULL
 FROM selected s LEFT JOIN roles r ON r.name=s.role LEFT JOIN role_permissions p ON p.role=r.name
 ORDER BY s.role,p.action LIMIT ?4";
pub(super) fn observe_roles(
    tx: &Transaction<'_>,
    work: &Work,
    subject: &str,
    claim_roles: Option<&[String]>,
    limits: AdminBrokerSessionLimits,
    action: SystemAction,
    mut gate: impl FnMut() -> Result<(), Error>,
) -> Result<(Vec<String>, Vec<SystemPermission>), Error> {
    gate()?;
    work.check().map_err(ControlError::from)?;
    let l = limits.identity;
    if claim_roles.is_some_and(|r| {
        r.len() > l.roles.get()
            || r.iter()
                .any(|r| !safe_identity_segment(r, l.role_bytes.get()))
    }) {
        return Err(BrokerAccessError::InvalidToken.into());
    }
    let claims = claim_roles
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| ControlError::CorruptRbac)?;
    let mut statement = tx
        .prepare(SELECT)
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let mut rows = statement
        .query(params![
            subject,
            claims,
            l.role_bytes.get() as i64,
            (l.rows.get() + 1) as i64
        ])
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let mut roles = BTreeSet::new();
    let mut permissions = Vec::new();
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(|e| ControlError::from(work.sql(e)))? {
        count += 1;
        if count > l.rows.get() {
            return Err(ControlError::IdentityLimitExceeded.into());
        }
        gate()?;
        work.check().map_err(ControlError::from)?;
        let role: &str = row
            .get_ref(0)
            .map_err(|_| ControlError::CorruptRbac)?
            .as_str()
            .map_err(|_| ControlError::CorruptRbac)?;
        if !safe_identity_segment(role, l.role_bytes.get()) {
            return Err(ControlError::CorruptRbac.into());
        }
        roles.insert(role.to_owned());
        if roles.len() > l.roles.get() {
            return Err(ControlError::IdentityLimitExceeded.into());
        }
        if row
            .get::<_, bool>(2)
            .map_err(|_| ControlError::CorruptRbac)?
        {
            let value: &str = row
                .get_ref(1)
                .map_err(|_| ControlError::CorruptRbac)?
                .as_str()
                .map_err(|_| ControlError::CorruptRbac)?;
            let permission = SystemPermission::stored(value).ok_or(ControlError::CorruptRbac)?;
            if !permissions.contains(&permission) {
                permissions.push(permission);
            }
        }
    }
    gate()?;
    work.check().map_err(ControlError::from)?;
    if !permissions.contains(&SystemPermission::All)
        && !permissions.contains(&SystemPermission::Action(action))
    {
        return Err(Error::Forbidden);
    }
    permissions.sort_unstable_by_key(|p| p.as_str());
    Ok((roles.into_iter().collect(), permissions))
}
impl SqliteAdminUpstreamSessions<'_, '_> {
    pub async fn read(&self, raw: &str, original: Instant) -> Result<AdminUpstreamSession, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let proof = self.verifier.verify(raw, end).await?;
        crate::service::admin_upstream_session::validate_profile(&proof, self.limits, end)?;
        let expiry = proof.expires_mono();
        let limits = self.limits;
        let observed = self
            .store
            .executor
            .execute(end.min(expiry), move |owner, work| {
                let outcome = (|| -> Result<_, Error> {
                    proof.check()?;
                    let subject = format!("{}|{}", proof.issuer(), proof.profile().subject);
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let data = observe_roles(
                        &tx,
                        work,
                        &subject,
                        proof.claim_roles(),
                        limits,
                        SystemAction::SessionRead,
                        || {
                            if Instant::now() >= end {
                                return Err(ControlError::Deadline.into());
                            }
                            proof.check()
                        },
                    )?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok(data)
                })();
                Ok((proof, outcome))
            })
            .await;
        if matches!(
            &observed,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok((_, Err(Error::Control(ControlError::OutcomeUncertain))))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        if Instant::now() >= expiry {
            return Err(BrokerAccessError::Expired.into());
        }
        let (proof, outcome) = observed.map_err(ControlError::from)?;
        proof.check()?;
        let (roles, permissions) = outcome?;
        let result = AdminUpstreamSession {
            proof,
            original: end,
            roles,
            permissions,
        };
        result.check()?;
        Ok(result)
    }
}
