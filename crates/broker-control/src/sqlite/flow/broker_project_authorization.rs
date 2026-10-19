use super::{SqliteControlStore, SqliteResourceGrants};
use crate::{
    AuthorizedBrokerProjectAccess, BrokerAccessVerifier, BrokerProjectAuthorizationError,
    ControlError, ProjectResourceAction, ProjectResourceModule,
    instance_registry::canonical_project_id,
    resource_policy::{ResourcePolicy, check_deadline},
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Authenticate a Broker JWT and observe current SQLite PROJECT grants.
///
/// ```compile_fail
/// fn escape(
///     store: &broker_control::SqliteControlStore,
///     verifier: &broker_control::BrokerAccessVerifier,
/// ) -> broker_control::SqliteBrokerProjectAuthorizer<'static> {
///     store.broker_project_authorizer(verifier, std::num::NonZeroUsize::new(4096).unwrap()).unwrap()
/// }
/// ```
pub struct SqliteBrokerProjectAuthorizer<'a> {
    owner: &'a SqliteControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants: SqliteResourceGrants<'a>,
}
impl fmt::Debug for SqliteBrokerProjectAuthorizer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteBrokerProjectAuthorizer([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn broker_project_authorizer<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
    ) -> Result<SqliteBrokerProjectAuthorizer<'a>, BrokerProjectAuthorizationError> {
        Ok(SqliteBrokerProjectAuthorizer {
            owner: self,
            verifier,
            grants: self.resource_grants(grants_json_bytes)?,
        })
    }
}
impl<'a> SqliteBrokerProjectAuthorizer<'a> {
    pub async fn authorize(
        &self,
        raw: &str,
        required_scopes: &[String],
        module: ProjectResourceModule,
        action: ProjectResourceAction,
        project_id: &str,
        original: Instant,
    ) -> Result<AuthorizedBrokerProjectAccess<'a>, BrokerProjectAuthorizationError> {
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let capability = module
            .capability(action)
            .ok_or(BrokerProjectAuthorizationError::InvalidOperation)?;
        if !canonical_project_id(project_id) {
            return Err(BrokerProjectAuthorizationError::InvalidProject);
        }
        let principal = self.verifier.verify(raw, required_scopes, end)?;
        // The actual snapshot producer retains its SQL cancellation/COMMIT classification.
        let snapshot = self.grants.read(end).await?;
        let policy = ResourcePolicy::compile(&snapshot, end)?;
        let allowed = policy.allows_broker(&principal, capability, project_id, end)?;
        principal.check()?;
        check_deadline(end)?;
        if !allowed {
            return Err(BrokerProjectAuthorizationError::Forbidden);
        }
        Ok(AuthorizedBrokerProjectAccess::new(
            principal,
            project_id,
            module,
            action,
            snapshot.revision(),
            capability,
        ))
    }
}
