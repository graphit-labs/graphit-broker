use super::{PostgresControlStore, PostgresResourceGrants, bounded_deadline};
use crate::{
    AuthorizedBrokerProjectAccess, BrokerAccessVerifier, BrokerProjectAuthorizationError,
    ProjectResourceAction, ProjectResourceModule,
    instance_registry::canonical_project_id,
    resource_policy::{ResourcePolicy, check_deadline},
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Borrows the actual SQL store and the configuration owner's trusted verifier.
/// See [the server contract](../../../../docs/rust-broker-project-authorization.md).
/// ~~~
/// use broker_control::{BrokerAccessVerifier, BrokerProjectAuthorizationError,
///     PostgresBrokerProjectAuthorizer, PostgresControlStore};
/// use std::num::NonZeroUsize;
/// fn configured<'a>(store: &'a PostgresControlStore, verifier: &'a BrokerAccessVerifier,
///     grants_json_bytes: NonZeroUsize,
/// ) -> Result<PostgresBrokerProjectAuthorizer<'a>, BrokerProjectAuthorizationError> {
///     store.broker_project_authorizer(verifier, grants_json_bytes)
/// }
/// ~~~
/// ~~~compile_fail
/// fn escape(
///     store: &broker_control::PostgresControlStore,
///     verifier: &broker_control::BrokerAccessVerifier,
/// ) -> broker_control::PostgresBrokerProjectAuthorizer<'static> {
///     store.broker_project_authorizer(verifier, std::num::NonZeroUsize::new(4096).unwrap()).unwrap()
/// }
/// ~~~
pub struct PostgresBrokerProjectAuthorizer<'a> {
    owner: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants: PostgresResourceGrants<'a>,
}
impl fmt::Debug for PostgresBrokerProjectAuthorizer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresBrokerProjectAuthorizer([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn broker_project_authorizer<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
    ) -> Result<PostgresBrokerProjectAuthorizer<'a>, BrokerProjectAuthorizationError> {
        Ok(PostgresBrokerProjectAuthorizer {
            owner: self,
            verifier,
            grants: self.resource_grants(grants_json_bytes)?,
        })
    }
}
impl<'a> PostgresBrokerProjectAuthorizer<'a> {
    /// Authenticate the JWT locally and read current whole SQL grants for this operation.
    pub async fn authorize(
        &self,
        raw: &str,
        required_scopes: &[String],
        module: ProjectResourceModule,
        action: ProjectResourceAction,
        project_id: &str,
        original: Instant,
    ) -> Result<AuthorizedBrokerProjectAccess<'a>, BrokerProjectAuthorizationError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        let capability = module
            .capability(action)
            .ok_or(BrokerProjectAuthorizationError::InvalidOperation)?;
        if !canonical_project_id(project_id) {
            return Err(BrokerProjectAuthorizationError::InvalidProject);
        }
        let principal = self.verifier.verify(raw, required_scopes, end)?;
        // Preserve the SQL producer's timeout/COMMIT classification, without an outer timer.
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
