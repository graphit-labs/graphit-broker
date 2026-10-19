use super::{PostgresControlStore, PostgresResourceGrants, bounded_deadline};
use crate::{
    AuthorizedBrokerPresence, BrokerAccessVerifier, BrokerPresenceAuthorizationError,
    PresenceCapability,
    instance_registry::canonical_project_id,
    resource_policy::{ResourcePolicy, check_deadline},
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Borrows the SQL store and the configuration owner's actual trusted verifier.
/// See [the server contract](../../../../docs/rust-broker-presence-authorization.md).
/// ~~~
/// use broker_control::{BrokerAccessVerifier, BrokerPresenceAuthorizationError,
///     PostgresBrokerPresenceAuthorizer, PostgresControlStore};
/// use std::num::NonZeroUsize;
/// fn configured<'a>(store: &'a PostgresControlStore, verifier: &'a BrokerAccessVerifier,
///     grants_json_bytes: NonZeroUsize,
/// ) -> Result<PostgresBrokerPresenceAuthorizer<'a>, BrokerPresenceAuthorizationError> {
///     store.broker_presence_authorizer(verifier, grants_json_bytes)
/// }
/// ~~~
/// ~~~compile_fail
/// fn escape(
///     store: &broker_control::PostgresControlStore,
///     verifier: &broker_control::BrokerAccessVerifier,
/// ) -> broker_control::PostgresBrokerPresenceAuthorizer<'static> {
///     store.broker_presence_authorizer(verifier, std::num::NonZeroUsize::new(4096).unwrap()).unwrap()
/// }
/// ~~~
pub struct PostgresBrokerPresenceAuthorizer<'a> {
    owner: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants: PostgresResourceGrants<'a>,
}
impl fmt::Debug for PostgresBrokerPresenceAuthorizer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresBrokerPresenceAuthorizer([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn broker_presence_authorizer<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
    ) -> Result<PostgresBrokerPresenceAuthorizer<'a>, BrokerPresenceAuthorizationError> {
        Ok(PostgresBrokerPresenceAuthorizer {
            owner: self,
            verifier,
            grants: self.resource_grants(grants_json_bytes)?,
        })
    }
}
impl<'a> PostgresBrokerPresenceAuthorizer<'a> {
    /// Authenticate the JWT locally and read current whole SQL grants for this operation.
    pub async fn authorize_project(
        &self,
        raw: &str,
        required_scopes: &[String],
        capability: PresenceCapability,
        project_id: &str,
        original: Instant,
    ) -> Result<AuthorizedBrokerPresence<'a>, BrokerPresenceAuthorizationError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        if !canonical_project_id(project_id) {
            return Err(BrokerPresenceAuthorizationError::InvalidProject);
        }
        let principal = self.verifier.verify(raw, required_scopes, end)?;
        // Preserve the SQL producer's timeout/COMMIT classification, without an outer timer.
        let snapshot = self.grants.read(end).await?;
        let policy = ResourcePolicy::compile(&snapshot, end)?;
        let allowed = policy.allows_broker(&principal, capability.as_str(), project_id, end)?;
        principal.check()?;
        check_deadline(end)?;
        if !allowed {
            return Err(BrokerPresenceAuthorizationError::Forbidden);
        }
        Ok(AuthorizedBrokerPresence::new(
            principal,
            project_id,
            capability,
            snapshot.revision(),
        ))
    }
}
