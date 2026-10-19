use super::{
    PostgresControlStore, PostgresLocalBearerVerifier, PostgresResourceGrants, bounded_deadline,
};
use crate::{
    BrokerAccessVerifier, HubAccessError, HubAccessResolution, hub_access::HubIdentity,
    resource_policy::HubResourcePolicy,
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Explicit native JWT ingress, borrowing its trusted configuration and SQL store.
pub struct PostgresBrokerHubAccessResolver<'a> {
    owner: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants: PostgresResourceGrants<'a>,
}
/// Explicit local opaque ingress; never interprets a bearer as a native JWT.
pub struct PostgresLocalHubAccessResolver<'a> {
    owner: &'a PostgresControlStore,
    verifier: PostgresLocalBearerVerifier<'a>,
    grants: PostgresResourceGrants<'a>,
}
impl fmt::Debug for PostgresBrokerHubAccessResolver<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresBrokerHubAccessResolver([REDACTED])")
    }
}
impl fmt::Debug for PostgresLocalHubAccessResolver<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresLocalHubAccessResolver([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn broker_hub_access_resolver<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
    ) -> Result<PostgresBrokerHubAccessResolver<'a>, HubAccessError> {
        Ok(PostgresBrokerHubAccessResolver {
            owner: self,
            verifier,
            grants: self.resource_grants(grants_json_bytes)?,
        })
    }
    pub fn local_hub_access_resolver<'a>(
        &'a self,
        audience: &'a str,
        identity_json_bytes: NonZeroUsize,
        grants_json_bytes: NonZeroUsize,
    ) -> Result<PostgresLocalHubAccessResolver<'a>, HubAccessError> {
        Ok(PostgresLocalHubAccessResolver {
            owner: self,
            verifier: self.local_bearer_verifier(audience, identity_json_bytes)?,
            grants: self.resource_grants(grants_json_bytes)?,
        })
    }
}
impl<'a> PostgresBrokerHubAccessResolver<'a> {
    pub async fn resolve(
        &self,
        raw: Option<&str>,
        original: Instant,
    ) -> Result<HubAccessResolution<'a>, HubAccessError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        let identity = match raw {
            Some(raw) => HubIdentity::Broker(self.verifier.verify(raw, &[], end)?),
            None => HubIdentity::Anonymous,
        };
        // The SQL reader alone classifies COMMIT and timeout, without an outer timer.
        let snapshot = self.grants.read(end).await?;
        let policy = HubResourcePolicy::compile(&snapshot, end)?;
        let selectors = policy.selectors(&identity, end)?;
        let routes = policy.catalog_routes(&identity, &snapshot, end)?;
        Ok(
            HubAccessResolution::new(identity, snapshot.revision(), selectors, end)?
                .bind_catalog_routes(routes),
        )
    }
}
impl PostgresLocalHubAccessResolver<'_> {
    pub async fn resolve(
        &self,
        raw: Option<&str>,
        original: Instant,
    ) -> Result<HubAccessResolution<'static>, HubAccessError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        let identity = match raw {
            Some(raw) => HubIdentity::Local(self.verifier.verify(raw, &[], end).await?),
            None => HubIdentity::Anonymous,
        };
        let snapshot = self.grants.read(end).await?;
        let policy = HubResourcePolicy::compile(&snapshot, end)?;
        let selectors = policy.selectors(&identity, end)?;
        let routes = policy.catalog_routes(&identity, &snapshot, end)?;
        Ok(
            HubAccessResolution::new(identity, snapshot.revision(), selectors, end)?
                .bind_catalog_routes(routes),
        )
    }
}
