use super::{SqliteControlStore, SqliteLocalBearerVerifier, SqliteResourceGrants};
use crate::{
    BrokerAccessVerifier, ControlError, HubAccessError, HubAccessResolution,
    hub_access::HubIdentity, resource_policy::HubResourcePolicy,
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Explicit native JWT ingress, borrowing its trusted configuration and SQL store.
pub struct SqliteBrokerHubAccessResolver<'a> {
    owner: &'a SqliteControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants: SqliteResourceGrants<'a>,
}
/// Explicit local opaque ingress; never interprets a bearer as a native JWT.
pub struct SqliteLocalHubAccessResolver<'a> {
    owner: &'a SqliteControlStore,
    verifier: SqliteLocalBearerVerifier<'a>,
    grants: SqliteResourceGrants<'a>,
}
impl fmt::Debug for SqliteBrokerHubAccessResolver<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteBrokerHubAccessResolver([REDACTED])")
    }
}
impl fmt::Debug for SqliteLocalHubAccessResolver<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalHubAccessResolver([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn broker_hub_access_resolver<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
    ) -> Result<SqliteBrokerHubAccessResolver<'a>, HubAccessError> {
        Ok(SqliteBrokerHubAccessResolver {
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
    ) -> Result<SqliteLocalHubAccessResolver<'a>, HubAccessError> {
        Ok(SqliteLocalHubAccessResolver {
            owner: self,
            verifier: self.local_bearer_verifier(audience, identity_json_bytes)?,
            grants: self.resource_grants(grants_json_bytes)?,
        })
    }
}
impl<'a> SqliteBrokerHubAccessResolver<'a> {
    pub async fn resolve(
        &self,
        raw: Option<&str>,
        original: Instant,
    ) -> Result<HubAccessResolution<'a>, HubAccessError> {
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
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
impl SqliteLocalHubAccessResolver<'_> {
    pub async fn resolve(
        &self,
        raw: Option<&str>,
        original: Instant,
    ) -> Result<HubAccessResolution<'static>, HubAccessError> {
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
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
