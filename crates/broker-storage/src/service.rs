//! Closed, configured storage issuance from the current private SQL grant.
use crate::{
    AwsStorageIssuer, FilesystemGateway, FilesystemGatewayConfig, FilesystemGatewayError,
    FilesystemStorageIssuer, FilesystemStore, IssuedStorageCredentials, StorageIssueError,
};
use broker_control::AuthorizedStorageGrant;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

/// Server-owned issuers. No request field can introduce another implementation.
pub enum StorageIssuer {
    Aws(AwsStorageIssuer),
    Filesystem(FilesystemStorageIssuer),
}

pub(crate) enum Issuer {
    Aws(AwsStorageIssuer),
    Filesystem(Arc<FilesystemStorageIssuer>),
}

pub struct StorageCredentialsService {
    pub(crate) routes: BTreeMap<String, usize>,
    pub(crate) issuers: Vec<Issuer>,
}

impl fmt::Debug for StorageCredentialsService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageCredentialsService([REDACTED])")
    }
}

impl StorageCredentialsService {
    pub fn new(issuers: Vec<StorageIssuer>) -> Result<Self, StorageIssueError> {
        if issuers.is_empty() {
            return Err(StorageIssueError::InvalidConfiguration);
        }
        let mut routes = BTreeMap::new();
        let mut buckets = BTreeSet::new();
        let mut configured = Vec::with_capacity(issuers.len());
        for (index, issuer) in issuers.into_iter().enumerate() {
            let issuer = match issuer {
                StorageIssuer::Aws(issuer) => {
                    for name in issuer.route_names() {
                        if routes.insert(name.to_owned(), index).is_some() {
                            return Err(StorageIssueError::InvalidConfiguration);
                        }
                    }
                    Issuer::Aws(issuer)
                }
                StorageIssuer::Filesystem(issuer) => {
                    for route in issuer.gateway_routes() {
                        if routes.insert(route.name.clone(), index).is_some()
                            || !buckets.insert(route.bucket.clone())
                        {
                            return Err(StorageIssueError::InvalidConfiguration);
                        }
                    }
                    Issuer::Filesystem(Arc::new(issuer))
                }
            };
            configured.push(issuer);
        }
        Ok(Self {
            routes,
            issuers: configured,
        })
    }

    /// Build gateways with the very same issuers that produce filesystem sessions.
    /// Stores must match all configured filesystem buckets exactly.
    pub fn filesystem_gateways(
        &self,
        stores: Vec<Arc<FilesystemStore>>,
        config: FilesystemGatewayConfig,
    ) -> Result<Vec<FilesystemGateway>, FilesystemGatewayError> {
        if config.request_timeout.is_zero()
            || std::time::Instant::now()
                .checked_add(config.request_timeout)
                .is_none()
        {
            return Err(FilesystemGatewayError::InvalidConfiguration);
        }
        let count = stores.len();
        let mut stores: BTreeMap<_, _> = stores
            .into_iter()
            .map(|store| (store.config.bucket.clone(), store))
            .collect();
        if stores.len() != count {
            return Err(FilesystemGatewayError::InvalidConfiguration);
        }
        let mut gateways = Vec::new();
        for issuer in &self.issuers {
            if let Issuer::Filesystem(issuer) = issuer {
                let selected = issuer
                    .gateway_routes()
                    .map(|route| {
                        stores
                            .remove(&route.bucket)
                            .ok_or(FilesystemGatewayError::InvalidConfiguration)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                gateways.push(FilesystemGateway::new(
                    issuer.clone(),
                    selected,
                    FilesystemGatewayConfig {
                        request_timeout: config.request_timeout,
                        request_head_bytes: config.request_head_bytes,
                    },
                )?);
            }
        }
        if !stores.is_empty() {
            return Err(FilesystemGatewayError::InvalidConfiguration);
        }
        Ok(gateways)
    }

    /// Select only the route in the actual SQL grant; never retry another issuer.
    pub async fn issue(
        &self,
        grant: &AuthorizedStorageGrant<'_>,
    ) -> Result<IssuedStorageCredentials, StorageIssueError> {
        grant.check()?;
        let result = match self.routes.get(grant.route()) {
            Some(index) => match &self.issuers[*index] {
                Issuer::Aws(issuer) => issuer.issue(grant).await,
                Issuer::Filesystem(issuer) => issuer.issue(grant).await,
            },
            None => Err(StorageIssueError::RouteUnavailable),
        };
        grant.check()?;
        result
    }
}
