//! Current Hub selector observations; storage permission remains separate.
//! See [the server contract](../../../docs/rust-hub-access.md).
use crate::{
    BrokerAccessError, ControlError, LocalBearerVerificationError, ResourceGrantReadError,
    VerifiedBrokerAccess, VerifiedLocalBearer,
    flow::now_micros,
    resource_policy::{ResourcePolicyError, check_deadline},
};
use serde::Serialize;
use std::{fmt, time::Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HubAccessError {
    InvalidPolicy,
    Authentication(BrokerAccessError),
    LocalAuthentication(LocalBearerVerificationError),
    Grants(ResourceGrantReadError),
    Control(ControlError),
}
impl fmt::Display for HubAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid Hub authorization policy",
            Self::Authentication(_) | Self::LocalAuthentication(_) => "Hub authentication failed",
            Self::Grants(_) => "Hub authorization unavailable",
            Self::Control(_) => "Hub operation failed",
        })
    }
}
impl std::error::Error for HubAccessError {}
impl From<BrokerAccessError> for HubAccessError {
    fn from(value: BrokerAccessError) -> Self {
        Self::Authentication(value)
    }
}
impl From<LocalBearerVerificationError> for HubAccessError {
    fn from(value: LocalBearerVerificationError) -> Self {
        Self::LocalAuthentication(value)
    }
}
impl From<ResourceGrantReadError> for HubAccessError {
    fn from(value: ResourceGrantReadError) -> Self {
        Self::Grants(value)
    }
}
impl From<ControlError> for HubAccessError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<ResourcePolicyError> for HubAccessError {
    fn from(value: ResourcePolicyError) -> Self {
        match value {
            ResourcePolicyError::InvalidPolicy => Self::InvalidPolicy,
            ResourcePolicyError::Deadline => Self::Control(ControlError::Deadline),
        }
    }
}

/// A project selector is response data, never an S3 grant.
#[derive(Serialize)]
pub struct HubProjectSelector {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    all: Option<bool>,
}
impl HubProjectSelector {
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
    pub fn is_all(&self) -> bool {
        self.all == Some(true)
    }
    pub(crate) fn project(id: &str) -> Self {
        Self {
            id: Some(id.into()),
            all: None,
        }
    }
    pub(crate) fn all() -> Self {
        Self {
            id: None,
            all: Some(true),
        }
    }
}

pub(crate) enum HubIdentity<'a> {
    Anonymous,
    Broker(VerifiedBrokerAccess<'a>),
    Local(VerifiedLocalBearer),
}
impl HubIdentity<'_> {
    fn subject(&self) -> String {
        match self {
            Self::Anonymous => "anonymous|anonymous".into(),
            Self::Broker(proof) => format!("{}|{}", proof.issuer(), proof.subject()),
            Self::Local(proof) => {
                let user = proof.current_local_user();
                format!("{}|{}", user.issuer(), user.subject())
            }
        }
    }
    fn check(&mut self) -> Result<(), HubAccessError> {
        match self {
            Self::Anonymous => Ok(()),
            Self::Broker(proof) => Ok(proof.check()?),
            Self::Local(proof) => Ok(proof.finish(now_micros()?)?),
        }
    }
}

/// One current SQL observation with a retained actual identity and deadline.
/// Call `check` again immediately before emitting a retained response. This does
/// not renew expiry or freeze permissions for a subsequent storage operation.
#[derive(Serialize)]
pub struct HubAccessResolution<'a> {
    v: u8,
    authorization_revision: String,
    subject: String,
    selectors: Vec<HubProjectSelector>,
    #[serde(skip)]
    identity: HubIdentity<'a>,
    #[serde(skip)]
    original: Instant,
    #[serde(skip)]
    catalog_routes: Vec<HubCatalogRoute>,
}
impl fmt::Debug for HubAccessResolution<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HubAccessResolution([REDACTED])")
    }
}
impl<'a> HubAccessResolution<'a> {
    pub(crate) fn new(
        identity: HubIdentity<'a>,
        revision: i64,
        selectors: Vec<HubProjectSelector>,
        original: Instant,
    ) -> Result<Self, HubAccessError> {
        let mut result = Self {
            v: 1,
            authorization_revision: revision.to_string(),
            subject: identity.subject(),
            selectors,
            identity,
            original,
            catalog_routes: Vec::new(),
        };
        result.check()?;
        Ok(result)
    }
    pub fn authorization_revision(&self) -> &str {
        &self.authorization_revision
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn selectors(&self) -> &[HubProjectSelector] {
        &self.selectors
    }
    pub fn check(&mut self) -> Result<(), HubAccessError> {
        check_deadline(self.original)?;
        self.identity.check()?;
        check_deadline(self.original)?;
        Ok(())
    }
}

/// Server policy projection retained with the same identity and SQL observation.
/// This grants metadata discovery only; it cannot issue storage credentials.
pub(crate) struct HubCatalogRoute {
    pub(crate) route: String,
    pub(crate) projects: Vec<String>,
}
impl HubAccessResolution<'_> {
    pub(crate) fn bind_catalog_routes(mut self, routes: Vec<HubCatalogRoute>) -> Self {
        self.catalog_routes = routes;
        self
    }
    pub fn catalog_route<'a>(
        &'a self,
        project: &str,
        default: &'a str,
    ) -> Result<Option<&'a str>, crate::StorageAdmissionError> {
        let mut selected = None;
        for rule in &self.catalog_routes {
            if rule.projects.is_empty() || rule.projects.iter().any(|id| id == "*" || id == project)
            {
                let route = if rule.route.is_empty() {
                    default
                } else {
                    &rule.route
                };
                if selected.is_some_and(|old| old != route) {
                    return Err(crate::StorageAdmissionError::ConflictingRoutes);
                }
                selected = Some(route);
            }
        }
        Ok(selected)
    }
    /// Routes are server selected; callers may not provide a route or bucket.
    pub fn catalog_routes(&self, default: &str) -> Vec<String> {
        self.catalog_routes
            .iter()
            .map(|r| {
                if r.route.is_empty() {
                    default.to_owned()
                } else {
                    r.route.clone()
                }
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    pub fn catalog_route_all(&self, route: &str, default: &str) -> bool {
        self.catalog_routes.iter().any(|r| {
            (if r.route.is_empty() {
                default
            } else {
                &r.route
            }) == route
                && (r.projects.is_empty() || r.projects.iter().any(|p| p == "*"))
        })
    }
}
