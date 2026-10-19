//! Fresh rerank capability admission with genuine retained authentication.
use crate::{
    AdminBrokerSessionError, BrokerAccessError, ControlError, EmbeddingAdmissionError,
    EmbeddingAdmissionLimits, LocalBearerVerificationError, ResourceGrantReadError,
    ResourceGrantSnapshot,
    embedding_admission::EmbeddingIdentity,
    resource_policy::{
        HubResourcePolicy, ResourcePolicyError, check_deadline, inference_cache_scope,
    },
};
use std::{fmt, num::NonZeroUsize, time::Instant};

#[derive(Clone, Copy, Debug)]
pub struct RerankAdmissionLimits {
    pub identity_json_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
}
impl RerankAdmissionLimits {
    pub(crate) fn validate(&self, audience: &str, scopes: &[String]) -> Result<(), ControlError> {
        EmbeddingAdmissionLimits {
            identity_json_bytes: self.identity_json_bytes,
            grants_json_bytes: self.grants_json_bytes,
        }
        .validate(audience, scopes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RerankAdmissionError {
    Authentication(BrokerAccessError),
    LocalAuthentication(LocalBearerVerificationError),
    Upstream(AdminBrokerSessionError),
    Grants(ResourceGrantReadError),
    Control(ControlError),
    InvalidPolicy,
    Forbidden,
}
impl fmt::Display for RerankAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authentication(_) | Self::LocalAuthentication(_) | Self::Upstream(_) => {
                "rerank authentication failed"
            }
            Self::Grants(_) | Self::InvalidPolicy => "rerank authorization unavailable",
            Self::Control(_) => "rerank admission failed",
            Self::Forbidden => "rerank capability denied",
        })
    }
}
impl std::error::Error for RerankAdmissionError {}
impl From<EmbeddingAdmissionError> for RerankAdmissionError {
    fn from(value: EmbeddingAdmissionError) -> Self {
        match value {
            EmbeddingAdmissionError::Authentication(source) => Self::Authentication(source),
            EmbeddingAdmissionError::LocalAuthentication(source) => {
                Self::LocalAuthentication(source)
            }
            EmbeddingAdmissionError::Upstream(source) => Self::Upstream(source),
            EmbeddingAdmissionError::Grants(source) => Self::Grants(source),
            EmbeddingAdmissionError::Control(source) => Self::Control(source),
            EmbeddingAdmissionError::InvalidPolicy => Self::InvalidPolicy,
            EmbeddingAdmissionError::Forbidden => Self::Forbidden,
        }
    }
}
impl From<LocalBearerVerificationError> for RerankAdmissionError {
    fn from(value: LocalBearerVerificationError) -> Self {
        Self::LocalAuthentication(value)
    }
}
impl From<ResourceGrantReadError> for RerankAdmissionError {
    fn from(value: ResourceGrantReadError) -> Self {
        Self::Grants(value)
    }
}
impl From<ControlError> for RerankAdmissionError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<ResourcePolicyError> for RerankAdmissionError {
    fn from(value: ResourcePolicyError) -> Self {
        match value {
            ResourcePolicyError::InvalidPolicy => Self::InvalidPolicy,
            ResourcePolicyError::Deadline => Self::Control(ControlError::Deadline),
        }
    }
}

/// One rerank grant observation; cache scope is opaque data, never reusable authority.
pub struct RerankAdmission<'v> {
    identity: EmbeddingIdentity<'v>,
    original: Instant,
    authorization_revision: i64,
    cache_scope: [u8; 32],
}
impl RerankAdmission<'_> {
    pub fn check(&mut self) -> Result<(), RerankAdmissionError> {
        self.identity.check(self.original)?;
        check_deadline(self.original)?;
        Ok(())
    }
    pub fn deadline(&self) -> Instant {
        self.identity.deadline(self.original)
    }
    pub fn authorization_revision(&self) -> i64 {
        self.authorization_revision
    }
    pub fn cache_scope(&self) -> [u8; 32] {
        self.cache_scope
    }
}

pub(crate) fn admit<'v>(
    mut identity: EmbeddingIdentity<'v>,
    observation: Result<ResourceGrantSnapshot, ResourceGrantReadError>,
    original: Instant,
) -> Result<RerankAdmission<'v>, RerankAdmissionError> {
    let snapshot = match observation {
        Ok(snapshot) => snapshot,
        Err(ResourceGrantReadError::Control(ControlError::Deadline)) => {
            identity.check(original)?;
            return Err(ResourceGrantReadError::Control(ControlError::Deadline).into());
        }
        Err(error) => return Err(error.into()),
    };
    identity.check(original)?;
    let policy = HubResourcePolicy::compile(&snapshot, original)?;
    if !policy.allows_inference(&identity, b"rerank", original)? {
        return Err(RerankAdmissionError::Forbidden);
    }
    let cache_scope = inference_cache_scope(&identity);
    let mut result = RerankAdmission {
        identity,
        original,
        authorization_revision: snapshot.revision(),
        cache_scope,
    };
    result.check()?;
    Ok(result)
}
