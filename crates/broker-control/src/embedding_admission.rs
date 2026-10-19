//! Current resource capability admission with retained genuine authentication.
use crate::{
    AdminBrokerSessionError, BrokerAccessError, BrokerAccessVerifier, ControlError,
    LocalBearerVerificationError, ResourceGrantReadError, ResourceGrantSnapshot,
    UpstreamBearerVerifier, VerifiedBrokerAccess, VerifiedLocalBearer,
    flow::now_micros,
    resource_policy::{HubResourcePolicy, ResourcePolicyError, check_deadline},
    upstream_oidc::VerifiedUpstreamBearer,
};
use std::{fmt, num::NonZeroUsize, time::Instant};

#[derive(Clone, Copy, Debug)]
pub struct EmbeddingAdmissionLimits {
    pub identity_json_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
}
impl EmbeddingAdmissionLimits {
    pub(crate) fn validate(&self, audience: &str, scopes: &[String]) -> Result<(), ControlError> {
        if audience.trim().is_empty() || scopes.iter().any(|s| s.trim().is_empty()) {
            return Err(ControlError::Configuration);
        }
        for cap in [self.identity_json_bytes, self.grants_json_bytes] {
            i64::try_from(cap.get()).map_err(|_| ControlError::Configuration)?;
            cap.get()
                .checked_add(1)
                .and_then(|v| isize::try_from(v).ok())
                .ok_or(ControlError::Configuration)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddingAdmissionError {
    Authentication(BrokerAccessError),
    LocalAuthentication(LocalBearerVerificationError),
    Upstream(AdminBrokerSessionError),
    Grants(ResourceGrantReadError),
    Control(ControlError),
    InvalidPolicy,
    Forbidden,
}
impl fmt::Display for EmbeddingAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authentication(_) | Self::LocalAuthentication(_) | Self::Upstream(_) => {
                "embedding authentication failed"
            }
            Self::Grants(_) | Self::InvalidPolicy => "embedding authorization unavailable",
            Self::Control(_) => "embedding admission failed",
            Self::Forbidden => "embedding capability denied",
        })
    }
}
impl std::error::Error for EmbeddingAdmissionError {}
impl From<BrokerAccessError> for EmbeddingAdmissionError {
    fn from(value: BrokerAccessError) -> Self {
        Self::Authentication(value)
    }
}
impl From<LocalBearerVerificationError> for EmbeddingAdmissionError {
    fn from(value: LocalBearerVerificationError) -> Self {
        Self::LocalAuthentication(value)
    }
}
impl From<ResourceGrantReadError> for EmbeddingAdmissionError {
    fn from(value: ResourceGrantReadError) -> Self {
        Self::Grants(value)
    }
}
impl From<ControlError> for EmbeddingAdmissionError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<ResourcePolicyError> for EmbeddingAdmissionError {
    fn from(value: ResourcePolicyError) -> Self {
        match value {
            ResourcePolicyError::InvalidPolicy => Self::InvalidPolicy,
            ResourcePolicyError::Deadline => Self::Control(ControlError::Deadline),
        }
    }
}

pub(crate) enum EmbeddingIdentity<'v> {
    Anonymous,
    Broker(VerifiedBrokerAccess<'v>),
    Local(VerifiedLocalBearer),
    Upstream(VerifiedUpstreamBearer),
}
impl EmbeddingIdentity<'_> {
    pub(crate) fn check(&mut self, original: Instant) -> Result<(), EmbeddingAdmissionError> {
        // Classify the first captured boundary even if the caller resumes after both.
        // This uses only the genuine retained authentication cutoff and returns denial.
        let cutoff = self.deadline(original);
        if cutoff < original && Instant::now() >= cutoff {
            return Err(match self {
                Self::Anonymous => unreachable!("anonymous has only Original"),
                Self::Broker(_) => BrokerAccessError::Expired.into(),
                Self::Local(_) => LocalBearerVerificationError::Unauthenticated.into(),
                Self::Upstream(_) => {
                    EmbeddingAdmissionError::Upstream(BrokerAccessError::Expired.into())
                }
            });
        }
        check_deadline(original)?;
        match self {
            Self::Anonymous => Ok(()),
            Self::Broker(proof) => Ok(proof.check()?),
            Self::Local(proof) => Ok(proof.finish(now_micros()?)?),
            Self::Upstream(proof) => proof.check().map_err(EmbeddingAdmissionError::Upstream),
        }
    }
    pub(crate) fn deadline(&self, original: Instant) -> Instant {
        match self {
            Self::Anonymous => original,
            Self::Broker(proof) => original.min(proof.authentication_expiry().1),
            Self::Local(proof) => original.min(proof.authentication_expiry().1),
            Self::Upstream(proof) => original.min(proof.expires_mono()),
        }
    }
}

/// One fresh capability observation, never reusable authority for another request.
/// The private authentication result remains alive through the consumer's effects.
/// Diagnostic and serialization access to identity payloads is deliberately absent.
pub struct EmbeddingAdmission<'v> {
    identity: EmbeddingIdentity<'v>,
    original: Instant,
    authorization_revision: i64,
}
impl EmbeddingAdmission<'_> {
    pub fn check(&mut self) -> Result<(), EmbeddingAdmissionError> {
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
}

pub(crate) async fn authenticate_nonlocal<'v>(
    native: &'v BrokerAccessVerifier,
    upstream: Option<&UpstreamBearerVerifier>,
    raw: Option<&str>,
    scopes: &[String],
    original: Instant,
) -> Result<EmbeddingIdentity<'v>, EmbeddingAdmissionError> {
    check_deadline(original)?;
    match raw {
        None => Ok(EmbeddingIdentity::Anonymous),
        Some(raw) => {
            if let Some(verifier) = upstream
                && !verifier
                    .selects_native(raw, original)
                    .map_err(EmbeddingAdmissionError::Upstream)?
            {
                return verifier
                    .verify(raw, original)
                    .await
                    .map(EmbeddingIdentity::Upstream)
                    .map_err(EmbeddingAdmissionError::Upstream);
            }
            Ok(EmbeddingIdentity::Broker(
                native.verify(raw, scopes, original)?,
            ))
        }
    }
}

pub(crate) fn admit<'v>(
    mut identity: EmbeddingIdentity<'v>,
    observation: Result<ResourceGrantSnapshot, ResourceGrantReadError>,
    original: Instant,
) -> Result<EmbeddingAdmission<'v>, EmbeddingAdmissionError> {
    let snapshot = match observation {
        Ok(snapshot) => snapshot,
        Err(ResourceGrantReadError::Control(ControlError::Deadline)) => {
            // This wait may have ended at authentication expiry rather than
            // Original. Reclassify that temporal boundary through the real proof.
            identity.check(original)?;
            return Err(ResourceGrantReadError::Control(ControlError::Deadline).into());
        }
        // In particular, an uncertain COMMIT must never be masked by a late
        // proof expiry. Preserve already-observed non-temporal failures as well.
        Err(error) => return Err(error.into()),
    };
    identity.check(original)?;
    let policy = HubResourcePolicy::compile(&snapshot, original)?;
    if !policy.allows_inference(&identity, b"embeddings", original)? {
        return Err(EmbeddingAdmissionError::Forbidden);
    }
    let mut result = EmbeddingAdmission {
        identity,
        original,
        authorization_revision: snapshot.revision(),
    };
    result.check()?;
    Ok(result)
}
