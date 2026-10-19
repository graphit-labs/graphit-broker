use crate::ControlError;
use broker_store::time::TimestampMicros;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    num::NonZeroUsize,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub(crate) const FLOW_TTL_MICROS: i64 = 600_000_000;
#[derive(Clone, Copy, Debug)]
pub struct FlowLimits {
    pub provider_bytes: NonZeroUsize,
    pub request_bytes: NonZeroUsize,
    pub continuation_bytes: NonZeroUsize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowPurpose {
    Admin,
    OAuth,
}
impl FlowPurpose {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::OAuth => "oauth",
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminContinuation {
    provider_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthContinuation {
    provider_id: String,
    request_id: String,
}

/// Continuation identifies the caller's protocol journey; it grants no authorization.
pub enum FlowContinuation {
    Admin {
        provider_id: String,
    },
    OAuth {
        provider_id: String,
        request_id: String,
    },
}
impl fmt::Debug for FlowContinuation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FlowContinuation([REDACTED])")
    }
}
impl FlowContinuation {
    pub fn purpose(&self) -> FlowPurpose {
        match self {
            Self::Admin { .. } => FlowPurpose::Admin,
            Self::OAuth { .. } => FlowPurpose::OAuth,
        }
    }
    pub fn provider_id(&self) -> &str {
        match self {
            Self::Admin { provider_id } | Self::OAuth { provider_id, .. } => provider_id,
        }
    }
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Admin { .. } => None,
            Self::OAuth { request_id, .. } => Some(request_id),
        }
    }
    pub fn to_json(&self, limits: FlowLimits) -> Result<String, ControlError> {
        bounded_text(self.provider_id(), limits.provider_bytes.get())?;
        let result = match self {
            Self::Admin { provider_id } => serde_json::to_string(&AdminContinuation {
                provider_id: provider_id.clone(),
            }),
            Self::OAuth {
                provider_id,
                request_id,
            } => {
                bounded_text(request_id, limits.request_bytes.get())?;
                serde_json::to_string(&OAuthContinuation {
                    provider_id: provider_id.clone(),
                    request_id: request_id.clone(),
                })
            }
        }
        .map_err(|_| ControlError::InvalidFlow)?;
        if result.len() > limits.continuation_bytes.get() {
            return Err(ControlError::InvalidFlow);
        }
        Ok(result)
    }
    pub fn from_json(
        purpose: FlowPurpose,
        value: &str,
        limits: FlowLimits,
    ) -> Result<Self, ControlError> {
        if value.len() > limits.continuation_bytes.get() {
            return Err(ControlError::InvalidFlow);
        }
        let result = match purpose {
            FlowPurpose::Admin => {
                let v: AdminContinuation =
                    serde_json::from_str(value).map_err(|_| ControlError::InvalidFlow)?;
                Self::Admin {
                    provider_id: v.provider_id,
                }
            }
            FlowPurpose::OAuth => {
                let v: OAuthContinuation =
                    serde_json::from_str(value).map_err(|_| ControlError::InvalidFlow)?;
                Self::OAuth {
                    provider_id: v.provider_id,
                    request_id: v.request_id,
                }
            }
        };
        result.to_json(limits)?;
        Ok(result)
    }
}
fn bounded_text(value: &str, limit: usize) -> Result<(), ControlError> {
    if value.is_empty() || value.len() > limit || value.contains('\0') {
        Err(ControlError::InvalidFlow)
    } else {
        Ok(())
    }
}
pub struct OidcFlow {
    nonce: Zeroizing<String>,
    pkce_verifier: Zeroizing<String>,
    continuation: FlowContinuation,
    expires_at: TimestampMicros,
}
impl fmt::Debug for OidcFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcFlow([REDACTED])")
    }
}
impl OidcFlow {
    pub fn new(
        nonce: String,
        pkce_verifier: String,
        continuation: FlowContinuation,
        expires_at: SystemTime,
        limits: FlowLimits,
    ) -> Result<Self, ControlError> {
        let value = Self {
            nonce: Zeroizing::new(nonce),
            pkce_verifier: Zeroizing::new(pkce_verifier),
            continuation,
            expires_at: TimestampMicros::try_from(expires_at)
                .map_err(|_| ControlError::InvalidFlow)?,
        };
        value.validate(limits)?;
        Ok(value)
    }
    pub(crate) fn validate(&self, limits: FlowLimits) -> Result<String, ControlError> {
        bounded_text(&self.nonce, 128)?;
        if !(43..=128).contains(&self.pkce_verifier.len())
            || !self
                .pkce_verifier
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"-._~".contains(&v))
        {
            return Err(ControlError::InvalidFlow);
        }
        self.continuation.to_json(limits)
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn pkce_verifier(&self) -> &str {
        &self.pkce_verifier
    }
    pub fn continuation(&self) -> &FlowContinuation {
        &self.continuation
    }
    pub fn expires_at(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_micros(self.expires_at.as_i64() as u64)
    }
    pub(crate) fn expiry_micros(&self) -> i64 {
        self.expires_at.as_i64()
    }
    pub(crate) fn stored(
        nonce: String,
        pkce_verifier: String,
        purpose: &str,
        continuation: &str,
        expires_at: i64,
        created_at: i64,
        limits: FlowLimits,
    ) -> Result<Self, ControlError> {
        let purpose = match purpose {
            "admin" => FlowPurpose::Admin,
            "oauth" => FlowPurpose::OAuth,
            _ => return Err(ControlError::CorruptFlow),
        };
        if created_at < 0 || expires_at <= created_at || expires_at - created_at > FLOW_TTL_MICROS {
            return Err(ControlError::CorruptFlow);
        }
        let result = Self {
            nonce: Zeroizing::new(nonce),
            pkce_verifier: Zeroizing::new(pkce_verifier),
            continuation: FlowContinuation::from_json(purpose, continuation, limits)
                .map_err(|_| ControlError::CorruptFlow)?,
            expires_at: TimestampMicros::new(expires_at).map_err(|_| ControlError::CorruptFlow)?,
        };
        result
            .validate(limits)
            .map_err(|_| ControlError::CorruptFlow)?;
        Ok(result)
    }
}
pub(crate) fn now_micros() -> Result<i64, ControlError> {
    TimestampMicros::try_from(SystemTime::now())
        .map(|v| v.as_i64())
        .map_err(|_| ControlError::Clock)
}
