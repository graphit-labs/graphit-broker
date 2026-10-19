//! Native access authentication composed with current SQL administrative permission.
use crate::{
    BrokerAccessError, ControlError, IdentityReadLimits, SessionPrincipal, SessionProfile,
    SystemPermission, VerifiedBrokerAccess,
};
use std::{fmt, num::NonZeroUsize, time::Instant};

#[derive(Clone, Copy, Debug)]
pub struct AdminBrokerSessionLimits {
    pub identity: IdentityReadLimits,
    pub profile_json_bytes: NonZeroUsize,
}
impl AdminBrokerSessionLimits {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.identity
            .validate()
            .map_err(|_| ControlError::Configuration)?;
        for value in [
            self.identity.username_bytes,
            self.identity.subject_bytes,
            self.identity.role_bytes,
            self.identity.roles,
            self.identity.rows,
            self.profile_json_bytes,
        ] {
            i64::try_from(value.get()).map_err(|_| ControlError::Configuration)?;
            isize::try_from(value.get()).map_err(|_| ControlError::Configuration)?;
        }
        self.profile_json_bytes
            .get()
            .checked_mul(9)
            .and_then(|v| isize::try_from(v).ok())
            .ok_or(ControlError::Configuration)?;
        self.identity
            .roles
            .get()
            .checked_mul(131)
            .and_then(|v| v.checked_add(self.profile_json_bytes.get()))
            .and_then(|v| v.checked_add(1024))
            .and_then(|v| isize::try_from(v).ok())
            .ok_or(ControlError::Configuration)?;
        self.identity
            .rows
            .get()
            .checked_add(1)
            .and_then(|v| i64::try_from(v).ok())
            .ok_or(ControlError::Configuration)?;
        self.identity
            .roles
            .get()
            .checked_mul(std::mem::size_of::<String>())
            .and_then(|v| isize::try_from(v).ok())
            .ok_or(ControlError::Configuration)?;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminBrokerSessionError {
    Authentication(BrokerAccessError),
    Control(ControlError),
    Forbidden,
    Entropy,
}
impl fmt::Display for AdminBrokerSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(error) => error.fmt(f),
            Self::Control(error) => error.fmt(f),
            Self::Forbidden => f.write_str("administrative access denied"),
            Self::Entropy => f.write_str("administrative request identifier unavailable"),
        }
    }
}
impl std::error::Error for AdminBrokerSessionError {}
impl From<ControlError> for AdminBrokerSessionError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<BrokerAccessError> for AdminBrokerSessionError {
    fn from(value: BrokerAccessError) -> Self {
        Self::Authentication(value)
    }
}
/// An opaque correlation ID from the existing native CSPRNG, never a credential.
pub fn new_admin_request_id() -> Result<String, AdminBrokerSessionError> {
    broker_security::new_local_auth_challenge()
        .map(|id| id.to_string())
        .map_err(|_| AdminBrokerSessionError::Entropy)
}
/// Request-scoped result for session.read, not a permission lease for another action.
/// Profile and principal getters expose data, never authentication.
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::AdminBrokerSession<'static>>();
/// ```
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::AdminBrokerSession<'static>>();
/// ```
/// ```compile_fail
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<broker_control::AdminBrokerSession<'static>>();
/// ```
pub struct AdminBrokerSession<'a> {
    pub(crate) proof: VerifiedBrokerAccess<'a>,
    pub(crate) original: Instant,
    pub(crate) profile: SessionProfile,
    pub(crate) principal: SessionPrincipal,
    pub(crate) roles: Vec<String>,
    pub(crate) permissions: Vec<SystemPermission>,
}
impl fmt::Debug for AdminBrokerSession<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminBrokerSession([REDACTED])")
    }
}
impl AdminBrokerSession<'_> {
    pub fn check(&self) -> Result<(), AdminBrokerSessionError> {
        if Instant::now() >= self.original {
            return Err(ControlError::Deadline.into());
        }
        self.proof.check()?;
        Ok(())
    }
    pub fn profile(&self) -> &SessionProfile {
        &self.profile
    }
    pub fn principal(&self) -> &SessionPrincipal {
        &self.principal
    }
    pub fn roles(&self) -> &[String] {
        &self.roles
    }
    pub fn permissions(&self) -> &[SystemPermission] {
        &self.permissions
    }
}
