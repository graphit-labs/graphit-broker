//! One-operation presence decisions require real local authentication and fresh SQL grants.
use crate::{
    ControlError, LocalBearerVerificationError, ResourceGrantReadError, VerifiedLocalBearer,
    resource_policy::ResourcePolicyError,
};
use std::{fmt, time::Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceCapability {
    Read,
    Publish,
}
impl PresenceCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "presence:read",
            Self::Publish => "presence:publish",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceAuthorizationError {
    InvalidProject,
    InvalidPolicy,
    Forbidden,
    Authentication(LocalBearerVerificationError),
    Grants(ResourceGrantReadError),
    Control(ControlError),
}
impl From<ControlError> for PresenceAuthorizationError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<LocalBearerVerificationError> for PresenceAuthorizationError {
    fn from(value: LocalBearerVerificationError) -> Self {
        match value {
            LocalBearerVerificationError::Control(error) => Self::Control(error),
            other => Self::Authentication(other),
        }
    }
}
impl From<ResourceGrantReadError> for PresenceAuthorizationError {
    fn from(value: ResourceGrantReadError) -> Self {
        match value {
            ResourceGrantReadError::Control(error) => Self::Control(error),
            other => Self::Grants(other),
        }
    }
}
impl fmt::Display for PresenceAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProject => f.write_str("invalid presence project"),
            Self::InvalidPolicy => f.write_str("invalid presence policy"),
            Self::Forbidden => f.write_str("presence access denied"),
            Self::Authentication(error) => error.fmt(f),
            Self::Grants(error) => error.fmt(f),
            Self::Control(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for PresenceAuthorizationError {}

/// A decision observed for this operation, never a lease for subsequent effects.
/// Raw credentials and policy rules are not retained. Verify again per operation.
/// ~~~compile_fail
/// fn forge(principal: broker_control::VerifiedLocalBearer) {
///     let _ = broker_control::AuthorizedLocalPresence::new(
///         principal, "01ARZ3NDEKTSV4RRFFQ69G5FAV",
///         broker_control::PresenceCapability::Read, 1);
/// }
/// ~~~
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::AuthorizedLocalPresence>();
/// ~~~
/// ~~~compile_fail
/// fn require_wire<T: serde::de::DeserializeOwned>() {}
/// require_wire::<broker_control::AuthorizedLocalPresence>();
/// ~~~
pub struct AuthorizedLocalPresence {
    principal: VerifiedLocalBearer,
    project_id: String,
    capability: PresenceCapability,
    policy_revision: i64,
}
impl fmt::Debug for AuthorizedLocalPresence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedLocalPresence([REDACTED])")
    }
}
impl AuthorizedLocalPresence {
    pub fn principal(&self) -> &VerifiedLocalBearer {
        &self.principal
    }
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
    pub fn capability(&self) -> PresenceCapability {
        self.capability
    }
    pub fn policy_revision(&self) -> i64 {
        self.policy_revision
    }
    pub(crate) fn new(
        principal: VerifiedLocalBearer,
        project_id: &str,
        capability: PresenceCapability,
        policy_revision: i64,
    ) -> Self {
        Self {
            principal,
            project_id: project_id.to_owned(),
            capability,
            policy_revision,
        }
    }
}

impl From<ResourcePolicyError> for PresenceAuthorizationError {
    fn from(value: ResourcePolicyError) -> Self {
        match value {
            ResourcePolicyError::InvalidPolicy => Self::InvalidPolicy,
            ResourcePolicyError::Deadline => Self::Control(ControlError::Deadline),
        }
    }
}
pub(crate) fn check_deadline(end: Instant) -> Result<(), PresenceAuthorizationError> {
    crate::resource_policy::check_deadline(end).map_err(Into::into)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_policy_errors_preserve_the_presence_boundary() {
        assert_eq!(
            PresenceAuthorizationError::Forbidden.to_string(),
            "presence access denied"
        );
        assert_eq!(
            format!("{:?}", PresenceAuthorizationError::InvalidPolicy),
            "InvalidPolicy"
        );
        assert_eq!(
            PresenceAuthorizationError::from(ResourcePolicyError::InvalidPolicy),
            PresenceAuthorizationError::InvalidPolicy
        );
        assert_eq!(
            PresenceAuthorizationError::from(ResourcePolicyError::Deadline),
            PresenceAuthorizationError::Control(ControlError::Deadline)
        );
    }
}
