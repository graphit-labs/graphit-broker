//! JWT-authenticated Presence decisions are observations for one operation.
use crate::{
    BrokerAccessError, ControlError, PresenceCapability, ResourceGrantReadError,
    VerifiedBrokerAccess, resource_policy::ResourcePolicyError,
};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerPresenceAuthorizationError {
    InvalidProject,
    InvalidPolicy,
    Forbidden,
    Authentication(BrokerAccessError),
    Grants(ResourceGrantReadError),
    Control(ControlError),
}
impl From<ControlError> for BrokerPresenceAuthorizationError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<BrokerAccessError> for BrokerPresenceAuthorizationError {
    fn from(value: BrokerAccessError) -> Self {
        match value {
            BrokerAccessError::Deadline => Self::Control(ControlError::Deadline),
            other => Self::Authentication(other),
        }
    }
}
impl From<ResourceGrantReadError> for BrokerPresenceAuthorizationError {
    fn from(value: ResourceGrantReadError) -> Self {
        match value {
            ResourceGrantReadError::Control(error) => Self::Control(error),
            other => Self::Grants(other),
        }
    }
}
impl From<ResourcePolicyError> for BrokerPresenceAuthorizationError {
    fn from(value: ResourcePolicyError) -> Self {
        match value {
            ResourcePolicyError::InvalidPolicy => Self::InvalidPolicy,
            ResourcePolicyError::Deadline => Self::Control(ControlError::Deadline),
        }
    }
}
impl fmt::Display for BrokerPresenceAuthorizationError {
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
impl std::error::Error for BrokerPresenceAuthorizationError {}

/// A signed identity and a current Presence ACL observation for one operation.
/// Subsequent effects must authenticate and read their current grants again.
/// See [the server contract](../../../docs/rust-broker-presence-authorization.md).
/// ~~~compile_fail
/// fn forge(principal: broker_control::VerifiedBrokerAccess<'_>) {
///     let _ = broker_control::AuthorizedBrokerPresence::new(
///         principal, "01ARZ3NDEKTSV4RRFFQ69G5FAV",
///         broker_control::PresenceCapability::Read, 1);
/// }
/// ~~~
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::AuthorizedBrokerPresence<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::AuthorizedBrokerPresence<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require_wire<T: serde::de::DeserializeOwned>() {}
/// require_wire::<broker_control::AuthorizedBrokerPresence<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require_wire<T: serde::Serialize>() {}
/// require_wire::<broker_control::AuthorizedBrokerPresence<'static>>();
/// ~~~
pub struct AuthorizedBrokerPresence<'a> {
    principal: VerifiedBrokerAccess<'a>,
    project_id: String,
    capability: PresenceCapability,
    policy_revision: i64,
}
impl fmt::Debug for AuthorizedBrokerPresence<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedBrokerPresence([REDACTED])")
    }
}
impl<'a> AuthorizedBrokerPresence<'a> {
    pub fn principal(&self) -> &VerifiedBrokerAccess<'a> {
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
        principal: VerifiedBrokerAccess<'a>,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_errors_preserve_sql_outcomes_and_authentication() {
        assert_eq!(
            BrokerPresenceAuthorizationError::from(BrokerAccessError::Deadline),
            BrokerPresenceAuthorizationError::Control(ControlError::Deadline)
        );
        assert_eq!(
            BrokerPresenceAuthorizationError::from(ResourceGrantReadError::Control(
                ControlError::OutcomeUncertain
            )),
            BrokerPresenceAuthorizationError::Control(ControlError::OutcomeUncertain)
        );
        assert_eq!(
            BrokerPresenceAuthorizationError::from(ResourcePolicyError::InvalidPolicy),
            BrokerPresenceAuthorizationError::InvalidPolicy
        );
        assert_eq!(
            BrokerPresenceAuthorizationError::from(ResourcePolicyError::Deadline),
            BrokerPresenceAuthorizationError::Control(ControlError::Deadline)
        );
        assert_eq!(
            BrokerPresenceAuthorizationError::from(BrokerAccessError::Expired),
            BrokerPresenceAuthorizationError::Authentication(BrokerAccessError::Expired)
        );
        assert_eq!(
            BrokerPresenceAuthorizationError::Forbidden.to_string(),
            "presence access denied"
        );
    }
}
