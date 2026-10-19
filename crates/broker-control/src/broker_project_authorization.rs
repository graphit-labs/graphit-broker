//! JWT-authenticated logical PROJECT decisions are observations for one operation.
use crate::{
    BrokerAccessError, ControlError, ProjectResourceAction, ProjectResourceModule,
    ResourceGrantReadError, VerifiedBrokerAccess, resource_policy::ResourcePolicyError,
};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerProjectAuthorizationError {
    InvalidProject,
    InvalidOperation,
    InvalidPolicy,
    Forbidden,
    Authentication(BrokerAccessError),
    Grants(ResourceGrantReadError),
    Control(ControlError),
}
impl From<ControlError> for BrokerProjectAuthorizationError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<BrokerAccessError> for BrokerProjectAuthorizationError {
    fn from(value: BrokerAccessError) -> Self {
        match value {
            BrokerAccessError::Deadline => Self::Control(ControlError::Deadline),
            other => Self::Authentication(other),
        }
    }
}
impl From<ResourceGrantReadError> for BrokerProjectAuthorizationError {
    fn from(value: ResourceGrantReadError) -> Self {
        match value {
            ResourceGrantReadError::Control(error) => Self::Control(error),
            other => Self::Grants(other),
        }
    }
}
impl From<ResourcePolicyError> for BrokerProjectAuthorizationError {
    fn from(value: ResourcePolicyError) -> Self {
        match value {
            ResourcePolicyError::InvalidPolicy => Self::InvalidPolicy,
            ResourcePolicyError::Deadline => Self::Control(ControlError::Deadline),
        }
    }
}
impl fmt::Display for BrokerProjectAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProject => f.write_str("invalid project"),
            Self::InvalidOperation => f.write_str("invalid project operation"),
            Self::InvalidPolicy => f.write_str("invalid project policy"),
            Self::Forbidden => f.write_str("project access denied"),
            Self::Authentication(error) => error.fmt(f),
            Self::Grants(error) => error.fmt(f),
            Self::Control(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for BrokerProjectAuthorizationError {}

/// An observed decision from a signed Broker identity and a current SQL policy.
/// Subsequent operations must authenticate and read their current grants again.
/// See [the server contract](../../../docs/rust-broker-project-authorization.md).
/// ~~~compile_fail
/// fn forge(principal: broker_control::VerifiedBrokerAccess<'_>) {
///     let _ = broker_control::AuthorizedBrokerProjectAccess::new(
///         principal, "01ARZ3NDEKTSV4RRFFQ69G5FAV",
///         broker_control::ProjectResourceModule::Task,
///         broker_control::ProjectResourceAction::Read, 1, "task:read");
/// }
/// ~~~
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::AuthorizedBrokerProjectAccess<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::AuthorizedBrokerProjectAccess<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require_wire<T: serde::de::DeserializeOwned>() {}
/// require_wire::<broker_control::AuthorizedBrokerProjectAccess<'static>>();
/// ~~~
pub struct AuthorizedBrokerProjectAccess<'a> {
    principal: VerifiedBrokerAccess<'a>,
    project_id: String,
    module: ProjectResourceModule,
    action: ProjectResourceAction,
    policy_revision: i64,
    capability: &'static str,
}
impl fmt::Debug for AuthorizedBrokerProjectAccess<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedBrokerProjectAccess([REDACTED])")
    }
}
impl<'a> AuthorizedBrokerProjectAccess<'a> {
    pub fn principal(&self) -> &VerifiedBrokerAccess<'a> {
        &self.principal
    }
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
    pub fn module(&self) -> ProjectResourceModule {
        self.module
    }
    pub fn action(&self) -> ProjectResourceAction {
        self.action
    }
    pub fn capability(&self) -> &'static str {
        self.capability
    }
    pub fn policy_revision(&self) -> i64 {
        self.policy_revision
    }
    pub(crate) fn new(
        principal: VerifiedBrokerAccess<'a>,
        project_id: &str,
        module: ProjectResourceModule,
        action: ProjectResourceAction,
        policy_revision: i64,
        capability: &'static str,
    ) -> Self {
        Self {
            principal,
            project_id: project_id.into(),
            module,
            action,
            policy_revision,
            capability,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_errors_preserve_deadline_and_sql_commit_classification() {
        assert_eq!(
            BrokerProjectAuthorizationError::from(BrokerAccessError::Deadline),
            BrokerProjectAuthorizationError::Control(ControlError::Deadline)
        );
        assert_eq!(
            BrokerProjectAuthorizationError::from(ResourceGrantReadError::Control(
                ControlError::OutcomeUncertain
            )),
            BrokerProjectAuthorizationError::Control(ControlError::OutcomeUncertain)
        );
        assert_eq!(
            BrokerProjectAuthorizationError::from(BrokerAccessError::Expired),
            BrokerProjectAuthorizationError::Authentication(BrokerAccessError::Expired)
        );
        assert_eq!(
            BrokerProjectAuthorizationError::Forbidden.to_string(),
            "project access denied"
        );
    }
}
