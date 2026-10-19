//! Logical PROJECT capabilities require a verified caller and current explicit SQL rules.
use crate::{
    ControlError, LocalBearerVerificationError, ResourceGrantReadError, VerifiedLocalBearer,
    resource_policy::ResourcePolicyError,
};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectResourceModule {
    Task,
    Memory,
    Knowledge,
    Ast,
    Hub,
}
impl ProjectResourceModule {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Memory => "memory",
            Self::Knowledge => "knowledge",
            Self::Ast => "ast",
            Self::Hub => "hub",
        }
    }
    pub const fn capability(self, action: ProjectResourceAction) -> Option<&'static str> {
        match (self, action) {
            (Self::Task, ProjectResourceAction::Read) => Some("task:read"),
            (Self::Task, ProjectResourceAction::Write) => Some("task:write"),
            (Self::Memory, ProjectResourceAction::Read) => Some("memory:read"),
            (Self::Memory, ProjectResourceAction::Write) => Some("memory:write"),
            (Self::Knowledge, ProjectResourceAction::Read) => Some("knowledge:read"),
            (Self::Knowledge, ProjectResourceAction::Write) => Some("knowledge:write"),
            (Self::Ast, ProjectResourceAction::Read) => Some("ast:read"),
            (Self::Ast, ProjectResourceAction::Write) => Some("ast:write"),
            (Self::Hub, ProjectResourceAction::Read) => Some("hub"),
            (Self::Hub, ProjectResourceAction::Write) => None,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectResourceAction {
    Read,
    Write,
}
impl ProjectResourceAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectAuthorizationError {
    InvalidProject,
    InvalidOperation,
    InvalidPolicy,
    Forbidden,
    Authentication(LocalBearerVerificationError),
    Grants(ResourceGrantReadError),
    Control(ControlError),
}
impl From<ControlError> for ProjectAuthorizationError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<LocalBearerVerificationError> for ProjectAuthorizationError {
    fn from(value: LocalBearerVerificationError) -> Self {
        match value {
            LocalBearerVerificationError::Control(error) => Self::Control(error),
            other => Self::Authentication(other),
        }
    }
}
impl From<ResourceGrantReadError> for ProjectAuthorizationError {
    fn from(value: ResourceGrantReadError) -> Self {
        match value {
            ResourceGrantReadError::Control(error) => Self::Control(error),
            other => Self::Grants(other),
        }
    }
}
impl From<ResourcePolicyError> for ProjectAuthorizationError {
    fn from(value: ResourcePolicyError) -> Self {
        match value {
            ResourcePolicyError::InvalidPolicy => Self::InvalidPolicy,
            ResourcePolicyError::Deadline => Self::Control(ControlError::Deadline),
        }
    }
}
impl fmt::Display for ProjectAuthorizationError {
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
impl std::error::Error for ProjectAuthorizationError {}

/// An observed local decision for one operation, without credentials or a future lease.
/// Authenticate and consult current grants again for subsequent operations.
/// ~~~compile_fail
/// fn forge(principal: broker_control::VerifiedLocalBearer) {
///     let _ = broker_control::AuthorizedLocalProjectAccess::new(principal,
///         "01ARZ3NDEKTSV4RRFFQ69G5FAV", broker_control::ProjectResourceModule::Task,
///         broker_control::ProjectResourceAction::Read, 1, "task:read");
/// }
/// ~~~
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::AuthorizedLocalProjectAccess>();
/// ~~~
/// ~~~compile_fail
/// fn require_wire<T: serde::de::DeserializeOwned>() {}
/// require_wire::<broker_control::AuthorizedLocalProjectAccess>();
/// ~~~
/// ~~~compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::AuthorizedLocalProjectAccess>();
/// ~~~
pub struct AuthorizedLocalProjectAccess {
    principal: VerifiedLocalBearer,
    project_id: String,
    module: ProjectResourceModule,
    action: ProjectResourceAction,
    policy_revision: i64,
    capability: &'static str,
}
impl fmt::Debug for AuthorizedLocalProjectAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedLocalProjectAccess([REDACTED])")
    }
}
impl AuthorizedLocalProjectAccess {
    pub fn principal(&self) -> &VerifiedLocalBearer {
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
        principal: VerifiedLocalBearer,
        project_id: &str,
        module: ProjectResourceModule,
        action: ProjectResourceAction,
        policy_revision: i64,
        capability: &'static str,
    ) -> Self {
        Self {
            principal,
            project_id: project_id.to_owned(),
            module,
            action,
            policy_revision,
            capability,
        }
    }
}
