//! MySQL control persistence. Native proofs stay private on the connection that uses them.
mod bootstrap;
mod capability;
mod catalog;
mod config;
mod executor;
mod flow;

pub use config::{
    MySqlControlConfig, MysqlAdmissionLimits, MysqlBudgets, MysqlCatalogLimits,
    MysqlConnectionLimits, MysqlCredentials, MysqlEndpoint,
};
pub use flow::{MySqlAdminSessions, MySqlControlStore, MySqlLocalIdentities};
use std::fmt;
pub(crate) type Result<T> = std::result::Result<T, MySqlControlError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaReason {
    Relations,
    Table,
    Columns,
    Indexes,
    ForeignKeys,
    Checks,
    Temporary,
    Trigger,
    Event,
    Partition,
    Marker,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredCapability {
    Select,
    Insert,
    Delete,
    Create,
    References,
    Trigger,
    Event,
    WritePrimary,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnprovenReason {
    Visibility,
    SessionSettings,
    SessionChanged,
    RoleChanged,
    GrantSyntax,
    Truncated,
    SecondaryExecution,
    StorageOptions,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupReason {
    LockRelease,
    Deadline,
}
/// Finite failures never retain driver errors, SQL, endpoint or flow values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MySqlControlError {
    Configuration,
    Connection,
    Deadline,
    Closed,
    Storage,
    OutcomeUncertain,
    StartupBusy,
    Clock,
    StartupCommittedCleanupFailed(CleanupReason),
    SchemaRejected(SchemaReason),
    Denied(RequiredCapability),
    Unproven(UnprovenReason),
    InvalidRole,
    InvalidAssignment,
    RoleNotFound,
    LastAssignedAdmin,
    InvalidIdentity,
    CorruptIdentity,
    CorruptRbac,
    IdentityLimitExceeded,
    SessionUnavailable,
    SessionExpired,
    InvalidSession,
    CorruptSession,
    SessionExists,
    FlowExists,
    InvalidFlow,
    Unavailable,
    Expired,
    CorruptFlow,
}
impl fmt::Display for MySqlControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid explicit MySQL configuration",
            Self::Connection => "MySQL connection failed",
            Self::Deadline => "MySQL operation deadline exceeded",
            Self::Closed => "MySQL persistence is closed",
            Self::Storage => "MySQL persistence failed",
            Self::OutcomeUncertain => "transaction outcome uncertain; do not replay automatically",
            Self::StartupBusy => "another broker owns the startup lock",
            Self::Clock => "invalid system clock",
            Self::StartupCommittedCleanupFailed(_) => {
                "startup committed but lock release was not confirmed"
            }
            Self::SchemaRejected(_) => "unsupported MySQL broker structure",
            Self::Denied(_) => "required MySQL capability denied",
            Self::Unproven(_) => "required MySQL proof unavailable",
            Self::InvalidRole => "invalid system role definition",
            Self::InvalidAssignment => "invalid system role assignment",
            Self::RoleNotFound => "system role does not exist",
            Self::LastAssignedAdmin => "cannot revoke the last assigned administrator",
            Self::InvalidIdentity => "invalid local identity reference",
            Self::CorruptIdentity => "corrupt local identity metadata",
            Self::CorruptRbac => "corrupt system role metadata",
            Self::IdentityLimitExceeded => "local identity read limit exceeded",
            Self::SessionUnavailable => "administrative session unavailable",
            Self::SessionExpired => "administrative session expired",
            Self::InvalidSession => "invalid administrative session",
            Self::CorruptSession => "corrupt administrative session",
            Self::SessionExists => "administrative session already exists",
            Self::FlowExists => "login flow already exists",
            Self::InvalidFlow => "invalid login flow input",
            Self::Unavailable => "login flow unavailable",
            Self::Expired => "login flow expired",
            Self::CorruptFlow => "stored login flow is invalid",
        })
    }
}
impl std::error::Error for MySqlControlError {}
