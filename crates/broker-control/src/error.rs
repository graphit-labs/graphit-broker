use std::fmt;

/// Public failures contain no driver errors, addresses, credentials or SQL values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlError {
    InvalidRole,
    InvalidIdentity,
    CorruptIdentity,
    CorruptRbac,
    IdentityLimitExceeded,
    SessionUnavailable,
    SessionExpired,
    InvalidSession,
    CorruptSession,
    SessionExists,
    Configuration,
    AmbientConfiguration,
    Connection,
    SchemaRejected,
    Storage,
    FlowExists,
    Unavailable,
    Expired,
    CorruptFlow,
    InvalidFlow,
    Clock,
    Deadline,
    Closed,
    OutcomeUncertain,
    PrivateFile,
}
impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRole => "invalid system role definition",
            Self::InvalidIdentity => "invalid local identity reference",
            Self::CorruptIdentity => "corrupt local identity metadata",
            Self::CorruptRbac => "corrupt system role metadata",
            Self::IdentityLimitExceeded => "local identity read limit exceeded",
            Self::SessionUnavailable => "administrative session unavailable",
            Self::SessionExpired => "administrative session expired",
            Self::InvalidSession => "invalid administrative session",
            Self::CorruptSession => "corrupt administrative session",
            Self::SessionExists => "administrative session already exists",
            Self::PrivateFile => "broker private file access rejected",
            Self::Configuration => "invalid explicit broker persistence configuration",
            Self::AmbientConfiguration => "ambient PostgreSQL configuration is not allowed",
            Self::Connection => "broker persistence connection failed",
            Self::SchemaRejected => "unsupported broker database structure; recreate explicitly",
            Self::Storage => "broker persistence failed",
            Self::FlowExists => "login flow already exists",
            Self::Unavailable => "login flow unavailable",
            Self::Expired => "login flow expired",
            Self::CorruptFlow => "stored login flow is invalid",
            Self::InvalidFlow => "invalid login flow input",
            Self::Clock => "invalid system clock",
            Self::Deadline => "broker persistence deadline exceeded",
            Self::Closed => "broker persistence is closed",
            Self::OutcomeUncertain => "transaction outcome uncertain; do not replay automatically",
        })
    }
}
impl std::error::Error for ControlError {}
