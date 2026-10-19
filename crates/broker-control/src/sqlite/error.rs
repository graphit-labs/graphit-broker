use std::fmt;

/// Finite failures never retain paths, SQL, driver errors or credential values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqliteControlError {
    Configuration,
    PrivateFile,
    Connection,
    SchemaRejected,
    Storage,
    Clock,
    Deadline,
    Closed,
    OutcomeUncertain,
    FlowExists,
    InvalidFlow,
    Unavailable,
    Expired,
    CorruptFlow,
}
impl fmt::Display for SqliteControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid explicit SQLite configuration",
            Self::PrivateFile => "SQLite private file access rejected",
            Self::Connection => "SQLite connection failed",
            Self::SchemaRejected => "unsupported broker database structure; recreate explicitly",
            Self::Storage => "broker persistence failed",
            Self::Clock => "invalid system clock",
            Self::Deadline => "broker persistence deadline exceeded",
            Self::Closed => "broker persistence is closed",
            Self::OutcomeUncertain => "transaction outcome uncertain; do not replay automatically",
            Self::FlowExists => "login flow already exists",
            Self::InvalidFlow => "invalid login flow input",
            Self::Unavailable => "login flow unavailable",
            Self::Expired => "login flow expired",
            Self::CorruptFlow => "stored login flow is invalid",
        })
    }
}
impl std::error::Error for SqliteControlError {}

impl From<SqliteControlError> for crate::ControlError {
    fn from(value: SqliteControlError) -> Self {
        match value {
            SqliteControlError::Configuration => Self::Configuration,
            SqliteControlError::PrivateFile => Self::PrivateFile,
            SqliteControlError::Connection => Self::Connection,
            SqliteControlError::SchemaRejected => Self::SchemaRejected,
            SqliteControlError::Storage => Self::Storage,
            SqliteControlError::Clock => Self::Clock,
            SqliteControlError::Deadline => Self::Deadline,
            SqliteControlError::Closed => Self::Closed,
            SqliteControlError::OutcomeUncertain => Self::OutcomeUncertain,
            SqliteControlError::FlowExists => Self::FlowExists,
            SqliteControlError::InvalidFlow => Self::InvalidFlow,
            SqliteControlError::Unavailable => Self::Unavailable,
            SqliteControlError::Expired => Self::Expired,
            SqliteControlError::CorruptFlow => Self::CorruptFlow,
        }
    }
}
