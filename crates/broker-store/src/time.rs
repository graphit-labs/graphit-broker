//! SQL timestamps use checked UTC microseconds, with SQL NULL for missing values.
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimestampMicros(i64);
impl TimestampMicros {
    pub fn new(value: i64) -> Result<Self, InvalidTimestamp> {
        if value < 0 {
            Err(InvalidTimestamp)
        } else {
            Ok(Self(value))
        }
    }
    pub const fn as_i64(self) -> i64 {
        self.0
    }
}
impl TryFrom<SystemTime> for TimestampMicros {
    type Error = InvalidTimestamp;
    /// Sub-microsecond precision is explicitly discarded when converting an OS timestamp.
    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        let micros = value
            .duration_since(UNIX_EPOCH)
            .map_err(|_| InvalidTimestamp)?
            .as_micros();
        Self::new(i64::try_from(micros).map_err(|_| InvalidTimestamp)?)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTimestamp;
impl fmt::Display for InvalidTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid UTC microsecond timestamp")
    }
}
impl std::error::Error for InvalidTimestamp {}
