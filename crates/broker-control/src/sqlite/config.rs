use super::{Result, SqliteControlError};
use crate::FlowLimits;
use std::{
    fmt,
    path::PathBuf,
    time::{Duration, Instant},
};

/// Explicit file and budgets. Path expansion belongs to the configuration caller.
///
/// ```compile_fail
/// let _ = broker_control::SqliteControlConfig::default();
/// ```
#[derive(Clone)]
pub struct SqliteControlConfig {
    pub(crate) path: PathBuf,
    pub(crate) startup: Duration,
    pub(crate) operation: Duration,
    pub(crate) shutdown: Duration,
    pub(crate) flows: FlowLimits,
}
impl fmt::Debug for SqliteControlConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteControlConfig([REDACTED])")
    }
}
impl SqliteControlConfig {
    pub fn new(
        path: PathBuf,
        startup: Duration,
        operation: Duration,
        shutdown: Duration,
        flows: FlowLimits,
    ) -> Result<Self> {
        let text = path.as_os_str().as_encoded_bytes();
        if text.is_empty()
            || text.contains(&0)
            || path.file_name().is_none()
            || text == b":memory:"
            || text.starts_with(b"file:")
            || [startup, operation, shutdown].iter().any(Duration::is_zero)
            || [
                flows.provider_bytes,
                flows.request_bytes,
                flows.continuation_bytes,
            ]
            .iter()
            .any(|v| i64::try_from(v.get()).is_err())
        {
            return Err(SqliteControlError::Configuration);
        }
        Ok(Self {
            path,
            startup,
            operation,
            shutdown,
            flows,
        })
    }
}
pub(crate) fn deadline(caller: Instant, budget: Duration) -> Result<Instant> {
    let end = Instant::now()
        .checked_add(budget)
        .ok_or(SqliteControlError::Configuration)?
        .min(caller);
    if end <= Instant::now() {
        return Err(SqliteControlError::Deadline);
    }
    Ok(end)
}
