use super::{MySqlControlError, Result};
use crate::FlowLimits;
use std::{
    fmt,
    num::{NonZeroU16, NonZeroUsize},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Explicit TCP endpoint. No URL, Unix socket or ambient configuration is read.
pub struct MysqlEndpoint {
    pub(crate) host: String,
    pub(crate) port: NonZeroU16,
    pub(crate) database: String,
}
impl MysqlEndpoint {
    pub fn new(
        host: String,
        port: NonZeroU16,
        database: String,
        limits: MysqlConnectionLimits,
    ) -> Result<Self> {
        text(&host, limits.text_bytes.get())?;
        text(&database, limits.text_bytes.get())?;
        if host.contains(['/', '\\', '@', '?', '#', ':'])
            && host.parse::<std::net::Ipv6Addr>().is_err()
        {
            return Err(MySqlControlError::Configuration);
        }
        if host.chars().any(char::is_whitespace) {
            return Err(MySqlControlError::Configuration);
        }
        Ok(Self {
            host,
            port,
            database,
        })
    }
}
impl fmt::Debug for MysqlEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MysqlEndpoint([REDACTED])")
    }
}
pub struct MysqlCredentials {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
}
impl MysqlCredentials {
    pub fn new(
        username: String,
        password: Zeroizing<String>,
        limits: MysqlConnectionLimits,
    ) -> Result<Self> {
        text(&username, limits.text_bytes.get())?;
        text(&password, limits.text_bytes.get())?;
        Ok(Self { username, password })
    }
}
impl fmt::Debug for MysqlCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MysqlCredentials([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug)]
pub struct MysqlConnectionLimits {
    pub text_bytes: NonZeroUsize,
    pub ca_bytes: NonZeroUsize,
}
#[derive(Clone, Copy, Debug)]
pub struct MysqlBudgets {
    pub acquire: Duration,
    pub connect: Duration,
    pub operation: Duration,
    pub startup: Duration,
    pub shutdown: Duration,
    pub lock: Duration,
}
#[derive(Clone, Copy, Debug)]
pub struct MysqlAdmissionLimits {
    pub max_inflight: NonZeroUsize,
    pub budgets: MysqlBudgets,
}
/// Bounds owned decoded metadata and work, not the driver's network allocations.
#[derive(Clone, Copy, Debug)]
pub struct MysqlCatalogLimits {
    pub rows_per_category: NonZeroUsize,
    pub cell_bytes: NonZeroUsize,
    pub total_bytes: NonZeroUsize,
    pub grant_rows: NonZeroUsize,
    pub grant_bytes: NonZeroUsize,
    pub grant_tokens: NonZeroUsize,
    pub roles: NonZeroUsize,
    pub statement_bytes: NonZeroUsize,
    pub probes: NonZeroUsize,
}
/// The operator supplies every budget and the trusted-peer provisioning policy.
pub struct MySqlControlConfig {
    pub endpoint: MysqlEndpoint,
    pub credentials: MysqlCredentials,
    pub ca_pem: Option<Vec<u8>>,
    pub connection: MysqlConnectionLimits,
    pub admission: MysqlAdmissionLimits,
    pub catalog: MysqlCatalogLimits,
    pub flows: FlowLimits,
}
impl fmt::Debug for MySqlControlConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MySqlControlConfig([REDACTED])")
    }
}
impl MySqlControlConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        text(&self.endpoint.host, self.connection.text_bytes.get())?;
        text(&self.endpoint.database, self.connection.text_bytes.get())?;
        text(&self.credentials.username, self.connection.text_bytes.get())?;
        text(&self.credentials.password, self.connection.text_bytes.get())?;
        if self
            .ca_pem
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > self.connection.ca_bytes.get())
        {
            return Err(MySqlControlError::Configuration);
        }
        if self.admission.max_inflight.get() > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(MySqlControlError::Configuration);
        }
        let b = self.admission.budgets;
        for duration in [
            b.acquire,
            b.connect,
            b.operation,
            b.startup,
            b.shutdown,
            b.lock,
        ] {
            if duration.is_zero() || Instant::now().checked_add(duration).is_none() {
                return Err(MySqlControlError::Configuration);
            }
        }
        let c = self.catalog;
        let columns = broker_store::schema::TABLES
            .iter()
            .try_fold(0usize, |total, table| {
                total.checked_add(table.definition().columns().len())
            })
            .ok_or(MySqlControlError::Configuration)?;
        if c.rows_per_category.get() < columns
            || c.total_bytes.get() < c.cell_bytes.get()
            || c.grant_bytes.get() > c.total_bytes.get()
            || c.rows_per_category.get().checked_add(1).is_none()
            || c.grant_rows.get().checked_add(1).is_none()
            || c.roles.get().checked_add(1).is_none()
            || u64::try_from(c.rows_per_category.get()).is_err()
            || u64::try_from(c.cell_bytes.get()).is_err()
            || u64::try_from(c.grant_bytes.get()).is_err()
        {
            return Err(MySqlControlError::Configuration);
        }
        self.physical_flow_limits()?;
        Ok(())
    }
    pub(crate) fn physical_flow_limits(&self) -> Result<FlowLimits> {
        let table = broker_store::schema::TABLES
            .iter()
            .find(|table| table.name() == "oidc_flows")
            .ok_or(MySqlControlError::Configuration)?
            .mysql_shape();
        let maximum = table
            .columns()
            .iter()
            .find(|column| column.name() == "continuation_json")
            .and_then(|column| column.character_octet_length())
            .and_then(|value| usize::try_from(value).ok())
            .and_then(NonZeroUsize::new)
            .ok_or(MySqlControlError::Configuration)?;
        Ok(FlowLimits {
            continuation_bytes: self.flows.continuation_bytes.min(maximum),
            ..self.flows
        })
    }
}
fn text(value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.contains('\0') {
        Err(MySqlControlError::Configuration)
    } else {
        Ok(())
    }
}
pub(crate) fn deadline(caller: Instant, budget: Duration) -> Result<Instant> {
    let now = Instant::now();
    if caller <= now {
        return Err(MySqlControlError::Deadline);
    }
    now.checked_add(budget)
        .map(|local| caller.min(local))
        .ok_or(MySqlControlError::Configuration)
}
pub(crate) fn identifier(value: &str, bound: usize) -> Result<String> {
    text(value, bound)?;
    let capacity = value
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(2))
        .ok_or(MySqlControlError::Configuration)?;
    if capacity > bound {
        return Err(MySqlControlError::Configuration);
    }
    Ok(format!("`{}`", value.replace('`', "``")))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn n(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).unwrap()
    }
    fn config() -> MySqlControlConfig {
        let connection = MysqlConnectionLimits {
            text_bytes: n(128),
            ca_bytes: n(4096),
        };
        MySqlControlConfig {
            endpoint: MysqlEndpoint::new(
                "localhost".into(),
                NonZeroU16::new(3306).unwrap(),
                "synthetic-db".into(),
                connection,
            )
            .unwrap(),
            credentials: MysqlCredentials::new(
                "synthetic-user".into(),
                Zeroizing::new("synthetic-password".into()),
                connection,
            )
            .unwrap(),
            ca_pem: None,
            connection,
            admission: MysqlAdmissionLimits {
                max_inflight: n(1),
                budgets: MysqlBudgets {
                    acquire: Duration::from_secs(1),
                    connect: Duration::from_secs(1),
                    operation: Duration::from_secs(1),
                    startup: Duration::from_secs(1),
                    shutdown: Duration::from_secs(1),
                    lock: Duration::from_secs(1),
                },
            },
            catalog: MysqlCatalogLimits {
                rows_per_category: n(138),
                cell_bytes: n(4096),
                total_bytes: n(100_000),
                grant_rows: n(64),
                grant_bytes: n(4096),
                grant_tokens: n(256),
                roles: n(32),
                statement_bytes: n(8192),
                probes: n(256),
            },
            flows: FlowLimits {
                provider_bytes: n(100_000),
                request_bytes: n(100_000),
                continuation_bytes: n(100_000),
            },
        }
    }
    #[test]
    fn mysql_text_capacity_bounds_serialized_json_without_rejecting_larger_caller_policy() {
        let config = config();
        config.validate().unwrap();
        let effective = config.physical_flow_limits().unwrap();
        assert_eq!(effective.continuation_bytes.get(), 65_535);
        assert_eq!(effective.provider_bytes, config.flows.provider_bytes);
        assert_eq!(effective.request_bytes, config.flows.request_bytes);
        let large = crate::FlowContinuation::Admin {
            provider_id: "\"".repeat(40_000),
        };
        assert!(large.to_json(config.flows).is_ok());
        assert!(large.to_json(effective).is_err());
        let small = crate::FlowContinuation::Admin {
            provider_id: "provider".into(),
        };
        assert!(small.to_json(effective).is_ok());
    }
    #[test]
    fn explicit_invalid_budget_ca_and_counter_overflow_are_configuration_failures() {
        let mut value = config();
        value.admission.budgets.operation = Duration::ZERO;
        assert_eq!(value.validate(), Err(MySqlControlError::Configuration));
        let mut value = config();
        value.ca_pem = Some(Vec::new());
        assert_eq!(value.validate(), Err(MySqlControlError::Configuration));
        let mut value = config();
        value.catalog.rows_per_category = n(usize::MAX);
        assert_eq!(value.validate(), Err(MySqlControlError::Configuration));
        let mut value = config();
        value.catalog.roles = n(usize::MAX);
        assert_eq!(value.validate(), Err(MySqlControlError::Configuration));
        let value = config();
        let debug = format!("{value:?}");
        for private in [
            "synthetic-db",
            "synthetic-user",
            "synthetic-password",
            "localhost",
        ] {
            assert!(!debug.contains(private));
        }
        assert_eq!(identifier("db`@_%", 128).unwrap(), "`db``@_%`");
    }
}
