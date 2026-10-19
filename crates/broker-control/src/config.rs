use crate::{ControlError, FlowLimits};
use sqlx_core::connection::ConnectOptions;
use sqlx_postgres::{PgConnectOptions, PgSslMode};
use std::{
    fmt,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const AMBIENT: [&str; 12] = [
    "PGPORT",
    "PGHOSTADDR",
    "PGHOST",
    "PGUSER",
    "PGDATABASE",
    "PGPASSWORD",
    "PGSSLROOTCERT",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGSSLMODE",
    "PGAPPNAME",
    "PGOPTIONS",
];

/// TCP endpoint; validation and finite byte bounds precede construction of SDK options.
pub struct PostgresEndpoint {
    pub host: String,
    pub port: NonZeroU16,
    pub database: String,
}
pub struct PostgresCredentials {
    username: String,
    password: Zeroizing<String>,
}
impl PostgresCredentials {
    pub fn new(username: String, password: Zeroizing<String>) -> Self {
        Self { username, password }
    }
}
impl fmt::Debug for PostgresCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresCredentials([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ConnectionLimits {
    pub text_bytes: NonZeroUsize,
    pub ca_bytes: NonZeroUsize,
}
/// All pool and I/O budgets are mandatory; no Broker defaults are inferred.
#[derive(Clone, Copy, Debug)]
pub struct PoolConfig {
    pub max_connections: NonZeroU32,
    pub min_connections: u32,
    pub statement_cache_capacity: usize,
    pub connect_timeout: Duration,
    pub acquire_timeout: Duration,
    pub operation_timeout: Duration,
    pub startup_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub max_lifetime: Duration,
    pub idle_timeout: Duration,
    pub statement_timeout: Duration,
    pub lock_timeout: Duration,
    pub idle_transaction_timeout: Duration,
}
impl PoolConfig {
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        if self.min_connections > self.max_connections.get() {
            return Err(ControlError::Configuration);
        }
        for value in [
            self.connect_timeout,
            self.acquire_timeout,
            self.operation_timeout,
            self.startup_timeout,
            self.shutdown_timeout,
            self.max_lifetime,
            self.idle_timeout,
        ] {
            if value.is_zero() || Instant::now().checked_add(value).is_none() {
                return Err(ControlError::Configuration);
            }
        }
        for value in [
            self.statement_timeout,
            self.lock_timeout,
            self.idle_transaction_timeout,
        ] {
            sql_milliseconds(value)?;
        }
        Ok(())
    }
}
pub(crate) fn sql_milliseconds(value: Duration) -> Result<u32, ControlError> {
    let milliseconds = value.as_millis();
    if milliseconds == 0 || milliseconds > i32::MAX as u128 {
        return Err(ControlError::Configuration);
    }
    Ok(milliseconds as u32)
}

/// Explicit TCP/TLS configuration. Trust is the union of the pinned WebPKI
/// roots bundled by SQLx and the supplied CA PEM; the supplied CA is additive,
/// not an exclusive trust store. Native/OS/environment roots are not enabled.
pub struct PostgresConfig {
    endpoint: PostgresEndpoint,
    credentials: PostgresCredentials,
    ca_pem: Vec<u8>,
    pub(crate) pool: PoolConfig,
    pub(crate) flows: FlowLimits,
}
impl fmt::Debug for PostgresConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresConfig([REDACTED])")
    }
}
impl PostgresConfig {
    /// All limits and budgets are supplied by the caller. TLS always verifies
    /// the hostname against pinned WebPKI roots plus this additional CA PEM.
    /// There is no plaintext, hostname-bypass or CA-exclusive mode.
    pub fn new(
        endpoint: PostgresEndpoint,
        credentials: PostgresCredentials,
        ca_pem: Vec<u8>,
        limits: ConnectionLimits,
        pool: PoolConfig,
        flows: FlowLimits,
    ) -> Result<Self, ControlError> {
        pool.validate()?;
        for text in [
            &endpoint.host,
            &endpoint.database,
            &credentials.username,
            &credentials.password,
        ] {
            if text.is_empty() || text.len() > limits.text_bytes.get() || text.contains('\0') {
                return Err(ControlError::Configuration);
            }
        }
        if endpoint.host.starts_with('/')
            || endpoint.host.contains('\\')
            || ca_pem.is_empty()
            || ca_pem.len() > limits.ca_bytes.get()
        {
            return Err(ControlError::Configuration);
        }
        Ok(Self {
            endpoint,
            credentials,
            ca_pem,
            pool,
            flows,
        })
    }
    /// The host process must not mutate its environment while this method executes.
    pub(crate) fn options(&self) -> Result<PgConnectOptions, ControlError> {
        if AMBIENT.iter().any(|key| std::env::var_os(key).is_some()) {
            return Err(ControlError::AmbientConfiguration);
        }
        // The explicit fields replace the environment-fed fields retained by SQLx.
        // new_without_pgpass bypasses PGPASSFILE; the twelve other inputs were rejected above.
        let options = PgConnectOptions::new_without_pgpass()
            .host(&self.endpoint.host)
            .port(self.endpoint.port.get())
            .database(&self.endpoint.database)
            .username(&self.credentials.username)
            .password(&self.credentials.password)
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(self.ca_pem.clone())
            .application_name("graphit-broker-rust-control")
            .statement_cache_capacity(self.pool.statement_cache_capacity)
            .options([
                ("search_path", "pg_catalog,public".to_owned()),
                (
                    "statement_timeout",
                    sql_milliseconds(self.pool.statement_timeout)?.to_string(),
                ),
                (
                    "lock_timeout",
                    sql_milliseconds(self.pool.lock_timeout)?.to_string(),
                ),
                (
                    "idle_in_transaction_session_timeout",
                    sql_milliseconds(self.pool.idle_transaction_timeout)?.to_string(),
                ),
            ])
            .disable_statement_logging();
        Ok(options)
    }
}
