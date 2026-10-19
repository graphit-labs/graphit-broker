use super::{
    MySqlControlConfig, MySqlControlError, MysqlCatalogLimits, RequiredCapability, Result,
    UnprovenReason, config,
};
use futures_util::TryStreamExt;
use sqlx_core::{
    connection::{ConnectOptions, Connection},
    row::Row,
    sql_str::AssertSqlSafe,
};
use sqlx_mysql::{MySqlConnectOptions, MySqlConnection, MySqlRow, MySqlSslMode};
use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

pub(crate) const SQL_MODES: &str = "ONLY_FULL_GROUP_BY,STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION";
struct AdmissionState {
    active: usize,
    closed: bool,
}
pub(crate) struct Admission {
    semaphore: Arc<Semaphore>,
    state: Mutex<AdmissionState>,
    changed: Notify,
}
impl Admission {
    pub(crate) fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(max)),
            state: Mutex::new(AdmissionState {
                active: 0,
                closed: false,
            }),
            changed: Notify::new(),
        })
    }
    pub(crate) async fn acquire(self: &Arc<Self>, end: Instant) -> Result<Permit> {
        let permit = tokio::time::timeout_at(end.into(), self.semaphore.clone().acquire_owned())
            .await
            .map_err(|_| MySqlControlError::Deadline)?
            .map_err(|_| MySqlControlError::Closed)?;
        let mut state = self.state.lock().map_err(|_| MySqlControlError::Closed)?;
        if state.closed {
            return Err(MySqlControlError::Closed);
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or(MySqlControlError::Closed)?;
        Ok(Permit {
            admission: self.clone(),
            _permit: permit,
        })
    }
    pub(crate) fn stop(&self) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| MySqlControlError::Closed)?
            .closed = true;
        self.semaphore.close();
        Ok(())
    }
    pub(crate) async fn close(&self, end: Instant) -> Result<()> {
        self.stop()?;
        tokio::time::timeout_at(end.into(), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self
                    .state
                    .lock()
                    .map_err(|_| MySqlControlError::Closed)?
                    .active
                    == 0
                {
                    return Ok(());
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| MySqlControlError::Deadline)?
    }
}
pub(crate) struct Permit {
    admission: Arc<Admission>,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.admission.state.lock() {
            state.active -= 1;
        }
        self.admission.changed.notify_waiters();
    }
}
/// Owns the actual driver connection; dropping it closes the local transport.
/// Nothing may pool, reset, replace or export this connection.
pub(crate) struct Lease {
    pub(crate) connection: MySqlConnection,
    pub(crate) observation: Observation,
    pub(crate) work: Work,
    _permit: Permit,
}
impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MySqlLease([REDACTED])")
    }
}
impl Lease {
    pub(crate) async fn open(
        config: &MySqlControlConfig,
        admission: &Arc<Admission>,
        end: Instant,
    ) -> Result<Self> {
        let permit = admission
            .acquire(config::deadline(end, config.admission.budgets.acquire)?)
            .await?;
        let options = options(config);
        let mut connection = tokio::time::timeout_at(
            config::deadline(end, config.admission.budgets.connect)?.into(),
            MySqlConnection::connect_with(&options),
        )
        .await
        .map_err(|_| MySqlControlError::Deadline)?
        .map_err(|_| MySqlControlError::Connection)?;
        let mut work = Work::new(config.catalog);
        let settings = format!(
            "SET SESSION sql_mode='{SQL_MODES}',time_zone='+00:00',transaction_isolation='READ-COMMITTED',foreign_key_checks=1,unique_checks=1,sql_quote_show_create=1,show_gipk_in_create_table_and_information_schema=1"
        );
        work.statement(&settings)?;
        sqlx_core::query::query(AssertSqlSafe(settings))
            .execute(&mut connection)
            .await
            .map_err(|_| MySqlControlError::Unproven(UnprovenReason::SessionSettings))?;
        work.statement("SET NAMES utf8mb4 COLLATE utf8mb4_bin")?;
        sqlx_core::query::query("SET NAMES utf8mb4 COLLATE utf8mb4_bin")
            .execute(&mut connection)
            .await
            .map_err(|_| MySqlControlError::Unproven(UnprovenReason::SessionSettings))?;
        let observation = observe(&mut connection, &mut work).await?;
        if observation.database != config.endpoint.database {
            return Err(MySqlControlError::Unproven(UnprovenReason::SessionChanged));
        }
        Ok(Self {
            connection,
            observation,
            work,
            _permit: permit,
        })
    }
    pub(crate) async fn unchanged(&mut self) -> Result<()> {
        let observation = observe(&mut self.connection, &mut self.work).await?;
        if observation.roles != self.observation.roles
            || observation.enabled_roles != self.observation.enabled_roles
        {
            return Err(MySqlControlError::Unproven(UnprovenReason::RoleChanged));
        }
        if observation != self.observation {
            return Err(MySqlControlError::Unproven(UnprovenReason::SessionChanged));
        }
        Ok(())
    }
    pub(crate) async fn begin(&mut self) -> Result<()> {
        const SQL: &str = "START TRANSACTION";
        self.work.statement(SQL)?;
        sqlx_core::raw_sql::raw_sql(SQL)
            .execute(&mut self.connection)
            .await
            .map_err(|error| native_error(&error, RequiredCapability::Select))?;
        Ok(())
    }
}
fn options(config: &MySqlControlConfig) -> MySqlConnectOptions {
    let mut options = MySqlConnectOptions::new()
        .host(&config.endpoint.host)
        .port(config.endpoint.port.get())
        .database(&config.endpoint.database)
        .username(&config.credentials.username)
        .password(&config.credentials.password)
        .ssl_mode(MySqlSslMode::VerifyIdentity)
        .pipes_as_concat(false)
        .no_engine_substitution(false)
        .charset("utf8mb4")
        .collation("utf8mb4_bin")
        .timezone(Some("+00:00".to_owned()))
        .statement_cache_capacity(0)
        .enable_cleartext_plugin(false)
        .disable_statement_logging();
    if let Some(ca) = &config.ca_pem {
        options = options.ssl_ca_from_pem(ca.clone());
    }
    options
}
#[derive(Eq, PartialEq)]
pub(crate) struct Observation {
    pub(crate) id: u64,
    pub(crate) uuid: String,
    pub(crate) database: String,
    pub(crate) principal: String,
    pub(crate) roles: String,
    pub(crate) enabled_roles: Vec<(String, String)>,
    pub(crate) partial_revokes: bool,
    pub(crate) lower_case_table_names: u64,
}
pub(crate) struct Work {
    pub(crate) limits: MysqlCatalogLimits,
    bytes: usize,
    probes: usize,
}
impl Work {
    pub(crate) fn new(limits: MysqlCatalogLimits) -> Self {
        Self {
            limits,
            bytes: 0,
            probes: 0,
        }
    }
    pub(crate) fn statement(&mut self, sql: &str) -> Result<()> {
        self.probes = self
            .probes
            .checked_add(1)
            .ok_or(MySqlControlError::Unproven(UnprovenReason::Truncated))?;
        if sql.len() > self.limits.statement_bytes.get() || self.probes > self.limits.probes.get() {
            return Err(MySqlControlError::Unproven(UnprovenReason::Truncated));
        }
        Ok(())
    }
    pub(crate) fn bytes(&mut self, value: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(value)
            .ok_or(MySqlControlError::Unproven(UnprovenReason::Truncated))?;
        if self.bytes > self.limits.total_bytes.get() {
            return Err(MySqlControlError::Unproven(UnprovenReason::Truncated));
        }
        Ok(())
    }
    pub(crate) fn text(
        &mut self,
        row: &MySqlRow,
        column: usize,
        limit: usize,
    ) -> Result<Option<String>> {
        let value: Option<&str> = row
            .try_get(column)
            .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?;
        value
            .map(|value| {
                if value.len() > limit {
                    return Err(MySqlControlError::Unproven(UnprovenReason::Truncated));
                }
                self.bytes(value.len())?;
                Ok(value.to_owned())
            })
            .transpose()
    }
}
async fn observe(connection: &mut MySqlConnection, work: &mut Work) -> Result<Observation> {
    const SQL: &str = "SELECT CAST(CONNECTION_ID() AS UNSIGNED),@@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE(),CAST(@@GLOBAL.partial_revokes AS SIGNED),CAST(@@lower_case_table_names AS UNSIGNED),@@version,@@SESSION.sql_mode,CAST(@@SESSION.innodb_strict_mode AS SIGNED),CAST(@@SESSION.foreign_key_checks AS SIGNED),CAST(@@SESSION.unique_checks AS SIGNED),CAST(@@SESSION.sql_quote_show_create AS SIGNED),CAST(@@SESSION.show_gipk_in_create_table_and_information_schema AS SIGNED),@@SESSION.character_set_client,@@SESSION.character_set_connection,@@SESSION.character_set_results,@@SESSION.collation_connection,@@SESSION.time_zone,@@SESSION.transaction_isolation,CAST(@@GLOBAL.read_only AS SIGNED),CAST(@@GLOBAL.super_read_only AS SIGNED)";
    work.statement(SQL)?;
    let row = sqlx_core::query::query(SQL)
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::SessionSettings))?;
    let id = row
        .try_get::<u64, _>(0)
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::SessionChanged))?;
    let bound = work.limits.cell_bytes.get();
    let mut string = |index| {
        work.text(&row, index, bound)?
            .ok_or(MySqlControlError::Unproven(UnprovenReason::SessionSettings))
    };
    let uuid = string(1)?;
    let database = string(2)?;
    let principal = string(3)?;
    let roles = string(4)?;
    let version = string(7)?;
    if version != "8.4.11" {
        return Err(MySqlControlError::Unproven(UnprovenReason::SessionSettings));
    }
    let modes = string(8)?;
    let mut actual: Vec<_> = modes.split(',').collect();
    actual.sort_unstable();
    let mut expected: Vec<_> = SQL_MODES.split(',').collect();
    expected.sort_unstable();
    if actual != expected {
        return Err(MySqlControlError::Unproven(UnprovenReason::SessionSettings));
    }
    for (index, expected) in [
        (14, "utf8mb4"),
        (15, "utf8mb4"),
        (16, "utf8mb4"),
        (17, "utf8mb4_bin"),
        (18, "+00:00"),
        (19, "READ-COMMITTED"),
    ] {
        if string(index)? != expected {
            return Err(MySqlControlError::Unproven(UnprovenReason::SessionSettings));
        }
    }
    for index in 9..=13 {
        if row
            .try_get::<i64, _>(index)
            .map_err(|_| MySqlControlError::Unproven(UnprovenReason::SessionSettings))?
            != 1
        {
            return Err(MySqlControlError::Unproven(UnprovenReason::SessionSettings));
        }
    }
    for index in [20, 21] {
        if row
            .try_get::<i64, _>(index)
            .map_err(|_| MySqlControlError::Unproven(UnprovenReason::SessionSettings))?
            != 0
        {
            return Err(MySqlControlError::Denied(RequiredCapability::WritePrimary));
        }
    }
    let partial_revokes = row
        .try_get::<i64, _>(5)
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?
        != 0;
    let lower_case_table_names = row
        .try_get::<u64, _>(6)
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?;
    const ROLES: &str = "SELECT ROLE_NAME,ROLE_HOST FROM information_schema.ENABLED_ROLES ORDER BY ROLE_NAME,ROLE_HOST LIMIT ";
    let sql = format!(
        "{ROLES}{}",
        work.limits
            .roles
            .get()
            .checked_add(1)
            .ok_or(MySqlControlError::Configuration)?
    );
    work.statement(&sql)?;
    let mut stream = sqlx_core::query::query(AssertSqlSafe(sql)).fetch(&mut *connection);
    let mut enabled_roles = Vec::new();
    while let Some(row) = stream
        .try_next()
        .await
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::RoleChanged))?
    {
        if enabled_roles.len() >= work.limits.roles.get() {
            return Err(MySqlControlError::Unproven(UnprovenReason::Truncated));
        }
        let name = work
            .text(&row, 0, bound)?
            .ok_or(MySqlControlError::Unproven(UnprovenReason::RoleChanged))?;
        let host = work
            .text(&row, 1, bound)?
            .ok_or(MySqlControlError::Unproven(UnprovenReason::RoleChanged))?;
        enabled_roles.push((name, host));
    }
    Ok(Observation {
        id,
        uuid,
        database,
        principal,
        roles,
        enabled_roles,
        partial_revokes,
        lower_case_table_names,
    })
}
pub(crate) fn native_error(
    error: &sqlx_core::error::Error,
    capability: RequiredCapability,
) -> MySqlControlError {
    match error
        .as_database_error()
        .and_then(|error| error.try_downcast_ref::<sqlx_mysql::MySqlDatabaseError>())
        .map(sqlx_mysql::MySqlDatabaseError::number)
    {
        Some(1142 | 1143 | 1044 | 1227) => MySqlControlError::Denied(capability),
        _ => MySqlControlError::Storage,
    }
}
