use super::{
    CleanupReason, MySqlControlError, RequiredCapability, Result, SchemaReason, UnprovenReason,
    capability::{self, Grants, Operation},
    catalog,
    config::identifier,
    executor::{Lease, native_error},
};
use broker_store::{
    schema::{Dialect, SchemaVersion, TABLES},
    seeds::InitialSeeds,
    time::TimestampMicros,
};
use sqlx_core::{row::Row, sql_str::AssertSqlSafe};
use std::{
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};

pub(crate) const STARTUP_LOCK: &str = "graphit-broker-rust-control-startup-v1";
const NOT_SENT: u8 = 0;
const SENT: u8 = 1;
const CONFIRMED: u8 = 2;
pub(crate) struct CommitState(AtomicU8);
impl CommitState {
    pub(crate) fn new() -> Self {
        Self(AtomicU8::new(NOT_SENT))
    }
    pub(crate) fn timeout(&self, startup: bool) -> MySqlControlError {
        match self.0.load(Ordering::Relaxed) {
            SENT => MySqlControlError::OutcomeUncertain,
            CONFIRMED if startup => {
                MySqlControlError::StartupCommittedCleanupFailed(CleanupReason::Deadline)
            }
            _ => MySqlControlError::Deadline,
        }
    }
    pub(crate) async fn commit(&self, lease: &mut Lease) -> Result<()> {
        lease.work.statement("COMMIT")?;
        // Sent means attempt started, not an independently observable wire ACK.
        self.0.store(SENT, Ordering::Relaxed);
        sqlx_core::raw_sql::raw_sql("COMMIT")
            .execute(&mut lease.connection)
            .await
            .map_err(|_| MySqlControlError::OutcomeUncertain)?;
        self.0.store(CONFIRMED, Ordering::Relaxed);
        Ok(())
    }
}
pub(crate) async fn initialize(
    lease: &mut Lease,
    state: &CommitState,
    end: Instant,
    lock_budget: Duration,
) -> Result<()> {
    let remaining = end
        .checked_duration_since(Instant::now())
        .ok_or(MySqlControlError::Deadline)?
        .min(lock_budget);
    let seconds =
        i64::try_from(remaining.as_secs()).map_err(|_| MySqlControlError::Configuration)?;
    const LOCK: &str = "SELECT CAST(GET_LOCK(?,?) AS SIGNED)";
    lease.work.statement(LOCK)?;
    let row = sqlx_core::query::query(LOCK)
        .bind(STARTUP_LOCK)
        .bind(seconds)
        .fetch_one(&mut lease.connection)
        .await
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?;
    match row
        .try_get::<Option<i64>, _>(0)
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?
    {
        Some(1) => {}
        Some(0) => return Err(MySqlControlError::StartupBusy),
        _ => return Err(MySqlControlError::Unproven(UnprovenReason::Visibility)),
    }
    owner(lease).await?;
    let grants = Grants::read(lease).await?;
    grants.triggers(&lease.observation.database)?;
    capability::events_absent(lease).await?;
    let fresh = catalog::fresh(lease, &grants).await?;
    if fresh {
        grants.creation(&lease.observation.database)?;
        lease.unchanged().await?;
        for table in TABLES {
            // Producer DDL only. Empty-database proof precedes these genuine
            // CREATEs; there is no DDL probe, importer or partial-DDL resume.
            let sql = table.create_statement(Dialect::Mysql).replacen(
                "CREATE TABLE IF NOT EXISTS ",
                "CREATE TABLE ",
                1,
            );
            lease.work.statement(&sql)?;
            sqlx_core::query::query(AssertSqlSafe(sql))
                .execute(&mut lease.connection)
                .await
                .map_err(|error| native_error(&error, RequiredCapability::Create))?;
        }
    }
    lease.begin().await?;
    catalog::inspect(lease, Operation::Startup).await?;
    if !fresh {
        marker(lease).await?;
    }
    seeds(lease).await?;
    if fresh {
        let database = identifier(
            &lease.observation.database,
            lease.work.limits.statement_bytes.get(),
        )?;
        let sql = format!("INSERT INTO {database}.`schema_meta`(id,format,epoch) VALUES(1,?,?)");
        lease.work.statement(&sql)?;
        let changed = sqlx_core::query::query(AssertSqlSafe(sql))
            .bind(SchemaVersion::FORMAT)
            .bind(SchemaVersion::EPOCH)
            .execute(&mut lease.connection)
            .await
            .map_err(|error| native_error(&error, RequiredCapability::Insert))?
            .rows_affected();
        if changed != 1 {
            return Err(MySqlControlError::Storage);
        }
    }
    lease.unchanged().await?;
    owner(lease).await?;
    state.commit(lease).await?;
    const RELEASE: &str = "SELECT CAST(RELEASE_LOCK(?) AS SIGNED)";
    // From this point errors concern cleanup of a known committed startup.
    lease.work.statement(RELEASE).map_err(|_| cleanup())?;
    let row = sqlx_core::query::query(RELEASE)
        .bind(STARTUP_LOCK)
        .fetch_one(&mut lease.connection)
        .await
        .map_err(|_| cleanup())?;
    if row.try_get::<Option<i64>, _>(0).map_err(|_| cleanup())? != Some(1) {
        return Err(cleanup());
    }
    Ok(())
}
fn cleanup() -> MySqlControlError {
    MySqlControlError::StartupCommittedCleanupFailed(CleanupReason::LockRelease)
}
async fn owner(lease: &mut Lease) -> Result<()> {
    const SQL: &str = "SELECT CAST(IS_USED_LOCK(?) AS UNSIGNED),CAST(CONNECTION_ID() AS UNSIGNED)";
    lease.work.statement(SQL)?;
    let row = sqlx_core::query::query(SQL)
        .bind(STARTUP_LOCK)
        .fetch_one(&mut lease.connection)
        .await
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::SessionChanged))?;
    let owner: Option<u64> = row
        .try_get(0)
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::SessionChanged))?;
    let id: u64 = row
        .try_get(1)
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::SessionChanged))?;
    if owner != Some(id) || id != lease.observation.id {
        return Err(MySqlControlError::Unproven(UnprovenReason::SessionChanged));
    }
    lease.unchanged().await
}
async fn marker(lease: &mut Lease) -> Result<()> {
    let database = identifier(
        &lease.observation.database,
        lease.work.limits.statement_bytes.get(),
    )?;
    let sql = format!("SELECT format,epoch FROM {database}.`schema_meta` WHERE id=1");
    lease.work.statement(&sql)?;
    let row = sqlx_core::query::query(AssertSqlSafe(sql))
        .fetch_optional(&mut lease.connection)
        .await
        .map_err(|error| native_error(&error, RequiredCapability::Select))?
        .ok_or(MySqlControlError::SchemaRejected(SchemaReason::Marker))?;
    let format = lease
        .work
        .text(&row, 0, lease.work.limits.cell_bytes.get())?
        .ok_or(MySqlControlError::SchemaRejected(SchemaReason::Marker))?;
    let epoch: i64 = row
        .try_get(1)
        .map_err(|_| MySqlControlError::SchemaRejected(SchemaReason::Marker))?;
    SchemaVersion::validate(&format, epoch)
        .map_err(|_| MySqlControlError::SchemaRejected(SchemaReason::Marker))?;
    Ok(())
}
async fn seeds(lease: &mut Lease) -> Result<()> {
    let seeds = InitialSeeds::new(
        TimestampMicros::new(crate::flow::now_micros().map_err(|_| MySqlControlError::Clock)?)
            .map_err(|_| MySqlControlError::Clock)?,
    );
    let database = identifier(
        &lease.observation.database,
        lease.work.limits.statement_bytes.get(),
    )?;
    for role in seeds.roles() {
        let sql = format!("SELECT name,created_at FROM {database}.`roles` WHERE name=? FOR UPDATE");
        lease.work.statement(&sql)?;
        let existing = sqlx_core::query::query(AssertSqlSafe(sql))
            .bind(role.name())
            .fetch_optional(&mut lease.connection)
            .await
            .map_err(|error| native_error(&error, RequiredCapability::Select))?;
        if let Some(row) = existing {
            let name = lease
                .work
                .text(&row, 0, lease.work.limits.cell_bytes.get())?
                .ok_or(MySqlControlError::Storage)?;
            if name != role.name() || row.try_get::<i64, _>(1).is_err() {
                return Err(MySqlControlError::Storage);
            }
        } else {
            let sql = format!("INSERT INTO {database}.`roles`(name,created_at) VALUES(?,?)");
            lease.work.statement(&sql)?;
            if sqlx_core::query::query(AssertSqlSafe(sql))
                .bind(role.name())
                .bind(seeds.timestamp().as_i64())
                .execute(&mut lease.connection)
                .await
                .map_err(|error| native_error(&error, RequiredCapability::Insert))?
                .rows_affected()
                != 1
            {
                return Err(MySqlControlError::Storage);
            }
        }
        let sql = format!("DELETE FROM {database}.`role_permissions` WHERE role=?");
        lease.work.statement(&sql)?;
        sqlx_core::query::query(AssertSqlSafe(sql))
            .bind(role.name())
            .execute(&mut lease.connection)
            .await
            .map_err(|error| native_error(&error, RequiredCapability::Delete))?;
        for action in role.actions() {
            let sql = format!("INSERT INTO {database}.`role_permissions`(role,action) VALUES(?,?)");
            lease.work.statement(&sql)?;
            if sqlx_core::query::query(AssertSqlSafe(sql))
                .bind(role.name())
                .bind(action.as_str())
                .execute(&mut lease.connection)
                .await
                .map_err(|error| native_error(&error, RequiredCapability::Insert))?
                .rows_affected()
                != 1
            {
                return Err(MySqlControlError::Storage);
            }
        }
    }
    let sql = format!(
        "SELECT id,revision,updated_at FROM {database}.`resource_acl_state` WHERE id=1 FOR UPDATE"
    );
    lease.work.statement(&sql)?;
    let existing = sqlx_core::query::query(AssertSqlSafe(sql))
        .fetch_optional(&mut lease.connection)
        .await
        .map_err(|error| native_error(&error, RequiredCapability::Select))?;
    if let Some(row) = existing {
        if row.try_get::<i16, _>(0).ok() != Some(1)
            || row.try_get::<i64, _>(1).is_err()
            || row.try_get::<i64, _>(2).is_err()
        {
            return Err(MySqlControlError::Storage);
        }
    } else {
        let sql = format!(
            "INSERT INTO {database}.`resource_acl_state`(id,revision,updated_at) VALUES(1,?,?)"
        );
        lease.work.statement(&sql)?;
        if sqlx_core::query::query(AssertSqlSafe(sql))
            .bind(seeds.acl_revision())
            .bind(seeds.timestamp().as_i64())
            .execute(&mut lease.connection)
            .await
            .map_err(|error| native_error(&error, RequiredCapability::Insert))?
            .rows_affected()
            != 1
        {
            return Err(MySqlControlError::Storage);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_commit_cleanup_is_distinct_from_uncertain_attempt() {
        let state = CommitState::new();
        assert_eq!(state.timeout(true), MySqlControlError::Deadline);
        state.0.store(SENT, Ordering::Relaxed);
        assert_eq!(state.timeout(true), MySqlControlError::OutcomeUncertain);
        state.0.store(CONFIRMED, Ordering::Relaxed);
        assert_eq!(
            state.timeout(true),
            MySqlControlError::StartupCommittedCleanupFailed(CleanupReason::Deadline)
        );
        assert!(STARTUP_LOCK.len() <= 64 && STARTUP_LOCK.is_ascii());
    }
}
