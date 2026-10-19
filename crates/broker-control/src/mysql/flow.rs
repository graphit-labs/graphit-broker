mod roles;

mod identity;
pub use identity::MySqlLocalIdentities;

mod session;
pub use session::MySqlAdminSessions;

use super::{
    MySqlControlConfig, MySqlControlError, RequiredCapability, Result,
    bootstrap::{self, CommitState},
    capability::Operation,
    catalog, config,
    executor::{Admission, Lease, native_error},
};
use crate::{
    FlowLimits, OidcFlow,
    flow::{FLOW_TTL_MICROS, now_micros},
};
use broker_security::{CredentialDigester, TokenKind};
use sqlx_core::{row::Row, sql_str::AssertSqlSafe};
use std::{fmt, sync::Arc, time::Instant};

/// Owns configuration and admission; each logical operation uses a new private
/// TCP connection with observed settings and identity. Flow and metadata readers
/// also validate their catalog contracts; role definitions execute their SQL directly.
pub struct MySqlControlStore {
    config: MySqlControlConfig,
    digester: CredentialDigester,
    admission: Arc<Admission>,
    limits: FlowLimits,
}
impl fmt::Debug for MySqlControlStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MySqlControlStore([REDACTED])")
    }
}
impl MySqlControlStore {
    pub async fn open(
        config: MySqlControlConfig,
        digester: CredentialDigester,
        caller: Instant,
    ) -> Result<Self> {
        config.validate()?;
        let limits = config.physical_flow_limits()?;
        let end = config::deadline(caller, config.admission.budgets.startup)?;
        let admission = Admission::new(config.admission.max_inflight.get());
        let state = CommitState::new();
        tokio::time::timeout_at(end.into(), async {
            let mut lease = Lease::open(&config, &admission, end).await?;
            bootstrap::initialize(&mut lease, &state, end, config.admission.budgets.lock).await?;
            // No new fallible await after confirmed COMMIT and RELEASE_LOCK.
            drop(lease);
            Ok(())
        })
        .await
        .map_err(|_| state.timeout(true))??;
        Ok(Self {
            config,
            digester,
            admission,
            limits,
        })
    }
    pub async fn save_flow(
        &self,
        state: &[u8],
        browser_binding: &[u8],
        flow: OidcFlow,
        caller: Instant,
    ) -> Result<()> {
        let end = config::deadline(caller, self.config.admission.budgets.operation)?;
        // Effective serialized TEXT capacity is enforced before admission/SQL.
        let json = flow
            .validate(self.limits)
            .map_err(|_| MySqlControlError::InvalidFlow)?;
        let (state, binding) = self.digests(state, browser_binding)?;
        valid_expiry(flow.expiry_micros(), clock()?)?;
        let commit = CommitState::new();
        tokio::time::timeout_at(end.into(),async {
            let mut lease = self.operation(end,Operation::Save).await?;
            let created = clock()?;
            valid_expiry(flow.expiry_micros(),created)?;
            let database = config::identifier(&lease.observation.database,lease.work.limits.statement_bytes.get())?;
            let sql = format!("INSERT INTO {database}.`oidc_flows`(state_hash,browser_binding_hash,nonce,pkce_verifier,purpose,continuation_json,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)");
            lease.work.statement(&sql)?;
            let result = sqlx_core::query::query(AssertSqlSafe(sql)).bind(state).bind(binding).bind(flow.nonce()).bind(flow.pkce_verifier())
                .bind(flow.continuation().purpose().as_str()).bind(json).bind(flow.expiry_micros()).bind(created).execute(&mut lease.connection).await;
            let changed = match result {
                Ok(result) => result.rows_affected(),
                Err(error) => return Err(if error.as_database_error().and_then(|error| error.try_downcast_ref::<sqlx_mysql::MySqlDatabaseError>()).map(sqlx_mysql::MySqlDatabaseError::number) == Some(1062) { MySqlControlError::FlowExists } else { native_error(&error,RequiredCapability::Insert) }),
            };
            if changed != 1 { return Err(MySqlControlError::Storage); }
            lease.unchanged().await?;
            let before_commit = clock()?;
            if before_commit < created { return Err(MySqlControlError::Clock); }
            if flow.expiry_micros() <= before_commit { return Err(MySqlControlError::InvalidFlow); }
            commit.commit(&mut lease).await?;
            drop(lease);
            Ok(())
        }).await.map_err(|_| commit.timeout(false))?
    }
    pub async fn consume_flow(
        &self,
        state: &[u8],
        browser_binding: &[u8],
        caller: Instant,
    ) -> Result<OidcFlow> {
        let end = config::deadline(caller, self.config.admission.budgets.operation)?;
        let (state, binding) = self.digests(state, browser_binding)?;
        let cap = u64::try_from(self.limits.continuation_bytes.get())
            .map_err(|_| MySqlControlError::Configuration)?;
        let commit = CommitState::new();
        tokio::time::timeout_at(end.into(),async {
            let mut lease = self.operation(end,Operation::Consume).await?;
            let database = config::identifier(&lease.observation.database,lease.work.limits.statement_bytes.get())?;
            let sql = format!("SELECT CASE WHEN OCTET_LENGTH(nonce)<=128 THEN nonce ELSE NULL END,CASE WHEN OCTET_LENGTH(pkce_verifier)<=128 THEN pkce_verifier ELSE NULL END,CASE WHEN OCTET_LENGTH(purpose)<=5 THEN purpose ELSE NULL END,CASE WHEN OCTET_LENGTH(continuation_json)<=? THEN continuation_json ELSE NULL END,expires_at,created_at FROM {database}.`oidc_flows` WHERE state_hash=? AND browser_binding_hash=? FOR UPDATE");
            lease.work.statement(&sql)?;
            let row = sqlx_core::query::query(AssertSqlSafe(sql)).bind(cap).bind(&state).bind(&binding).fetch_optional(&mut lease.connection).await.map_err(|error| native_error(&error,RequiredCapability::Select))?.ok_or(MySqlControlError::Unavailable)?;
            let nonce = lease.work.text(&row,0,128)?.ok_or(MySqlControlError::CorruptFlow)?;
            let verifier = lease.work.text(&row,1,128)?.ok_or(MySqlControlError::CorruptFlow)?;
            let purpose = lease.work.text(&row,2,5)?.ok_or(MySqlControlError::CorruptFlow)?;
            let json = lease.work.text(&row,3,self.limits.continuation_bytes.get())?.ok_or(MySqlControlError::CorruptFlow)?;
            let expiry: i64 = row.try_get(4).map_err(|_| MySqlControlError::CorruptFlow)?;
            let created: i64 = row.try_get(5).map_err(|_| MySqlControlError::CorruptFlow)?;
            let flow = OidcFlow::stored(nonce,verifier,&purpose,&json,expiry,created,self.limits).map_err(|_| MySqlControlError::CorruptFlow)?;
            let after_lock = clock()?;
            if created > after_lock { return Err(MySqlControlError::CorruptFlow); }
            let expired_after_lock = expiry <= after_lock;
            if !expired_after_lock {
                tracing::trace!(target: "broker_control::mysql::flow_locked_live", "locked login flow remains live before deletion");
            }
            let sql = format!("DELETE FROM {database}.`oidc_flows` WHERE state_hash=? AND browser_binding_hash=?");
            lease.work.statement(&sql)?;
            if sqlx_core::query::query(AssertSqlSafe(sql)).bind(state).bind(binding).execute(&mut lease.connection).await.map_err(|error| native_error(&error,RequiredCapability::Delete))?.rows_affected() != 1 { return Err(MySqlControlError::Storage); }
            tracing::trace!(target: "broker_control::mysql::flow_delete_staged", "login flow deletion staged in current transaction");
            lease.unchanged().await?;
            let before_commit = clock()?;
            let expired = consumed_expired(created,expiry,expired_after_lock,before_commit)?;
            commit.commit(&mut lease).await?;
            tracing::trace!(target: "broker_control::mysql::flow_consume_committed", "login flow consumption commit confirmed");
            drop(lease);
            // Known commit outcome has no subsequent fallible cleanup await.
            if expired { Err(MySqlControlError::Expired) } else { Ok(flow) }
        }).await.map_err(|_| commit.timeout(false))?
    }
    pub async fn shutdown(&self, caller: Instant) -> Result<()> {
        self.admission.stop()?;
        let end = config::deadline(caller, self.config.admission.budgets.shutdown)?;
        self.admission.close(end).await
    }
    fn digests(&self, state: &[u8], binding: &[u8]) -> Result<(String, String)> {
        let state = self
            .digester
            .token(TokenKind::OidcFlowState, state)
            .map_err(|_| MySqlControlError::InvalidFlow)?
            .to_sql_hex();
        let binding = self
            .digester
            .token(TokenKind::OidcBrowserBinding, binding)
            .map_err(|_| MySqlControlError::InvalidFlow)?
            .to_sql_hex();
        Ok((state, binding))
    }
    async fn operation(&self, end: Instant, operation: Operation) -> Result<Lease> {
        let mut lease = Lease::open(&self.config, &self.admission, end).await?;
        lease.begin().await?;
        catalog::inspect(&mut lease, operation).await?;
        Ok(lease)
    }
}
fn clock() -> Result<i64> {
    now_micros().map_err(|_| MySqlControlError::Clock)
}
fn consumed_expired(
    created: i64,
    expiry: i64,
    expired_after_lock: bool,
    before_commit: i64,
) -> Result<bool> {
    if before_commit < created {
        return Err(MySqlControlError::Clock);
    }
    Ok(expired_after_lock || expiry <= before_commit)
}
fn valid_expiry(expiry: i64, now: i64) -> Result<()> {
    if expiry <= now
        || expiry
            .checked_sub(now)
            .is_none_or(|ttl| ttl > FLOW_TTL_MICROS)
    {
        Err(MySqlControlError::InvalidFlow)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expiry_latch_survives_clock_reversal_before_commit() {
        assert_eq!(consumed_expired(10, 20, false, 19), Ok(false));
        assert_eq!(consumed_expired(10, 20, false, 20), Ok(true));
        // An observed expiry cannot be undone by a later earlier wall time.
        assert_eq!(consumed_expired(10, 20, true, 15), Ok(true));
        // A wall time older than creation cannot authorize any COMMIT.
        assert_eq!(
            consumed_expired(10, 20, true, 9),
            Err(MySqlControlError::Clock)
        );
    }
    #[test]
    fn expiry_bounds_reject_overflow_and_closed_interval() {
        assert_eq!(valid_expiry(i64::MAX, i64::MAX - 1), Ok(()));
        assert_eq!(valid_expiry(1, 1), Err(MySqlControlError::InvalidFlow));
        assert_eq!(
            valid_expiry(i64::MAX, 0),
            Err(MySqlControlError::InvalidFlow)
        );
        assert_eq!(valid_expiry(FLOW_TTL_MICROS, 0), Ok(()));
        assert_eq!(
            valid_expiry(FLOW_TTL_MICROS + 1, 0),
            Err(MySqlControlError::InvalidFlow)
        );
    }
}
