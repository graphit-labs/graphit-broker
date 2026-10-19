mod instance_candidates;
mod local_instance_registration;
mod local_inventory_list;
mod local_inventory_read;
pub use instance_candidates::SqliteInstanceInventoryCandidates;
pub use local_instance_registration::SqliteLocalInstanceRegistrar;
pub use local_inventory_list::SqliteLocalInstanceInventoryLister;
pub use local_inventory_read::SqliteLocalInstanceInventoryReader;
mod admin_users;
pub use admin_users::SqliteAdminUsers;
mod hub_access;
mod storage_admission;
pub use hub_access::{SqliteBrokerHubAccessResolver, SqliteLocalHubAccessResolver};
pub use storage_admission::{SqliteBrokerStorageAuthorizer, SqliteLocalStorageAuthorizer};
mod admin_rbac;
pub use admin_rbac::SqliteAdminRbac;
mod admin_grants;
pub use admin_grants::SqliteAdminGrants;
mod admin_read;
pub use admin_read::{SqliteAdminReads, SqliteLocalAdminReads};
mod oidc_access_snapshot;
mod oidc_userinfo;
mod upstream_login;
pub use oidc_userinfo::SqliteOidcUserInfo;
pub use upstream_login::SqliteUpstreamLogins;
mod oidc_end_session;
mod oidc_introspection;
mod oidc_revocation;
pub use oidc_end_session::SqliteOidcEndSession;
pub use oidc_introspection::SqliteOidcIntrospection;
pub use oidc_revocation::SqliteOidcRevocation;
mod device;
pub use device::SqliteDeviceAuthorizations;
mod admin_broker_session;
mod admin_upstream_session;
pub use admin_broker_session::SqliteAdminBrokerSessions;
pub use admin_upstream_session::SqliteAdminUpstreamSessions;
mod embedding_admission;
mod rerank_admission;
pub use rerank_admission::SqliteRerankAdmissions;
mod embedding_cache;
pub use embedding_admission::SqliteEmbeddingAdmissions;
pub use embedding_cache::SqliteEmbeddingCache;
mod admin_local_bearer_session;
pub use admin_local_bearer_session::SqliteAdminLocalBearerSessions;
mod oidc_authorization;
mod oidc_refresh;
mod oidc_token_exchange;
mod oidc_tokens;
pub use oidc_authorization::SqliteOidcAuthorizationService;
pub use oidc_refresh::SqliteOidcRefresh;
pub use oidc_token_exchange::SqliteOidcTokenExchange;
mod broker_instance_inventory_read;
mod broker_instance_registration;
mod broker_now_channel;
pub use broker_instance_inventory_read::SqliteBrokerInstanceInventoryReader;
pub use broker_instance_registration::SqliteBrokerInstanceRegistrar;
pub use broker_now_channel::SqliteNowChannelAuthorizer;
mod local_bearer;
mod local_bearer_verifier;
mod project_authorization;
pub use local_bearer_verifier::SqliteLocalBearerVerifier;
pub use project_authorization::SqliteLocalProjectAuthorizer;
mod admin_cookie_session;
mod admin_local_observer;
pub use admin_cookie_session::{SqliteAdminCookieSessions, SqliteLocalAdminCookieSessions};
mod broker_project_authorization;
pub use broker_project_authorization::SqliteBrokerProjectAuthorizer;
mod instance_read;
pub use instance_read::SqliteInstanceInventories;
mod oidc_registration;
pub use oidc_registration::SqliteOidcRegistrationService;
mod session;
pub use session::SqliteAdminSessions;
mod identity;
mod instances;
mod resource_grants;
mod roles;
pub use identity::SqliteLocalIdentities;
pub use resource_grants::SqliteResourceGrants;
mod local_administrator;
mod local_auth;
mod local_password;
use super::{Result, SqliteControlConfig, SqliteControlError, executor::Executor};
use crate::{
    FlowLimits, OidcFlow,
    flow::{FLOW_TTL_MICROS, now_micros},
};
use broker_security::{CredentialDigester, TokenKind};
pub use local_auth::SqliteLocalAuthService;
pub use local_password::{SqliteAdmittedLocalPasswords, SqliteLocalPasswordVerifier};
use rusqlite::{OptionalExtension, params};
use std::{fmt, sync::Arc, time::Instant};

/// One physical SQLite connection. Callers authenticate/authorize all journeys;
/// stored login continuation metadata is never an authorization capability.
///
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore) { let _ = &store.executor; }
/// ```
pub struct SqliteControlStore {
    executor: Executor,
    digester: Arc<CredentialDigester>,
    limits: FlowLimits,
}
impl fmt::Debug for SqliteControlStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteControlStore([REDACTED])")
    }
}
impl SqliteControlStore {
    pub async fn open(
        config: SqliteControlConfig,
        digester: CredentialDigester,
        caller: Instant,
    ) -> Result<Self> {
        let limits = config.flows;
        let executor = Executor::open(config, caller).await?;
        Ok(Self {
            executor,
            digester: Arc::new(digester),
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
        let json = flow
            .validate(self.limits)
            .map_err(|_| SqliteControlError::InvalidFlow)?;
        let (state, binding) = self.digests(state, browser_binding)?;
        valid_expiry(flow.expiry_micros(), clock()?)?;
        self.executor.execute(caller, move |owner, work| {
            let tx = owner.begin(work)?;
            let created = clock()?;
            valid_expiry(flow.expiry_micros(), created)?;
            let result = tx.execute("INSERT INTO oidc_flows(state_hash,browser_binding_hash,nonce,pkce_verifier,purpose,continuation_json,expires_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![state,binding,flow.nonce(),flow.pkce_verifier(),flow.continuation().purpose().as_str(),json,flow.expiry_micros(),created]);
            match result {
                Ok(1) => {},
                Ok(_) => return Err(SqliteControlError::Storage),
                Err(error) if matches!(error.sqlite_error().map(|error| error.extended_code), Some(rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY | rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)) => return Err(SqliteControlError::FlowExists),
                Err(error) => return Err(work.sql(error)),
            }
            let before_commit = clock()?;
            if before_commit < created { return Err(SqliteControlError::Clock); }
            if flow.expiry_micros() <= before_commit { return Err(SqliteControlError::InvalidFlow); }
            work.commit(tx)
        }).await
    }
    pub async fn consume_flow(
        &self,
        state: &[u8],
        browser_binding: &[u8],
        caller: Instant,
    ) -> Result<OidcFlow> {
        let (state, binding) = self.digests(state, browser_binding)?;
        let limits = self.limits;
        self.executor.execute(caller, move |owner, work| {
            let tx = owner.begin(work)?;
            let row = tx.query_row("SELECT CASE WHEN length(CAST(nonce AS BLOB))<=128 THEN nonce END,CASE WHEN length(CAST(pkce_verifier AS BLOB))<=128 THEN pkce_verifier END,CASE WHEN length(CAST(purpose AS BLOB))<=5 THEN purpose END,CASE WHEN length(CAST(continuation_json AS BLOB))<=?1 THEN continuation_json END,expires_at,created_at FROM oidc_flows WHERE state_hash=?2 AND browser_binding_hash=?3",params![limits.continuation_bytes.get() as i64,&state,&binding], |row| {
                Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?, row.get::<_,String>(2)?, row.get::<_,String>(3)?, row.get::<_,i64>(4)?, row.get::<_,i64>(5)?))
            }).optional().map_err(|error| {
                if work.check().is_err() { work.sql(error) } else { SqliteControlError::CorruptFlow }
            })?.ok_or(SqliteControlError::Unavailable)?;
            let flow = OidcFlow::stored(row.0,row.1,&row.2,&row.3,row.4,row.5,limits).map_err(|_| SqliteControlError::CorruptFlow)?;
            let after_lock = clock()?;
            if row.5 > after_lock { return Err(SqliteControlError::CorruptFlow); }
            let expired_after_lock = row.4 <= after_lock;
            if tx.execute("DELETE FROM oidc_flows WHERE state_hash=?1 AND browser_binding_hash=?2", params![state,binding]).map_err(|error| work.sql(error))? != 1 { return Err(SqliteControlError::Storage); }
            tracing::trace!(target: "broker_control::sqlite::flow_delete_staged", "SQLite login flow deletion staged");
            let before_commit = clock()?;
            if before_commit < row.5 { return Err(SqliteControlError::Clock); }
            let expired = expired_after_lock || row.4 <= before_commit;
            work.commit(tx)?;
            if expired { Err(SqliteControlError::Expired) } else { Ok(flow) }
        }).await
    }
    pub fn shutdown(
        &self,
        caller: Instant,
    ) -> impl std::future::Future<Output = Result<()>> + Send + '_ {
        self.executor.shutdown(caller)
    }

    fn digests(&self, state: &[u8], binding: &[u8]) -> Result<(String, String)> {
        Ok((
            self.digester
                .token(TokenKind::OidcFlowState, state)
                .map_err(|_| SqliteControlError::InvalidFlow)?
                .to_sql_hex(),
            self.digester
                .token(TokenKind::OidcBrowserBinding, binding)
                .map_err(|_| SqliteControlError::InvalidFlow)?
                .to_sql_hex(),
        ))
    }
}
fn clock() -> Result<i64> {
    now_micros().map_err(|_| SqliteControlError::Clock)
}
fn valid_expiry(expiry: i64, now: i64) -> Result<()> {
    if expiry <= now
        || expiry
            .checked_sub(now)
            .is_none_or(|ttl| ttl > FLOW_TTL_MICROS)
    {
        Err(SqliteControlError::InvalidFlow)
    } else {
        Ok(())
    }
}
