pub(crate) use roles::role_values;
mod embedding_admission;
mod rerank_admission;
pub use rerank_admission::PostgresRerankAdmissions;
mod embedding_cache;
pub use embedding_admission::PostgresEmbeddingAdmissions;
pub use embedding_cache::PostgresEmbeddingCache;
pub(crate) mod admin_cookie_session;
pub(crate) mod upstream_login;
pub(crate) use admin_cookie_session::CookieReadProof;
pub use admin_cookie_session::PostgresAdminCookieSessions;
pub use upstream_login::{
    PostgresUpstreamLogins, UPSTREAM_LOGIN_STATE_BYTES, upstream_login_purpose_hint,
};
mod admin_broker_session;
mod admin_grants;
mod admin_rbac;
mod admin_read;
mod admin_users;
pub use admin_broker_session::PostgresAdminBrokerSessions;
pub use admin_grants::PostgresAdminGrants;
pub use admin_rbac::PostgresAdminRbac;
pub use admin_read::PostgresAdminReads;
pub use admin_users::PostgresAdminUsers;
mod admin_local_bearer_session;
pub(crate) mod admin_upstream_session;
pub use admin_local_bearer_session::PostgresAdminLocalBearerSessions;
pub use admin_upstream_session::PostgresAdminUpstreamSessions;
mod now_channel;
pub use now_channel::PostgresNowChannelAuthorizer;
mod broker_instance_inventory_read;
pub use broker_instance_inventory_read::PostgresBrokerInstanceInventoryReader;
mod broker_instance_registration;
pub use broker_instance_registration::PostgresBrokerInstanceRegistrar;
mod oidc_registration;
pub use oidc_registration::PostgresOidcRegistrationService;
pub(crate) mod oidc_access_snapshot;
pub(crate) mod oidc_authorization;
mod oidc_end_session;
mod oidc_introspection;
pub(crate) mod oidc_principal;
pub(crate) mod oidc_refresh;
mod oidc_revocation;
pub use oidc_end_session::PostgresOidcEndSession;
pub use oidc_introspection::PostgresOidcIntrospection;
mod oidc_userinfo;
pub use oidc_revocation::PostgresOidcRevocation;
pub use oidc_userinfo::PostgresOidcUserInfo;
pub(crate) mod oidc_token_exchange;
pub(crate) mod oidc_tokens;
pub use oidc_authorization::PostgresOidcAuthorizationService;
pub use oidc_refresh::PostgresOidcRefresh;
pub use oidc_token_exchange::PostgresOidcTokenExchange;
mod local_auth;
pub use local_auth::PostgresLocalAuthService;
pub(crate) use local_auth::preserve_federated_request;
mod local_administrator;
mod local_password;
pub use local_password::PostgresAdmittedLocalPasswords;
pub use local_password::PostgresLocalPasswordVerifier;
mod broker_project_authorization;
pub use broker_project_authorization::PostgresBrokerProjectAuthorizer;
mod broker_presence_authorization;
pub use broker_presence_authorization::PostgresBrokerPresenceAuthorizer;
mod hub_access;
pub use hub_access::{PostgresBrokerHubAccessResolver, PostgresLocalHubAccessResolver};
mod storage_admission;
pub use storage_admission::{PostgresBrokerStorageAuthorizer, PostgresLocalStorageAuthorizer};
mod identity;
mod instance_candidates;
pub use instance_candidates::PostgresInstanceInventoryCandidates;
mod instance_inventory_read;
pub use instance_inventory_read::PostgresLocalInstanceInventoryReader;
mod instance_list;
pub use instance_list::PostgresLocalInstanceInventoryLister;
mod instance_read;
pub use instance_read::PostgresInstanceInventories;
mod instance_registration;
mod instances;
pub use instance_registration::PostgresLocalInstanceRegistrar;
mod local_bearer;
mod oidc_access_grant;
pub use oidc_access_grant::PostgresOidcAccessGrants;
mod local_bearer_verifier;
mod presence_authorization;
mod project_authorization;
pub use presence_authorization::PostgresLocalPresenceAuthorizer;
pub use project_authorization::PostgresLocalProjectAuthorizer;
mod resource_grants;
pub use local_bearer::PostgresLocalBearerStates;
pub use local_bearer_verifier::PostgresLocalBearerVerifier;
pub use resource_grants::PostgresResourceGrants;
mod roles;
pub use identity::PostgresLocalIdentities;

use crate::{
    ControlError, FlowLimits, OidcFlow, PostgresConfig,
    config::PoolConfig,
    flow::{FLOW_TTL_MICROS, now_micros},
    schema,
    session::{
        AdminSession, AdminSessions, NewAdminSession, SessionLimits, SessionPrincipal,
        SessionProfile, SessionRevocation, positive_expiry,
    },
};
use broker_security::{CredentialDigester, TokenKind};
use sqlx_core::{pool::PoolConnection, row::Row};
use sqlx_postgres::{PgConnection, PgPool, PgPoolOptions, Postgres};
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

/// A failed or cancelled transaction cannot return its connection for another caller.
struct ConnectionGuard(Option<PoolConnection<Postgres>>);
impl ConnectionGuard {
    fn connection(&mut self) -> Result<&mut PgConnection, ControlError> {
        self.0.as_deref_mut().ok_or(ControlError::Storage)
    }
    fn confirmed(&mut self) {
        drop(self.0.take());
    }
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(connection) = self.0.as_mut() {
            connection.close_on_drop();
        }
    }
}
pub struct PostgresControlStore {
    pool: PgPool,
    digester: CredentialDigester,
    budgets: PoolConfig,
    limits: FlowLimits,
}
impl fmt::Debug for PostgresControlStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresControlStore([REDACTED])")
    }
}
fn bounded_deadline(caller: Instant, budget: std::time::Duration) -> Result<Instant, ControlError> {
    let now = Instant::now();
    if caller <= now {
        return Err(ControlError::Deadline);
    }
    Ok(caller.min(now.checked_add(budget).ok_or(ControlError::Configuration)?))
}
fn storage_error(error: sqlx_core::error::Error) -> ControlError {
    match error {
        sqlx_core::error::Error::PoolClosed => ControlError::Closed,
        sqlx_core::error::Error::PoolTimedOut => ControlError::Deadline,
        _ => ControlError::Storage,
    }
}
fn expired_observation(expiry: i64, now: i64, already_expired: bool) -> bool {
    already_expired || expiry <= now
}

fn timeout_error(commit_started: &AtomicBool) -> ControlError {
    if commit_started.load(Ordering::Relaxed) {
        ControlError::OutcomeUncertain
    } else {
        ControlError::Deadline
    }
}
impl PostgresControlStore {
    pub async fn open(
        config: PostgresConfig,
        digester: CredentialDigester,
        deadline: Instant,
    ) -> Result<Self, ControlError> {
        let deadline = bounded_deadline(deadline, config.pool.startup_timeout)?;
        let options = config.options()?;
        let connect_deadline = bounded_deadline(deadline, config.pool.connect_timeout)?;
        let pool = tokio::time::timeout_at(
            connect_deadline.into(),
            PgPoolOptions::new()
                .max_connections(config.pool.max_connections.get())
                .min_connections(config.pool.min_connections)
                .acquire_timeout(config.pool.acquire_timeout)
                .max_lifetime(config.pool.max_lifetime)
                .idle_timeout(config.pool.idle_timeout)
                .connect_with(options),
        )
        .await
        .map_err(|_| ControlError::Deadline)?
        .map_err(|_| ControlError::Connection)?;
        let commit_started = AtomicBool::new(false);
        let result = tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(pool.acquire().await.map_err(storage_error)?));
            let mut tx = schema::transaction(guard.connection()?).await?;
            schema::initialize(&mut tx).await?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok::<_, ControlError>(())
        })
        .await
        .map_err(|_| timeout_error(&commit_started))
        .and_then(|v| v);
        if let Err(error) = result {
            // Poll close to close admission even if the startup budget is exhausted.
            let _ = tokio::time::timeout(std::time::Duration::ZERO, pool.close()).await;
            drop(pool);
            return Err(error);
        }
        Ok(Self {
            pool,
            digester,
            budgets: config.pool,
            limits: config.flows,
        })
    }

    pub async fn save_flow(
        &self,
        state: &[u8],
        browser_binding: &[u8],
        flow: OidcFlow,
        deadline: Instant,
    ) -> Result<(), ControlError> {
        let deadline = bounded_deadline(deadline, self.budgets.operation_timeout)?;
        let json = flow.validate(self.limits)?;
        let state = self
            .digester
            .token(TokenKind::OidcFlowState, state)
            .map_err(|_| ControlError::InvalidFlow)?
            .to_sql_hex();
        let binding = self
            .digester
            .token(TokenKind::OidcBrowserBinding, browser_binding)
            .map_err(|_| ControlError::InvalidFlow)?
            .to_sql_hex();
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(self.pool.acquire().await.map_err(storage_error)?));
            let mut tx = schema::transaction(guard.connection()?).await?;
            let now = now_micros()?;
            if flow.expiry_micros() <= now || flow.expiry_micros() - now > FLOW_TTL_MICROS { return Err(ControlError::InvalidFlow); }
            let result = sqlx_core::query::query("INSERT INTO public.oidc_flows(state_hash,browser_binding_hash,nonce,pkce_verifier,purpose,continuation_json,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(state).bind(binding).bind(flow.nonce()).bind(flow.pkce_verifier())
                .bind(flow.continuation().purpose().as_str()).bind(json).bind(flow.expiry_micros()).bind(now)
                .execute(&mut *tx).await;
            let changed = match result {
                Ok(result) => result.rows_affected(),
                Err(error) => {
                return Err(if error.as_database_error().is_some_and(|e| e.is_unique_violation()) { ControlError::FlowExists } else { ControlError::Storage });
                }
            };
            if changed != 1 { return Err(ControlError::Storage); }
            if flow.expiry_micros() <= now_micros()? { return Err(ControlError::InvalidFlow); }
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok(())
        }).await.map_err(|_| timeout_error(&commit_started))?
    }

    pub async fn consume_flow(
        &self,
        state: &[u8],
        browser_binding: &[u8],
        deadline: Instant,
    ) -> Result<OidcFlow, ControlError> {
        let deadline = bounded_deadline(deadline, self.budgets.operation_timeout)?;
        let state = self
            .digester
            .token(TokenKind::OidcFlowState, state)
            .map_err(|_| ControlError::InvalidFlow)?
            .to_sql_hex();
        let binding = self
            .digester
            .token(TokenKind::OidcBrowserBinding, browser_binding)
            .map_err(|_| ControlError::InvalidFlow)?
            .to_sql_hex();
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(self.pool.acquire().await.map_err(storage_error)?));
            let mut tx = schema::transaction(guard.connection()?).await?;
            let row: Option<(String,String,String,Option<String>,i64,i64)> = sqlx_core::query_as::query_as("SELECT nonce,pkce_verifier,purpose,CASE WHEN octet_length(continuation_json)::bigint<=$3 THEN continuation_json ELSE NULL END,expires_at,created_at FROM public.oidc_flows WHERE state_hash=$1 AND browser_binding_hash=$2 FOR UPDATE")
                .bind(&state).bind(&binding).bind(i64::try_from(self.limits.continuation_bytes.get()).unwrap_or(i64::MAX)).fetch_optional(&mut *tx).await.map_err(|_| ControlError::Storage)?;
            let (nonce, verifier, purpose, continuation, expiry, created) = row.ok_or(ControlError::Unavailable)?;
            let flow = OidcFlow::stored(nonce, verifier, &purpose, &continuation.ok_or(ControlError::CorruptFlow)?, expiry, created, self.limits)?;
            let after_lock = now_micros()?;
            if created > after_lock { return Err(ControlError::CorruptFlow); }
            let expired_after_lock = expired_observation(expiry, after_lock, false);
            let changed = sqlx_core::query::query("DELETE FROM public.oidc_flows WHERE state_hash=$1 AND browser_binding_hash=$2")
                .bind(state).bind(binding).execute(&mut *tx).await.map_err(|_| ControlError::Storage)?.rows_affected();
            if changed != 1 { return Err(ControlError::Storage); }
            let before_commit = now_micros()?;
            let expired = expired_observation(expiry, before_commit, expired_after_lock);
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            if expired { Err(ControlError::Expired) } else { Ok(flow) }
        }).await.map_err(|_| timeout_error(&commit_started))?
    }

    pub fn admin_sessions(&self, limits: SessionLimits) -> Result<AdminSessions<'_>, ControlError> {
        limits.validate()?;
        Ok(AdminSessions {
            owner: self,
            limits,
        })
    }

    pub(crate) async fn create_admin_session(
        &self,
        raw_token: &str,
        session: &NewAdminSession,
        limits: &SessionLimits,
        caller: Instant,
    ) -> Result<(), ControlError> {
        let deadline = bounded_deadline(caller, self.budgets.operation_timeout)?;
        let json = session.validate(limits)?;
        let expiry = positive_expiry(session.expires_at())?;
        let hash = self
            .digester
            .token(TokenKind::AdminSession, raw_token.as_bytes())
            .map_err(|_| ControlError::InvalidSession)?
            .to_sql_hex();
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard =
                ConnectionGuard(Some(self.pool.acquire().await.map_err(storage_error)?));
            let mut tx = schema::transaction(guard.connection()?).await?;
            let created = now_micros()?;
            if expiry <= created || expiry - created > limits.lifetime_micros()? {
                return Err(ControlError::InvalidSession);
            }
            insert_admin_session(&mut tx, &hash, session, json, expiry, created).await?;
            if expiry <= now_micros()? {
                return Err(ControlError::SessionExpired);
            }
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok(())
        })
        .await
        .map_err(|_| timeout_error(&commit_started))?
    }

    pub(crate) async fn read_admin_session(
        &self,
        raw_token: &str,
        limits: &SessionLimits,
        caller: Instant,
    ) -> Result<AdminSession, ControlError> {
        let deadline = bounded_deadline(caller, self.budgets.operation_timeout)?;
        let hash = self
            .digester
            .token(TokenKind::AdminSession, raw_token.as_bytes())
            .map_err(|_| ControlError::InvalidSession)?
            .to_sql_hex();
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard =
                ConnectionGuard(Some(self.pool.acquire().await.map_err(storage_error)?));
            let mut tx = schema::transaction(guard.connection()?).await?;
            let session = load_admin_session(&mut tx, &hash, limits)
                .await?
                .ok_or(ControlError::SessionUnavailable)?;
            let after_lock = now_micros()?;
            let expiry = session.expires_at().as_i64();
            let observed_expired = expired_observation(expiry, after_lock, false);
            let expired = expired_observation(expiry, now_micros()?, observed_expired);
            if expired {
                let changed = sqlx_core::query::query(
                    "DELETE FROM public.admin_sessions WHERE token_hash=$1",
                )
                .bind(&hash)
                .execute(&mut *tx)
                .await
                .map_err(|_| ControlError::Storage)?
                .rows_affected();
                if changed != 1 {
                    return Err(ControlError::Storage);
                }
            }
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            if expired {
                Err(ControlError::SessionExpired)
            } else {
                Ok(session)
            }
        })
        .await
        .map_err(|_| timeout_error(&commit_started))?
    }

    pub(crate) async fn revoke_admin_session(
        &self,
        raw_token: &str,
        caller: Instant,
    ) -> Result<SessionRevocation, ControlError> {
        let deadline = bounded_deadline(caller, self.budgets.operation_timeout)?;
        let hash = self
            .digester
            .token(TokenKind::AdminSession, raw_token.as_bytes())
            .map_err(|_| ControlError::InvalidSession)?
            .to_sql_hex();
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard =
                ConnectionGuard(Some(self.pool.acquire().await.map_err(storage_error)?));
            let mut tx = schema::transaction(guard.connection()?).await?;
            let changed =
                sqlx_core::query::query("DELETE FROM public.admin_sessions WHERE token_hash=$1")
                    .bind(hash)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| ControlError::Storage)?
                    .rows_affected();
            let result = match changed {
                0 => SessionRevocation::Absent,
                1 => SessionRevocation::Revoked,
                _ => return Err(ControlError::Storage),
            };
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok(result)
        })
        .await
        .map_err(|_| timeout_error(&commit_started))?
    }

    /// Close admission immediately. Keys remain owned until the store itself is dropped.
    pub async fn shutdown(&self, deadline: Instant) -> Result<(), ControlError> {
        // Constructing close stops admission. Keep its owner until the physical
        // pool drain completes, even when the original deadline has expired.
        let close = self.pool.close();
        tokio::pin!(close);
        let deadline = match bounded_deadline(deadline, self.budgets.shutdown_timeout) {
            Ok(deadline) => deadline,
            Err(error) => {
                close.await;
                return Err(error);
            }
        };
        match tokio::time::timeout_at(deadline.into(), &mut close).await {
            Ok(()) => Ok(()),
            Err(_) => {
                close.await;
                Err(ControlError::Deadline)
            }
        }
    }
}

async fn insert_admin_session(
    connection: &mut PgConnection,
    hash: &str,
    session: &NewAdminSession,
    json: crate::session::SessionJson,
    expiry: i64,
    created: i64,
) -> Result<(), ControlError> {
    let profile = session.profile();
    let principal = session.principal();
    let parent = sqlx_core::query::query("INSERT INTO public.admin_sessions(token_hash,subject,name,email,csrf_token,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(hash).bind(&profile.subject).bind(&profile.name).bind(&profile.email).bind(session.csrf_token()).bind(expiry).bind(created).execute(&mut *connection).await;
    let parent = parent.map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|e| e.is_unique_violation())
        {
            ControlError::SessionExists
        } else {
            ControlError::Storage
        }
    })?;
    if parent.rows_affected() != 1 {
        return Err(ControlError::Storage);
    }
    let changed = sqlx_core::query::query("INSERT INTO public.admin_session_principals(token_hash,issuer,username,organization,teams_json,local_user_revision) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(hash).bind(&principal.issuer).bind(&principal.username).bind(&principal.organization).bind(json.teams).bind(principal.local_user_revision).execute(&mut *connection).await.map_err(|_|ControlError::Storage)?.rows_affected();
    if changed != 1 {
        return Err(ControlError::Storage);
    }
    if let Some(claims) = session.claimed_roles() {
        let changed = sqlx_core::query::query("INSERT INTO public.admin_session_claim_roles(token_hash,claim_selector,roles_json) VALUES($1,$2,$3)")
            .bind(hash).bind(&claims.selector).bind(json.roles.ok_or(ControlError::InvalidSession)?).execute(&mut *connection).await.map_err(|_|ControlError::Storage)?.rows_affected();
        if changed != 1 {
            return Err(ControlError::Storage);
        }
    }
    Ok(())
}
async fn load_admin_session(
    connection: &mut PgConnection,
    hash: &str,
    limits: &SessionLimits,
) -> Result<Option<AdminSession>, ControlError> {
    // Cap every potentially large text in SQL, before SDK decoding or JSON allocation.
    // Child-presence booleans distinguish missing rows from cap-rejected SQL NULLs.
    let row = sqlx_core::query::query("SELECT CASE WHEN pg_catalog.octet_length(s.subject)::bigint<=$2 THEN s.subject END AS subject,CASE WHEN pg_catalog.octet_length(s.name)::bigint<=$2 THEN s.name END AS name,CASE WHEN pg_catalog.octet_length(s.email)::bigint<=$2 THEN s.email END AS email,CASE WHEN pg_catalog.octet_length(s.csrf_token)::bigint<=$3 THEN s.csrf_token END AS csrf, s.created_at,s.expires_at,p.token_hash IS NOT NULL AS principal_present,CASE WHEN pg_catalog.octet_length(p.issuer)::bigint<=$2 THEN p.issuer END AS issuer,CASE WHEN pg_catalog.octet_length(p.username)::bigint<=$2 THEN p.username END AS username,CASE WHEN pg_catalog.octet_length(p.organization)::bigint<=$2 THEN p.organization END AS organization,CASE WHEN pg_catalog.octet_length(p.teams_json)::bigint<=$4 THEN p.teams_json END AS teams,p.local_user_revision,c.token_hash IS NOT NULL AS claims_present,CASE WHEN pg_catalog.octet_length(c.claim_selector)::bigint<=$2 THEN c.claim_selector END AS selector,CASE WHEN pg_catalog.octet_length(c.roles_json)::bigint<=$5 THEN c.roles_json END AS roles FROM public.admin_sessions s LEFT JOIN public.admin_session_principals p ON p.token_hash=s.token_hash LEFT JOIN public.admin_session_claim_roles c ON c.token_hash=s.token_hash WHERE s.token_hash=$1 FOR UPDATE OF s")
        .bind(hash).bind(limits.text_bytes.get() as i64).bind(limits.csrf_bytes.get() as i64).bind(limits.teams_json_bytes.get() as i64).bind(limits.roles_json_bytes.get() as i64).fetch_optional(&mut *connection).await.map_err(|_|ControlError::Storage)?;
    let Some(row) = row else {
        return Ok(None);
    };

    let get_text = |name| -> Result<String, ControlError> {
        row.try_get::<Option<String>, _>(name)
            .map_err(|_| ControlError::CorruptSession)?
            .ok_or(ControlError::CorruptSession)
    };
    if !row
        .try_get::<bool, _>("principal_present")
        .map_err(|_| ControlError::CorruptSession)?
    {
        return Err(ControlError::CorruptSession);
    }
    let profile = SessionProfile {
        subject: get_text("subject")?,
        name: get_text("name")?,
        email: get_text("email")?,
    };
    let principal = SessionPrincipal {
        issuer: get_text("issuer")?,
        username: get_text("username")?,
        organization: get_text("organization")?,
        teams: Vec::new(),
        local_user_revision: row
            .try_get::<Option<i64>, _>("local_user_revision")
            .map_err(|_| ControlError::CorruptSession)?
            .ok_or(ControlError::CorruptSession)?,
    };
    let claims = if row
        .try_get::<bool, _>("claims_present")
        .map_err(|_| ControlError::CorruptSession)?
    {
        Some((get_text("selector")?, get_text("roles")?))
    } else {
        None
    };
    let created: i64 = row
        .try_get("created_at")
        .map_err(|_| ControlError::CorruptSession)?;
    let expiry: i64 = row
        .try_get("expires_at")
        .map_err(|_| ControlError::CorruptSession)?;
    let session = AdminSession::stored(
        profile,
        principal,
        Zeroizing::new(get_text("csrf")?),
        claims,
        &get_text("teams")?,
        (created, expiry),
        limits,
    )?;
    if created > now_micros()? {
        return Err(ControlError::CorruptSession);
    }
    Ok(Some(session))
}

#[cfg(test)]
mod tests {
    use super::expired_observation;
    #[test]
    fn expiry_boundary_is_inclusive_and_never_resurrected_by_clock_reversal() {
        assert!(!expired_observation(101, 100, false));
        assert!(expired_observation(100, 100, false));
        assert!(expired_observation(99, 100, false));
        assert!(expired_observation(
            100,
            50,
            expired_observation(100, 100, false)
        ));
        assert!(expired_observation(
            100,
            100,
            expired_observation(100, 50, false)
        ));
    }
}

mod device;
pub use device::PostgresDeviceAuthorizations;
