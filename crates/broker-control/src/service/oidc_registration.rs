use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    ControlError, OidcAuthorizationPolicy, OidcRegistrationError as Error, RegisteredOidcClient,
    flow::now_micros, oidc_authorization::guard_original, oidc_registration::Registration,
};
use broker_security::new_local_auth_challenge;
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

pub struct PostgresOidcRegistrationService<'a> {
    store: &'a PostgresControlStore,
    policy: &'a OidcAuthorizationPolicy,
}
impl fmt::Debug for PostgresOidcRegistrationService<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresOidcRegistrationService([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn oidc_registration_service<'a>(
        &'a self,
        policy: &'a OidcAuthorizationPolicy,
    ) -> PostgresOidcRegistrationService<'a> {
        PostgresOidcRegistrationService {
            store: self,
            policy,
        }
    }
}
impl PostgresOidcRegistrationService<'_> {
    pub fn enabled(&self) -> bool {
        self.policy.dynamic_registration
    }
    pub async fn register(
        &self,
        raw: &[u8],
        original: Instant,
    ) -> Result<RegisteredOidcClient, Error> {
        if !self.enabled() {
            return Err(Error::Disabled);
        }
        let deadline = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        guard_original(deadline).map_err(|_| ControlError::Deadline)?;
        let registration = Registration::parse(raw, self.policy)?;
        let (redirects, scopes) = registration.columns(self.policy)?;
        let id = new_local_auth_challenge().map_err(|_| Error::Random)?;
        if id.as_str() == self.policy.cli_client_id {
            return Err(Error::Random);
        }
        let created_at = now_micros()?;
        if created_at <= 0 {
            return Err(ControlError::Clock.into());
        }
        let response = registration.response(id.to_string(), created_at)?;
        let committing = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = sqlx_core::connection::Connection::begin_with(guard.connection()?, "BEGIN ISOLATION LEVEL READ COMMITTED").await.map_err(storage_error)?;
            guard_original(deadline).map_err(|_| ControlError::Deadline)?;
            let rows = sqlx_core::query::query("INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES($1,$2,$3,$4,$5,$6)")
                .bind(id.as_str()).bind(&registration.name).bind(&redirects).bind(&scopes)
                .bind(if registration.native { "native" } else { "web" }).bind(created_at)
                .execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if rows != 1 { return Err(ControlError::Storage.into()); }
            guard_original(deadline).map_err(|_| ControlError::Deadline)?;
            committing.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            guard_original(deadline).map_err(|_| ControlError::OutcomeUncertain)?;
            Ok(response)
        }).await.map_err(|_| Error::Control(timeout_error(&committing)))?
    }
}
