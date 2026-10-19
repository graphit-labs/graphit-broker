//! Public dynamic client registration through the private SQLite owner.
use super::SqliteControlStore;
use crate::{
    ControlError, OidcAuthorizationPolicy, OidcRegistrationError as Error, RegisteredOidcClient,
    flow::now_micros, oidc_authorization::guard_original, oidc_registration::Registration,
};
use broker_security::new_local_auth_challenge;
use rusqlite::params;
use std::{fmt, time::Instant};

/// Borrowed registration view. A registered client is catalog metadata, not authority.
pub struct SqliteOidcRegistrationService<'a> {
    store: &'a SqliteControlStore,
    policy: &'a OidcAuthorizationPolicy,
}
impl fmt::Debug for SqliteOidcRegistrationService<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteOidcRegistrationService([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn oidc_registration_service<'a>(
        &'a self,
        policy: &'a OidcAuthorizationPolicy,
    ) -> SqliteOidcRegistrationService<'a> {
        SqliteOidcRegistrationService {
            store: self,
            policy,
        }
    }
}
impl SqliteOidcRegistrationService<'_> {
    pub fn enabled(&self) -> bool {
        self.policy.dynamic_registration
    }

    /// Admit SDK metadata and return public registration data after a known COMMIT.
    /// An uncertain outcome withholds the response and must not be replayed automatically.
    pub async fn register(
        &self,
        raw: &[u8],
        original: Instant,
    ) -> Result<RegisteredOidcClient, Error> {
        if !self.enabled() {
            return Err(Error::Disabled);
        }
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        guard_original(end).map_err(|_| ControlError::Deadline)?;
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
        self.store.executor.execute(end, move |owner, work| {
            let tx = owner.begin(work)?;
            let rows = tx.execute(
                "INSERT INTO oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES(?1,?2,?3,?4,?5,?6)",
                params![id.as_str(), registration.name, redirects, scopes, if registration.native { "native" } else { "web" }, created_at],
            ).map_err(|error| work.sql(error))?;
            if rows != 1 {
                return Err(super::SqliteControlError::Storage);
            }
            work.commit(tx)
        }).await.map_err(ControlError::from)?;
        guard_original(end).map_err(|_| ControlError::OutcomeUncertain)?;
        Ok(response)
    }
}
