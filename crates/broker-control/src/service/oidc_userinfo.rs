use super::oidc_access_snapshot::{AccessGrantError, COLUMNS, decode};
use super::oidc_authorization::completion::current_principal;
use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    BrokerAccessError, BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy,
    OidcTokenExchangeError, OidcUserInfo, OidcUserInfoError as Error, UpstreamBearerVerifier,
    flow::now_micros,
};
use broker_security::{TokenKind, validate_local_auth_challenge};
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

pub struct PostgresOidcUserInfo<'a> {
    store: &'a PostgresControlStore,
    authorization: &'a OidcAuthorizationPolicy,
    verifier: &'a BrokerAccessVerifier,
    upstream: Option<&'a UpstreamBearerVerifier>,
}
impl fmt::Debug for PostgresOidcUserInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresOidcUserInfo([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn oidc_userinfo<'a>(
        &'a self,
        authorization: &'a OidcAuthorizationPolicy,
        verifier: &'a BrokerAccessVerifier,
    ) -> Result<PostgresOidcUserInfo<'a>, Error> {
        if authorization.api_audience != verifier.api_audience() {
            return Err(Error::InvalidConfiguration);
        }
        Ok(PostgresOidcUserInfo {
            store: self,
            authorization,
            verifier,
            upstream: None,
        })
    }
}
impl<'a> PostgresOidcUserInfo<'a> {
    pub fn parameter_bytes(&self) -> usize {
        self.authorization.limits.parameter_bytes()
    }
    pub fn with_upstream(mut self, verifier: &'a UpstreamBearerVerifier) -> Self {
        self.upstream = Some(verifier);
        self
    }
    pub async fn profile(&self, raw: &str, original: Instant) -> Result<OidcUserInfo, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let proof = self
            .verifier
            .verify_for_oidc_operation(raw, end)
            .map_err(bearer_error)?;
        validate_local_auth_challenge(proof.jti()).map_err(|_| Error::InvalidToken)?;
        let hash = self
            .store
            .digester
            .token(TokenKind::OidcStoredAccess, proof.jti().as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        let cap = self.authorization.limits.json_bytes;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = sqlx_core::connection::Connection::begin_with(guard.connection()?, "BEGIN ISOLATION LEVEL READ COMMITTED")
                .await.map_err(storage_error)?;
            let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!("SELECT {COLUMNS} FROM public.local_tokens WHERE token_hash=$1 AND token_kind='oidc_access'"))).bind(&hash).bind(cap)
                .fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(Error::InvalidToken)?;
            let (initial, revoked) = decode(&row, cap)?;
            initial.matches(&proof, revoked, self.authorization)?;
            let observed = initial.principal(&self.store.digester)?;
            let principal = if let Some(local) = observed.as_local() {
                // The same user -> token order as refresh/revocation and managed identity changes.
                current_principal(&mut tx, &local.subject, &local.username, local.local_user_revision, cap, end)
                    .await.map_err(|error|principal_error(error.into()))?
            } else {
                if !observed.current_trust(self.upstream) { return Err(Error::InvalidToken); }
                observed
            };
            let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!("SELECT {COLUMNS} FROM public.local_tokens WHERE token_hash=$1 AND token_kind='oidc_access' FOR UPDATE")))
                .bind(&hash).bind(cap).fetch_optional(&mut *tx).await.map_err(storage_error)?
                .ok_or(Error::InvalidToken)?;
            let (stored, revoked) = decode(&row, cap)?;
            if stored != initial { return Err(Error::InvalidToken); }
            stored.matches(&proof, revoked, self.authorization)?;
            if !principal.current_trust(self.upstream) { return Err(Error::InvalidToken); }
            let optional = |value: &str| (!value.is_empty()).then(|| value.to_owned());
            let result = OidcUserInfo {
                sub: stored.oidc_subject, preferred_username: optional(principal.username()),
                name: optional(principal.name()), email: optional(principal.email()),
                organization: optional(principal.organization()), groups:principal.teams().to_vec(),
                roles:principal.roles().to_vec(),
            };
            proof.check().map_err(bearer_error)?;
            let changed = sqlx_core::query::query("UPDATE public.local_tokens SET last_used_at=$1 WHERE token_hash=$2 AND token_kind='oidc_access'")
                .bind(now_micros()?).bind(&hash).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if changed != 1 { return Err(ControlError::Storage.into()); }
            proof.check().map_err(bearer_error)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            proof.check().map_err(bearer_error)?;
            Ok(result)
        }).await.map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
}
fn bearer_error(error: BrokerAccessError) -> Error {
    match error {
        BrokerAccessError::Deadline => ControlError::Deadline.into(),
        _ => Error::InvalidToken,
    }
}
fn principal_error(error: OidcTokenExchangeError) -> Error {
    match error {
        OidcTokenExchangeError::InvalidGrant => Error::InvalidToken,
        OidcTokenExchangeError::Control(error) => error.into(),
        OidcTokenExchangeError::ReadLimitExceeded => Error::ReadLimitExceeded,
        _ => Error::MalformedStored,
    }
}
impl From<AccessGrantError> for Error {
    fn from(error: AccessGrantError) -> Self {
        match error {
            AccessGrantError::InvalidToken => Self::InvalidToken,
            AccessGrantError::MalformedStored => Self::MalformedStored,
            AccessGrantError::ReadLimitExceeded => Self::ReadLimitExceeded,
            AccessGrantError::Credential => Self::Credential,
            AccessGrantError::Control(error) => Self::Control(error),
        }
    }
}
