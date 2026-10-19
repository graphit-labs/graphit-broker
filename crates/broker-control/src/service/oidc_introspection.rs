use super::oidc_access_snapshot::{
    AccessGrant, AccessGrantError, COLUMNS, bearer_error, decode, token_hash,
};
use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy, OidcIntrospection,
    OidcIntrospectionError as Error, VerifiedBrokerAccess, flow::now_micros,
};
use sqlx_core::row::Row;
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

pub struct PostgresOidcIntrospection<'a> {
    store: &'a PostgresControlStore,
    authorization: &'a OidcAuthorizationPolicy,
    verifier: &'a BrokerAccessVerifier,
}
impl fmt::Debug for PostgresOidcIntrospection<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresOidcIntrospection([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn oidc_introspection<'a>(
        &'a self,
        authorization: &'a OidcAuthorizationPolicy,
        verifier: &'a BrokerAccessVerifier,
    ) -> Result<PostgresOidcIntrospection<'a>, Error> {
        if authorization.api_audience != verifier.api_audience() {
            return Err(Error::InvalidConfiguration);
        }
        Ok(PostgresOidcIntrospection {
            store: self,
            authorization,
            verifier,
        })
    }
}
impl PostgresOidcIntrospection<'_> {
    pub fn parameter_bytes(&self) -> usize {
        self.authorization.limits.parameter_bytes()
    }
    pub async fn introspect(
        &self,
        authority: &str,
        token: Option<&str>,
        original: Instant,
    ) -> Result<OidcIntrospection, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let authority = self
            .verifier
            .verify_for_oidc_operation(authority, end)
            .map_err(bearer_error)?;
        let authority_hash = token_hash(&self.store.digester, &authority)?;
        let target = match token.filter(|v| !v.is_empty()) {
            Some(raw) => match self.verifier.verify_for_oidc_operation(raw, end) {
                Ok(proof)
                    if proof.client_id() == authority.client_id()
                        && proof.subject() == authority.subject() =>
                {
                    match token_hash(&self.store.digester, &proof) {
                        Ok(hash) => Some((proof, hash)),
                        Err(AccessGrantError::InvalidToken) => None,
                        Err(error) => return Err(error.into()),
                    }
                }
                Ok(_) => None,
                Err(error) => match bearer_error(error) {
                    AccessGrantError::InvalidToken => None,
                    error => return Err(error.into()),
                },
            },
            None => None,
        };
        let target_hash = target.as_ref().map_or(&authority_hash, |(_, hash)| hash);
        let cap = self.authorization.limits.json_bytes;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = sqlx_core::connection::Connection::begin_with(guard.connection()?,
                "BEGIN ISOLATION LEVEL READ COMMITTED").await.map_err(storage_error)?;
            // One statement snapshot authorizes the pair; it takes no row locks.
            let rows = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
                "SELECT {COLUMNS} FROM public.local_tokens WHERE token_kind='oidc_access' AND token_hash IN ($1,$3)"
            ))).bind(&authority_hash).bind(cap).bind(target_hash)
                .fetch_all(&mut *tx).await.map_err(storage_error)?;
            let authority_row = rows.iter().find(|row| row.try_get::<&str, _>("token_hash")
                .is_ok_and(|hash| hash == authority_hash)).ok_or(Error::InvalidAuthority)?;
            let (stored_authority, revoked_authority) = decode(authority_row, cap)?;
            self.admit(&stored_authority, revoked_authority, &authority)?;
            authority.check().map_err(bearer_error)?;
            let candidate = match target.as_ref() {
                Some((_, hash)) => rows.iter().find(|row| row.try_get::<&str, _>("token_hash")
                    .is_ok_and(|value| value == hash)).map(|row| decode(row, cap)).transpose()?,
                None => None,
            };
            let mut result = OidcIntrospection::inactive();
            let mut updated = false;
            if let (Some((proof, hash)), Some((initial, revoked))) = (target.as_ref(), candidate)
                && self.target_admitted(&initial, revoked, proof)? {
                    // At most one row lock: never authority/user/family after this.
                    let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
                        "SELECT {COLUMNS} FROM public.local_tokens WHERE token_kind='oidc_access' AND token_hash=$1 FOR UPDATE"
                    ))).bind(hash).bind(cap).fetch_optional(&mut *tx).await.map_err(storage_error)?;
                    authority.check().map_err(bearer_error)?;
                    let current = row.as_ref().map(|row| decode(row, cap)).transpose()?;
                    if let Some((stored, revoked)) = current
                        && stored == initial && self.target_admitted(&stored, revoked, proof)? {
                            let changed = sqlx_core::query::query(
                                "UPDATE public.local_tokens SET last_used_at=$1 WHERE token_hash=$2 AND token_kind='oidc_access' AND revoked_at IS NULL"
                            ).bind(now_micros()?).bind(hash).execute(&mut *tx)
                                .await.map_err(storage_error)?.rows_affected();
                            if changed != 1 { return Err(ControlError::Storage.into()); }
                            authority.check().map_err(bearer_error)?;
                            if !self.target_admitted(&stored, revoked, proof)? {
                                tx.rollback().await.map_err(storage_error)?;
                                guard.confirmed();
                                authority.check().map_err(bearer_error)?;
                                return Ok(OidcIntrospection::inactive());
                            }
                            updated = true;
                            result = OidcIntrospection::active(stored.client, &stored.scopes, stored.expiry);
                    }
            }
            authority.check().map_err(bearer_error)?;
            if !updated {
                tx.rollback().await.map_err(storage_error)?;
                guard.confirmed();
                authority.check().map_err(bearer_error)?;
                return Ok(OidcIntrospection::inactive());
            }
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            authority.check().map_err(bearer_error)?;
            if let Some((proof, _)) = target.as_ref() {
                match proof.check().map_err(bearer_error) {
                    Ok(()) => {},
                    Err(AccessGrantError::InvalidToken) => return Ok(OidcIntrospection::inactive()),
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(result)
        }).await.map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
    fn admit(
        &self,
        stored: &AccessGrant,
        revoked: Option<i64>,
        proof: &VerifiedBrokerAccess<'_>,
    ) -> Result<(), AccessGrantError> {
        stored.matches(proof, revoked, self.authorization)?;
        stored.principal(&self.store.digester)?;
        Ok(())
    }
    fn target_admitted(
        &self,
        stored: &AccessGrant,
        revoked: Option<i64>,
        proof: &VerifiedBrokerAccess<'_>,
    ) -> Result<bool, Error> {
        match self.admit(stored, revoked, proof) {
            Ok(()) => Ok(true),
            Err(AccessGrantError::InvalidToken) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}
impl From<AccessGrantError> for Error {
    fn from(error: AccessGrantError) -> Self {
        match error {
            AccessGrantError::InvalidToken => Self::InvalidAuthority,
            AccessGrantError::MalformedStored => Self::MalformedStored,
            AccessGrantError::ReadLimitExceeded => Self::ReadLimitExceeded,
            AccessGrantError::Credential => Self::Credential,
            AccessGrantError::Control(error) => Self::Control(error),
        }
    }
}
