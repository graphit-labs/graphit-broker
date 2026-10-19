use super::oidc_principal::OidcPrincipal;
use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy, OidcEndSessionInput,
    OidcTokenExchangeError as Error, flow::now_micros, oidc_authorization::guard_original,
};
use sqlx_core::row::Row;
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

const PRINCIPAL: &str = r#"SELECT local_user_revision, created_at,
 OCTET_LENGTH(subject)::bigint AS subject_bytes,
 CASE WHEN OCTET_LENGTH(subject)<=$4 THEN subject END AS subject,
 OCTET_LENGTH(principal_json)::bigint AS principal_bytes,
 CASE WHEN OCTET_LENGTH(principal_json)<=$4 THEN principal_json END AS principal_json
 FROM public.local_tokens WHERE oidc_subject=$1 AND client_id=$2 AND audience=$3
 AND token_kind IN ('oidc_access','refresh') ORDER BY created_at DESC LIMIT 1"#;

/// Ends SQL grants of the signed pair; emitted JWTs retain local validity until expiry.
pub struct PostgresOidcEndSession<'a> {
    store: &'a PostgresControlStore,
    authorization: &'a OidcAuthorizationPolicy,
    verifier: &'a BrokerAccessVerifier,
}
impl fmt::Debug for PostgresOidcEndSession<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresOidcEndSession([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn oidc_end_session<'a>(
        &'a self,
        authorization: &'a OidcAuthorizationPolicy,
        verifier: &'a BrokerAccessVerifier,
    ) -> Result<PostgresOidcEndSession<'a>, Error> {
        if verifier.api_audience() != authorization.api_audience {
            return Err(Error::InvalidConfiguration);
        }
        Ok(PostgresOidcEndSession {
            store: self,
            authorization,
            verifier,
        })
    }
}
impl PostgresOidcEndSession<'_> {
    pub fn parameter_bytes(&self) -> usize {
        self.authorization.limits.parameter_bytes()
    }
    pub async fn end_session(
        &self,
        input: OidcEndSessionInput<'_>,
        original: Instant,
    ) -> Result<(), Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let size = input
            .id_token_hint
            .unwrap_or("")
            .len()
            .checked_add(input.client_id.unwrap_or("").len())
            .ok_or(Error::InvalidRequest)?;
        if size > self.parameter_bytes() {
            return Err(Error::InvalidRequest);
        }
        let raw = input
            .id_token_hint
            .filter(|v| !v.is_empty())
            .ok_or(Error::InvalidRequest)?;
        let proof = self.verifier.verify_end_session_hint(raw, end)?;
        if input.client_id.is_some_and(|v| v != proof.client_id()) {
            return Err(Error::InvalidRequest);
        }
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = sqlx_core::connection::Connection::begin_with(guard.connection()?,
                "BEGIN ISOLATION LEVEL READ COMMITTED").await.map_err(storage_error)?;
            super::oidc_tokens::lock_pair_exclusive(&mut tx, proof.subject(), proof.client_id(), end).await?;
            proof.check()?;
            let cap = self.authorization.limits.json_bytes;
            let row = sqlx_core::query::query(PRINCIPAL).bind(proof.subject()).bind(proof.client_id())
                .bind(&self.authorization.api_audience).bind(cap).fetch_optional(&mut *tx)
                .await.map_err(storage_error)?;
            let mut newest_created = 0;
            if let Some(row) = row {
                let bounded = |length, column| -> Result<String, Error> {
                    let bytes: i64 = row.try_get(length).map_err(|_| Error::MalformedStored)?;
                    if !(0..=cap).contains(&bytes) { return Err(Error::ReadLimitExceeded); }
                    row.try_get(column).map_err(|_| Error::MalformedStored)
                };
                let subject = bounded("subject_bytes", "subject")?;
                let json = Zeroizing::new(bounded("principal_bytes", "principal_json")?);
                let principal = OidcPrincipal::parse(&json)?;
                let revision: i64 = row.try_get("local_user_revision").map_err(|_| Error::MalformedStored)?;
                let created_at: i64 = row.try_get("created_at").map_err(|_| Error::MalformedStored)?;
                if created_at <= 0 || principal.subject() != subject || principal.revision() != revision {
                    return Err(Error::MalformedStored);
                }
                newest_created = created_at;
                if created_at > now_micros()? { return Err(ControlError::Clock.into()); }
                let oidc_subject = self.store.digester.oidc_subject(principal.issuer().as_bytes(), subject.as_bytes())
                    .map_err(|_| Error::Credential)?;
                if oidc_subject.as_str() != proof.subject() { return Err(Error::MalformedStored); }
                if principal.issuer() == "local" {
                    // Managed deletion can already have disposed the pair; no current-user gate.
                    sqlx_core::query::query("SELECT subject FROM public.local_users WHERE subject=$1 FOR UPDATE")
                        .bind(&subject).fetch_optional(&mut *tx).await.map_err(storage_error)?;
                }
            }
            proof.check()?;
            let now = now_micros()?;
            if now < newest_created { return Err(ControlError::Clock.into()); }
            sqlx_core::query::query("UPDATE public.local_tokens SET revoked_at=$1 WHERE oidc_subject=$2 AND client_id=$3 AND audience=$4 AND token_kind IN ('oidc_access','refresh') AND revoked_at IS NULL")
                .bind(now).bind(proof.subject()).bind(proof.client_id()).bind(&self.authorization.api_audience)
                .execute(&mut *tx).await.map_err(storage_error)?;
            proof.check()?;
            guard_original(end)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            guard_original(end)?;
            proof.check()?;
            Ok(())
        }).await.map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
}
