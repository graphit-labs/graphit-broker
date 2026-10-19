use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    BrokerAccessError, BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy,
    OidcRevocationInput, OidcTokenExchangeError as Error, VerifiedBrokerAccess, flow::now_micros,
    oidc_access_grant::parse_principal, oidc_authorization::guard_original,
};
use broker_security::{TokenKind, validate_local_auth_challenge};
use sqlx_core::row::Row;
use sqlx_postgres::PgRow;
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::{Instant, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const REFRESH: &str = r#"SELECT token_id,oidc_subject,client_id,audience,family_id,
 local_user_revision,expires_at,created_at,revoked_at,
 OCTET_LENGTH(subject)::bigint AS subject_bytes,
 CASE WHEN OCTET_LENGTH(subject)<=$2 THEN subject END AS subject,
 OCTET_LENGTH(principal_json)::bigint AS principal_bytes,
 CASE WHEN OCTET_LENGTH(principal_json)<=$2 THEN principal_json END AS principal_json
 FROM public.local_tokens WHERE token_hash=$1 AND token_kind='refresh'"#;

/// Explicit credential disposal, not a JWT authentication gate or identity grant.
pub struct PostgresOidcRevocation<'a> {
    store: &'a PostgresControlStore,
    authorization: &'a OidcAuthorizationPolicy,
    verifier: &'a BrokerAccessVerifier,
}
impl fmt::Debug for PostgresOidcRevocation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresOidcRevocation([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn oidc_revocation<'a>(
        &'a self,
        authorization: &'a OidcAuthorizationPolicy,
        verifier: &'a BrokerAccessVerifier,
    ) -> Result<PostgresOidcRevocation<'a>, Error> {
        if verifier.api_audience() != authorization.api_audience {
            return Err(Error::InvalidConfiguration);
        }
        Ok(PostgresOidcRevocation {
            store: self,
            authorization,
            verifier,
        })
    }
}
impl PostgresOidcRevocation<'_> {
    pub async fn revoke(
        &self,
        input: OidcRevocationInput<'_>,
        original: Instant,
    ) -> Result<(), Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        if input.authorization.is_some() {
            return Err(Error::InvalidClient);
        }
        let mut bytes = 0usize;
        for value in [input.token, input.client_id, input.token_type_hint]
            .into_iter()
            .flatten()
        {
            bytes = bytes
                .checked_add(value.len())
                .ok_or(Error::InvalidRequest)?;
        }
        if bytes > self.authorization.limits.parameter_bytes() {
            return Err(Error::InvalidRequest);
        }
        let raw = input
            .token
            .filter(|v| !v.is_empty())
            .ok_or(Error::InvalidRequest)?;
        let client = input
            .client_id
            .filter(|v| !v.is_empty())
            .ok_or(Error::InvalidRequest)?;
        if crate::oidc_authorization::OidcClientId::parse(client).is_none() {
            return Err(Error::InvalidRequest);
        }
        // A hint never changes credential recognition or its authority.
        let refresh_hash = raw
            .strip_prefix("gb_rt_")
            .filter(|suffix| validate_local_auth_challenge(suffix).is_ok())
            .map(|_| {
                self.store
                    .digester
                    .token(TokenKind::LocalRefresh, raw.as_bytes())
                    .map(|d| d.to_sql_hex())
                    .map_err(|_| Error::Credential)
            })
            .transpose()?;
        let access = if refresh_hash.is_none() {
            match self.verifier.verify_for_revocation(raw, end) {
                Ok(proof) => Some(proof),
                Err(BrokerAccessError::Deadline) => return Err(ControlError::Deadline.into()),
                Err(_) => None,
            }
        } else {
            None
        };
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = sqlx_core::connection::Connection::begin_with(guard.connection()?, "BEGIN ISOLATION LEVEL READ COMMITTED")
                .await.map_err(storage_error)?;
            let cap = self.authorization.limits.json_bytes;
            let initial = if let Some(hash) = &refresh_hash {
                sqlx_core::query::query(REFRESH).bind(hash).bind(cap)
                    .fetch_optional(&mut *tx).await.map_err(storage_error)?
                    .map(|row| refresh(&row, cap)).transpose()?
            } else { None };
            if let Some((stored, _)) = initial.as_ref().filter(|(s, _)| s.client_id == client) {
                let principal = parse_principal(&stored.principal_json).map_err(|_| Error::MalformedStored)?;
                if principal.subject() != stored.subject || principal.local_user_revision() != stored.revision {
                    return Err(Error::MalformedStored);
                }
                let subject = self.store.digester.oidc_subject(principal.issuer().as_bytes(), principal.subject().as_bytes())
                    .map_err(|_| Error::Credential)?;
                if stored.oidc_subject != subject.as_str() { return Err(Error::MalformedStored); }
                super::oidc_tokens::lock_pair_shared(&mut tx, &stored.oidc_subject, &stored.client_id, end).await?;
                if principal.issuer() == "local" {
                    // Optional after managed deletion, but always before a token row lock.
                    sqlx_core::query::query("SELECT subject FROM public.local_users WHERE subject=$1 FOR UPDATE")
                        .bind(&stored.subject).fetch_optional(&mut *tx).await.map_err(storage_error)?;
                } else {
                    sqlx_core::query::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4750301))")
                        .bind(&stored.family).execute(&mut *tx).await.map_err(storage_error)?;
                }
            }
            self.store.oidc_authorization_service(&self.store.digester, self.authorization)
                .client(&mut tx, client, end).await?;
            guard_original(end)?;
            if let Some((initial, _)) = initial.filter(|(s, _)| s.client_id == client) {
                let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!("{REFRESH} FOR UPDATE")))
                    .bind(refresh_hash.as_ref().ok_or(Error::MalformedStored)?).bind(cap)
                    .fetch_optional(&mut *tx).await.map_err(storage_error)?;
                if let Some(row) = row {
                    let (stored, revoked) = refresh(&row, cap)?;
                    let now = now_micros()?;
                    if now < stored.created_at { return Err(ControlError::Clock.into()); }
                    if stored == initial && stored.audience == self.authorization.api_audience
                        && stored.expires_at > now && revoked.is_none() {
                        let changed = sqlx_core::query::query("UPDATE public.local_tokens SET revoked_at=$1 WHERE family_id=$2 AND client_id=$3 AND audience=$4 AND revoked_at IS NULL")
                            .bind(now).bind(&stored.family).bind(client).bind(&self.authorization.api_audience)
                            .execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
                        if changed == 0 { return Err(ControlError::Storage.into()); }
                    }
                }
            } else if let Some(proof) = access.as_ref().filter(|p| p.client_id() == client) {
                match proof.check() {
                    Ok(()) => self.revoke_access(&mut tx, proof).await?,
                    Err(BrokerAccessError::Deadline) => return Err(ControlError::Deadline.into()),
                    Err(_) => {},
                }
            }
            guard_original(end)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            guard_original(end)?;
            Ok(())
        }).await.map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }

    async fn revoke_access(
        &self,
        tx: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
        proof: &VerifiedBrokerAccess<'_>,
    ) -> Result<(), Error> {
        if validate_local_auth_challenge(proof.jti()).is_err() {
            return Ok(());
        }
        let Some(expiry) = proof
            .expires_at()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|v| i64::try_from(v.as_secs()).ok())
            .and_then(|v| v.checked_mul(1_000_000))
        else {
            return Ok(());
        };
        let hash = self
            .store
            .digester
            .token(TokenKind::OidcStoredAccess, proof.jti().as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        let now = now_micros()?;
        sqlx_core::query::query("UPDATE public.local_tokens SET revoked_at=$1 WHERE token_hash=$2 AND token_kind='oidc_access' AND token_id=$3 AND client_id=$4 AND oidc_subject=$5 AND expires_at=$6 AND audience=$7 AND expires_at>$1 AND revoked_at IS NULL")
            .bind(now).bind(hash).bind(proof.jti()).bind(proof.client_id()).bind(proof.subject())
            .bind(expiry).bind(&self.authorization.api_audience).execute(&mut **tx).await.map_err(storage_error)?;
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
struct Refresh {
    token_id: String,
    subject: String,
    oidc_subject: String,
    client_id: String,
    audience: String,
    family: String,
    principal_json: Zeroizing<String>,
    revision: i64,
    expires_at: i64,
    created_at: i64,
}
fn refresh(row: &PgRow, cap: i64) -> Result<(Refresh, Option<i64>), Error> {
    let text = |name| {
        row.try_get::<String, _>(name)
            .map_err(|_| Error::MalformedStored)
    };
    let number = |name| {
        row.try_get::<i64, _>(name)
            .map_err(|_| Error::MalformedStored)
    };
    let bounded = |length, name| {
        if !(0..=cap).contains(&number(length)?) {
            return Err(Error::ReadLimitExceeded);
        }
        text(name)
    };
    let stored = Refresh {
        token_id: text("token_id")?,
        subject: bounded("subject_bytes", "subject")?,
        oidc_subject: text("oidc_subject")?,
        client_id: text("client_id")?,
        audience: text("audience")?,
        family: text("family_id")?,
        principal_json: Zeroizing::new(bounded("principal_bytes", "principal_json")?),
        revision: number("local_user_revision")?,
        expires_at: number("expires_at")?,
        created_at: number("created_at")?,
    };
    for value in [&stored.token_id, &stored.oidc_subject, &stored.family] {
        validate_local_auth_challenge(value).map_err(|_| Error::MalformedStored)?;
    }
    let now = now_micros()?;
    let revoked: Option<i64> = row
        .try_get("revoked_at")
        .map_err(|_| Error::MalformedStored)?;
    if stored.created_at <= 0
        || stored.created_at > now
        || stored.expires_at <= stored.created_at
        || revoked.is_some_and(|v| v < stored.created_at || v > now)
    {
        return Err(Error::MalformedStored);
    }
    Ok((stored, revoked))
}
