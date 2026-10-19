use super::{oidc_principal::OidcPrincipal, storage_error};
use crate::{ControlError, OidcTokenExchangeError as Error};
use sqlx_postgres::Postgres;

/// Private persistence inputs established by the two native SQL protocol producers.
pub(crate) struct TokenData<'a> {
    pub(crate) principal: &'a OidcPrincipal,
    pub(crate) oidc_subject: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) audience: &'a str,
    pub(crate) resource: Option<&'a str>,
    pub(crate) principal_json: &'a str,
    pub(crate) scopes_json: &'a str,
    pub(crate) family: &'a str,
    pub(crate) auth_time: i64,
    pub(crate) created_at: i64,
}
pub(super) async fn insert(
    tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    d: &TokenData<'_>,
    hash: &str,
    id: &str,
    kind: &str,
    expiry: i64,
) -> Result<(), Error> {
    let count = sqlx_core::query::query(r#"INSERT INTO public.local_tokens
      (token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,
       scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)"#)
        .bind(hash).bind(id).bind(kind).bind(d.principal.subject()).bind(d.oidc_subject)
        .bind(d.principal_json).bind(d.client_id).bind(d.audience).bind(d.resource.unwrap_or(""))
        .bind(d.scopes_json).bind(d.principal.revision()).bind(d.family)
        .bind(d.auth_time).bind(expiry).bind(d.created_at)
        .execute(&mut **tx).await.map_err(storage_error)?.rows_affected();
    if count != 1 {
        return Err(ControlError::Storage.into());
    }
    Ok(())
}

// Separate two-int keyspace from the existing one-bigint refresh-family locks.
const PAIR_LOCK_NAMESPACE: i32 = 4_750_302;

/// Coordinate admitted writers without serializing independent refresh families.
pub(super) async fn lock_pair_shared(
    tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    subject: &str,
    client: &str,
    end: std::time::Instant,
) -> Result<(), ControlError> {
    if std::time::Instant::now() >= end {
        return Err(ControlError::Deadline);
    }
    let key = serde_json::to_string(&(subject, client)).map_err(|_| ControlError::Storage)?;
    sqlx_core::query::query("SELECT pg_advisory_xact_lock_shared($1, hashtext($2))")
        .bind(PAIR_LOCK_NAMESPACE)
        .bind(key)
        .execute(&mut **tx)
        .await
        .map_err(storage_error)?;
    if std::time::Instant::now() >= end {
        return Err(ControlError::Deadline);
    }
    Ok(())
}

/// Dispose all generations only after every earlier shared writer has committed.
pub(super) async fn lock_pair_exclusive(
    tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    subject: &str,
    client: &str,
    end: std::time::Instant,
) -> Result<(), ControlError> {
    if std::time::Instant::now() >= end {
        return Err(ControlError::Deadline);
    }
    let key = serde_json::to_string(&(subject, client)).map_err(|_| ControlError::Storage)?;
    sqlx_core::query::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
        .bind(PAIR_LOCK_NAMESPACE)
        .bind(key)
        .execute(&mut **tx)
        .await
        .map_err(storage_error)?;
    if std::time::Instant::now() >= end {
        return Err(ControlError::Deadline);
    }
    Ok(())
}
