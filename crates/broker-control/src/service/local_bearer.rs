use super::{ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error};
use crate::{
    LocalBearerKind, LocalBearerState, LocalBearerStateError, LocalBearerUser, LocalIdentityKind,
    identity::{safe_identity_segment, valid_identity_subject},
    local_bearer::{LOCAL_ISSUER, normalize, parse_array, parse_principal},
};
use broker_security::CredentialDigest;
use broker_store::time::TimestampMicros;
use sqlx_core::{connection::Connection, row::Row};
use sqlx_postgres::PgRow;
use std::{fmt, num::NonZeroUsize, time::Instant};

const SELECT_STATE: &str = "SELECT t.token_kind,t.subject AS token_subject,t.audience,t.local_user_revision AS token_revision,t.expires_at,t.revoked_at,pg_catalog.octet_length(t.principal_json)::bigint AS principal_length,CASE WHEN pg_catalog.octet_length(t.principal_json)::bigint<=$2 THEN t.principal_json END AS principal_json,pg_catalog.octet_length(t.scopes_json)::bigint AS scopes_length,CASE WHEN pg_catalog.octet_length(t.scopes_json)::bigint<=$2 THEN t.scopes_json END AS scopes_json,u.subject IS NOT NULL AS user_present,u.username,u.subject AS user_subject,u.identity_kind,u.name,u.email,u.organization,u.enabled::bigint,u.revision AS user_revision,pg_catalog.octet_length(u.teams_json)::bigint AS teams_length,CASE WHEN pg_catalog.octet_length(u.teams_json)::bigint<=$2 THEN u.teams_json END AS teams_json FROM public.local_tokens t LEFT JOIN public.local_users u ON u.subject=t.subject WHERE t.token_hash=$1";

/// Borrowed metadata reader; it cannot authenticate a raw bearer.
pub struct PostgresLocalBearerStates<'a> {
    owner: &'a PostgresControlStore,
    json_bytes: i64,
}
impl fmt::Debug for PostgresLocalBearerStates<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresLocalBearerStates([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn local_bearer_states(
        &self,
        json_bytes: NonZeroUsize,
    ) -> Result<PostgresLocalBearerStates<'_>, LocalBearerStateError> {
        isize::try_from(json_bytes.get()).map_err(|_| LocalBearerStateError::InvalidLimits)?;
        let json_bytes =
            i64::try_from(json_bytes.get()).map_err(|_| LocalBearerStateError::InvalidLimits)?;
        Ok(PostgresLocalBearerStates {
            owner: self,
            json_bytes,
        })
    }
}
impl PostgresLocalBearerStates<'_> {
    /// Read one token and its current user from one SQL statement snapshot.
    /// The caller still must verify bearer possession, audience, exact required
    /// scopes, expiry and revocation before producing any authenticated principal.
    pub async fn read(
        &self,
        digest: &CredentialDigest,
        kind: LocalBearerKind,
        caller: Instant,
    ) -> Result<Option<LocalBearerState>, LocalBearerStateError> {
        let end = bounded_deadline(caller, self.owner.budgets.operation_timeout)?;
        let hash = digest.to_sql_hex();
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.owner.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
                .await
                .map_err(storage_error)?;
            let row = sqlx_core::query::query(SELECT_STATE)
                .bind(&hash)
                .bind(self.json_bytes)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?;
            let state = row
                .map(|row| decode(&row, kind, self.json_bytes))
                .transpose()?
                .flatten();
            tx.commit().await.map_err(storage_error)?;
            guard.confirmed();
            Ok(state)
        })
        .await
        .map_err(|_| LocalBearerStateError::Control(crate::ControlError::Deadline))?
    }
}
fn get<'r, T>(row: &'r PgRow, name: &str) -> Result<T, LocalBearerStateError>
where
    T: sqlx_core::decode::Decode<'r, sqlx_postgres::Postgres>
        + sqlx_core::types::Type<sqlx_postgres::Postgres>,
{
    row.try_get(name)
        .map_err(|_| LocalBearerStateError::MalformedStored)
}
fn json_text<'a>(
    row: &'a PgRow,
    length: &str,
    field: &str,
    cap: i64,
) -> Result<&'a str, LocalBearerStateError> {
    let size: i64 = get(row, length)?;
    if size < 0 {
        return Err(LocalBearerStateError::MalformedStored);
    }
    if size > cap {
        return Err(LocalBearerStateError::ReadLimitExceeded);
    }
    get(row, field)
}
fn decode(
    row: &PgRow,
    kind: LocalBearerKind,
    cap: i64,
) -> Result<Option<LocalBearerState>, LocalBearerStateError> {
    let stored_kind: &str = get(row, "token_kind")?;
    if stored_kind != kind.as_str() {
        return Ok(None);
    }
    let principal = parse_principal(json_text(row, "principal_length", "principal_json", cap)?)?;
    if principal.issuer != LOCAL_ISSUER {
        return Ok(None);
    }
    let subject: &str = get(row, "token_subject")?;
    let revision: i64 = get(row, "token_revision")?;
    if !valid_identity_subject(subject, 512) || revision < 1 {
        return Err(LocalBearerStateError::MalformedStored);
    }
    if principal.subject != subject || principal.local_user_revision != Some(revision) {
        return Ok(None);
    }
    let scopes = parse_array(json_text(row, "scopes_length", "scopes_json", cap)?)?;
    let expires_at = TimestampMicros::new(get(row, "expires_at")?)
        .map_err(|_| LocalBearerStateError::MalformedStored)?;
    let revoked_at = get::<Option<i64>>(row, "revoked_at")?
        .map(TimestampMicros::new)
        .transpose()
        .map_err(|_| LocalBearerStateError::MalformedStored)?;
    if !get::<bool>(row, "user_present")? {
        return Ok(None);
    }
    let username: &str = get(row, "username")?;
    let user_subject: &str = get(row, "user_subject")?;
    let user_kind = match get::<&str>(row, "identity_kind")? {
        "human" => LocalIdentityKind::Human,
        "service" => LocalIdentityKind::Service,
        _ => return Err(LocalBearerStateError::MalformedStored),
    };
    let enabled: i64 = get(row, "enabled")?;
    let current_revision: i64 = get(row, "user_revision")?;
    if !safe_identity_segment(username, 128)
        || !valid_identity_subject(user_subject, 512)
        || !matches!(enabled, 0 | 1)
        || current_revision < 1
    {
        return Err(LocalBearerStateError::MalformedStored);
    }
    if enabled == 0
        || current_revision != revision
        || user_subject != subject
        || user_kind != kind.identity_kind()
    {
        return Ok(None);
    }
    let mut teams = parse_array(json_text(row, "teams_length", "teams_json", cap)?)?;
    normalize(&mut teams);
    Ok(Some(LocalBearerState {
        kind,
        audience: get(row, "audience")?,
        raw_scopes: scopes,
        expires_at,
        revoked_at,
        user: LocalBearerUser {
            username: username.to_owned(),
            subject: user_subject.to_owned(),
            kind: user_kind,
            name: get(row, "name")?,
            email: get(row, "email")?,
            organization: get(row, "organization")?,
            teams,
            revision: current_revision,
        },
    }))
}
