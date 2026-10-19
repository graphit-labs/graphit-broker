//! Physical SQLite decoding for the shared immutable access-grant contract.
use crate::{
    ControlError,
    service::oidc_access_snapshot::{AccessGrant, AccessGrantError as Error},
};
use rusqlite::{Row, types::ValueRef};
use zeroize::Zeroizing;

pub(super) const COLUMNS: &str = r#"token_hash,local_user_revision,expires_at,created_at,auth_time,revoked_at,
 CASE WHEN typeof(token_id)='text' THEN length(CAST(token_id AS BLOB)) END AS token_id_bytes,
 CASE WHEN typeof(token_id)='text' AND length(CAST(token_id AS BLOB))<=?2 THEN token_id END AS token_id,
 CASE WHEN typeof(oidc_subject)='text' THEN length(CAST(oidc_subject AS BLOB)) END AS oidc_subject_bytes,
 CASE WHEN typeof(oidc_subject)='text' AND length(CAST(oidc_subject AS BLOB))<=?2 THEN oidc_subject END AS oidc_subject,
 CASE WHEN typeof(client_id)='text' THEN length(CAST(client_id AS BLOB)) END AS client_id_bytes,
 CASE WHEN typeof(client_id)='text' AND length(CAST(client_id AS BLOB))<=?2 THEN client_id END AS client_id,
 CASE WHEN typeof(audience)='text' THEN length(CAST(audience AS BLOB)) END AS audience_bytes,
 CASE WHEN typeof(audience)='text' AND length(CAST(audience AS BLOB))<=?2 THEN audience END AS audience,
 CASE WHEN typeof(resource)='text' THEN length(CAST(resource AS BLOB)) END AS resource_bytes,
 CASE WHEN typeof(resource)='text' AND length(CAST(resource AS BLOB))<=?2 THEN resource END AS resource,
 CASE WHEN typeof(subject)='text' THEN length(CAST(subject AS BLOB)) END AS subject_bytes,
 CASE WHEN typeof(subject)='text' AND length(CAST(subject AS BLOB))<=?2 THEN subject END AS subject,
 CASE WHEN typeof(principal_json)='text' THEN length(CAST(principal_json AS BLOB)) END AS principal_bytes,
 CASE WHEN typeof(principal_json)='text' AND length(CAST(principal_json AS BLOB))<=?2 THEN principal_json END AS principal_json,
 CASE WHEN typeof(scopes_json)='text' THEN length(CAST(scopes_json AS BLOB)) END AS scope_bytes,
 CASE WHEN typeof(scopes_json)='text' AND length(CAST(scopes_json AS BLOB))<=?2 THEN scopes_json END AS scopes_json"#;

pub(super) fn number(row: &Row<'_>, name: &str) -> Result<i64, Error> {
    match row.get_ref(name).map_err(|_| Error::MalformedStored)? {
        ValueRef::Integer(value) => Ok(value),
        _ => Err(Error::MalformedStored),
    }
}
pub(super) fn stamp(row: &Row<'_>, name: &str) -> Result<Option<i64>, Error> {
    match row.get_ref(name).map_err(|_| Error::MalformedStored)? {
        ValueRef::Null => Ok(None),
        ValueRef::Integer(value) => Ok(Some(value)),
        _ => Err(Error::MalformedStored),
    }
}
pub(super) fn text<'a>(row: &'a Row<'_>, name: &str) -> Result<&'a str, Error> {
    row.get_ref(name)
        .map_err(|_| Error::MalformedStored)?
        .as_str()
        .map_err(|_| Error::MalformedStored)
}
pub(super) fn bounded(row: &Row<'_>, bytes: &str, name: &str, cap: i64) -> Result<String, Error> {
    let size = number(row, bytes)?;
    if size < 0 {
        return Err(Error::MalformedStored);
    }
    if size > cap {
        return Err(Error::ReadLimitExceeded);
    }
    Ok(text(row, name)?.to_owned())
}
pub(super) fn decode(row: &Row<'_>, cap: i64) -> Result<(AccessGrant, Option<i64>), Error> {
    let stored = AccessGrant {
        hash: text(row, "token_hash")?.to_owned(),
        id: bounded(row, "token_id_bytes", "token_id", cap)?,
        subject: bounded(row, "subject_bytes", "subject", cap)?,
        oidc_subject: bounded(row, "oidc_subject_bytes", "oidc_subject", cap)?,
        client: bounded(row, "client_id_bytes", "client_id", cap)?,
        audience: bounded(row, "audience_bytes", "audience", cap)?,
        resource: bounded(row, "resource_bytes", "resource", cap)?,
        revision: number(row, "local_user_revision")?,
        expiry: number(row, "expires_at")?,
        created: number(row, "created_at")?,
        auth_time: number(row, "auth_time")?,
        principal: Zeroizing::new(bounded(row, "principal_bytes", "principal_json", cap)?),
        scopes: serde_json::from_str(&bounded(row, "scope_bytes", "scopes_json", cap)?)
            .map_err(|_| Error::MalformedStored)?,
    };
    let revoked = stamp(row, "revoked_at")?;
    if stored.created <= 0
        || stored.expiry <= stored.created
        || stored.auth_time <= 0
        || stored.auth_time > stored.created
        || revoked.is_some_and(|v| v < stored.created)
    {
        return Err(Error::MalformedStored);
    }
    Ok((stored, revoked))
}
pub(super) fn exchange_error(error: Error) -> crate::OidcTokenExchangeError {
    use crate::OidcTokenExchangeError as E;
    match error {
        Error::InvalidToken => E::InvalidGrant,
        Error::MalformedStored => E::MalformedStored,
        Error::ReadLimitExceeded => E::ReadLimitExceeded,
        Error::Credential => E::Credential,
        Error::Control(error) => E::Control(error),
    }
}
pub(super) fn sql(error: rusqlite::Error, work: &super::super::executor::Work) -> Error {
    ControlError::from(work.sql(error)).into()
}
