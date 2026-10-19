use crate::{
    ControlError, LocalBearerKind, LocalBearerState, LocalBearerStateError as Error,
    LocalBearerUser, LocalIdentityKind,
    identity::{safe_identity_segment, valid_identity_subject},
    local_bearer::{LOCAL_ISSUER, normalize, parse_array, parse_principal},
    sqlite::executor::Work,
};
use broker_store::time::TimestampMicros;
use rusqlite::{Row, Transaction, params};

// Reject dynamic SQLite types and cap text in SQL before the driver copies it.
const SELECT: &str = "SELECT
 CASE WHEN typeof(t.token_kind)='text' AND length(CAST(t.token_kind AS BLOB))<=16 THEN t.token_kind END AS token_kind,
 CASE WHEN typeof(t.subject)='text' AND length(CAST(t.subject AS BLOB))<=512 THEN t.subject END AS token_subject,
 CASE WHEN typeof(t.audience)='text' AND length(CAST(t.audience AS BLOB))<=512 THEN t.audience END AS audience,
 t.local_user_revision AS token_revision,t.expires_at,t.revoked_at,
 CASE WHEN typeof(t.principal_json)='text' THEN length(CAST(t.principal_json AS BLOB)) END AS principal_length,
 CASE WHEN typeof(t.principal_json)='text' AND length(CAST(t.principal_json AS BLOB))<=?2 THEN t.principal_json END AS principal_json,
 CASE WHEN typeof(t.scopes_json)='text' THEN length(CAST(t.scopes_json AS BLOB)) END AS scopes_length,
 CASE WHEN typeof(t.scopes_json)='text' AND length(CAST(t.scopes_json AS BLOB))<=?2 THEN t.scopes_json END AS scopes_json,
 u.subject IS NOT NULL AS user_present,
 CASE WHEN typeof(u.username)='text' AND length(CAST(u.username AS BLOB))<=128 THEN u.username END AS username,
 CASE WHEN typeof(u.subject)='text' AND length(CAST(u.subject AS BLOB))<=512 THEN u.subject END AS user_subject,
 CASE WHEN typeof(u.identity_kind)='text' AND length(CAST(u.identity_kind AS BLOB))<=16 THEN u.identity_kind END AS identity_kind,
 CASE WHEN typeof(u.name)='text' AND length(CAST(u.name AS BLOB))<=2048 THEN u.name END AS name,
 CASE WHEN typeof(u.email)='text' AND length(CAST(u.email AS BLOB))<=2048 THEN u.email END AS email,
 CASE WHEN typeof(u.organization)='text' AND length(CAST(u.organization AS BLOB))<=2048 THEN u.organization END AS organization,
 u.enabled,u.revision AS user_revision,
 CASE WHEN typeof(u.teams_json)='text' THEN length(CAST(u.teams_json AS BLOB)) END AS teams_length,
 CASE WHEN typeof(u.teams_json)='text' AND length(CAST(u.teams_json AS BLOB))<=?2 THEN u.teams_json END AS teams_json
 FROM local_tokens t LEFT JOIN local_users u ON u.subject=t.subject WHERE t.token_hash=?1";

pub(super) fn read(
    tx: &Transaction<'_>,
    work: &Work,
    hash: &str,
    kind: LocalBearerKind,
    cap: i64,
) -> Result<Option<LocalBearerState>, Error> {
    let mut statement = tx
        .prepare(SELECT)
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let mut rows = statement
        .query(params![hash, cap])
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let row = rows.next().map_err(|e| ControlError::from(work.sql(e)))?;
    work.check().map_err(ControlError::from)?;
    row.map(|row| decode(row, kind, cap))
        .transpose()
        .map(Option::flatten)
}
fn get<T: rusqlite::types::FromSql>(row: &Row<'_>, name: &str) -> Result<T, Error> {
    row.get(name).map_err(|_| Error::MalformedStored)
}
fn text<'r>(row: &'r Row<'_>, name: &str) -> Result<&'r str, Error> {
    row.get_ref(name)
        .map_err(|_| Error::MalformedStored)?
        .as_str()
        .map_err(|_| Error::MalformedStored)
}
fn json<'r>(row: &'r Row<'_>, length: &str, field: &str, cap: i64) -> Result<&'r str, Error> {
    let size: i64 = get(row, length)?;
    if size < 0 {
        return Err(Error::MalformedStored);
    }
    if size > cap {
        return Err(Error::ReadLimitExceeded);
    }
    text(row, field)
}
fn profile(row: &Row<'_>, field: &str) -> Result<String, Error> {
    let value = text(row, field)?;
    if value.chars().count() > 512 {
        return Err(Error::MalformedStored);
    }
    Ok(value.to_owned())
}
fn decode(
    row: &Row<'_>,
    kind: LocalBearerKind,
    cap: i64,
) -> Result<Option<LocalBearerState>, Error> {
    if text(row, "token_kind")? != kind.as_str() {
        return Ok(None);
    }
    let principal = parse_principal(json(row, "principal_length", "principal_json", cap)?)?;
    if principal.issuer != LOCAL_ISSUER {
        return Ok(None);
    }
    let subject = text(row, "token_subject")?;
    let revision: i64 = get(row, "token_revision")?;
    if !valid_identity_subject(subject, 512) || revision < 1 {
        return Err(Error::MalformedStored);
    }
    if principal.subject != subject || principal.local_user_revision != Some(revision) {
        return Ok(None);
    }
    let scopes = parse_array(json(row, "scopes_length", "scopes_json", cap)?)?;
    let expires_at =
        TimestampMicros::new(get(row, "expires_at")?).map_err(|_| Error::MalformedStored)?;
    let revoked_at = get::<Option<i64>>(row, "revoked_at")?
        .map(TimestampMicros::new)
        .transpose()
        .map_err(|_| Error::MalformedStored)?;
    if !get::<bool>(row, "user_present")? {
        return Ok(None);
    }
    let username = text(row, "username")?;
    let user_subject = text(row, "user_subject")?;
    let user_kind = match text(row, "identity_kind")? {
        "human" => LocalIdentityKind::Human,
        "service" => LocalIdentityKind::Service,
        _ => return Err(Error::MalformedStored),
    };
    let enabled: i64 = get(row, "enabled")?;
    let current_revision: i64 = get(row, "user_revision")?;
    if !safe_identity_segment(username, 128)
        || !valid_identity_subject(user_subject, 512)
        || !matches!(enabled, 0 | 1)
        || current_revision < 1
    {
        return Err(Error::MalformedStored);
    }
    if enabled == 0
        || current_revision != revision
        || user_subject != subject
        || user_kind != kind.identity_kind()
    {
        return Ok(None);
    }
    let mut teams = parse_array(json(row, "teams_length", "teams_json", cap)?)?;
    normalize(&mut teams);
    let audience = text(row, "audience")?;
    if audience.chars().count() > 128 {
        return Err(Error::MalformedStored);
    }
    Ok(Some(LocalBearerState {
        kind,
        audience: audience.to_owned(),
        raw_scopes: scopes,
        expires_at,
        revoked_at,
        user: LocalBearerUser {
            username: username.to_owned(),
            subject: user_subject.to_owned(),
            kind: user_kind,
            name: profile(row, "name")?,
            email: profile(row, "email")?,
            organization: profile(row, "organization")?,
            teams,
            revision: current_revision,
        },
    }))
}
