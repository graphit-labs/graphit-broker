use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    ControlError, LocalIdentityKind, OidcAccessGrantReadError as Error, OidcAccessGrantSnapshot,
    OidcClientApplicationType, OidcCurrentLocalUser, OidcDynamicClientRegistration,
    identity::{safe_identity_segment, valid_identity_subject},
    oidc_access_grant::{canonical, parse_principal},
};
use broker_security::CredentialDigest;
use broker_store::time::TimestampMicros;
use sqlx_core::row::Row;
use sqlx_postgres::PgRow;
use std::{
    fmt,
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const SELECT_GRANT: &str = r#"
SELECT t.token_id,t.token_kind,t.oidc_subject,t.client_id,t.audience,t.resource,
       OCTET_LENGTH(t.subject)::bigint AS subject_bytes,
       CASE WHEN OCTET_LENGTH(t.subject)<=$2 THEN t.subject END AS subject,
       t.local_user_revision,t.family_id,t.auth_time,t.expires_at,t.revoked_at,t.created_at,
       OCTET_LENGTH(t.principal_json)::bigint AS principal_bytes,
       CASE WHEN OCTET_LENGTH(t.principal_json)<=$2 THEN t.principal_json END AS principal_json,
       OCTET_LENGTH(t.scopes_json)::bigint AS scope_bytes,
       CASE WHEN OCTET_LENGTH(t.scopes_json)<=$2 THEN t.scopes_json END AS scopes_json,
       u.subject IS NOT NULL AS user_present,u.username,u.subject AS user_subject,
       u.identity_kind,u.enabled,u.name,u.email,u.organization,u.revision AS user_revision,
       OCTET_LENGTH(u.teams_json)::bigint AS team_bytes,
       CASE WHEN OCTET_LENGTH(u.teams_json)<=$2 THEN u.teams_json END AS teams_json,
       c.client_id IS NOT NULL AS client_present,c.client_id AS registered_client_id,c.client_name,
       c.application_type,c.created_at AS client_created_at,
       OCTET_LENGTH(c.redirect_uris_json)::bigint AS redirect_bytes,
       CASE WHEN OCTET_LENGTH(c.redirect_uris_json)<=$2 THEN c.redirect_uris_json END AS redirect_uris_json,
       OCTET_LENGTH(c.scopes_json)::bigint AS client_scope_bytes,
       CASE WHEN OCTET_LENGTH(c.scopes_json)<=$2 THEN c.scopes_json END AS client_scopes_json
FROM public.local_tokens t
LEFT JOIN public.local_users u ON u.subject=t.subject
LEFT JOIN public.oauth_dynamic_clients c ON c.client_id=t.client_id
WHERE t.token_hash=$1 AND t.token_kind='oidc_access'
"#;
/// Borrowed read-only data access. A digest is not proof of its domain or possession.
pub struct PostgresOidcAccessGrants<'a> {
    store: &'a PostgresControlStore,
    json_bytes: i64,
}
impl fmt::Debug for PostgresOidcAccessGrants<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresOidcAccessGrants([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn oidc_access_grants(
        &self,
        json_bytes: NonZeroUsize,
    ) -> Result<PostgresOidcAccessGrants<'_>, Error> {
        if json_bytes.get() > isize::MAX as usize {
            return Err(Error::InvalidLimits);
        }
        let json_bytes = i64::try_from(json_bytes.get()).map_err(|_| Error::InvalidLimits)?;
        Ok(PostgresOidcAccessGrants {
            store: self,
            json_bytes,
        })
    }
}
impl PostgresOidcAccessGrants<'_> {
    pub async fn read(
        &self,
        digest: &CredentialDigest,
        deadline: Instant,
    ) -> Result<Option<OidcAccessGrantSnapshot>, Error> {
        let deadline = bounded_deadline(deadline, self.store.budgets.operation_timeout)?;
        let hash = digest.to_sql_hex();
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = sqlx_core::connection::Connection::begin_with(
                guard.connection()?,
                "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY",
            )
            .await
            .map_err(storage_error)?;
            let row = sqlx_core::query::query(SELECT_GRANT)
                .bind(hash)
                .bind(self.json_bytes)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?;
            let value = row
                .as_ref()
                .map(|row| decode(row, self.json_bytes))
                .transpose()?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok(value)
        })
        .await
        .map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
}
fn get<'r, T>(row: &'r PgRow, name: &str) -> Result<T, Error>
where
    T: sqlx_core::decode::Decode<'r, sqlx_postgres::Postgres>
        + sqlx_core::types::Type<sqlx_postgres::Postgres>,
{
    row.try_get(name).map_err(|_| Error::MalformedStored)
}
fn bounded_json<'r>(row: &'r PgRow, length: &str, text: &str, cap: i64) -> Result<&'r str, Error> {
    let bytes: i64 = get(row, length)?;
    if bytes < 0 {
        return Err(Error::MalformedStored);
    }
    if bytes > cap {
        return Err(Error::ReadLimitExceeded);
    }
    get(row, text)
}
fn array(row: &PgRow, length: &str, text: &str, cap: i64) -> Result<Vec<String>, Error> {
    serde_json::from_str(bounded_json(row, length, text, cap)?).map_err(|_| Error::MalformedStored)
}
fn id(value: &str, empty: bool) -> bool {
    value.len() <= 128 && ((empty && value.is_empty()) || canonical(value))
}
fn time(row: &PgRow, name: &str) -> Result<TimestampMicros, Error> {
    TimestampMicros::new(get(row, name)?).map_err(|_| Error::MalformedStored)
}
fn decode(row: &PgRow, cap: i64) -> Result<OidcAccessGrantSnapshot, Error> {
    let token_id: String = get(row, "token_id")?;
    let subject = bounded_json(row, "subject_bytes", "subject", cap)?.to_owned();
    let oidc_subject: String = get(row, "oidc_subject")?;
    let client_id: String = get(row, "client_id")?;
    let audience: String = get(row, "audience")?;
    let resource: String = get(row, "resource")?;
    let family_id: String = get(row, "family_id")?;
    let revision: i64 = get(row, "local_user_revision")?;
    if ![&token_id, &oidc_subject, &client_id, &audience]
        .iter()
        .all(|v| id(v, false))
        || !id(&family_id, true)
        || resource.chars().count() > 512
    {
        return Err(Error::MalformedStored);
    }
    let principal = parse_principal(bounded_json(row, "principal_bytes", "principal_json", cap)?)?;
    if principal.subject() != subject || principal.local_user_revision() != revision {
        return Err(Error::MalformedStored);
    }
    let scopes = array(row, "scope_bytes", "scopes_json", cap)?;
    let revoked: Option<i64> = get(row, "revoked_at")?;
    let revoked_at = revoked
        .map(TimestampMicros::new)
        .transpose()
        .map_err(|_| Error::MalformedStored)?;
    let current_local_user = if principal.issuer() == "local" && get::<bool>(row, "user_present")? {
        let username: String = get(row, "username")?;
        let user_subject: String = get(row, "user_subject")?;
        let kind = match get::<&str>(row, "identity_kind")? {
            "human" => LocalIdentityKind::Human,
            "service" => LocalIdentityKind::Service,
            _ => return Err(Error::MalformedStored),
        };
        let enabled = match get::<i16>(row, "enabled")? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedStored),
        };
        let user_revision: i64 = get(row, "user_revision")?;
        if !safe_identity_segment(&username, 128)
            || !valid_identity_subject(&user_subject, 512)
            || user_subject != subject
            || user_revision < 1
        {
            return Err(Error::MalformedStored);
        }
        Some(OidcCurrentLocalUser {
            username,
            subject: user_subject,
            kind,
            enabled,
            name: get(row, "name")?,
            email: get(row, "email")?,
            organization: get(row, "organization")?,
            teams: array(row, "team_bytes", "teams_json", cap)?,
            revision: user_revision,
        })
    } else {
        None
    };
    let dynamic_registration = if get::<bool>(row, "client_present")? {
        let registered_id: String = get(row, "registered_client_id")?;
        if registered_id != client_id || !id(&registered_id, false) {
            return Err(Error::MalformedStored);
        }
        let application_type = match get::<&str>(row, "application_type")? {
            "native" => OidcClientApplicationType::Native,
            "web" => OidcClientApplicationType::Web,
            _ => return Err(Error::MalformedStored),
        };
        Some(OidcDynamicClientRegistration {
            client_id: registered_id,
            client_name: get(row, "client_name")?,
            redirect_uris: array(row, "redirect_bytes", "redirect_uris_json", cap)?,
            scopes: array(row, "client_scope_bytes", "client_scopes_json", cap)?,
            application_type,
            created_at: time(row, "client_created_at")?,
        })
    } else {
        None
    };
    Ok(OidcAccessGrantSnapshot {
        token_id,
        subject,
        oidc_subject,
        client_id,
        audience,
        resource,
        scopes,
        local_user_revision: revision,
        family_id,
        auth_time: time(row, "auth_time")?,
        expires_at: time(row, "expires_at")?,
        revoked_at,
        created_at: time(row, "created_at")?,
        principal,
        current_local_user,
        dynamic_registration,
    })
}
