use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    BrowserOidcAuthorization, ControlError, OidcAuthorizationError as Error,
    OidcAuthorizationInput, OidcAuthorizationPolicy, OidcAuthorizationRejectionCode,
    OidcAuthorizationRequestInfo, PendingOidcAuthorization, RejectedOidcAuthorization,
    flow::now_micros,
    oidc_authorization::{ClientData, PendingFields, guard_original, parse_pending},
};
use broker_security::{
    CredentialDigester, TokenKind, new_local_auth_challenge, validate_local_auth_challenge,
};
use sqlx_core::row::Row;
use sqlx_postgres::{PgRow, Postgres};
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

pub(crate) mod completion;
mod federated;

const CLIENT: &str = r#"SELECT client_id,application_type,created_at,
 OCTET_LENGTH(client_name)::bigint AS name_bytes,
 CASE WHEN OCTET_LENGTH(client_name)<=1024 THEN client_name END AS client_name,
 OCTET_LENGTH(redirect_uris_json)::bigint AS redirect_bytes,
 CASE WHEN OCTET_LENGTH(redirect_uris_json)<=$2 THEN redirect_uris_json END AS redirect_json,
 OCTET_LENGTH(scopes_json)::bigint AS scope_bytes,
 CASE WHEN OCTET_LENGTH(scopes_json)<=$2 THEN scopes_json END AS scope_json
 FROM public.oauth_dynamic_clients WHERE client_id=$1 FOR SHARE"#;
const REQUEST: &str = r#"SELECT request_hash,code_hash,created_at,expires_at,
 OCTET_LENGTH(identity_subject)::bigint AS identity_bytes,
 CASE WHEN OCTET_LENGTH(identity_subject)<=$2 THEN identity_subject END AS identity_subject,
 OCTET_LENGTH(request_json)::bigint AS request_bytes,
 CASE WHEN OCTET_LENGTH(request_json)<=$2 THEN request_json END AS request_json
 FROM public.oidc_auth_requests WHERE request_hash=$1"#;

/// Pending request persistence. Borrowed data owners; no login or grant producer.
pub struct PostgresOidcAuthorizationService<'a> {
    store: &'a PostgresControlStore,
    digester: &'a CredentialDigester,
    policy: &'a OidcAuthorizationPolicy,
}
impl fmt::Debug for PostgresOidcAuthorizationService<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresOidcAuthorizationService([REDACTED])")
    }
}
impl PostgresControlStore {
    /// Browser protocol adapters borrow the existing store credential owner.
    pub fn browser_oidc_authorizations<'a>(
        &'a self,
        policy: &'a OidcAuthorizationPolicy,
    ) -> PostgresOidcAuthorizationService<'a> {
        self.oidc_authorization_service(&self.digester, policy)
    }

    pub fn oidc_authorization_service<'a>(
        &'a self,
        digester: &'a CredentialDigester,
        policy: &'a OidcAuthorizationPolicy,
    ) -> PostgresOidcAuthorizationService<'a> {
        PostgresOidcAuthorizationService {
            store: self,
            digester,
            policy,
        }
    }
}
impl PostgresOidcAuthorizationService<'_> {
    pub async fn create(
        &self,
        input: OidcAuthorizationInput<'_>,
        original: Instant,
    ) -> Result<PendingOidcAuthorization, Error> {
        let deadline = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        self.policy.bound(&input, deadline)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = sqlx_core::connection::Connection::begin_with(
                guard.connection()?,
                "BEGIN ISOLATION LEVEL READ COMMITTED",
            )
            .await
            .map_err(storage_error)?;
            let client = self.client(&mut tx, input.client_id, deadline).await?;
            let fields = self.policy.admit(&input, &client, deadline)?;
            let pending = self
                .insert_pending(tx, fields, deadline, &commit_started)
                .await?;
            guard.confirmed();
            final_gate(deadline, pending.info.expires_at)?;
            Ok(pending)
        })
        .await
        .map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
    /// Admit an initial browser request. Only sealed semantic rejections have a response target.
    pub async fn admit_browser<'a>(
        &self,
        input: OidcAuthorizationInput<'a>,
        original: Instant,
    ) -> Result<BrowserOidcAuthorization<'a>, Error> {
        let deadline = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        self.policy.bound(&input, deadline)?;
        if input.state.len() > 512
            || (input.response_mode == Some("form_post")
                && input.state.contains(['\0', '\r', '\n']))
        {
            return Err(Error::InvalidRequest);
        }
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = sqlx_core::connection::Connection::begin_with(
                guard.connection()?,
                "BEGIN ISOLATION LEVEL READ COMMITTED",
            )
            .await
            .map_err(storage_error)?;
            let client = self.client(&mut tx, input.client_id, deadline).await?;
            client.admit_redirect(input.redirect_uri)?;
            match self.policy.admit(&input, &client, deadline) {
                Ok(fields) => {
                    let pending = self
                        .insert_pending(tx, fields, deadline, &commit_started)
                        .await?;
                    guard.confirmed();
                    final_gate(deadline, pending.info.expires_at)?;
                    Ok(BrowserOidcAuthorization::Pending(Box::new(pending)))
                }
                Err(error) => {
                    let code = OidcAuthorizationRejectionCode::from_error(error)?;
                    guard_original(deadline)?;
                    commit_started.store(true, Ordering::Relaxed);
                    tx.commit()
                        .await
                        .map_err(|_| ControlError::OutcomeUncertain)?;
                    guard.confirmed();
                    guard_original(deadline)?;
                    let rejected =
                        RejectedOidcAuthorization::confirmed(code, &input, &client, deadline)?;
                    Ok(BrowserOidcAuthorization::Rejected(rejected))
                }
            }
        })
        .await
        .map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
    async fn insert_pending(
        &self,
        mut tx: sqlx_core::transaction::Transaction<'_, Postgres>,
        fields: PendingFields,
        deadline: Instant,
        commit_started: &AtomicBool,
    ) -> Result<PendingOidcAuthorization, Error> {
        let request = new_local_auth_challenge().map_err(|_| Error::Random)?;
        let hash = self
            .digester
            .token(TokenKind::OidcAuthRequest, request.as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        let json =
            Zeroizing::new(serde_json::to_string(&fields).map_err(|_| Error::MalformedStored)?);
        if i64::try_from(json.len()).map_err(|_| Error::ReadLimitExceeded)?
            > self.policy.limits.json_bytes
        {
            return Err(Error::ReadLimitExceeded);
        }
        let created_at = now_micros()?;
        if created_at <= 0 {
            return Err(ControlError::Clock.into());
        }
        let expires_at = created_at
            .checked_add(self.policy.ttl_micros)
            .ok_or(ControlError::Clock)?;
        guard_original(deadline)?;
        let count=sqlx_core::query::query("INSERT INTO public.oidc_auth_requests(request_hash,identity_subject,request_json,code_hash,expires_at,created_at) VALUES($1,'',$2,NULL,$3,$4)")
                .bind(hash).bind(&*json).bind(expires_at).bind(created_at).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
        if count != 1 {
            return Err(ControlError::Storage.into());
        }
        final_gate(deadline, expires_at)?;
        commit_started.store(true, Ordering::Relaxed);
        tx.commit()
            .await
            .map_err(|_| ControlError::OutcomeUncertain)?;
        Ok(PendingOidcAuthorization {
            request,
            info: OidcAuthorizationRequestInfo {
                fields,
                created_at,
                expires_at,
            },
        })
    }
    pub async fn load(
        &self,
        raw: &str,
        original: Instant,
    ) -> Result<Option<OidcAuthorizationRequestInfo>, Error> {
        let deadline = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        validate_local_auth_challenge(raw).map_err(|_| Error::InvalidRequest)?;
        let hash = self
            .digester
            .token(TokenKind::OidcAuthRequest, raw.as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        guard_original(deadline)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = sqlx_core::connection::Connection::begin_with(
                guard.connection()?,
                "BEGIN ISOLATION LEVEL READ COMMITTED",
            )
            .await
            .map_err(storage_error)?;
            let initial = sqlx_core::query::query(REQUEST)
                .bind(&hash)
                .bind(self.policy.limits.json_bytes)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?;
            let mut info = if let Some(initial) = initial {
                let initial = decode_request(&initial, self.policy.limits.json_bytes)?;
                if initial.completed() || initial.expires_at <= now_micros()? {
                    None
                } else {
                    let fields =
                        parse_pending(initial.json.as_deref().ok_or(Error::MalformedStored)?)?;
                    let client = self.client(&mut tx, &fields.client_id, deadline).await?;
                    let locked = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(
                        format!("{REQUEST} FOR SHARE"),
                    ))
                    .bind(&hash)
                    .bind(self.policy.limits.json_bytes)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(storage_error)?;
                    match locked {
                        None => None,
                        Some(locked) => {
                            let current = decode_request(&locked, self.policy.limits.json_bytes)?;
                            if current.completed() || current.expires_at <= now_micros()? {
                                None
                            } else {
                                if current != initial
                                    || current.hash != hash
                                    || current.created_at <= 0
                                    || current.created_at > now_micros()?
                                    || current.expires_at.checked_sub(current.created_at)
                                        != Some(self.policy.ttl_micros)
                                {
                                    return Err(Error::MalformedStored);
                                }
                                self.policy.revalidate(&fields, &client, deadline)?;
                                Some(OidcAuthorizationRequestInfo {
                                    fields,
                                    created_at: current.created_at,
                                    expires_at: current.expires_at,
                                })
                            }
                        }
                    }
                }
            } else {
                None
            };
            info = live_info(info, deadline)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            info = live_info(info, deadline)?;
            Ok(info)
        })
        .await
        .map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
    pub(super) async fn client(
        &self,
        tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
        id: &str,
        original: Instant,
    ) -> Result<ClientData, Error> {
        guard_original(original)?;
        if id == self.policy.cli_client_id {
            return Ok(ClientData {
                id: id.into(),
                redirects: vec![self.policy.cli_redirect.clone()],
                native: true,
            });
        }
        if !self.policy.dynamic_registration {
            return Err(Error::InvalidClient);
        }
        let row = sqlx_core::query::query(CLIENT)
            .bind(id)
            .bind(self.policy.limits.json_bytes)
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage_error)?
            .ok_or(Error::InvalidClient)?;
        guard_original(original)?;
        let name_bytes: i64 = get(&row, "name_bytes")?;
        if !(0..=1024).contains(&name_bytes) {
            return Err(Error::MalformedStored);
        }
        let name: &str = get(&row, "client_name")?;
        let created_at: i64 = get(&row, "created_at")?;
        if name.trim() != name
            || name.chars().count() > 256
            || name.contains('\0')
            || created_at <= 0
            || created_at > now_micros()?
        {
            return Err(Error::MalformedStored);
        }
        let redirects: Vec<String> = serde_json::from_str(bounded(
            &row,
            "redirect_bytes",
            "redirect_json",
            self.policy.limits.json_bytes,
        )?)
        .map_err(|_| Error::MalformedStored)?;
        let scopes: Vec<String> = serde_json::from_str(bounded(
            &row,
            "scope_bytes",
            "scope_json",
            self.policy.limits.json_bytes,
        )?)
        .map_err(|_| Error::MalformedStored)?;
        if scopes.is_empty() {
            return Err(Error::MalformedStored);
        }
        for (index, scope) in scopes.iter().enumerate() {
            guard_original(original)?;
            if scope.is_empty()
                || scope.contains(' ')
                || scope
                    .parse::<oxide_auth::primitives::scope::Scope>()
                    .is_err()
                || scopes[..index].contains(scope)
            {
                return Err(Error::MalformedStored);
            }
        }
        for (index, uri) in redirects.iter().enumerate() {
            guard_original(original)?;
            if redirects[..index].contains(uri) {
                return Err(Error::MalformedStored);
            }
        }
        let client = ClientData {
            id: get(&row, "client_id")?,
            redirects,
            native: match get::<&str>(&row, "application_type")? {
                "native" => true,
                "web" => false,
                _ => return Err(Error::MalformedStored),
            },
        };
        if client.id != id {
            return Err(Error::MalformedStored);
        }
        client.validate_registration()?;
        Ok(client)
    }
}
fn final_gate(original: Instant, expires_at: i64) -> Result<(), Error> {
    guard_original(original)?;
    if now_micros()? >= expires_at {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}
fn get<'r, T>(row: &'r PgRow, name: &str) -> Result<T, Error>
where
    T: sqlx_core::decode::Decode<'r, Postgres> + sqlx_core::types::Type<Postgres>,
{
    row.try_get(name).map_err(|_| Error::MalformedStored)
}
fn bounded<'r>(row: &'r PgRow, len: &str, text: &str, cap: i64) -> Result<&'r str, Error> {
    let bytes: i64 = get(row, len)?;
    if bytes < 0 {
        return Err(Error::MalformedStored);
    }
    if bytes > cap {
        return Err(Error::ReadLimitExceeded);
    }
    get(row, text)
}
#[derive(PartialEq, Eq)]
struct StoredRequest {
    hash: String,
    identity: String,
    code: Option<String>,
    created_at: i64,
    expires_at: i64,
    json: Option<Zeroizing<String>>,
}
impl StoredRequest {
    fn completed(&self) -> bool {
        !self.identity.is_empty() || self.code.is_some()
    }
}
fn decode_request(row: &PgRow, cap: i64) -> Result<StoredRequest, Error> {
    let identity = bounded(row, "identity_bytes", "identity_subject", cap)?.to_owned();
    let code: Option<String> = get(row, "code_hash")?;
    // Authorized rows belong to the later producer; do not interpret its JSON here.
    let json = if !identity.is_empty() || code.is_some() {
        None
    } else {
        Some(Zeroizing::new(
            bounded(row, "request_bytes", "request_json", cap)?.to_owned(),
        ))
    };
    Ok(StoredRequest {
        hash: get(row, "request_hash")?,
        identity,
        code,
        created_at: get(row, "created_at")?,
        expires_at: get(row, "expires_at")?,
        json,
    })
}

fn live_info(
    info: Option<OidcAuthorizationRequestInfo>,
    original: Instant,
) -> Result<Option<OidcAuthorizationRequestInfo>, Error> {
    guard_original(original)?;
    let now = now_micros()?;
    Ok(info.filter(|info| info.expires_at > now))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn info(expiry: i64) -> OidcAuthorizationRequestInfo {
        let fields = parse_pending(r#"{"format":"rust-broker-authorization-v1","phase":"pending","client_id":"graphit-cli","api_audience":"graphit-broker","resource":null,"redirect_uri":"http://127.0.0.1/cb","state":"s","scopes":["openid"],"response_mode":"query","nonce":"n","code_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","code_challenge_method":"S256"}"#).unwrap();
        OidcAuthorizationRequestInfo {
            fields,
            created_at: 1,
            expires_at: expiry,
        }
    }
    #[test]
    fn final_load_expiry_is_none_but_original_deadline_is_error() {
        let original = Instant::now() + std::time::Duration::from_secs(2);
        assert!(
            live_info(Some(info(now_micros().unwrap())), original)
                .unwrap()
                .is_none()
        );
        assert!(
            live_info(Some(info(now_micros().unwrap() + 1_000_000)), original)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            live_info(Some(info(i64::MAX)), Instant::now()).unwrap_err(),
            Error::Control(ControlError::Deadline)
        );
        assert_eq!(
            final_gate(original, now_micros().unwrap()),
            Err(Error::InvalidRequest)
        );
    }
}
