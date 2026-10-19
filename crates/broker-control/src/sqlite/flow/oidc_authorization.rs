use super::SqliteControlStore;
use crate::{
    BrowserOidcAuthorization, ControlError, OidcAuthorizationError as Error,
    OidcAuthorizationInput, OidcAuthorizationPolicy, OidcAuthorizationRejectionCode,
    OidcAuthorizationRequestInfo, PendingOidcAuthorization, RejectedOidcAuthorization,
    flow::now_micros,
    oidc_authorization::{ClientData, PendingFields, guard_original, parse_pending},
    sqlite::executor::Work,
};
use broker_security::{
    CredentialDigester, TokenKind, new_local_auth_challenge, validate_local_auth_challenge,
};
use rusqlite::{OptionalExtension, Row, Transaction, params, types::ValueRef};
use std::{fmt, sync::Arc, time::Instant};
use zeroize::Zeroizing;

pub(super) mod completion;
mod federated;

/// Native pending/completion over the actual SQLite owner and shared policy.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore,
///     policy: std::sync::Arc<broker_control::OidcAuthorizationPolicy>)
///     -> broker_control::SqliteOidcAuthorizationService<'static> {
///     store.browser_oidc_authorizations(policy)
/// }
/// ```
pub struct SqliteOidcAuthorizationService<'a> {
    store: &'a SqliteControlStore,
    policy: Arc<OidcAuthorizationPolicy>,
}
impl fmt::Debug for SqliteOidcAuthorizationService<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteOidcAuthorizationService([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn browser_oidc_authorizations(
        &self,
        policy: Arc<OidcAuthorizationPolicy>,
    ) -> SqliteOidcAuthorizationService<'_> {
        SqliteOidcAuthorizationService {
            store: self,
            policy,
        }
    }
}
// Copy only after the actual policy has bounded every scalar and list parameter.
struct OwnedInput {
    scalar: [String; 8],
    response_mode: Option<String>,
    resources: Vec<String>,
    prompts: Vec<String>,
}
impl OwnedInput {
    fn new(input: &OidcAuthorizationInput<'_>) -> Self {
        Self {
            scalar: [
                input.client_id,
                input.redirect_uri,
                input.response_type,
                input.scope,
                input.state,
                input.nonce,
                input.code_challenge,
                input.code_challenge_method,
            ]
            .map(str::to_owned),
            response_mode: input.response_mode.map(str::to_owned),
            resources: input.resources.iter().map(|s| (*s).to_owned()).collect(),
            prompts: input.prompts.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
    fn borrowed<'a>(
        &'a self,
        resources: &'a [&'a str],
        prompts: &'a [&'a str],
    ) -> OidcAuthorizationInput<'a> {
        OidcAuthorizationInput {
            client_id: &self.scalar[0],
            redirect_uri: &self.scalar[1],
            response_type: &self.scalar[2],
            scope: &self.scalar[3],
            state: &self.scalar[4],
            nonce: &self.scalar[5],
            code_challenge: &self.scalar[6],
            code_challenge_method: &self.scalar[7],
            response_mode: self.response_mode.as_deref(),
            resources,
            prompts,
        }
    }
}
enum Admission {
    Pending(Box<PendingOidcAuthorization>),
    Rejected(OidcAuthorizationRejectionCode, ClientData),
}
impl SqliteOidcAuthorizationService<'_> {
    pub async fn create(
        &self,
        input: OidcAuthorizationInput<'_>,
        original: Instant,
    ) -> Result<PendingOidcAuthorization, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        self.policy.bound(&input, end)?;
        let owned = OwnedInput::new(&input);
        let policy = Arc::clone(&self.policy);
        let digester = Arc::clone(&self.store.digester);
        let pending = self
            .store
            .executor
            .execute(end, move |state, work| {
                Ok((|| {
                    let resources: Vec<_> = owned.resources.iter().map(String::as_str).collect();
                    let prompts: Vec<_> = owned.prompts.iter().map(String::as_str).collect();
                    let input = owned.borrowed(&resources, &prompts);
                    let tx = state.begin(work).map_err(ControlError::from)?;
                    let client = current_client(&tx, work, &policy, input.client_id, end)?;
                    let fields = policy.admit(&input, &client, end)?;
                    insert_pending(tx, work, &digester, &policy, fields, end)
                })())
            })
            .await
            .map_err(ControlError::from)??;
        final_gate(end, pending.info.expires_at)?;
        Ok(pending)
    }
    pub async fn admit_browser<'a>(
        &self,
        input: OidcAuthorizationInput<'a>,
        original: Instant,
    ) -> Result<BrowserOidcAuthorization<'a>, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        self.policy.bound(&input, end)?;
        if input.state.len() > 512
            || (input.response_mode == Some("form_post")
                && input.state.contains(['\0', '\r', '\n']))
        {
            return Err(Error::InvalidRequest);
        }
        let owned = OwnedInput::new(&input);
        let policy = Arc::clone(&self.policy);
        let digester = Arc::clone(&self.store.digester);
        let admission = self
            .store
            .executor
            .execute(end, move |state, work| {
                Ok((|| {
                    let resources: Vec<_> = owned.resources.iter().map(String::as_str).collect();
                    let prompts: Vec<_> = owned.prompts.iter().map(String::as_str).collect();
                    let input = owned.borrowed(&resources, &prompts);
                    let tx = state.begin(work).map_err(ControlError::from)?;
                    let client = current_client(&tx, work, &policy, input.client_id, end)?;
                    client.admit_redirect(input.redirect_uri)?;
                    match policy.admit(&input, &client, end) {
                        Ok(fields) => insert_pending(tx, work, &digester, &policy, fields, end)
                            .map(|pending| Admission::Pending(Box::new(pending))),
                        Err(error) => {
                            let code = OidcAuthorizationRejectionCode::from_error(error)?;
                            guard_original(end)?;
                            work.commit(tx).map_err(ControlError::from)?;
                            Ok(Admission::Rejected(code, client))
                        }
                    }
                })())
            })
            .await
            .map_err(ControlError::from)??;
        // The sealed redirect decision is created only after the worker's known ACK.
        match admission {
            Admission::Pending(pending) => {
                final_gate(end, pending.info.expires_at)?;
                Ok(BrowserOidcAuthorization::Pending(pending))
            }
            Admission::Rejected(code, client) => {
                guard_original(end)?;
                Ok(BrowserOidcAuthorization::Rejected(
                    RejectedOidcAuthorization::confirmed(code, &input, &client, end)?,
                ))
            }
        }
    }
    pub async fn load(
        &self,
        raw: &str,
        original: Instant,
    ) -> Result<Option<OidcAuthorizationRequestInfo>, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        validate_local_auth_challenge(raw).map_err(|_| Error::InvalidRequest)?;
        let hash = self
            .store
            .digester
            .token(TokenKind::OidcAuthRequest, raw.as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        let policy = Arc::clone(&self.policy);
        let info = self
            .store
            .executor
            .execute(end, move |state, work| {
                Ok((|| {
                    let tx = state.begin(work).map_err(ControlError::from)?;
                    let row = tx
                        .query_row(REQUEST, params![hash, policy.limits.json_bytes], |row| {
                            Ok(decode_request(row, policy.limits.json_bytes))
                        })
                        .optional()
                        .map_err(|e| ControlError::from(work.sql(e)))?
                        .transpose()?;
                    let info = match row {
                        Some(row) if !row.completed() && row.expires_at > now_micros()? => {
                            if row.hash != hash
                                || row.created_at <= 0
                                || row.created_at > now_micros()?
                                || row.expires_at.checked_sub(row.created_at)
                                    != Some(policy.ttl_micros)
                            {
                                return Err(Error::MalformedStored);
                            }
                            let fields =
                                parse_pending(row.json.as_deref().ok_or(Error::MalformedStored)?)?;
                            let client =
                                current_client(&tx, work, &policy, &fields.client_id, end)?;
                            policy.revalidate(&fields, &client, end)?;
                            Some(OidcAuthorizationRequestInfo {
                                fields,
                                created_at: row.created_at,
                                expires_at: row.expires_at,
                            })
                        }
                        _ => None,
                    };
                    let info = live_info(info, end)?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok(info)
                })())
            })
            .await
            .map_err(ControlError::from)??;
        live_info(info, end)
    }
}
fn insert_pending(
    tx: Transaction<'_>,
    work: &Work,
    digester: &CredentialDigester,
    policy: &OidcAuthorizationPolicy,
    fields: PendingFields,
    end: Instant,
) -> Result<PendingOidcAuthorization, Error> {
    let request = new_local_auth_challenge().map_err(|_| Error::Random)?;
    let hash = digester
        .token(TokenKind::OidcAuthRequest, request.as_bytes())
        .map_err(|_| Error::Credential)?
        .to_sql_hex();
    let json = Zeroizing::new(serde_json::to_string(&fields).map_err(|_| Error::MalformedStored)?);
    if i64::try_from(json.len()).map_err(|_| Error::ReadLimitExceeded)? > policy.limits.json_bytes {
        return Err(Error::ReadLimitExceeded);
    }
    let created_at = now_micros()?;
    if created_at <= 0 {
        return Err(ControlError::Clock.into());
    }
    let expires_at = created_at
        .checked_add(policy.ttl_micros)
        .ok_or(ControlError::Clock)?;
    guard_original(end)?;
    let changed = tx.execute("INSERT INTO oidc_auth_requests(request_hash,identity_subject,request_json,code_hash,expires_at,created_at) VALUES(?1,'',?2,NULL,?3,?4)",params![hash,&*json,expires_at,created_at]).map_err(|e| ControlError::from(work.sql(e)))?;
    if changed != 1 {
        return Err(ControlError::Storage.into());
    }
    final_gate(end, expires_at)?;
    work.commit(tx).map_err(ControlError::from)?;
    Ok(PendingOidcAuthorization {
        request,
        info: OidcAuthorizationRequestInfo {
            fields,
            created_at,
            expires_at,
        },
    })
}
pub(super) fn current_client(
    tx: &Transaction<'_>,
    work: &Work,
    policy: &OidcAuthorizationPolicy,
    id: &str,
    end: Instant,
) -> Result<ClientData, Error> {
    guard_original(end)?;
    if id == policy.cli_client_id {
        return Ok(ClientData {
            id: id.into(),
            redirects: vec![policy.cli_redirect.clone()],
            native: true,
        });
    }
    if !policy.dynamic_registration {
        return Err(Error::InvalidClient);
    }
    tx.query_row(CLIENT, params![id, policy.limits.json_bytes], |row| {
        Ok((|| {
            let name = bounded(row, "name_bytes", "client_name", 1024)?;
            let created_at = number(row, "created_at")?;
            if name.trim() != name
                || name.chars().count() > 256
                || name.contains('\0')
                || created_at <= 0
                || created_at > now_micros()?
            {
                return Err(Error::MalformedStored);
            }
            let redirects: Vec<String> = serde_json::from_str(bounded(
                row,
                "redirect_bytes",
                "redirect_json",
                policy.limits.json_bytes,
            )?)
            .map_err(|_| Error::MalformedStored)?;
            let scopes: Vec<String> = serde_json::from_str(bounded(
                row,
                "scope_bytes",
                "scope_json",
                policy.limits.json_bytes,
            )?)
            .map_err(|_| Error::MalformedStored)?;
            if scopes.is_empty() {
                return Err(Error::MalformedStored);
            }
            for (i, scope) in scopes.iter().enumerate() {
                guard_original(end)?;
                if scope.is_empty()
                    || scope.contains(' ')
                    || scope
                        .parse::<oxide_auth::primitives::scope::Scope>()
                        .is_err()
                    || scopes[..i].contains(scope)
                {
                    return Err(Error::MalformedStored);
                }
            }
            for (i, uri) in redirects.iter().enumerate() {
                guard_original(end)?;
                if redirects[..i].contains(uri) {
                    return Err(Error::MalformedStored);
                }
            }
            let client = ClientData {
                id: text(row, "client_id")?.into(),
                redirects,
                native: match text(row, "application_type")? {
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
        })())
    })
    .optional()
    .map_err(|e| ControlError::from(work.sql(e)))?
    .ok_or(Error::InvalidClient)?
}
pub(super) fn final_gate(end: Instant, expiry: i64) -> Result<(), Error> {
    guard_original(end)?;
    if now_micros()? >= expiry {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}
fn live_info(
    info: Option<OidcAuthorizationRequestInfo>,
    end: Instant,
) -> Result<Option<OidcAuthorizationRequestInfo>, Error> {
    guard_original(end)?;
    let now = now_micros()?;
    Ok(info.filter(|info| info.expires_at > now))
}
pub(super) fn text<'a>(row: &'a Row<'_>, name: &str) -> Result<&'a str, Error> {
    row.get_ref(name)
        .map_err(|_| Error::MalformedStored)?
        .as_str()
        .map_err(|_| Error::MalformedStored)
}
pub(super) fn number(row: &Row<'_>, name: &str) -> Result<i64, Error> {
    match row.get_ref(name).map_err(|_| Error::MalformedStored)? {
        ValueRef::Integer(v) => Ok(v),
        _ => Err(Error::MalformedStored),
    }
}
pub(super) fn bounded<'a>(
    row: &'a Row<'_>,
    size: &str,
    name: &str,
    cap: i64,
) -> Result<&'a str, Error> {
    let bytes = number(row, size)?;
    if bytes < 0 {
        return Err(Error::MalformedStored);
    }
    if bytes > cap {
        return Err(Error::ReadLimitExceeded);
    }
    text(row, name)
}
pub(super) struct StoredRequest {
    pub(super) hash: String,
    pub(super) identity: String,
    pub(super) code: Option<String>,
    pub(super) json: Option<Zeroizing<String>>,
    pub(super) created_at: i64,
    pub(super) expires_at: i64,
}
impl StoredRequest {
    fn completed(&self) -> bool {
        !self.identity.is_empty() || self.code.is_some()
    }
}
fn decode_request(row: &Row<'_>, cap: i64) -> Result<StoredRequest, Error> {
    let identity = bounded(row, "identity_bytes", "identity_subject", cap)?.to_owned();
    let code = match text(row, "code_type")? {
        "null" => None,
        "text" => Some(text(row, "code_hash")?.to_owned()),
        _ => return Err(Error::MalformedStored),
    };
    let json = if !identity.is_empty() || code.is_some() {
        None
    } else {
        Some(Zeroizing::new(
            bounded(row, "request_bytes", "request_json", cap)?.to_owned(),
        ))
    };
    Ok(StoredRequest {
        hash: text(row, "request_hash")?.into(),
        identity,
        code,
        json,
        created_at: number(row, "created_at")?,
        expires_at: number(row, "expires_at")?,
    })
}
const CLIENT: &str = r#"SELECT
 CASE WHEN typeof(client_id)='text' AND length(CAST(client_id AS BLOB))<=128 THEN client_id END AS client_id,
 CASE WHEN typeof(application_type)='text' AND length(CAST(application_type AS BLOB))<=6 THEN application_type END AS application_type,
 created_at, CASE WHEN typeof(client_name)='text' THEN length(CAST(client_name AS BLOB)) END AS name_bytes,
 CASE WHEN typeof(client_name)='text' AND length(CAST(client_name AS BLOB))<=1024 THEN client_name END AS client_name,
 CASE WHEN typeof(redirect_uris_json)='text' THEN length(CAST(redirect_uris_json AS BLOB)) END AS redirect_bytes,
 CASE WHEN typeof(redirect_uris_json)='text' AND length(CAST(redirect_uris_json AS BLOB))<=?2 THEN redirect_uris_json END AS redirect_json,
 CASE WHEN typeof(scopes_json)='text' THEN length(CAST(scopes_json AS BLOB)) END AS scope_bytes,
 CASE WHEN typeof(scopes_json)='text' AND length(CAST(scopes_json AS BLOB))<=?2 THEN scopes_json END AS scope_json
 FROM oauth_dynamic_clients WHERE client_id=?1"#;
const REQUEST: &str = r#"SELECT
 CASE WHEN typeof(request_hash)='text' AND length(CAST(request_hash AS BLOB))<=64 THEN request_hash END AS request_hash,
 typeof(code_hash) AS code_type, CASE WHEN typeof(code_hash)='text' AND length(CAST(code_hash AS BLOB))<=64 THEN code_hash END AS code_hash,
 created_at, expires_at,
 CASE WHEN typeof(identity_subject)='text' THEN length(CAST(identity_subject AS BLOB)) END AS identity_bytes,
 CASE WHEN typeof(identity_subject)='text' AND length(CAST(identity_subject AS BLOB))<=?2 THEN identity_subject END AS identity_subject,
 CASE WHEN typeof(request_json)='text' THEN length(CAST(request_json AS BLOB)) END AS request_bytes,
 CASE WHEN typeof(request_json)='text' AND length(CAST(request_json AS BLOB))<=?2 THEN request_json END AS request_json
 FROM oidc_auth_requests WHERE request_hash=?1"#;
