use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    BrokerAccessIssuer, BrokerAccessTokenInput, BrokerIdTokenInput, ControlError,
    OidcAuthorizationPolicy, OidcTokenExchangeError as Error, OidcTokenExchangeInput,
    OidcTokenExchangePolicy, OidcTokenExchangeResult, UpstreamBearerVerifier, flow::now_micros,
    oidc_authorization::guard_original,
};
use broker_security::{
    CredentialDigest, CredentialDigester, TokenKind, new_local_auth_challenge,
    validate_local_auth_challenge,
};
use chrono::{DateTime, Utc};
use oxide_auth::{
    code_grant::{
        accesstoken::{AccessToken, Input, Output},
        extensions::Pkce,
    },
    primitives::{
        grant::{Extensions, Grant},
        issuer::{IssuedToken, TokenType},
    },
};
use sqlx_core::row::Row;
use sqlx_postgres::{PgRow, Postgres};
use std::{
    borrow::Cow,
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

pub(crate) mod codec;
use super::oidc_authorization::completion::current_principal;
use super::oidc_tokens::{TokenData, insert};

const REQUEST: &str = r#"SELECT request_hash,code_hash,created_at,expires_at,
 OCTET_LENGTH(identity_subject)::bigint AS identity_bytes,
 CASE WHEN OCTET_LENGTH(identity_subject)<=$2 THEN identity_subject END AS identity_subject,
 OCTET_LENGTH(request_json)::bigint AS request_bytes,
 CASE WHEN OCTET_LENGTH(request_json)<=$2 THEN request_json END AS request_json
 FROM public.oidc_auth_requests WHERE code_hash=$1"#;
/// Borrowed native SQL producer. No externally constructible grant or callback authority.
pub struct PostgresOidcTokenExchange<'a> {
    store: &'a PostgresControlStore,
    digester: &'a CredentialDigester,
    authorization: &'a OidcAuthorizationPolicy,
    policy: &'a OidcTokenExchangePolicy,
    issuer: &'a BrokerAccessIssuer,
    upstream: Option<&'a UpstreamBearerVerifier>,
}
impl fmt::Debug for PostgresOidcTokenExchange<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresOidcTokenExchange([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn oidc_token_exchange<'a>(
        &'a self,
        authorization: &'a OidcAuthorizationPolicy,
        policy: &'a OidcTokenExchangePolicy,
        issuer: &'a BrokerAccessIssuer,
    ) -> Result<PostgresOidcTokenExchange<'a>, Error> {
        if issuer.api_audience() != authorization.api_audience {
            return Err(Error::InvalidConfiguration);
        }
        Ok(PostgresOidcTokenExchange {
            store: self,
            digester: &self.digester,
            authorization,
            policy,
            issuer,
            upstream: None,
        })
    }
}
impl<'a> PostgresOidcTokenExchange<'a> {
    /// Attach the current common upstream trust owner for native federated grants.
    /// LOCAL-only callers retain their existing authority and SQL checks.
    pub fn with_upstream(mut self, verifier: &'a UpstreamBearerVerifier) -> Self {
        self.upstream = Some(verifier);
        self
    }
    pub async fn exchange(
        &self,
        input: OidcTokenExchangeInput<'_>,
        original: Instant,
    ) -> Result<OidcTokenExchangeResult, Error> {
        let deadline = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        match input.grant_type {
            Some("authorization_code") => {}
            None => return Err(Error::InvalidRequest),
            _ => return Err(Error::UnsupportedGrantType),
        }
        // The transport bounds allocation; this producer independently bounds borrowed parameters.
        let mut total = 0usize;
        for value in [
            input.grant_type,
            input.client_id,
            input.code,
            input.redirect_uri,
            input.code_verifier,
            input.resource,
        ]
        .into_iter()
        .flatten()
        .chain(input.authorization.map(|(u, _)| u))
        {
            guard_original(deadline)?;
            total = total
                .checked_add(value.len())
                .ok_or(Error::InvalidRequest)?;
        }
        total = total
            .checked_add(input.authorization.map_or(0, |(_, p)| p.len()))
            .ok_or(Error::InvalidRequest)?;
        if total > self.authorization.limits.parameter_bytes() {
            return Err(Error::InvalidRequest);
        }
        let raw = input.code.ok_or(Error::InvalidRequest)?;
        validate_local_auth_challenge(raw).map_err(|_| Error::InvalidGrant)?;
        let verifier = input.code_verifier.ok_or(Error::InvalidGrant)?;
        if !(43..=128).contains(&verifier.len())
            || !verifier
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"-._~".contains(&v))
        {
            return Err(Error::InvalidGrant);
        }
        let hash = self
            .digester
            .token(TokenKind::OidcAuthorizationCode, raw.as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        let mut sdk = AccessToken::new(&input);
        let client_id = match sdk.advance(Input::None) {
            Output::Authenticate {
                client,
                passdata: None,
            } => client.to_owned(),
            Output::Authenticate { .. } => return Err(Error::InvalidClient),
            _ => return Err(Error::InvalidRequest),
        };
        if client_id != self.authorization.cli_client_id && input.resource.is_none() {
            return Err(Error::InvalidTarget);
        }
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = sqlx_core::connection::Connection::begin_with(guard.connection()?, "BEGIN ISOLATION LEVEL READ COMMITTED")
                .await.map_err(storage_error)?;
            let cap = self.authorization.limits.json_bytes;
            let initial = sqlx_core::query::query(REQUEST).bind(&hash).bind(cap)
                .fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(Error::InvalidGrant)?;
            let initial = decode(&initial, cap)?;
            gate(deadline, initial.expires_at)?;
            let data = codec::parse(&initial.json)?;
            data.validate(initial.created_at, now_micros()?)?;
            let fields = data.request_fields();
            if initial.code != hash || initial.identity != data.principal.subject()
                || initial.created_at <= 0 || initial.created_at > now_micros()?
                || initial.expires_at.checked_sub(initial.created_at) != Some(self.authorization.ttl_micros)
            { return Err(Error::MalformedStored); }
            if fields.client_id != client_id || input.redirect_uri != Some(fields.redirect_uri.as_str()) {
                return Err(Error::InvalidGrant);
            }
            if let Some(resource) = input.resource.map(str::trim).filter(|r| !r.is_empty())
                && fields.resource.as_deref() != Some(resource) { return Err(Error::InvalidTarget); }
            let subject = self.digester.oidc_subject(data.principal.issuer().as_bytes(), data.principal.subject().as_bytes()).map_err(|_| Error::Credential)?;
            if data.oidc_subject != subject.as_str() { return Err(Error::MalformedStored); }
            super::oidc_tokens::lock_pair_shared(&mut tx, &data.oidc_subject, &client_id, deadline).await?;
            // Read initial DATA unlocked; shared pair precedes user → client → exact request.
            let principal = if let Some(local) = data.principal.as_local() {
                current_principal(&mut tx, &local.subject, &local.username, local.local_user_revision, cap, deadline).await?
            } else {
                if !data.principal.current_trust(self.upstream) { return Err(Error::InvalidGrant); }
                data.principal
            };
            let authorization = self.store.oidc_authorization_service(self.digester, self.authorization);
            let client = authorization.client(&mut tx, &client_id, deadline).await?;
            let locked = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!("{REQUEST} FOR UPDATE")))
                .bind(&hash).bind(cap).fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(Error::InvalidGrant)?;
            let current = decode(&locked, cap)?;
            if current != initial { return Err(Error::InvalidGrant); }
            gate(deadline, current.expires_at)?;
            self.authorization.revalidate_authorized(&fields, &client, deadline)?;
            match sdk.advance(Input::Authenticated) {
                Output::Recover { code } if code == raw => {},
                _ => return Err(Error::InvalidRequest),
            }
            let pkce = Pkce::required();
            let challenge = pkce.challenge(Some(Cow::Borrowed(&fields.code_challenge_method)), Some(Cow::Borrowed(&fields.code_challenge)))
                .map_err(|_| Error::MalformedStored)?.ok_or(Error::MalformedStored)?;
            let mut extensions = Extensions::new();
            extensions.set(&pkce, challenge);
            let grant = Grant {
                owner_id: data.oidc_subject.clone(), client_id: client_id.clone(),
                redirect_uri: fields.redirect_uri.parse().map_err(|_| Error::MalformedStored)?,
                scope: fields.scopes.join(" ").parse().map_err(|_| Error::MalformedStored)?,
                until: utc(current.expires_at)?, extensions,
            };
            match sdk.advance(Input::Recovered(Some(Box::new(grant)))) {
                Output::Extend { extensions } => pkce.verify(extensions.remove(&pkce), Some(Cow::Borrowed(verifier)))
                    .map_err(|_| Error::InvalidGrant)?,
                _ => return Err(Error::InvalidGrant),
            }
            if !matches!(sdk.advance(Input::Extended { access_extensions: Extensions::new() }), Output::Issue { .. }) {
                return Err(Error::InvalidGrant);
            }
            if !principal.current_trust(self.upstream) { return Err(Error::InvalidGrant); }
            // Every guard, including SDK S256 verification, precedes any code consumption.
            gate(deadline, current.expires_at)?;
            let issued_at = now_micros()?;
            let expires_at = issued_at.checked_add(self.policy.access_micros).ok_or(ControlError::Clock)? / 1_000_000 * 1_000_000;
            let jti = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let scope = fields.scopes.join(" ");
            let resource = fields.resource.as_deref();
            let access = Zeroizing::new(self.issuer.sign_access(BrokerAccessTokenInput {
                subject: &data.oidc_subject, client_id: &client_id, resource, scope: &scope, jti: &jti,
                issued_at: seconds(issued_at)?, expires_at: seconds(expires_at)?,
                preferred_username: Some(principal.username()), name: nonempty(principal.name().trim()), email: nonempty(principal.email().trim()),
                organization: nonempty(principal.organization().trim()), groups: principal.teams(), roles: principal.roles(),
            }, deadline).map_err(sign_error)?);
            let id = Zeroizing::new(self.issuer.sign_id(BrokerIdTokenInput {
                subject: &data.oidc_subject, client_id: &client_id, resource,
                issued_at: seconds(issued_at)?, expires_at: seconds(expires_at)?, auth_time: seconds(data.auth_time)?,
                amr: &data.amr, nonce: nonempty(&fields.nonce), access_token: &access, code: Some(raw),
                preferred_username: Some(principal.username()), name: nonempty(principal.name()), email: nonempty(principal.email()),
                organization: nonempty(principal.organization().trim()), groups: principal.teams(), roles: principal.roles(),
            }, deadline).map_err(sign_error)?);
            let offline = fields.scopes.iter().any(|s| s == "offline_access");
            let family = if offline { new_local_auth_challenge().map_err(|_| Error::Random)?.to_string() } else { String::new() };
            let refresh = if offline {
                let suffix = new_local_auth_challenge().map_err(|_| Error::Random)?;
                Some(Zeroizing::new(format!("gb_rt_{}", suffix.as_str())))
            } else { None };
            let principal_json = Zeroizing::new(serde_json::to_string(&principal).map_err(|_| Error::MalformedStored)?);
            let scopes_json = serde_json::to_string(&fields.scopes).map_err(|_| Error::MalformedStored)?;
            if i64::try_from(principal_json.len()).map_err(|_| Error::ReadLimitExceeded)? > cap
                || i64::try_from(scopes_json.len()).map_err(|_| Error::ReadLimitExceeded)? > cap { return Err(Error::ReadLimitExceeded); }
            let access_hash = self.digester.token(TokenKind::OidcStoredAccess, jti.as_bytes()).map_err(|_| Error::Credential)?.to_sql_hex();
            let token_data = TokenData { principal: &principal, oidc_subject: &data.oidc_subject, client_id: &fields.client_id,
                audience: &fields.api_audience, resource, auth_time: data.auth_time,
                principal_json: &principal_json, scopes_json: &scopes_json, family: &family, created_at: issued_at };
            insert(&mut tx, &token_data, &access_hash, &jti, "oidc_access", expires_at).await?;
            if let Some(refresh) = &refresh {
                let refresh_hash = self.digester.token(TokenKind::LocalRefresh, refresh.as_bytes()).map_err(|_| Error::Credential)?.to_sql_hex();
                let refresh_id = new_local_auth_challenge().map_err(|_| Error::Random)?;
                let refresh_expiry = issued_at.checked_add(self.policy.refresh_micros).ok_or(ControlError::Clock)?;
                insert(&mut tx, &token_data, &refresh_hash, &refresh_id, "refresh", refresh_expiry).await?;
            }
            gate(deadline, current.expires_at)?;
            let count = sqlx_core::query::query("DELETE FROM public.oidc_auth_requests WHERE request_hash=$1 AND code_hash=$2 AND identity_subject=$3 AND request_json=$4 AND created_at=$5 AND expires_at=$6 AND expires_at>$7")
                .bind(&current.hash).bind(&hash).bind(&current.identity).bind(&*current.json)
                .bind(current.created_at).bind(current.expires_at).bind(now_micros()?)
                .execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if count != 1 { return Err(Error::InvalidGrant); }
            let issued = IssuedToken { token: access.to_string(), refresh: refresh.as_ref().map(|s| s.to_string()),
                until: utc(expires_at)?, token_type: TokenType::Bearer };
            // Feed actual minted tokens through the SDK's terminal transition before COMMIT.
            if !matches!(sdk.advance(Input::Issued(issued)), Output::Ok(_)) { return Err(Error::Signing); }
            gate(deadline, current.expires_at)?;
            gate(deadline, expires_at)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            gate(deadline, current.expires_at)?;
            gate(deadline, expires_at)?;
            let result = OidcTokenExchangeResult { access, id, refresh, scope, issued_at, expires_at, grant_expires_at: None };
            result.expires_in(deadline)?;
            Ok(result)
        }).await.map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
}

fn nonempty(v: &str) -> Option<&str> {
    if v.is_empty() { None } else { Some(v) }
}
fn sign_error(e: crate::BrokerAccessIssueError) -> Error {
    match e {
        crate::BrokerAccessIssueError::Deadline => ControlError::Deadline.into(),
        _ => Error::Signing,
    }
}
fn seconds(v: i64) -> Result<u64, Error> {
    if v <= 0 {
        return Err(ControlError::Clock.into());
    }
    u64::try_from(v / 1_000_000).map_err(|_| ControlError::Clock.into())
}
fn utc(v: i64) -> Result<DateTime<Utc>, Error> {
    DateTime::from_timestamp_micros(v).ok_or_else(|| ControlError::Clock.into())
}
fn gate(original: Instant, expiry: i64) -> Result<(), Error> {
    guard_original(original)?;
    if now_micros()? >= expiry {
        return Err(Error::InvalidGrant);
    }
    Ok(())
}
#[derive(PartialEq, Eq)]
struct StoredRequest {
    hash: String,
    identity: String,
    code: String,
    created_at: i64,
    expires_at: i64,
    json: Zeroizing<String>,
}
fn get<'r, T>(row: &'r PgRow, name: &str) -> Result<T, Error>
where
    T: sqlx_core::decode::Decode<'r, Postgres> + sqlx_core::types::Type<Postgres>,
{
    row.try_get(name).map_err(|_| Error::MalformedStored)
}
fn decode(row: &PgRow, cap: i64) -> Result<StoredRequest, Error> {
    let identity_bytes: i64 = get(row, "identity_bytes")?;
    if identity_bytes < 0 {
        return Err(Error::MalformedStored);
    }
    if identity_bytes > cap {
        return Err(Error::ReadLimitExceeded);
    }
    let size: i64 = get(row, "request_bytes")?;
    if size < 0 {
        return Err(Error::MalformedStored);
    }
    if size > cap {
        return Err(Error::ReadLimitExceeded);
    }
    let hash: String = get(row, "request_hash")?;
    let code: String = get(row, "code_hash")?;
    CredentialDigest::parse_sql_hex(&hash).map_err(|_| Error::MalformedStored)?;
    CredentialDigest::parse_sql_hex(&code).map_err(|_| Error::MalformedStored)?;
    Ok(StoredRequest {
        hash,
        code,
        identity: get(row, "identity_subject")?,
        created_at: get(row, "created_at")?,
        expires_at: get(row, "expires_at")?,
        json: Zeroizing::new(get(row, "request_json")?),
    })
}
