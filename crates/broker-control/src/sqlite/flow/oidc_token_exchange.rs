use super::{
    SqliteControlStore,
    oidc_authorization::{completion::current_principal, current_client},
    oidc_tokens::insert,
};
use crate::{
    BrokerAccessIssuer, BrokerAccessTokenInput, BrokerIdTokenInput, ControlError,
    OidcAuthorizationPolicy, OidcTokenExchangeError as Error, OidcTokenExchangeInput,
    OidcTokenExchangePolicy, OidcTokenExchangeResult, UpstreamBearerVerifier,
    flow::now_micros,
    oidc_authorization::guard_original,
    service::{oidc_token_exchange::codec, oidc_tokens::TokenData},
};
use broker_security::{
    CredentialDigest, TokenKind, new_local_auth_challenge, validate_local_auth_challenge,
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
use rusqlite::{OptionalExtension, Row, params};
use std::{borrow::Cow, fmt, sync::Arc, time::Instant};
use zeroize::Zeroizing;

/// Borrowed SQLite exchange retaining the actual issuer and configured trust owner.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore,a: std::sync::Arc<broker_control::OidcAuthorizationPolicy>,p: std::sync::Arc<broker_control::OidcTokenExchangePolicy>,i: std::sync::Arc<broker_control::BrokerAccessIssuer>) -> broker_control::SqliteOidcTokenExchange<'static> { store.oidc_token_exchange(a,p,i).unwrap() }
/// ```
pub struct SqliteOidcTokenExchange<'a> {
    store: &'a SqliteControlStore,
    authorization: Arc<OidcAuthorizationPolicy>,
    policy: Arc<OidcTokenExchangePolicy>,
    issuer: Arc<BrokerAccessIssuer>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
}
impl fmt::Debug for SqliteOidcTokenExchange<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteOidcTokenExchange([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn oidc_token_exchange(
        &self,
        authorization: Arc<OidcAuthorizationPolicy>,
        policy: Arc<OidcTokenExchangePolicy>,
        issuer: Arc<BrokerAccessIssuer>,
    ) -> Result<SqliteOidcTokenExchange<'_>, Error> {
        if issuer.api_audience() != authorization.api_audience {
            return Err(Error::InvalidConfiguration);
        }
        Ok(SqliteOidcTokenExchange {
            store: self,
            authorization,
            policy,
            issuer,
            upstream: None,
        })
    }
}
struct OwnedInput {
    values: [Option<Zeroizing<String>>; 6],
    basic: Option<(String, Zeroizing<Vec<u8>>)>,
}
impl OwnedInput {
    fn new(input: &OidcTokenExchangeInput<'_>, cap: usize, end: Instant) -> Result<Self, Error> {
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
            guard_original(end)?;
            total = total
                .checked_add(value.len())
                .ok_or(Error::InvalidRequest)?;
        }
        total = total
            .checked_add(input.authorization.map_or(0, |(_, p)| p.len()))
            .ok_or(Error::InvalidRequest)?;
        if total > cap {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            values: [
                input.grant_type,
                input.client_id,
                input.code,
                input.redirect_uri,
                input.code_verifier,
                input.resource,
            ]
            .map(|v| v.map(|s| Zeroizing::new(s.to_owned()))),
            basic: input
                .authorization
                .map(|(u, p)| (u.to_owned(), Zeroizing::new(p.to_vec()))),
        })
    }
    fn borrowed(&self) -> OidcTokenExchangeInput<'_> {
        OidcTokenExchangeInput {
            grant_type: self.values[0].as_deref().map(String::as_str),
            client_id: self.values[1].as_deref().map(String::as_str),
            code: self.values[2].as_deref().map(String::as_str),
            redirect_uri: self.values[3].as_deref().map(String::as_str),
            code_verifier: self.values[4].as_deref().map(String::as_str),
            resource: self.values[5].as_deref().map(String::as_str),
            authorization: self.basic.as_ref().map(|(u, p)| (u.as_str(), p.as_slice())),
        }
    }
}
impl SqliteOidcTokenExchange<'_> {
    pub fn with_upstream(mut self, verifier: Arc<UpstreamBearerVerifier>) -> Self {
        self.upstream = Some(verifier);
        self
    }
    pub async fn exchange(
        &self,
        input: OidcTokenExchangeInput<'_>,
        original: Instant,
    ) -> Result<OidcTokenExchangeResult, Error> {
        let deadline = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let owned = OwnedInput::new(
            &input,
            self.authorization.limits.parameter_bytes(),
            deadline,
        )?;
        let authorization = Arc::clone(&self.authorization);
        let policy = Arc::clone(&self.policy);
        let issuer = Arc::clone(&self.issuer);
        let upstream = self.upstream.clone();
        let digester = Arc::clone(&self.store.digester);
        let (result,code_expiry)=self.store.executor.execute(deadline,move |state,work| Ok((|| {
        let input=owned.borrowed();
        match input.grant_type {
            Some("authorization_code") => {}
            None => return Err(Error::InvalidRequest),
            _ => return Err(Error::UnsupportedGrantType),
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
        let hash = digester
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
        if client_id != authorization.cli_client_id && input.resource.is_none() {
            return Err(Error::InvalidTarget);
        }
        let tx=state.begin(work).map_err(ControlError::from)?;
            let cap = authorization.limits.json_bytes;
            let initial = tx.query_row(REQUEST,params![hash,cap],|row| Ok(decode(row,cap)))
                .optional().map_err(|e| ControlError::from(work.sql(e)))?.ok_or(Error::InvalidGrant)??;
            gate(deadline, initial.expires_at)?;
            let data = codec::parse(&initial.json)?;
            data.validate(initial.created_at, now_micros()?)?;
            let fields = data.request_fields();
            if initial.code != hash || initial.identity != data.principal.subject()
                || initial.created_at <= 0 || initial.created_at > now_micros()?
                || initial.expires_at.checked_sub(initial.created_at) != Some(authorization.ttl_micros)
            { return Err(Error::MalformedStored); }
            if fields.client_id != client_id || input.redirect_uri != Some(fields.redirect_uri.as_str()) {
                return Err(Error::InvalidGrant);
            }
            if let Some(resource) = input.resource.map(str::trim).filter(|r| !r.is_empty())
                && fields.resource.as_deref() != Some(resource) { return Err(Error::InvalidTarget); }
            let subject = digester.oidc_subject(data.principal.issuer().as_bytes(), data.principal.subject().as_bytes()).map_err(|_| Error::Credential)?;
            if data.oidc_subject != subject.as_str() { return Err(Error::MalformedStored); }
            let principal = if let Some(local) = data.principal.as_local() {
                current_principal(&tx,work,&local.subject,&local.username,local.local_user_revision,cap,deadline)?
            } else {
                if !data.principal.current_trust(upstream.as_deref()) { return Err(Error::InvalidGrant); }
                data.principal
            };
            let client = current_client(&tx,work,&authorization,&client_id,deadline)?;
            let current = initial;
            gate(deadline,current.expires_at)?;
            authorization.revalidate_authorized(&fields, &client, deadline)?;
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
            // Every guard, including SDK S256 verification, precedes any code consumption.
            gate(deadline, current.expires_at)?;
            let issued_at = now_micros()?;
            let expires_at = issued_at.checked_add(policy.access_micros).ok_or(ControlError::Clock)? / 1_000_000 * 1_000_000;
            let jti = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let scope = fields.scopes.join(" ");
            let resource = fields.resource.as_deref();
            let access = Zeroizing::new(issuer.sign_access(BrokerAccessTokenInput {
                subject: &data.oidc_subject, client_id: &client_id, resource, scope: &scope, jti: &jti,
                issued_at: seconds(issued_at)?, expires_at: seconds(expires_at)?,
                preferred_username: Some(principal.username()), name: nonempty(principal.name().trim()), email: nonempty(principal.email().trim()),
                organization: nonempty(principal.organization().trim()), groups: principal.teams(), roles: principal.roles(),
            }, deadline).map_err(sign_error)?);
            let id = Zeroizing::new(issuer.sign_id(BrokerIdTokenInput {
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
            let access_hash = digester.token(TokenKind::OidcStoredAccess, jti.as_bytes()).map_err(|_| Error::Credential)?.to_sql_hex();
            let token_data = TokenData { principal: &principal, oidc_subject: &data.oidc_subject, client_id: &fields.client_id,
                audience: &fields.api_audience, resource, auth_time: data.auth_time,
                principal_json: &principal_json, scopes_json: &scopes_json, family: &family, created_at: issued_at };
            insert(&tx, work, &token_data, &access_hash, &jti, "oidc_access", expires_at)?;
            if let Some(refresh) = &refresh {
                let refresh_hash = digester.token(TokenKind::LocalRefresh, refresh.as_bytes()).map_err(|_| Error::Credential)?.to_sql_hex();
                let refresh_id = new_local_auth_challenge().map_err(|_| Error::Random)?;
                let refresh_expiry = issued_at.checked_add(policy.refresh_micros).ok_or(ControlError::Clock)?;
                insert(&tx, work, &token_data, &refresh_hash, &refresh_id, "refresh", refresh_expiry)?;
            }
            gate(deadline, current.expires_at)?;
            let count = tx.execute("DELETE FROM oidc_auth_requests WHERE request_hash=?1 AND code_hash=?2 AND identity_subject=?3 AND request_json=?4 AND created_at=?5 AND expires_at=?6 AND expires_at>?7",
                params![current.hash,hash,current.identity,&*current.json,current.created_at,current.expires_at,now_micros()?]).map_err(|e| ControlError::from(work.sql(e)))?;
            if count != 1 { return Err(Error::InvalidGrant); }
            let issued = IssuedToken { token: access.to_string(), refresh: refresh.as_ref().map(|s| s.to_string()),
                until: utc(expires_at)?, token_type: TokenType::Bearer };
            // Feed actual minted tokens through the SDK's terminal transition before COMMIT.
            if !matches!(sdk.advance(Input::Issued(issued)), Output::Ok(_)) { return Err(Error::Signing); }
            gate(deadline, current.expires_at)?;
            gate(deadline, expires_at)?;
            work.commit(tx).map_err(ControlError::from)?;
            let result=OidcTokenExchangeResult { access,id,refresh,scope,issued_at,expires_at,grant_expires_at:None };
            Ok((result,current.expires_at))
        })())).await.map_err(ControlError::from)??;
        gate(deadline, code_expiry)?;
        gate(deadline, result.expires_at)?;
        result.expires_in(deadline)?;
        Ok(result)
    }
}
pub(super) fn nonempty(v: &str) -> Option<&str> {
    if v.is_empty() { None } else { Some(v) }
}
pub(super) fn sign_error(e: crate::BrokerAccessIssueError) -> Error {
    match e {
        crate::BrokerAccessIssueError::Deadline => ControlError::Deadline.into(),
        _ => Error::Signing,
    }
}
pub(super) fn seconds(v: i64) -> Result<u64, Error> {
    if v <= 0 {
        return Err(ControlError::Clock.into());
    }
    u64::try_from(v / 1_000_000).map_err(|_| ControlError::Clock.into())
}
pub(super) fn utc(v: i64) -> Result<DateTime<Utc>, Error> {
    DateTime::from_timestamp_micros(v).ok_or_else(|| ControlError::Clock.into())
}
pub(super) fn gate(original: Instant, expiry: i64) -> Result<(), Error> {
    guard_original(original)?;
    if now_micros()? >= expiry {
        return Err(Error::InvalidGrant);
    }
    Ok(())
}
struct StoredRequest {
    hash: String,
    identity: String,
    code: String,
    created_at: i64,
    expires_at: i64,
    json: Zeroizing<String>,
}
fn decode(row: &Row<'_>, cap: i64) -> Result<StoredRequest, Error> {
    use super::oidc_authorization::{bounded, number, text};
    let identity = bounded(row, "identity_bytes", "identity_subject", cap)?.to_owned();
    let json = Zeroizing::new(bounded(row, "request_bytes", "request_json", cap)?.to_owned());
    let hash = text(row, "request_hash")?.to_owned();
    let code = text(row, "code_hash")?.to_owned();
    CredentialDigest::parse_sql_hex(&hash).map_err(|_| Error::MalformedStored)?;
    CredentialDigest::parse_sql_hex(&code).map_err(|_| Error::MalformedStored)?;
    Ok(StoredRequest {
        hash,
        identity,
        code,
        created_at: number(row, "created_at")?,
        expires_at: number(row, "expires_at")?,
        json,
    })
}
const REQUEST: &str = r#"SELECT
 CASE WHEN typeof(request_hash)='text' AND length(CAST(request_hash AS BLOB))<=64 THEN request_hash END AS request_hash,
 CASE WHEN typeof(code_hash)='text' AND length(CAST(code_hash AS BLOB))<=64 THEN code_hash END AS code_hash,
 created_at,expires_at,
 CASE WHEN typeof(identity_subject)='text' THEN length(CAST(identity_subject AS BLOB)) END AS identity_bytes,
 CASE WHEN typeof(identity_subject)='text' AND length(CAST(identity_subject AS BLOB))<=?2 THEN identity_subject END AS identity_subject,
 CASE WHEN typeof(request_json)='text' THEN length(CAST(request_json AS BLOB)) END AS request_bytes,
 CASE WHEN typeof(request_json)='text' AND length(CAST(request_json AS BLOB))<=?2 THEN request_json END AS request_json
 FROM oidc_auth_requests WHERE code_hash=?1"#;
