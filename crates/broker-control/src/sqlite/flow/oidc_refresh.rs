use super::{
    SqliteControlStore,
    oidc_authorization::{completion::current_principal, current_client},
    oidc_token_exchange::{gate, nonempty, seconds, sign_error, utc},
    oidc_tokens::insert,
};
use crate::{
    BrokerAccessIssuer, BrokerAccessTokenInput, BrokerIdTokenInput, ControlError,
    OidcAuthorizationPolicy, OidcRefreshInput, OidcTokenExchangeError as Error,
    OidcTokenExchangePolicy, OidcTokenExchangeResult, UpstreamBearerVerifier,
    flow::now_micros,
    oidc_authorization::guard_original,
    oidc_refresh::requested_scopes,
    service::{
        oidc_principal::OidcPrincipal,
        oidc_refresh::{State, Stored, parse_refresh_scopes},
        oidc_tokens::TokenData,
    },
};
use broker_security::{TokenKind, new_local_auth_challenge, validate_local_auth_challenge};
use oxide_auth::{
    code_grant::refresh::{Input, Output, Refresh},
    primitives::{
        grant::{Extensions, Grant},
        issuer::{RefreshedToken, TokenType},
        scope::Scope,
    },
};
use rusqlite::{OptionalExtension, Row, params, types::ValueRef};
use std::{borrow::Cow, fmt, sync::Arc, time::Instant};
use zeroize::Zeroizing;

/// LOCAL or federated refresh with an absolute family expiry and one SQLite transaction.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore,a: std::sync::Arc<broker_control::OidcAuthorizationPolicy>,p: std::sync::Arc<broker_control::OidcTokenExchangePolicy>,i: std::sync::Arc<broker_control::BrokerAccessIssuer>) -> broker_control::SqliteOidcRefresh<'static> { store.oidc_refresh(a,p,i).unwrap() }
/// ```
pub struct SqliteOidcRefresh<'a> {
    store: &'a SqliteControlStore,
    authorization: Arc<OidcAuthorizationPolicy>,
    policy: Arc<OidcTokenExchangePolicy>,
    issuer: Arc<BrokerAccessIssuer>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
}
impl fmt::Debug for SqliteOidcRefresh<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteOidcRefresh([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn oidc_refresh(
        &self,
        authorization: Arc<OidcAuthorizationPolicy>,
        policy: Arc<OidcTokenExchangePolicy>,
        issuer: Arc<BrokerAccessIssuer>,
    ) -> Result<SqliteOidcRefresh<'_>, Error> {
        if issuer.api_audience() != authorization.api_audience {
            return Err(Error::InvalidConfiguration);
        }
        Ok(SqliteOidcRefresh {
            store: self,
            authorization,
            policy,
            issuer,
            upstream: None,
        })
    }
}
struct OwnedInput {
    values: [Option<Zeroizing<String>>; 5],
    basic: Option<(String, Zeroizing<Vec<u8>>)>,
}
impl OwnedInput {
    fn new(input: &OidcRefreshInput<'_>, cap: usize, end: Instant) -> Result<Self, Error> {
        let mut bytes = input.authorization.map_or(0, |(_, p)| p.len());
        for v in [
            input.grant_type,
            input.client_id,
            input.refresh_token,
            input.scope,
            input.resource,
        ]
        .into_iter()
        .flatten()
        .chain(input.authorization.map(|(u, _)| u))
        {
            guard_original(end)?;
            bytes = bytes.checked_add(v.len()).ok_or(Error::InvalidRequest)?;
        }
        if bytes > cap {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            values: [
                input.grant_type,
                input.client_id,
                input.refresh_token,
                input.scope,
                input.resource,
            ]
            .map(|v| v.map(|s| Zeroizing::new(s.to_owned()))),
            basic: input
                .authorization
                .map(|(u, p)| (u.to_owned(), Zeroizing::new(p.to_vec()))),
        })
    }
    fn borrowed(&self) -> OidcRefreshInput<'_> {
        OidcRefreshInput {
            grant_type: self.values[0].as_deref().map(String::as_str),
            client_id: self.values[1].as_deref().map(String::as_str),
            refresh_token: self.values[2].as_deref().map(String::as_str),
            scope: self.values[3].as_deref().map(String::as_str),
            resource: self.values[4].as_deref().map(String::as_str),
            authorization: self.basic.as_ref().map(|(u, p)| (u.as_str(), p.as_slice())),
        }
    }
}
impl SqliteOidcRefresh<'_> {
    pub fn with_upstream(mut self, verifier: Arc<UpstreamBearerVerifier>) -> Self {
        self.upstream = Some(verifier);
        self
    }
    pub async fn rotate(
        &self,
        input: OidcRefreshInput<'_>,
        original: Instant,
    ) -> Result<OidcTokenExchangeResult, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let owned = OwnedInput::new(&input, self.authorization.limits.parameter_bytes(), end)?;
        let authorization = Arc::clone(&self.authorization);
        let policy = Arc::clone(&self.policy);
        let issuer = Arc::clone(&self.issuer);
        let upstream = self.upstream.clone();
        let digester = Arc::clone(&self.store.digester);
        let result=self.store.executor.execute(end,move |owner,work| Ok((|| {
        let input=owned.borrowed();
        match input.grant_type {
            Some("refresh_token") => {}
            None => return Err(Error::InvalidRequest),
            _ => return Err(Error::UnsupportedGrantType),
        }
        let raw = input
            .refresh_token
            .filter(|v| !v.is_empty())
            .ok_or(Error::InvalidRequest)?;
        let suffix = raw.strip_prefix("gb_rt_").ok_or(Error::InvalidGrant)?;
        validate_local_auth_challenge(suffix).map_err(|_| Error::InvalidGrant)?;
        let client_id = input
            .client_id
            .filter(|v| !v.is_empty())
            .ok_or(Error::InvalidRequest)?;
        let mut sdk = Refresh::new(&input);
        match sdk.advance(Input::None) {
            Output::RecoverRefresh { token } if token == raw => {}
            Output::Unauthenticated { .. } => return Err(Error::InvalidClient),
            _ => return Err(Error::InvalidRequest),
        }
        if client_id != authorization.cli_client_id && input.resource.is_none() {
            return Err(Error::InvalidTarget);
        }
        let hash = digester
            .token(TokenKind::LocalRefresh, raw.as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        let cap=authorization.limits.json_bytes;
        let tx=owner.begin(work).map_err(ControlError::from)?;
            let (stored,token_state)=tx.query_row(SELECT,params![hash,cap],|row|Ok(decode(row,cap))).optional().map_err(|e|ControlError::from(work.sql(e)))?.ok_or(Error::InvalidGrant)??;
            let initial=&stored;
            let observed = OidcPrincipal::parse(&initial.principal_json)?;
            if initial.client_id != client_id { return Err(Error::InvalidGrant); }
            if initial.subject != observed.subject() || initial.revision != observed.revision()
                || initial.audience != authorization.api_audience { return Err(Error::MalformedStored); }
            let subject = digester.oidc_subject(observed.issuer().as_bytes(), observed.subject().as_bytes()).map_err(|_| Error::Credential)?;
            if initial.oidc_subject != subject.as_str() { return Err(Error::MalformedStored); }
            let principal = if let Some(local) = observed.as_local() {
                current_principal(&tx,work,&local.subject,&local.username,local.local_user_revision,cap,end)?
            } else {
                if !observed.current_trust(upstream.as_deref()) { return Err(Error::InvalidGrant); }
                observed
            };
            let client=current_client(&tx,work,&authorization,client_id,end)?;
            let resource = if stored.resource.is_empty() { None } else { Some(stored.resource.as_str()) };
            if !authorization.refresh_resource_allowed(resource)
                || (client_id != authorization.cli_client_id && resource.is_none()) { return Err(Error::InvalidTarget); }
            if let Some(requested) = input.resource.map(str::trim).filter(|r| !r.is_empty())
                && resource != Some(requested) { return Err(Error::InvalidTarget); }
            let scopes = requested_scopes(input.scope, &stored.scopes, end)?;
            guard_original(end)?;
            if token_state.revoked.is_some() { return Err(Error::InvalidGrant); }
            // Authenticated current authority/bindings precede the only denial with effects.
            if token_state.consumed.is_some() {
                let count=tx.execute("UPDATE local_tokens SET revoked_at=?1 WHERE family_id=?2 AND revoked_at IS NULL",params![now_micros()?,stored.family]).map_err(|e|ControlError::from(work.sql(e)))?;
                if count==0 { return Err(ControlError::Storage.into()); }
                guard_original(end)?;
                work.commit(tx).map_err(ControlError::from)?;
                guard_original(end)?;
                return Err(Error::InvalidGrant);
            }
            gate(end, stored.expires_at)?;
            let grant = Grant {
                owner_id: stored.oidc_subject.clone(), client_id: client_id.to_owned(),
                redirect_uri: client.redirects.first().ok_or(Error::MalformedStored)?.parse().map_err(|_| Error::MalformedStored)?,
                scope: stored.scopes.join(" ").parse().map_err(|_| Error::MalformedStored)?,
                until: utc(stored.expires_at)?, extensions: Extensions::new(),
            };
            match sdk.advance(Input::Recovered { scope: input.scope.map(Cow::Borrowed), grant: Some(Box::new(grant)) }) {
                Output::Unauthenticated { client, pass: None } if client == client_id => {},
                _ => return Err(Error::InvalidGrant),
            }
            match sdk.advance(Input::Authenticated { scope: input.scope.map(Cow::Borrowed) }) {
                Output::Refresh { token, grant } if token == raw && grant.scope == scopes.join(" ").parse::<Scope>().map_err(|_| Error::InvalidScope)? => {},
                _ => return Err(Error::InvalidScope),
            }
            gate(end, stored.expires_at)?;
            let issued_at = now_micros()?;
            let expires_at = issued_at.checked_add(policy.access_micros).ok_or(ControlError::Clock)? / 1_000_000 * 1_000_000;
            let jti = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let scope = scopes.join(" ");
            let access = Zeroizing::new(issuer.sign_access(BrokerAccessTokenInput {
                subject: &stored.oidc_subject, client_id, resource, scope: &scope, jti: &jti,
                issued_at: seconds(issued_at)?, expires_at: seconds(expires_at)?,
                preferred_username: Some(principal.username()), name: nonempty(principal.name().trim()), email: nonempty(principal.email().trim()),
                organization: nonempty(principal.organization().trim()), groups: principal.teams(), roles: principal.roles(),
            }, end).map_err(sign_error)?);
            let amr = [principal.auth_method().to_owned()];
            let id = Zeroizing::new(issuer.sign_id(BrokerIdTokenInput {
                subject: &stored.oidc_subject, client_id, resource, issued_at: seconds(issued_at)?, expires_at: seconds(expires_at)?,
                auth_time: seconds(stored.auth_time)?, amr: &amr, nonce: None, access_token: &access, code: None,
                preferred_username: Some(principal.username()), name: nonempty(principal.name()), email: nonempty(principal.email()),
                organization: nonempty(principal.organization().trim()), groups: principal.teams(), roles: principal.roles(),
            }, end).map_err(sign_error)?);
            let suffix = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let refresh = Zeroizing::new(format!("gb_rt_{}", suffix.as_str()));
            let refresh_id = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let access_hash = digester.token(TokenKind::OidcStoredAccess, jti.as_bytes()).map_err(|_| Error::Credential)?.to_sql_hex();
            let refresh_hash = digester.token(TokenKind::LocalRefresh, refresh.as_bytes()).map_err(|_| Error::Credential)?.to_sql_hex();
            let principal_json = Zeroizing::new(serde_json::to_string(&principal).map_err(|_| Error::MalformedStored)?);
            let scopes_json = serde_json::to_string(&scopes).map_err(|_| Error::MalformedStored)?;
            if i64::try_from(principal_json.len()).map_err(|_| Error::ReadLimitExceeded)? > cap
                || i64::try_from(scopes_json.len()).map_err(|_| Error::ReadLimitExceeded)? > cap { return Err(Error::ReadLimitExceeded); }
            gate(end, stored.expires_at)?;
            let changed=tx.execute("UPDATE local_tokens SET consumed_at=?1,last_used_at=?1 WHERE token_hash=?2 AND token_kind='refresh' AND subject=?3 AND client_id=?4 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>?1",params![issued_at,hash,principal.subject(),client_id]).map_err(|e|ControlError::from(work.sql(e)))?;
            if changed != 1 { return Err(ControlError::Storage.into()); }
            let data = TokenData { principal: &principal, oidc_subject: &stored.oidc_subject, client_id, audience: &stored.audience,
                resource, principal_json: &principal_json, scopes_json: &scopes_json, family: &stored.family,
                auth_time: stored.auth_time, created_at: issued_at };
            insert(&tx,work, &data, &access_hash, &jti, "oidc_access", expires_at)?;
            insert(&tx,work, &data, &refresh_hash, &refresh_id, "refresh", stored.expires_at)?;
            if !matches!(sdk.advance(Input::Refreshed(RefreshedToken { token: access.to_string(), refresh: Some(refresh.to_string()),
                until: utc(expires_at)?, token_type: TokenType::Bearer })), Output::Ok(_)) { return Err(Error::Signing); }
            gate(end, stored.expires_at)?;
            gate(end, expires_at)?;
            work.commit(tx).map_err(ControlError::from)?;
            Ok(OidcTokenExchangeResult { access,id,refresh:Some(refresh),scope,issued_at,expires_at,grant_expires_at:Some(stored.expires_at) })
        })())).await.map_err(ControlError::from)??;
        gate(end, result.grant_expires_at.ok_or(Error::MalformedStored)?)?;
        gate(end, result.expires_at)?;
        result.expires_in(end)?;
        Ok(result)
    }
}
fn decode(row: &Row<'_>, cap: i64) -> Result<(Stored, State), Error> {
    use super::oidc_authorization::{number, text};
    let bound = |size, name| -> Result<String, Error> {
        let size = number(row, size)?;
        if size < 0 || size > cap {
            return Err(Error::ReadLimitExceeded);
        }
        Ok(text(row, name)?.to_owned())
    };
    let principal_json = Zeroizing::new(bound("principal_bytes", "principal_json")?);
    let scopes = parse_refresh_scopes(&bound("scope_bytes", "scopes_json")?)?;
    let stored = Stored {
        token_id: text(row, "token_id")?.into(),
        subject: bound("subject_bytes", "subject")?,
        oidc_subject: text(row, "oidc_subject")?.into(),
        client_id: text(row, "client_id")?.into(),
        audience: text(row, "audience")?.into(),
        resource: bound("resource_bytes", "resource")?,
        principal_json,
        scopes,
        revision: number(row, "local_user_revision")?,
        family: text(row, "family_id")?.into(),
        auth_time: number(row, "auth_time")?,
        created_at: number(row, "created_at")?,
        expires_at: number(row, "expires_at")?,
    };
    stored.validate()?;
    let now = now_micros()?;
    let stamp = |name| -> Result<Option<i64>, Error> {
        match row.get_ref(name).map_err(|_| Error::MalformedStored)? {
            ValueRef::Null => Ok(None),
            ValueRef::Integer(v) => Ok(Some(v)),
            _ => Err(Error::MalformedStored),
        }
    };
    let state = State {
        consumed: stamp("consumed_at")?,
        revoked: stamp("revoked_at")?,
    };
    state.validate(stored.created_at, now, stamp("last_used_at")?)?;
    Ok((stored, state))
}
const SELECT: &str = r#"SELECT
 CASE WHEN typeof(token_id)='text' AND length(CAST(token_id AS BLOB))<=43 THEN token_id END AS token_id,
 CASE WHEN typeof(oidc_subject)='text' AND length(CAST(oidc_subject AS BLOB))<=43 THEN oidc_subject END AS oidc_subject,
 CASE WHEN typeof(client_id)='text' AND length(CAST(client_id AS BLOB))<=128 THEN client_id END AS client_id,
 CASE WHEN typeof(audience)='text' AND length(CAST(audience AS BLOB))<=128 THEN audience END AS audience,
 CASE WHEN typeof(resource)='text' THEN length(CAST(resource AS BLOB)) END AS resource_bytes,
 CASE WHEN typeof(resource)='text' AND length(CAST(resource AS BLOB))<=?2 THEN resource END AS resource,
 CASE WHEN typeof(subject)='text' THEN length(CAST(subject AS BLOB)) END AS subject_bytes,
 CASE WHEN typeof(subject)='text' AND length(CAST(subject AS BLOB))<=?2 THEN subject END AS subject,
 CASE WHEN typeof(family_id)='text' AND length(CAST(family_id AS BLOB))<=43 THEN family_id END AS family_id,
 local_user_revision,auth_time,expires_at,created_at,consumed_at,revoked_at,last_used_at,
 CASE WHEN typeof(principal_json)='text' THEN length(CAST(principal_json AS BLOB)) END AS principal_bytes,
 CASE WHEN typeof(principal_json)='text' AND length(CAST(principal_json AS BLOB))<=?2 THEN principal_json END AS principal_json,
 CASE WHEN typeof(scopes_json)='text' THEN length(CAST(scopes_json AS BLOB)) END AS scope_bytes,
 CASE WHEN typeof(scopes_json)='text' AND length(CAST(scopes_json AS BLOB))<=?2 THEN scopes_json END AS scopes_json
 FROM local_tokens WHERE token_hash=?1 AND token_kind='refresh'"#;
