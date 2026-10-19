use super::oidc_authorization::completion::current_principal;
use super::oidc_principal::OidcPrincipal;
use super::oidc_tokens::{TokenData, insert};
use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    BrokerAccessIssuer, BrokerAccessTokenInput, BrokerIdTokenInput, ControlError,
    OidcAuthorizationPolicy, OidcRefreshInput, OidcTokenExchangeError as Error,
    OidcTokenExchangePolicy, OidcTokenExchangeResult, UpstreamBearerVerifier, flow::now_micros,
    oidc_authorization::guard_original, oidc_refresh::requested_scopes,
};
use broker_security::{TokenKind, new_local_auth_challenge, validate_local_auth_challenge};
use chrono::{DateTime, Utc};
use oxide_auth::{
    code_grant::refresh::{Input, Output, Refresh},
    primitives::{
        grant::{Extensions, Grant},
        issuer::{RefreshedToken, TokenType},
        scope::Scope,
    },
};
use sqlx_core::row::Row;
use sqlx_postgres::PgRow;
use std::{
    borrow::Cow,
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

const SELECT: &str = r#"SELECT token_id,oidc_subject,client_id,audience,resource,
 OCTET_LENGTH(subject)::bigint AS subject_bytes,
 CASE WHEN OCTET_LENGTH(subject)<=$2 THEN subject END AS subject,
 local_user_revision,family_id,auth_time,expires_at,created_at,consumed_at,revoked_at,last_used_at,
 OCTET_LENGTH(principal_json)::bigint AS principal_bytes,
 CASE WHEN OCTET_LENGTH(principal_json)<=$2 THEN principal_json END AS principal_json,
 OCTET_LENGTH(scopes_json)::bigint AS scope_bytes,
 CASE WHEN OCTET_LENGTH(scopes_json)<=$2 THEN scopes_json END AS scopes_json
 FROM public.local_tokens WHERE token_hash=$1 AND token_kind='refresh'"#;
pub struct PostgresOidcRefresh<'a> {
    store: &'a PostgresControlStore,
    authorization: &'a OidcAuthorizationPolicy,
    policy: &'a OidcTokenExchangePolicy,
    issuer: &'a BrokerAccessIssuer,
    upstream: Option<&'a UpstreamBearerVerifier>,
}
impl fmt::Debug for PostgresOidcRefresh<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresOidcRefresh([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn oidc_refresh<'a>(
        &'a self,
        authorization: &'a OidcAuthorizationPolicy,
        policy: &'a OidcTokenExchangePolicy,
        issuer: &'a BrokerAccessIssuer,
    ) -> Result<PostgresOidcRefresh<'a>, Error> {
        if issuer.api_audience() != authorization.api_audience {
            return Err(Error::InvalidConfiguration);
        }
        Ok(PostgresOidcRefresh {
            store: self,
            authorization,
            policy,
            issuer,
            upstream: None,
        })
    }
}
impl<'a> PostgresOidcRefresh<'a> {
    /// Use the current common issuer trust for federated refresh grants.
    pub fn with_upstream(mut self, verifier: &'a UpstreamBearerVerifier) -> Self {
        self.upstream = Some(verifier);
        self
    }
    pub async fn rotate(
        &self,
        input: OidcRefreshInput<'_>,
        original: Instant,
    ) -> Result<OidcTokenExchangeResult, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        match input.grant_type {
            Some("refresh_token") => {}
            None => return Err(Error::InvalidRequest),
            _ => return Err(Error::UnsupportedGrantType),
        }
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
        if bytes > self.authorization.limits.parameter_bytes() {
            return Err(Error::InvalidRequest);
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
        if client_id != self.authorization.cli_client_id && input.resource.is_none() {
            return Err(Error::InvalidTarget);
        }
        let hash = self
            .store
            .digester
            .token(TokenKind::LocalRefresh, raw.as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        let cap = self.authorization.limits.json_bytes;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = sqlx_core::connection::Connection::begin_with(guard.connection()?, "BEGIN ISOLATION LEVEL READ COMMITTED").await.map_err(storage_error)?;
            let row = sqlx_core::query::query(SELECT).bind(&hash).bind(cap).fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(Error::InvalidGrant)?;
            let (initial, _) = decode(&row, cap)?;
            let observed = OidcPrincipal::parse(&initial.principal_json)?;
            if initial.client_id != client_id { return Err(Error::InvalidGrant); }
            if initial.subject != observed.subject() || initial.revision != observed.revision()
                || initial.audience != self.authorization.api_audience { return Err(Error::MalformedStored); }
            let subject = self.store.digester.oidc_subject(observed.issuer().as_bytes(), observed.subject().as_bytes()).map_err(|_| Error::Credential)?;
            if initial.oidc_subject != subject.as_str() { return Err(Error::MalformedStored); }
            super::oidc_tokens::lock_pair_shared(&mut tx, &initial.oidc_subject, client_id, end).await?;
            let principal = if let Some(local) = observed.as_local() {
                // Preserve the strong LOCAL lock; federated grants have no LOCAL row.
                let locked_user = sqlx_core::query::query("SELECT subject FROM public.local_users WHERE subject=$1 FOR UPDATE")
                    .bind(&local.subject).fetch_optional(&mut *tx).await.map_err(storage_error)?;
                if locked_user.is_none() { return Err(Error::InvalidGrant); }
                current_principal(&mut tx, &local.subject, &local.username, local.local_user_revision, cap, end).await?
            } else {
                if !observed.current_trust(self.upstream) { return Err(Error::InvalidGrant); }
                // Every generation shares this transaction lock, including ancestor reuse.
                // Hash collisions only serialize unrelated families; no authority is derived.
                sqlx_core::query::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4750301))")
                    .bind(&initial.family).execute(&mut *tx).await.map_err(storage_error)?;
                observed
            };
            let service = self.store.oidc_authorization_service(&self.store.digester, self.authorization);
            let client = service.client(&mut tx, client_id, end).await?;
            let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!("{SELECT} FOR UPDATE")))
                .bind(&hash).bind(cap).fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(Error::InvalidGrant)?;
            let (stored, state) = decode(&row, cap)?;
            if stored != initial { return Err(Error::InvalidGrant); }
            let resource = if stored.resource.is_empty() { None } else { Some(stored.resource.as_str()) };
            if !self.authorization.refresh_resource_allowed(resource)
                || (client_id != self.authorization.cli_client_id && resource.is_none()) { return Err(Error::InvalidTarget); }
            if let Some(requested) = input.resource.map(str::trim).filter(|r| !r.is_empty())
                && resource != Some(requested) { return Err(Error::InvalidTarget); }
            let scopes = requested_scopes(input.scope, &stored.scopes, end)?;
            guard_original(end)?;
            if state.revoked.is_some() { return Err(Error::InvalidGrant); }
            if !principal.current_trust(self.upstream) { return Err(Error::InvalidGrant); }
            // Authenticated current authority/bindings precede the only denial with effects.
            if state.consumed.is_some() {
                let count = sqlx_core::query::query("UPDATE public.local_tokens SET revoked_at=$1 WHERE family_id=$2 AND revoked_at IS NULL")
                    .bind(now_micros()?).bind(&stored.family).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
                if count == 0 { return Err(ControlError::Storage.into()); }
                guard_original(end)?;
                commit_started.store(true, Ordering::Relaxed);
                tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
                guard.confirmed();
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
            let expires_at = issued_at.checked_add(self.policy.access_micros).ok_or(ControlError::Clock)? / 1_000_000 * 1_000_000;
            let jti = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let scope = scopes.join(" ");
            let access = Zeroizing::new(self.issuer.sign_access(BrokerAccessTokenInput {
                subject: &stored.oidc_subject, client_id, resource, scope: &scope, jti: &jti,
                issued_at: seconds(issued_at)?, expires_at: seconds(expires_at)?,
                preferred_username: Some(principal.username()), name: nonempty(principal.name().trim()), email: nonempty(principal.email().trim()),
                organization: nonempty(principal.organization().trim()), groups: principal.teams(), roles: principal.roles(),
            }, end).map_err(sign_error)?);
            let amr = [principal.auth_method().to_owned()];
            let id = Zeroizing::new(self.issuer.sign_id(BrokerIdTokenInput {
                subject: &stored.oidc_subject, client_id, resource, issued_at: seconds(issued_at)?, expires_at: seconds(expires_at)?,
                auth_time: seconds(stored.auth_time)?, amr: &amr, nonce: None, access_token: &access, code: None,
                preferred_username: Some(principal.username()), name: nonempty(principal.name()), email: nonempty(principal.email()),
                organization: nonempty(principal.organization().trim()), groups: principal.teams(), roles: principal.roles(),
            }, end).map_err(sign_error)?);
            let suffix = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let refresh = Zeroizing::new(format!("gb_rt_{}", suffix.as_str()));
            let refresh_id = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let access_hash = self.store.digester.token(TokenKind::OidcStoredAccess, jti.as_bytes()).map_err(|_| Error::Credential)?.to_sql_hex();
            let refresh_hash = self.store.digester.token(TokenKind::LocalRefresh, refresh.as_bytes()).map_err(|_| Error::Credential)?.to_sql_hex();
            let principal_json = Zeroizing::new(serde_json::to_string(&principal).map_err(|_| Error::MalformedStored)?);
            let scopes_json = serde_json::to_string(&scopes).map_err(|_| Error::MalformedStored)?;
            if i64::try_from(principal_json.len()).map_err(|_| Error::ReadLimitExceeded)? > cap
                || i64::try_from(scopes_json.len()).map_err(|_| Error::ReadLimitExceeded)? > cap { return Err(Error::ReadLimitExceeded); }
            gate(end, stored.expires_at)?;
            let changed = sqlx_core::query::query("UPDATE public.local_tokens SET consumed_at=$1,last_used_at=$1 WHERE token_hash=$2 AND token_kind='refresh' AND subject=$3 AND client_id=$4 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>$1")
                .bind(issued_at).bind(&hash).bind(principal.subject()).bind(client_id).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if changed != 1 { return Err(ControlError::Storage.into()); }
            let data = TokenData { principal: &principal, oidc_subject: &stored.oidc_subject, client_id, audience: &stored.audience,
                resource, principal_json: &principal_json, scopes_json: &scopes_json, family: &stored.family,
                auth_time: stored.auth_time, created_at: issued_at };
            insert(&mut tx, &data, &access_hash, &jti, "oidc_access", expires_at).await?;
            insert(&mut tx, &data, &refresh_hash, &refresh_id, "refresh", stored.expires_at).await?;
            if !matches!(sdk.advance(Input::Refreshed(RefreshedToken { token: access.to_string(), refresh: Some(refresh.to_string()),
                until: utc(expires_at)?, token_type: TokenType::Bearer })), Output::Ok(_)) { return Err(Error::Signing); }
            gate(end, stored.expires_at)?;
            gate(end, expires_at)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            gate(end, stored.expires_at)?;
            gate(end, expires_at)?;
            let result = OidcTokenExchangeResult { access, id, refresh: Some(refresh), scope, issued_at, expires_at, grant_expires_at: Some(stored.expires_at) };
            result.expires_in(end)?;
            Ok(result)
        }).await.map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
}
#[derive(PartialEq, Eq)]
pub(crate) struct Stored {
    pub(crate) token_id: String,
    pub(crate) subject: String,
    pub(crate) oidc_subject: String,
    pub(crate) client_id: String,
    pub(crate) audience: String,
    pub(crate) resource: String,
    pub(crate) principal_json: Zeroizing<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) revision: i64,
    pub(crate) family: String,
    pub(crate) auth_time: i64,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
}
pub(crate) struct State {
    pub(crate) consumed: Option<i64>,
    pub(crate) revoked: Option<i64>,
}
fn decode(row: &PgRow, cap: i64) -> Result<(Stored, State), Error> {
    let text =
        |name| -> Result<String, Error> { row.try_get(name).map_err(|_| Error::MalformedStored) };
    let number =
        |name| -> Result<i64, Error> { row.try_get(name).map_err(|_| Error::MalformedStored) };
    let bound = |size, name| -> Result<String, Error> {
        if number(size)? > cap || number(size)? < 0 {
            return Err(Error::ReadLimitExceeded);
        }
        text(name)
    };
    let principal_json = Zeroizing::new(bound("principal_bytes", "principal_json")?);
    let scopes = parse_refresh_scopes(&bound("scope_bytes", "scopes_json")?)?;
    let stored = Stored {
        token_id: text("token_id")?,
        subject: bound("subject_bytes", "subject")?,
        oidc_subject: text("oidc_subject")?,
        client_id: text("client_id")?,
        audience: text("audience")?,
        resource: text("resource")?,
        principal_json,
        scopes,
        revision: number("local_user_revision")?,
        family: text("family_id")?,
        auth_time: number("auth_time")?,
        created_at: number("created_at")?,
        expires_at: number("expires_at")?,
    };
    stored.validate()?;
    let now = now_micros()?;
    let stamp = |name| -> Result<Option<i64>, Error> {
        row.try_get(name).map_err(|_| Error::MalformedStored)
    };
    let state = State {
        consumed: stamp("consumed_at")?,
        revoked: stamp("revoked_at")?,
    };
    state.validate(stored.created_at, now, stamp("last_used_at")?)?;
    Ok((stored, state))
}
// Shared native refresh data validation; SQL projection remains backend-specific.
pub(crate) fn parse_refresh_scopes(raw: &str) -> Result<Vec<String>, Error> {
    let scopes: Vec<String> = serde_json::from_str(raw).map_err(|_| Error::MalformedStored)?;
    if scopes.is_empty() {
        return Err(Error::MalformedStored);
    }
    for (i, s) in scopes.iter().enumerate() {
        if !matches!(
            s.as_str(),
            "openid" | "profile" | "email" | "phone" | "address" | "offline_access"
        ) || scopes[..i].contains(s)
        {
            return Err(Error::MalformedStored);
        }
    }
    Ok(scopes)
}
impl Stored {
    // Keep the first live clock sample at the original PG decoder step.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        for id in [&self.token_id, &self.oidc_subject, &self.family] {
            validate_local_auth_challenge(id).map_err(|_| Error::MalformedStored)?;
        }
        if self.created_at <= 0
            || self.created_at > now_micros()?
            || self.expires_at <= self.created_at
            || self.auth_time <= 0
            || self.auth_time > self.created_at
            || self.revision < 0
            || crate::oidc_authorization::OidcClientId::parse(&self.client_id).is_none()
            || !crate::identity::safe_identity_segment(&self.audience, 128)
            || (!self.resource.is_empty() && self.resource.trim() != self.resource)
        {
            return Err(Error::MalformedStored);
        }
        Ok(())
    }
}
impl State {
    pub(crate) fn validate(
        &self,
        created_at: i64,
        now: i64,
        last_used: Option<i64>,
    ) -> Result<(), Error> {
        for value in [self.consumed, self.revoked, last_used] {
            if value.is_some_and(|v| v < created_at || v > now) {
                return Err(Error::MalformedStored);
            }
        }
        Ok(())
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
fn gate(end: Instant, expiry: i64) -> Result<(), Error> {
    guard_original(end)?;
    if now_micros()? >= expiry {
        return Err(Error::InvalidGrant);
    }
    Ok(())
}
