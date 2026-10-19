//! Configured OIDC resource-token trust; decoded claims only locate one authority.
#[path = "upstream_login.rs"]
pub(crate) mod browser;
use crate::{
    AdminBrokerSessionError as Error, BrokerAccessError, ControlError, SessionProfile,
    broker_access::UniqueRoot, identity::safe_identity_segment,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
pub use browser::{
    IssuedUpstreamAuthorization, UpstreamBrowserClaimsSource, UpstreamBrowserClient,
    UpstreamBrowserOption, UpstreamLoginCallback, UpstreamLoginError, UpstreamLoginFailure,
    VerifiedUpstreamLogin,
};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode,
    jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use openidconnect::{IssuerUrl, core::CoreProviderMetadata, http};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_path::JsonPath;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    num::NonZeroUsize,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use url::{Host, Url};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamClaimSelectors {
    pub subject: String,
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub organization: Option<String>,
    pub teams: Option<String>,
    pub roles: Option<String>,
    pub scope: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamClaimPredicate {
    pub selector: String,
    pub value: String,
}
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpstreamAccessPolicy {
    ResourceAudience {
        id_token_audiences: Vec<String>,
    },
    SignedMarker {
        typ: Option<String>,
        claim: Option<UpstreamClaimPredicate>,
    },
}
#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamReadLimits {
    pub token_bytes: NonZeroUsize,
    pub response_bytes: NonZeroUsize,
    pub keys: NonZeroUsize,
    pub selector_bytes: NonZeroUsize,
    pub claim_string_bytes: NonZeroUsize,
    pub profile_json_bytes: NonZeroUsize,
    pub teams: NonZeroUsize,
}
pub struct UpstreamProviderConfig {
    pub id: String,
    pub issuer: String,
    pub audiences: Vec<String>,
    pub required_scopes: Vec<String>,
    pub allowed_algorithms: Vec<Algorithm>,
    pub access_policy: UpstreamAccessPolicy,
    pub predicates: Vec<UpstreamClaimPredicate>,
    pub claims: UpstreamClaimSelectors,
    pub limits: UpstreamReadLimits,
    pub request_timeout: Duration,
    pub cache_max_age: Duration,
    pub min_refresh_interval: Duration,
    pub allow_loopback_http: bool,
    pub trusted_ca_pem: Option<Vec<u8>>,
    pub browser_clients: Vec<UpstreamBrowserClient>,
}
struct Selector {
    key: String,
    path: Option<JsonPath>,
}
impl Selector {
    fn new(key: String, cap: usize) -> Result<Self, ControlError> {
        if key.is_empty() || key.len() > cap {
            return Err(ControlError::Configuration);
        }
        let path = key
            .starts_with('$')
            .then(|| JsonPath::parse(&key))
            .transpose()
            .map_err(|_| ControlError::Configuration)?;
        Ok(Self { key, path })
    }
    fn select<'a>(&self, claims: &'a Value) -> Vec<&'a Value> {
        if let Some(path) = &self.path {
            return path.query(claims).all();
        }
        if let Some(v) = claims.get(&self.key) {
            return vec![v];
        }
        let mut value = claims;
        for key in self.key.split('.') {
            let Some(v) = value.as_object().and_then(|m| m.get(key)) else {
                return vec![];
            };
            value = v;
        }
        vec![value]
    }
    fn single(&self, claims: &Value, required: bool, cap: usize) -> Result<String, Error> {
        let nodes = self.select(claims);
        if nodes.is_empty() && !required {
            return Ok(String::new());
        }
        if nodes.len() != 1 {
            return Err(invalid());
        }
        let v = nodes[0]
            .as_str()
            .filter(|v| v.len() <= cap && !v.contains('\0'))
            .ok_or_else(invalid)?;
        if v.trim().is_empty() {
            return Err(invalid());
        }
        Ok(v.to_owned())
    }
    fn multi(&self, claims: &Value, cap: usize, count: usize) -> Result<Vec<String>, Error> {
        let mut result = BTreeSet::new();
        for node in self.select(claims) {
            let nodes: Vec<&Value> = match node {
                Value::Array(a) => a.iter().collect(),
                _ => vec![node],
            };
            for node in nodes {
                let value = node
                    .as_str()
                    .filter(|v| v.len() <= cap && !v.contains('\0'))
                    .ok_or_else(invalid)?
                    .trim();
                if !value.is_empty() {
                    result.insert(value.to_owned());
                }
                if result.len() > count {
                    return Err(invalid());
                }
            }
        }
        Ok(result.into_iter().collect())
    }
}
struct Claims {
    subject: Selector,
    username: Selector,
    name: Option<Selector>,
    email: Option<Selector>,
    organization: Option<Selector>,
    teams: Option<Selector>,
    roles: Option<Selector>,
    scope: Selector,
}
struct Cache {
    updated: Option<Instant>,
    attempted: Option<Instant>,
    keys: JwkSet,
    metadata: Option<CoreProviderMetadata>,
}
struct Provider {
    config: UpstreamProviderConfig,
    claims: Claims,
    predicates: Vec<(Selector, String)>,
    marker: Option<(Selector, String)>,
    cache: Mutex<Cache>,
    client: reqwest::Client,
}
pub(super) struct BrowserOwner;
/// Owns configured issuers, cache and HTTP policy, never request-provided trust.
pub struct UpstreamBearerVerifier {
    browser_owner: Arc<BrowserOwner>,
    native_issuer: String,
    providers: BTreeMap<String, Provider>,
    token_bytes: usize,
    browser_order: Vec<(String, usize)>,
}
impl fmt::Debug for UpstreamBearerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UpstreamBearerVerifier([REDACTED])")
    }
}
fn values_valid(values: &[String]) -> bool {
    !values.is_empty() && values.iter().all(|v| !v.trim().is_empty())
}
fn asymmetric(a: Algorithm) -> bool {
    matches!(
        a,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}
fn trusted_url(raw: &str, loopback: bool) -> bool {
    let Ok(u) = Url::parse(raw) else {
        return false;
    };
    let local = match u.host() {
        Some(Host::Domain(h)) => h == "localhost",
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    u.username().is_empty()
        && u.password().is_none()
        && u.fragment().is_none()
        && u.host().is_some()
        && (u.scheme() == "https" || (loopback && u.scheme() == "http" && local))
}
impl UpstreamBearerVerifier {
    // Pure current configuration lookup: cookie reads never contact discovery or UserInfo.
    pub(crate) fn cookie_role_selector(&self, issuer: &str) -> Option<Option<&str>> {
        self.providers
            .get(issuer)
            .map(|p| p.claims.roles.as_ref().map(|s| s.key.as_str()))
    }
    // OAuth grants require an enabled issuer with a remaining login channel.
    // Admin-cookie trust intentionally has a separate lookup and policy.
    pub(crate) fn oauth_role_selector(&self, issuer: &str) -> Option<Option<&str>> {
        self.providers
            .get(issuer)
            .filter(|p| !p.config.browser_clients.is_empty())
            .map(|p| p.claims.roles.as_ref().map(|s| s.key.as_str()))
    }
    pub fn new(
        native_issuer: &str,
        native_token_bytes: NonZeroUsize,
        configs: Vec<UpstreamProviderConfig>,
    ) -> Result<Self, ControlError> {
        let mut providers = BTreeMap::new();
        let mut ids = BTreeSet::new();
        let mut token_bytes = native_token_bytes.get();
        let mut browser_order = Vec::new();
        let mut browser_ids = BTreeSet::new();
        for config in configs {
            let l = config.limits;
            if !safe_identity_segment(&config.id, 128)
                || !ids.insert(config.id.clone())
                || config.issuer == native_issuer
                || config.issuer.contains('|')
                || !trusted_url(&config.issuer, config.allow_loopback_http)
                || Url::parse(&config.issuer)
                    .ok()
                    .is_none_or(|u| u.query().is_some())
                || !values_valid(&config.audiences)
                || config.allowed_algorithms.is_empty()
                || config.allowed_algorithms.iter().any(|a| !asymmetric(*a))
                || config
                    .required_scopes
                    .iter()
                    .any(|s| s.is_empty() || s.bytes().any(|b| b <= b' ' || b >= 127))
                || config.min_refresh_interval > config.cache_max_age
            {
                return Err(ControlError::Configuration);
            }
            for cap in [
                l.token_bytes,
                l.response_bytes,
                l.keys,
                l.selector_bytes,
                l.claim_string_bytes,
                l.profile_json_bytes,
                l.teams,
            ] {
                cap.get()
                    .checked_add(1)
                    .and_then(|n| isize::try_from(n).ok())
                    .ok_or(ControlError::Configuration)?;
                i64::try_from(cap.get()).map_err(|_| ControlError::Configuration)?;
            }
            for duration in [
                config.request_timeout,
                config.cache_max_age,
                config.min_refresh_interval,
            ] {
                if duration.is_zero() || Instant::now().checked_add(duration).is_none() {
                    return Err(ControlError::Configuration);
                }
            }
            match &config.access_policy {
                UpstreamAccessPolicy::ResourceAudience { id_token_audiences } => {
                    if !values_valid(id_token_audiences)
                        || id_token_audiences
                            .iter()
                            .any(|id| config.audiences.contains(id))
                    {
                        return Err(ControlError::Configuration);
                    }
                }
                UpstreamAccessPolicy::SignedMarker { typ, claim } => {
                    if typ.is_none() && claim.is_none()
                        || typ.as_ref().is_some_and(|v| v.trim().is_empty())
                    {
                        return Err(ControlError::Configuration);
                    }
                }
            }
            let mk = |s| Selector::new(s, l.selector_bytes.get());
            let c = &config.claims;
            let claims = Claims {
                subject: mk(c.subject.clone())?,
                username: mk(c.username.clone())?,
                name: c.name.clone().map(mk).transpose()?,
                email: c.email.clone().map(mk).transpose()?,
                organization: c.organization.clone().map(mk).transpose()?,
                teams: c.teams.clone().map(mk).transpose()?,
                roles: c.roles.clone().map(mk).transpose()?,
                scope: mk(c.scope.clone())?,
            };
            let predicate = |p: &UpstreamClaimPredicate| -> Result<_, ControlError> {
                if p.value.is_empty() || p.value.len() > l.claim_string_bytes.get() {
                    return Err(ControlError::Configuration);
                }
                Ok((mk(p.selector.clone())?, p.value.clone()))
            };
            let predicates = config
                .predicates
                .iter()
                .map(predicate)
                .collect::<Result<_, _>>()?;
            let marker = match &config.access_policy {
                UpstreamAccessPolicy::SignedMarker { claim, .. } => {
                    claim.as_ref().map(predicate).transpose()?
                }
                _ => None,
            };
            token_bytes = token_bytes.max(l.token_bytes.get());
            let issuer = config.issuer.clone();
            for (index, browser) in config.browser_clients.iter().enumerate() {
                browser.validate()?;
                if !browser_ids.insert(browser.id(&issuer)) {
                    return Err(ControlError::Configuration);
                }
                browser_order.push((issuer.clone(), index));
            }
            let mut client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
            if let Some(pem) = &config.trusted_ca_pem {
                let certificates = reqwest::Certificate::from_pem_bundle(pem)
                    .map_err(|_| ControlError::Configuration)?;
                if certificates.is_empty() {
                    return Err(ControlError::Configuration);
                }
                for certificate in certificates {
                    client = client.add_root_certificate(certificate);
                }
            }
            let client = client.build().map_err(|_| ControlError::Configuration)?;
            let provider = Provider {
                config,
                claims,
                predicates,
                marker,
                client,
                cache: Mutex::new(Cache {
                    updated: None,
                    attempted: None,
                    keys: JwkSet { keys: Vec::new() },
                    metadata: None,
                }),
            };
            if providers.insert(issuer, provider).is_some() {
                return Err(ControlError::Configuration);
            }
        }
        Ok(Self {
            browser_owner: Arc::new(BrowserOwner),
            native_issuer: native_issuer.into(),
            providers,
            token_bytes,
            browser_order,
        })
    }
    pub fn selects_native(&self, raw: &str, original: Instant) -> Result<bool, Error> {
        deadline(original)?;
        // Native's independently configured byte cap still applies after dispatch.
        let outcome = (|| {
            let issuer = locate(raw, self.token_bytes)?;
            if issuer == self.native_issuer {
                Ok(true)
            } else if self.providers.contains_key(&issuer) {
                Ok(false)
            } else {
                Err(invalid())
            }
        })();
        deadline(original)?;
        outcome
    }
    pub(crate) async fn verify(
        &self,
        raw: &str,
        original: Instant,
    ) -> Result<VerifiedUpstreamBearer, Error> {
        deadline(original)?;
        let outcome = self.verify_selected(raw, original).await;
        deadline(original)?;
        outcome
    }
    async fn verify_selected(
        &self,
        raw: &str,
        original: Instant,
    ) -> Result<VerifiedUpstreamBearer, Error> {
        let issuer = locate(raw, self.token_bytes)?;
        let provider = self.providers.get(&issuer).ok_or_else(invalid)?;
        if raw.len() > provider.config.limits.token_bytes.get() {
            return Err(invalid());
        }
        let (header, _) = parts(raw)?;
        if ["crit", "b64", "jku", "x5u", "jwk", "x5c"]
            .iter()
            .any(|k| header.get(*k).is_some())
        {
            return Err(invalid());
        }
        let algorithm: Algorithm =
            serde_json::from_value(header.get("alg").cloned().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        if !provider.config.allowed_algorithms.contains(&algorithm) {
            return Err(invalid());
        }
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(invalid)?;
        let end = original.min(
            Instant::now()
                .checked_add(provider.config.request_timeout)
                .ok_or(ControlError::Configuration)?,
        );
        let anchor_mono = Instant::now();
        let anchor = (SystemTime::now(), anchor_mono);
        let mut cache = tokio::time::timeout_at(end.into(), provider.cache.lock())
            .await
            .map_err(|_| ControlError::Deadline)?;
        let fresh = cache
            .updated
            .is_some_and(|at| Instant::now().duration_since(at) < provider.config.cache_max_age);
        if !fresh || cache.keys.find(kid).is_none() {
            self.refresh(provider, &mut cache, end, !fresh).await?;
        }
        let key = cache.keys.find(kid).ok_or_else(invalid)?;
        let claims = verify_signature(raw, key, algorithm, provider)
            .map_err(|e| {
                if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                    Error::Authentication(BrokerAccessError::Expired)
                } else {
                    invalid()
                }
            })?
            .claims
            .0;
        drop(cache);
        deadline(original)?;
        provider.profile(claims, header, anchor, original)
    }
    async fn refresh(
        &self,
        provider: &Provider,
        cache: &mut Cache,
        end: Instant,
        required: bool,
    ) -> Result<(), Error> {
        deadline(end)?;
        let now = Instant::now();
        if cache
            .attempted
            .is_some_and(|at| now.duration_since(at) < provider.config.min_refresh_interval)
        {
            return if required {
                Err(ControlError::Unavailable.into())
            } else {
                Ok(())
            };
        }
        cache.attempted = Some(now);
        let captured = StdMutex::new(None);
        let adapter = SdkAdapter {
            provider,
            operation: SdkOperation::Metadata(&captured),
        };
        let issuer = IssuerUrl::new(provider.config.issuer.clone())
            .map_err(|_| ControlError::Configuration)?;
        let metadata = tokio::time::timeout_at(
            end.into(),
            CoreProviderMetadata::discover_async(issuer, &adapter),
        )
        .await
        .map_err(|_| ControlError::Deadline)?
        .map_err(|_| ControlError::Unavailable)?;
        let jwks = captured
            .into_inner()
            .map_err(|_| ControlError::Unavailable)?
            .ok_or(ControlError::Unavailable)?;
        let mut keys = JwkSet { keys: Vec::new() };
        let mut identified = BTreeSet::new();
        for key in jwks.keys {
            if key
                .common
                .public_key_use
                .as_ref()
                .is_some_and(|u| u != &PublicKeyUse::Signature)
            {
                continue;
            }
            if key.common.key_operations.as_ref().is_some_and(|ops| {
                !ops.contains(&KeyOperations::Verify)
                    || ops.iter().any(|o| o != &KeyOperations::Verify)
            }) {
                continue;
            }
            if matches!(
                key.algorithm,
                jsonwebtoken::jwk::AlgorithmParameters::OctetKey(_)
            ) {
                continue;
            }
            DecodingKey::from_jwk(&key).map_err(|_| ControlError::Unavailable)?;
            if let Some(kid) = key.common.key_id.as_ref().filter(|s| !s.is_empty())
                && !identified.insert(kid.clone())
            {
                return Err(ControlError::Unavailable.into());
            }
            keys.keys.push(key);
        }
        if keys.keys.is_empty() {
            return Err(ControlError::Unavailable.into());
        }
        let sdk_keys = serde_json::from_value(
            serde_json::to_value(&keys).map_err(|_| ControlError::Unavailable)?,
        )
        .map_err(|_| ControlError::Unavailable)?;
        cache.keys = keys;
        cache.metadata = Some(metadata.set_jwks(sdk_keys));
        cache.updated = Some(Instant::now());
        Ok(())
    }
}
fn verify_signature(
    raw: &str,
    key: &Jwk,
    algorithm: Algorithm,
    p: &Provider,
) -> jsonwebtoken::errors::Result<jsonwebtoken::TokenData<UniqueRoot<Value>>> {
    if key
        .common
        .key_algorithm
        .as_ref()
        .is_some_and(|alg| alg.to_string() != format!("{algorithm:?}"))
    {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into());
    }
    let mut validation = Validation::new(algorithm);
    validation.leeway = 0;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["iss", "aud", "exp"]);
    validation.set_issuer(&[p.config.issuer.as_str()]);
    validation.set_audience(&p.config.audiences);
    decode(raw, &DecodingKey::from_jwk(key)?, &validation)
}
fn parts(raw: &str) -> Result<(Value, Value), Error> {
    let p: Vec<_> = raw.split('.').collect();
    if p.len() != 3 || p.iter().any(|p| p.is_empty()) {
        return Err(invalid());
    }
    let parse = |s| -> Result<Value, Error> {
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| invalid())?;
        let UniqueRoot(v): UniqueRoot<Value> =
            serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        Ok(v)
    };
    Ok((parse(p[0])?, parse(p[1])?))
}
fn locate(raw: &str, cap: usize) -> Result<String, Error> {
    if raw.is_empty() || raw.len() > cap {
        return Err(invalid());
    }
    let (_, claims) = parts(raw)?;
    claims
        .get("iss")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(invalid)
}
fn invalid() -> Error {
    BrokerAccessError::InvalidToken.into()
}
fn deadline(end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        Err(ControlError::Deadline.into())
    } else {
        Ok(())
    }
}
#[derive(Debug)]
struct SdkHttpError;
impl fmt::Display for SdkHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("trusted OIDC metadata unavailable")
    }
}
impl std::error::Error for SdkHttpError {}

pub(crate) struct VerifiedUpstreamBearer {
    profile: SessionProfile,
    issuer: String,
    username: String,
    organization: String,
    teams: Vec<String>,
    claim_roles: Option<Vec<String>>,
    expires_at: SystemTime,
    expires_mono: Instant,
    original: Instant,
}
impl VerifiedUpstreamBearer {
    pub(crate) fn profile(&self) -> &SessionProfile {
        &self.profile
    }
    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }
    pub(crate) fn username(&self) -> &str {
        &self.username
    }
    pub(crate) fn organization(&self) -> &str {
        &self.organization
    }
    pub(crate) fn teams(&self) -> &[String] {
        &self.teams
    }
    pub(crate) fn claim_roles(&self) -> Option<&[String]> {
        self.claim_roles.as_deref()
    }
    pub(crate) fn expires_mono(&self) -> Instant {
        self.expires_mono
    }
    pub(crate) fn check(&self) -> Result<(), Error> {
        deadline(self.original)?;
        if Instant::now() >= self.expires_mono || SystemTime::now() >= self.expires_at {
            return Err(BrokerAccessError::Expired.into());
        }
        Ok(())
    }
}
impl fmt::Debug for VerifiedUpstreamBearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedUpstreamBearer([REDACTED])")
    }
}
#[derive(Serialize)]
struct ProfileProjection<'a> {
    subject: &'a str,
    issuer: &'a str,
    username: &'a str,
    name: &'a str,
    email: &'a str,
    organization: &'a str,
    teams: &'a [String],
}
impl Provider {
    fn profile(
        &self,
        claims: Value,
        header: Value,
        anchor: (SystemTime, Instant),
        original: Instant,
    ) -> Result<VerifiedUpstreamBearer, Error> {
        let l = self.config.limits;
        let cap = l.claim_string_bytes.get();
        if let UpstreamAccessPolicy::ResourceAudience { id_token_audiences } =
            &self.config.access_policy
        {
            let aud = claims.get("aud").ok_or_else(invalid)?;
            let audience: Vec<&str> = match aud {
                Value::String(s) => vec![s],
                Value::Array(v) => v
                    .iter()
                    .map(|v| v.as_str().ok_or_else(invalid))
                    .collect::<Result<_, _>>()?,
                _ => return Err(invalid()),
            };
            if audience
                .iter()
                .any(|a| id_token_audiences.iter().any(|id| a == id))
            {
                return Err(invalid());
            }
        }
        if let UpstreamAccessPolicy::SignedMarker { typ: Some(typ), .. } =
            &self.config.access_policy
            && header.get("typ").and_then(Value::as_str) != Some(typ.as_str())
        {
            return Err(invalid());
        }
        for (selector, expected) in self.predicates.iter().chain(self.marker.iter()) {
            if selector.single(&claims, true, cap)? != *expected {
                return Err(invalid());
            }
        }
        let c = &self.claims;
        let nodes = c.scope.select(&claims);
        let mut scopes = BTreeSet::new();
        if nodes.len() > 1 {
            return Err(invalid());
        }
        if let Some(node) = nodes.first() {
            match node {
                Value::String(s) => {
                    if s.len() > l.token_bytes.get() {
                        return Err(invalid());
                    }
                    for scope in s.split_ascii_whitespace() {
                        scopes.insert(scope.to_owned());
                    }
                }
                Value::Array(v) => {
                    for scope in v {
                        let s = scope
                            .as_str()
                            .filter(|s| {
                                !s.is_empty()
                                    && s.len() <= cap
                                    && !s.bytes().any(|b| b <= b' ' || b >= 127)
                            })
                            .ok_or_else(invalid)?;
                        scopes.insert(s.to_owned());
                    }
                }
                _ => return Err(invalid()),
            }
        }
        if !self
            .config
            .required_scopes
            .iter()
            .all(|s| scopes.contains(s))
        {
            return Err(invalid());
        }
        let data = self.mapped_profile(&claims, None)?;
        let profile = data.profile;
        let username = data.username;
        let organization = data.organization;
        let teams = data.teams;
        let roles = data.roles;
        let exp = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or_else(invalid)?;
        let now = anchor
            .0
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_secs();
        for key in ["iat", "nbf"] {
            if let Some(value) = claims.get(key) {
                let n = value.as_u64().ok_or_else(invalid)?;
                if n > now || (key == "iat" && n >= exp) {
                    return Err(invalid());
                }
            }
        }
        let expires_at = UNIX_EPOCH
            .checked_add(Duration::from_secs(exp))
            .ok_or_else(invalid)?;
        let expires_mono = anchor
            .1
            .checked_add(
                expires_at
                    .duration_since(anchor.0)
                    .map_err(|_| Error::Authentication(BrokerAccessError::Expired))?,
            )
            .ok_or_else(invalid)?;
        let result = VerifiedUpstreamBearer {
            profile,
            issuer: self.config.issuer.clone(),
            username,
            organization,
            teams,
            claim_roles: roles,
            expires_at,
            expires_mono,
            original,
        };
        result.check()?;
        Ok(result)
    }
}

struct SdkAdapter<'a> {
    provider: &'a Provider,
    operation: SdkOperation<'a>,
}
enum SdkOperation<'a> {
    Metadata(&'a StdMutex<Option<JwkSet>>),
    Token(&'a str),
    UserInfo(&'a str, &'a StdMutex<Option<Value>>),
}
impl<'c> openidconnect::AsyncHttpClient<'c> for SdkAdapter<'_> {
    type Error = SdkHttpError;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<http::Response<Vec<u8>>, SdkHttpError>>
                + Send
                + 'c,
        >,
    >;
    fn call(&'c self, request: http::Request<Vec<u8>>) -> Self::Future {
        Box::pin(async move {
            let url = request.uri().to_string();
            if !trusted_url(&url, self.provider.config.allow_loopback_http) {
                return Err(SdkHttpError);
            }
            match &self.operation {
                SdkOperation::Metadata(_) if request.method() != http::Method::GET => {
                    return Err(SdkHttpError);
                }
                SdkOperation::Token(expected)
                    if url != *expected || request.method() != http::Method::POST =>
                {
                    return Err(SdkHttpError);
                }
                SdkOperation::UserInfo(expected, _)
                    if url != *expected || request.method() != http::Method::GET =>
                {
                    return Err(SdkHttpError);
                }
                _ => {}
            }
            let req = reqwest::Request::try_from(request).map_err(|_| SdkHttpError)?;
            let mut response = self
                .provider
                .client
                .execute(req)
                .await
                .map_err(|_| SdkHttpError)?;
            if !response.status().is_success() && !matches!(self.operation, SdkOperation::Token(_))
            {
                return Err(SdkHttpError);
            }
            let mut result = http::Response::builder().status(response.status());
            *result.headers_mut().ok_or(SdkHttpError)? = response.headers().clone();
            let mut body = Vec::new();
            let cap = self.provider.config.limits.response_bytes.get();
            if response.content_length().is_some_and(|n| n > cap as u64) {
                return Err(SdkHttpError);
            }
            while let Some(chunk) = response.chunk().await.map_err(|_| SdkHttpError)? {
                if body.len().checked_add(chunk.len()).is_none_or(|n| n > cap) {
                    return Err(SdkHttpError);
                }
                body.extend_from_slice(&chunk);
            }
            let UniqueRoot(json): UniqueRoot<Value> =
                serde_json::from_slice(&body).map_err(|_| SdkHttpError)?;
            if let SdkOperation::Metadata(captured) = &self.operation {
                if let Some(keys) = json.get("keys") {
                    let keys = keys
                        .as_array()
                        .filter(|v| {
                            !v.is_empty() && v.len() <= self.provider.config.limits.keys.get()
                        })
                        .ok_or(SdkHttpError)?;
                    if keys.iter().any(|k| {
                        ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                            .iter()
                            .any(|n| k.get(*n).is_some())
                    }) {
                        return Err(SdkHttpError);
                    }
                    let jwks: JwkSet = serde_json::from_value(json).map_err(|_| SdkHttpError)?;
                    *captured.lock().map_err(|_| SdkHttpError)? = Some(jwks);
                } else if json.get("issuer").and_then(Value::as_str)
                    != Some(self.provider.config.issuer.as_str())
                {
                    return Err(SdkHttpError);
                }
            } else if let SdkOperation::UserInfo(_, captured) = &self.operation {
                *captured.lock().map_err(|_| SdkHttpError)? = Some(json);
            }
            result.body(body).map_err(|_| SdkHttpError)
        })
    }
}
