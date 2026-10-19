//! Browser authentication uses the configured resource owner's discovery and transport.
use super::*;
use crate::service::upstream_login::ConsumedUpstreamFlow;
use crate::{FlowContinuation, FlowPurpose};
use oauth2::TokenResponse as _;
use oauth2::{
    AuthType, AuthUrl, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use openidconnect::core::{
    CoreClient, CoreClientAuthMethod, CoreIdTokenVerifier, CoreJwsSigningAlgorithm, CoreTokenType,
    CoreUserInfoClaims,
};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientSecret, Nonce, SubjectIdentifier, TokenResponse,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamBrowserClaimsSource {
    IdToken,
    AccessToken,
    Userinfo,
}

/// Explicit browser configuration. This data never establishes an authenticated identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamBrowserClient {
    pub display_name: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_url: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "required_nonce")]
    pub require_nonce: bool,
    #[serde(default = "id_claims_source")]
    pub claims_source: UpstreamBrowserClaimsSource,
    #[serde(default)]
    pub id_token_additional_audiences: Vec<String>,
}
fn required_nonce() -> bool {
    true
}
fn id_claims_source() -> UpstreamBrowserClaimsSource {
    UpstreamBrowserClaimsSource::IdToken
}
impl Drop for UpstreamBrowserClient {
    fn drop(&mut self) {
        if let Some(secret) = self.client_secret.as_mut() {
            secret.zeroize();
        }
    }
}
impl fmt::Debug for UpstreamBrowserClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UpstreamBrowserClient([REDACTED])")
    }
}
impl UpstreamBrowserClient {
    pub(super) fn validate(&self) -> Result<(), ControlError> {
        let name = self.display_name.trim();
        let printable = regex::Regex::new(r"^[\p{L}\p{M}\p{N}\p{P}\p{S}\p{Zs}]+$")
            .map_err(|_| ControlError::Configuration)?;
        if !(1..=80).contains(&name.chars().count())
            || !printable.is_match(name)
            || self.client_id.trim().is_empty()
            || self.client_id.contains('\0')
            || !trusted_url(&self.redirect_url, true)
            || self
                .scopes
                .iter()
                .any(|s| s.is_empty() || s.bytes().any(|b| b <= b' ' || b >= 127))
            || self
                .id_token_additional_audiences
                .iter()
                .any(|a| a.trim().is_empty() || a.contains('\0'))
        {
            return Err(ControlError::Configuration);
        }
        Ok(())
    }
    pub fn id(&self, issuer: &str) -> String {
        let mut hash = Sha256::new();
        hash.update(issuer.trim().trim_end_matches('/').as_bytes());
        hash.update([0]);
        hash.update(self.client_id.trim().as_bytes());
        format!("oidc_{}", URL_SAFE_NO_PAD.encode(&hash.finalize()[..12]))
    }
}

#[derive(Debug, Serialize)]
pub struct UpstreamBrowserOption {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamLoginFailure {
    InvalidProvider,
    InvalidState,
    InvalidIdentity,
    ProviderError,
    Control(ControlError),
}
impl From<ControlError> for UpstreamLoginFailure {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<Error> for UpstreamLoginFailure {
    fn from(value: Error) -> Self {
        match value {
            Error::Control(e) => Self::Control(e),
            _ => Self::InvalidIdentity,
        }
    }
}
/// The continuation is available only after this producer consumed a matching SQL flow.
pub struct UpstreamLoginError {
    failure: UpstreamLoginFailure,
    continuation: Option<FlowContinuation>,
}
impl UpstreamLoginError {
    pub(crate) fn new(
        failure: UpstreamLoginFailure,
        continuation: Option<FlowContinuation>,
    ) -> Self {
        Self {
            failure,
            continuation,
        }
    }
    pub fn failure(&self) -> UpstreamLoginFailure {
        self.failure
    }
    pub fn continuation(&self) -> Option<&FlowContinuation> {
        self.continuation.as_ref()
    }
}
impl fmt::Debug for UpstreamLoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("UpstreamLoginError")
            .field(&self.failure)
            .finish()
    }
}
impl fmt::Display for UpstreamLoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("upstream browser login failed")
    }
}
impl std::error::Error for UpstreamLoginError {}

pub enum UpstreamLoginCallback<'a> {
    Code(&'a str),
    ProviderError,
}

/// Created only after the flow INSERT's COMMIT is acknowledged.
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::IssuedUpstreamAuthorization>();
/// ```
pub struct IssuedUpstreamAuthorization {
    location: Url,
    state: Zeroizing<String>,
    binding: Zeroizing<String>,
    expires_at: SystemTime,
    expires_mono: Instant,
    original: Instant,
}
impl fmt::Debug for IssuedUpstreamAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuedUpstreamAuthorization([REDACTED])")
    }
}
impl IssuedUpstreamAuthorization {
    pub fn location(&self) -> &Url {
        &self.location
    }
    pub fn state(&self) -> &str {
        &self.state
    }
    pub fn browser_binding(&self) -> &str {
        &self.binding
    }
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    pub fn check(&self) -> Result<(), ControlError> {
        temporal_gate(self.original, self.expires_at, self.expires_mono)
    }
    pub(crate) fn committed(
        location: Url,
        state: Zeroizing<String>,
        binding: Zeroizing<String>,
        expires_at: SystemTime,
        expires_mono: Instant,
        original: Instant,
    ) -> Result<Self, ControlError> {
        let value = Self {
            location,
            state,
            binding,
            expires_at,
            expires_mono,
            original,
        };
        value.check()?;
        Ok(value)
    }
}

/// Authority produced only by matched flow consumption and a real OIDC exchange.
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::VerifiedUpstreamLogin>();
/// ```
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::VerifiedUpstreamLogin>();
/// ```
/// ```compile_fail
/// fn data(value: broker_control::SessionProfile) -> broker_control::VerifiedUpstreamLogin {
///     broker_control::VerifiedUpstreamLogin { profile: value }
/// }
/// ```
pub struct VerifiedUpstreamLogin {
    owner: Arc<BrowserOwner>,
    continuation: FlowContinuation,
    issuer: String,
    profile: SessionProfile,
    username: String,
    organization: String,
    teams: Vec<String>,
    claim_roles: Option<Vec<String>>,
    role_selector: Option<String>,
    original: Instant,
    expires_at: SystemTime,
    expires_mono: Instant,
    binding: Zeroizing<String>,
}
impl fmt::Debug for VerifiedUpstreamLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedUpstreamLogin([REDACTED])")
    }
}
impl VerifiedUpstreamLogin {
    pub fn purpose(&self) -> FlowPurpose {
        self.continuation.purpose()
    }
    pub fn continuation(&self) -> &FlowContinuation {
        &self.continuation
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn profile(&self) -> &SessionProfile {
        &self.profile
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn organization(&self) -> &str {
        &self.organization
    }
    pub fn teams(&self) -> &[String] {
        &self.teams
    }
    pub fn claim_roles(&self) -> Option<&[String]> {
        self.claim_roles.as_deref()
    }
    pub fn role_selector(&self) -> Option<&str> {
        self.role_selector.as_deref()
    }
    pub fn original(&self) -> Instant {
        self.original
    }
    pub(crate) fn expires_mono(&self) -> Instant {
        self.expires_mono
    }
    pub fn check(&self, verifier: &UpstreamBearerVerifier) -> Result<(), ControlError> {
        if !Arc::ptr_eq(&self.owner, &verifier.browser_owner) || self.binding.len() != 43 {
            return Err(ControlError::InvalidFlow);
        }
        temporal_gate(self.original, self.expires_at, self.expires_mono)
    }
}
pub(crate) fn temporal_gate(
    original: Instant,
    wall: SystemTime,
    mono: Instant,
) -> Result<(), ControlError> {
    if Instant::now() >= original {
        return Err(ControlError::Deadline);
    }
    if Instant::now() >= mono || SystemTime::now() >= wall {
        return Err(ControlError::Expired);
    }
    Ok(())
}
pub(crate) fn copy_continuation(c: &FlowContinuation) -> FlowContinuation {
    match c {
        FlowContinuation::Admin { provider_id } => FlowContinuation::Admin {
            provider_id: provider_id.clone(),
        },
        FlowContinuation::OAuth {
            provider_id,
            request_id,
        } => FlowContinuation::OAuth {
            provider_id: provider_id.clone(),
            request_id: request_id.clone(),
        },
    }
}

impl UpstreamBearerVerifier {
    pub fn browser_options(
        &self,
        original: Instant,
    ) -> Result<Vec<UpstreamBrowserOption>, ControlError> {
        deadline(original).map_err(|_| ControlError::Deadline)?;
        let result = self
            .browser_order
            .iter()
            .map(|(issuer, index)| {
                let client = &self.providers[issuer].config.browser_clients[*index];
                UpstreamBrowserOption {
                    id: client.id(issuer),
                    name: client.display_name.trim().to_owned(),
                }
            })
            .collect();
        deadline(original).map_err(|_| ControlError::Deadline)?;
        Ok(result)
    }
    fn browser_provider(
        &self,
        id: &str,
    ) -> Result<(&Provider, &UpstreamBrowserClient), UpstreamLoginFailure> {
        for (issuer, index) in &self.browser_order {
            let provider = &self.providers[issuer];
            let client = &provider.config.browser_clients[*index];
            if client.id(issuer) == id {
                return Ok((provider, client));
            }
        }
        Err(UpstreamLoginFailure::InvalidProvider)
    }
    async fn browser_metadata(
        &self,
        p: &Provider,
        original: Instant,
    ) -> Result<CoreProviderMetadata, UpstreamLoginFailure> {
        deadline(original)?;
        let end = original.min(
            Instant::now()
                .checked_add(p.config.request_timeout)
                .ok_or(ControlError::Configuration)?,
        );
        let mut cache = tokio::time::timeout_at(end.into(), p.cache.lock())
            .await
            .map_err(|_| ControlError::Deadline)?;
        let fresh = cache
            .updated
            .is_some_and(|at| Instant::now().duration_since(at) < p.config.cache_max_age);
        if !fresh || cache.metadata.is_none() {
            self.refresh(p, &mut cache, end, true).await?;
        }
        let metadata = cache.metadata.clone().ok_or(ControlError::Unavailable)?;
        for endpoint in [
            Some(metadata.authorization_endpoint().as_str()),
            metadata.token_endpoint().map(|u| u.as_str()),
            metadata.userinfo_endpoint().map(|u| u.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            if !trusted_url(endpoint, p.config.allow_loopback_http) {
                return Err(ControlError::Unavailable.into());
            }
        }
        if metadata.token_endpoint().is_none() {
            return Err(ControlError::Unavailable.into());
        }
        deadline(original)?;
        Ok(metadata)
    }
    async fn browser_key_metadata(
        &self,
        p: &Provider,
        kid: Option<&str>,
        original: Instant,
    ) -> Result<CoreProviderMetadata, UpstreamLoginFailure> {
        deadline(original)?;
        let end = original.min(
            Instant::now()
                .checked_add(p.config.request_timeout)
                .ok_or(ControlError::Configuration)?,
        );
        let mut cache = tokio::time::timeout_at(end.into(), p.cache.lock())
            .await
            .map_err(|_| ControlError::Deadline)?;
        if kid.is_some_and(|kid| cache.keys.find(kid).is_none()) {
            self.refresh(p, &mut cache, end, false).await?;
        }
        let metadata = cache.metadata.clone().ok_or(ControlError::Unavailable)?;
        deadline(original)?;
        Ok(metadata)
    }
    pub(crate) async fn browser_authorization(
        &self,
        continuation: &FlowContinuation,
        state: &str,
        nonce: &str,
        verifier: &str,
        original: Instant,
    ) -> Result<Url, UpstreamLoginFailure> {
        let (p, browser) = self.browser_provider(continuation.provider_id())?;
        let metadata = self.browser_metadata(p, original).await?;
        let client = oauth2::basic::BasicClient::new(ClientId::new(browser.client_id.clone()))
            .set_auth_uri(
                AuthUrl::new(metadata.authorization_endpoint().as_str().to_owned())
                    .map_err(|_| ControlError::Unavailable)?,
            )
            .set_redirect_uri(
                RedirectUrl::new(browser.redirect_url.clone())
                    .map_err(|_| ControlError::Configuration)?,
            );
        let pkce = PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(
            verifier.to_owned(),
        ));
        let mut request = client
            .authorize_url(|| CsrfToken::new(state.to_owned()))
            .set_pkce_challenge(pkce);
        let mut scopes = BTreeSet::new();
        for scope in std::iter::once("openid").chain(browser.scopes.iter().map(String::as_str)) {
            if scopes.insert(scope) {
                request = request.add_scope(Scope::new(scope.to_owned()));
            }
        }
        if browser.require_nonce {
            request = request.add_extra_param("nonce", nonce);
        }
        let (location, _) = request.url();
        deadline(original)?;
        Ok(location)
    }
    pub(crate) async fn authenticate_browser(
        &self,
        consumed: ConsumedUpstreamFlow,
        code: &str,
    ) -> Result<VerifiedUpstreamLogin, UpstreamLoginFailure> {
        let original = consumed.original();
        consumed.check()?;
        let flow = consumed.flow();
        let (p, browser) = self.browser_provider(flow.continuation().provider_id())?;
        if code.is_empty() || code.len() > p.config.limits.token_bytes.get() || code.contains('\0')
        {
            return Err(UpstreamLoginFailure::ProviderError);
        }
        let metadata = self.browser_metadata(p, original).await?;
        let methods = metadata.token_endpoint_auth_methods_supported();
        let secret = browser.client_secret.as_ref().filter(|s| !s.is_empty());
        let auth = if secret.is_none() {
            AuthType::RequestBody
        } else if methods.is_none_or(|m| m.contains(&CoreClientAuthMethod::ClientSecretBasic)) {
            AuthType::BasicAuth
        } else if methods.is_some_and(|m| m.contains(&CoreClientAuthMethod::ClientSecretPost)) {
            AuthType::RequestBody
        } else {
            return Err(ControlError::Unavailable.into());
        };
        let endpoint = metadata
            .token_endpoint()
            .ok_or(ControlError::Unavailable)?
            .as_str()
            .to_owned();
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(browser.client_id.clone()),
            secret.map(|s| ClientSecret::new(s.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(browser.redirect_url.clone())
                .map_err(|_| ControlError::Configuration)?,
        )
        .set_auth_type(auth);
        let adapter = SdkAdapter {
            provider: p,
            operation: SdkOperation::Token(&endpoint),
        };
        let request = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|_| ControlError::Unavailable)?
            .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier().to_owned()));
        let end = original.min(
            Instant::now()
                .checked_add(p.config.request_timeout)
                .ok_or(ControlError::Configuration)?,
        );
        let token = tokio::time::timeout_at(end.into(), request.request_async(&adapter))
            .await
            .map_err(|_| ControlError::Deadline)?
            .map_err(|error| match error {
                openidconnect::RequestTokenError::ServerResponse(_) => {
                    UpstreamLoginFailure::ProviderError
                }
                _ => ControlError::Unavailable.into(),
            })?;
        consumed.check()?;
        if token.token_type() != &CoreTokenType::Bearer {
            return Err(UpstreamLoginFailure::InvalidIdentity);
        }
        let id = token
            .id_token()
            .ok_or(UpstreamLoginFailure::InvalidIdentity)?;
        let raw_id = Zeroizing::new(id.to_string());
        if raw_id.len() > p.config.limits.token_bytes.get() {
            return Err(UpstreamLoginFailure::InvalidIdentity);
        }
        let (header, id_claims) = parts(&raw_id)?;
        valid_header(&header, p)?;
        let verification_metadata = self
            .browser_key_metadata(p, header.get("kid").and_then(Value::as_str), original)
            .await?;
        let algorithms = p
            .config
            .allowed_algorithms
            .iter()
            .map(|a| {
                serde_json::from_value::<CoreJwsSigningAlgorithm>(Value::String(format!("{a:?}")))
                    .map_err(|_| ControlError::Configuration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let algorithms = algorithms
            .into_iter()
            .filter(|a| {
                verification_metadata
                    .id_token_signing_alg_values_supported()
                    .contains(a)
            })
            .collect::<Vec<_>>();
        let verifier = CoreIdTokenVerifier::new_public_client(
            ClientId::new(browser.client_id.clone()),
            verification_metadata.issuer().clone(),
            verification_metadata.jwks().clone(),
        )
        .set_allowed_algs(algorithms)
        .set_other_audience_verifier_fn(|a| {
            browser
                .id_token_additional_audiences
                .iter()
                .any(|trusted| trusted == a.as_str())
        });
        let nonce = Nonce::new(flow.nonce().to_owned());
        let verified = if browser.require_nonce {
            id.claims(&verifier, &nonce)
        } else {
            id.claims(&verifier, |_nonce: Option<&Nonce>| Ok(()))
        }
        .map_err(|_| UpstreamLoginFailure::InvalidIdentity)?;
        let raw_sub = verified.subject().as_str();
        if raw_sub.is_empty()
            || raw_sub.contains('\0')
            || raw_sub.len() > p.config.limits.claim_string_bytes.get()
        {
            return Err(UpstreamLoginFailure::InvalidIdentity);
        }
        validate_azp(&id_claims, &browser.client_id)?;
        if let Some(expected) = verified.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                token.access_token(),
                id.signing_alg()
                    .map_err(|_| UpstreamLoginFailure::InvalidIdentity)?,
                id.signing_key(&verifier)
                    .map_err(|_| UpstreamLoginFailure::InvalidIdentity)?,
            )
            .map_err(|_| UpstreamLoginFailure::InvalidIdentity)?;
            if !bool::from(
                actual
                    .as_str()
                    .as_bytes()
                    .ct_eq(expected.as_str().as_bytes()),
            ) {
                return Err(UpstreamLoginFailure::InvalidIdentity);
            }
        }
        // The issuer creates these JWTs during the exchange. Observe their temporal
        // window after verification, retaining the already anchored flow deadline.
        let anchor_mono = Instant::now();
        let anchor = (SystemTime::now(), anchor_mono);
        let id_expiry = claim_expiry(&id_claims, anchor)?;
        let mut expiry = id_expiry.min(flow.expires_at());
        let access_claims;
        let selected = if browser.claims_source == UpstreamBrowserClaimsSource::AccessToken {
            let raw = token.access_token().secret();
            access_claims = self.verify_browser_access(p, raw, original).await?;
            if access_claims.get("sub").and_then(Value::as_str) != Some(raw_sub) {
                return Err(UpstreamLoginFailure::InvalidIdentity);
            }
            expiry = expiry.min(claim_expiry(&access_claims, anchor)?);
            &access_claims
        } else {
            &id_claims
        };
        let supplementary = if browser.claims_source == UpstreamBrowserClaimsSource::Userinfo
            && p.needs_userinfo(selected)?
        {
            let endpoint = client
                .user_info_url()
                .ok_or(ControlError::Unavailable)?
                .as_str()
                .to_owned();
            let captured = StdMutex::new(None);
            let adapter = SdkAdapter {
                provider: p,
                operation: SdkOperation::UserInfo(&endpoint, &captured),
            };
            let request = client
                .user_info(
                    token.access_token().clone(),
                    Some(SubjectIdentifier::new(raw_sub.to_owned())),
                )
                .map_err(|_| ControlError::Unavailable)?;
            let end = original.min(
                Instant::now()
                    .checked_add(p.config.request_timeout)
                    .ok_or(ControlError::Configuration)?,
            );
            let _: CoreUserInfoClaims =
                tokio::time::timeout_at(end.into(), request.request_async(&adapter))
                    .await
                    .map_err(|_| ControlError::Deadline)?
                    .map_err(|error| match error {
                        openidconnect::UserInfoError::ClaimsVerification(_) => {
                            UpstreamLoginFailure::InvalidIdentity
                        }
                        _ => ControlError::Unavailable.into(),
                    })?;
            let value = captured
                .into_inner()
                .map_err(|_| ControlError::Unavailable)?
                .ok_or(ControlError::Unavailable)?;
            if value.get("sub").and_then(Value::as_str) != Some(raw_sub) {
                return Err(UpstreamLoginFailure::InvalidIdentity);
            }
            Some(value)
        } else {
            None
        };
        let data = p
            .mapped_profile(selected, supplementary.as_ref())
            .map_err(|error| {
                if supplementary.is_some() {
                    UpstreamLoginFailure::Control(ControlError::Unavailable)
                } else {
                    error.into()
                }
            })?;
        let expires_mono = anchor
            .1
            .checked_add(
                expiry
                    .duration_since(anchor.0)
                    .map_err(|_| ControlError::Expired)?,
            )
            .ok_or(ControlError::Clock)?
            .min(consumed.expires_mono());
        let result = VerifiedUpstreamLogin {
            owner: Arc::clone(&self.browser_owner),
            continuation: copy_continuation(flow.continuation()),
            issuer: p.config.issuer.clone(),
            profile: data.profile,
            username: data.username,
            organization: data.organization,
            teams: data.teams,
            claim_roles: data.roles,
            role_selector: p.config.claims.roles.clone(),
            original,
            expires_at: expiry,
            expires_mono,
            binding: consumed.into_binding(),
        };
        result.check(self)?;
        Ok(result)
    }
    async fn verify_browser_access(
        &self,
        p: &Provider,
        raw: &str,
        original: Instant,
    ) -> Result<Value, UpstreamLoginFailure> {
        if raw.is_empty() || raw.len() > p.config.limits.token_bytes.get() {
            return Err(UpstreamLoginFailure::InvalidIdentity);
        }
        let (header, _) = parts(raw)?;
        let algorithm = valid_header(&header, p)?;
        let kid = match header.get("kid") {
            None => None,
            Some(Value::String(kid)) if !kid.is_empty() => Some(kid.as_str()),
            _ => return Err(UpstreamLoginFailure::InvalidIdentity),
        };
        let end = original.min(
            Instant::now()
                .checked_add(p.config.request_timeout)
                .ok_or(ControlError::Configuration)?,
        );
        let mut cache = tokio::time::timeout_at(end.into(), p.cache.lock())
            .await
            .map_err(|_| ControlError::Deadline)?;
        if kid.is_some_and(|kid| cache.keys.find(kid).is_none()) {
            self.refresh(p, &mut cache, end, false).await?;
        }
        // This JWT is accepted only inside this producer's real token exchange, never as a resource credential.
        let mut validation = Validation::new(algorithm);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["iss", "sub", "exp"]);
        validation.set_issuer(&[p.config.issuer.as_str()]);
        // A missing kid does not discard a valid signature: try the bounded, filtered
        // configured key set. This is private to the genuine code-exchange producer.
        let value = cache
            .keys
            .keys
            .iter()
            .filter(|key| {
                kid.is_none_or(|kid| key.common.key_id.as_deref() == Some(kid))
                    && key
                        .common
                        .key_algorithm
                        .as_ref()
                        .is_none_or(|a| a.to_string() == format!("{algorithm:?}"))
            })
            .find_map(|key| {
                let decoding_key = DecodingKey::from_jwk(key).ok()?;
                decode::<UniqueRoot<Value>>(raw, &decoding_key, &validation)
                    .ok()
                    .map(|token| token.claims.0)
            })
            .ok_or(UpstreamLoginFailure::InvalidIdentity)?;
        deadline(original)?;
        Ok(value)
    }
}

fn valid_header(header: &Value, p: &Provider) -> Result<Algorithm, UpstreamLoginFailure> {
    if ["crit", "b64", "jku", "x5u", "jwk", "x5c"]
        .iter()
        .any(|k| header.get(*k).is_some())
    {
        return Err(UpstreamLoginFailure::InvalidIdentity);
    }
    let algorithm: Algorithm = serde_json::from_value(
        header
            .get("alg")
            .cloned()
            .ok_or(UpstreamLoginFailure::InvalidIdentity)?,
    )
    .map_err(|_| UpstreamLoginFailure::InvalidIdentity)?;
    if !p.config.allowed_algorithms.contains(&algorithm) {
        return Err(UpstreamLoginFailure::InvalidIdentity);
    }
    Ok(algorithm)
}
fn validate_azp(claims: &Value, client: &str) -> Result<(), UpstreamLoginFailure> {
    let audience = match claims.get("aud") {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(a)) if !a.is_empty() => a
            .iter()
            .map(|v| v.as_str().ok_or(UpstreamLoginFailure::InvalidIdentity))
            .collect::<Result<_, _>>()?,
        _ => return Err(UpstreamLoginFailure::InvalidIdentity),
    };
    if !audience.contains(&client)
        || claims
            .get("azp")
            .is_some_and(|a| a.as_str() != Some(client))
        || (audience.len() > 1 && claims.get("azp").and_then(Value::as_str) != Some(client))
    {
        return Err(UpstreamLoginFailure::InvalidIdentity);
    }
    Ok(())
}
fn claim_expiry(
    claims: &Value,
    anchor: (SystemTime, Instant),
) -> Result<SystemTime, UpstreamLoginFailure> {
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(UpstreamLoginFailure::InvalidIdentity)?;
    let now = anchor
        .0
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ControlError::Clock)?
        .as_secs();
    for key in ["iat", "nbf"] {
        if let Some(value) = claims.get(key) {
            let n = value
                .as_u64()
                .ok_or(UpstreamLoginFailure::InvalidIdentity)?;
            if n > now || (key == "iat" && n >= exp) {
                return Err(UpstreamLoginFailure::InvalidIdentity);
            }
        }
    }
    let expiry = UNIX_EPOCH
        .checked_add(Duration::from_secs(exp))
        .ok_or(UpstreamLoginFailure::InvalidIdentity)?;
    if expiry <= anchor.0 {
        return Err(ControlError::Expired.into());
    }
    Ok(expiry)
}

pub(super) struct MappedProfile {
    pub(super) profile: SessionProfile,
    pub(super) username: String,
    pub(super) organization: String,
    pub(super) teams: Vec<String>,
    pub(super) roles: Option<Vec<String>>,
}
impl Provider {
    fn needs_userinfo(&self, base: &Value) -> Result<bool, UpstreamLoginFailure> {
        // Validate every present selected value before treating absent profile data as supplementary.
        let c = &self.claims;
        let cap = self.config.limits.claim_string_bytes.get();
        let mut missing = c.username.select(base).is_empty();
        if !missing {
            c.username.single(base, true, cap)?;
        }
        for selector in [&c.name, &c.email, &c.organization].into_iter().flatten() {
            if selector.select(base).is_empty() {
                missing = true;
            } else {
                selector.single(base, false, cap)?;
            }
        }
        if let Some(selector) = &c.teams {
            if selector.select(base).is_empty() {
                missing = true;
            } else {
                selector.multi(base, cap, self.config.limits.teams.get())?;
            }
        }
        c.subject.single(base, true, cap)?;
        if let Some(selector) = &c.roles {
            let roles = selector.multi(base, 128, self.config.limits.token_bytes.get())?;
            if roles.iter().any(|role| !safe_identity_segment(role, 128)) {
                return Err(UpstreamLoginFailure::InvalidIdentity);
            }
        }
        Ok(missing)
    }
    pub(super) fn mapped_profile(
        &self,
        base: &Value,
        supplementary: Option<&Value>,
    ) -> Result<MappedProfile, Error> {
        let l = self.config.limits;
        let cap = l.claim_string_bytes.get();
        let c = &self.claims;
        let subject = c.subject.single(base, true, cap)?;
        if subject.len() > 512
            || self.config.issuer.chars().count() + subject.chars().count() + 1 > 1024
        {
            return Err(invalid());
        }
        let selected = |s: &Selector| {
            if s.select(base).is_empty() {
                supplementary.unwrap_or(base)
            } else {
                base
            }
        };
        let optional = |s: &Option<Selector>| {
            s.as_ref()
                .map(|s| s.single(selected(s), false, cap))
                .transpose()
                .map(Option::unwrap_or_default)
        };
        let username = c.username.single(selected(&c.username), true, cap)?;
        let teams = c
            .teams
            .as_ref()
            .map(|s| s.multi(selected(s), cap, l.teams.get()))
            .transpose()?
            .unwrap_or_default();
        let roles = c
            .roles
            .as_ref()
            .map(|s| s.multi(base, 128, l.token_bytes.get()))
            .transpose()?;
        if roles
            .as_ref()
            .is_some_and(|r| r.iter().any(|r| !safe_identity_segment(r, 128)))
        {
            return Err(invalid());
        }
        let profile = SessionProfile {
            subject,
            name: optional(&c.name)?,
            email: optional(&c.email)?,
        };
        let organization = optional(&c.organization)?;
        let bytes = serde_json::to_vec(&ProfileProjection {
            subject: &profile.subject,
            issuer: &self.config.issuer,
            username: &username,
            name: &profile.name,
            email: &profile.email,
            organization: &organization,
            teams: &teams,
        })
        .map_err(|_| invalid())?;
        if bytes.len() > l.profile_json_bytes.get() {
            return Err(invalid());
        }
        Ok(MappedProfile {
            profile,
            username,
            organization,
            teams,
            roles,
        })
    }
}
