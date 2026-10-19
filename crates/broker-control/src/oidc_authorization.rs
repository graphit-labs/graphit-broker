//! Native pending authorization DATA; no resource-owner or token authority.
//!
//! Secrets cannot be cloned or serialized:
//! ```compile_fail
//! fn copy(p: broker_control::PendingOidcAuthorization) { let _ = p.clone(); }
//! ```
//! ```compile_fail
//! fn serialize(p: broker_control::PendingOidcAuthorization) { let _ = serde_json::to_string(&p); }
//! ```
//! Stored observations cannot be constructed by callers:
//! ```compile_fail
//! fn forge(i: broker_control::OidcAuthorizationRequestInfo) { let _ = i.fields; }
//! ```
//! Borrowed owners cannot escape their lifetime:
//! ```compile_fail
//! fn escape(s: &broker_control::PostgresControlStore, d: &broker_security::CredentialDigester,
//! p: &broker_control::OidcAuthorizationPolicy) -> broker_control::PostgresOidcAuthorizationService<'static> {
//! s.oidc_authorization_service(d, p)
//! }
//! ```
use crate::{ControlError, identity::safe_identity_segment};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iri_string::types::IriAbsoluteStr;
use oxide_auth::{
    code_grant::{
        authorization::{self, Request},
        extensions::Pkce,
    },
    primitives::{
        grant::Extensions,
        registrar::{
            BoundClient, ClientUrl, ExactUrl, PreGrant, RegisteredUrl, Registrar, RegistrarError,
        },
        scope::Scope,
    },
};
use serde::{
    Deserialize, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{
    borrow::Cow,
    fmt,
    net::IpAddr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcAuthorizationError {
    InvalidConfiguration,
    InvalidLimits,
    InvalidRequest,
    InvalidClient,
    InvalidRedirect,
    InvalidScope,
    LoginRequired,
    InvalidTarget,
    InvalidLogin,
    MalformedStored,
    ReadLimitExceeded,
    Credential,
    Random,
    Control(ControlError),
}
impl fmt::Display for OidcAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(e) => e.fmt(f),
            _ => write!(f, "OIDC authorization {self:?}"),
        }
    }
}
impl std::error::Error for OidcAuthorizationError {}
impl From<ControlError> for OidcAuthorizationError {
    fn from(e: ControlError) -> Self {
        Self::Control(e)
    }
}
type Error = OidcAuthorizationError;

mod completion;
pub use completion::AuthorizedOidcAuthorization;
mod browser;
pub use browser::{
    BrowserOidcAuthorization, OidcAuthorizationRejectionCode, RejectedOidcAuthorization,
};
mod response;
pub use response::OidcAuthorizationResponseTarget;

/// Startup must supply every setting, including TTL and dynamic registration policy.
pub struct OidcAuthorizationConfiguration {
    pub cli_client_id: String,
    pub cli_redirect_path: String,
    pub api_audience: String,
    pub accepted_resources: Vec<String>,
    pub dynamic_registration: bool,
    pub authorization_ttl: Duration,
}
impl fmt::Debug for OidcAuthorizationConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcAuthorizationConfiguration([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug)]
pub struct OidcAuthorizationLimits {
    pub(crate) json_bytes: i64,
    parameter_bytes: usize,
}
impl OidcAuthorizationLimits {
    pub(crate) const fn parameter_bytes(&self) -> usize {
        self.parameter_bytes
    }
    pub fn new(json_bytes: NonZeroUsize, parameter_bytes: NonZeroUsize) -> Result<Self, Error> {
        if json_bytes.get() > isize::MAX as usize || parameter_bytes.get() > isize::MAX as usize {
            return Err(Error::InvalidLimits);
        }
        let json_bytes = i64::try_from(json_bytes.get()).map_err(|_| Error::InvalidLimits)?;
        json_bytes.checked_add(1).ok_or(Error::InvalidLimits)?;
        i64::try_from(parameter_bytes.get()).map_err(|_| Error::InvalidLimits)?;
        Ok(Self {
            json_bytes,
            parameter_bytes: parameter_bytes.get(),
        })
    }
}
pub struct OidcAuthorizationPolicy {
    pub(crate) cli_client_id: String,
    pub(crate) cli_redirect: String,
    pub(crate) api_audience: String,
    accepted_resources: Vec<String>,
    pub(crate) dynamic_registration: bool,
    pub(crate) ttl_micros: i64,
    pub(crate) limits: OidcAuthorizationLimits,
}
impl fmt::Debug for OidcAuthorizationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcAuthorizationPolicy([REDACTED])")
    }
}
impl OidcAuthorizationPolicy {
    pub(crate) fn refresh_resource_allowed(&self, resource: Option<&str>) -> bool {
        resource.is_none_or(|r| valid_resource(r) && self.accepted_resources.iter().any(|v| v == r))
    }
    pub fn new(
        c: OidcAuthorizationConfiguration,
        limits: OidcAuthorizationLimits,
    ) -> Result<Self, Error> {
        if !safe_identity_segment(&c.cli_client_id, 128)
            || !safe_identity_segment(&c.api_audience, 128)
            || !c.cli_redirect_path.starts_with('/')
            || c.cli_redirect_path.contains(['?', '#'])
            || c.cli_redirect_path.len() > limits.parameter_bytes
            || !(Duration::from_secs(30)..=Duration::from_secs(600)).contains(&c.authorization_ttl)
        {
            return Err(Error::InvalidConfiguration);
        }
        let cli_redirect = format!("http://127.0.0.1{}", c.cli_redirect_path);
        redirect(&cli_redirect).map_err(|_| Error::InvalidConfiguration)?;
        let mut accepted_resources = Vec::new();
        for resource in c.accepted_resources {
            let resource = resource.trim();
            if !valid_resource(resource) {
                return Err(Error::InvalidConfiguration);
            }
            if !accepted_resources.iter().any(|v| v == resource) {
                accepted_resources.push(resource.to_owned())
            }
        }
        Ok(Self {
            cli_client_id: c.cli_client_id,
            cli_redirect,
            api_audience: c.api_audience,
            accepted_resources,
            dynamic_registration: c.dynamic_registration,
            ttl_micros: i64::try_from(c.authorization_ttl.as_micros())
                .map_err(|_| Error::InvalidConfiguration)?,
            limits,
        })
    }
    pub(crate) fn bound(
        &self,
        input: &OidcAuthorizationInput<'_>,
        original: Instant,
    ) -> Result<(), Error> {
        let mut total = 0usize;
        let scalar = [
            input.client_id,
            input.redirect_uri,
            input.response_type,
            input.scope,
            input.state,
            input.nonce,
            input.code_challenge,
            input.code_challenge_method,
            input.response_mode.unwrap_or(""),
        ];
        for (text, delimiter) in scalar.into_iter().map(|s| (s, 0)).chain(
            input
                .resources
                .iter()
                .chain(input.prompts.iter())
                .map(|s| (*s, 1)),
        ) {
            guard_original(original)?;
            if text.len() > self.limits.parameter_bytes {
                return Err(Error::InvalidRequest);
            }
            total = total
                .checked_add(text.len())
                .and_then(|n| n.checked_add(delimiter))
                .ok_or(Error::InvalidRequest)?;
            if total > self.limits.parameter_bytes {
                return Err(Error::InvalidRequest);
            }
        }
        Ok(())
    }
    pub(crate) fn admit(
        &self,
        input: &OidcAuthorizationInput<'_>,
        client: &ClientData,
        original: Instant,
    ) -> Result<PendingFields, Error> {
        self.bound(input, original)?;
        if OidcClientId::parse(input.client_id).map(|id| id.as_str()) != Some(client.id.as_str()) {
            return Err(Error::InvalidClient);
        }
        if input.state.trim().is_empty() || input.state.len() > 512 || input.nonce.trim().is_empty()
        {
            return Err(Error::InvalidRequest);
        }
        if input.prompts.contains(&"none") {
            return Err(if input.prompts.len() == 1 {
                Error::LoginRequired
            } else {
                Error::InvalidRequest
            });
        }
        if input.code_challenge_method != "S256" || !canonical_challenge(input.code_challenge) {
            return Err(Error::InvalidRequest);
        }
        let mut resource = None;
        for value in input.resources {
            guard_original(original)?;
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            if resource.is_some()
                || !valid_resource(value)
                || !self.accepted_resources.iter().any(|r| r == value)
            {
                return Err(Error::InvalidTarget);
            }
            resource = Some(value.to_owned());
        }
        if input.client_id != self.cli_client_id && resource.is_none() {
            return Err(Error::InvalidTarget);
        }
        client.admit_redirect(input.redirect_uri)?;
        let mut scopes = Vec::new();
        for scope in input.scope.split(' ').filter(|s| !s.is_empty()) {
            guard_original(original)?;
            if matches!(
                scope,
                "openid" | "profile" | "email" | "phone" | "address" | "offline_access"
            ) && !scopes.iter().any(|s| s == scope)
            {
                scopes.push(scope.to_owned())
            }
        }
        if !scopes.iter().any(|s| s == "openid") {
            return Err(Error::InvalidScope);
        }
        let filtered_scope = scopes.join(" ");
        drive_sdk(input, &filtered_scope, original)?;
        Ok(PendingFields {
            format: "rust-broker-authorization-v1".into(),
            phase: "pending".into(),
            client_id: input.client_id.into(),
            api_audience: self.api_audience.clone(),
            resource,
            redirect_uri: input.redirect_uri.into(),
            state: input.state.into(),
            scopes,
            response_mode: OidcAuthorizationResponseMode::from_parameter(input.response_mode)
                .as_str()
                .into(),
            nonce: input.nonce.into(),
            code_challenge: input.code_challenge.into(),
            code_challenge_method: input.code_challenge_method.into(),
        })
    }
    pub(crate) fn revalidate(
        &self,
        fields: &PendingFields,
        client: &ClientData,
        original: Instant,
    ) -> Result<(), Error> {
        self.revalidate_phase(fields, client, "pending", original)
    }
    pub(crate) fn revalidate_authorized(
        &self,
        fields: &PendingFields,
        client: &ClientData,
        original: Instant,
    ) -> Result<(), Error> {
        self.revalidate_phase(fields, client, "authorized", original)
    }
    fn revalidate_phase(
        &self,
        fields: &PendingFields,
        client: &ClientData,
        phase: &str,
        original: Instant,
    ) -> Result<(), Error> {
        if fields.format != "rust-broker-authorization-v1"
            || fields.phase != phase
            || fields.api_audience != self.api_audience
        {
            return Err(Error::MalformedStored);
        }
        let scope = fields.scopes.join(" ");
        let resources: Vec<&str> = fields.resource.as_deref().into_iter().collect();
        let input = OidcAuthorizationInput {
            client_id: &fields.client_id,
            redirect_uri: &fields.redirect_uri,
            response_type: "code",
            scope: &scope,
            state: &fields.state,
            nonce: &fields.nonce,
            code_challenge: &fields.code_challenge,
            code_challenge_method: &fields.code_challenge_method,
            response_mode: Some(&fields.response_mode),
            resources: &resources,
            prompts: &[],
        };
        let mut admitted = self.admit(&input, client, original).map_err(|e| match e {
            Error::Control(_) => e,
            _ => Error::MalformedStored,
        })?;
        admitted.phase = phase.into();
        if admitted != *fields {
            return Err(Error::MalformedStored);
        }
        Ok(())
    }
}
/// Borrowed decoded parameters. A transport must reject duplicates of scalar parameters.
pub struct OidcAuthorizationInput<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub response_type: &'a str,
    pub scope: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub response_mode: Option<&'a str>,
    pub resources: &'a [&'a str],
    pub prompts: &'a [&'a str],
}
impl fmt::Debug for OidcAuthorizationInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcAuthorizationInput([REDACTED])")
    }
}
/// Borrowed public client syntax: configured names or the SDK's native opaque ID.
/// Admission still requires the exact current configured/catalog client.
pub(crate) struct OidcClientId<'a>(&'a str);
impl<'a> OidcClientId<'a> {
    pub(crate) fn parse(value: &'a str) -> Option<Self> {
        (safe_identity_segment(value, 128)
            || broker_security::validate_local_auth_challenge(value).is_ok())
        .then_some(Self(value))
    }
    pub(crate) fn as_str(&self) -> &'a str {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcAuthorizationResponseMode {
    Query,
    Fragment,
    FormPost,
}
impl OidcAuthorizationResponseMode {
    fn from_parameter(v: Option<&str>) -> Self {
        match v {
            Some("fragment") => Self::Fragment,
            Some("form_post") => Self::FormPost,
            _ => Self::Query,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::FormPost => "form_post",
        }
    }
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingFields {
    pub(crate) format: String,
    pub(crate) phase: String,
    pub(crate) client_id: String,
    pub(crate) api_audience: String,
    pub(crate) resource: Option<String>,
    pub(crate) redirect_uri: String,
    pub(crate) state: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) response_mode: String,
    pub(crate) nonce: String,
    pub(crate) code_challenge: String,
    pub(crate) code_challenge_method: String,
}
pub(crate) fn parse_pending(raw: &str) -> Result<PendingFields, Error> {
    struct Object;
    impl<'de> Visitor<'de> for Object {
        type Value = PendingFields;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a native pending authorization object")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            PendingFields::deserialize(MapAccessDeserializer::new(map))
        }
    }
    use serde::Deserializer;
    let mut d = serde_json::Deserializer::from_str(raw);
    let fields = d
        .deserialize_map(Object)
        .map_err(|_| Error::MalformedStored)?;
    d.end().map_err(|_| Error::MalformedStored)?;
    Ok(fields)
}
pub struct OidcAuthorizationRequestInfo {
    pub(crate) fields: PendingFields,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
}
impl fmt::Debug for OidcAuthorizationRequestInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcAuthorizationRequestInfo([REDACTED])")
    }
}
impl OidcAuthorizationRequestInfo {
    pub fn client_id(&self) -> &str {
        &self.fields.client_id
    }
    pub fn redirect_uri(&self) -> &str {
        &self.fields.redirect_uri
    }
    pub fn scopes(&self) -> &[String] {
        &self.fields.scopes
    }
    pub fn state(&self) -> &str {
        &self.fields.state
    }
    pub fn nonce(&self) -> &str {
        &self.fields.nonce
    }
    pub fn resource(&self) -> Option<&str> {
        self.fields.resource.as_deref()
    }
    pub fn response_mode(&self) -> OidcAuthorizationResponseMode {
        OidcAuthorizationResponseMode::from_parameter(Some(&self.fields.response_mode))
    }
    pub const fn created_at(&self) -> i64 {
        self.created_at
    }
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}
/// Returned only after known commit and final deadline/UTC gates.
pub struct PendingOidcAuthorization {
    pub(crate) request: Zeroizing<String>,
    pub(crate) info: OidcAuthorizationRequestInfo,
}
impl fmt::Debug for PendingOidcAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingOidcAuthorization([REDACTED])")
    }
}
impl PendingOidcAuthorization {
    pub fn request(&self) -> &str {
        &self.request
    }
    pub const fn info(&self) -> &OidcAuthorizationRequestInfo {
        &self.info
    }
}
pub(crate) fn guard_original(original: Instant) -> Result<(), Error> {
    if Instant::now() >= original {
        Err(ControlError::Deadline.into())
    } else {
        Ok(())
    }
}
fn valid_resource(raw: &str) -> bool {
    raw.len() <= 512
        && !raw.is_empty()
        && !raw.contains('\0')
        && IriAbsoluteStr::new(raw).is_ok()
        && url::Url::parse(raw).is_ok()
}
fn canonical_challenge(raw: &str) -> bool {
    let mut bytes = Zeroizing::new([0u8; 32]);
    raw.len() == 43
        && URL_SAFE_NO_PAD
            .decode_slice(raw, bytes.as_mut())
            .is_ok_and(|n| n == 32)
        && URL_SAFE_NO_PAD.encode(bytes.as_ref()) == raw
}
struct Redirect<'a> {
    uri: &'a IriAbsoluteStr,
    loopback: bool,
    https: bool,
}
fn redirect(raw: &str) -> Result<Redirect<'_>, Error> {
    let uri = IriAbsoluteStr::new(raw).map_err(|_| Error::InvalidRedirect)?;
    url::Url::parse(raw).map_err(|_| Error::InvalidRedirect)?;
    let https = uri.scheme_str().eq_ignore_ascii_case("https");
    if !https && !uri.scheme_str().eq_ignore_ascii_case("http") {
        return Err(Error::InvalidRedirect);
    }
    let auth = uri.authority_components().ok_or(Error::InvalidRedirect)?;
    if auth.userinfo().is_some() || auth.host().is_empty() {
        return Err(Error::InvalidRedirect);
    }
    if let Some(port) = auth.port()
        && port.parse::<u16>().map_err(|_| Error::InvalidRedirect)? == 0
    {
        return Err(Error::InvalidRedirect);
    }
    let host = auth.host();
    let host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    Ok(Redirect {
        uri,
        loopback,
        https,
    })
}
pub(crate) struct ClientData {
    pub(crate) id: String,
    pub(crate) redirects: Vec<String>,
    pub(crate) native: bool,
}
impl ClientData {
    pub(crate) fn validate_registration(&self) -> Result<(), Error> {
        if OidcClientId::parse(&self.id).is_none() || self.redirects.is_empty() {
            return Err(Error::MalformedStored);
        }
        for raw in &self.redirects {
            if raw.trim() != raw || raw.is_empty() {
                return Err(Error::MalformedStored);
            }
            let r = redirect(raw).map_err(|_| Error::MalformedStored)?;
            if (!r.https && !r.loopback) || (r.https && r.loopback) {
                return Err(Error::MalformedStored);
            }
        }
        let saw_https = self
            .redirects
            .iter()
            .any(|uri| redirect(uri).is_ok_and(|r| r.https));
        if self.native == saw_https {
            return Err(Error::MalformedStored);
        }
        Ok(())
    }
    pub(crate) fn admit_redirect(&self, raw: &str) -> Result<(), Error> {
        let requested = redirect(raw)?;
        let accepted = if self.native && requested.loopback {
            self.redirects.iter().any(|s| {
                redirect(s).is_ok_and(|registered| {
                    registered.loopback
                        && percent_encoding::percent_decode_str(registered.uri.path_str())
                            .collect::<Vec<u8>>()
                            == percent_encoding::percent_decode_str(requested.uri.path_str())
                                .collect::<Vec<u8>>()
                        && registered.uri.query_str().unwrap_or("")
                            == requested.uri.query_str().unwrap_or("")
                })
            })
        } else {
            !self.native && self.redirects.iter().any(|s| s == raw)
        };
        if accepted {
            Ok(())
        } else {
            Err(Error::InvalidRedirect)
        }
    }
}
struct SdkRequest<'a> {
    input: &'a OidcAuthorizationInput<'a>,
    scope: &'a str,
}
impl Request for SdkRequest<'_> {
    fn valid(&self) -> bool {
        true
    }
    fn client_id(&self) -> Option<Cow<'_, str>> {
        Some(Cow::Borrowed(self.input.client_id))
    }
    fn scope(&self) -> Option<Cow<'_, str>> {
        Some(Cow::Borrowed(self.scope))
    }
    fn redirect_uri(&self) -> Option<Cow<'_, str>> {
        Some(Cow::Borrowed(self.input.redirect_uri))
    }
    fn state(&self) -> Option<Cow<'_, str>> {
        Some(Cow::Borrowed(self.input.state))
    }
    fn response_type(&self) -> Option<Cow<'_, str>> {
        Some(Cow::Borrowed(self.input.response_type))
    }
    fn extension(&self, key: &str) -> Option<Cow<'_, str>> {
        match key {
            "code_challenge" => Some(Cow::Borrowed(self.input.code_challenge)),
            "code_challenge_method" => Some(Cow::Borrowed(self.input.code_challenge_method)),
            _ => None,
        }
    }
}
/// Adapter over an already admitted current client. ExactUrl preserves the request literal.
struct AdmittedRegistrar<'a> {
    id: &'a str,
    redirect: &'a str,
}
impl Registrar for AdmittedRegistrar<'_> {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        let r = bound.redirect_uri.ok_or(RegistrarError::Unspecified)?;
        if bound.client_id != self.id || r.as_str() != self.redirect {
            return Err(RegistrarError::Unspecified);
        }
        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: Cow::Owned(RegisteredUrl::Exact(r.into_owned())),
        })
    }
    fn negotiate(
        &self,
        bound: BoundClient<'_>,
        scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        Ok(PreGrant {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            scope: scope.ok_or(RegistrarError::Unspecified)?,
        })
    }
    fn check(&self, id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        if id == self.id && passphrase.is_none() {
            Ok(())
        } else {
            Err(RegistrarError::Unspecified)
        }
    }
}
fn drive_sdk(
    input: &OidcAuthorizationInput<'_>,
    scope: &str,
    original: Instant,
) -> Result<(), Error> {
    let request = SdkRequest { input, scope };
    let registrar = AdmittedRegistrar {
        id: input.client_id,
        redirect: input.redirect_uri,
    };
    let pkce = Pkce::required();
    let mut machine = authorization::Authorization::new(&request);
    let mut next = authorization::Input::None;
    loop {
        guard_original(original)?;
        next = match machine.advance(next) {
            authorization::Output::Bind {
                client_id,
                redirect_uri,
            } => authorization::Input::Bound {
                request: &request,
                bound_client: registrar
                    .bound_redirect(ClientUrl {
                        client_id: Cow::Owned(client_id),
                        redirect_uri: redirect_uri.map(Cow::Owned),
                    })
                    .map_err(|_| Error::InvalidRedirect)?,
            },
            authorization::Output::Extend => {
                let challenge = pkce
                    .challenge(
                        request.extension("code_challenge_method"),
                        request.extension("code_challenge"),
                    )
                    .map_err(|_| Error::InvalidRequest)?
                    .ok_or(Error::InvalidRequest)?;
                let mut extensions = Extensions::new();
                extensions.set(&pkce, challenge);
                authorization::Input::Extended(extensions)
            }
            authorization::Output::Negotiate {
                bound_client,
                scope,
            } => authorization::Input::Negotiated {
                pre_grant: registrar
                    .negotiate(bound_client.clone(), scope)
                    .map_err(|_| Error::InvalidScope)?,
                state: Some(input.state.to_owned()),
            },
            authorization::Output::Ok { pre_grant, .. } => {
                let exact: ExactUrl = input
                    .redirect_uri
                    .parse()
                    .map_err(|_| Error::InvalidRedirect)?;
                if pre_grant.client_id != input.client_id
                    || pre_grant.redirect_uri != RegisteredUrl::Exact(exact)
                {
                    return Err(Error::InvalidRequest);
                }
                return Ok(());
            }
            authorization::Output::Err(_) => return Err(Error::InvalidRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn n(v: usize) -> NonZeroUsize {
        NonZeroUsize::new(v).unwrap()
    }
    fn config(ttl: u64) -> OidcAuthorizationConfiguration {
        OidcAuthorizationConfiguration {
            cli_client_id: "graphit-cli".into(),
            cli_redirect_path: "/oauth/callback".into(),
            api_audience: "graphit-broker".into(),
            accepted_resources: vec![
                " https://broker.example/v1 ".into(),
                "https://broker.example/v1".into(),
            ],
            dynamic_registration: true,
            authorization_ttl: Duration::from_secs(ttl),
        }
    }
    fn policy() -> OidcAuthorizationPolicy {
        OidcAuthorizationPolicy::new(
            config(60),
            OidcAuthorizationLimits::new(n(4096), n(8192)).unwrap(),
        )
        .unwrap()
    }
    fn input() -> OidcAuthorizationInput<'static> {
        OidcAuthorizationInput {
            client_id: "graphit-cli",
            redirect_uri: "http://127.0.0.1:49152/oauth/callback",
            response_type: "code",
            scope: "openid profile email phone address offline_access custom profile",
            state: " state ",
            nonce: " nonce ",
            code_challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            code_challenge_method: "S256",
            response_mode: None,
            resources: &[],
            prompts: &[],
        }
    }
    fn admit(i: &OidcAuthorizationInput<'_>) -> Result<PendingFields, Error> {
        let p = policy();
        let c = ClientData {
            id: p.cli_client_id.clone(),
            redirects: vec![p.cli_redirect.clone()],
            native: true,
        };
        p.admit(i, &c, Instant::now() + Duration::from_secs(2))
    }
    #[test]
    fn public_client_ids_keep_every_sdk_base64url_leading_byte() {
        let policy = policy();
        for first in 0u8..=255 {
            let mut bytes = [0u8; 32];
            bytes[0] = first;
            let id = URL_SAFE_NO_PAD.encode(bytes);
            assert_eq!(OidcClientId::parse(&id).unwrap().as_str(), id);
            let client = ClientData {
                id: id.clone(),
                redirects: vec!["https://client.example/cb".into()],
                native: false,
            };
            client.validate_registration().unwrap();
            let mut request = input();
            request.client_id = &id;
            request.redirect_uri = "https://client.example/cb";
            request.resources = &["https://broker.example/v1"];
            assert_eq!(
                policy
                    .admit(&request, &client, Instant::now() + Duration::from_secs(2))
                    .unwrap()
                    .client_id,
                id
            );
        }
        for id in ["graphit-cli", "web-client", "Client_1"] {
            assert_eq!(OidcClientId::parse(id).unwrap().as_str(), id);
        }
        let mut bytes = [0u8; 32];
        bytes[0] = 248;
        let id = URL_SAFE_NO_PAD.encode(bytes);
        let bad_tail = format!("{}B", &id[..42]);
        for invalid in [
            "".to_owned(),
            "-short".to_owned(),
            format!("{id}="),
            bad_tail,
            id.replace('-', "+"),
            "a".repeat(129),
        ] {
            assert!(OidcClientId::parse(&invalid).is_none());
        }
    }

    #[test]
    fn explicit_configuration_limits_and_original_deadline() {
        for ttl in [30, 60, 600] {
            assert!(
                OidcAuthorizationPolicy::new(
                    config(ttl),
                    OidcAuthorizationLimits::new(n(4096), n(8192)).unwrap()
                )
                .is_ok()
            )
        }
        for ttl in [0, 29, 601, u64::MAX] {
            assert!(matches!(
                OidcAuthorizationPolicy::new(
                    config(ttl),
                    OidcAuthorizationLimits::new(n(4096), n(8192)).unwrap()
                ),
                Err(Error::InvalidConfiguration)
            ))
        }
        assert!(matches!(
            OidcAuthorizationLimits::new(n(usize::MAX), n(1)),
            Err(Error::InvalidLimits)
        ));
        assert!(matches!(
            OidcAuthorizationLimits::new(n(1), n(usize::MAX)),
            Err(Error::InvalidLimits)
        ));
        for path in ["callback", "/callback?x", "/callback#x"] {
            let mut c = config(60);
            c.cli_redirect_path = path.into();
            assert!(matches!(
                OidcAuthorizationPolicy::new(
                    c,
                    OidcAuthorizationLimits::new(n(4096), n(8192)).unwrap()
                ),
                Err(Error::InvalidConfiguration)
            ))
        }
        for resource in ["relative", "https://broker.example/v1#x", ""] {
            let mut c = config(60);
            c.accepted_resources = vec![resource.into()];
            assert!(matches!(
                OidcAuthorizationPolicy::new(
                    c,
                    OidcAuthorizationLimits::new(n(4096), n(8192)).unwrap()
                ),
                Err(Error::InvalidConfiguration)
            ))
        }
        assert_eq!(policy().accepted_resources, ["https://broker.example/v1"]);
        let p = policy();
        assert_eq!(
            p.bound(&input(), Instant::now()).unwrap_err(),
            Error::Control(ControlError::Deadline)
        );
        let mut p = policy();
        let i = input();
        let bytes = [
            i.client_id,
            i.redirect_uri,
            i.response_type,
            i.scope,
            i.state,
            i.nonce,
            i.code_challenge,
            i.code_challenge_method,
        ]
        .iter()
        .map(|s| s.len())
        .sum();
        p.limits.parameter_bytes = bytes;
        assert!(p.bound(&i, Instant::now() + Duration::from_secs(2)).is_ok());
        let mut i = i;
        i.resources = &[""];
        assert_eq!(
            p.bound(&i, Instant::now() + Duration::from_secs(2))
                .unwrap_err(),
            Error::InvalidRequest
        );
        i.resources = &[];
        i.prompts = &[""];
        assert_eq!(
            p.bound(&i, Instant::now() + Duration::from_secs(2))
                .unwrap_err(),
            Error::InvalidRequest
        );
        p.limits.parameter_bytes = bytes - 1;
        i.prompts = &[];
        assert_eq!(
            p.bound(&i, Instant::now() + Duration::from_secs(2))
                .unwrap_err(),
            Error::InvalidRequest
        );
    }
    #[test]
    fn real_sdk_scopes_pkce_modes_state_nonce_prompts_and_resources() {
        let fields = admit(&input()).unwrap();
        assert_eq!(
            fields.scopes,
            [
                "openid",
                "profile",
                "email",
                "phone",
                "address",
                "offline_access"
            ]
        );
        assert_eq!(fields.state, " state ");
        assert_eq!(fields.nonce, " nonce ");
        assert_eq!(fields.response_mode, "query");
        for (mode, expected) in [
            ("query", "query"),
            ("fragment", "fragment"),
            ("form_post", "form_post"),
            ("unknown", "query"),
        ] {
            let mut i = input();
            i.response_mode = Some(mode);
            assert_eq!(admit(&i).unwrap().response_mode, expected)
        }
        for method in ["plain", "s256", ""] {
            let mut i = input();
            i.code_challenge_method = method;
            assert_eq!(admit(&i).err(), Some(Error::InvalidRequest))
        }
        for challenge in [
            "",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let mut i = input();
            i.code_challenge = challenge;
            assert_eq!(admit(&i).err(), Some(Error::InvalidRequest))
        }
        for response in ["token", "id_token", "code token", ""] {
            let mut i = input();
            i.response_type = response;
            assert_eq!(admit(&i).err(), Some(Error::InvalidRequest))
        }
        for scope in ["", "email unknown", "OPENID"] {
            let mut i = input();
            i.scope = scope;
            assert_eq!(admit(&i).err(), Some(Error::InvalidScope))
        }
        let mut i = input();
        i.prompts = &["none"];
        assert_eq!(admit(&i).err(), Some(Error::LoginRequired));
        i.prompts = &["none", "login"];
        assert_eq!(admit(&i).err(), Some(Error::InvalidRequest));
        i.prompts = &["login", "consent"];
        assert!(admit(&i).is_ok());
        let mut i = input();
        let state = "s".repeat(512);
        i.state = &state;
        assert!(admit(&i).is_ok());
        let state = "s".repeat(513);
        i.state = &state;
        assert_eq!(admit(&i).err(), Some(Error::InvalidRequest));
        for field in ["", " \t "] {
            let mut i = input();
            i.state = field;
            assert_eq!(admit(&i).err(), Some(Error::InvalidRequest));
            i = input();
            i.nonce = field;
            assert_eq!(admit(&i).err(), Some(Error::InvalidRequest))
        }
        let mut i = input();
        i.resources = &["", " https://broker.example/v1 ", ""];
        assert_eq!(
            admit(&i).unwrap().resource.as_deref(),
            Some("https://broker.example/v1")
        );
        for resources in [
            &["https://broker.example/v1", "https://broker.example/v1"][..],
            &["https://broker.example/v1#x"],
            &["https://other.example/v1"],
            &["relative"],
        ] {
            i.resources = resources;
            assert_eq!(admit(&i).err(), Some(Error::InvalidTarget))
        }
        let p = policy();
        let c = ClientData {
            id: "native-client".into(),
            redirects: vec![p.cli_redirect.clone()],
            native: true,
        };
        i = input();
        i.client_id = "native-client";
        assert_eq!(
            p.admit(&i, &c, Instant::now() + Duration::from_secs(2))
                .err(),
            Some(Error::InvalidTarget)
        );
        i.resources = &["https://broker.example/v1"];
        assert!(
            p.admit(&i, &c, Instant::now() + Duration::from_secs(2))
                .is_ok()
        );
    }
    #[test]
    fn original_uri_matching_rejects_normalization_widening() {
        for uri in [
            "http://localhost:49153/oauth/callback",
            "https://127.0.0.2:49153/oauth/callback",
            "http://[::1]:49153/oauth/callback",
            "http://127.0.0.1:49152/oauth/callback?",
        ] {
            let mut i = input();
            i.redirect_uri = uri;
            assert!(admit(&i).is_ok(), "{uri}")
        }
        for uri in [
            "http://127.1:49152/oauth/callback",
            "http://0x7f000001:49152/oauth/callback",
            "http://0177.0.0.1:49152/oauth/callback",
            "http://localhost:0/oauth/callback",
            "http://example.com/oauth/callback",
            "http://localhost/oauth/../oauth/callback",
            "http://localhost/other",
            "http://localhost/oauth/callback?q=x",
            "http://user@localhost/oauth/callback",
            "http://localhost/oauth/callback#x",
        ] {
            let mut i = input();
            i.redirect_uri = uri;
            assert_eq!(admit(&i).err(), Some(Error::InvalidRedirect), "{uri}")
        }
        for (registered, requested, expected) in [
            ("http://127.0.0.1/café", "https://localhost/caf%C3%A9", true),
            ("http://127.0.0.1/%FF", "https://localhost/%ff", true),
            ("http://127.0.0.1/a+b", "https://localhost/a%2Bb", true),
            ("http://127.0.0.1/a+b", "https://localhost/a%20b", false),
            ("http://127.0.0.1/a/../b", "https://localhost/b", false),
            (
                "http://127.0.0.1/cb?q=é",
                "https://localhost/cb?q=%C3%A9",
                false,
            ),
            (
                "http://127.0.0.1/cb?q=%2f",
                "https://localhost/cb?q=%2F",
                false,
            ),
            ("http://127.0.0.1/cb?", "https://localhost/cb", true),
        ] {
            let c = ClientData {
                id: "native".into(),
                redirects: vec![registered.into()],
                native: true,
            };
            assert_eq!(
                c.admit_redirect(requested).is_ok(),
                expected,
                "{registered} → {requested}"
            )
        }
        let c = ClientData {
            id: "web".into(),
            redirects: vec!["https://client.example/callback?q=x".into()],
            native: false,
        };
        assert!(
            c.admit_redirect("https://client.example/callback?q=x")
                .is_ok()
        );
        for raw in [
            "https://CLIENT.example/callback?q=x",
            "https://client.example:443/callback?q=x",
            "https://client.example/callback/?q=x",
            "https://client.example/callback?q=%78",
            "http://client.example/callback?q=x",
        ] {
            assert_eq!(c.admit_redirect(raw), Err(Error::InvalidRedirect))
        }
    }

    #[test]
    fn mixed_web_catalog_admits_only_registered_literals() {
        let c = ClientData {
            id: "mixed".into(),
            redirects: vec![
                "https://client.example/cb?q=%2F".into(),
                "http://localhost:8123/cb?q=x".into(),
            ],
            native: false,
        };
        c.validate_registration().unwrap();
        for raw in &c.redirects {
            c.admit_redirect(raw).unwrap();
        }
        for raw in [
            "http://localhost:8124/cb?q=x",
            "http://127.0.0.1:8123/cb?q=x",
            "http://LOCALHOST:8123/cb?q=x",
            "http://localhost:8123/other?q=x",
            "http://localhost:8123/cb?q=%78",
            "https://client.example/cb?q=%2f",
            "https://client.example:443/cb?q=%2F",
        ] {
            assert_eq!(c.admit_redirect(raw), Err(Error::InvalidRedirect), "{raw}");
        }
    }
    #[test]
    fn strict_native_object_codec_and_revalidation() {
        let fields = admit(&input()).unwrap();
        let json = serde_json::to_string(&fields).unwrap();
        assert!(parse_pending(&json).is_ok());
        for raw in ["[]", "{}", "null", "1"] {
            assert_eq!(parse_pending(raw).err(), Some(Error::MalformedStored))
        }
        for raw in [
            format!("{json} {{}}"),
            json.replacen('{', "{\"extra\":1,", 1),
            json.replacen('{', "{\"phase\":\"pending\",", 1),
            serde_json::to_string(
                &serde_json::from_str::<serde_json::Value>(&json)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .values()
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        ] {
            assert_eq!(parse_pending(&raw).err(), Some(Error::MalformedStored))
        }
        let p = policy();
        let c = ClientData {
            id: p.cli_client_id.clone(),
            redirects: vec![p.cli_redirect.clone()],
            native: true,
        };
        for (field, value) in [
            ("format", "go"),
            ("phase", "authorized"),
            ("api_audience", "other"),
            ("response_mode", "unknown"),
            ("code_challenge_method", "plain"),
        ] {
            let mut v = serde_json::from_str::<serde_json::Value>(&json).unwrap();
            v[field] = value.into();
            let f = parse_pending(&v.to_string()).unwrap();
            assert_eq!(
                p.revalidate(&f, &c, Instant::now() + Duration::from_secs(2)),
                Err(Error::MalformedStored)
            )
        }
    }
}
