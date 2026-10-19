//! Shared browser transport for genuine upstream Admin and OAuth flows.
use super::oauth_response::{OAuthResponseRenderer, privacy_headers};
use super::{AdminCookieHttpConfig, admin_cookie_header};
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::{MethodFilter, on},
};
use broker_control::{
    AdminCookieSessionError, ControlError, FlowContinuation, FlowPurpose,
    IssuedUpstreamAuthorization, OidcAuthorizationError, OidcAuthorizationPolicy,
    PostgresControlStore, SqliteControlStore, UpstreamBearerVerifier, UpstreamLoginCallback,
    UpstreamLoginError, UpstreamLoginFailure, upstream_login_purpose_hint,
};
use headers::{Cookie, Expires, Header};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
pub struct AdminUpstreamLoginHttpConfig {
    pub response_json_bytes: NonZeroUsize,
    pub request_timeout: Duration,
    pub cookie: Option<AdminCookieHttpConfig>,
}
pub struct OidcUpstreamLoginHttpConfig {
    pub authorization: Arc<OidcAuthorizationPolicy>,
    pub request_timeout: Duration,
}
pub struct UpstreamLoginHttpConfig {
    /// Aggregate raw query and all Cookie bytes before decoding or SQL.
    pub input_bytes: NonZeroUsize,
    /// Existing CookieSecure policy, independent of an administrative session.
    pub cookie_secure: bool,
    pub administration: Option<AdminUpstreamLoginHttpConfig>,
    pub oidc: Option<OidcUpstreamLoginHttpConfig>,
}
enum LoginBackend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
struct LoginState {
    store: LoginBackend,
    verifier: Option<Arc<UpstreamBearerVerifier>>,
    config: UpstreamLoginHttpConfig,
    renderer: Option<OAuthResponseRenderer>,
}
pub fn upstream_login_router(
    store: Arc<PostgresControlStore>,
    verifier: Option<Arc<UpstreamBearerVerifier>>,
    config: UpstreamLoginHttpConfig,
) -> Result<Router, ControlError> {
    login_router(LoginBackend::Postgres(store), verifier, config)
}
/// Compose the shared Admin/OAuth callback with genuine SQLite H1 and H2 owners.
pub fn sqlite_upstream_login_router(
    store: Arc<SqliteControlStore>,
    verifier: Option<Arc<UpstreamBearerVerifier>>,
    config: UpstreamLoginHttpConfig,
) -> Result<Router, ControlError> {
    login_router(LoginBackend::Sqlite(store), verifier, config)
}
fn login_router(
    store: LoginBackend,
    verifier: Option<Arc<UpstreamBearerVerifier>>,
    config: UpstreamLoginHttpConfig,
) -> Result<Router, ControlError> {
    let valid_timeout =
        |timeout: Duration| !timeout.is_zero() && Instant::now().checked_add(timeout).is_some();
    if isize::try_from(config.input_bytes.get()).is_err() {
        return Err(ControlError::Configuration);
    }
    if let Some(admin) = config.administration {
        if !valid_timeout(admin.request_timeout)
            || isize::try_from(admin.response_json_bytes.get()).is_err()
        {
            return Err(ControlError::Configuration);
        }
        if let Some(cookie) = admin.cookie {
            if cookie.secure != config.cookie_secure {
                return Err(ControlError::Configuration);
            }
            cookie.validate()?;
            match &store {
                LoginBackend::Postgres(store) => {
                    store.admin_cookie_sessions(
                        cookie.limits,
                        cookie.policy,
                        verifier.as_deref(),
                    )?;
                }
                LoginBackend::Sqlite(store) => {
                    store.admin_cookie_sessions(cookie.limits, cookie.policy, verifier.clone())?;
                }
            }
        }
    }
    let renderer = if let Some(oidc) = config.oidc.as_ref() {
        if !valid_timeout(oidc.request_timeout) {
            return Err(ControlError::Configuration);
        }
        Some(OAuthResponseRenderer::new().map_err(|_| ControlError::Configuration)?)
    } else {
        None
    };
    let mut router = Router::new();
    if config.administration.is_some() {
        router = router.route("/admin/auth/login", on(MethodFilter::GET, begin));
    }
    if config.administration.is_some() || config.oidc.is_some() {
        router = router.route("/oauth/oidc/callback", on(MethodFilter::GET, callback));
    }
    Ok(router.with_state(Arc::new(LoginState {
        store,
        verifier,
        config,
        renderer,
    })))
}
enum LoginError {
    Control(ControlError),
    Input,
    State,
    Provider,
    Unavailable,
    Consumed(&'static str),
}
impl From<ControlError> for LoginError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
fn gate(original: Instant) -> Result<(), LoginError> {
    if Instant::now() >= original {
        Err(ControlError::Deadline.into())
    } else {
        Ok(())
    }
}
fn ingress(request: &axum::http::request::Parts, cap: usize) -> Result<(), LoginError> {
    let bytes = request
        .headers
        .get_all(header::COOKIE)
        .iter()
        .try_fold(request.uri.query().map_or(0, str::len), |sum, value| {
            sum.checked_add(value.as_bytes().len())
        })
        .ok_or(LoginError::Input)?;
    if bytes > cap {
        return Err(LoginError::Input);
    }
    Ok(())
}
/// Cookie-name DATA only; possession of a name proves no flow or login.
pub fn upstream_login_flow_cookie_name(state: &str, secure: bool) -> String {
    let mut name = String::from(if secure {
        "__Host-graphit_oidc_flow_"
    } else {
        "graphit_oidc_flow_"
    });
    for byte in Sha256::digest(state.as_bytes()) {
        write!(name, "{byte:02x}").expect("String write");
    }
    name
}
fn flow_cookie(
    name: &str,
    binding: &str,
    expiry: SystemTime,
    seconds: u64,
    secure: bool,
) -> Result<HeaderValue, ControlError> {
    let mut values = Vec::new();
    Expires::from(expiry).encode(&mut values);
    let date = values
        .first()
        .and_then(|v| v.to_str().ok())
        .ok_or(ControlError::Clock)?;
    let mut value = HeaderValue::from_str(&format!(
        "{name}={binding}; Path=/; HttpOnly; SameSite=Lax; Expires={date}; Max-Age={seconds}{}",
        if secure { "; Secure" } else { "" }
    ))
    .map_err(|_| ControlError::InvalidFlow)?;
    value.set_sensitive(true);
    Ok(value)
}
/// Encode the genuine issued flow without renewing its expiry or Original.
pub fn upstream_login_flow_cookie(
    issued: &IssuedUpstreamAuthorization,
    secure: bool,
) -> Result<HeaderValue, ControlError> {
    issued.check()?;
    let remaining = issued
        .expires_at()
        .duration_since(SystemTime::now())
        .map_err(|_| ControlError::Expired)?
        .as_secs();
    let value = flow_cookie(
        &upstream_login_flow_cookie_name(issued.state(), secure),
        issued.browser_binding(),
        issued.expires_at(),
        remaining,
        secure,
    )?;
    issued.check()?;
    Ok(value)
}
fn binding(headers: &HeaderMap, name: &str) -> Result<Zeroizing<String>, LoginError> {
    let values = headers.get_all(header::COOKIE);
    if values.iter().count() != 1 {
        return Err(LoginError::State);
    }
    let cookies = Cookie::decode(&mut values.iter()).map_err(|_| LoginError::State)?;
    let mut matches = cookies.iter().filter(|(key, _)| *key == name);
    let (_, value) = matches.next().ok_or(LoginError::State)?;
    if matches.next().is_some() || value.is_empty() {
        return Err(LoginError::State);
    }
    Ok(Zeroizing::new(value.to_owned()))
}
fn redirect(
    location: &str,
    status: StatusCode,
    id: &str,
    cap: usize,
    original: Instant,
) -> Result<Response, LoginError> {
    gate(original)?;
    if location.len() > cap {
        return Err(ControlError::IdentityLimitExceeded.into());
    }
    let location = HeaderValue::from_str(location).map_err(|_| ControlError::InvalidFlow)?;
    let mut response = super::admin_session::response(status, Vec::new(), id);
    response.headers_mut().remove(header::CONTENT_TYPE);
    response.headers_mut().insert(header::LOCATION, location);
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    gate(original)?;
    Ok(response)
}
fn upstream_error(error: UpstreamLoginError) -> LoginError {
    let admin = matches!(error.continuation(), Some(FlowContinuation::Admin { .. }));
    match error.failure() {
        UpstreamLoginFailure::Control(ControlError::Expired | ControlError::InvalidFlow)
            if admin =>
        {
            LoginError::Consumed("invalid_state")
        }
        UpstreamLoginFailure::Control(error) => LoginError::Control(error),
        UpstreamLoginFailure::InvalidProvider if admin => LoginError::Consumed("invalid_identity"),
        UpstreamLoginFailure::InvalidProvider => LoginError::Provider,
        UpstreamLoginFailure::InvalidIdentity if admin => LoginError::Consumed("invalid_identity"),
        UpstreamLoginFailure::ProviderError if admin => LoginError::Consumed("oidc_error"),
        UpstreamLoginFailure::InvalidState if admin => LoginError::Consumed("invalid_state"),
        _ => LoginError::State,
    }
}
fn cookie_error(error: AdminCookieSessionError) -> LoginError {
    match error {
        AdminCookieSessionError::Control(ControlError::SessionExpired | ControlError::Expired) => {
            LoginError::Consumed("invalid_state")
        }
        AdminCookieSessionError::Control(error) => LoginError::Control(error),
        AdminCookieSessionError::Forbidden | AdminCookieSessionError::CsrfFailed => {
            LoginError::Consumed("admin_forbidden")
        }
        AdminCookieSessionError::Entropy => LoginError::Unavailable,
        _ => LoginError::Consumed("invalid_identity"),
    }
}
fn error_response(error: LoginError, id: &str, cap: usize, original: Instant) -> Response {
    if let LoginError::Control(error) = error {
        return super::admin_session::failure(error.into(), id);
    }
    if let LoginError::Consumed(code) = error {
        // Form encoding prevents request ID characters from becoming fragment fields.
        let fragment = form_urlencoded::Serializer::new(String::new())
            .append_pair("login_error", code)
            .append_pair("request_id", id)
            .finish();
        return match redirect(
            &format!("/admin/#{fragment}"),
            StatusCode::SEE_OTHER,
            id,
            cap,
            original,
        ) {
            Ok(value) => value,
            Err(LoginError::Control(error)) => super::admin_session::failure(error.into(), id),
            _ => super::admin_session::failure(ControlError::Configuration.into(), id),
        };
    }
    plain_error_response(error, id, Some(cap), Some(original))
}
fn plain_error_response(
    error: LoginError,
    id: &str,
    cap: Option<usize>,
    original: Option<Instant>,
) -> Response {
    if let LoginError::Control(error) = error {
        return super::admin_session::failure(error.into(), id);
    }
    let (status, code, message) = match error {
        LoginError::State => (
            StatusCode::UNAUTHORIZED,
            "invalid_state",
            "Invalid browser login state",
        ),
        LoginError::Provider => (
            StatusCode::BAD_REQUEST,
            "provider_required",
            "Choose a valid OIDC login provider",
        ),
        LoginError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "administration_unavailable",
            "OIDC browser login is unavailable",
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid browser login request",
        ),
    };
    let bytes = serde_json::json!({"error":{"code":code,"message":message},"request_id":id})
        .to_string()
        .into_bytes();
    if cap.is_some_and(|cap| bytes.len() > cap) {
        return super::admin_session::failure(ControlError::IdentityLimitExceeded.into(), id);
    }
    if original.is_some_and(|original| Instant::now() >= original) {
        return super::admin_session::failure(ControlError::Deadline.into(), id);
    }
    super::admin_session::response(status, bytes, id)
}
async fn begin(State(state): State<Arc<LoginState>>, request: Request) -> Response {
    if request.method() != axum::http::Method::GET {
        return super::admin_session::response(StatusCode::METHOD_NOT_ALLOWED, Vec::new(), "");
    }
    let start = Instant::now();
    let request = request.into_parts().0;
    let id = match super::admin_session::request_id(&request.headers) {
        Ok(id) => id,
        Err(error) => return super::admin_session::failure(error, ""),
    };
    let Some(admin) = state.config.administration else {
        return plain_error_response(LoginError::Unavailable, &id, None, None);
    };
    let Some(original) = start.checked_add(admin.request_timeout) else {
        return super::admin_session::failure(ControlError::Configuration.into(), &id);
    };
    let result = async {
        gate(original)?;
        ingress(&request, state.config.input_bytes.get())?;
        let cookie = admin.cookie.ok_or(LoginError::Unavailable)?;
        let verifier = state.verifier.as_deref().ok_or(LoginError::Unavailable)?;
        if verifier.browser_options(original)?.is_empty() {
            return Err(LoginError::Unavailable);
        }
        let mut provider = None;
        for (key, value) in form_urlencoded::parse(request.uri.query().unwrap_or("").as_bytes()) {
            if key == "provider" {
                if provider.is_some() {
                    return Err(LoginError::Provider);
                }
                provider = Some(value.into_owned());
            }
        }
        let provider_id = provider
            .filter(|s| !s.is_empty())
            .ok_or(LoginError::Provider)?;
        let continuation = FlowContinuation::Admin { provider_id };
        let issued = match &state.store {
            LoginBackend::Postgres(store) => {
                store
                    .upstream_logins(verifier)
                    .begin(continuation, original)
                    .await
            }
            LoginBackend::Sqlite(store) => {
                store
                    .upstream_logins(verifier)
                    .begin(continuation, original)
                    .await
            }
        }
        .map_err(upstream_error)?;
        let binding = upstream_login_flow_cookie(&issued, cookie.secure)?;
        let mut response = redirect(
            issued.location().as_str(),
            StatusCode::FOUND,
            &id,
            admin.response_json_bytes.get(),
            original,
        )?;
        issued.check()?;
        response.headers_mut().append(header::SET_COOKIE, binding);
        Ok(response)
    }
    .await;
    match result {
        Ok(value) => value,
        Err(error) => error_response(error, &id, admin.response_json_bytes.get(), original),
    }
}
struct CallbackInput {
    flow: Zeroizing<String>,
    code: Option<Zeroizing<String>>,
    provider_error: bool,
}
fn parse_callback(query: &str) -> Result<CallbackInput, LoginError> {
    let (mut flow, mut code, mut provider_error) = (None, None, false);
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "state" => {
                if flow.is_some() {
                    return Err(LoginError::State);
                }
                flow = Some(Zeroizing::new(value.into_owned()));
            }
            "code" => {
                if code.is_some() {
                    return Err(LoginError::State);
                }
                code = Some(Zeroizing::new(value.into_owned()));
            }
            "error" => {
                if provider_error {
                    return Err(LoginError::State);
                }
                provider_error = true;
            }
            _ => {}
        }
    }
    Ok(CallbackInput {
        flow: flow.ok_or(LoginError::State)?,
        code,
        provider_error,
    })
}
fn authorization_error(error: OidcAuthorizationError) -> LoginError {
    match error {
        OidcAuthorizationError::Control(error) => LoginError::Control(error),
        OidcAuthorizationError::InvalidRequest => LoginError::Input,
        OidcAuthorizationError::InvalidClient
        | OidcAuthorizationError::InvalidRedirect
        | OidcAuthorizationError::InvalidLogin => LoginError::State,
        OidcAuthorizationError::ReadLimitExceeded => {
            LoginError::Control(ControlError::IdentityLimitExceeded)
        }
        _ => LoginError::Control(ControlError::Storage),
    }
}
fn callback_failure(
    state: &LoginState,
    purpose: Option<FlowPurpose>,
    error: LoginError,
    id: &str,
    original: Option<Instant>,
) -> Response {
    let mut response = match (purpose, state.config.administration, original) {
        (Some(FlowPurpose::Admin), Some(admin), Some(original)) => {
            error_response(error, id, admin.response_json_bytes.get(), original)
        }
        _ => plain_error_response(error, id, None, original),
    };
    privacy_headers(&mut response);
    response
}
async fn callback(State(state): State<Arc<LoginState>>, request: Request) -> Response {
    if request.method() != axum::http::Method::GET {
        let mut response =
            super::admin_session::response(StatusCode::METHOD_NOT_ALLOWED, Vec::new(), "");
        privacy_headers(&mut response);
        return response;
    }
    let arrival = Instant::now();
    let request = request.into_parts().0;
    let id = match super::admin_session::request_id(&request.headers) {
        Ok(id) => id,
        Err(error) => {
            let mut response = super::admin_session::failure(error, "");
            privacy_headers(&mut response);
            return response;
        }
    };
    if let Err(error) = ingress(&request, state.config.input_bytes.get()) {
        return callback_failure(&state, None, error, &id, None);
    }
    let input = match parse_callback(request.uri.query().unwrap_or("")) {
        Ok(input) => input,
        Err(error) => return callback_failure(&state, None, error, &id, None),
    };
    // This bounded local hint selects only the budget. SQL proves the actual purpose.
    let Some(purpose) = upstream_login_purpose_hint(&input.flow) else {
        return callback_failure(&state, None, LoginError::State, &id, None);
    };
    let timeout = match purpose {
        FlowPurpose::Admin => state
            .config
            .administration
            .map(|admin| admin.request_timeout),
        FlowPurpose::OAuth => state.config.oidc.as_ref().map(|oidc| oidc.request_timeout),
    };
    let Some(original) = timeout.and_then(|timeout| arrival.checked_add(timeout)) else {
        return callback_failure(&state, Some(purpose), LoginError::State, &id, None);
    };
    let mut clear = None;
    let result = async {
        gate(original)?;
        if purpose == FlowPurpose::Admin
            && state
                .config
                .administration
                .and_then(|admin| admin.cookie)
                .is_none()
        {
            return Err(LoginError::Unavailable);
        }
        let verifier = state.verifier.as_ref().ok_or(LoginError::Unavailable)?;
        let name = upstream_login_flow_cookie_name(&input.flow, state.config.cookie_secure);
        let binding = binding(&request.headers, &name)?;
        let callback = match input.code.as_deref().filter(|code| !code.is_empty()) {
            Some(code) if !input.provider_error => UpstreamLoginCallback::Code(code),
            _ => UpstreamLoginCallback::ProviderError,
        };
        let completed = match &state.store {
            LoginBackend::Postgres(store) => {
                store
                    .upstream_logins(verifier)
                    .complete(&input.flow, &binding, callback, original)
                    .await
            }
            LoginBackend::Sqlite(store) => {
                store
                    .upstream_logins(verifier)
                    .complete(&input.flow, &binding, callback, original)
                    .await
            }
        };
        let proof = match completed {
            Ok(proof) => proof,
            Err(error) => {
                if error.continuation().is_some() {
                    clear = Some(flow_cookie(
                        &name,
                        "",
                        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                        0,
                        state.config.cookie_secure,
                    )?);
                }
                if matches!(
                    error.failure(),
                    UpstreamLoginFailure::ProviderError | UpstreamLoginFailure::InvalidIdentity
                ) && let Some(FlowContinuation::OAuth { request_id, .. }) = error.continuation()
                {
                    let oidc = state.config.oidc.as_ref().ok_or(LoginError::Unavailable)?;
                    let info = match &state.store {
                        LoginBackend::Postgres(store) => {
                            store
                                .browser_oidc_authorizations(&oidc.authorization)
                                .load(request_id, original)
                                .await
                        }
                        LoginBackend::Sqlite(store) => {
                            store
                                .browser_oidc_authorizations(oidc.authorization.clone())
                                .load(request_id, original)
                                .await
                        }
                    }
                    .map_err(authorization_error)?
                    .ok_or(LoginError::State)?;
                    let target = info
                        .response_target(original)
                        .map_err(authorization_error)?;
                    return state
                        .renderer
                        .as_ref()
                        .ok_or(LoginError::Unavailable)?
                        .denied(target)
                        .map_err(authorization_error);
                }
                return Err(upstream_error(error));
            }
        };
        clear = Some(flow_cookie(
            &name,
            "",
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            0,
            state.config.cookie_secure,
        )?);
        match proof.continuation().purpose() {
            FlowPurpose::Admin => {
                let admin = state.config.administration.ok_or(LoginError::Unavailable)?;
                let cookie = admin.cookie.ok_or(LoginError::Unavailable)?;
                let issued = match &state.store {
                    LoginBackend::Postgres(store) => {
                        store
                            .admin_cookie_sessions(cookie.limits, cookie.policy, Some(verifier))?
                            .issue_upstream(proof, original)
                            .await
                    }
                    LoginBackend::Sqlite(store) => {
                        store
                            .admin_cookie_sessions(
                                cookie.limits,
                                cookie.policy,
                                Some(verifier.clone()),
                            )?
                            .issue_upstream(proof, original)
                            .await
                    }
                }
                .map_err(cookie_error)?;
                let auth = admin_cookie_header(&issued, cookie.secure).map_err(cookie_error)?;
                let mut response = redirect(
                    "/admin/",
                    StatusCode::SEE_OTHER,
                    &id,
                    admin.response_json_bytes.get(),
                    original,
                )?;
                issued.check().map_err(cookie_error)?;
                response.headers_mut().append(header::SET_COOKIE, auth);
                Ok(response)
            }
            FlowPurpose::OAuth => {
                let oidc = state.config.oidc.as_ref().ok_or(LoginError::Unavailable)?;
                let authorized = match &state.store {
                    LoginBackend::Postgres(store) => {
                        store
                            .browser_oidc_authorizations(&oidc.authorization)
                            .complete_upstream(proof, verifier, original)
                            .await
                    }
                    LoginBackend::Sqlite(store) => {
                        store
                            .browser_oidc_authorizations(oidc.authorization.clone())
                            .complete_upstream(proof, verifier.clone(), original)
                            .await
                    }
                }
                .map_err(authorization_error)?;
                state
                    .renderer
                    .as_ref()
                    .ok_or(LoginError::Unavailable)?
                    .authorized(authorized, original)
                    .map_err(authorization_error)
            }
        }
    }
    .await;
    let mut response = match result {
        Ok(response) => response,
        Err(error) => callback_failure(&state, Some(purpose), error, &id, Some(original)),
    };
    if let Some(clear) = clear {
        response.headers_mut().append(header::SET_COOKIE, clear);
    }
    privacy_headers(&mut response);
    response
}

/// OAuth-only SQLite callback composition. No administrative route or cookie policy.
pub struct SqliteOidcUpstreamLoginHttpConfig {
    pub input_bytes: NonZeroUsize,
    pub cookie_secure: bool,
    pub oidc: OidcUpstreamLoginHttpConfig,
}
pub fn sqlite_oidc_upstream_login_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<UpstreamBearerVerifier>,
    config: SqliteOidcUpstreamLoginHttpConfig,
) -> Result<Router, ControlError> {
    sqlite_upstream_login_router(
        store,
        Some(verifier),
        UpstreamLoginHttpConfig {
            input_bytes: config.input_bytes,
            cookie_secure: config.cookie_secure,
            administration: None,
            oidc: Some(config.oidc),
        },
    )
}
