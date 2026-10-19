//! Native administrative LOCAL login consumes genuine password/factor/SQL proofs.
use super::{
    AdminCookieHttpConfig, LocalLoginRuntime, SqliteLocalLoginRuntime, admin_cookie_header,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use broker_control::{
    AdminBrokerSessionError, AdminCookieSessionError, ControlError, LocalAuthError, LocalAuthStage,
    LocalAuthStep, LocalCaptchaChallenge, LocalPasswordAdmissionError, PostgresControlStore,
    PreparedAdminLogin, SqliteControlStore, UpstreamBearerVerifier, UpstreamBrowserOption,
};
use broker_security::{
    LOCAL_PASSWORD_MAX_BYTES, LocalAuthBinding, LocalAuthPurpose, LocalPasswordError,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    io::Write,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
pub struct AdminLocalLoginHttpConfig {
    pub body_bytes: NonZeroUsize,
    pub response_json_bytes: NonZeroUsize,
    pub request_timeout: Duration,
    pub cookie: Option<AdminCookieHttpConfig>,
}
enum LoginBackend {
    Postgres {
        store: Arc<PostgresControlStore>,
        local: Option<Arc<LocalLoginRuntime>>,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
    },
    Sqlite {
        store: Arc<SqliteControlStore>,
        local: Option<Arc<SqliteLocalLoginRuntime>>,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
    },
}
impl LoginBackend {
    fn enabled(&self) -> bool {
        match self {
            Self::Postgres { local, .. } => local.is_some(),
            Self::Sqlite { local, .. } => local.is_some(),
        }
    }
    fn challenge(&self) -> Option<LocalCaptchaChallenge> {
        match self {
            Self::Postgres { local, .. } => local
                .as_ref()
                .and_then(|o| o.challenge(LocalAuthPurpose::AdminLogin)),
            Self::Sqlite { local, .. } => local
                .as_ref()
                .and_then(|o| o.challenge(LocalAuthPurpose::AdminLogin)),
        }
    }
    fn next_challenge(&self) -> Result<Option<LocalCaptchaChallenge>, ControlError> {
        match self {
            Self::Postgres { local, .. } => local
                .as_ref()
                .map(|o| o.next_password_challenge(LocalAuthPurpose::AdminLogin))
                .transpose()
                .map(Option::flatten),
            Self::Sqlite { local, .. } => local
                .as_ref()
                .map(|o| o.next_password_challenge(LocalAuthPurpose::AdminLogin))
                .transpose()
                .map(Option::flatten),
        }
    }
    fn browser_options(&self, end: Instant) -> Result<Vec<UpstreamBrowserOption>, ControlError> {
        match self {
            Self::Postgres { upstream, .. } | Self::Sqlite { upstream, .. } => upstream
                .as_ref()
                .map(|o| o.browser_options(end))
                .transpose()
                .map(Option::unwrap_or_default),
        }
    }
    async fn begin(&self, input: PasswordInput, end: Instant) -> Result<LocalAuthStep, LoginError> {
        match self {
            Self::Postgres { store, local, .. } => {
                let owner = local.as_ref().ok_or(ControlError::Configuration)?;
                let view = owner.passwords(store, LocalAuthPurpose::AdminLogin)?;
                let proof = view
                    .authenticate(
                        &input.username,
                        &input.password.0,
                        input.captcha_token.as_ref().map(|s| s.0.as_str()),
                        end,
                    )
                    .await?;
                Ok(owner
                    .authentication(store)
                    .begin(proof, LocalAuthBinding::AdminLogin, end)
                    .await?)
            }
            Self::Sqlite { store, local, .. } => {
                let owner = local.as_ref().ok_or(ControlError::Configuration)?;
                let view = owner.passwords(store, LocalAuthPurpose::AdminLogin)?;
                let proof = view
                    .authenticate(
                        &input.username,
                        &input.password.0,
                        input.captcha_token.as_ref().map(|s| s.0.as_str()),
                        end,
                    )
                    .await?;
                Ok(owner
                    .authentication(store)
                    .begin(proof, LocalAuthBinding::AdminLogin, end)
                    .await?)
            }
        }
    }
    async fn change_password(
        &self,
        raw: &str,
        password: &str,
        end: Instant,
    ) -> Result<LocalAuthStep, LoginError> {
        match self {
            Self::Postgres { store, local, .. } => {
                let o = local.as_ref().ok_or(ControlError::Configuration)?;
                Ok(o.admit_password_change(end)?
                    .complete(
                        &o.authentication(store),
                        raw,
                        LocalAuthBinding::AdminLogin,
                        password,
                    )
                    .await?)
            }
            Self::Sqlite { store, local, .. } => {
                let o = local.as_ref().ok_or(ControlError::Configuration)?;
                Ok(o.admit_password_change(end)?
                    .complete_sqlite(
                        &o.authentication(store),
                        raw,
                        LocalAuthBinding::AdminLogin,
                        password,
                    )
                    .await?)
            }
        }
    }
    async fn complete_mfa(
        &self,
        raw: &str,
        code: &str,
        end: Instant,
    ) -> Result<LocalAuthStep, LoginError> {
        match self {
            Self::Postgres { store, local, .. } => {
                let o = local.as_ref().ok_or(ControlError::Configuration)?;
                Ok(o.authentication(store)
                    .complete_mfa(o.limiter(), raw, LocalAuthBinding::AdminLogin, code, end)
                    .await?)
            }
            Self::Sqlite { store, local, .. } => {
                let o = local.as_ref().ok_or(ControlError::Configuration)?;
                Ok(o.authentication(store)
                    .complete_mfa(o.limiter(), raw, LocalAuthBinding::AdminLogin, code, end)
                    .await?)
            }
        }
    }
    async fn issue(
        &self,
        prepared: PreparedAdminLogin,
        config: AdminCookieHttpConfig,
        end: Instant,
    ) -> Result<broker_control::IssuedAdminCookie, LoginError> {
        match self {
            Self::Postgres { store, local, .. } => {
                let o = local.as_ref().ok_or(ControlError::Configuration)?;
                Ok(store
                    .admin_cookie_sessions(config.limits, config.policy, None)?
                    .issue_local(prepared, o.policy(), end)
                    .await?)
            }
            Self::Sqlite { store, local, .. } => {
                let o = local.as_ref().ok_or(ControlError::Configuration)?;
                Ok(store
                    .local_admin_cookie_sessions(config.limits, config.policy)?
                    .issue_local(prepared, o.policy(), end)
                    .await?)
            }
        }
    }
}
struct LoginState {
    backend: LoginBackend,
    config: AdminLocalLoginHttpConfig,
}
fn validate_config(config: AdminLocalLoginHttpConfig) -> Result<(), ControlError> {
    if config.request_timeout.is_zero()
        || Instant::now().checked_add(config.request_timeout).is_none()
        || isize::try_from(config.body_bytes.get()).is_err()
        || isize::try_from(config.response_json_bytes.get()).is_err()
    {
        return Err(ControlError::Configuration);
    }
    Ok(())
}
pub fn admin_local_login_router(
    store: Arc<PostgresControlStore>,
    config: AdminLocalLoginHttpConfig,
    local: Option<Arc<LocalLoginRuntime>>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
) -> Result<Router, ControlError> {
    validate_config(config)?;
    if let Some(owner) = &local {
        let cookie = config.cookie.ok_or(ControlError::Configuration)?;
        cookie.validate()?;
        store.admin_cookie_sessions(cookie.limits, cookie.policy, None)?;
        owner.passwords(&store, LocalAuthPurpose::AdminLogin)?;
    }
    Ok(login_router(
        LoginBackend::Postgres {
            store,
            local,
            upstream,
        },
        config,
    ))
}
pub fn sqlite_admin_local_login_router(
    store: Arc<SqliteControlStore>,
    config: AdminLocalLoginHttpConfig,
    local: Option<Arc<SqliteLocalLoginRuntime>>,
) -> Result<Router, ControlError> {
    sqlite_admin_local_login_router_with_upstream(store, config, local, None)
}
/// Serve existing LOCAL pages/options with explicitly configured browser providers.
pub fn sqlite_admin_local_login_router_with_upstream(
    store: Arc<SqliteControlStore>,
    config: AdminLocalLoginHttpConfig,
    local: Option<Arc<SqliteLocalLoginRuntime>>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
) -> Result<Router, ControlError> {
    validate_config(config)?;
    if let Some(owner) = &local {
        let cookie = config.cookie.ok_or(ControlError::Configuration)?;
        cookie.validate()?;
        store.local_admin_cookie_sessions(cookie.limits, cookie.policy)?;
        owner.passwords(&store, LocalAuthPurpose::AdminLogin)?;
    }
    Ok(login_router(
        LoginBackend::Sqlite {
            store,
            local,
            upstream,
        },
        config,
    ))
}
fn login_router(backend: LoginBackend, config: AdminLocalLoginHttpConfig) -> Router {
    Router::new()
        .route("/admin", get(page))
        .route("/admin/", get(page))
        .route("/admin/api/v1/login-options", get(options))
        .route("/admin/auth/local", post(password))
        .route("/admin/auth/local/continue", post(continuation))
        .layer(DefaultBodyLimit::max(config.body_bytes.get()))
        .with_state(Arc::new(LoginState { backend, config }))
}

struct ProtectedString(Zeroizing<String>);
impl<'de> Deserialize<'de> for ProtectedString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|value| Self(Zeroizing::new(value)))
    }
}
fn present_secret<'de, D: Deserializer<'de>>(d: D) -> Result<Option<ProtectedString>, D::Error> {
    ProtectedString::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordInput {
    username: String,
    password: ProtectedString,
    #[serde(default, deserialize_with = "present_secret")]
    captcha_token: Option<ProtectedString>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContinuationInput {
    challenge_token: ProtectedString,
    #[serde(default, deserialize_with = "present_secret")]
    new_password: Option<ProtectedString>,
    #[serde(default, deserialize_with = "present_secret")]
    code: Option<ProtectedString>,
}
enum LoginError {
    Admission(LocalPasswordAdmissionError),
    Auth(LocalAuthError),
    Cookie(AdminCookieSessionError),
    Control(ControlError),
    Input(StatusCode),
}
impl From<LocalPasswordAdmissionError> for LoginError {
    fn from(value: LocalPasswordAdmissionError) -> Self {
        Self::Admission(value)
    }
}
impl From<LocalAuthError> for LoginError {
    fn from(value: LocalAuthError) -> Self {
        Self::Auth(value)
    }
}
impl From<AdminCookieSessionError> for LoginError {
    fn from(value: AdminCookieSessionError) -> Self {
        Self::Cookie(value)
    }
}
impl From<ControlError> for LoginError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
fn ensure(original: Instant) -> Result<(), LoginError> {
    if Instant::now() >= original {
        Err(ControlError::Deadline.into())
    } else {
        Ok(())
    }
}
async fn input<T: for<'de> Deserialize<'de>>(
    request: Request,
    original: Instant,
) -> Result<T, LoginError> {
    ensure(original)?;
    let result = tokio::time::timeout_at(original.into(), Json::<T>::from_request(request, &()))
        .await
        .map_err(|_| ControlError::Deadline)?;
    ensure(original)?;
    // The native wire contract treats JSON data/schema rejection as 400.
    let Json(value) = result.map_err(|error| {
        LoginError::Input(match error.status() {
            StatusCode::UNPROCESSABLE_ENTITY => StatusCode::BAD_REQUEST,
            status => status,
        })
    })?;
    Ok(value)
}
struct ResponseBytes {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for ResponseBytes {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("administrative response limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn serialized<T: Serialize>(
    value: &T,
    limit: usize,
    original: Instant,
) -> Result<Vec<u8>, LoginError> {
    ensure(original)?;
    let mut writer = ResponseBytes {
        bytes: Vec::new(),
        limit,
    };
    let result = serde_json::to_writer(&mut writer, value);
    ensure(original)?;
    result.map_err(|_| ControlError::Configuration)?;
    Ok(writer.bytes)
}
fn failure(status: StatusCode, code: &'static str, message: &'static str, id: &str) -> Response {
    let value = serde_json::json!({"error":{"code":code,"message":message},"request_id":id});
    super::admin_session::response(status, value.to_string().into_bytes(), id)
}
fn denied(id: &str, continuing: bool) -> Response {
    failure(
        StatusCode::UNAUTHORIZED,
        if continuing {
            "local_login_step_failed"
        } else {
            "local_login_failed"
        },
        "The local Broker credentials or challenge are invalid",
        id,
    )
}
fn limited(duration: Duration, id: &str) -> Response {
    let mut response = failure(
        StatusCode::TOO_MANY_REQUESTS,
        "authentication_rate_limited",
        "Local authentication is rate limited",
        id,
    );
    let seconds = duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
        .max(1);
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}
fn auth_error(error: LocalAuthError, id: &str, continuing: bool) -> Response {
    match error {
        LocalAuthError::Control(error) => {
            super::admin_session::failure(AdminBrokerSessionError::Control(error), id)
        }
        LocalAuthError::MfaRateLimited(duration) => limited(duration, id),
        LocalAuthError::MfaBusy => limited(Duration::from_secs(1), id),
        LocalAuthError::MfaCapacity | LocalAuthError::MfaUnavailable => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "Local authentication is unavailable",
            id,
        ),
        LocalAuthError::Unauthenticated
        | LocalAuthError::InvalidChallenge
        | LocalAuthError::InvalidMfaCode => denied(id, continuing),
        LocalAuthError::PasswordUnchanged
        | LocalAuthError::Password(LocalPasswordError::InvalidPassword) => failure(
            StatusCode::BAD_REQUEST,
            "local_login_step_failed",
            "The new password is invalid or unchanged",
            id,
        ),
        _ => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "local_login_failed",
            "Could not complete local login",
            id,
        ),
    }
}
fn error(error: LoginError, id: &str, continuing: bool, original: Instant, cap: usize) -> Response {
    match error {
        LoginError::Control(error) => {
            super::admin_session::failure(AdminBrokerSessionError::Control(error), id)
        }
        LoginError::Auth(error)
        | LoginError::Admission(LocalPasswordAdmissionError::LocalAuth(error)) => {
            auth_error(error, id, continuing)
        }
        LoginError::Admission(LocalPasswordAdmissionError::Control(error)) => {
            super::admin_session::failure(AdminBrokerSessionError::Control(error), id)
        }
        LoginError::Admission(LocalPasswordAdmissionError::Unauthenticated) => {
            denied(id, continuing)
        }
        LoginError::Admission(LocalPasswordAdmissionError::RateLimited(duration)) => {
            limited(duration, id)
        }
        LoginError::Admission(LocalPasswordAdmissionError::Capacity) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "Local authentication is unavailable",
            id,
        ),
        LoginError::Admission(LocalPasswordAdmissionError::CaptchaRequired(challenge)) => {
            let value = serde_json::json!({"error":{"code":"captcha_required","message":"Local authentication requires CAPTCHA"},"captcha":challenge,"request_id":id});
            match serialized(&value, cap, original) {
                Ok(bytes) => super::admin_session::response(StatusCode::FORBIDDEN, bytes, id),
                Err(LoginError::Control(error)) => {
                    super::admin_session::failure(AdminBrokerSessionError::Control(error), id)
                }
                _ => failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "local_login_failed",
                    "Could not complete local login",
                    id,
                ),
            }
        }
        LoginError::Admission(LocalPasswordAdmissionError::Password(_)) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "local_login_failed",
            "Local password verification unavailable",
            id,
        ),
        LoginError::Cookie(AdminCookieSessionError::Control(error)) => {
            super::admin_session::failure(AdminBrokerSessionError::Control(error), id)
        }
        LoginError::Cookie(
            AdminCookieSessionError::Forbidden | AdminCookieSessionError::CsrfFailed,
        ) => super::admin_session::failure(AdminBrokerSessionError::Forbidden, id),
        LoginError::Cookie(AdminCookieSessionError::Entropy) => {
            super::admin_session::failure(AdminBrokerSessionError::Entropy, id)
        }
        LoginError::Cookie(_) => denied(id, continuing),
        LoginError::Input(status) => failure(
            status,
            if status == StatusCode::UNSUPPORTED_MEDIA_TYPE {
                "content_type_required"
            } else {
                "invalid_request"
            },
            "Invalid local login request",
            id,
        ),
    }
}
fn original(state: &LoginState) -> Result<Instant, ControlError> {
    Instant::now()
        .checked_add(state.config.request_timeout)
        .ok_or(ControlError::Configuration)
}
async fn options(State(state): State<Arc<LoginState>>, request: Request) -> Response {
    let end = match original(&state) {
        Ok(end) => end,
        Err(error) => {
            return super::admin_session::failure(AdminBrokerSessionError::Control(error), "");
        }
    };
    let id = match super::admin_session::request_id(request.headers()) {
        Ok(id) => id,
        Err(error) => return super::admin_session::failure(error, ""),
    };
    let head = request.method() == Method::HEAD;
    let result = (|| -> Result<Response, LoginError> {
        #[derive(Serialize)]
        struct Options<'a> {
            oidc_providers: Vec<UpstreamBrowserOption>,
            local: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            captcha: Option<&'a LocalCaptchaChallenge>,
        }
        let challenge = state.backend.next_challenge()?;
        let bytes = serialized(
            &Options {
                oidc_providers: state.backend.browser_options(end)?,
                local: state.backend.enabled(),
                captcha: challenge.as_ref(),
            },
            state.config.response_json_bytes.get(),
            end,
        )?;
        let response = super::admin_session::response(StatusCode::OK, bytes, &id);
        ensure(end)?;
        Ok(response)
    })();
    let mut response = match result {
        Ok(response) => response,
        Err(value) => error(
            value,
            &id,
            false,
            end,
            state.config.response_json_bytes.get(),
        ),
    };
    if head {
        *response.body_mut() = Body::empty();
    }
    response
}
async fn page(State(state): State<Arc<LoginState>>, request: Request) -> Response {
    let end = match original(&state) {
        Ok(end) => end,
        Err(e) => return super::admin_session::failure(e.into(), ""),
    };
    let id = match super::admin_session::request_id(request.headers()) {
        Ok(id) => id,
        Err(e) => return super::admin_session::failure(e, ""),
    };
    let provider = state
        .backend
        .challenge()
        .map(|challenge| challenge.provider());
    use broker_control::LocalCaptchaProvider;
    let (scripts, frames, connect) = match provider {
        None => ("", "'none'", ""),
        Some(LocalCaptchaProvider::Turnstile) => (
            " https://challenges.cloudflare.com",
            "https://challenges.cloudflare.com",
            "",
        ),
        Some(LocalCaptchaProvider::Recaptcha) => (
            " https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/",
            "https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/",
            " https://www.google.com/recaptcha/",
        ),
    };
    let mut response = super::admin_session::response(StatusCode::OK, Vec::new(), &id);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    let csp = format!(
        "default-src 'self'; script-src 'unsafe-inline'{scripts}; style-src 'unsafe-inline'; connect-src 'self'{connect}; img-src 'self' data:; frame-src {frames}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    );
    let Ok(csp) = HeaderValue::from_str(&csp) else {
        return super::admin_session::failure(ControlError::Configuration.into(), &id);
    };
    headers.insert("content-security-policy", csp);
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    if request.method() != Method::HEAD {
        *response.body_mut() = Body::from(include_str!("../assets/admin/index.html"));
    }
    if Instant::now() >= end {
        return super::admin_session::failure(ControlError::Deadline.into(), &id);
    }
    response
}
async fn password(State(state): State<Arc<LoginState>>, request: Request) -> Response {
    login(state, request, false).await
}
async fn continuation(State(state): State<Arc<LoginState>>, request: Request) -> Response {
    login(state, request, true).await
}
async fn login(state: Arc<LoginState>, request: Request, continuing: bool) -> Response {
    let end = match original(&state) {
        Ok(end) => end,
        Err(error) => {
            return super::admin_session::failure(AdminBrokerSessionError::Control(error), "");
        }
    };
    let id = match super::admin_session::request_id(request.headers()) {
        Ok(id) => id,
        Err(error) => return super::admin_session::failure(error, ""),
    };
    if !state.backend.enabled() {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "administration_unavailable",
            "Administration unavailable",
            &id,
        );
    };

    let result = async {
        let step = if continuing {
            let input: ContinuationInput = input(request, end).await?;
            let new = input
                .new_password
                .as_ref()
                .filter(|value| !value.0.is_empty());
            let code = input.code.as_ref().filter(|value| !value.0.is_empty());
            match (new, code) {
                (Some(password), None) => {
                    if password.0.len() > LOCAL_PASSWORD_MAX_BYTES
                        || password.0.chars().count() < 15
                    {
                        return Err(LoginError::Input(StatusCode::BAD_REQUEST));
                    }
                    state
                        .backend
                        .change_password(&input.challenge_token.0, &password.0, end)
                        .await?
                }
                (None, Some(code)) => {
                    state
                        .backend
                        .complete_mfa(&input.challenge_token.0, &code.0, end)
                        .await?
                }
                _ => return Err(LoginError::Input(StatusCode::BAD_REQUEST)),
            }
        } else {
            let input: PasswordInput = input(request, end).await?;
            state.backend.begin(input, end).await?
        };
        finish(&state, step, end, &id).await
    }
    .await;
    match result {
        Ok(response) => response,
        Err(value) => error(value, &id, continuing, end, state.config.body_bytes.get()),
    }
}
async fn finish(
    state: &LoginState,
    step: LocalAuthStep,
    end: Instant,
    id: &str,
) -> Result<Response, LoginError> {
    match step {
        LocalAuthStep::Pending(pending) => {
            #[derive(Serialize)]
            struct Pending<'a> {
                status: &'static str,
                challenge_token: &'a str,
                #[serde(skip_serializing_if = "Option::is_none")]
                secret: Option<&'a str>,
                #[serde(skip_serializing_if = "Option::is_none")]
                otpauth_uri: Option<&'a str>,
                #[serde(skip_serializing_if = "Option::is_none")]
                qr_code_data_url: Option<&'a str>,
            }
            let enrollment = pending.enrollment();
            let status = match pending.stage() {
                LocalAuthStage::PasswordChange => "password-change",
                LocalAuthStage::Mfa => "mfa",
                LocalAuthStage::Enrollment => "mfa-enrollment",
            };
            let bytes = serialized(
                &Pending {
                    status,
                    challenge_token: pending.challenge(),
                    secret: enrollment.map(|value| value.secret()),
                    otpauth_uri: enrollment.map(|value| value.otpauth_uri()),
                    qr_code_data_url: enrollment.map(|value| value.qr_data_url()),
                },
                state.config.body_bytes.get(),
                end,
            )?;
            ensure(end)?;
            Ok(super::admin_session::response(StatusCode::OK, bytes, id))
        }
        LocalAuthStep::Complete(mut login) => {
            let codes = login.take_recovery_codes();
            let prepared = PreparedAdminLogin::try_from(login)
                .map_err(|_| LocalAuthError::InvalidChallenge)?;
            let config = state.config.cookie.ok_or(ControlError::Configuration)?;
            let cookie = state.backend.issue(prepared, config, end).await?;
            cookie.check()?;
            let (status, bytes) = if let Some(codes) = &codes {
                #[derive(Serialize)]
                struct Completed<'a> {
                    status: &'static str,
                    recovery_codes: Vec<&'a str>,
                }
                (
                    StatusCode::OK,
                    serialized(
                        &Completed {
                            status: "complete",
                            recovery_codes: codes.iter().collect(),
                        },
                        state.config.body_bytes.get(),
                        end,
                    )?,
                )
            } else {
                (StatusCode::NO_CONTENT, Vec::new())
            };
            let header = admin_cookie_header(&cookie, config.secure)?;
            let mut response = super::admin_session::response(status, bytes, id);
            cookie.check()?;
            response.headers_mut().insert(header::SET_COOKIE, header);
            cookie.check()?;
            Ok(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn json_credentials_reject_null_duplicate_unknown_and_wrong_types() {
        let valid: PasswordInput = serde_json::from_str(
            r#"{"username":"alice","password":"  exact fixture content  ","captcha_token":""}"#,
        )
        .unwrap();
        assert!(valid.password.0.starts_with("  ") && valid.password.0.ends_with("  "));
        for value in [
            r#"{"username":"alice","username":"bob","password":"fixture"}"#,
            r#"{"username":"alice","password":"fixture","password":"second"}"#,
            r#"{"username":"alice","password":"fixture","purpose":"admin-login"}"#,
            r#"{"username":"alice","password":null}"#,
            r#"{"username":"alice","password":[]}"#,
            r#"{"username":"alice","password":"fixture","captcha_token":null}"#,
            r#"{"username":"alice","password":"fixture"} {}"#,
        ] {
            assert!(serde_json::from_str::<PasswordInput>(value).is_err());
        }
        for value in [
            r#"{"challenge_token":"fixture","code":null}"#,
            r#"{"challenge_token":"fixture","new_password":null}"#,
            r#"{"challenge_token":"fixture","code":"123456","code":"654321"}"#,
            r#"{"challenge_token":"fixture","code":"123456","binding":"other"}"#,
            r#"{"challenge_token":0,"code":"123456"}"#,
        ] {
            assert!(serde_json::from_str::<ContinuationInput>(value).is_err());
        }
    }
    #[tokio::test]
    async fn mature_json_extractor_keeps_media_and_original_failures_finite() {
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(r#"{"username":"alice","password":"fixture"}"#))
            .unwrap();
        assert!(matches!(
            input::<PasswordInput>(request, Instant::now() + Duration::from_secs(1)).await,
            Err(LoginError::Input(StatusCode::UNSUPPORTED_MEDIA_TYPE))
        ));
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"username":"alice","password":"fixture"}"#))
            .unwrap();
        assert!(matches!(
            input::<PasswordInput>(request, Instant::now()).await,
            Err(LoginError::Control(ControlError::Deadline))
        ));
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"username":"alice","password":null}"#))
            .unwrap();
        assert!(matches!(
            input::<PasswordInput>(request, Instant::now() + Duration::from_secs(1)).await,
            Err(LoginError::Input(StatusCode::BAD_REQUEST))
        ));
    }
    #[tokio::test]
    async fn synchronous_json_rejection_crossing_original_returns_deadline() {
        struct LateRejectedData;
        impl<'de> Deserialize<'de> for LateRejectedData {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                let _data = String::deserialize(decoder)?;
                std::thread::sleep(Duration::from_millis(20));
                Err(serde::de::Error::custom("bounded data rejection"))
            }
        }
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#""bounded data""#))
            .unwrap();
        assert!(matches!(
            input::<LateRejectedData>(request, Instant::now() + Duration::from_millis(10)).await,
            Err(LoginError::Control(ControlError::Deadline))
        ));
    }
    #[test]
    fn synchronous_response_cap_rejection_crossing_original_returns_deadline() {
        struct LateResponseData;
        impl Serialize for LateResponseData {
            fn serialize<S: serde::Serializer>(&self, encoder: S) -> Result<S::Ok, S::Error> {
                std::thread::sleep(Duration::from_millis(20));
                encoder.serialize_str("bounded data")
            }
        }
        assert!(matches!(
            serialized(
                &LateResponseData,
                4,
                Instant::now() + Duration::from_millis(10)
            ),
            Err(LoginError::Control(ControlError::Deadline))
        ));
    }
    #[test]
    fn response_serialization_is_bounded_and_never_renews_original() {
        let value = serde_json::json!({"test":"bounded data"});
        assert!(matches!(
            serialized(&value, 4, Instant::now() + Duration::from_secs(1)),
            Err(LoginError::Control(ControlError::Configuration))
        ));
        assert!(matches!(
            serialized(&value, 1024, Instant::now()),
            Err(LoginError::Control(ControlError::Deadline))
        ));
    }
}
