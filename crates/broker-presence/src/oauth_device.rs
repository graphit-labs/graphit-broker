//! LOCAL Device HTTP composition; SQL producers alone confer authority.
mod forms;
mod views;

use crate::{LocalLoginRuntime, SqliteLocalLoginRuntime};
use axum::http::Uri;
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{MethodFilter, on, post},
};
use broker_control::{
    BrokerAccessIssuer, CompletedLocalLogin, ControlError, DeviceAuthorizationCodes,
    DeviceAuthorizationPolicy, DeviceConsent, DeviceError, LocalAuthError, LocalAuthStep,
    LocalCaptchaChallenge, LocalCaptchaProvider, LocalPasswordAdmissionError,
    OidcAuthorizationPolicy, OidcTokenExchangeError as Protocol, PendingLocalAuth,
    PostgresControlStore, SqliteControlStore,
};
use broker_security::{
    LOCAL_PASSWORD_MAX_BYTES, LocalAuthBinding, LocalAuthPurpose, LocalPasswordError,
};
use serde::Serialize;
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct OidcDeviceHttpConfig {
    pub authorization: Arc<OidcAuthorizationPolicy>,
    pub policy: Arc<DeviceAuthorizationPolicy>,
    pub issuer: Arc<BrokerAccessIssuer>,
    pub verification_uri: Uri,
    pub body_bytes: NonZeroUsize,
    pub request_timeout: Duration,
}
enum Backend {
    Postgres {
        store: Arc<PostgresControlStore>,
        local: Option<Arc<LocalLoginRuntime>>,
    },
    SqliteLocal {
        store: Arc<SqliteControlStore>,
        local: Option<Arc<SqliteLocalLoginRuntime>>,
    },
}
struct DeviceState {
    backend: Backend,
    config: OidcDeviceHttpConfig,
    views: views::Views,
}
impl DeviceState {
    fn local(&self) -> Option<LocalOwner<'_>> {
        match &self.backend {
            Backend::Postgres { store, local } => local
                .as_deref()
                .map(|owner| LocalOwner::Postgres { store, owner }),
            Backend::SqliteLocal { store, local } => local
                .as_deref()
                .map(|owner| LocalOwner::Sqlite { store, owner }),
        }
    }
    async fn issue(
        &self,
        client: &str,
        scope: &str,
        end: Instant,
    ) -> Result<DeviceAuthorizationCodes, DeviceError> {
        match &self.backend {
            Backend::Postgres { store, .. } => {
                store
                    .device_authorizations(
                        &self.config.authorization,
                        &self.config.policy,
                        &self.config.issuer,
                    )?
                    .issue(client, scope, end)
                    .await
            }
            Backend::SqliteLocal { store, .. } => {
                store
                    .device_authorizations(
                        self.config.authorization.clone(),
                        self.config.policy.clone(),
                        self.config.issuer.clone(),
                    )?
                    .issue(client, scope, end)
                    .await
            }
        }
    }
    async fn prepare(
        &self,
        code: &str,
        login: CompletedLocalLogin,
        end: Instant,
    ) -> Result<DeviceConsent, DeviceError> {
        match &self.backend {
            Backend::Postgres { store, .. } => {
                store
                    .device_authorizations(
                        &self.config.authorization,
                        &self.config.policy,
                        &self.config.issuer,
                    )?
                    .prepare(code, login, end)
                    .await
            }
            Backend::SqliteLocal { store, .. } => {
                store
                    .device_authorizations(
                        self.config.authorization.clone(),
                        self.config.policy.clone(),
                        self.config.issuer.clone(),
                    )?
                    .prepare(code, login, end)
                    .await
            }
        }
    }
    async fn decide(
        &self,
        code: &str,
        client: &str,
        secret: &str,
        allow: bool,
        end: Instant,
    ) -> Result<(), DeviceError> {
        match &self.backend {
            Backend::Postgres { store, .. } => {
                store
                    .device_authorizations(
                        &self.config.authorization,
                        &self.config.policy,
                        &self.config.issuer,
                    )?
                    .decide(code, client, secret, allow, end)
                    .await
            }
            Backend::SqliteLocal { store, .. } => {
                store
                    .device_authorizations(
                        self.config.authorization.clone(),
                        self.config.policy.clone(),
                        self.config.issuer.clone(),
                    )?
                    .decide(code, client, secret, allow, end)
                    .await
            }
        }
    }
}
pub fn oidc_device_router(
    store: Arc<PostgresControlStore>,
    config: OidcDeviceHttpConfig,
    local: Option<Arc<LocalLoginRuntime>>,
) -> Result<Router, ControlError> {
    router(Backend::Postgres { store, local }, config)
}
/// Compose Device routes with the actual SQLite LOCAL startup owners.
/// ```no_run
/// fn compose(store: std::sync::Arc<broker_control::SqliteControlStore>, config: broker_presence::OidcDeviceHttpConfig,
///     owner: Option<std::sync::Arc<broker_presence::SqliteLocalLoginRuntime>>) -> Result<axum::Router, broker_control::ControlError> {
///     broker_presence::sqlite_local_oidc_device_router(store,config,owner)
/// }
/// ```
pub fn sqlite_local_oidc_device_router(
    store: Arc<SqliteControlStore>,
    config: OidcDeviceHttpConfig,
    local: Option<Arc<SqliteLocalLoginRuntime>>,
) -> Result<Router, ControlError> {
    router(Backend::SqliteLocal { store, local }, config)
}
fn router(backend: Backend, config: OidcDeviceHttpConfig) -> Result<Router, ControlError> {
    let uri = &config.verification_uri;
    if config.request_timeout.is_zero()
        || Instant::now().checked_add(config.request_timeout).is_none()
        || isize::try_from(config.body_bytes.get()).is_err()
        || !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.host().is_none()
        || uri.authority().is_some_and(|a| a.as_str().contains('@'))
        || uri.path() != "/oauth/device"
        || uri.query().is_some()
    {
        return Err(ControlError::Configuration);
    }
    match &backend {
        Backend::Postgres { store, local } => {
            store
                .device_authorizations(&config.authorization, &config.policy, &config.issuer)
                .map_err(|_| ControlError::Configuration)?;
            if let Some(owner) = local {
                owner.passwords(store, LocalAuthPurpose::DeviceApprove)?;
            }
        }
        Backend::SqliteLocal { store, local } => {
            store
                .device_authorizations(
                    config.authorization.clone(),
                    config.policy.clone(),
                    config.issuer.clone(),
                )
                .map_err(|_| ControlError::Configuration)?;
            if let Some(owner) = local {
                owner.passwords(store, LocalAuthPurpose::DeviceApprove)?;
            }
        }
    }
    Ok(Router::new()
        .route("/oauth/device/authorize", post(authorize))
        .route(
            "/oauth/device",
            on(MethodFilter::GET.or(MethodFilter::POST), browser),
        )
        .with_state(Arc::new(DeviceState {
            backend,
            config,
            views: views::Views::new()?,
        })))
}
enum LocalOwner<'a> {
    Postgres {
        store: &'a PostgresControlStore,
        owner: &'a LocalLoginRuntime,
    },
    Sqlite {
        store: &'a SqliteControlStore,
        owner: &'a SqliteLocalLoginRuntime,
    },
}
impl LocalOwner<'_> {
    fn challenge(&self) -> Option<LocalCaptchaChallenge> {
        match self {
            Self::Postgres { owner, .. } => owner.challenge(LocalAuthPurpose::DeviceApprove),
            Self::Sqlite { owner, .. } => owner.challenge(LocalAuthPurpose::DeviceApprove),
        }
    }
    fn presentation(&self, error: Option<&Error>) -> Result<views::PasswordPresentation, Error> {
        let challenge = match error {
            Some(Error::Admission(LocalPasswordAdmissionError::CaptchaRequired(c))) => {
                Some(c.clone())
            }
            _ => match self {
                Self::Postgres { owner, .. } => {
                    owner.next_password_challenge(LocalAuthPurpose::DeviceApprove)?
                }
                Self::Sqlite { owner, .. } => {
                    owner.next_password_challenge(LocalAuthPurpose::DeviceApprove)?
                }
            },
        };
        Ok(views::PasswordPresentation { challenge })
    }
    async fn begin(
        &self,
        username: &str,
        password: &str,
        captcha: Option<&str>,
        binding: LocalAuthBinding<'_>,
        end: Instant,
    ) -> Result<LocalAuthStep, Error> {
        Ok(match self {
            Self::Postgres { store, owner } => {
                let proof = owner
                    .passwords(store, LocalAuthPurpose::DeviceApprove)?
                    .authenticate(username, password, captcha, end)
                    .await?;
                owner
                    .authentication(store)
                    .begin(proof, binding, end)
                    .await?
            }
            Self::Sqlite { store, owner } => {
                let proof = owner
                    .passwords(store, LocalAuthPurpose::DeviceApprove)?
                    .authenticate(username, password, captcha, end)
                    .await?;
                owner
                    .authentication(store)
                    .begin(proof, binding, end)
                    .await?
            }
        })
    }
    async fn password_change(
        &self,
        raw: &str,
        binding: LocalAuthBinding<'_>,
        password: &str,
        end: Instant,
    ) -> Result<LocalAuthStep, Error> {
        Ok(match self {
            Self::Postgres { store, owner } => {
                owner
                    .admit_password_change(end)?
                    .complete(&owner.authentication(store), raw, binding, password)
                    .await?
            }
            Self::Sqlite { store, owner } => {
                owner
                    .admit_password_change(end)?
                    .complete_sqlite(&owner.authentication(store), raw, binding, password)
                    .await?
            }
        })
    }
    async fn mfa(
        &self,
        raw: &str,
        binding: LocalAuthBinding<'_>,
        code: &str,
        end: Instant,
    ) -> Result<LocalAuthStep, Error> {
        Ok(match self {
            Self::Postgres { store, owner } => {
                owner
                    .authentication(store)
                    .complete_mfa(owner.limiter(), raw, binding, code, end)
                    .await?
            }
            Self::Sqlite { store, owner } => {
                owner
                    .authentication(store)
                    .complete_mfa(owner.limiter(), raw, binding, code, end)
                    .await?
            }
        })
    }
    async fn load(
        &self,
        raw: &str,
        binding: LocalAuthBinding<'_>,
        end: Instant,
    ) -> Result<PendingLocalAuth, Error> {
        Ok(match self {
            Self::Postgres { store, owner } => {
                owner.authentication(store).load(raw, binding, end).await?
            }
            Self::Sqlite { store, owner } => {
                owner.authentication(store).load(raw, binding, end).await?
            }
        })
    }
}

#[derive(Serialize)]
struct CodesWire<'a> {
    device_code: &'a str,
    user_code: &'a str,
    verification_uri: &'a str,
    verification_uri_complete: &'a str,
    expires_in: u64,
    interval: u64,
}
pub(crate) fn failure(error: DeviceError) -> Response {
    let code = match error {
        DeviceError::AuthorizationPending => "authorization_pending",
        DeviceError::SlowDown => "slow_down",
        DeviceError::AccessDenied => "access_denied",
        DeviceError::ExpiredToken => "expired_token",
        DeviceError::Protocol(Protocol::Control(ControlError::Unavailable)) => {
            return crate::oauth_token::no_store(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"error":"temporarily_unavailable"})),
                )
                    .into_response(),
            );
        }
        DeviceError::Protocol(e) => return crate::oauth_token::failure(e),
    };
    crate::oauth_token::no_store(
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":code})),
        )
            .into_response(),
    )
}
async fn authorize(State(state): State<Arc<DeviceState>>, request: Request) -> Response {
    let result = async {
        if state.local().is_none() {
            return Err(ControlError::Unavailable.into());
        }
        let end = Instant::now()
            .checked_add(state.config.request_timeout)
            .ok_or(Protocol::InvalidConfiguration)?;
        let cap = state.config.body_bytes.get().min(16 * 1024);
        let query_len = request.uri().query().map_or(0, str::len);
        if query_len > cap {
            return Err(Protocol::InvalidRequest.into());
        }
        let parsed = crate::oauth_form::read(request, forms::API, end, cap - query_len).await?;
        let get = |key: &str| parsed.fields.get(key).map(|s| s.as_str());
        if parsed.authorization.is_some()
            || forms::API
                .iter()
                .any(|key| !["client_id", "scope"].contains(key) && get(key).is_some())
        {
            return Err(Protocol::InvalidRequest.into());
        }
        let codes = state
            .issue(
                get("client_id").unwrap_or(""),
                get("scope").unwrap_or(""),
                end,
            )
            .await?;
        let verification_uri = state.config.verification_uri.to_string();
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("user_code", codes.user_code())
            .finish();
        let complete = format!("{verification_uri}?{query}");
        let response = Json(CodesWire {
            device_code: codes.device_code(),
            user_code: codes.user_code(),
            verification_uri: &verification_uri,
            verification_uri_complete: complete.as_str(),
            expires_in: codes.expires_in(end)?,
            interval: codes.interval_seconds(),
        })
        .into_response();
        codes.expires_in(end)?;
        Ok(crate::oauth_token::no_store(response))
    }
    .await;
    result.unwrap_or_else(failure)
}

#[derive(Debug)]
enum Error {
    Input(StatusCode),
    Control(ControlError),
    Device(DeviceError),
    Auth(LocalAuthError),
    Admission(LocalPasswordAdmissionError),
}
impl From<ControlError> for Error {
    fn from(e: ControlError) -> Self {
        Self::Control(e)
    }
}
impl From<DeviceError> for Error {
    fn from(e: DeviceError) -> Self {
        Self::Device(e)
    }
}
impl From<LocalAuthError> for Error {
    fn from(e: LocalAuthError) -> Self {
        Self::Auth(e)
    }
}
impl From<LocalPasswordAdmissionError> for Error {
    fn from(e: LocalPasswordAdmissionError) -> Self {
        Self::Admission(e)
    }
}
fn gate(end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        Err(ControlError::Deadline.into())
    } else {
        Ok(())
    }
}
fn browser_url(code: &str) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("user_code", code)
        .finish();
    format!("/oauth/device?{query}")
}
async fn browser(State(state): State<Arc<DeviceState>>, request: Request) -> Response {
    if request.method() == Method::HEAD {
        let mut response = Response::new(axum::body::Body::empty());
        crate::oauth_response::privacy_headers(&mut response);
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, POST"));
        return response;
    }
    let Some(end) = Instant::now().checked_add(state.config.request_timeout) else {
        return state.views.failure(&ControlError::Unavailable.into());
    };
    let Some(owner) = state.local() else {
        return state.views.failure(&ControlError::Unavailable.into());
    };
    let post = request.method() == Method::POST;
    let fields = match forms::read(request, state.config.body_bytes.get().min(16 * 1024), end).await
    {
        Ok(v) => v,
        Err(e) => return state.views.failure(&e),
    };
    let raw = fields.get("user_code");
    if !post && raw.is_empty() {
        return state
            .views
            .entry(None, end)
            .unwrap_or_else(|e| state.views.failure(&e));
    }
    let Some(code) = broker_control::normalize_device_user_code(raw) else {
        return state
            .views
            .entry(Some(&Error::Input(StatusCode::BAD_REQUEST)), end)
            .unwrap_or_else(|e| state.views.failure(&e));
    };
    let result = async {
        gate(end)?;
        if let Some(decision) = fields.optional("decision") {
            if fields.has_login_fields() {
                return Err(Error::Input(StatusCode::BAD_REQUEST));
            }
            let allow = match decision {
                "allow" => true,
                "deny" => false,
                _ => return Err(Error::Input(StatusCode::BAD_REQUEST)),
            };
            state
                .decide(
                    &code,
                    fields.get("client_id"),
                    fields.get("consent_secret"),
                    allow,
                    end,
                )
                .await?;
            return state.views.decided(allow, end);
        }
        if fields.optional("consent_secret").is_some()
            || fields.optional("client_id").is_some()
            || !matches!(fields.optional("login_method"), None | Some("" | "local"))
        {
            return Err(Error::Input(StatusCode::BAD_REQUEST));
        }
        if !post {
            return state
                .views
                .login(&code, owner.presentation(None)?, None, end);
        }
        let binding = LocalAuthBinding::DeviceApprove(code.as_bytes());
        let factor_attempt =
            fields.optional("challenge_token").is_some() && fields.optional("code").is_some();
        let step = if let Some(challenge) = fields.optional("challenge_token") {
            if fields.optional("username").is_some()
                || fields.optional("password").is_some()
                || fields.optional("cf-turnstile-response").is_some()
                || fields.optional("g-recaptcha-response").is_some()
            {
                return Err(Error::Input(StatusCode::BAD_REQUEST));
            }
            match (
                fields.optional("new_password"),
                fields.optional("confirm_password"),
                fields.optional("code"),
            ) {
                (Some(password), Some(confirm), None)
                    if password == confirm
                        && password.len() <= LOCAL_PASSWORD_MAX_BYTES
                        && password.chars().count() >= 15 =>
                {
                    owner
                        .password_change(challenge, binding, password, end)
                        .await?
                }
                (None, None, Some(code)) if !code.is_empty() && code.len() <= 64 => {
                    owner.mfa(challenge, binding, code, end).await?
                }
                _ => return Err(Error::Input(StatusCode::BAD_REQUEST)),
            }
        } else {
            if ["new_password", "confirm_password", "code"]
                .iter()
                .any(|k| fields.optional(k).is_some())
            {
                return Err(Error::Input(StatusCode::BAD_REQUEST));
            }
            let captcha = captcha_token(&fields, owner.challenge().as_ref())?;
            owner
                .begin(
                    fields.get("username"),
                    fields.get("password"),
                    captcha,
                    binding,
                    end,
                )
                .await?
        };
        match step {
            LocalAuthStep::Pending(pending) => {
                let denied = factor_attempt.then_some(Error::Auth(LocalAuthError::Unauthenticated));
                state.views.pending(&code, &pending, denied.as_ref(), end)
            }
            LocalAuthStep::Complete(login) => {
                let consent = state.prepare(&code, login, end).await?;
                state.views.consent(consent, end)
            }
        }
    }
    .await;
    match result {
        Ok(response) => response,
        Err(error) if retryable(&error) => {
            let retry = async {
                gate(end)?;
                if let Some(challenge) = fields.optional("challenge_token") {
                    let pending = owner
                        .load(
                            challenge,
                            LocalAuthBinding::DeviceApprove(code.as_bytes()),
                            end,
                        )
                        .await?;
                    state.views.pending(&code, &pending, Some(&error), end)
                } else {
                    state.views.login(
                        &code,
                        owner.presentation(Some(&error))?,
                        Some((&error, fields.get("username"))),
                        end,
                    )
                }
            }
            .await;
            retry.unwrap_or_else(|e| state.views.failure(&e))
        }
        Err(e) => state.views.failure(&e),
    }
}
fn captcha_token<'a>(
    fields: &'a forms::Fields,
    challenge: Option<&LocalCaptchaChallenge>,
) -> Result<Option<&'a str>, Error> {
    let t = fields.optional("cf-turnstile-response");
    let r = fields.optional("g-recaptcha-response");
    match (challenge.map(|c| c.provider()), t, r) {
        (_, Some(_), Some(_))
        | (Some(LocalCaptchaProvider::Turnstile), _, Some(_))
        | (Some(LocalCaptchaProvider::Recaptcha), Some(_), _) => {
            Err(Error::Input(StatusCode::BAD_REQUEST))
        }
        (Some(LocalCaptchaProvider::Turnstile), v, None)
        | (Some(LocalCaptchaProvider::Recaptcha), None, v) => Ok(v),
        (None, None, None) => Ok(None),
        _ => Err(Error::Input(StatusCode::BAD_REQUEST)),
    }
}
fn retryable(e: &Error) -> bool {
    matches!(
        e,
        Error::Input(_)
            | Error::Auth(
                LocalAuthError::Unauthenticated
                    | LocalAuthError::InvalidChallenge
                    | LocalAuthError::InvalidMfaCode
                    | LocalAuthError::PasswordUnchanged
                    | LocalAuthError::Password(LocalPasswordError::InvalidPassword)
            )
            | Error::Admission(
                LocalPasswordAdmissionError::Unauthenticated
                    | LocalPasswordAdmissionError::CaptchaRequired(_)
                    | LocalPasswordAdmissionError::RateLimited(_)
            )
    )
}
