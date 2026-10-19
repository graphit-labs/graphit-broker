//! Public browser composition of sealed authorization and LOCAL/upstream producers.
mod forms;
pub(crate) mod views;

use super::{
    LocalLoginRuntime, SqliteLocalLoginRuntime, oauth_response::OAuthResponseRenderer,
    upstream_login_flow_cookie,
};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::Response,
    routing::{MethodFilter, on},
};
use broker_control::{
    AuthorizedOidcAuthorization, BrowserOidcAuthorization, ControlError, FlowContinuation,
    LocalAuthError, LocalAuthStep, LocalCaptchaChallenge, LocalCaptchaProvider,
    LocalPasswordAdmissionError, OidcAuthorizationError, OidcAuthorizationInput,
    OidcAuthorizationPolicy, OidcAuthorizationRequestInfo, PendingLocalAuth, PostgresControlStore,
    PreparedOidcLogin, SqliteControlStore, UpstreamBearerVerifier, UpstreamBrowserOption,
    UpstreamLoginError,
};
use broker_security::{
    LOCAL_PASSWORD_MAX_BYTES, LocalAuthBinding, LocalAuthPurpose, LocalPasswordError,
};
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct OidcBrowserHttpConfig {
    pub authorization: Arc<OidcAuthorizationPolicy>,
    pub body_bytes: NonZeroUsize,
    pub request_timeout: Duration,
    pub cookie_secure: bool,
}
enum Backend {
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
struct BrowserState {
    backend: Backend,
    config: OidcBrowserHttpConfig,
    renderer: OAuthResponseRenderer,
    views: views::Views,
}
impl BrowserState {
    fn router(backend: Backend, config: OidcBrowserHttpConfig) -> Result<Router, ControlError> {
        if config.request_timeout.is_zero()
            || Instant::now().checked_add(config.request_timeout).is_none()
            || isize::try_from(config.body_bytes.get()).is_err()
        {
            return Err(ControlError::Configuration);
        }
        Ok(Router::new()
            .route(
                "/oauth/authorize",
                on(MethodFilter::GET.or(MethodFilter::POST), authorize),
            )
            .route(
                "/oauth/login",
                on(MethodFilter::GET.or(MethodFilter::POST), login),
            )
            .with_state(Arc::new(Self {
                backend,
                config,
                renderer: OAuthResponseRenderer::new().map_err(|_| ControlError::Configuration)?,
                views: views::Views::new()?,
            })))
    }
    async fn admit_browser<'a>(
        &self,
        input: OidcAuthorizationInput<'a>,
        end: Instant,
    ) -> Result<BrowserOidcAuthorization<'a>, Error> {
        Ok(match &self.backend {
            Backend::Postgres { store, .. } => {
                store
                    .browser_oidc_authorizations(&self.config.authorization)
                    .admit_browser(input, end)
                    .await?
            }
            Backend::Sqlite { store, .. } => {
                store
                    .browser_oidc_authorizations(self.config.authorization.clone())
                    .admit_browser(input, end)
                    .await?
            }
        })
    }
    async fn load(
        &self,
        raw: &str,
        end: Instant,
    ) -> Result<Option<OidcAuthorizationRequestInfo>, Error> {
        Ok(match &self.backend {
            Backend::Postgres { store, .. } => {
                store
                    .browser_oidc_authorizations(&self.config.authorization)
                    .load(raw, end)
                    .await?
            }
            Backend::Sqlite { store, .. } => {
                store
                    .browser_oidc_authorizations(self.config.authorization.clone())
                    .load(raw, end)
                    .await?
            }
        })
    }
    async fn complete(
        &self,
        raw: &str,
        prepared: PreparedOidcLogin,
        end: Instant,
    ) -> Result<AuthorizedOidcAuthorization, Error> {
        Ok(match &self.backend {
            Backend::Postgres { store, .. } => {
                store
                    .browser_oidc_authorizations(&self.config.authorization)
                    .complete(raw, prepared, end)
                    .await?
            }
            Backend::Sqlite { store, .. } => {
                store
                    .browser_oidc_authorizations(self.config.authorization.clone())
                    .complete(raw, prepared, end)
                    .await?
            }
        })
    }
    fn options(&self, end: Instant) -> Result<Vec<UpstreamBrowserOption>, Error> {
        Ok(match &self.backend {
            Backend::Postgres {
                upstream: Some(verifier),
                ..
            }
            | Backend::Sqlite {
                upstream: Some(verifier),
                ..
            } => verifier.browser_options(end)?,
            _ => Vec::new(),
        })
    }
    fn local(&self) -> Option<LocalOwner<'_>> {
        match &self.backend {
            Backend::Postgres {
                store,
                local: Some(owner),
                ..
            } => Some(LocalOwner::Postgres { store, owner }),
            Backend::Sqlite {
                store,
                local: Some(owner),
                ..
            } => Some(LocalOwner::Sqlite { store, owner }),
            _ => None,
        }
    }
}
pub fn oidc_browser_router(
    store: Arc<PostgresControlStore>,
    config: OidcBrowserHttpConfig,
    local: Option<Arc<LocalLoginRuntime>>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
) -> Result<Router, ControlError> {
    if let Some(owner) = &local {
        owner.passwords(&store, LocalAuthPurpose::OauthAuthorize)?;
    }
    BrowserState::router(
        Backend::Postgres {
            store,
            local,
            upstream,
        },
        config,
    )
}
/// Compose public OAuth browser routes with the actual SQLite LOCAL startup owner.
/// A missing LOCAL owner is an explicitly disabled sign-in channel.
/// ```no_run
/// fn compose(store: std::sync::Arc<broker_control::SqliteControlStore>,
///     config: broker_presence::OidcBrowserHttpConfig,
///     owner: Option<std::sync::Arc<broker_presence::SqliteLocalLoginRuntime>>)
///     -> Result<axum::Router, broker_control::ControlError> {
///     broker_presence::sqlite_local_oidc_browser_router(store, config, owner)
/// }
/// ```
pub fn sqlite_local_oidc_browser_router(
    store: Arc<SqliteControlStore>,
    config: OidcBrowserHttpConfig,
    local: Option<Arc<SqliteLocalLoginRuntime>>,
) -> Result<Router, ControlError> {
    if let Some(owner) = &local {
        owner.passwords(&store, LocalAuthPurpose::OauthAuthorize)?;
    }
    BrowserState::router(
        Backend::Sqlite {
            store,
            local,
            upstream: None,
        },
        config,
    )
}
/// Compose the existing browser UI with real SQLite LOCAL and upstream owners.
pub fn sqlite_oidc_browser_router(
    store: Arc<SqliteControlStore>,
    config: OidcBrowserHttpConfig,
    local: Option<Arc<SqliteLocalLoginRuntime>>,
    upstream: Arc<UpstreamBearerVerifier>,
) -> Result<Router, ControlError> {
    if let Some(owner) = &local {
        owner.passwords(&store, LocalAuthPurpose::OauthAuthorize)?;
    }
    BrowserState::router(
        Backend::Sqlite {
            store,
            local,
            upstream: Some(upstream),
        },
        config,
    )
}
// Concrete borrowed startup owners. Presentation data never supplies authentication.
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
            Self::Postgres { owner, .. } => owner.challenge(LocalAuthPurpose::OauthAuthorize),
            Self::Sqlite { owner, .. } => owner.challenge(LocalAuthPurpose::OauthAuthorize),
        }
    }
    fn presentation(&self, error: Option<&Error>) -> Result<views::PasswordPresentation, Error> {
        let challenge = match error {
            Some(Error::Admission(LocalPasswordAdmissionError::CaptchaRequired(c))) => {
                Some(c.clone())
            }
            _ => match self {
                Self::Postgres { owner, .. } => {
                    owner.next_password_challenge(LocalAuthPurpose::OauthAuthorize)?
                }
                Self::Sqlite { owner, .. } => {
                    owner.next_password_challenge(LocalAuthPurpose::OauthAuthorize)?
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
                    .passwords(store, LocalAuthPurpose::OauthAuthorize)?
                    .authenticate(username, password, captcha, end)
                    .await?;
                owner
                    .authentication(store)
                    .begin(proof, binding, end)
                    .await?
            }
            Self::Sqlite { store, owner } => {
                let proof = owner
                    .passwords(store, LocalAuthPurpose::OauthAuthorize)?
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

#[derive(Debug)]
enum Error {
    Input(StatusCode),
    Control(ControlError),
    Authorization(OidcAuthorizationError),
    Auth(LocalAuthError),
    Admission(LocalPasswordAdmissionError),
    Upstream(UpstreamLoginError),
}
impl From<ControlError> for Error {
    fn from(e: ControlError) -> Self {
        Self::Control(e)
    }
}
impl From<OidcAuthorizationError> for Error {
    fn from(e: OidcAuthorizationError) -> Self {
        Self::Authorization(e)
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
impl From<UpstreamLoginError> for Error {
    fn from(e: UpstreamLoginError) -> Self {
        Self::Upstream(e)
    }
}
fn gate(original: Instant) -> Result<(), Error> {
    if Instant::now() >= original {
        Err(ControlError::Deadline.into())
    } else {
        Ok(())
    }
}
fn redirect(location: &str, original: Instant) -> Result<Response, Error> {
    gate(original)?;
    let location =
        HeaderValue::from_str(location).map_err(|_| Error::Input(StatusCode::BAD_REQUEST))?;
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response.headers_mut().insert(header::LOCATION, location);
    super::oauth_response::privacy_headers(&mut response);
    gate(original)?;
    Ok(response)
}
fn login_url(request: &str) -> String {
    format!(
        "/oauth/login?{}",
        form_urlencoded::Serializer::new(String::new())
            .append_pair("id", request)
            .finish()
    )
}
async fn authorize(State(state): State<Arc<BrowserState>>, request: Request) -> Response {
    if request.method() == Method::HEAD {
        return head_rejected();
    }
    let Some(end) = Instant::now().checked_add(state.config.request_timeout) else {
        return views::unavailable();
    };
    let result = async {
        let fields = forms::read(request, true, state.config.body_bytes.get(), end).await?;
        let resources: Vec<_> = fields.resources.iter().map(|s| s.as_str()).collect();
        let prompts: Vec<_> = fields.get("prompt").split_whitespace().collect();
        let input = OidcAuthorizationInput {
            client_id: fields.get("client_id"),
            redirect_uri: fields.get("redirect_uri"),
            response_type: fields.get("response_type"),
            scope: fields.get("scope"),
            state: fields.get("state"),
            nonce: fields.get("nonce"),
            code_challenge: fields.get("code_challenge"),
            code_challenge_method: fields.get("code_challenge_method"),
            response_mode: fields.optional("response_mode"),
            resources: &resources,
            prompts: &prompts,
        };
        match state.admit_browser(input, end).await? {
            BrowserOidcAuthorization::Pending(pending) => {
                let target = pending.info().response_target(end)?;
                let response = redirect(&login_url(pending.request()), end)?;
                target.check()?;
                Ok(response)
            }
            BrowserOidcAuthorization::Rejected(rejected) => {
                state.renderer.rejected(rejected).map_err(Into::into)
            }
        }
    }
    .await;
    result.unwrap_or_else(|e| state.views.failure(&e, None))
}
async fn provider(
    state: &BrowserState,
    request: &str,
    selected: &str,
    end: Instant,
) -> Result<Response, Error> {
    let verifier = match &state.backend {
        Backend::Postgres {
            upstream: Some(verifier),
            ..
        }
        | Backend::Sqlite {
            upstream: Some(verifier),
            ..
        } => verifier,
        _ => return Err(Error::Input(StatusCode::BAD_REQUEST)),
    };
    if !verifier
        .browser_options(end)?
        .iter()
        .any(|p| p.id == selected)
    {
        return Err(Error::Input(StatusCode::BAD_REQUEST));
    }
    let continuation = FlowContinuation::OAuth {
        provider_id: selected.to_owned(),
        request_id: request.to_owned(),
    };
    let issued = match &state.backend {
        Backend::Postgres { store, .. } => {
            store
                .upstream_logins(verifier)
                .begin(continuation, end)
                .await?
        }
        Backend::Sqlite { store, .. } => {
            store
                .upstream_logins(verifier)
                .begin(continuation, end)
                .await?
        }
    };
    let cookie = upstream_login_flow_cookie(&issued, state.config.cookie_secure)?;
    let mut response = redirect(issued.location().as_str(), end)?;
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    issued.check()?;
    Ok(response)
}
async fn login(State(state): State<Arc<BrowserState>>, request: Request) -> Response {
    if request.method() == Method::HEAD {
        return head_rejected();
    }
    let Some(end) = Instant::now().checked_add(state.config.request_timeout) else {
        return views::unavailable();
    };
    let post = request.method() == Method::POST;
    let fields = match forms::read(
        request,
        false,
        state.config.body_bytes.get().min(16 * 1024),
        end,
    )
    .await
    {
        Ok(fields) => fields,
        Err(e) => return state.views.failure(&e, None),
    };
    let id = fields.get("id");
    let info = match state.load(id, end).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            return state
                .views
                .failure(&Error::Input(StatusCode::BAD_REQUEST), None);
        }
        Err(e) => return state.views.failure(&e, None),
    };
    let target = match info.response_target(end) {
        Ok(t) => t,
        Err(e) => return state.views.failure(&e.into(), None),
    };
    let result = async {
        let options = state.options(end)?;
        match fields.optional("login_method") {
            Some("oidc") => {
                if [
                    "challenge_token",
                    "username",
                    "password",
                    "new_password",
                    "confirm_password",
                    "code",
                    "cf-turnstile-response",
                    "g-recaptcha-response",
                ]
                .iter()
                .any(|key| fields.optional(key).is_some())
                {
                    return Err(Error::Input(StatusCode::BAD_REQUEST));
                }
                return provider(&state, id, fields.get("provider"), end).await;
            }
            Some("local" | "") | None => {}
            _ => return Err(Error::Input(StatusCode::BAD_REQUEST)),
        }
        if fields.optional("provider").is_some() {
            return Err(Error::Input(StatusCode::BAD_REQUEST));
        }
        if !post {
            if state.local().is_none() && options.len() == 1 {
                return provider(&state, id, &options[0].id, end).await;
            }
            return state.views.login(
                id,
                target.origin(),
                state
                    .local()
                    .map(|owner| owner.presentation(None))
                    .transpose()?,
                &options,
                None,
                end,
            );
        }
        let owner = state.local().ok_or(ControlError::Unavailable)?;
        let binding = LocalAuthBinding::OauthAuthorize(id.as_bytes());
        let factor_attempt =
            fields.optional("challenge_token").is_some() && fields.optional("code").is_some();
        let step = if let Some(challenge) = fields.optional("challenge_token") {
            if fields.optional("username").is_some() || fields.optional("password").is_some() {
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
                state
                    .views
                    .pending(id, target.origin(), &pending, denied.as_ref(), end)
            }
            LocalAuthStep::Complete(mut login) => {
                // Take the only presentation owner synchronously before constructing the SQL future.
                let recovery = login.take_recovery_codes();
                let prepared = PreparedOidcLogin::try_from(login)
                    .map_err(|_| Error::Authorization(OidcAuthorizationError::InvalidLogin))?;
                let authorized = state.complete(id, prepared, end).await?;
                match recovery {
                    Some(codes) => state
                        .renderer
                        .recovery(authorized, codes, end)
                        .map_err(Into::into),
                    None => state
                        .renderer
                        .authorized(authorized, end)
                        .map_err(Into::into),
                }
            }
        }
    }
    .await;
    match result {
        Ok(response) => match target.check() {
            Ok(()) => response,
            Err(e) => state.views.failure(&e.into(), None),
        },
        Err(error) => {
            if !retryable(&error) {
                return state.views.failure(&error, Some(id));
            }
            let retry = async {
                gate(end)?;
                let owner = state.local().ok_or(ControlError::Unavailable)?;
                if let Some(challenge) = fields.optional("challenge_token") {
                    let pending = owner
                        .load(
                            challenge,
                            LocalAuthBinding::OauthAuthorize(id.as_bytes()),
                            end,
                        )
                        .await?;
                    state
                        .views
                        .pending(id, target.origin(), &pending, Some(&error), end)
                } else {
                    let options = state.options(end)?;
                    state.views.login(
                        id,
                        target.origin(),
                        Some(owner.presentation(Some(&error))?),
                        &options,
                        Some((&error, fields.get("username"))),
                        end,
                    )
                }
            }
            .await;
            match retry {
                Ok(response) => match target.check() {
                    Ok(()) => response,
                    Err(e) => state.views.failure(&e.into(), None),
                },
                Err(e) => state.views.failure(&e, Some(id)),
            }
        }
    }
}
fn head_rejected() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET, POST"));
    super::oauth_response::privacy_headers(&mut response);
    response
}
fn captcha_token<'a>(
    fields: &'a forms::Fields,
    challenge: Option<&LocalCaptchaChallenge>,
) -> Result<Option<&'a str>, Error> {
    let turnstile = fields.optional("cf-turnstile-response");
    let recaptcha = fields.optional("g-recaptcha-response");
    match (challenge.map(|c| c.provider()), turnstile, recaptcha) {
        (_, Some(_), Some(_))
        | (Some(LocalCaptchaProvider::Turnstile), _, Some(_))
        | (Some(LocalCaptchaProvider::Recaptcha), Some(_), _) => {
            Err(Error::Input(StatusCode::BAD_REQUEST))
        }
        (Some(LocalCaptchaProvider::Turnstile), value, None)
        | (Some(LocalCaptchaProvider::Recaptcha), None, value) => Ok(value),
        (None, None, None) => Ok(None),
        _ => Err(Error::Input(StatusCode::BAD_REQUEST)),
    }
}
fn retryable(error: &Error) -> bool {
    matches!(
        error,
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
