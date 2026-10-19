//! Native administrative session: configured LOCAL authentication + current SQL.
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use broker_control::{
    AdminBrokerSession, AdminBrokerSessionError, AdminBrokerSessionLimits, AdminCookieReadSession,
    AdminCookieSessionError, AdminLocalBearerSession, AdminUpstreamSession, BrokerAccessError,
    BrokerAccessVerifier, ControlError, PostgresControlStore, SessionProfile, SqliteControlStore,
    SystemPermission, UpstreamBearerVerifier, new_admin_request_id,
};
use headers::{Cookie, Header};
use serde::Serialize;
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
pub struct AdminSessionHttpConfig {
    pub limits: AdminBrokerSessionLimits,
    pub request_timeout: Duration,
}
impl AdminSessionHttpConfig {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.limits.validate()?;
        if self.request_timeout.is_zero()
            || Instant::now().checked_add(self.request_timeout).is_none()
        {
            return Err(ControlError::Configuration);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct AdminLocalBearerHttpConfig {
    pub audience: String,
    pub identity_json_bytes: NonZeroUsize,
    pub required_scopes: Vec<String>,
}
impl AdminLocalBearerHttpConfig {
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.audience.trim().is_empty()
            || self
                .required_scopes
                .iter()
                .any(|scope| scope.trim().is_empty())
            || self
                .identity_json_bytes
                .get()
                .checked_add(1)
                .and_then(|v| isize::try_from(v).ok())
                .is_none()
        {
            return Err(ControlError::Configuration);
        }
        i64::try_from(self.identity_json_bytes.get()).map_err(|_| ControlError::Configuration)?;
        Ok(())
    }
}
enum AdminBackend {
    Postgres {
        store: Arc<PostgresControlStore>,
        verifier: Arc<BrokerAccessVerifier>,
        local_bearer: Option<AdminLocalBearerHttpConfig>,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
        cookie: Option<super::AdminCookieHttpConfig>,
    },
    Sqlite {
        store: Arc<SqliteControlStore>,
        verifier: Arc<BrokerAccessVerifier>,
        local_bearer: Option<AdminLocalBearerHttpConfig>,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
        cookie: Option<super::AdminCookieHttpConfig>,
    },
    SqliteLocal {
        store: Arc<SqliteControlStore>,
        local_bearer: Option<AdminLocalBearerHttpConfig>,
        cookie: Option<super::AdminCookieHttpConfig>,
    },
}
impl AdminBackend {
    fn cookie(&self) -> Option<&super::AdminCookieHttpConfig> {
        match self {
            Self::Postgres { cookie, .. } | Self::Sqlite { cookie, .. } => cookie.as_ref(),
            Self::SqliteLocal { cookie, .. } => cookie.as_ref(),
        }
    }
    async fn read_cookie(
        &self,
        raw: &str,
        original: Instant,
    ) -> Result<AdminCookieReadSession, AdminBrokerSessionError> {
        let config = self
            .cookie()
            .ok_or(AdminBrokerSessionError::Authentication(
                BrokerAccessError::InvalidToken,
            ))?;
        match self {
            Self::Postgres {
                store, upstream, ..
            } => store
                .admin_cookie_sessions(config.limits, config.policy, upstream.as_deref())?
                .read(raw, original)
                .await
                .map_err(cookie_error),
            Self::Sqlite {
                store, upstream, ..
            } => store
                .admin_cookie_sessions(config.limits, config.policy, upstream.clone())?
                .read(raw, original)
                .await
                .map_err(cookie_error),
            Self::SqliteLocal { store, .. } => store
                .local_admin_cookie_sessions(config.limits, config.policy)?
                .read(raw, original)
                .await
                .map_err(cookie_error),
        }
    }
    async fn logout_cookie(
        &self,
        raw: &str,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<broker_control::AdminCookieLogout, AdminCookieSessionError> {
        let config = self.cookie().ok_or(ControlError::Configuration)?;
        match self {
            Self::Postgres {
                store, upstream, ..
            } => {
                store
                    .admin_cookie_sessions(config.limits, config.policy, upstream.as_deref())?
                    .logout(raw, csrf, original)
                    .await
            }
            Self::Sqlite {
                store, upstream, ..
            } => {
                store
                    .admin_cookie_sessions(config.limits, config.policy, upstream.clone())?
                    .logout(raw, csrf, original)
                    .await
            }
            Self::SqliteLocal { store, .. } => {
                store
                    .local_admin_cookie_sessions(config.limits, config.policy)?
                    .logout(raw, csrf, original)
                    .await
            }
        }
    }
}
struct AdminState {
    backend: AdminBackend,
    config: AdminSessionHttpConfig,
}
fn validate_cookie_limits(
    config: AdminSessionHttpConfig,
    cookie: super::AdminCookieHttpConfig,
) -> Result<(), ControlError> {
    if cookie.limits.authorization.identity.username_bytes != config.limits.identity.username_bytes
        || cookie.limits.authorization.identity.subject_bytes
            != config.limits.identity.subject_bytes
        || cookie.limits.authorization.identity.role_bytes != config.limits.identity.role_bytes
        || cookie.limits.authorization.identity.roles != config.limits.identity.roles
        || cookie.limits.authorization.identity.rows != config.limits.identity.rows
        || cookie.limits.authorization.profile_json_bytes != config.limits.profile_json_bytes
    {
        return Err(ControlError::Configuration);
    }
    Ok(())
}
pub fn sqlite_local_admin_session_router(
    store: Arc<SqliteControlStore>,
    config: AdminSessionHttpConfig,
    local_bearer: Option<AdminLocalBearerHttpConfig>,
    cookie: Option<super::AdminCookieHttpConfig>,
) -> Result<Router, ControlError> {
    config.validate()?;
    if let Some(local) = &local_bearer {
        local.validate()?;
        store.admin_local_bearer_sessions(
            &local.audience,
            local.identity_json_bytes,
            config.limits,
        )?;
    }
    if let Some(cookie) = cookie {
        cookie.validate()?;
        validate_cookie_limits(config, cookie)?;
        store.local_admin_cookie_sessions(cookie.limits, cookie.policy)?;
    }
    let router = Router::new().route("/admin/api/v1/session", get(session));
    let router = if cookie.is_some() {
        router.route("/admin/auth/logout", post(logout))
    } else {
        router
    };
    Ok(router.with_state(Arc::new(AdminState {
        backend: AdminBackend::SqliteLocal {
            store,
            local_bearer,
            cookie,
        },
        config,
    })))
}
pub fn admin_session_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: AdminSessionHttpConfig,
) -> Result<Router, ControlError> {
    admin_session_router_with_local_bearer(store, verifier, config, None)
}
pub fn admin_session_router_with_local_bearer(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: AdminSessionHttpConfig,
    local_bearer: Option<AdminLocalBearerHttpConfig>,
) -> Result<Router, ControlError> {
    admin_session_router_with_authentication(store, verifier, config, local_bearer, None)
}
pub fn admin_session_router_with_authentication(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: AdminSessionHttpConfig,
    local_bearer: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
) -> Result<Router, ControlError> {
    admin_session_router_with_cookie(store, verifier, config, local_bearer, upstream, None)
}
pub fn sqlite_admin_session_router_with_cookie(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: AdminSessionHttpConfig,
    local_bearer: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<super::admin_cookie::AdminCookieHttpConfig>,
) -> Result<Router, ControlError> {
    config.validate()?;
    store.admin_broker_sessions(&verifier, config.limits)?;
    if let Some(local) = &local_bearer {
        local.validate()?;
        store.admin_local_bearer_sessions(
            &local.audience,
            local.identity_json_bytes,
            config.limits,
        )?;
    }
    if let Some(upstream) = &upstream {
        store.admin_upstream_sessions(upstream, config.limits)?;
    }
    if let Some(cookie) = &cookie {
        cookie.validate()?;
        store.admin_cookie_sessions(cookie.limits, cookie.policy, upstream.clone())?;
        validate_cookie_limits(config, *cookie)?;
    }
    let router = Router::new().route("/admin/api/v1/session", get(session));
    let router = if cookie.is_some() {
        router.route("/admin/auth/logout", post(logout))
    } else {
        router
    };
    Ok(router.with_state(Arc::new(AdminState {
        backend: AdminBackend::Sqlite {
            store,
            verifier,
            local_bearer,
            upstream,
            cookie,
        },
        config,
    })))
}

pub fn admin_session_router_with_cookie(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: AdminSessionHttpConfig,
    local_bearer: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<super::admin_cookie::AdminCookieHttpConfig>,
) -> Result<Router, ControlError> {
    config.validate()?;
    store.admin_broker_sessions(&verifier, config.limits)?;
    if let Some(local) = &local_bearer {
        local.validate()?;
        store.admin_local_bearer_sessions(
            &local.audience,
            local.identity_json_bytes,
            config.limits,
        )?;
    }
    if let Some(upstream) = &upstream {
        store.admin_upstream_sessions(upstream, config.limits)?;
    }
    if let Some(cookie) = &cookie {
        cookie.validate()?;
        store.admin_cookie_sessions(cookie.limits, cookie.policy, upstream.as_deref())?;
        validate_cookie_limits(config, *cookie)?;
    }
    let router = Router::new().route("/admin/api/v1/session", get(session));
    let router = if cookie.is_some() {
        router.route("/admin/auth/logout", post(logout))
    } else {
        router
    };
    Ok(router.with_state(Arc::new(AdminState {
        backend: AdminBackend::Postgres {
            store,
            verifier,
            local_bearer,
            upstream,
            cookie,
        },
        config,
    })))
}

// The mature Cookie parser preserves known-cookie priority and rejects ambiguous input.
pub(super) fn cookie_credential(
    headers: &HeaderMap,
) -> Result<Option<Zeroizing<String>>, AdminBrokerSessionError> {
    let values = headers.get_all(header::COOKIE);
    let count = values.iter().count();
    if count == 0 {
        return Ok(None);
    }
    let unauthorized = || AdminBrokerSessionError::Authentication(BrokerAccessError::InvalidToken);
    if count != 1 {
        return Err(unauthorized());
    }
    let cookies = Cookie::decode(&mut values.iter()).map_err(|_| unauthorized())?;
    let mut known = cookies
        .iter()
        .filter(|(name, _)| *name == "graphit_admin_session");
    match known.next() {
        None => Ok(None),
        Some((_, raw)) => {
            if known.next().is_some() {
                return Err(unauthorized());
            }
            if raw.is_empty() || raw == "\"\"" {
                Ok(None)
            } else {
                Ok(Some(Zeroizing::new(raw.to_owned())))
            }
        }
    }
}
fn cookie_error(error: AdminCookieSessionError) -> AdminBrokerSessionError {
    match error {
        AdminCookieSessionError::MalformedCookie
        | AdminCookieSessionError::Unauthorized
        | AdminCookieSessionError::Control(
            ControlError::SessionUnavailable | ControlError::SessionExpired,
        ) => AdminBrokerSessionError::Authentication(BrokerAccessError::InvalidToken),
        AdminCookieSessionError::Forbidden | AdminCookieSessionError::CsrfFailed => {
            AdminBrokerSessionError::Forbidden
        }
        AdminCookieSessionError::Entropy => AdminBrokerSessionError::Entropy,
        AdminCookieSessionError::Control(error) => AdminBrokerSessionError::Control(error),
    }
}
pub(super) fn request_id(headers: &HeaderMap) -> Result<String, AdminBrokerSessionError> {
    match headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 128)
    {
        Some(value) => Ok(value.to_owned()),
        None => new_admin_request_id(),
    }
}
pub(super) fn response(status: StatusCode, bytes: Vec<u8>, id: &str) -> Response {
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if let Ok(value) = HeaderValue::from_str(id) {
        headers.insert("x-request-id", value);
    }
    response
}
pub(super) fn failure(error: AdminBrokerSessionError, id: &str) -> Response {
    use AdminBrokerSessionError::{Authentication, Control, Entropy, Forbidden};
    let (status, code, message) = match error {
        Authentication(BrokerAccessError::Deadline) | Control(ControlError::Deadline) => (
            StatusCode::GATEWAY_TIMEOUT,
            "administration_unavailable",
            "Administrative request deadline exceeded",
        ),
        Authentication(_) => (
            StatusCode::UNAUTHORIZED,
            "admin_unauthorized",
            "Administrative authentication required",
        ),
        Forbidden => (
            StatusCode::FORBIDDEN,
            "admin_forbidden",
            "Administrative access denied",
        ),
        Control(
            ControlError::Closed | ControlError::OutcomeUncertain | ControlError::Unavailable,
        )
        | Entropy => (
            StatusCode::SERVICE_UNAVAILABLE,
            "administration_unavailable",
            "Administration unavailable",
        ),
        Control(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "authorization_failed",
            "Administrative authorization failed",
        ),
    };
    // Strings are static except the validated, non-secret correlation ID.
    let value = serde_json::json!({"error":{"code":code,"message":message},"request_id":id});
    response(status, value.to_string().into_bytes(), id)
}
#[derive(Serialize)]
struct SessionWire<'a> {
    subject: &'a str,
    name: &'a str,
    email: &'a str,
    username: &'a str,
    organization: &'a str,
    teams: &'a [String],
    roles: &'a [String],
    role_source: &'static str,
    permissions: Vec<&'static str>,
    csrf_token: &'a str,
}
enum SessionObservation<'a> {
    Broker(AdminBrokerSession<'a>),
    Opaque(AdminLocalBearerSession),
    Upstream(AdminUpstreamSession),
    Cookie(AdminCookieReadSession),
}
impl SessionObservation<'_> {
    fn csrf_token(&self) -> &str {
        match self {
            Self::Cookie(s) => s.csrf_token(),
            _ => "",
        }
    }

    fn check(&self) -> Result<(), AdminBrokerSessionError> {
        match self {
            Self::Broker(s) => s.check(),
            Self::Opaque(s) => s.check(),
            Self::Upstream(s) => s.check(),
            Self::Cookie(s) => s.check().map_err(cookie_error),
        }
    }
    fn profile(&self) -> &SessionProfile {
        match self {
            Self::Broker(s) => s.profile(),
            Self::Opaque(s) => s.profile(),
            Self::Upstream(s) => s.profile(),
            Self::Cookie(s) => s.profile(),
        }
    }
    fn username(&self) -> &str {
        match self {
            Self::Broker(s) => &s.principal().username,
            Self::Opaque(s) => &s.principal().username,
            Self::Upstream(s) => s.username(),
            Self::Cookie(s) => &s.principal().username,
        }
    }
    fn organization(&self) -> &str {
        match self {
            Self::Broker(s) => &s.principal().organization,
            Self::Opaque(s) => &s.principal().organization,
            Self::Upstream(s) => s.organization(),
            Self::Cookie(s) => &s.principal().organization,
        }
    }
    fn teams(&self) -> &[String] {
        match self {
            Self::Broker(s) => &s.principal().teams,
            Self::Opaque(s) => &s.principal().teams,
            Self::Upstream(s) => s.teams(),
            Self::Cookie(s) => &s.principal().teams,
        }
    }
    fn role_source(&self) -> &'static str {
        match self {
            Self::Upstream(s) => s.role_source(),
            Self::Cookie(s) => s.role_source(),
            _ => "database",
        }
    }
    fn roles(&self) -> &[String] {
        match self {
            Self::Broker(s) => s.roles(),
            Self::Opaque(s) => s.roles(),
            Self::Upstream(s) => s.roles(),
            Self::Cookie(s) => s.roles(),
        }
    }
    fn permissions(&self) -> &[SystemPermission] {
        match self {
            Self::Broker(s) => s.permissions(),
            Self::Opaque(s) => s.permissions(),
            Self::Upstream(s) => s.permissions(),
            Self::Cookie(s) => s.permissions(),
        }
    }
}
async fn session(State(state): State<Arc<AdminState>>, mut request: Request) -> Response {
    let start = Instant::now();
    for (name, value) in request.headers_mut().iter_mut() {
        if name == header::AUTHORIZATION || name == header::COOKIE {
            value.set_sensitive(true);
        }
    }
    let headers = request.into_parts().0.headers;
    let id = match request_id(&headers) {
        Ok(id) => id,
        Err(error) => return failure(error, ""),
    };
    let result = async {
        let original = start
            .checked_add(state.config.request_timeout)
            .ok_or(ControlError::Configuration)?;
        if Instant::now() >= original {
            return Err(ControlError::Deadline.into());
        }
        let cookie = cookie_credential(&headers)?;
        let session = if let Some(raw) = cookie {
            SessionObservation::Cookie(state.backend.read_cookie(&raw, original).await?)
        } else {
            match &state.backend {
                AdminBackend::SqliteLocal {
                    store,
                    local_bearer,
                    ..
                } => {
                    let local =
                        local_bearer
                            .as_ref()
                            .ok_or(AdminBrokerSessionError::Authentication(
                                BrokerAccessError::InvalidToken,
                            ))?;
                    let credential = super::bearer(&headers).map_err(|_| {
                        AdminBrokerSessionError::Authentication(BrokerAccessError::InvalidToken)
                    })?;
                    let raw = Zeroizing::new(credential.token().to_owned());
                    SessionObservation::Opaque(
                        store
                            .admin_local_bearer_sessions(
                                &local.audience,
                                local.identity_json_bytes,
                                state.config.limits,
                            )?
                            .read(&raw, &local.required_scopes, original)
                            .await?,
                    )
                }
                AdminBackend::Postgres {
                    store,
                    verifier,
                    local_bearer,
                    upstream,
                    ..
                } => {
                    let credential = super::bearer(&headers).map_err(|_| {
                        AdminBrokerSessionError::Authentication(BrokerAccessError::InvalidToken)
                    })?;
                    let raw = Zeroizing::new(credential.token().to_owned());
                    let session = if let Some(local) = local_bearer
                        && (raw.starts_with("gb_at_") || raw.starts_with("gb_sc_"))
                    {
                        SessionObservation::Opaque(
                            store
                                .admin_local_bearer_sessions(
                                    &local.audience,
                                    local.identity_json_bytes,
                                    state.config.limits,
                                )?
                                .read(&raw, &local.required_scopes, original)
                                .await?,
                        )
                    } else if let Some(upstream) = upstream
                        && !upstream.selects_native(&raw, original)?
                    {
                        SessionObservation::Upstream(
                            store
                                .admin_upstream_sessions(upstream, state.config.limits)?
                                .read(&raw, original)
                                .await?,
                        )
                    } else {
                        let proof = verifier.verify(&raw, &[], original)?;
                        SessionObservation::Broker(
                            store
                                .admin_broker_sessions(verifier, state.config.limits)?
                                .read(proof, original)
                                .await?,
                        )
                    };
                    drop(raw);
                    session
                }
                AdminBackend::Sqlite {
                    store,
                    verifier,
                    local_bearer,
                    upstream,
                    ..
                } => {
                    let credential = super::bearer(&headers).map_err(|_| {
                        AdminBrokerSessionError::Authentication(BrokerAccessError::InvalidToken)
                    })?;
                    let raw = Zeroizing::new(credential.token().to_owned());
                    let session = if let Some(local) = local_bearer
                        && (raw.starts_with("gb_at_") || raw.starts_with("gb_sc_"))
                    {
                        SessionObservation::Opaque(
                            store
                                .admin_local_bearer_sessions(
                                    &local.audience,
                                    local.identity_json_bytes,
                                    state.config.limits,
                                )?
                                .read(&raw, &local.required_scopes, original)
                                .await?,
                        )
                    } else if let Some(upstream) = upstream
                        && !upstream.selects_native(&raw, original)?
                    {
                        SessionObservation::Upstream(
                            store
                                .admin_upstream_sessions(upstream, state.config.limits)?
                                .read(&raw, original)
                                .await?,
                        )
                    } else {
                        let proof = verifier.verify(&raw, &[], original)?;
                        SessionObservation::Broker(
                            store
                                .admin_broker_sessions(verifier, state.config.limits)?
                                .read(proof, original)
                                .await?,
                        )
                    };
                    drop(raw);
                    session
                }
            }
        };
        session.check()?;
        let profile = session.profile();
        let bytes = serde_json::to_vec(&SessionWire {
            subject: &profile.subject,
            name: &profile.name,
            email: &profile.email,
            username: session.username(),
            organization: session.organization(),
            teams: session.teams(),
            roles: session.roles(),
            role_source: session.role_source(),
            permissions: session.permissions().iter().map(|p| p.as_str()).collect(),
            csrf_token: session.csrf_token(),
        })
        .map_err(|_| AdminBrokerSessionError::Control(ControlError::CorruptIdentity))?;
        session.check()?;
        Ok::<_, AdminBrokerSessionError>(bytes)
    }
    .await;
    match result {
        Ok(bytes) => response(StatusCode::OK, bytes, &id),
        Err(error) => failure(error, &id),
    }
}

async fn logout(State(state): State<Arc<AdminState>>, mut request: Request) -> Response {
    let start = Instant::now();
    for (name, value) in request.headers_mut().iter_mut() {
        if name == header::AUTHORIZATION
            || name == header::COOKIE
            || name.as_str() == "x-csrf-token"
        {
            value.set_sensitive(true);
        }
    }
    let headers = request.into_parts().0.headers;
    let id = match request_id(&headers) {
        Ok(id) => id,
        Err(error) => return failure(error, ""),
    };
    let Some(config) = state.backend.cookie().copied() else {
        return failure(ControlError::Configuration.into(), &id);
    };
    let original = match start.checked_add(state.config.request_timeout) {
        Some(end) => end,
        None => return failure(ControlError::Configuration.into(), &id),
    };
    let result = async {
        if Instant::now() >= original {
            return Err(ControlError::Deadline.into());
        }
        if let Some(raw) =
            cookie_credential(&headers).map_err(|_| AdminCookieSessionError::Unauthorized)?
        {
            let csrf = headers.get_all("x-csrf-token");
            let mut values = csrf.iter();
            let value = values.next().and_then(|v| v.to_str().ok());
            let value = if values.next().is_none() { value } else { None };
            match state.backend.logout_cookie(&raw, value, original).await {
                Ok(proof) => proof.check()?,
                // A malformed native secret clears only the guest browser value.
                Err(AdminCookieSessionError::MalformedCookie) => {}
                Err(error) => return Err(error),
            }
        }
        if Instant::now() >= original {
            return Err(ControlError::Deadline.into());
        }
        let header = super::admin_cookie::clear_cookie_header(config.secure)?;
        if Instant::now() >= original {
            return Err(ControlError::Deadline.into());
        }
        Ok::<_, AdminCookieSessionError>(header)
    }
    .await;
    match result {
        Ok(header)=> { let mut result=response(StatusCode::NO_CONTENT,Vec::new(),&id); result.headers_mut().insert(header::SET_COOKIE,header); result }
        Err(AdminCookieSessionError::CsrfFailed)=>response(StatusCode::FORBIDDEN,serde_json::json!({"error":{"code":"csrf_failed","message":"Administrative CSRF verification failed"},"request_id":id}).to_string().into_bytes(),&id),
        Err(error)=>failure(cookie_error(error),&id),
    }
}
