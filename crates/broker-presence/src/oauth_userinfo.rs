//! Explicit profile lookup; never a mandatory authentication gate for JWT consumers.
use crate::oauth_token::{OidcTokenHttpConfigurationError, no_store};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{MethodFilter, on},
};
use broker_control::{
    BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy, OidcUserInfoError as Error,
    PostgresControlStore, SqliteControlStore, UpstreamBearerVerifier,
};
use headers::{Authorization, ContentType, Header, authorization::Bearer};
use serde::Serialize;
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub struct OidcUserInfoHttpConfig {
    pub request_timeout: Duration,
    pub body_bytes: NonZeroUsize,
}
enum Backend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
struct UserInfoState {
    backend: Backend,
    authorization: Arc<OidcAuthorizationPolicy>,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    parameter_bytes: usize,
    config: OidcUserInfoHttpConfig,
}
pub fn oidc_userinfo_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: OidcUserInfoHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    if config.request_timeout.is_zero()
        || Instant::now().checked_add(config.request_timeout).is_none()
        || isize::try_from(config.body_bytes.get()).is_err()
    {
        return Err(OidcTokenHttpConfigurationError);
    }
    let parameter_bytes = store
        .oidc_userinfo(&authorization, &verifier)
        .map_err(|_| OidcTokenHttpConfigurationError)?
        .parameter_bytes();
    Ok(Router::new()
        .route(
            "/oauth/userinfo",
            on(MethodFilter::GET.or(MethodFilter::POST), userinfo),
        )
        .with_state(Arc::new(UserInfoState {
            backend: Backend::Postgres(store),
            authorization,
            verifier,
            upstream,
            parameter_bytes,
            config,
        }))
        .layer(middleware::map_response(private_response)))
}
/// Compose explicit UserInfo over the actual SQLite grant snapshot producer.
pub fn sqlite_oidc_userinfo_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: OidcUserInfoHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    if config.request_timeout.is_zero()
        || Instant::now().checked_add(config.request_timeout).is_none()
        || isize::try_from(config.body_bytes.get()).is_err()
    {
        return Err(OidcTokenHttpConfigurationError);
    }
    let parameter_bytes = store
        .oidc_userinfo(authorization.clone(), verifier.clone())
        .map_err(|_| OidcTokenHttpConfigurationError)?
        .parameter_bytes();
    Ok(Router::new()
        .route(
            "/oauth/userinfo",
            on(MethodFilter::GET.or(MethodFilter::POST), userinfo),
        )
        .with_state(Arc::new(UserInfoState {
            backend: Backend::Sqlite(store),
            authorization,
            verifier,
            upstream,
            parameter_bytes,
            config,
        }))
        .layer(middleware::map_response(private_response)))
}
impl UserInfoState {
    async fn profile(
        &self,
        token: &str,
        end: Instant,
    ) -> Result<broker_control::OidcUserInfo, Error> {
        match &self.backend {
            Backend::Postgres(store) => {
                let producer = store.oidc_userinfo(&self.authorization, &self.verifier)?;
                let producer = match self.upstream.as_deref() {
                    Some(v) => producer.with_upstream(v),
                    None => producer,
                };
                producer.profile(token, end).await
            }
            Backend::Sqlite(store) => {
                let producer =
                    store.oidc_userinfo(self.authorization.clone(), self.verifier.clone())?;
                let producer = match &self.upstream {
                    Some(v) => producer.with_upstream(v.clone()),
                    None => producer,
                };
                producer.profile(token, end).await
            }
        }
    }
}
async fn private_response(response: Response) -> Response {
    no_store(response)
}
#[derive(Serialize)]
struct ErrorWire {
    error: &'static str,
}
fn failure(error: Error) -> Response {
    let (status, code) = match error {
        Error::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid_token"),
        Error::Control(ControlError::Deadline) => {
            (StatusCode::GATEWAY_TIMEOUT, "temporarily_unavailable")
        }
        Error::Control(ControlError::Closed | ControlError::OutcomeUncertain) => {
            (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    let mut response = (status, Json(ErrorWire { error: code })).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"graphit-broker\", error=\"invalid_token\""),
        );
    }
    response
}
fn invalid_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorWire {
            error: "invalid_request",
        }),
    )
        .into_response()
}
async fn userinfo(State(state): State<Arc<UserInfoState>>, request: Request) -> Response {
    if !matches!(*request.method(), Method::GET | Method::POST) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let Some(end) = Instant::now().checked_add(state.config.request_timeout) else {
        return failure(Error::InvalidConfiguration);
    };
    let token = match credential(
        request,
        end,
        state.config.body_bytes.get(),
        state.parameter_bytes,
    )
    .await
    {
        Ok(Some(token)) => token,
        Ok(None) => {
            let mut response = StatusCode::UNAUTHORIZED.into_response();
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"graphit-broker\""),
            );
            return response;
        }
        Err(error) => return error.response(),
    };
    match state.profile(&token, end).await {
        Ok(profile) => Json(profile).into_response(),
        Err(error) => failure(error),
    }
}
enum CredentialError {
    Request,
    Token,
    Deadline,
}
impl CredentialError {
    fn response(self) -> Response {
        match self {
            Self::Request => invalid_request(),
            Self::Token => failure(Error::InvalidToken),
            Self::Deadline => failure(ControlError::Deadline.into()),
        }
    }
}
async fn credential(
    mut request: Request,
    end: Instant,
    body_bytes: usize,
    parameter_bytes: usize,
) -> Result<Option<Zeroizing<String>>, CredentialError> {
    for (name, value) in request.headers_mut().iter_mut() {
        if name == header::AUTHORIZATION {
            value.set_sensitive(true);
        }
    }
    let header_token = {
        let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
        let first = values.next();
        if values.next().is_some() {
            return Err(CredentialError::Request);
        }
        first
            .map(|value| {
                Authorization::<Bearer>::decode(&mut std::iter::once(value))
                    .map(|v| Zeroizing::new(v.token().to_owned()))
                    .map_err(|_| CredentialError::Token)
            })
            .transpose()?
    };
    let query = request.uri().query().unwrap_or("");
    if query.len() > parameter_bytes {
        return Err(CredentialError::Request);
    }
    let mut query = crate::oauth_form::form(query.as_bytes(), &["access_token"])
        .map_err(|_| CredentialError::Request)?;
    let form_type = {
        let mut values = request.headers().get_all(header::CONTENT_TYPE).iter();
        let first = values.next();
        if values.next().is_some() {
            return Err(CredentialError::Request);
        }
        first
            .map(|value| {
                ContentType::decode(&mut std::iter::once(value)).map(|v| {
                    v.to_string().split(';').next() == Some("application/x-www-form-urlencoded")
                })
            })
            .transpose()
            .map_err(|_| CredentialError::Request)?
            .unwrap_or(false)
    };
    let post = request.method() == Method::POST;
    let body = tokio::time::timeout_at(end.into(), to_bytes(request.into_body(), body_bytes))
        .await
        .map_err(|_| CredentialError::Deadline)?
        .map_err(|_| CredentialError::Request)?;
    let body_token = if body.is_empty() {
        None
    } else {
        if !post || !form_type || body.len() > parameter_bytes {
            return Err(CredentialError::Request);
        }
        crate::oauth_form::form(&body, &["access_token"])
            .map_err(|_| CredentialError::Request)?
            .remove("access_token")
    };
    let mut tokens = [header_token, query.remove("access_token"), body_token]
        .into_iter()
        .flatten();
    let token = tokens.next();
    if tokens.next().is_some()
        || token
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > parameter_bytes)
    {
        return Err(CredentialError::Request);
    }
    Ok(token)
}
