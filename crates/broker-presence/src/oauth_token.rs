//! Productive form transport for the native committed code and refresh producers.
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use broker_control::{
    BrokerAccessIssuer, ControlError, OidcAuthorizationPolicy, OidcRefreshInput,
    OidcTokenExchangeError as Error, OidcTokenExchangeInput, OidcTokenExchangePolicy,
    PostgresControlStore, SqliteControlStore, UpstreamBearerVerifier,
};
use serde::Serialize;
use std::{
    fmt,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct OidcTokenHttpConfig {
    request_timeout: Duration,
    body_bytes: usize,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    device: Option<Arc<broker_control::DeviceAuthorizationPolicy>>,
}
impl fmt::Debug for OidcTokenHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcTokenHttpConfig([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OidcTokenHttpConfigurationError;
impl fmt::Display for OidcTokenHttpConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid OIDC token HTTP configuration")
    }
}
impl std::error::Error for OidcTokenHttpConfigurationError {}
impl OidcTokenHttpConfig {
    /// Attach the startup-owned upstream trust to both productive grant handlers.
    pub fn with_upstream(mut self, verifier: Arc<UpstreamBearerVerifier>) -> Self {
        self.upstream = Some(verifier);
        self
    }
    /// Attach Device only when the startup-owned LOCAL runtime is operational.
    pub fn with_device(mut self, policy: Arc<broker_control::DeviceAuthorizationPolicy>) -> Self {
        self.device = Some(policy);
        self
    }
    pub fn new(
        request_timeout: Duration,
        body_bytes: NonZeroUsize,
    ) -> Result<Self, OidcTokenHttpConfigurationError> {
        if request_timeout.is_zero()
            || Instant::now().checked_add(request_timeout).is_none()
            || isize::try_from(body_bytes.get()).is_err()
        {
            return Err(OidcTokenHttpConfigurationError);
        }
        Ok(Self {
            request_timeout,
            body_bytes: body_bytes.get(),
            upstream: None,
            device: None,
        })
    }
}
enum Backend {
    Postgres {
        store: Arc<PostgresControlStore>,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
        device: Option<Arc<broker_control::DeviceAuthorizationPolicy>>,
    },
    Sqlite {
        store: Arc<SqliteControlStore>,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
        device: Option<Arc<broker_control::DeviceAuthorizationPolicy>>,
    },
}
struct TokenState {
    backend: Backend,
    issuer: Arc<BrokerAccessIssuer>,
    authorization: Arc<OidcAuthorizationPolicy>,
    policy: Arc<OidcTokenExchangePolicy>,
    request_timeout: Duration,
    body_bytes: usize,
}
impl TokenState {
    fn router(
        backend: Backend,
        issuer: Arc<BrokerAccessIssuer>,
        authorization: Arc<OidcAuthorizationPolicy>,
        policy: Arc<OidcTokenExchangePolicy>,
        config: OidcTokenHttpConfig,
    ) -> Router {
        Router::new()
            .route("/oauth/token", post(exchange))
            .with_state(Arc::new(Self {
                backend,
                issuer,
                authorization,
                policy,
                request_timeout: config.request_timeout,
                body_bytes: config.body_bytes,
            }))
    }
    async fn device_poll(
        &self,
        client: &str,
        device: &str,
        end: Instant,
    ) -> Result<broker_control::DeviceAccessToken, broker_control::DeviceError> {
        match &self.backend {
            Backend::Postgres {
                store,
                device: Some(policy),
                ..
            } => {
                store
                    .device_authorizations(&self.authorization, policy, &self.issuer)?
                    .poll(client, device, end)
                    .await
            }
            Backend::Sqlite {
                store,
                device: Some(policy),
                ..
            } => {
                store
                    .device_authorizations(
                        self.authorization.clone(),
                        policy.clone(),
                        self.issuer.clone(),
                    )?
                    .poll(client, device, end)
                    .await
            }
            _ => Err(ControlError::Unavailable.into()),
        }
    }
    async fn exchange(
        &self,
        input: OidcTokenExchangeInput<'_>,
        end: Instant,
    ) -> Result<broker_control::OidcTokenExchangeResult, Error> {
        match &self.backend {
            Backend::Postgres {
                store, upstream, ..
            } => {
                let producer =
                    store.oidc_token_exchange(&self.authorization, &self.policy, &self.issuer)?;
                let producer = match upstream.as_deref() {
                    Some(v) => producer.with_upstream(v),
                    None => producer,
                };
                producer.exchange(input, end).await
            }
            Backend::Sqlite {
                store, upstream, ..
            } => {
                let producer = store.oidc_token_exchange(
                    Arc::clone(&self.authorization),
                    Arc::clone(&self.policy),
                    Arc::clone(&self.issuer),
                )?;
                let producer = match upstream {
                    Some(owner) => producer.with_upstream(owner.clone()),
                    None => producer,
                };
                producer.exchange(input, end).await
            }
        }
    }
    async fn rotate(
        &self,
        input: OidcRefreshInput<'_>,
        end: Instant,
    ) -> Result<broker_control::OidcTokenExchangeResult, Error> {
        match &self.backend {
            Backend::Postgres {
                store, upstream, ..
            } => {
                let producer =
                    store.oidc_refresh(&self.authorization, &self.policy, &self.issuer)?;
                let producer = match upstream.as_deref() {
                    Some(v) => producer.with_upstream(v),
                    None => producer,
                };
                producer.rotate(input, end).await
            }
            Backend::Sqlite {
                store, upstream, ..
            } => {
                let producer = store.oidc_refresh(
                    Arc::clone(&self.authorization),
                    Arc::clone(&self.policy),
                    Arc::clone(&self.issuer),
                )?;
                let producer = match upstream {
                    Some(owner) => producer.with_upstream(owner.clone()),
                    None => producer,
                };
                producer.rotate(input, end).await
            }
        }
    }
}
pub fn oidc_token_router(
    store: Arc<PostgresControlStore>,
    issuer: Arc<BrokerAccessIssuer>,
    authorization: Arc<OidcAuthorizationPolicy>,
    policy: Arc<OidcTokenExchangePolicy>,
    mut config: OidcTokenHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    store
        .oidc_token_exchange(&authorization, &policy, &issuer)
        .map_err(|_| OidcTokenHttpConfigurationError)?;
    if let Some(device) = &config.device {
        store
            .device_authorizations(&authorization, device, &issuer)
            .map_err(|_| OidcTokenHttpConfigurationError)?;
    }
    let backend = Backend::Postgres {
        store,
        upstream: config.upstream.take(),
        device: config.device.take(),
    };
    Ok(TokenState::router(
        backend,
        issuer,
        authorization,
        policy,
        config,
    ))
}
/// Serve native LOCAL code/refresh grants and explicitly configured Device polling.
/// This explicitly LOCAL composition rejects upstream at construction.
pub fn sqlite_local_oidc_token_router(
    store: Arc<SqliteControlStore>,
    issuer: Arc<BrokerAccessIssuer>,
    authorization: Arc<OidcAuthorizationPolicy>,
    policy: Arc<OidcTokenExchangePolicy>,
    config: OidcTokenHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    if config.upstream.is_some() {
        return Err(OidcTokenHttpConfigurationError);
    }
    sqlite_token_router(store, issuer, authorization, policy, config)
}
/// Serve native federated grants with the actual startup-owned trust verifier.
pub fn sqlite_oidc_token_router(
    store: Arc<SqliteControlStore>,
    issuer: Arc<BrokerAccessIssuer>,
    authorization: Arc<OidcAuthorizationPolicy>,
    policy: Arc<OidcTokenExchangePolicy>,
    config: OidcTokenHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    if config.upstream.is_none() {
        return Err(OidcTokenHttpConfigurationError);
    }
    sqlite_token_router(store, issuer, authorization, policy, config)
}
fn sqlite_token_router(
    store: Arc<SqliteControlStore>,
    issuer: Arc<BrokerAccessIssuer>,
    authorization: Arc<OidcAuthorizationPolicy>,
    policy: Arc<OidcTokenExchangePolicy>,
    mut config: OidcTokenHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    store
        .oidc_token_exchange(
            Arc::clone(&authorization),
            Arc::clone(&policy),
            Arc::clone(&issuer),
        )
        .map_err(|_| OidcTokenHttpConfigurationError)?;
    store
        .oidc_refresh(
            Arc::clone(&authorization),
            Arc::clone(&policy),
            Arc::clone(&issuer),
        )
        .map_err(|_| OidcTokenHttpConfigurationError)?;
    if let Some(device) = &config.device {
        store
            .device_authorizations(authorization.clone(), device.clone(), issuer.clone())
            .map_err(|_| OidcTokenHttpConfigurationError)?;
    }
    let backend = Backend::Sqlite {
        store,
        upstream: config.upstream.take(),
        device: config.device.take(),
    };
    Ok(TokenState::router(
        backend,
        issuer,
        authorization,
        policy,
        config,
    ))
}
#[derive(Serialize)]
struct TokenWire<'a> {
    access_token: &'a str,
    id_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    token_type: &'static str,
    expires_in: u64,
    scope: &'a str,
}
#[derive(Serialize)]
struct ErrorWire {
    error: &'static str,
}
pub(super) fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
pub(super) fn failure(error: Error) -> Response {
    let (status, code) = match error {
        Error::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
        Error::InvalidClient => (StatusCode::UNAUTHORIZED, "invalid_client"),
        Error::InvalidGrant => (StatusCode::BAD_REQUEST, "invalid_grant"),
        Error::InvalidTarget => (StatusCode::BAD_REQUEST, "invalid_target"),
        Error::InvalidScope => (StatusCode::BAD_REQUEST, "invalid_scope"),
        Error::UnsupportedGrantType => (StatusCode::BAD_REQUEST, "unsupported_grant_type"),
        Error::Control(ControlError::Deadline) => {
            (StatusCode::GATEWAY_TIMEOUT, "temporarily_unavailable")
        }
        Error::Control(ControlError::Closed | ControlError::OutcomeUncertain) => {
            (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    let mut response = no_store((status, Json(ErrorWire { error: code })).into_response());
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"graphit-broker\""),
        );
    }
    response
}
const PARAMETERS: &[&str] = &[
    "device_code",
    "grant_type",
    "client_id",
    "client_secret",
    "client_assertion",
    "client_assertion_type",
    "code",
    "redirect_uri",
    "code_verifier",
    "resource",
    "scope",
    "refresh_token",
];
async fn exchange(State(state): State<Arc<TokenState>>, request: Request) -> Response {
    let Some(end) = Instant::now().checked_add(state.request_timeout) else {
        return failure(Error::InvalidConfiguration);
    };
    let result = async {
        if request
            .uri()
            .query()
            .is_some_and(|q| q.len() > state.body_bytes)
        {
            return Err(Error::InvalidRequest);
        }
        let parsed = crate::oauth_form::read(request, PARAMETERS, end, state.body_bytes).await?;
        let fields = parsed.fields;
        let header = parsed.authorization;
        let get = |key: &str| fields.get(key).map(|v| v.as_str());
        let authorization = header.as_ref().map(|(u, p)| (u.as_str(), p.as_bytes()));
        if get("grant_type") == Some(broker_control::DEVICE_GRANT_TYPE) {
            if get("scope").is_some_and(|s| !s.is_empty()) {
                return Err(Error::InvalidScope);
            }
            if authorization.is_some()
                || [
                    "client_secret",
                    "code",
                    "redirect_uri",
                    "code_verifier",
                    "resource",
                    "refresh_token",
                ]
                .iter()
                .any(|k| get(k).is_some())
            {
                return Err(Error::InvalidRequest);
            }
            let result = async {
                let tokens = state
                    .device_poll(
                        get("client_id").unwrap_or(""),
                        get("device_code").unwrap_or(""),
                        end,
                    )
                    .await?;
                #[derive(Serialize)]
                struct DeviceWire<'a> {
                    access_token: &'a str,
                    token_type: &'static str,
                    expires_in: u64,
                    scope: &'a str,
                }
                let response = Json(DeviceWire {
                    access_token: tokens.access_token(),
                    token_type: "Bearer",
                    expires_in: tokens.expires_in(end)?,
                    scope: tokens.scope(),
                })
                .into_response();
                tokens.expires_in(end)?;
                Ok(no_store(response))
            }
            .await;
            return Ok(result.unwrap_or_else(crate::oauth_device::failure));
        }
        if get("device_code").is_some() {
            return Err(Error::InvalidRequest);
        }
        let tokens = if get("grant_type") == Some("refresh_token") {
            state
                .rotate(
                    OidcRefreshInput {
                        grant_type: get("grant_type"),
                        client_id: get("client_id"),
                        refresh_token: get("refresh_token"),
                        scope: get("scope"),
                        resource: get("resource"),
                        authorization,
                    },
                    end,
                )
                .await?
        } else {
            state
                .exchange(
                    OidcTokenExchangeInput {
                        grant_type: get("grant_type"),
                        client_id: get("client_id"),
                        code: get("code"),
                        redirect_uri: get("redirect_uri"),
                        code_verifier: get("code_verifier"),
                        resource: get("resource"),
                        authorization,
                    },
                    end,
                )
                .await?
        };
        let expires_in = tokens.expires_in(end)?;
        let response = Json(TokenWire {
            access_token: tokens.access_token(),
            id_token: tokens.id_token(),
            refresh_token: tokens.refresh_token(),
            token_type: "Bearer",
            expires_in,
            scope: tokens.scope(),
        })
        .into_response();
        tokens.expires_in(end)?;
        Ok(no_store(response))
    }
    .await;
    result.unwrap_or_else(failure)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn form(
        raw: &[u8],
    ) -> Result<std::collections::BTreeMap<String, zeroize::Zeroizing<String>>, Error> {
        crate::oauth_form::form(raw, PARAMETERS)
    }
    #[test]
    fn known_scalar_duplicates_fail_and_unknown_extensions_are_ignored() {
        assert!(form(b"code=a&code=b").is_err());
        assert!(form(b"resource=a&resource=a").is_err());
        let f = form(b"extension=a&extension=b&code=literal%2Bcode").unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f["code"].as_str(), "literal+code");
        assert!(form(b"code=%FF").is_err());
    }
}
