//! Hub discovery observations over the explicit SQL identity ingress.
use super::{
    HttpFailure, authentication_failure, bearer, control_failure, finalize_inventory_routes,
};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use broker_control::{
    BrokerAccessError, BrokerAccessVerifier, HubAccessError, HubAccessResolution,
    LocalBearerStateError, LocalBearerVerificationError, PostgresControlStore,
    ResourceGrantReadError, SqliteControlStore,
};
use headers::{Authorization, authorization::Bearer};
use std::{
    fmt,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct HubAccessHttpConfig {
    pub grants_json_bytes: NonZeroUsize,
    pub request_timeout: Duration,
}
pub struct LocalHubAccessHttpConfig {
    pub audience: String,
    pub identity_json_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
    pub request_timeout: Duration,
}
impl fmt::Debug for HubAccessHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HubAccessHttpConfig([REDACTED])")
    }
}
impl fmt::Debug for LocalHubAccessHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalHubAccessHttpConfig([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HubAccessHttpConfigurationError;
impl fmt::Display for HubAccessHttpConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Hub access HTTP configuration")
    }
}
impl std::error::Error for HubAccessHttpConfigurationError {}
struct BrokerState {
    store: HubStore,
    verifier: Arc<BrokerAccessVerifier>,
    config: HubAccessHttpConfig,
}
struct LocalState {
    store: HubStore,
    config: LocalHubAccessHttpConfig,
}
fn configuration_timeout(timeout: Duration) -> Result<(), HubAccessHttpConfigurationError> {
    if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
        return Err(HubAccessHttpConfigurationError);
    }
    Ok(())
}
/// Native JWT ingress. There is no opaque-token detection or fallback.
pub fn broker_hub_access_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: HubAccessHttpConfig,
) -> Result<Router, HubAccessHttpConfigurationError> {
    make_broker_router(HubStore::Postgres(store), verifier, config)
}
/// Native JWT ingress backed by current SQLite ACL observations.
pub fn sqlite_broker_hub_access_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: HubAccessHttpConfig,
) -> Result<Router, HubAccessHttpConfigurationError> {
    make_broker_router(HubStore::Sqlite(store), verifier, config)
}
fn make_broker_router(
    store: HubStore,
    verifier: Arc<BrokerAccessVerifier>,
    config: HubAccessHttpConfig,
) -> Result<Router, HubAccessHttpConfigurationError> {
    configuration_timeout(config.request_timeout)?;
    store.validate_broker(&verifier, config.grants_json_bytes)?;
    Ok(finalize_inventory_routes(Router::new().route(
        "/v1/hub/access/resolve",
        post(broker_resolve).with_state(Arc::new(BrokerState {
            store,
            verifier,
            config,
        })),
    )))
}
/// Local opaque ingress with explicit audience and current SQL identity.
pub fn local_hub_access_router(
    store: Arc<PostgresControlStore>,
    config: LocalHubAccessHttpConfig,
) -> Result<Router, HubAccessHttpConfigurationError> {
    make_local_router(HubStore::Postgres(store), config)
}
/// Explicit opaque ingress backed by current SQLite identity and ACL state.
pub fn sqlite_local_hub_access_router(
    store: Arc<SqliteControlStore>,
    config: LocalHubAccessHttpConfig,
) -> Result<Router, HubAccessHttpConfigurationError> {
    make_local_router(HubStore::Sqlite(store), config)
}
fn make_local_router(
    store: HubStore,
    config: LocalHubAccessHttpConfig,
) -> Result<Router, HubAccessHttpConfigurationError> {
    configuration_timeout(config.request_timeout)?;
    store.validate_local(
        &config.audience,
        config.identity_json_bytes,
        config.grants_json_bytes,
    )?;
    Ok(finalize_inventory_routes(Router::new().route(
        "/v1/hub/access/resolve",
        post(local_resolve).with_state(Arc::new(LocalState { store, config })),
    )))
}
pub(crate) fn optional_bearer(
    headers: &HeaderMap,
) -> Result<Option<Authorization<Bearer>>, HttpFailure> {
    let values = headers.get_all(header::AUTHORIZATION);
    let mut iter = values.iter();
    let Some(value) = iter.next() else {
        return Ok(None);
    };
    // Duplicates are ambiguous even when every value is empty.
    if iter.next().is_some() {
        return Err(HttpFailure::unauthenticated());
    }
    if value
        .to_str()
        .map_err(|_| HttpFailure::unauthenticated())?
        .trim()
        .is_empty()
    {
        return Ok(None);
    }
    bearer(headers).map(Some)
}
pub(crate) fn deadline(timeout: Duration) -> Result<Instant, HttpFailure> {
    Instant::now().checked_add(timeout).ok_or_else(|| {
        HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
    })
}
pub(crate) fn failure(error: HubAccessError) -> HttpFailure {
    match error {
        HubAccessError::Authentication(
            BrokerAccessError::InvalidToken | BrokerAccessError::Expired,
        ) => HttpFailure::unauthenticated(),
        HubAccessError::Authentication(BrokerAccessError::InsufficientScope) => {
            HttpFailure::new(StatusCode::FORBIDDEN, "insufficient_scope")
        }
        HubAccessError::Authentication(BrokerAccessError::InvalidConfiguration) => {
            HttpFailure::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
            )
        }
        HubAccessError::Authentication(BrokerAccessError::Deadline) => {
            HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline")
        }
        HubAccessError::LocalAuthentication(LocalBearerVerificationError::Control(error))
        | HubAccessError::LocalAuthentication(LocalBearerVerificationError::State(
            LocalBearerStateError::Control(error),
        )) => control_failure(error, "authorization_unavailable"),
        HubAccessError::LocalAuthentication(error) => authentication_failure(error),
        HubAccessError::Control(error)
        | HubAccessError::Grants(ResourceGrantReadError::Control(error)) => {
            control_failure(error, "authorization_unavailable")
        }
        HubAccessError::InvalidPolicy | HubAccessError::Grants(_) => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
        }
    }
}
fn response(mut resolved: HubAccessResolution<'_>) -> Result<Response, HttpFailure> {
    resolved.check().map_err(failure)?;
    let mut response = Json(resolved).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        headers::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}
async fn broker_resolve(
    State(state): State<Arc<BrokerState>>,
    request: Request,
) -> Result<Response, HttpFailure> {
    let end = deadline(state.config.request_timeout)?;
    let credential = optional_bearer(request.headers())?;
    let resolved = state
        .store
        .resolve_broker(
            &state.verifier,
            state.config.grants_json_bytes,
            credential.as_ref().map(|c| c.token()),
            end,
        )
        .await
        .map_err(failure)?;
    response(resolved)
}
async fn local_resolve(
    State(state): State<Arc<LocalState>>,
    request: Request,
) -> Result<Response, HttpFailure> {
    let end = deadline(state.config.request_timeout)?;
    let credential = optional_bearer(request.headers())?;
    let resolved = state
        .store
        .resolve_local(
            &state.config.audience,
            state.config.identity_json_bytes,
            state.config.grants_json_bytes,
            credential.as_ref().map(|c| c.token()),
            end,
        )
        .await
        .map_err(failure)?;
    response(resolved)
}

// Physical storage is selected by the factory, never by request claims.
pub(super) enum HubStore {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
impl HubStore {
    pub(super) fn validate_broker(
        &self,
        verifier: &BrokerAccessVerifier,
        cap: NonZeroUsize,
    ) -> Result<(), HubAccessHttpConfigurationError> {
        match self {
            Self::Postgres(store) => store.broker_hub_access_resolver(verifier, cap).map(|_| ()),
            Self::Sqlite(store) => store.broker_hub_access_resolver(verifier, cap).map(|_| ()),
        }
        .map_err(|_| HubAccessHttpConfigurationError)
    }
    pub(super) fn validate_local(
        &self,
        audience: &str,
        identity_cap: NonZeroUsize,
        grants_cap: NonZeroUsize,
    ) -> Result<(), HubAccessHttpConfigurationError> {
        match self {
            Self::Postgres(store) => store
                .local_hub_access_resolver(audience, identity_cap, grants_cap)
                .map(|_| ()),
            Self::Sqlite(store) => store
                .local_hub_access_resolver(audience, identity_cap, grants_cap)
                .map(|_| ()),
        }
        .map_err(|_| HubAccessHttpConfigurationError)
    }
    pub(super) async fn resolve_broker<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        cap: NonZeroUsize,
        raw: Option<&str>,
        end: Instant,
    ) -> Result<HubAccessResolution<'a>, HubAccessError> {
        match self {
            Self::Postgres(store) => {
                store
                    .broker_hub_access_resolver(verifier, cap)?
                    .resolve(raw, end)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .broker_hub_access_resolver(verifier, cap)?
                    .resolve(raw, end)
                    .await
            }
        }
    }
    pub(super) async fn resolve_local(
        &self,
        audience: &str,
        identity_cap: NonZeroUsize,
        grants_cap: NonZeroUsize,
        raw: Option<&str>,
        end: Instant,
    ) -> Result<HubAccessResolution<'static>, HubAccessError> {
        match self {
            Self::Postgres(store) => {
                store
                    .local_hub_access_resolver(audience, identity_cap, grants_cap)?
                    .resolve(raw, end)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .local_hub_access_resolver(audience, identity_cap, grants_cap)?
                    .resolve(raw, end)
                    .await
            }
        }
    }
}
