//! Actual PROJECT and USER storage admission and configured storage issuance over an explicit HTTP ingress.
use super::{
    HttpFailure, authentication_failure, bearer, control_failure, finalize_inventory_routes,
};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, post},
};
use broker_control::{
    AuthenticatedStorageCaller, AuthorizedStorageGrant, BrokerAccessError, BrokerAccessVerifier,
    PostgresBrokerStorageAuthorizer, PostgresControlStore, PostgresLocalStorageAuthorizer,
    ResourceGrantReadError, SqliteBrokerStorageAuthorizer, SqliteControlStore,
    SqliteLocalStorageAuthorizer, StorageAdmissionError, StorageModule, StorageScope,
};
use broker_storage::{IssuedStorageCredentials, StorageCredentialsService, StorageIssueError};
use serde::{
    Deserialize, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{
    fmt,
    marker::PhantomData,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub struct BrokerStorageCredentialsHttpConfig {
    pub required_scopes: Vec<String>,
    pub grants_json_bytes: NonZeroUsize,
    pub default_route: String,
    pub body_bytes: NonZeroUsize,
    pub request_timeout: Duration,
    pub enabled: bool,
}
pub struct LocalStorageCredentialsHttpConfig {
    pub required_scopes: Vec<String>,
    pub audience: String,
    pub identity_json_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
    pub default_route: String,
    pub body_bytes: NonZeroUsize,
    pub request_timeout: Duration,
    pub enabled: bool,
}
impl fmt::Debug for BrokerStorageCredentialsHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrokerStorageCredentialsHttpConfig([REDACTED])")
    }
}
impl fmt::Debug for LocalStorageCredentialsHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalStorageCredentialsHttpConfig([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCredentialsHttpConfigError;
impl fmt::Display for StorageCredentialsHttpConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid storage credentials HTTP configuration")
    }
}
impl std::error::Error for StorageCredentialsHttpConfigError {}

#[derive(Clone)]
enum StorageBackend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
enum BrokerFactory<'a> {
    Postgres(PostgresBrokerStorageAuthorizer<'a>),
    Sqlite(SqliteBrokerStorageAuthorizer<'a>),
}
enum LocalFactory<'a> {
    Postgres(PostgresLocalStorageAuthorizer<'a>),
    Sqlite(SqliteLocalStorageAuthorizer<'a>),
}
impl StorageBackend {
    fn broker_storage_authorizer<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        cap: NonZeroUsize,
        route: &str,
    ) -> Result<BrokerFactory<'a>, StorageAdmissionError> {
        match self {
            Self::Postgres(store) => store
                .broker_storage_authorizer(verifier, cap, route)
                .map(BrokerFactory::Postgres),
            Self::Sqlite(store) => store
                .broker_storage_authorizer(verifier, cap, route)
                .map(BrokerFactory::Sqlite),
        }
    }
    fn local_storage_authorizer<'a>(
        &'a self,
        audience: &'a str,
        identity_cap: NonZeroUsize,
        grants_cap: NonZeroUsize,
        route: &str,
    ) -> Result<LocalFactory<'a>, StorageAdmissionError> {
        match self {
            Self::Postgres(store) => store
                .local_storage_authorizer(audience, identity_cap, grants_cap, route)
                .map(LocalFactory::Postgres),
            Self::Sqlite(store) => store
                .local_storage_authorizer(audience, identity_cap, grants_cap, route)
                .map(LocalFactory::Sqlite),
        }
    }
}
impl BrokerFactory<'_> {
    fn authenticate<'s>(
        &'s self,
        raw: &str,
        scopes: &[String],
        original: Instant,
    ) -> Result<AuthenticatedStorageCaller<'s>, StorageAdmissionError> {
        match self {
            Self::Postgres(factory) => factory.authenticate(raw, scopes, original),
            Self::Sqlite(factory) => factory.authenticate(raw, scopes, original),
        }
    }
    async fn authorize_authenticated<'s>(
        &'s self,
        caller: AuthenticatedStorageCaller<'s>,
        scope: &StorageScope,
    ) -> Result<AuthorizedStorageGrant<'s>, StorageAdmissionError> {
        match self {
            Self::Postgres(factory) => factory.authorize_authenticated(caller, scope).await,
            Self::Sqlite(factory) => factory.authorize_authenticated(caller, scope).await,
        }
    }
}
impl LocalFactory<'_> {
    async fn authenticate<'s>(
        &'s self,
        raw: &str,
        scopes: &[String],
        original: Instant,
    ) -> Result<AuthenticatedStorageCaller<'s>, StorageAdmissionError> {
        match self {
            Self::Postgres(factory) => factory.authenticate(raw, scopes, original).await,
            Self::Sqlite(factory) => factory.authenticate(raw, scopes, original).await,
        }
    }
    async fn authorize_authenticated<'s>(
        &'s self,
        caller: AuthenticatedStorageCaller<'s>,
        scope: &StorageScope,
    ) -> Result<AuthorizedStorageGrant<'s>, StorageAdmissionError> {
        match self {
            Self::Postgres(factory) => factory.authorize_authenticated(caller, scope).await,
            Self::Sqlite(factory) => factory.authorize_authenticated(caller, scope).await,
        }
    }
}

struct BrokerState {
    store: StorageBackend,
    verifier: Arc<BrokerAccessVerifier>,
    issuer: Arc<StorageCredentialsService>,
    config: BrokerStorageCredentialsHttpConfig,
}
struct LocalState {
    store: StorageBackend,
    issuer: Arc<StorageCredentialsService>,
    config: LocalStorageCredentialsHttpConfig,
}
fn valid_config(scopes: &[String], timeout: Duration) -> bool {
    !timeout.is_zero()
        && Instant::now().checked_add(timeout).is_some()
        && !scopes.iter().any(|s| s.trim().is_empty())
}
fn finish(router: Router) -> Router {
    finalize_inventory_routes(router).layer(middleware::from_fn(no_store))
}
async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        headers::HeaderValue::from_static("no-store"),
    );
    response
}
fn disabled_router() -> Router {
    finish(Router::new().route(
        "/v1/s3/credentials",
        any(|| async { HttpFailure::new(StatusCode::NOT_FOUND, "capability_disabled") }),
    ))
}
/// Native JWT ingress with actual configured key/issuer/audience/resource trust.
/// `None` is allowed only when disabled; inactive topology is not fabricated.
/// ~~~no_run
/// fn router(
///     store: std::sync::Arc<broker_control::PostgresControlStore>,
///     verifier: std::sync::Arc<broker_control::BrokerAccessVerifier>,
///     issuer: Option<std::sync::Arc<broker_storage::StorageCredentialsService>>,
///     config: broker_presence::BrokerStorageCredentialsHttpConfig,
/// ) -> Result<axum::Router, broker_presence::StorageCredentialsHttpConfigError> {
///     broker_presence::broker_storage_credentials_router(store, verifier, issuer, config)
/// }
/// ~~~
pub fn broker_storage_credentials_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    issuer: Option<Arc<StorageCredentialsService>>,
    config: BrokerStorageCredentialsHttpConfig,
) -> Result<Router, StorageCredentialsHttpConfigError> {
    broker_router(StorageBackend::Postgres(store), verifier, issuer, config)
}
/// SQLite ingress over the actual configured store, factory and mature issuer.
pub fn sqlite_broker_storage_credentials_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    issuer: Option<Arc<StorageCredentialsService>>,
    config: BrokerStorageCredentialsHttpConfig,
) -> Result<Router, StorageCredentialsHttpConfigError> {
    broker_router(StorageBackend::Sqlite(store), verifier, issuer, config)
}
fn broker_router(
    store: StorageBackend,
    verifier: Arc<BrokerAccessVerifier>,
    issuer: Option<Arc<StorageCredentialsService>>,
    config: BrokerStorageCredentialsHttpConfig,
) -> Result<Router, StorageCredentialsHttpConfigError> {
    if !valid_config(&config.required_scopes, config.request_timeout) {
        return Err(StorageCredentialsHttpConfigError);
    }
    if !config.enabled {
        return Ok(disabled_router());
    }
    let issuer = issuer.ok_or(StorageCredentialsHttpConfigError)?;
    store
        .broker_storage_authorizer(&verifier, config.grants_json_bytes, &config.default_route)
        .map_err(|_| StorageCredentialsHttpConfigError)?;
    Ok(finish(Router::new().route(
        "/v1/s3/credentials",
        post(broker_issue).with_state(Arc::new(BrokerState {
            store,
            verifier,
            issuer,
            config,
        })),
    )))
}
/// Opaque access/service ingress with fresh SQL identity and explicit audience.
pub fn local_storage_credentials_router(
    store: Arc<PostgresControlStore>,
    issuer: Option<Arc<StorageCredentialsService>>,
    config: LocalStorageCredentialsHttpConfig,
) -> Result<Router, StorageCredentialsHttpConfigError> {
    local_router(StorageBackend::Postgres(store), issuer, config)
}
/// SQLite ingress over the actual configured store, factory and mature issuer.
pub fn sqlite_local_storage_credentials_router(
    store: Arc<SqliteControlStore>,
    issuer: Option<Arc<StorageCredentialsService>>,
    config: LocalStorageCredentialsHttpConfig,
) -> Result<Router, StorageCredentialsHttpConfigError> {
    local_router(StorageBackend::Sqlite(store), issuer, config)
}
fn local_router(
    store: StorageBackend,
    issuer: Option<Arc<StorageCredentialsService>>,
    config: LocalStorageCredentialsHttpConfig,
) -> Result<Router, StorageCredentialsHttpConfigError> {
    if !valid_config(&config.required_scopes, config.request_timeout) {
        return Err(StorageCredentialsHttpConfigError);
    }
    if !config.enabled {
        return Ok(disabled_router());
    }
    let issuer = issuer.ok_or(StorageCredentialsHttpConfigError)?;
    store
        .local_storage_authorizer(
            &config.audience,
            config.identity_json_bytes,
            config.grants_json_bytes,
            &config.default_route,
        )
        .map_err(|_| StorageCredentialsHttpConfigError)?;
    Ok(finish(Router::new().route(
        "/v1/s3/credentials",
        post(local_issue).with_state(Arc::new(LocalState {
            store,
            issuer,
            config,
        })),
    )))
}
struct ComposedState {
    broker: BrokerState,
    local: LocalState,
}

/// Select the credential envelope once, without retrying another authority.
/// Both factories use the same request Original and configured storage service.
pub fn storage_credentials_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    issuer: Option<Arc<StorageCredentialsService>>,
    broker: BrokerStorageCredentialsHttpConfig,
    local: LocalStorageCredentialsHttpConfig,
) -> Result<Router, StorageCredentialsHttpConfigError> {
    composed_router(
        StorageBackend::Postgres(store),
        verifier,
        issuer,
        broker,
        local,
    )
}
/// SQLite ingress over the actual configured store, factory and mature issuer.
pub fn sqlite_storage_credentials_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    issuer: Option<Arc<StorageCredentialsService>>,
    broker: BrokerStorageCredentialsHttpConfig,
    local: LocalStorageCredentialsHttpConfig,
) -> Result<Router, StorageCredentialsHttpConfigError> {
    composed_router(
        StorageBackend::Sqlite(store),
        verifier,
        issuer,
        broker,
        local,
    )
}
fn composed_router(
    store: StorageBackend,
    verifier: Arc<BrokerAccessVerifier>,
    issuer: Option<Arc<StorageCredentialsService>>,
    broker: BrokerStorageCredentialsHttpConfig,
    local: LocalStorageCredentialsHttpConfig,
) -> Result<Router, StorageCredentialsHttpConfigError> {
    if !valid_config(&broker.required_scopes, broker.request_timeout)
        || !valid_config(&local.required_scopes, local.request_timeout)
        || broker.enabled != local.enabled
        || broker.required_scopes != local.required_scopes
        || broker.grants_json_bytes != local.grants_json_bytes
        || broker.default_route != local.default_route
        || broker.body_bytes != local.body_bytes
        || broker.request_timeout != local.request_timeout
    {
        return Err(StorageCredentialsHttpConfigError);
    }
    if !broker.enabled {
        return Ok(disabled_router());
    }
    let issuer = issuer.ok_or(StorageCredentialsHttpConfigError)?;
    store
        .broker_storage_authorizer(&verifier, broker.grants_json_bytes, &broker.default_route)
        .map_err(|_| StorageCredentialsHttpConfigError)?;
    store
        .local_storage_authorizer(
            &local.audience,
            local.identity_json_bytes,
            local.grants_json_bytes,
            &local.default_route,
        )
        .map_err(|_| StorageCredentialsHttpConfigError)?;
    let state = Arc::new(ComposedState {
        broker: BrokerState {
            store: store.clone(),
            verifier,
            issuer: issuer.clone(),
            config: broker,
        },
        local: LocalState {
            store,
            issuer,
            config: local,
        },
    });
    Ok(finish(Router::new().route(
        "/v1/s3/credentials",
        post(composed_issue).with_state(state),
    )))
}

async fn composed_issue(
    State(state): State<Arc<ComposedState>>,
    mut request: Request,
) -> Result<Response, HttpFailure> {
    let end = original(state.broker.config.request_timeout)?;
    let raw = raw_bearer(&mut request)?;
    if raw.starts_with("gb_at_") || raw.starts_with("gb_sc_") {
        local_issue_with(&state.local, request, raw, end).await
    } else {
        broker_issue_with(&state.broker, request, raw, end).await
    }
}

// Only map root representations reach the mature field/duplicate decoder.
struct MapOnly<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor<T>(PhantomData<fn() -> T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for MapVisitor<T> {
            type Value = MapOnly<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(MapOnly)
            }
        }
        deserializer.deserialize_map(MapVisitor(PhantomData))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialsRequest {
    scope: String,
    module: String,
    #[serde(default, deserialize_with = "present_string")]
    project_id: Option<String>,
    #[serde(default, deserialize_with = "present_string")]
    installation_id: Option<String>,
}
// Absence is DATA; an explicitly present null or non-string is invalid JSON.
fn present_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}
impl CredentialsRequest {
    fn into_scope(self) -> Result<StorageScope, HttpFailure> {
        let invalid = || HttpFailure::new(StatusCode::BAD_REQUEST, "invalid_scope");
        match self.scope.as_str() {
            "project" => {
                if self.installation_id.is_some() {
                    return Err(HttpFailure::new(StatusCode::BAD_REQUEST, "invalid_json"));
                }
                let project = self
                    .project_id
                    .as_deref()
                    .ok_or_else(|| HttpFailure::new(StatusCode::BAD_REQUEST, "invalid_json"))?;
                let module = match self.module.as_str() {
                    "hub" => StorageModule::Hub,
                    "task" => StorageModule::Task,
                    "memory" => StorageModule::Memory,
                    "knowledge" => StorageModule::Knowledge,
                    "ast" => StorageModule::Ast,
                    _ => return Err(invalid()),
                };
                StorageScope::project(project, module).map_err(|_| invalid())
            }
            "user" if self.module == "memory" && self.project_id.is_none() => {
                let installation = self.installation_id.as_deref().ok_or_else(invalid)?;
                StorageScope::user_memory(installation).map_err(|_| invalid())
            }
            "hub"
                if self.module == "hub"
                    && self.project_id.is_none()
                    && self.installation_id.is_none() =>
            {
                Ok(StorageScope::global_hub())
            }
            _ => Err(invalid()),
        }
    }
}
fn raw_bearer(request: &mut Request) -> Result<Zeroizing<String>, HttpFailure> {
    for (name, value) in request.headers_mut().iter_mut() {
        if name == header::AUTHORIZATION {
            value.set_sensitive(true);
        }
    }
    bearer(request.headers()).map(|value| Zeroizing::new(value.token().to_owned()))
}
fn original(timeout: Duration) -> Result<Instant, HttpFailure> {
    Instant::now().checked_add(timeout).ok_or_else(|| {
        HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "configuration_unavailable")
    })
}
async fn input(
    mut request: Request,
    caller: &AuthenticatedStorageCaller<'_>,
    body_bytes: NonZeroUsize,
    end: Instant,
) -> Result<StorageScope, HttpFailure> {
    caller.check().map_err(admission_failure)?;
    DefaultBodyLimit::max(body_bytes.get()).apply(&mut request);
    let result = tokio::time::timeout_at(
        end.into(),
        Json::<MapOnly<CredentialsRequest>>::from_request(request, &()),
    )
    .await;
    caller.check().map_err(admission_failure)?;
    let Json(MapOnly(body)) = result
        .map_err(|_| HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"))?
        .map_err(|e| {
            if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
                HttpFailure::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large")
            } else {
                HttpFailure::new(StatusCode::BAD_REQUEST, "invalid_json")
            }
        })?;
    let scope = body.into_scope();
    caller.check().map_err(admission_failure)?;
    scope
}
async fn broker_issue(
    State(state): State<Arc<BrokerState>>,
    mut request: Request,
) -> Result<Response, HttpFailure> {
    let end = original(state.config.request_timeout)?;
    let raw = raw_bearer(&mut request)?;
    broker_issue_with(&state, request, raw, end).await
}
async fn broker_issue_with(
    state: &BrokerState,
    request: Request,
    raw: Zeroizing<String>,
    end: Instant,
) -> Result<Response, HttpFailure> {
    let factory = state
        .store
        .broker_storage_authorizer(
            &state.verifier,
            state.config.grants_json_bytes,
            &state.config.default_route,
        )
        .map_err(admission_failure)?;
    let caller = factory
        .authenticate(&raw, &state.config.required_scopes, end)
        .map_err(admission_failure)?;
    drop(raw);
    let scope = input(request, &caller, state.config.body_bytes, end).await?;
    let grant = factory
        .authorize_authenticated(caller, &scope)
        .await
        .map_err(admission_failure)?;
    response(&state.issuer, &grant).await
}
async fn local_issue(
    State(state): State<Arc<LocalState>>,
    mut request: Request,
) -> Result<Response, HttpFailure> {
    let end = original(state.config.request_timeout)?;
    let raw = raw_bearer(&mut request)?;
    local_issue_with(&state, request, raw, end).await
}
async fn local_issue_with(
    state: &LocalState,
    request: Request,
    raw: Zeroizing<String>,
    end: Instant,
) -> Result<Response, HttpFailure> {
    let factory = state
        .store
        .local_storage_authorizer(
            &state.config.audience,
            state.config.identity_json_bytes,
            state.config.grants_json_bytes,
            &state.config.default_route,
        )
        .map_err(admission_failure)?;
    let caller = factory
        .authenticate(&raw, &state.config.required_scopes, end)
        .await
        .map_err(admission_failure)?;
    drop(raw);
    let scope = input(request, &caller, state.config.body_bytes, end).await?;
    let grant = factory
        .authorize_authenticated(caller, &scope)
        .await
        .map_err(admission_failure)?;
    response(&state.issuer, &grant).await
}
#[derive(Serialize)]
struct CredentialsResponse<'a> {
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: &'a str,
    expires_at: &'a str,
    bucket: &'a str,
    region: &'a str,
    endpoint: &'a str,
    conditional_delete: bool,
    copy_if_not_exists: broker_storage::StorageCopyIfNotExists,
    prefixes: [&'a str; 1],
    authorization_revision: String,
    scope: &'static str,
    project_id: &'a str,
    module: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    installation_id: Option<&'a str>,
}
struct SecretBody(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for SecretBody {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
fn encode(
    keys: &IssuedStorageCredentials,
    scope: &StorageScope,
) -> Result<SecretBody, HttpFailure> {
    let revision = u64::try_from(keys.authorization_revision())
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| HttpFailure::new(StatusCode::BAD_GATEWAY, "invalid_credentials"))?;
    let wire = CredentialsResponse {
        access_key_id: keys.access_key_id(),
        secret_access_key: keys.secret_access_key(),
        session_token: keys.session_token(),
        expires_at: keys.expires_at(),
        bucket: keys.bucket(),
        region: keys.region(),
        endpoint: keys.endpoint().unwrap_or(""),
        conditional_delete: keys.supports_conditional_delete(),
        copy_if_not_exists: keys.copy_if_not_exists(),
        prefixes: [keys.base_prefix()],
        authorization_revision: revision.to_string(),
        scope: if scope.project_id().is_some() {
            "project"
        } else if scope.installation_id().is_some() {
            "user"
        } else {
            "hub"
        },
        project_id: scope.project_id().unwrap_or(""),
        module: scope.module().as_str(),
        installation_id: scope.installation_id(),
    };
    let mut buffer = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *buffer, &wire)
        .map_err(|_| HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "response_unavailable"))?;
    Ok(SecretBody(buffer))
}
async fn response(
    issuer: &StorageCredentialsService,
    grant: &AuthorizedStorageGrant<'_>,
) -> Result<Response, HttpFailure> {
    grant.check().map_err(admission_failure)?;
    let issued = issuer.issue(grant).await;
    grant.check().map_err(admission_failure)?;
    let keys = issued.map_err(issue_failure)?;
    let encoded = encode(&keys, grant.scope());
    grant.check().map_err(admission_failure)?;
    let bytes = Bytes::from_owner(encoded?);
    let mut result = Body::from(bytes).into_response();
    result.headers_mut().insert(
        header::CONTENT_TYPE,
        headers::HeaderValue::from_static("application/json"),
    );
    grant.check().map_err(admission_failure)?;
    Ok(result)
}
fn admission_failure(error: StorageAdmissionError) -> HttpFailure {
    match error {
        StorageAdmissionError::Native(error) => match error {
            BrokerAccessError::InvalidToken | BrokerAccessError::Expired => {
                HttpFailure::unauthenticated()
            }
            BrokerAccessError::InsufficientScope => {
                HttpFailure::new(StatusCode::FORBIDDEN, "insufficient_scope")
            }
            BrokerAccessError::Deadline => {
                HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline")
            }
            BrokerAccessError::InvalidConfiguration => HttpFailure::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
            ),
        },
        StorageAdmissionError::Local(error) => authentication_failure(error),
        StorageAdmissionError::Control(error)
        | StorageAdmissionError::Grants(ResourceGrantReadError::Control(error)) => {
            control_failure(error, "authorization_unavailable")
        }
        StorageAdmissionError::Grants(_) => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
        }
        StorageAdmissionError::InvalidScope => {
            HttpFailure::new(StatusCode::BAD_REQUEST, "invalid_scope")
        }
        StorageAdmissionError::Forbidden => HttpFailure::new(StatusCode::FORBIDDEN, "forbidden"),
        StorageAdmissionError::Deadline => {
            HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline")
        }
        StorageAdmissionError::InvalidConfiguration => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "configuration_unavailable")
        }
        StorageAdmissionError::InvalidPolicy => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "invalid_policy")
        }
        StorageAdmissionError::ConflictingRoutes => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "conflicting_routes")
        }
    }
}
fn issue_failure(error: StorageIssueError) -> HttpFailure {
    match error {
        StorageIssueError::Admission(error) => admission_failure(error),
        StorageIssueError::InvalidConfiguration => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "configuration_unavailable")
        }
        StorageIssueError::RouteUnavailable => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "route_unavailable")
        }
        StorageIssueError::PolicyTooLarge => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "policy_too_large")
        }
        StorageIssueError::Deadline => HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"),
        StorageIssueError::Forbidden => {
            HttpFailure::new(StatusCode::BAD_GATEWAY, "storage_credentials_refused")
        }
        StorageIssueError::Provider => {
            HttpFailure::new(StatusCode::BAD_GATEWAY, "credential_provider_unavailable")
        }
        StorageIssueError::Sdk => {
            HttpFailure::new(StatusCode::BAD_GATEWAY, "storage_credentials_unavailable")
        }
        StorageIssueError::InvalidResponse => {
            HttpFailure::new(StatusCode::BAD_GATEWAY, "invalid_credentials")
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_is_exact_object_and_scope_data() {
        let good =
            r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"hub"}"#;
        for module in ["hub", "task", "memory", "knowledge", "ast"] {
            let data = good.replace("hub", module);
            let MapOnly(v) = serde_json::from_str::<MapOnly<CredentialsRequest>>(&data).unwrap();
            let scope = v.into_scope().unwrap();
            assert_eq!(scope.project_id(), Some("01D39ZY06FGSCTVN4T2V9PKHFZ"));
            assert_eq!(scope.module().as_str(), module);
        }
        for bad in [
            r#"["project","01D39ZY06FGSCTVN4T2V9PKHFZ","hub"]"#,
            r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"hub","route":"injected"}"#,
            r#"{"scope":"project","scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"hub"}"#,
            r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ"}"#,
            r#"{"scope":{"project":null},"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"hub"}"#,
        ] {
            assert!(serde_json::from_str::<MapOnly<CredentialsRequest>>(bad).is_err());
        }
        for (scope, module, id) in [
            ("user", "hub", "01D39ZY06FGSCTVN4T2V9PKHFZ"),
            ("project", "fs", "01D39ZY06FGSCTVN4T2V9PKHFZ"),
            ("project", "hub", "00000000000000000000000000"),
        ] {
            assert!(
                CredentialsRequest {
                    scope: scope.into(),
                    module: module.into(),
                    project_id: Some(id.into()),
                    installation_id: None
                }
                .into_scope()
                .is_err()
            );
        }
    }
    #[test]
    fn project_required_and_unknown_id_errors_are_preserved() {
        for input in [
            r#"{"scope":"project","module":"memory"}"#,
            r#"{"scope":"project","module":"memory","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","installation_id":"a"}"#,
        ] {
            let MapOnly(v) = serde_json::from_str::<MapOnly<CredentialsRequest>>(input).unwrap();
            let failure = v.into_scope().unwrap_err();
            assert_eq!(failure.status, StatusCode::BAD_REQUEST);
            assert_eq!(failure.code, "invalid_json");
        }
    }
    #[test]
    fn user_request_has_exact_canonical_data_and_rejects_null_incompatible_ids() {
        for installation in ["a", "Install-A", "Install.B_2", &"A".repeat(128)] {
            let data = serde_json::json!({"scope":"user","module":"memory","installation_id":installation});
            let MapOnly(v) = serde_json::from_value::<MapOnly<CredentialsRequest>>(data).unwrap();
            let scope = v.into_scope().unwrap();
            assert_eq!(scope.project_id(), None);
            assert_eq!(scope.installation_id(), Some(installation));
            assert_eq!(scope.module(), StorageModule::Memory);
        }
        for bad in [
            r#"{"scope":"user","module":"memory","installation_id":null}"#,
            r#"{"scope":"user","module":"memory","installation_id":"a","project_id":null}"#,
            r#"{"scope":"project","module":"memory","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","installation_id":null}"#,
            r#"{"scope":"user","module":"memory","installation_id":"a","installation_id":"b"}"#,
            r#"{"scope":"user","module":"memory","installation_id":"a","issuer":"injected"}"#,
            r#"["user","memory","a"]"#,
            r#"{"scope":"user","module":"memory","installation_id":"a"}{}"#,
        ] {
            assert!(serde_json::from_str::<MapOnly<CredentialsRequest>>(bad).is_err());
        }
        for data in [
            serde_json::json!({"scope":"user","module":"memory"}),
            serde_json::json!({"scope":"user","module":"memory","installation_id":"a","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ"}),
            serde_json::json!({"scope":"project","module":"memory","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","installation_id":"a"}),
            serde_json::json!({"scope":"user","module":"hub","installation_id":"a"}),
            serde_json::json!({"scope":"USER","module":"memory","installation_id":"a"}),
            serde_json::json!({"scope":"hub","module":"memory"}),
            serde_json::json!({"scope":"user","module":"memory","installation_id":" a"}),
            serde_json::json!({"scope":"user","module":"memory","installation_id":"a/escape"}),
        ] {
            let MapOnly(v) = serde_json::from_value::<MapOnly<CredentialsRequest>>(data).unwrap();
            assert!(v.into_scope().is_err());
        }
    }
    #[test]
    fn global_hub_body_is_scope_data_without_owner_or_project() {
        let MapOnly(v) = serde_json::from_str::<MapOnly<CredentialsRequest>>(
            r#"{"scope":"hub","module":"hub"}"#,
        )
        .unwrap();
        let scope = v.into_scope().unwrap();
        assert_eq!(scope.project_id(), None);
        assert_eq!(scope.installation_id(), None);
        assert_eq!(scope.module(), StorageModule::Hub);
        for field in ["project_id", "installation_id"] {
            let data = format!(r#"{{"scope":"hub","module":"hub","{field}":null}}"#);
            assert!(serde_json::from_str::<MapOnly<CredentialsRequest>>(&data).is_err());
            let data = format!(r#"{{"scope":"hub","module":"hub","{field}":"a"}}"#);
            let MapOnly(v) = serde_json::from_str::<MapOnly<CredentialsRequest>>(&data).unwrap();
            assert!(v.into_scope().is_err());
        }
    }
    #[test]
    fn errors_preserve_origin_status_and_challenge() {
        for (error, (status, code)) in [
            (
                StorageAdmissionError::Native(BrokerAccessError::InsufficientScope),
                (StatusCode::FORBIDDEN, "insufficient_scope"),
            ),
            (
                StorageAdmissionError::Native(BrokerAccessError::Expired),
                (StatusCode::UNAUTHORIZED, "unauthenticated"),
            ),
            (
                StorageAdmissionError::Control(broker_control::ControlError::OutcomeUncertain),
                (StatusCode::SERVICE_UNAVAILABLE, "outcome_uncertain"),
            ),
        ] {
            let failure = admission_failure(error);
            assert_eq!(failure.status, status);
            assert_eq!(failure.code, code);
        }
        let response = admission_failure(StorageAdmissionError::Native(
            BrokerAccessError::InsufficientScope,
        ))
        .into_response();
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"insufficient_scope\""
        );
        assert_eq!(
            issue_failure(StorageIssueError::Forbidden).status,
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            issue_failure(StorageIssueError::Deadline).status,
            StatusCode::GATEWAY_TIMEOUT
        );
    }
}
