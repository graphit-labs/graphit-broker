//! Authenticated instance inventory HTTP routing for the Rust Broker server.
//! The router owns no separate runtime or SQL pool. Supply the shared store,
//! explicit audience/scopes, useful byte limits and a positive request timeout.
mod rerank;
pub use rerank::{
    RerankConfigurationError, RerankHttpConfig, disabled_rerank_router, postgres_rerank_router,
    sqlite_rerank_router,
};
mod local_model;
pub use local_model::{LocalEmbeddingConfig, LocalRerankConfig};
mod rerank_backend;
pub use rerank_backend::{RemoteRerankConfig, RerankBackend, RerankBackendError, RerankResult};
mod embeddings;
pub use embeddings::{
    EmbeddingBackend, EmbeddingsError, EmbeddingsHttpConfig, RemoteEmbeddingsConfig,
    disabled_embeddings_router, postgres_embeddings_router, sqlite_embeddings_router,
};
mod instruction_overrides;
pub use instruction_overrides::{
    InstructionHttpConfig, InstructionStore, instruction_overrides_router,
};
mod admin_cookie;
mod admin_upstream_login;
pub use admin_cookie::{AdminCookieHttpConfig, admin_cookie_header};
pub use admin_upstream_login::{
    AdminUpstreamLoginHttpConfig, OidcUpstreamLoginHttpConfig, SqliteOidcUpstreamLoginHttpConfig,
    UpstreamLoginHttpConfig, sqlite_oidc_upstream_login_router, sqlite_upstream_login_router,
    upstream_login_flow_cookie, upstream_login_flow_cookie_name, upstream_login_router,
};
mod admin_local_login;
mod local_login;
mod sqlite_local_login;
pub use admin_local_login::{
    AdminLocalLoginHttpConfig, admin_local_login_router, sqlite_admin_local_login_router,
    sqlite_admin_local_login_router_with_upstream,
};
pub use local_login::LocalLoginRuntime;
pub use sqlite_local_login::SqliteLocalLoginRuntime;
mod admin_grants;
mod admin_rbac;
mod admin_read;
mod admin_users;
pub use admin_grants::{AdminGrantsHttpConfig, admin_grants_router, sqlite_admin_grants_router};
pub use admin_rbac::{admin_rbac_router, sqlite_admin_rbac_router};
pub use admin_users::{AdminUsersHttpConfig, admin_users_router, sqlite_admin_users_router};
mod admin_session;
pub use admin_read::{AdminReadHttpConfig, admin_read_router, sqlite_admin_read_router};
pub use admin_session::{
    AdminLocalBearerHttpConfig, AdminSessionHttpConfig, admin_session_router,
    admin_session_router_with_authentication, admin_session_router_with_cookie,
    admin_session_router_with_local_bearer, sqlite_admin_session_router_with_cookie,
    sqlite_local_admin_session_router,
};
mod oauth_registration;
pub use oauth_registration::{
    OidcRegistrationHttpConfig, OidcRegistrationHttpConfigurationError, oidc_registration_router,
    sqlite_oidc_registration_router,
};
mod oauth_browser;
mod oauth_response;
pub use oauth_browser::{
    OidcBrowserHttpConfig, oidc_browser_router, sqlite_local_oidc_browser_router,
    sqlite_oidc_browser_router,
};
mod oauth_end_session;
mod oauth_form;
mod oauth_introspection;
mod oauth_revocation;
pub use oauth_end_session::{
    OidcEndSessionHttpConfig, oidc_end_session_router, sqlite_oidc_end_session_router,
};
pub use oauth_introspection::{
    OidcIntrospectionHttpConfig, oidc_introspection_router, sqlite_oidc_introspection_router,
};
mod oauth_userinfo;
pub use oauth_revocation::{
    OidcRevocationHttpConfig, oidc_revocation_router, sqlite_oidc_revocation_router,
};
pub use oauth_userinfo::{
    OidcUserInfoHttpConfig, oidc_userinfo_router, sqlite_oidc_userinfo_router,
};
mod oauth_device;
mod oauth_token;
pub use oauth_device::{OidcDeviceHttpConfig, oidc_device_router, sqlite_local_oidc_device_router};
mod realtime;
pub use oauth_token::{
    OidcTokenHttpConfig, OidcTokenHttpConfigurationError, oidc_token_router,
    sqlite_local_oidc_token_router, sqlite_oidc_token_router,
};
pub use realtime::{
    LocalRealtimeHttpConfig, RealtimeHttpConfig, RealtimeServerError, RealtimeServerRuntime,
    broker_realtime_router, local_realtime_router, sqlite_broker_realtime_router,
    sqlite_local_realtime_router,
};
mod realtime_hub;
pub use realtime_hub::{
    RealtimeHub, RealtimeHubError, RealtimeHubInstance, RealtimeHubMaintenance, RealtimeHubReplay,
    RealtimeHubSignalError, RealtimeProjectSubscription, RealtimePublisherHandle,
};
mod broker_inventory;
pub use broker_inventory::{
    BrokerInventoryHttpConfigurationError, BrokerOwnReadHttpConfig, BrokerPublishHttpConfig,
    broker_instance_inventory_router, sqlite_broker_instance_inventory_router,
};
mod filesystem_storage;
mod storage_credentials;
pub use filesystem_storage::FilesystemStorageHttp;
pub use storage_credentials::{
    BrokerStorageCredentialsHttpConfig, LocalStorageCredentialsHttpConfig,
    StorageCredentialsHttpConfigError, broker_storage_credentials_router,
    local_storage_credentials_router, sqlite_broker_storage_credentials_router,
    sqlite_local_storage_credentials_router, sqlite_storage_credentials_router,
    storage_credentials_router,
};
mod hub_access;
pub use hub_access::{
    HubAccessHttpConfig, HubAccessHttpConfigurationError, LocalHubAccessHttpConfig,
    broker_hub_access_router, local_hub_access_router, sqlite_broker_hub_access_router,
    sqlite_local_hub_access_router,
};
mod inventory_list;
mod inventory_read;
mod project_authorization;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Path, Request, State, rejection::PathRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{MethodRouter, put},
};
use broker_control::{
    ControlError, InstanceInventory, InstanceProjectVersions, InstanceRegistrationError,
    InstanceRegistryError, LocalBearerStateError, LocalBearerVerificationError,
    PostgresControlStore, PresenceAuthorizationError, RegistrationChange, ResourceGrantReadError,
};
use headers::{Authorization, Header, authorization::Bearer};
pub use inventory_list::InstanceInventoryListHttpConfig;
pub use inventory_read::{
    InstanceInventoryReadHttpConfig, InstanceInventoryReadHttpConfigurationError,
    instance_inventory_read_router, instance_inventory_router,
    sqlite_instance_inventory_read_router, sqlite_instance_inventory_router,
};
pub use project_authorization::{
    BrokerProjectAuthorizationHttpConfig, ProjectAuthorizationHttpConfig,
    ProjectAuthorizationHttpConfigurationError, broker_project_authorization_router,
    project_authorization_router, sqlite_broker_project_authorization_router,
    sqlite_project_authorization_router,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

/// Explicit integration settings; no audience, scope or size defaults are inferred.
pub struct InstanceRegistryHttpConfig {
    pub audience: String,
    pub required_scopes: Vec<String>,
    pub identity_json_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
    pub body_bytes: NonZeroUsize,
    pub request_timeout: Duration,
}
impl fmt::Debug for InstanceRegistryHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceRegistryHttpConfig([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryHttpConfigurationError;
impl fmt::Display for RegistryHttpConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid instance registry HTTP configuration")
    }
}
impl std::error::Error for RegistryHttpConfigurationError {}

enum RegistryStore {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<broker_control::SqliteControlStore>),
}
impl RegistryStore {
    fn validate(
        &self,
        config: &InstanceRegistryHttpConfig,
    ) -> Result<(), InstanceRegistrationError> {
        match self {
            Self::Postgres(store) => {
                store.local_instance_registrar(
                    &config.audience,
                    config.identity_json_bytes,
                    config.grants_json_bytes,
                )?;
            }
            Self::Sqlite(store) => {
                store.local_instance_registrar(
                    &config.audience,
                    config.identity_json_bytes,
                    config.grants_json_bytes,
                )?;
            }
        }
        Ok(())
    }
    async fn register(
        &self,
        config: &InstanceRegistryHttpConfig,
        raw: &str,
        inventory: &InstanceInventory,
        end: Instant,
    ) -> Result<broker_control::RegistrationResult, InstanceRegistrationError> {
        match self {
            Self::Postgres(store) => {
                store
                    .local_instance_registrar(
                        &config.audience,
                        config.identity_json_bytes,
                        config.grants_json_bytes,
                    )?
                    .register(raw, &config.required_scopes, inventory, end)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .local_instance_registrar(
                        &config.audience,
                        config.identity_json_bytes,
                        config.grants_json_bytes,
                    )?
                    .register(raw, &config.required_scopes, inventory, end)
                    .await
            }
        }
    }
}
struct RegistryState {
    store: RegistryStore,
    config: InstanceRegistryHttpConfig,
}
/// A shared-store router with one complete registration route.
/// The serving application supplies its listener and normal shutdown lifecycle.
/// ~~~no_run
/// fn routes(store: std::sync::Arc<broker_control::PostgresControlStore>)
///     -> Result<axum::Router, broker_presence::RegistryHttpConfigurationError> {
///     broker_presence::instance_registry_router(store, broker_presence::InstanceRegistryHttpConfig {
///         audience: "explicit-audience".into(),
///         required_scopes: vec!["presence:publish".into()],
///         identity_json_bytes: std::num::NonZeroUsize::new(4096).unwrap(),
///         grants_json_bytes: std::num::NonZeroUsize::new(16384).unwrap(),
///         body_bytes: std::num::NonZeroUsize::new(4096).unwrap(),
///         request_timeout: std::time::Duration::from_secs(2),
///     })
/// }
/// ~~~
pub fn instance_registry_router(
    store: Arc<PostgresControlStore>,
    config: InstanceRegistryHttpConfig,
) -> Result<Router, RegistryHttpConfigurationError> {
    Ok(inventory_route(registration_method_router(store, config)?))
}
fn registration_method_router(
    store: Arc<PostgresControlStore>,
    config: InstanceRegistryHttpConfig,
) -> Result<MethodRouter, RegistryHttpConfigurationError> {
    registration_methods(RegistryStore::Postgres(store), config)
}
/// Register inventory through current LOCAL bearer and project grants in SQLite.
pub fn sqlite_instance_registry_router(
    store: Arc<broker_control::SqliteControlStore>,
    config: InstanceRegistryHttpConfig,
) -> Result<Router, RegistryHttpConfigurationError> {
    Ok(inventory_route(sqlite_registration_method_router(
        store, config,
    )?))
}
fn sqlite_registration_method_router(
    store: Arc<broker_control::SqliteControlStore>,
    config: InstanceRegistryHttpConfig,
) -> Result<MethodRouter, RegistryHttpConfigurationError> {
    registration_methods(RegistryStore::Sqlite(store), config)
}
fn registration_methods(
    store: RegistryStore,
    config: InstanceRegistryHttpConfig,
) -> Result<MethodRouter, RegistryHttpConfigurationError> {
    if config.audience.trim().is_empty()
        || config.request_timeout.is_zero()
        || Instant::now().checked_add(config.request_timeout).is_none()
        || config.required_scopes.iter().any(|s| s.trim().is_empty())
    {
        return Err(RegistryHttpConfigurationError);
    }
    store
        .validate(&config)
        .map_err(|_| RegistryHttpConfigurationError)?;
    let state = Arc::new(RegistryState { store, config });
    Ok(put(register_inventory).with_state(state))
}
fn inventory_route(methods: MethodRouter) -> Router {
    finalize_inventory_routes(Router::new().route("/v1/instances/{id}/inventory", methods))
}
fn inventory_and_list_routes(methods: MethodRouter, list: MethodRouter) -> Router {
    finalize_inventory_routes(
        Router::new()
            .route("/v1/instances/{id}/inventory", methods)
            .route("/v1/instances", list),
    )
}
fn finalize_inventory_routes(router: Router) -> Router {
    router
        .fallback(|| async { HttpFailure::new(StatusCode::NOT_FOUND, "not_found") })
        .method_not_allowed_fallback(|| async {
            HttpFailure::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
        })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryRequest {
    projects: Vec<ProjectRequest>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRequest {
    project_id: String,
    versions: Vec<String>,
}
impl InventoryRequest {
    fn into_inventory(self, id: String) -> Result<InstanceInventory, HttpFailure> {
        let projects = self
            .projects
            .into_iter()
            .map(|p| {
                InstanceProjectVersions::new(p.project_id, p.versions)
                    .map_err(|_| HttpFailure::bad_inventory())
            })
            .collect::<Result<Vec<_>, _>>()?;
        InstanceInventory::new(id, projects).map_err(|_| HttpFailure::bad_inventory())
    }
}
#[derive(Serialize)]
struct InventoryResponse<'a> {
    instance_id: &'a str,
    change: &'static str,
    created_at: i64,
    updated_at: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HttpFailure {
    status: StatusCode,
    code: &'static str,
}
impl HttpFailure {
    const fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }
    const fn bad_inventory() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_inventory")
    }
    const fn unauthenticated() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthenticated")
    }
}
#[derive(Serialize)]
struct ErrorResponse {
    error: ErrorCode,
}
#[derive(Serialize)]
struct ErrorCode {
    code: &'static str,
}
impl IntoResponse for HttpFailure {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorResponse {
                error: ErrorCode { code: self.code },
            }),
        )
            .into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                headers::HeaderValue::from_static("Bearer"),
            );
        }
        if self.status == StatusCode::FORBIDDEN && self.code == "insufficient_scope" {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                headers::HeaderValue::from_static("Bearer error=\"insufficient_scope\""),
            );
        }
        response
    }
}
fn control_failure(error: ControlError, unavailable: &'static str) -> HttpFailure {
    match error {
        ControlError::Deadline => HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"),
        ControlError::Closed => HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "closed"),
        ControlError::OutcomeUncertain => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "outcome_uncertain")
        }
        _ => HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, unavailable),
    }
}
fn authentication_failure(error: LocalBearerVerificationError) -> HttpFailure {
    match error {
        LocalBearerVerificationError::Unauthenticated => HttpFailure::unauthenticated(),
        LocalBearerVerificationError::Control(c)
        | LocalBearerVerificationError::State(LocalBearerStateError::Control(c)) => {
            control_failure(c, "authentication_unavailable")
        }
        LocalBearerVerificationError::State(_) => HttpFailure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        ),
    }
}
fn authorization_failure(error: PresenceAuthorizationError) -> HttpFailure {
    match error {
        PresenceAuthorizationError::InvalidProject => HttpFailure::bad_inventory(),
        PresenceAuthorizationError::InvalidPolicy => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "invalid_policy")
        }
        PresenceAuthorizationError::Forbidden => {
            HttpFailure::new(StatusCode::FORBIDDEN, "forbidden")
        }
        PresenceAuthorizationError::Authentication(e) => authentication_failure(e),
        PresenceAuthorizationError::Control(c)
        | PresenceAuthorizationError::Grants(ResourceGrantReadError::Control(c)) => {
            control_failure(c, "authorization_unavailable")
        }
        PresenceAuthorizationError::Grants(_) => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
        }
    }
}
impl From<InstanceRegistrationError> for HttpFailure {
    fn from(error: InstanceRegistrationError) -> Self {
        match error {
            InstanceRegistrationError::Authorization(e) => authorization_failure(e),
            InstanceRegistrationError::Registry(InstanceRegistryError::OwnerConflict) => {
                Self::new(StatusCode::CONFLICT, "owner_conflict")
            }
            InstanceRegistrationError::Registry(InstanceRegistryError::InvalidInventory) => {
                Self::bad_inventory()
            }
            InstanceRegistrationError::Registry(InstanceRegistryError::Control(c)) => {
                control_failure(c, "registration_unavailable")
            }
            InstanceRegistrationError::Registry(_) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "registration_unavailable")
            }
        }
    }
}
fn bearer(headers: &HeaderMap) -> Result<Authorization<Bearer>, HttpFailure> {
    let values = headers.get_all(header::AUTHORIZATION);
    if values.iter().count() != 1 {
        return Err(HttpFailure::unauthenticated());
    }
    Authorization::<Bearer>::decode(&mut values.iter()).map_err(|_| HttpFailure::unauthenticated())
}
async fn register_inventory(
    State(state): State<Arc<RegistryState>>,
    path: Result<Path<String>, PathRejection>,
    mut request: Request,
) -> Result<Response, HttpFailure> {
    let end = Instant::now()
        .checked_add(state.config.request_timeout)
        .ok_or_else(|| {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "registration_unavailable")
        })?;
    let credential = bearer(request.headers())?;
    let Path(id) = path.map_err(|_| HttpFailure::bad_inventory())?;
    DefaultBodyLimit::max(state.config.body_bytes.get()).apply(&mut request);
    let Json(input) = tokio::time::timeout_at(
        end.into(),
        Json::<InventoryRequest>::from_request(request, &state),
    )
    .await
    .map_err(|_| HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"))?
    .map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            HttpFailure::new(StatusCode::BAD_REQUEST, "body_too_large")
        } else {
            HttpFailure::new(StatusCode::BAD_REQUEST, "invalid_json")
        }
    })?;
    let inventory = input.into_inventory(id)?;
    let result = state
        .store
        .register(&state.config, credential.token(), &inventory, end)
        .await?;
    let (status, change) = match result.change() {
        RegistrationChange::Created => (StatusCode::CREATED, "created"),
        RegistrationChange::Updated => (StatusCode::OK, "updated"),
        RegistrationChange::Unchanged => (StatusCode::OK, "unchanged"),
    };
    Ok((
        status,
        Json(InventoryResponse {
            instance_id: result.instance_id(),
            change,
            created_at: result.created_at_micros(),
            updated_at: result.updated_at_micros(),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_wire_and_inventory_validation_reject_supplied_authority() {
        for raw in [
            "{}",
            r#"{"projects":null}"#,
            r#"{"projects":[],"owner":"forged"}"#,
            r#"{"projects":[],"created_at":0}"#,
            r#"{"projects":[],"projects":[]}"#,
            r#"{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main"],"subject":"forged"}]}"#,
            r#"{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main"]}]}"#,
            r#"{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ"}]}"#,
            r#"{"projects":[]} trailing"#,
        ] {
            assert!(serde_json::from_str::<InventoryRequest>(raw).is_err());
        }
        for raw in [
            r#"{"projects":[{"project_id":"friendly","versions":["main"]}]}"#,
            r#"{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main","main"]}]}"#,
            r#"{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":[" main"]}]}"#,
            r#"{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main"]},{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["release"]}]}"#,
        ] {
            assert!(
                serde_json::from_str::<InventoryRequest>(raw)
                    .unwrap()
                    .into_inventory("station".into())
                    .is_err()
            );
        }
        let empty = serde_json::from_str::<InventoryRequest>(r#"{"projects":[]}"#).unwrap();
        assert!(
            empty
                .into_inventory("station".into())
                .unwrap()
                .projects()
                .is_empty()
        );
    }
    #[test]
    fn sdk_bearer_requires_one_authorization_value_and_preserves_token_bytes() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            bearer(&headers).unwrap_err(),
            HttpFailure::unauthenticated()
        );
        for value in ["Basic dTpw", "Bearer"] {
            headers.insert(header::AUTHORIZATION, value.parse().unwrap());
            assert_eq!(
                bearer(&headers).unwrap_err(),
                HttpFailure::unauthenticated()
            );
        }
        headers.insert(header::AUTHORIZATION, "Bearer gb_at_exact".parse().unwrap());
        assert_eq!(bearer(&headers).unwrap().token(), "gb_at_exact");
        headers.append(
            header::AUTHORIZATION,
            "Bearer gb_sc_second".parse().unwrap(),
        );
        assert_eq!(
            bearer(&headers).unwrap_err(),
            HttpFailure::unauthenticated()
        );
    }
    #[test]
    fn finite_mappings_preserve_uncertainty_at_every_nested_boundary() {
        let c = ControlError::OutcomeUncertain;
        let errors = [
            InstanceRegistrationError::Registry(InstanceRegistryError::Control(c)),
            InstanceRegistrationError::Authorization(PresenceAuthorizationError::Control(c)),
            InstanceRegistrationError::Authorization(PresenceAuthorizationError::Grants(
                ResourceGrantReadError::Control(c),
            )),
            InstanceRegistrationError::Authorization(PresenceAuthorizationError::Authentication(
                LocalBearerVerificationError::Control(c),
            )),
            InstanceRegistrationError::Authorization(PresenceAuthorizationError::Authentication(
                LocalBearerVerificationError::State(LocalBearerStateError::Control(c)),
            )),
        ];
        for error in errors {
            assert_eq!(
                HttpFailure::from(error),
                HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "outcome_uncertain")
            );
        }
        assert_eq!(
            authorization_failure(PresenceAuthorizationError::Forbidden).status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            HttpFailure::from(InstanceRegistrationError::Registry(
                InstanceRegistryError::InvalidOwner
            ))
            .status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            control_failure(ControlError::Deadline, "unavailable").status,
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            control_failure(ControlError::Closed, "unavailable").code,
            "closed"
        );
        assert_eq!(
            serde_json::to_value(InventoryResponse {
                instance_id: "station",
                change: "created",
                created_at: 1,
                updated_at: 1
            })
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
            4
        );
        assert_eq!(
            serde_json::to_value(ErrorResponse {
                error: ErrorCode {
                    code: "outcome_uncertain"
                }
            })
            .unwrap(),
            serde_json::json!({"error":{"code":"outcome_uncertain"}})
        );
    }
}

mod hub_catalog;
pub use hub_catalog::{HubCatalogHttpConfig, hub_catalog_router, sqlite_hub_catalog_router};
