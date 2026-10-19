//! Own-inventory HTTP reads through the authenticated shared control store.
use super::{
    HttpFailure, InstanceRegistryHttpConfig, authorization_failure, bearer, control_failure,
    inventory_and_list_routes,
    inventory_list::{InstanceInventoryListHttpConfig, list_method_router},
    inventory_route, registration_method_router, sqlite_registration_method_router,
};
use axum::{
    Json, Router,
    extract::{Path, Request, State, rejection::PathRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{MethodRouter, get},
};
use broker_control::{
    AuthorizedInstanceInventory, AuthorizedInstanceList, InstanceInventory,
    InstanceInventoryReadError, InstanceListError, InstanceListQuery, InstanceReadError,
    PostgresControlStore, SqliteControlStore,
};
use serde::Serialize;
use std::{
    fmt,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

/// Integration settings for Read; Publish settings remain independent.
pub struct InstanceInventoryReadHttpConfig {
    pub audience: String,
    pub required_scopes: Vec<String>,
    pub identity_json_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
    pub inventory_json_bytes: NonZeroUsize,
    pub request_timeout: Duration,
}
impl fmt::Debug for InstanceInventoryReadHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceInventoryReadHttpConfig([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceInventoryReadHttpConfigurationError;
impl fmt::Display for InstanceInventoryReadHttpConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid instance inventory HTTP configuration")
    }
}
impl std::error::Error for InstanceInventoryReadHttpConfigurationError {}
struct ReadState {
    store: InventoryBackend,
    config: InstanceInventoryReadHttpConfig,
}
fn valid_config(config: &InstanceInventoryReadHttpConfig) -> bool {
    !config.audience.trim().is_empty()
        && !config.request_timeout.is_zero()
        && Instant::now().checked_add(config.request_timeout).is_some()
        && !config.required_scopes.iter().any(|s| s.trim().is_empty())
}
fn read_method_router(
    store: Arc<PostgresControlStore>,
    config: InstanceInventoryReadHttpConfig,
) -> Result<MethodRouter, InstanceInventoryReadHttpConfigurationError> {
    read_backend(InventoryBackend::Postgres(store), config)
}
fn read_backend(
    store: InventoryBackend,
    config: InstanceInventoryReadHttpConfig,
) -> Result<MethodRouter, InstanceInventoryReadHttpConfigurationError> {
    if !valid_config(&config) {
        return Err(InstanceInventoryReadHttpConfigurationError);
    }
    store
        .validate_read(&config)
        .map_err(|_| InstanceInventoryReadHttpConfigurationError)?;
    Ok(get(read_inventory).with_state(Arc::new(ReadState { store, config })))
}
/// Read-only own-inventory route. The application supplies its listener and shutdown.
pub fn instance_inventory_read_router(
    store: Arc<PostgresControlStore>,
    config: InstanceInventoryReadHttpConfig,
) -> Result<Router, InstanceInventoryReadHttpConfigurationError> {
    Ok(inventory_route(read_method_router(store, config)?))
}
/// Explicit SQLite own-inventory HTTP route with current LOCAL authentication.
pub fn sqlite_instance_inventory_read_router(
    store: Arc<SqliteControlStore>,
    config: InstanceInventoryReadHttpConfig,
) -> Result<Router, InstanceInventoryReadHttpConfigurationError> {
    Ok(inventory_route(read_backend(
        InventoryBackend::Sqlite(store),
        config,
    )?))
}
/// Compose SQLite PUT, own GET and projected LIST using the maintained handlers.
pub fn sqlite_instance_inventory_router(
    store: Arc<SqliteControlStore>,
    registration_config: InstanceRegistryHttpConfig,
    read_config: InstanceInventoryReadHttpConfig,
    list_config: InstanceInventoryListHttpConfig,
) -> Result<Router, InstanceInventoryReadHttpConfigurationError> {
    let publish = sqlite_registration_method_router(store.clone(), registration_config)
        .map_err(|_| InstanceInventoryReadHttpConfigurationError)?;
    let read = read_backend(InventoryBackend::Sqlite(store.clone()), read_config)?;
    let list = super::inventory_list::sqlite_list_method_router(store, list_config)?;
    Ok(inventory_and_list_routes(publish.merge(read), list))
}
/// Compose PUT, own-inventory GET and partial LIST before one finite JSON fallback.
/// ~~~no_run
/// fn routes(store: std::sync::Arc<broker_control::PostgresControlStore>)
///     -> Result<axum::Router, broker_presence::InstanceInventoryReadHttpConfigurationError>
/// {
///     use broker_presence::{InstanceRegistryHttpConfig, InstanceInventoryReadHttpConfig, InstanceInventoryListHttpConfig};
///     use std::{num::NonZeroUsize, time::Duration};
///     let cap = NonZeroUsize::new(16384).unwrap();
///     let _read_routes = broker_presence::instance_inventory_read_router(store.clone(),
///         InstanceInventoryReadHttpConfig {
///             audience: "explicit-audience".into(), required_scopes: vec!["presence:read".into()],
///             identity_json_bytes: cap, grants_json_bytes: cap, inventory_json_bytes: cap,
///             request_timeout: Duration::from_secs(2),
///         })?;
///     broker_presence::instance_inventory_router(store,
///         InstanceRegistryHttpConfig {
///             audience: "explicit-audience".into(), required_scopes: vec!["presence:publish".into()],
///             identity_json_bytes: cap, grants_json_bytes: cap, body_bytes: cap,
///             request_timeout: Duration::from_secs(2),
///         },
///         InstanceInventoryReadHttpConfig {
///             audience: "explicit-audience".into(), required_scopes: vec!["presence:read".into()],
///             identity_json_bytes: cap, grants_json_bytes: cap, inventory_json_bytes: cap,
///             request_timeout: Duration::from_secs(2),
///         },
///         InstanceInventoryListHttpConfig {
///             audience: "explicit-audience".into(), required_scopes: vec!["presence:read".into()],
///             identity_json_bytes: cap, grants_json_bytes: cap, inventory_json_bytes: cap,
///             request_timeout: Duration::from_secs(2), query_bytes: cap,
///         })
/// }
/// ~~~
pub fn instance_inventory_router(
    store: Arc<PostgresControlStore>,
    registration_config: InstanceRegistryHttpConfig,
    read_config: InstanceInventoryReadHttpConfig,
    list_config: InstanceInventoryListHttpConfig,
) -> Result<Router, InstanceInventoryReadHttpConfigurationError> {
    let publish = registration_method_router(store.clone(), registration_config)
        .map_err(|_| InstanceInventoryReadHttpConfigurationError)?;
    let read = read_method_router(store.clone(), read_config)?;
    let list = list_method_router(store, list_config)?;
    Ok(inventory_and_list_routes(publish.merge(read), list))
}
impl From<InstanceInventoryReadError> for HttpFailure {
    fn from(error: InstanceInventoryReadError) -> Self {
        match error {
            InstanceInventoryReadError::Authorization(error) => authorization_failure(error),
            InstanceInventoryReadError::OwnerConflict => {
                Self::new(StatusCode::CONFLICT, "owner_conflict")
            }
            InstanceInventoryReadError::Inventory(InstanceReadError::InvalidInstanceId) => {
                Self::bad_inventory()
            }
            InstanceInventoryReadError::Inventory(InstanceReadError::Control(error)) => {
                control_failure(error, "inventory_unavailable")
            }
            InstanceInventoryReadError::Inventory(_) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "inventory_unavailable")
            }
        }
    }
}
#[derive(Serialize)]
struct ProjectResponse<'a> {
    project_id: &'a str,
    versions: &'a [String],
}
#[derive(Serialize)]
pub(super) struct ReadResponse<'a> {
    instance_id: &'a str,
    projects: Vec<ProjectResponse<'a>>,
    created_at: i64,
    updated_at: i64,
}
impl<'a> ReadResponse<'a> {
    pub(super) fn new(inventory: &'a InstanceInventory, created_at: i64, updated_at: i64) -> Self {
        Self {
            instance_id: inventory.instance_id(),
            projects: inventory
                .projects()
                .iter()
                .map(|p| ProjectResponse {
                    project_id: p.project_id(),
                    versions: p.versions(),
                })
                .collect(),
            created_at,
            updated_at,
        }
    }
}
async fn read_inventory(
    State(state): State<Arc<ReadState>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, HttpFailure> {
    let end = Instant::now()
        .checked_add(state.config.request_timeout)
        .ok_or_else(|| {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "inventory_unavailable")
        })?;
    let credential = bearer(request.headers())?;
    let Path(id) = path.map_err(|_| HttpFailure::bad_inventory())?;
    let result = state
        .store
        .read(&state.config, credential.token(), &id, end)
        .await?
        .ok_or_else(|| HttpFailure::new(StatusCode::NOT_FOUND, "not_found"))?;
    Ok(Json(ReadResponse::new(
        result.inventory(),
        result.created_at_micros(),
        result.updated_at_micros(),
    ))
    .into_response())
}

// Closed physical backend selection; each branch invokes its actual LOCAL consumer.
pub(super) enum InventoryBackend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
impl InventoryBackend {
    fn validate_read(
        &self,
        c: &InstanceInventoryReadHttpConfig,
    ) -> Result<(), InstanceInventoryReadError> {
        match self {
            Self::Postgres(s) => s
                .local_instance_inventory_reader(
                    &c.audience,
                    c.identity_json_bytes,
                    c.grants_json_bytes,
                    c.inventory_json_bytes,
                )
                .map(|_| ()),
            Self::Sqlite(s) => s
                .local_instance_inventory_reader(
                    &c.audience,
                    c.identity_json_bytes,
                    c.grants_json_bytes,
                    c.inventory_json_bytes,
                )
                .map(|_| ()),
        }
    }
    pub(super) fn validate_list(
        &self,
        c: &InstanceInventoryListHttpConfig,
    ) -> Result<(), InstanceListError> {
        match self {
            Self::Postgres(s) => s
                .local_instance_inventory_lister(
                    &c.audience,
                    c.identity_json_bytes,
                    c.grants_json_bytes,
                    c.inventory_json_bytes,
                )
                .map(|_| ()),
            Self::Sqlite(s) => s
                .local_instance_inventory_lister(
                    &c.audience,
                    c.identity_json_bytes,
                    c.grants_json_bytes,
                    c.inventory_json_bytes,
                )
                .map(|_| ()),
        }
    }
    async fn read(
        &self,
        c: &InstanceInventoryReadHttpConfig,
        raw: &str,
        id: &str,
        end: Instant,
    ) -> Result<Option<AuthorizedInstanceInventory>, InstanceInventoryReadError> {
        match self {
            Self::Postgres(s) => {
                s.local_instance_inventory_reader(
                    &c.audience,
                    c.identity_json_bytes,
                    c.grants_json_bytes,
                    c.inventory_json_bytes,
                )?
                .read(raw, &c.required_scopes, id, end)
                .await
            }
            Self::Sqlite(s) => {
                s.local_instance_inventory_reader(
                    &c.audience,
                    c.identity_json_bytes,
                    c.grants_json_bytes,
                    c.inventory_json_bytes,
                )?
                .read(raw, &c.required_scopes, id, end)
                .await
            }
        }
    }
    pub(super) async fn list(
        &self,
        c: &InstanceInventoryListHttpConfig,
        raw: &str,
        q: &InstanceListQuery,
        end: Instant,
    ) -> Result<AuthorizedInstanceList, InstanceListError> {
        match self {
            Self::Postgres(s) => {
                s.local_instance_inventory_lister(
                    &c.audience,
                    c.identity_json_bytes,
                    c.grants_json_bytes,
                    c.inventory_json_bytes,
                )?
                .list(raw, &c.required_scopes, q, end)
                .await
            }
            Self::Sqlite(s) => {
                s.local_instance_inventory_lister(
                    &c.audience,
                    c.identity_json_bytes,
                    c.grants_json_bytes,
                    c.inventory_json_bytes,
                )?
                .list(raw, &c.required_scopes, q, end)
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_control::{
        ControlError, InstanceProjectVersions, LocalBearerStateError, LocalBearerVerificationError,
        PresenceAuthorizationError, ResourceGrantReadError,
    };
    #[test]
    fn nested_read_errors_preserve_all_control_classifications() {
        for (control, status, code) in [
            (
                ControlError::OutcomeUncertain,
                StatusCode::SERVICE_UNAVAILABLE,
                "outcome_uncertain",
            ),
            (
                ControlError::Deadline,
                StatusCode::GATEWAY_TIMEOUT,
                "deadline",
            ),
            (
                ControlError::Closed,
                StatusCode::SERVICE_UNAVAILABLE,
                "closed",
            ),
        ] {
            for error in [
                InstanceInventoryReadError::Inventory(InstanceReadError::Control(control)),
                InstanceInventoryReadError::Authorization(PresenceAuthorizationError::Control(
                    control,
                )),
                InstanceInventoryReadError::Authorization(PresenceAuthorizationError::Grants(
                    ResourceGrantReadError::Control(control),
                )),
                InstanceInventoryReadError::Authorization(
                    PresenceAuthorizationError::Authentication(
                        LocalBearerVerificationError::Control(control),
                    ),
                ),
                InstanceInventoryReadError::Authorization(
                    PresenceAuthorizationError::Authentication(
                        LocalBearerVerificationError::State(LocalBearerStateError::Control(
                            control,
                        )),
                    ),
                ),
            ] {
                assert_eq!(HttpFailure::from(error), HttpFailure::new(status, code));
            }
        }
        for error in [
            InstanceReadError::InvalidLimits,
            InstanceReadError::MalformedStored,
            InstanceReadError::ReadLimitExceeded,
        ] {
            assert_eq!(
                HttpFailure::from(InstanceInventoryReadError::Inventory(error)).code,
                "inventory_unavailable"
            );
        }
        assert_eq!(
            HttpFailure::from(InstanceInventoryReadError::Inventory(
                InstanceReadError::InvalidInstanceId
            )),
            HttpFailure::bad_inventory()
        );
        assert_eq!(
            HttpFailure::from(InstanceInventoryReadError::OwnerConflict).code,
            "owner_conflict"
        );
    }
    #[test]
    fn wire_projection_contains_only_inventory_and_stamps() {
        let inventory = InstanceInventory::new(
            "station".into(),
            vec![
                InstanceProjectVersions::new(
                    "01D39ZY06FGSCTVN4T2V9PKHFZ".into(),
                    vec!["main".into()],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(ReadResponse::new(&inventory, 1, 2)).unwrap(),
            serde_json::json!({"instance_id":"station","projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main"]}],"created_at":1,"updated_at":2})
        );
        let empty = InstanceInventory::new("empty".into(), vec![]).unwrap();
        assert_eq!(
            serde_json::to_value(ReadResponse::new(&empty, 0, 0)).unwrap()["projects"],
            serde_json::json!([])
        );
    }
    #[test]
    fn explicit_read_config_rejects_blank_and_invalid_deadlines() {
        fn config() -> InstanceInventoryReadHttpConfig {
            let n = NonZeroUsize::new(4096).unwrap();
            InstanceInventoryReadHttpConfig {
                audience: "explicit".into(),
                required_scopes: vec![],
                identity_json_bytes: n,
                grants_json_bytes: n,
                inventory_json_bytes: n,
                request_timeout: Duration::from_secs(2),
            }
        }
        assert!(valid_config(&config()));
        for duration in [Duration::ZERO, Duration::MAX] {
            let mut c = config();
            c.request_timeout = duration;
            assert!(!valid_config(&c));
        }
        let mut c = config();
        c.audience = " ".into();
        assert!(!valid_config(&c));
        let mut c = config();
        c.required_scopes = vec![" ".into()];
        assert!(!valid_config(&c));
        assert_eq!(
            format!("{:?}", config()),
            "InstanceInventoryReadHttpConfig([REDACTED])"
        );
    }
}
