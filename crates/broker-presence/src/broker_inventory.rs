//! Explicit Native PUT/own-GET routing through qualified shared store producers.
use super::{
    HttpFailure, InventoryRequest, InventoryResponse, ProjectRequest, bearer, control_failure,
    inventory_read::ReadResponse, inventory_route,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Path, Request, State, rejection::PathRejection},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use broker_control::{
    AuthorizedBrokerInstanceInventory, BrokerAccessError, BrokerAccessVerifier,
    BrokerInstanceInventoryReadError, BrokerInstanceRegistrationError,
    BrokerPresenceAuthorizationError, InstanceInventory, InstanceReadError, InstanceRegistryError,
    PostgresControlStore, RegistrationChange, RegistrationResult, ResourceGrantReadError,
    SqliteControlStore,
};
use serde::{
    Deserialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{
    fmt,
    marker::PhantomData,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

/// Explicit Native Publish integration settings, independent of Read settings.
pub struct BrokerPublishHttpConfig {
    pub required_scopes: Vec<String>,
    pub grants_json_bytes: NonZeroUsize,
    pub body_bytes: NonZeroUsize,
    pub request_timeout: Duration,
}
impl fmt::Debug for BrokerPublishHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrokerPublishHttpConfig([REDACTED])")
    }
}
/// Explicit Native own-Read integration settings; the supplied verifier owns trust.
pub struct BrokerOwnReadHttpConfig {
    pub required_scopes: Vec<String>,
    pub grants_json_bytes: NonZeroUsize,
    pub inventory_json_bytes: NonZeroUsize,
    pub request_timeout: Duration,
}
impl fmt::Debug for BrokerOwnReadHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrokerOwnReadHttpConfig([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerInventoryHttpConfigurationError;
impl fmt::Display for BrokerInventoryHttpConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Native inventory HTTP configuration")
    }
}
impl std::error::Error for BrokerInventoryHttpConfigurationError {}
#[derive(Clone)]
enum NativeInventoryBackend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
impl NativeInventoryBackend {
    async fn register(
        &self,
        verifier: &BrokerAccessVerifier,
        cap: NonZeroUsize,
        raw: &str,
        scopes: &[String],
        inventory: &InstanceInventory,
        end: Instant,
    ) -> Result<RegistrationResult, BrokerInstanceRegistrationError> {
        match self {
            Self::Postgres(store) => {
                store
                    .broker_instance_registrar(verifier, cap)?
                    .register(raw, scopes, inventory, end)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .broker_instance_registrar(verifier, cap)?
                    .register(raw, scopes, inventory, end)
                    .await
            }
        }
    }
    async fn read<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        caps: (NonZeroUsize, NonZeroUsize),
        raw: &str,
        scopes: &[String],
        id: &str,
        end: Instant,
    ) -> Result<AuthorizedBrokerInstanceInventory<'a>, BrokerInstanceInventoryReadError> {
        match self {
            Self::Postgres(store) => {
                store
                    .broker_instance_inventory_reader(verifier, caps.0, caps.1)?
                    .read(raw, scopes, id, end)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .broker_instance_inventory_reader(verifier, caps.0, caps.1)?
                    .read(raw, scopes, id, end)
                    .await
            }
        }
    }
}
struct PublishState {
    backend: NativeInventoryBackend,
    verifier: Arc<BrokerAccessVerifier>,
    config: BrokerPublishHttpConfig,
}
struct ReadState {
    backend: NativeInventoryBackend,
    verifier: Arc<BrokerAccessVerifier>,
    config: BrokerOwnReadHttpConfig,
}
fn valid_config(scopes: &[String], timeout: Duration) -> bool {
    !timeout.is_zero()
        && Instant::now().checked_add(timeout).is_some()
        && !scopes.iter().any(|s| s.trim().is_empty())
}
/// Compose Native PUT and own GET before finite JSON fallbacks; all responses are no-store.
/// The application owns its listener and shutdown; there is no opaque probing.
/// ~~~no_run
/// fn routes(store:std::sync::Arc<broker_control::PostgresControlStore>,
///     verifier:std::sync::Arc<broker_control::BrokerAccessVerifier>,
/// ) -> Result<axum::Router,broker_presence::BrokerInventoryHttpConfigurationError> {
///     use broker_presence::{BrokerPublishHttpConfig,BrokerOwnReadHttpConfig};
///     let cap=std::num::NonZeroUsize::new(16384).unwrap();
///     let timeout=std::time::Duration::from_secs(4);
///     broker_presence::broker_instance_inventory_router(store,verifier,
///         BrokerPublishHttpConfig {required_scopes:vec!["presence-sdk".into()],
///             grants_json_bytes:cap,body_bytes:cap,request_timeout:timeout},
///         BrokerOwnReadHttpConfig {required_scopes:vec!["presence-sdk".into()],
///             grants_json_bytes:cap,inventory_json_bytes:cap,request_timeout:timeout})
/// }
/// ~~~
pub fn broker_instance_inventory_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    publish: BrokerPublishHttpConfig,
    read: BrokerOwnReadHttpConfig,
) -> Result<Router, BrokerInventoryHttpConfigurationError> {
    inventory_routes(
        NativeInventoryBackend::Postgres(store),
        verifier,
        publish,
        read,
    )
}
/// Explicit SQLite Native JWT inventory PUT/own-GET with the shared wire contract.
pub fn sqlite_broker_instance_inventory_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    publish: BrokerPublishHttpConfig,
    read: BrokerOwnReadHttpConfig,
) -> Result<Router, BrokerInventoryHttpConfigurationError> {
    inventory_routes(
        NativeInventoryBackend::Sqlite(store),
        verifier,
        publish,
        read,
    )
}
fn inventory_routes(
    backend: NativeInventoryBackend,
    verifier: Arc<BrokerAccessVerifier>,
    publish: BrokerPublishHttpConfig,
    read: BrokerOwnReadHttpConfig,
) -> Result<Router, BrokerInventoryHttpConfigurationError> {
    if !valid_config(&publish.required_scopes, publish.request_timeout)
        || !valid_config(&read.required_scopes, read.request_timeout)
    {
        return Err(BrokerInventoryHttpConfigurationError);
    }
    match &backend {
        NativeInventoryBackend::Postgres(store) => {
            store
                .broker_instance_registrar(&verifier, publish.grants_json_bytes)
                .map_err(|_| BrokerInventoryHttpConfigurationError)?;
            store
                .broker_instance_inventory_reader(
                    &verifier,
                    read.grants_json_bytes,
                    read.inventory_json_bytes,
                )
                .map_err(|_| BrokerInventoryHttpConfigurationError)?;
        }
        NativeInventoryBackend::Sqlite(store) => {
            store
                .broker_instance_registrar(&verifier, publish.grants_json_bytes)
                .map_err(|_| BrokerInventoryHttpConfigurationError)?;
            store
                .broker_instance_inventory_reader(
                    &verifier,
                    read.grants_json_bytes,
                    read.inventory_json_bytes,
                )
                .map_err(|_| BrokerInventoryHttpConfigurationError)?;
        }
    }
    let publish = put(publish_inventory).with_state(Arc::new(PublishState {
        backend: backend.clone(),
        verifier: verifier.clone(),
        config: publish,
    }));
    let read = get(read_inventory).with_state(Arc::new(ReadState {
        backend,
        verifier,
        config: read,
    }));
    Ok(inventory_route(publish.merge(read)).layer(middleware::from_fn(no_store)))
}
async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        headers::HeaderValue::from_static("no-store"),
    );
    response
}
// Serde's struct decoder accepts sequence representations. This adapter admits
// maps only, then delegates field/duplicate validation to the actual SDK decoder.
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
struct NativeInventoryRequest {
    projects: Vec<MapOnly<ProjectRequest>>,
}
impl NativeInventoryRequest {
    fn into_request(self) -> InventoryRequest {
        InventoryRequest {
            projects: self.projects.into_iter().map(|p| p.0).collect(),
        }
    }
}
impl From<BrokerPresenceAuthorizationError> for HttpFailure {
    fn from(error: BrokerPresenceAuthorizationError) -> Self {
        match error {
            BrokerPresenceAuthorizationError::InvalidProject => Self::bad_inventory(),
            BrokerPresenceAuthorizationError::InvalidPolicy => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "invalid_policy")
            }
            BrokerPresenceAuthorizationError::Forbidden => {
                Self::new(StatusCode::FORBIDDEN, "forbidden")
            }
            BrokerPresenceAuthorizationError::Authentication(error) => match error {
                BrokerAccessError::InvalidToken | BrokerAccessError::Expired => {
                    Self::unauthenticated()
                }
                BrokerAccessError::InsufficientScope => {
                    Self::new(StatusCode::FORBIDDEN, "insufficient_scope")
                }
                BrokerAccessError::Deadline => Self::new(StatusCode::GATEWAY_TIMEOUT, "deadline"),
                BrokerAccessError::InvalidConfiguration => Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authentication_unavailable",
                ),
            },
            BrokerPresenceAuthorizationError::Control(error)
            | BrokerPresenceAuthorizationError::Grants(ResourceGrantReadError::Control(error)) => {
                control_failure(error, "authorization_unavailable")
            }
            BrokerPresenceAuthorizationError::Grants(_) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
            }
        }
    }
}
impl From<BrokerInstanceRegistrationError> for HttpFailure {
    fn from(error: BrokerInstanceRegistrationError) -> Self {
        match error {
            BrokerInstanceRegistrationError::Authorization(error) => error.into(),
            BrokerInstanceRegistrationError::Registry(InstanceRegistryError::OwnerConflict) => {
                Self::new(StatusCode::CONFLICT, "owner_conflict")
            }
            BrokerInstanceRegistrationError::Registry(InstanceRegistryError::InvalidInventory) => {
                Self::bad_inventory()
            }
            BrokerInstanceRegistrationError::Registry(InstanceRegistryError::Control(error)) => {
                control_failure(error, "registration_unavailable")
            }
            BrokerInstanceRegistrationError::Registry(_) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "registration_unavailable")
            }
        }
    }
}
impl From<BrokerInstanceInventoryReadError> for HttpFailure {
    fn from(error: BrokerInstanceInventoryReadError) -> Self {
        match error {
            BrokerInstanceInventoryReadError::Authorization(error) => error.into(),
            BrokerInstanceInventoryReadError::NotFound => {
                Self::new(StatusCode::NOT_FOUND, "not_found")
            }
            BrokerInstanceInventoryReadError::OwnerConflict => {
                Self::new(StatusCode::CONFLICT, "owner_conflict")
            }
            BrokerInstanceInventoryReadError::Inventory(InstanceReadError::InvalidInstanceId) => {
                Self::bad_inventory()
            }
            BrokerInstanceInventoryReadError::Inventory(InstanceReadError::Control(error)) => {
                control_failure(error, "inventory_unavailable")
            }
            BrokerInstanceInventoryReadError::Inventory(_) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "inventory_unavailable")
            }
        }
    }
}
async fn publish_inventory(
    State(state): State<Arc<PublishState>>,
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
    let Json(MapOnly(input)) = tokio::time::timeout_at(
        end.into(),
        Json::<MapOnly<NativeInventoryRequest>>::from_request(request, &state),
    )
    .await
    .map_err(|_| HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"))?
    .map_err(|e| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            HttpFailure::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large")
        } else {
            HttpFailure::new(StatusCode::BAD_REQUEST, "invalid_json")
        }
    })?;
    let inventory = input.into_request().into_inventory(id)?;
    let result = state
        .backend
        .register(
            &state.verifier,
            state.config.grants_json_bytes,
            credential.token(),
            &state.config.required_scopes,
            &inventory,
            end,
        )
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
        .backend
        .read(
            &state.verifier,
            (
                state.config.grants_json_bytes,
                state.config.inventory_json_bytes,
            ),
            credential.token(),
            &state.config.required_scopes,
            &id,
            end,
        )
        .await?;
    Ok(Json(ReadResponse::new(
        result.inventory(),
        result.created_at_micros(),
        result.updated_at_micros(),
    ))
    .into_response())
}
#[cfg(test)]
mod tests {
    use super::*;
    use broker_control::ControlError;
    #[test]
    fn native_objects_are_strict_without_changing_opaque_data_constructors() {
        for text in [
            "[[]]",
            r#"{"projects":[["01D39ZY06FGSCTVN4T2V9PKHFZ",["main"]]]}"#,
            r#"{"projects":[],"projects":[]}"#,
            r#"{"projects":[],"owner":"invented"}"#,
            r#"{"projects":[{"project_id":"x","project_id":"y","versions":[] }]}"#,
            r#"{"projects":[{"project_id":"x"}]}"#,
            r#"{"projects":[]} {}"#,
        ] {
            assert!(
                serde_json::from_str::<MapOnly<NativeInventoryRequest>>(text).is_err(),
                "{text}"
            );
        }
        let MapOnly(input)=serde_json::from_str::<MapOnly<NativeInventoryRequest>>(
            r#"{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main","branch/ação"]}]}"#).unwrap();
        let inventory = input
            .into_request()
            .into_inventory("station".into())
            .unwrap();
        assert_eq!(
            inventory.projects()[0].versions(),
            &["branch/ação".to_owned(), "main".to_owned()]
        );
    }
    #[test]
    fn native_nested_failures_preserve_control_origins_and_finite_wire() {
        for (error, status, code) in [
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
            (
                ControlError::OutcomeUncertain,
                StatusCode::SERVICE_UNAVAILABLE,
                "outcome_uncertain",
            ),
        ] {
            for failure in [
                HttpFailure::from(BrokerInstanceRegistrationError::Registry(
                    InstanceRegistryError::Control(error),
                )),
                HttpFailure::from(BrokerInstanceInventoryReadError::Inventory(
                    InstanceReadError::Control(error),
                )),
                HttpFailure::from(BrokerPresenceAuthorizationError::Control(error)),
                HttpFailure::from(BrokerPresenceAuthorizationError::Grants(
                    ResourceGrantReadError::Control(error),
                )),
            ] {
                assert_eq!(failure, HttpFailure::new(status, code));
            }
        }
        assert_eq!(
            HttpFailure::from(BrokerPresenceAuthorizationError::Authentication(
                BrokerAccessError::InsufficientScope
            )),
            HttpFailure::new(StatusCode::FORBIDDEN, "insufficient_scope")
        );
    }
}
