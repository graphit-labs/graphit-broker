//! Current Hub metadata discovery through the configured, metadata-only reader.
use super::{HttpFailure, finalize_inventory_routes, hub_access};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use broker_control::{BrokerAccessVerifier, PostgresControlStore, SqliteControlStore};
use broker_storage::{HubCatalogError, HubCatalogQuery, HubCatalogReader};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
pub struct HubCatalogHttpConfig {
    pub audience: String,
    pub identity_json_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
    pub default_route: String,
    pub query_bytes: NonZeroUsize,
    pub request_timeout: Duration,
}
struct CatalogState {
    store: hub_access::HubStore,
    verifier: Arc<BrokerAccessVerifier>,
    reader: Arc<HubCatalogReader>,
    config: HubCatalogHttpConfig,
}
pub fn hub_catalog_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    reader: Arc<HubCatalogReader>,
    config: HubCatalogHttpConfig,
) -> Result<Router, super::HubAccessHttpConfigurationError> {
    make_router(
        hub_access::HubStore::Postgres(store),
        verifier,
        reader,
        config,
    )
}
/// Metadata catalog using current SQLite identity and Hub ACL observations.
pub fn sqlite_hub_catalog_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    reader: Arc<HubCatalogReader>,
    config: HubCatalogHttpConfig,
) -> Result<Router, super::HubAccessHttpConfigurationError> {
    make_router(
        hub_access::HubStore::Sqlite(store),
        verifier,
        reader,
        config,
    )
}
fn make_router(
    store: hub_access::HubStore,
    verifier: Arc<BrokerAccessVerifier>,
    reader: Arc<HubCatalogReader>,
    config: HubCatalogHttpConfig,
) -> Result<Router, super::HubAccessHttpConfigurationError> {
    if config.default_route.is_empty()
        || config.request_timeout.is_zero()
        || std::time::Instant::now()
            .checked_add(config.request_timeout)
            .is_none()
    {
        return Err(super::HubAccessHttpConfigurationError);
    }
    store.validate_broker(&verifier, config.grants_json_bytes)?;
    store.validate_local(
        &config.audience,
        config.identity_json_bytes,
        config.grants_json_bytes,
    )?;
    Ok(finalize_inventory_routes(Router::new().route(
        "/v1/hub/catalog/projects",
        get(projects).with_state(Arc::new(CatalogState {
            store,
            verifier,
            reader,
            config,
        })),
    )))
}
fn failure(error: HubCatalogError) -> HttpFailure {
    match error {
        HubCatalogError::InvalidQuery => HttpFailure::new(StatusCode::BAD_REQUEST, "invalid_query"),
        HubCatalogError::InvalidCursor => {
            HttpFailure::new(StatusCode::BAD_REQUEST, "invalid_cursor")
        }
        HubCatalogError::RestartRequired => {
            HttpFailure::new(StatusCode::CONFLICT, "catalog_restart_required")
        }
        HubCatalogError::ConflictingRoutes => {
            HttpFailure::new(StatusCode::FORBIDDEN, "conflicting_routes")
        }
        HubCatalogError::Authorization => HttpFailure::unauthenticated(),
        HubCatalogError::Access(error) => hub_access::failure(error),
        HubCatalogError::Deadline => HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"),
        HubCatalogError::InvalidMetadata => {
            HttpFailure::new(StatusCode::BAD_GATEWAY, "invalid_project_metadata")
        }
        HubCatalogError::Storage => {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "catalog_unavailable")
        }
    }
}
async fn projects(
    State(state): State<Arc<CatalogState>>,
    request: Request,
) -> Result<Response, HttpFailure> {
    let end = hub_access::deadline(state.config.request_timeout)?;
    let credential = hub_access::optional_bearer(request.headers())?;
    let raw = credential.as_ref().map(|c| c.token());
    let query = request.uri().query().unwrap_or("");
    if query.len() > state.config.query_bytes.get() {
        return Err(failure(HubCatalogError::InvalidQuery));
    }
    let mut id = None;
    let mut name_prefix = None;
    let mut limit = None;
    let mut cursor = None;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        let slot = match key.as_ref() {
            "id" => &mut id,
            "name_prefix" => &mut name_prefix,
            "limit" => &mut limit,
            "cursor" => &mut cursor,
            _ => return Err(failure(HubCatalogError::InvalidQuery)),
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(failure(HubCatalogError::InvalidQuery));
        }
    }
    let query = HubCatalogQuery {
        id,
        name_prefix,
        limit: match limit {
            Some(l) => l
                .parse()
                .map_err(|_| failure(HubCatalogError::InvalidQuery))?,
            None => 100,
        },
        cursor,
    };
    // The credential envelope selects the configured ingress exactly once.
    let mut resolved = if raw.is_some_and(|s| s.starts_with("gb_at_") || s.starts_with("gb_sc_")) {
        state
            .store
            .resolve_local(
                &state.config.audience,
                state.config.identity_json_bytes,
                state.config.grants_json_bytes,
                raw,
                end,
            )
            .await
    } else {
        state
            .store
            .resolve_broker(&state.verifier, state.config.grants_json_bytes, raw, end)
            .await
    }
    .map_err(hub_access::failure)?;
    let page = tokio::time::timeout_at(
        end.into(),
        state
            .reader
            .page(&mut resolved, &state.config.default_route, query, end),
    )
    .await
    .map_err(|_| failure(HubCatalogError::Deadline))?
    .map_err(failure)?;
    resolved.check().map_err(hub_access::failure)?;
    let mut response = Json(page).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    Ok(response)
}
