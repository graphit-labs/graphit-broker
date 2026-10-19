//! Partial authorized inventory listing through the existing shared-store composer.
use super::inventory_read::InventoryBackend;
use super::{
    HttpFailure, authorization_failure, bearer, control_failure,
    inventory_read::InstanceInventoryReadHttpConfigurationError,
};
use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{MethodRouter, get},
};
use broker_control::{
    AuthorizedInstanceList, InstanceListError, InstanceListQuery, InstanceReadError,
    PostgresControlStore, SqliteControlStore,
};
use serde::Serialize;
use std::{
    fmt,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

/// Explicit integration settings for the LIST route; no quota or Auth defaults.
pub struct InstanceInventoryListHttpConfig {
    pub audience: String,
    pub required_scopes: Vec<String>,
    pub identity_json_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
    pub inventory_json_bytes: NonZeroUsize,
    pub request_timeout: Duration,
    pub query_bytes: NonZeroUsize,
}
impl fmt::Debug for InstanceInventoryListHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceInventoryListHttpConfig([REDACTED])")
    }
}
struct ListState {
    store: InventoryBackend,
    config: InstanceInventoryListHttpConfig,
}
pub(super) fn list_method_router(
    store: Arc<PostgresControlStore>,
    config: InstanceInventoryListHttpConfig,
) -> Result<MethodRouter, InstanceInventoryReadHttpConfigurationError> {
    list_backend(InventoryBackend::Postgres(store), config)
}
pub(super) fn sqlite_list_method_router(
    store: Arc<SqliteControlStore>,
    config: InstanceInventoryListHttpConfig,
) -> Result<MethodRouter, InstanceInventoryReadHttpConfigurationError> {
    list_backend(InventoryBackend::Sqlite(store), config)
}
fn list_backend(
    store: InventoryBackend,
    config: InstanceInventoryListHttpConfig,
) -> Result<MethodRouter, InstanceInventoryReadHttpConfigurationError> {
    if config.audience.trim().is_empty()
        || config.required_scopes.iter().any(|s| s.trim().is_empty())
        || config.request_timeout.is_zero()
        || Instant::now().checked_add(config.request_timeout).is_none()
        || isize::try_from(config.query_bytes.get()).is_err()
    {
        return Err(InstanceInventoryReadHttpConfigurationError);
    }
    store
        .validate_list(&config)
        .map_err(|_| InstanceInventoryReadHttpConfigurationError)?;
    Ok(get(list_inventory).with_state(Arc::new(ListState { store, config })))
}
fn invalid_query() -> HttpFailure {
    HttpFailure::new(StatusCode::BAD_REQUEST, "INVALID_QUERY")
}
fn parse_query(raw: Option<&str>, cap: NonZeroUsize) -> Result<InstanceListQuery, HttpFailure> {
    let raw = raw.unwrap_or("");
    if raw.len() > cap.get() {
        return Err(HttpFailure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "QUERY_TOO_LARGE",
        ));
    }
    // The SDK decoders accept malformed percent or lossy UTF-8; enforce the strict boundary first.
    let bytes = raw.as_bytes();
    let mut position = 0;
    while position < bytes.len() {
        if bytes[position] == b'%' {
            if position + 2 >= bytes.len()
                || !bytes[position + 1].is_ascii_hexdigit()
                || !bytes[position + 2].is_ascii_hexdigit()
            {
                return Err(invalid_query());
            }
            position += 3;
        } else {
            position += 1;
        }
    }
    percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| invalid_query())?;
    let mut limit = 50;
    let mut after = None;
    let mut instance = None;
    let mut project = None;
    let mut version = None;
    let mut seen = 0u8;
    for (name, value) in form_urlencoded::parse(bytes) {
        let flag = match name.as_ref() {
            "limit" => 1,
            "after" => 2,
            "instance_id" => 4,
            "project_id" => 8,
            "version" => 16,
            _ => return Err(invalid_query()),
        };
        if seen & flag != 0 {
            return Err(invalid_query());
        }
        seen |= flag;
        match flag {
            1 => {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(invalid_query());
                }
                limit = value.parse::<usize>().map_err(|_| invalid_query())?;
            }
            2 => after = Some(value.into_owned()),
            4 => instance = Some(value.into_owned()),
            8 => project = Some(value.into_owned()),
            16 => version = Some(value.into_owned()),
            _ => unreachable!("parameter flag selected above"),
        }
    }
    InstanceListQuery::new(
        NonZeroUsize::new(limit).ok_or_else(invalid_query)?,
        after,
        instance,
        project,
        version,
    )
    .map_err(HttpFailure::from)
}
impl From<InstanceListError> for HttpFailure {
    fn from(error: InstanceListError) -> Self {
        match error {
            InstanceListError::InvalidQuery => invalid_query(),
            InstanceListError::Authorization(error) => authorization_failure(error),
            InstanceListError::Inventory(InstanceReadError::InvalidInstanceId) => invalid_query(),
            InstanceListError::Inventory(InstanceReadError::Control(error)) => {
                control_failure(error, "inventory_unavailable")
            }
            InstanceListError::Inventory(_) => {
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
struct ItemResponse<'a> {
    instance_id: &'a str,
    projects: Vec<ProjectResponse<'a>>,
    created_at: i64,
    updated_at: i64,
}
#[derive(Serialize)]
struct ListResponse<'a> {
    items: Vec<ItemResponse<'a>>,
    next_after: Option<&'a str>,
}
impl<'a> ListResponse<'a> {
    fn new(result: &'a AuthorizedInstanceList) -> Self {
        Self {
            items: result
                .items()
                .iter()
                .map(|item| ItemResponse {
                    instance_id: item.inventory().instance_id(),
                    projects: item
                        .inventory()
                        .projects()
                        .iter()
                        .map(|project| ProjectResponse {
                            project_id: project.project_id(),
                            versions: project.versions(),
                        })
                        .collect(),
                    created_at: item.created_at_micros(),
                    updated_at: item.updated_at_micros(),
                })
                .collect(),
            next_after: result.next_after(),
        }
    }
}
async fn list_inventory(
    State(state): State<Arc<ListState>>,
    request: Request,
) -> Result<Response, HttpFailure> {
    let end = Instant::now()
        .checked_add(state.config.request_timeout)
        .ok_or_else(|| {
            HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "inventory_unavailable")
        })?;
    let credential = bearer(request.headers())?;
    let query = parse_query(request.uri().query(), state.config.query_bytes)?;
    let result = state
        .store
        .list(&state.config, credential.token(), &query, end)
        .await?;
    Ok(Json(ListResponse::new(&result)).into_response())
}
#[cfg(test)]
mod tests {
    use super::*;
    use broker_control::{
        ControlError, LocalBearerStateError, LocalBearerVerificationError,
        PresenceAuthorizationError as AuthError, ResourceGrantReadError,
    };
    fn n(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).unwrap()
    }
    #[test]
    fn strict_query_rejects_lexical_corruption_decoded_duplicates_and_invalid_domain_values() {
        for raw in [
            "limit=1",
            "limit=100",
            "limit=01",
            "%6cimit=2",
            "version=feature+branch",
            "version=%E7%95%8C%F0%9F%98%80",
            "",
            "&&",
        ] {
            assert!(parse_query(Some(raw), n(4096)).is_ok(), "{raw}");
        }
        assert!(parse_query(None, n(1)).is_ok());
        for raw in [
            "limit=",
            "limit=0",
            "limit=101",
            "limit=+1",
            "limit=%2B1",
            "limit=-1",
            "limit=1%20",
            "limit=%EF%BC%91",
            "limit=99999999999999999999999999",
            "limit=1&limit=2",
            "limit=1&%6cimit=2",
            "unknown=x",
            "%FF=x",
            "version=%FF",
            "version=%",
            "version=%0",
            "version=%GG",
            "version=%C0%AF",
            "after=",
            "after=x%2F1",
            "instance_id=x%27",
            "project_id=friendly",
            "version=+main",
            "version=main%00",
        ] {
            let failure = parse_query(Some(raw), n(4096)).unwrap_err();
            assert_eq!(
                (failure.status, failure.code),
                (StatusCode::BAD_REQUEST, "INVALID_QUERY"),
                "{raw}"
            );
        }
        assert!(parse_query(Some("limit=1"), n(7)).is_ok());
        let failure = parse_query(Some("limit=1"), n(6)).unwrap_err();
        assert_eq!(
            (failure.status, failure.code),
            (StatusCode::PAYLOAD_TOO_LARGE, "QUERY_TOO_LARGE")
        );
        // Cap rejection precedes even malformed-percent decoding.
        assert_eq!(
            parse_query(Some("version=%GG"), n(1)).unwrap_err().code,
            "QUERY_TOO_LARGE"
        );
    }
    #[test]
    fn list_errors_preserve_nested_control_classifications_and_finite_inventory_failures() {
        for (control, status, code) in [
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
            for error in [
                InstanceListError::Inventory(InstanceReadError::Control(control)),
                InstanceListError::Authorization(AuthError::Control(control)),
                InstanceListError::Authorization(AuthError::Grants(
                    ResourceGrantReadError::Control(control),
                )),
                InstanceListError::Authorization(AuthError::Authentication(
                    LocalBearerVerificationError::State(LocalBearerStateError::Control(control)),
                )),
            ] {
                let failure = HttpFailure::from(error);
                assert_eq!((failure.status, failure.code), (status, code));
            }
        }
        assert_eq!(
            HttpFailure::from(InstanceListError::Inventory(
                InstanceReadError::MalformedStored
            ))
            .code,
            "inventory_unavailable"
        );
        assert_eq!(
            HttpFailure::from(InstanceListError::InvalidQuery).code,
            "INVALID_QUERY"
        );
    }
}
