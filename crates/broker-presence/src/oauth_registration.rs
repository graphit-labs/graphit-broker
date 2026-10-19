//! Public dynamic client registration backed by the selected committed SQL producer.
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use broker_control::{
    ControlError, OIDC_REGISTRATION_BODY_BYTES, OidcAuthorizationPolicy,
    OidcRegistrationError as Error, PostgresControlStore, SqliteControlStore,
};
use serde::Serialize;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub struct OidcRegistrationHttpConfig {
    request_timeout: Duration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OidcRegistrationHttpConfigurationError;
impl fmt::Display for OidcRegistrationHttpConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid OIDC registration HTTP configuration")
    }
}
impl std::error::Error for OidcRegistrationHttpConfigurationError {}
impl OidcRegistrationHttpConfig {
    pub fn new(request_timeout: Duration) -> Result<Self, OidcRegistrationHttpConfigurationError> {
        if request_timeout.is_zero() || Instant::now().checked_add(request_timeout).is_none() {
            return Err(OidcRegistrationHttpConfigurationError);
        }
        Ok(Self { request_timeout })
    }
}
enum RegistrationBackend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
struct RegistrationState {
    store: RegistrationBackend,
    policy: Arc<OidcAuthorizationPolicy>,
    config: OidcRegistrationHttpConfig,
}
pub fn oidc_registration_router(
    store: Arc<PostgresControlStore>,
    policy: Arc<OidcAuthorizationPolicy>,
    config: OidcRegistrationHttpConfig,
) -> Router {
    registration_router(RegistrationBackend::Postgres(store), policy, config)
}

/// Mount public registration through the qualified private SQLite producer.
pub fn sqlite_oidc_registration_router(
    store: Arc<SqliteControlStore>,
    policy: Arc<OidcAuthorizationPolicy>,
    config: OidcRegistrationHttpConfig,
) -> Router {
    registration_router(RegistrationBackend::Sqlite(store), policy, config)
}

fn registration_router(
    store: RegistrationBackend,
    policy: Arc<OidcAuthorizationPolicy>,
    config: OidcRegistrationHttpConfig,
) -> Router {
    let enabled = match &store {
        RegistrationBackend::Postgres(store) => store.oidc_registration_service(&policy).enabled(),
        RegistrationBackend::Sqlite(store) => store.oidc_registration_service(&policy).enabled(),
    };
    if !enabled {
        return Router::new();
    }
    Router::new()
        .route("/oauth/register", post(register))
        .with_state(Arc::new(RegistrationState {
            store,
            policy,
            config,
        }))
}
#[derive(Serialize)]
struct ErrorWire {
    error: &'static str,
}
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
fn failure(error: Error) -> Response {
    let (status, code) = match error {
        Error::Disabled => (StatusCode::NOT_FOUND, "not_found"),
        Error::InvalidMetadata => (StatusCode::BAD_REQUEST, "invalid_client_metadata"),
        Error::Control(ControlError::Deadline) => {
            (StatusCode::GATEWAY_TIMEOUT, "temporarily_unavailable")
        }
        Error::Control(ControlError::Closed | ControlError::OutcomeUncertain) => {
            (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    no_store((status, Json(ErrorWire { error: code })).into_response())
}
async fn register(State(state): State<Arc<RegistrationState>>, request: Request) -> Response {
    let Some(end) = Instant::now().checked_add(state.config.request_timeout) else {
        return failure(Error::Control(ControlError::Deadline));
    };
    let body = match tokio::time::timeout_at(
        end.into(),
        to_bytes(request.into_body(), OIDC_REGISTRATION_BODY_BYTES),
    )
    .await
    {
        Err(_) => return failure(Error::Control(ControlError::Deadline)),
        Ok(Err(_)) => return failure(Error::InvalidMetadata),
        Ok(Ok(body)) => body,
    };
    let result = match &state.store {
        RegistrationBackend::Postgres(store) => {
            store
                .oidc_registration_service(&state.policy)
                .register(&body, end)
                .await
        }
        RegistrationBackend::Sqlite(store) => {
            store
                .oidc_registration_service(&state.policy)
                .register(&body, end)
                .await
        }
    };
    match result {
        Ok(client) => no_store((StatusCode::CREATED, Json(client)).into_response()),
        Err(error) => failure(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn registration_errors_are_finite_uncertainty_precedes_deadline_and_no_store() {
        for (error, status, code) in [
            (Error::InvalidMetadata, 400, "invalid_client_metadata"),
            (Error::Disabled, 404, "not_found"),
            (
                Error::Control(ControlError::Deadline),
                504,
                "temporarily_unavailable",
            ),
            (
                Error::Control(ControlError::Closed),
                503,
                "temporarily_unavailable",
            ),
            (
                Error::Control(ControlError::OutcomeUncertain),
                503,
                "temporarily_unavailable",
            ),
            (Error::Control(ControlError::Storage), 500, "server_error"),
            (Error::Random, 500, "server_error"),
        ] {
            let response = failure(error);
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::PRAGMA], "no-cache");
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"error":code})
            );
        }
        assert!(OidcRegistrationHttpConfig::new(Duration::ZERO).is_err());
        assert!(OidcRegistrationHttpConfig::new(Duration::MAX).is_err());
        assert!(OidcRegistrationHttpConfig::new(Duration::from_secs(1)).is_ok());
    }
}
