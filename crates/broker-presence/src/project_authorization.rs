//! Explicit opaque-local or Broker-JWT PROJECT authorization with native SQL backends.
use super::{HttpFailure, authentication_failure, bearer, control_failure};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use broker_control::{
    BrokerAccessError, BrokerAccessVerifier, BrokerProjectAuthorizationError, PostgresControlStore,
    ProjectAuthorizationError, ProjectResourceAction, ProjectResourceModule,
    ResourceGrantReadError, SqliteControlStore,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

/// Explicit local HTTP settings. Scopes never replace the logical PROJECT grant.
pub struct ProjectAuthorizationHttpConfig {
    pub audience: String,
    pub required_scopes: Vec<String>,
    pub identity_json_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
    pub body_bytes: NonZeroUsize,
    pub request_timeout: Duration,
}
impl fmt::Debug for ProjectAuthorizationHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProjectAuthorizationHttpConfig([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectAuthorizationHttpConfigurationError;
impl fmt::Display for ProjectAuthorizationHttpConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid project authorization HTTP configuration")
    }
}
impl std::error::Error for ProjectAuthorizationHttpConfigurationError {}
struct ProjectState {
    authentication: ProjectAuthentication,
}
enum ProjectAuthentication {
    Local {
        backend: LocalProjectBackend,
        config: ProjectAuthorizationHttpConfig,
    },
    Broker {
        backend: BrokerProjectBackend,
        verifier: Arc<BrokerAccessVerifier>,
        config: BrokerProjectAuthorizationHttpConfig,
    },
}
enum LocalProjectBackend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
enum BrokerProjectBackend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
impl ProjectState {
    fn request_limits(&self) -> (NonZeroUsize, Duration) {
        match &self.authentication {
            ProjectAuthentication::Local { config, .. } => {
                (config.body_bytes, config.request_timeout)
            }
            ProjectAuthentication::Broker { config, .. } => {
                (config.body_bytes, config.request_timeout)
            }
        }
    }
}
fn valid_config(config: &ProjectAuthorizationHttpConfig) -> bool {
    !config.audience.trim().is_empty()
        && !config.required_scopes.iter().any(|s| s.trim().is_empty())
        && !config.request_timeout.is_zero()
        && Instant::now().checked_add(config.request_timeout).is_some()
}
/// Serve one exact POST route. The application supplies the listener and shutdown.
/// This local response does not prove a Broker JWT subject or admit Core Records.
/// ~~~no_run
/// fn routes(store: std::sync::Arc<broker_control::PostgresControlStore>)
///     -> Result<axum::Router, broker_presence::ProjectAuthorizationHttpConfigurationError> {
///     let cap = std::num::NonZeroUsize::new(16384).unwrap();
///     broker_presence::project_authorization_router(store, broker_presence::ProjectAuthorizationHttpConfig {
///         audience: "explicit-audience".into(), required_scopes: vec!["project-api".into()],
///         identity_json_bytes: cap, grants_json_bytes: cap, body_bytes: cap,
///         request_timeout: std::time::Duration::from_secs(2),
///     })
/// }
/// ~~~
pub fn project_authorization_router(
    store: Arc<PostgresControlStore>,
    config: ProjectAuthorizationHttpConfig,
) -> Result<Router, ProjectAuthorizationHttpConfigurationError> {
    if !valid_config(&config) {
        return Err(ProjectAuthorizationHttpConfigurationError);
    }
    store
        .local_project_authorizer(
            &config.audience,
            config.identity_json_bytes,
            config.grants_json_bytes,
        )
        .map_err(|_| ProjectAuthorizationHttpConfigurationError)?;
    Ok(project_router(ProjectState {
        authentication: ProjectAuthentication::Local {
            backend: LocalProjectBackend::Postgres(store),
            config,
        },
    }))
}
/// Explicit SQLite factory for the existing opaque LOCAL PROJECT route.
/// It shares HTTP policy and wire validation with the PostgreSQL constructor.
pub fn sqlite_project_authorization_router(
    store: Arc<SqliteControlStore>,
    config: ProjectAuthorizationHttpConfig,
) -> Result<Router, ProjectAuthorizationHttpConfigurationError> {
    if !valid_config(&config) {
        return Err(ProjectAuthorizationHttpConfigurationError);
    }
    store
        .local_project_authorizer(
            &config.audience,
            config.identity_json_bytes,
            config.grants_json_bytes,
        )
        .map_err(|_| ProjectAuthorizationHttpConfigurationError)?;
    Ok(project_router(ProjectState {
        authentication: ProjectAuthentication::Local {
            backend: LocalProjectBackend::Sqlite(store),
            config,
        },
    }))
}
fn project_router(state: ProjectState) -> Router {
    Router::new()
        .route("/v1/project/access/authorize", post(authorize_project))
        .with_state(Arc::new(state))
        .fallback(|| async { HttpFailure::new(StatusCode::NOT_FOUND, "not_found") })
        .method_not_allowed_fallback(|| async {
            HttpFailure::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
        })
}

/// Explicit JWT transport settings. Trust comes from the supplied verifier.
pub struct BrokerProjectAuthorizationHttpConfig {
    pub required_scopes: Vec<String>,
    pub grants_json_bytes: NonZeroUsize,
    pub body_bytes: NonZeroUsize,
    pub request_timeout: Duration,
}
impl fmt::Debug for BrokerProjectAuthorizationHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrokerProjectAuthorizationHttpConfig([REDACTED])")
    }
}
fn valid_broker_config(config: &BrokerProjectAuthorizationHttpConfig) -> bool {
    !config
        .required_scopes
        .iter()
        .any(|s| s.trim().is_empty() || s.contains(' '))
        && !config.request_timeout.is_zero()
        && Instant::now().checked_add(config.request_timeout).is_some()
}
/// Serve the exact PROJECT POST route with local Broker JWT verification.
/// The application explicitly selects this factory and owns listener/shutdown.
/// ~~~no_run
/// fn routes(
///     store: std::sync::Arc<broker_control::PostgresControlStore>,
///     verifier: std::sync::Arc<broker_control::BrokerAccessVerifier>,
/// ) -> Result<axum::Router, broker_presence::ProjectAuthorizationHttpConfigurationError> {
///     let cap = std::num::NonZeroUsize::new(16384).unwrap();
///     broker_presence::broker_project_authorization_router(store, verifier,
///         broker_presence::BrokerProjectAuthorizationHttpConfig {
///             required_scopes: vec!["project-api".into()], grants_json_bytes: cap,
///             body_bytes: cap, request_timeout: std::time::Duration::from_secs(2),
///         })
/// }
/// ~~~
pub fn broker_project_authorization_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: BrokerProjectAuthorizationHttpConfig,
) -> Result<Router, ProjectAuthorizationHttpConfigurationError> {
    if !valid_broker_config(&config) {
        return Err(ProjectAuthorizationHttpConfigurationError);
    }
    store
        .broker_project_authorizer(&verifier, config.grants_json_bytes)
        .map_err(|_| ProjectAuthorizationHttpConfigurationError)?;
    Ok(project_router(ProjectState {
        authentication: ProjectAuthentication::Broker {
            backend: BrokerProjectBackend::Postgres(store),
            verifier,
            config,
        },
    }))
}
/// Explicit SQLite Broker-JWT factory for the same PROJECT wire contract.
/// The application owns trusted keys, listener and store shutdown.
pub fn sqlite_broker_project_authorization_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: BrokerProjectAuthorizationHttpConfig,
) -> Result<Router, ProjectAuthorizationHttpConfigurationError> {
    if !valid_broker_config(&config) {
        return Err(ProjectAuthorizationHttpConfigurationError);
    }
    store
        .broker_project_authorizer(&verifier, config.grants_json_bytes)
        .map_err(|_| ProjectAuthorizationHttpConfigurationError)?;
    Ok(project_router(ProjectState {
        authentication: ProjectAuthentication::Broker {
            backend: BrokerProjectBackend::Sqlite(store),
            verifier,
            config,
        },
    }))
}
impl From<BrokerProjectAuthorizationError> for HttpFailure {
    fn from(error: BrokerProjectAuthorizationError) -> Self {
        match error {
            BrokerProjectAuthorizationError::InvalidProject
            | BrokerProjectAuthorizationError::InvalidOperation => invalid_request(),
            BrokerProjectAuthorizationError::Forbidden => {
                Self::new(StatusCode::FORBIDDEN, "forbidden")
            }
            BrokerProjectAuthorizationError::InvalidPolicy => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "invalid_policy")
            }
            BrokerProjectAuthorizationError::Authentication(error) => match error {
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
            BrokerProjectAuthorizationError::Control(error)
            | BrokerProjectAuthorizationError::Grants(ResourceGrantReadError::Control(error)) => {
                control_failure(error, "authorization_unavailable")
            }
            BrokerProjectAuthorizationError::Grants(_) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
            }
        }
    }
}

struct ProjectRequest {
    project_id: String,
    module: ModuleRequest,
    action: ActionRequest,
}
impl<'de> Deserialize<'de> for ProjectRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> serde::de::Visitor<'de> for ObjectVisitor {
            type Value = ProjectRequest;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a project authorization object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Fields {
                    project_id: String,
                    #[serde(deserialize_with = "string_enum")]
                    module: ModuleRequest,
                    #[serde(deserialize_with = "string_enum")]
                    action: ActionRequest,
                }
                let fields =
                    Fields::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(ProjectRequest {
                    project_id: fields.project_id,
                    module: fields.module,
                    action: fields.action,
                })
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}
fn string_enum<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value = String::deserialize(deserializer)?;
    T::deserialize(serde::de::value::StringDeserializer::<D::Error>::new(value))
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ModuleRequest {
    Task,
    Memory,
    Knowledge,
    Ast,
    Hub,
}
impl From<ModuleRequest> for ProjectResourceModule {
    fn from(value: ModuleRequest) -> Self {
        match value {
            ModuleRequest::Task => Self::Task,
            ModuleRequest::Memory => Self::Memory,
            ModuleRequest::Knowledge => Self::Knowledge,
            ModuleRequest::Ast => Self::Ast,
            ModuleRequest::Hub => Self::Hub,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ActionRequest {
    Read,
    Write,
}
impl From<ActionRequest> for ProjectResourceAction {
    fn from(value: ActionRequest) -> Self {
        match value {
            ActionRequest::Read => Self::Read,
            ActionRequest::Write => Self::Write,
        }
    }
}
#[derive(Serialize)]
struct SubjectResponse<'a> {
    issuer: &'a str,
    subject: &'a str,
}
#[derive(Serialize)]
struct ProjectResponse<'a> {
    subject: SubjectResponse<'a>,
    authorization_revision: i64,
    project_id: &'a str,
    module: &'static str,
    action: &'static str,
}
fn invalid_request() -> HttpFailure {
    HttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request")
}
impl From<ProjectAuthorizationError> for HttpFailure {
    fn from(error: ProjectAuthorizationError) -> Self {
        match error {
            ProjectAuthorizationError::InvalidProject
            | ProjectAuthorizationError::InvalidOperation => invalid_request(),
            ProjectAuthorizationError::Forbidden => Self::new(StatusCode::FORBIDDEN, "forbidden"),
            ProjectAuthorizationError::InvalidPolicy => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "invalid_policy")
            }
            ProjectAuthorizationError::Authentication(error) => authentication_failure(error),
            ProjectAuthorizationError::Control(error)
            | ProjectAuthorizationError::Grants(ResourceGrantReadError::Control(error)) => {
                control_failure(error, "authorization_unavailable")
            }
            ProjectAuthorizationError::Grants(_) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
            }
        }
    }
}
async fn authorize_project(
    State(state): State<Arc<ProjectState>>,
    mut request: Request,
) -> Result<Response, HttpFailure> {
    let (body_bytes, request_timeout) = state.request_limits();
    let end = Instant::now().checked_add(request_timeout).ok_or_else(|| {
        HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
    })?;
    let credential = bearer(request.headers())?;
    if request.uri().query().is_some_and(|query| !query.is_empty()) {
        return Err(invalid_request());
    }
    DefaultBodyLimit::max(body_bytes.get()).apply(&mut request);
    let Json(input) = tokio::time::timeout_at(
        end.into(),
        Json::<ProjectRequest>::from_request(request, &state),
    )
    .await
    .map_err(|_| HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"))?
    .map_err(|error| match error.status() {
        StatusCode::PAYLOAD_TOO_LARGE => {
            HttpFailure::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large")
        }
        StatusCode::UNSUPPORTED_MEDIA_TYPE => {
            HttpFailure::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
        }
        _ => invalid_request(),
    })?;
    // The real SQL producer owns COMMIT classification; no outer business timeout.
    match &state.authentication {
        ProjectAuthentication::Local { backend, config } => {
            let decision = match backend {
                LocalProjectBackend::Postgres(store) => {
                    store
                        .local_project_authorizer(
                            &config.audience,
                            config.identity_json_bytes,
                            config.grants_json_bytes,
                        )?
                        .authorize(
                            credential.token(),
                            &config.required_scopes,
                            input.module.into(),
                            input.action.into(),
                            &input.project_id,
                            end,
                        )
                        .await?
                }
                LocalProjectBackend::Sqlite(store) => {
                    store
                        .local_project_authorizer(
                            &config.audience,
                            config.identity_json_bytes,
                            config.grants_json_bytes,
                        )?
                        .authorize(
                            credential.token(),
                            &config.required_scopes,
                            input.module.into(),
                            input.action.into(),
                            &input.project_id,
                            end,
                        )
                        .await?
                }
            };
            let principal = decision.principal().current_local_user();
            Ok(Json(ProjectResponse {
                subject: SubjectResponse {
                    issuer: principal.issuer(),
                    subject: principal.subject(),
                },
                authorization_revision: decision.policy_revision(),
                project_id: decision.project_id(),
                module: decision.module().as_str(),
                action: decision.action().as_str(),
            })
            .into_response())
        }
        ProjectAuthentication::Broker {
            backend,
            verifier,
            config,
        } => {
            let decision = match backend {
                BrokerProjectBackend::Postgres(store) => {
                    store
                        .broker_project_authorizer(verifier, config.grants_json_bytes)?
                        .authorize(
                            credential.token(),
                            &config.required_scopes,
                            input.module.into(),
                            input.action.into(),
                            &input.project_id,
                            end,
                        )
                        .await?
                }
                BrokerProjectBackend::Sqlite(store) => {
                    store
                        .broker_project_authorizer(verifier, config.grants_json_bytes)?
                        .authorize(
                            credential.token(),
                            &config.required_scopes,
                            input.module.into(),
                            input.action.into(),
                            &input.project_id,
                            end,
                        )
                        .await?
                }
            };
            let principal = decision.principal();
            Ok(Json(ProjectResponse {
                subject: SubjectResponse {
                    issuer: principal.issuer(),
                    subject: principal.subject(),
                },
                authorization_revision: decision.policy_revision(),
                project_id: decision.project_id(),
                module: decision.module().as_str(),
                action: decision.action().as_str(),
            })
            .into_response())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use broker_control::{ControlError, LocalBearerStateError, LocalBearerVerificationError};
    #[test]
    fn project_request_rejects_unknown_duplicate_and_case_aliases() {
        for raw in [
            r#"["p","task","read"]"#,
            r#"{"project_id":"p","module":{"task":null},"action":"read"}"#,
            r#"{"project_id":"p","module":"task","action":{"read":null}}"#,
            r#"{"project_id":"p","module":[],"action":"read"}"#,
            r#"{"project_id":"p","module":"task","action":1}"#,
            r#"{"project_id":"p","module":"Task","action":"read"}"#,
            r#"{"project_id":"p","module":"task","action":"Read"}"#,
            r#"{"project_id":"p","module":"task","action":"read","subject":"forged"}"#,
            r#"{"project_id":"p","project_id":"q","module":"task","action":"read"}"#,
            r#"{"project_id":"p","module":"task","module":"ast","action":"read"}"#,
            r#"{"project_id":"p","module":"task","action":"read","action":"write"}"#,
            r#"{"project_id":"p","module":"task","action":"read"} {}"#,
            r#"{"project_id":"p","module":"task"}"#,
            r#"{"project_id":"p","module":"task","action":null}"#,
        ] {
            assert!(serde_json::from_str::<ProjectRequest>(raw).is_err());
        }
    }
    #[test]
    fn project_failures_preserve_nested_control_and_redact_state() {
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
                ProjectAuthorizationError::Control(control),
                ProjectAuthorizationError::Grants(ResourceGrantReadError::Control(control)),
                ProjectAuthorizationError::Authentication(LocalBearerVerificationError::Control(
                    control,
                )),
                ProjectAuthorizationError::Authentication(LocalBearerVerificationError::State(
                    LocalBearerStateError::Control(control),
                )),
            ] {
                assert_eq!(HttpFailure::from(error), HttpFailure::new(status, code));
            }
        }
        assert_eq!(
            HttpFailure::from(ProjectAuthorizationError::InvalidProject),
            invalid_request()
        );
        assert_eq!(
            HttpFailure::from(ProjectAuthorizationError::InvalidPolicy).code,
            "invalid_policy"
        );
        assert_eq!(
            HttpFailure::from(ProjectAuthorizationError::Authentication(
                LocalBearerVerificationError::Unauthenticated
            ))
            .status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            HttpFailure::from(ProjectAuthorizationError::Grants(
                ResourceGrantReadError::ReadLimitExceeded
            ))
            .code,
            "authorization_unavailable"
        );
    }
    #[test]
    fn project_configuration_is_explicit_and_finite() {
        let cap = NonZeroUsize::new(4096).unwrap();
        let mut config = ProjectAuthorizationHttpConfig {
            audience: "explicit".into(),
            required_scopes: vec![],
            identity_json_bytes: cap,
            grants_json_bytes: cap,
            body_bytes: cap,
            request_timeout: Duration::from_secs(1),
        };
        assert!(valid_config(&config));
        assert_eq!(
            format!("{config:?}"),
            "ProjectAuthorizationHttpConfig([REDACTED])"
        );
        config.audience = " ".into();
        assert!(!valid_config(&config));
        config.audience = "explicit".into();
        config.required_scopes = vec![" ".into()];
        assert!(!valid_config(&config));
        config.required_scopes.clear();
        config.request_timeout = Duration::ZERO;
        assert!(!valid_config(&config));
        config.request_timeout = Duration::MAX;
        assert!(!valid_config(&config));
        assert_eq!(
            ProjectAuthorizationHttpConfigurationError.to_string(),
            "invalid project authorization HTTP configuration"
        );
    }

    #[test]
    fn broker_configuration_and_failures_are_finite() {
        let mut config = BrokerProjectAuthorizationHttpConfig {
            required_scopes: vec![],
            grants_json_bytes: NonZeroUsize::new(4096).unwrap(),
            body_bytes: NonZeroUsize::new(1024).unwrap(),
            request_timeout: Duration::from_secs(2),
        };
        assert!(valid_broker_config(&config));
        for scope in ["", " ", "a b"] {
            config.required_scopes = vec![scope.into()];
            assert!(!valid_broker_config(&config));
        }
        config.required_scopes = vec!["project-api".into()];
        assert!(valid_broker_config(&config));
        config.request_timeout = Duration::ZERO;
        assert!(!valid_broker_config(&config));
        config.request_timeout = Duration::MAX;
        assert!(!valid_broker_config(&config));
        for (error, status, code) in [
            (
                BrokerAccessError::InvalidToken,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
            ),
            (
                BrokerAccessError::Expired,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
            ),
            (
                BrokerAccessError::InsufficientScope,
                StatusCode::FORBIDDEN,
                "insufficient_scope",
            ),
            (
                BrokerAccessError::InvalidConfiguration,
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
            ),
            (
                BrokerAccessError::Deadline,
                StatusCode::GATEWAY_TIMEOUT,
                "deadline",
            ),
        ] {
            let failure = HttpFailure::from(BrokerProjectAuthorizationError::Authentication(error));
            assert_eq!(failure, HttpFailure::new(status, code));
        }
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
                BrokerProjectAuthorizationError::Control(control),
                BrokerProjectAuthorizationError::Grants(ResourceGrantReadError::Control(control)),
            ] {
                assert_eq!(HttpFailure::from(error), HttpFailure::new(status, code));
            }
        }
        assert_eq!(
            format!("{config:?}"),
            "BrokerProjectAuthorizationHttpConfig([REDACTED])"
        );
    }
}
