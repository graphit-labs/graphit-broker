//! Administrative grant writes retain current SQL authorization and CAS.
use super::{
    AdminCookieHttpConfig, AdminLocalBearerHttpConfig, AdminSessionHttpConfig,
    admin_session::{cookie_credential, failure, request_id, response},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Path, Request, State, rejection::PathRejection},
    http::{StatusCode, header},
    response::Response,
    routing::{post, put},
};
use broker_control::{
    AdminBrokerSessionError, AdminGrantError, AdminGrantInput, AdminGrantRequest, AdminGrantResult,
    AdminGrantRoutes, AdminReadAuthentication, AdminReadLimits, BrokerAccessError,
    BrokerAccessVerifier, ControlError, PostgresControlStore, SqliteControlStore,
    UpstreamBearerVerifier, parse_grant_if_match,
};
use std::{num::NonZeroUsize, sync::Arc, time::Instant};
use zeroize::Zeroizing;

pub struct AdminGrantsHttpConfig {
    pub session: AdminSessionHttpConfig,
    pub body_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
    pub response_json_bytes: NonZeroUsize,
    pub local: Option<AdminLocalBearerHttpConfig>,
    pub upstream: Option<Arc<UpstreamBearerVerifier>>,
    pub cookie: Option<AdminCookieHttpConfig>,
    pub routes: Arc<AdminGrantRoutes>,
}

enum WriteBackend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
struct WriteState {
    backend: WriteBackend,
    verifier: Arc<BrokerAccessVerifier>,
    config: AdminGrantsHttpConfig,
}
fn validate_config(config: &AdminGrantsHttpConfig) -> Result<AdminReadLimits, ControlError> {
    config.session.validate()?;
    let limits = AdminReadLimits {
        authorization: config.session.limits,
        grants_json_bytes: config.grants_json_bytes,
        response_json_bytes: config.response_json_bytes,
    };
    limits.validate()?;
    if let Some(local) = &config.local {
        local.validate()?;
    }
    if let Some(cookie) = &config.cookie {
        cookie.validate()?;
    }
    Ok(limits)
}
pub fn admin_grants_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: AdminGrantsHttpConfig,
) -> Result<Router, ControlError> {
    let limits = validate_config(&config)?;
    store.admin_grants(limits, &config.routes)?;
    Ok(routes(WriteState {
        backend: WriteBackend::Postgres(store),
        verifier,
        config,
    }))
}
/// Native SQLite grants CAS with the configured genuine administrative ingresses.
pub fn sqlite_admin_grants_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: AdminGrantsHttpConfig,
) -> Result<Router, ControlError> {
    let limits = validate_config(&config)?;
    store.admin_grants(limits, config.routes.clone())?;
    Ok(routes(WriteState {
        backend: WriteBackend::Sqlite(store),
        verifier,
        config,
    }))
}
fn routes(state: WriteState) -> Router {
    Router::new()
        .route("/admin/api/v1/grants", post(create))
        .route("/admin/api/v1/grants/{id}", put(update).delete(delete))
        .with_state(Arc::new(state))
}
impl WriteState {
    async fn apply<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminGrantRequest<'_>,
        expected: u64,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminGrantResult<'a>, AdminGrantError> {
        let limits = AdminReadLimits {
            authorization: self.config.session.limits,
            grants_json_bytes: self.config.grants_json_bytes,
            response_json_bytes: self.config.response_json_bytes,
        };
        match &self.backend {
            WriteBackend::Postgres(store) => {
                store
                    .admin_grants(limits, &self.config.routes)?
                    .write(authentication, request, expected, csrf, original)
                    .await
            }
            WriteBackend::Sqlite(store) => {
                store
                    .admin_grants(limits, self.config.routes.clone())?
                    .write(authentication, request, expected, csrf, original)
                    .await
            }
        }
    }
}

enum Operation {
    Create,
    Update(Result<Path<String>, PathRejection>),
    Delete(Result<Path<String>, PathRejection>),
}
async fn create(State(state): State<Arc<WriteState>>, request: Request) -> Response {
    write(state, request, Operation::Create).await
}
async fn update(
    State(state): State<Arc<WriteState>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    write(state, request, Operation::Update(path)).await
}
async fn delete(
    State(state): State<Arc<WriteState>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    write(state, request, Operation::Delete(path)).await
}
fn write_failure(error: AdminGrantError, id: &str) -> Response {
    let (status, code, message) = match error {
        AdminGrantError::Authorization(error) => return failure(error, id),
        AdminGrantError::CsrfFailed => (
            StatusCode::FORBIDDEN,
            "csrf_failed",
            "Administrative CSRF verification failed",
        ),
        AdminGrantError::PreconditionRequired => (
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "A positive policy revision is required",
        ),
        AdminGrantError::RevisionConflict => (
            StatusCode::CONFLICT,
            "revision_conflict",
            "Policy revision changed",
        ),
        AdminGrantError::InvalidGrant => (
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Invalid resource grant",
        ),
        AdminGrantError::WriteFailed => (
            StatusCode::BAD_REQUEST,
            "grant_write_failed",
            "Resource grant write failed",
        ),
        AdminGrantError::ReadFailed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "grants_read_failed",
            "Current resource grants unavailable",
        ),
    };
    response(
        status,
        serde_json::json!({"error":{"code":code,"message":message},"request_id":id})
            .to_string()
            .into_bytes(),
        id,
    )
}
async fn write(state: Arc<WriteState>, mut request: Request, operation: Operation) -> Response {
    let start = Instant::now();
    for (name, value) in request.headers_mut().iter_mut() {
        if name == header::AUTHORIZATION
            || name == header::COOKIE
            || name.as_str() == "x-csrf-token"
        {
            value.set_sensitive(true);
        }
    }
    let headers = request.headers().clone();
    let id = match request_id(&headers) {
        Ok(id) => id,
        Err(error) => return failure(error, ""),
    };
    let result =
        async {
            let original = start
                .checked_add(state.config.session.request_timeout)
                .ok_or(ControlError::Configuration)?;
            if Instant::now() >= original {
                return Err(ControlError::Deadline.into());
            }
            let invalid = AdminGrantError::InvalidGrant;
            let cookie = cookie_credential(&headers)?;
            let raw = if cookie.is_none() {
                Some(Zeroizing::new(
                    super::bearer(&headers)
                        .map_err(|_| {
                            AdminBrokerSessionError::Authentication(BrokerAccessError::InvalidToken)
                        })?
                        .token()
                        .to_owned(),
                ))
            } else {
                None
            };
            let authentication =
                if let Some(raw) = cookie.as_deref() {
                    let config = state.config.cookie.as_ref().ok_or(
                        AdminBrokerSessionError::Authentication(BrokerAccessError::InvalidToken),
                    )?;
                    AdminReadAuthentication::Cookie {
                        raw,
                        limits: config.limits,
                        policy: config.policy,
                        upstream: state.config.upstream.clone(),
                    }
                } else {
                    let raw = raw
                        .as_deref()
                        .ok_or(AdminBrokerSessionError::Authentication(
                            BrokerAccessError::InvalidToken,
                        ))?;
                    if let Some(local) = &state.config.local
                        && (raw.starts_with("gb_at_") || raw.starts_with("gb_sc_"))
                    {
                        AdminReadAuthentication::Opaque {
                            raw,
                            audience: &local.audience,
                            identity_json_bytes: local.identity_json_bytes,
                            required_scopes: &local.required_scopes,
                        }
                    } else if let Some(upstream) = &state.config.upstream
                        && !upstream.selects_native(raw, original)?
                    {
                        AdminReadAuthentication::Upstream {
                            raw,
                            verifier: upstream,
                        }
                    } else {
                        AdminReadAuthentication::Broker {
                            verifier: &state.verifier,
                            proof: state
                                .verifier
                                .verify(raw, &[], original)
                                .map_err(AdminBrokerSessionError::from)?,
                        }
                    }
                };
            let mut csrf_values = headers.get_all("x-csrf-token").iter();
            let csrf = csrf_values.next().and_then(|value| value.to_str().ok());
            let csrf = if csrf_values.next().is_none() {
                csrf
            } else {
                None
            };
            let mut values = headers.get_all(header::IF_MATCH).iter();
            let value = values.next().and_then(|value| value.to_str().ok());
            let expected =
                parse_grant_if_match(if values.next().is_none() { value } else { None })?;
            DefaultBodyLimit::max(state.config.body_bytes.get()).apply(&mut request);
            let status = if matches!(&operation, Operation::Create) {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            let mut committed = match operation {
                Operation::Create => {
                    let Json(body) = tokio::time::timeout_at(
                        original.into(),
                        Json::<AdminGrantInput>::from_request(request, &state),
                    )
                    .await
                    .map_err(|_| ControlError::Deadline)?
                    .map_err(|_| invalid)?;
                    state
                        .apply(
                            authentication,
                            AdminGrantRequest::Create(&body),
                            expected,
                            csrf,
                            original,
                        )
                        .await?
                }
                Operation::Update(path) => {
                    let Path(id) = path.map_err(|_| invalid)?;
                    let Json(body) = tokio::time::timeout_at(
                        original.into(),
                        Json::<AdminGrantInput>::from_request(request, &state),
                    )
                    .await
                    .map_err(|_| ControlError::Deadline)?
                    .map_err(|_| invalid)?;
                    state
                        .apply(
                            authentication,
                            AdminGrantRequest::Update {
                                id: &id,
                                grant: &body,
                            },
                            expected,
                            csrf,
                            original,
                        )
                        .await?
                }
                Operation::Delete(path) => {
                    let Path(id) = path.map_err(|_| invalid)?;
                    state
                        .apply(
                            authentication,
                            AdminGrantRequest::Delete { id: &id },
                            expected,
                            csrf,
                            original,
                        )
                        .await?
                }
            };
            committed.check()?;
            let revision = committed.revision();
            let mut response = response(status, committed.take_body(), &id);
            response.headers_mut().insert(
                header::ETAG,
                format!("\"{revision}\"")
                    .parse()
                    .map_err(|_| ControlError::Configuration)?,
            );
            committed.check()?;
            Ok::<_, AdminGrantError>(response)
        }
        .await;
    match result {
        Ok(response) => response,
        Err(error) => write_failure(error, &id),
    }
}
