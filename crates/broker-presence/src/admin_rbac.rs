//! Administrative RBAC writes use the same genuine ingress as reads, with current SQL authorization.
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
    AdminBrokerSessionError, AdminRbacError, AdminRbacRequest, AdminRbacResult,
    AdminReadAuthentication, BrokerAccessError, BrokerAccessVerifier, ControlError,
    PostgresControlStore, SqliteControlStore, UpstreamBearerVerifier,
};
use serde::Deserialize;
use std::{num::NonZeroUsize, sync::Arc, time::Instant};
use zeroize::Zeroizing;

enum WriteBackend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
struct WriteState {
    backend: WriteBackend,
    verifier: Arc<BrokerAccessVerifier>,
    session: AdminSessionHttpConfig,
    body_bytes: NonZeroUsize,
    local: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<AdminCookieHttpConfig>,
}
pub fn admin_rbac_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    session: AdminSessionHttpConfig,
    body_bytes: NonZeroUsize,
    local: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<AdminCookieHttpConfig>,
) -> Result<Router, ControlError> {
    write_router(
        WriteBackend::Postgres(store),
        verifier,
        session,
        body_bytes,
        local,
        upstream,
        cookie,
    )
}
pub fn sqlite_admin_rbac_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    session: AdminSessionHttpConfig,
    body_bytes: NonZeroUsize,
    local: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<AdminCookieHttpConfig>,
) -> Result<Router, ControlError> {
    write_router(
        WriteBackend::Sqlite(store),
        verifier,
        session,
        body_bytes,
        local,
        upstream,
        cookie,
    )
}
fn write_router(
    backend: WriteBackend,
    verifier: Arc<BrokerAccessVerifier>,
    session: AdminSessionHttpConfig,
    body_bytes: NonZeroUsize,
    local: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<AdminCookieHttpConfig>,
) -> Result<Router, ControlError> {
    session.validate()?;
    match &backend {
        WriteBackend::Postgres(store) => {
            store.admin_rbac(session.limits)?;
        }
        WriteBackend::Sqlite(store) => {
            store.admin_rbac(session.limits)?;
        }
    }
    if let Some(local) = &local {
        local.validate()?;
    }
    if let Some(cookie) = &cookie {
        cookie.validate()?;
    }
    Ok(Router::new()
        .route(
            "/admin/api/v1/roles/{name}",
            put(set_role).delete(delete_role),
        )
        .route(
            "/admin/api/v1/role-assignments",
            post(assign).delete(revoke),
        )
        .with_state(Arc::new(WriteState {
            backend,
            verifier,
            session,
            body_bytes,
            local,
            upstream,
            cookie,
        })))
}

impl WriteState {
    async fn apply<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminRbacRequest<'_>,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminRbacResult<'a>, AdminRbacError> {
        match &self.backend {
            WriteBackend::Postgres(store) => {
                store
                    .admin_rbac(self.session.limits)?
                    .write(authentication, request, csrf, original)
                    .await
            }
            WriteBackend::Sqlite(store) => {
                store
                    .admin_rbac(self.session.limits)?
                    .write(authentication, request, csrf, original)
                    .await
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleInput {
    #[serde(default)]
    permissions: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentInput {
    subject: String,
    role: String,
}
enum Operation {
    SetRole(Result<Path<String>, PathRejection>),
    DeleteRole(Result<Path<String>, PathRejection>),
    Assign,
    Revoke,
}
impl Operation {
    fn invalid(&self) -> AdminRbacError {
        match self {
            Self::SetRole(_) => AdminRbacError::InvalidRole,
            Self::DeleteRole(_) => AdminRbacError::RoleDeleteFailed,
            Self::Assign | Self::Revoke => AdminRbacError::AssignmentFailed,
        }
    }
}
async fn set_role(
    State(state): State<Arc<WriteState>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    write(state, request, Operation::SetRole(path)).await
}
async fn delete_role(
    State(state): State<Arc<WriteState>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    write(state, request, Operation::DeleteRole(path)).await
}
async fn assign(State(state): State<Arc<WriteState>>, request: Request) -> Response {
    write(state, request, Operation::Assign).await
}
async fn revoke(State(state): State<Arc<WriteState>>, request: Request) -> Response {
    write(state, request, Operation::Revoke).await
}
fn write_failure(error: AdminRbacError, id: &str) -> Response {
    let (status, code, message) = match error {
        AdminRbacError::Authorization(error) => return failure(error, id),
        AdminRbacError::CsrfFailed => (
            StatusCode::FORBIDDEN,
            "csrf_failed",
            "Administrative CSRF verification failed",
        ),
        AdminRbacError::InvalidRole => (
            StatusCode::BAD_REQUEST,
            "invalid_role",
            "Invalid system role definition",
        ),
        AdminRbacError::RoleDeleteFailed => (
            StatusCode::BAD_REQUEST,
            "role_delete_failed",
            "System role deletion failed",
        ),
        AdminRbacError::AssignmentFailed => (
            StatusCode::BAD_REQUEST,
            "assignment_failed",
            "System role assignment failed",
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
    let result = async {
        let original = start
            .checked_add(state.session.request_timeout)
            .ok_or(ControlError::Configuration)?;
        if Instant::now() >= original {
            return Err(ControlError::Deadline.into());
        }
        let invalid = operation.invalid();
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
        let authentication = if let Some(raw) = cookie.as_deref() {
            let config = state
                .cookie
                .as_ref()
                .ok_or(AdminBrokerSessionError::Authentication(
                    BrokerAccessError::InvalidToken,
                ))?;
            AdminReadAuthentication::Cookie {
                raw,
                limits: config.limits,
                policy: config.policy,
                upstream: state.upstream.clone(),
            }
        } else {
            let raw = raw
                .as_deref()
                .ok_or(AdminBrokerSessionError::Authentication(
                    BrokerAccessError::InvalidToken,
                ))?;
            if let Some(local) = &state.local
                && (raw.starts_with("gb_at_") || raw.starts_with("gb_sc_"))
            {
                AdminReadAuthentication::Opaque {
                    raw,
                    audience: &local.audience,
                    identity_json_bytes: local.identity_json_bytes,
                    required_scopes: &local.required_scopes,
                }
            } else if let Some(upstream) = &state.upstream
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
        DefaultBodyLimit::max(state.body_bytes.get()).apply(&mut request);
        let committed = match operation {
            Operation::SetRole(path) => {
                let Path(name) = path.map_err(|_| invalid)?;
                let Json(body) = tokio::time::timeout_at(
                    original.into(),
                    Json::<RoleInput>::from_request(request, &state),
                )
                .await
                .map_err(|_| ControlError::Deadline)?
                .map_err(|_| invalid)?;
                state
                    .apply(
                        authentication,
                        AdminRbacRequest::SetRole {
                            name: &name,
                            permissions: &body.permissions,
                        },
                        csrf,
                        original,
                    )
                    .await?
            }
            Operation::DeleteRole(path) => {
                let Path(name) = path.map_err(|_| invalid)?;
                state
                    .apply(
                        authentication,
                        AdminRbacRequest::DeleteRole { name: &name },
                        csrf,
                        original,
                    )
                    .await?
            }
            Operation::Assign | Operation::Revoke => {
                let Json(body) = tokio::time::timeout_at(
                    original.into(),
                    Json::<AssignmentInput>::from_request(request, &state),
                )
                .await
                .map_err(|_| ControlError::Deadline)?
                .map_err(|_| invalid)?;
                let command = if matches!(operation, Operation::Assign) {
                    AdminRbacRequest::Assign {
                        subject: &body.subject,
                        role: &body.role,
                    }
                } else {
                    AdminRbacRequest::Revoke {
                        subject: &body.subject,
                        role: &body.role,
                    }
                };
                state.apply(authentication, command, csrf, original).await?
            }
        };
        committed.check()?;
        let response = response(StatusCode::NO_CONTENT, Vec::new(), &id);
        committed.check()?;
        Ok::<_, AdminRbacError>(response)
    }
    .await;
    match result {
        Ok(response) => response,
        Err(error) => write_failure(error, &id),
    }
}
