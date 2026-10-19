//! Native LOCAL user, factor and service-credential administration.
use super::{
    AdminCookieHttpConfig, AdminLocalBearerHttpConfig, AdminSessionHttpConfig,
    admin_session::{cookie_credential, failure, request_id, response},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Path, Request, State, rejection::PathRejection},
    http::{StatusCode, header},
    response::Response,
    routing::{delete, get, post, put},
};
use broker_control::{
    AdminBrokerSessionError, AdminReadAuthentication, AdminServiceCredentialInput, AdminUserInput,
    AdminUsersError, AdminUsersLimits, AdminUsersRequest, AdminUsersResult, BrokerAccessError,
    BrokerAccessVerifier, ControlError, LocalPasswordEngine, PostgresAdminUsers,
    PostgresControlStore, SqliteAdminUsers, SqliteControlStore, UpstreamBearerVerifier,
};
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[derive(Clone)]
pub struct AdminUsersHttpConfig {
    pub session: AdminSessionHttpConfig,
    pub body_bytes: NonZeroUsize,
    pub response_json_bytes: NonZeroUsize,
    pub local: Option<AdminLocalBearerHttpConfig>,
    pub upstream: Option<Arc<UpstreamBearerVerifier>>,
    pub cookie: Option<AdminCookieHttpConfig>,
    pub service_credential_audience: String,
    pub service_credential_max_ttl: Duration,
}
enum UserStore {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
enum UserService<'s> {
    Postgres(PostgresAdminUsers<'s>),
    Sqlite(SqliteAdminUsers<'s>),
}
impl UserStore {
    fn admin_users<'s>(
        &'s self,
        engine: &'s LocalPasswordEngine,
        limits: &'s AdminUsersLimits,
    ) -> Result<UserService<'s>, ControlError> {
        match self {
            Self::Postgres(store) => store.admin_users(engine, limits).map(UserService::Postgres),
            Self::Sqlite(store) => store.admin_users(engine, limits).map(UserService::Sqlite),
        }
    }
}
impl UserService<'_> {
    async fn execute<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminUsersRequest<'_>,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminUsersResult<'a>, AdminUsersError> {
        match self {
            Self::Postgres(users) => users.execute(authentication, request, csrf, original).await,
            Self::Sqlite(users) => users.execute(authentication, request, csrf, original).await,
        }
    }
}
struct UserState {
    store: UserStore,
    verifier: Arc<BrokerAccessVerifier>,
    engine: Arc<LocalPasswordEngine>,
    config: AdminUsersHttpConfig,
    limits: AdminUsersLimits,
}
pub fn admin_users_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    engine: Arc<LocalPasswordEngine>,
    config: AdminUsersHttpConfig,
) -> Result<Router, ControlError> {
    make_router(UserStore::Postgres(store), verifier, engine, config)
}
/// Explicit SQLite composition with the actual shared password engine.
pub fn sqlite_admin_users_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    engine: Arc<LocalPasswordEngine>,
    config: AdminUsersHttpConfig,
) -> Result<Router, ControlError> {
    make_router(UserStore::Sqlite(store), verifier, engine, config)
}
fn make_router(
    store: UserStore,
    verifier: Arc<BrokerAccessVerifier>,
    engine: Arc<LocalPasswordEngine>,
    config: AdminUsersHttpConfig,
) -> Result<Router, ControlError> {
    config.session.validate()?;
    if let Some(local) = &config.local {
        local.validate()?;
    }
    if let Some(cookie) = &config.cookie {
        cookie.validate()?;
    }
    let limits = AdminUsersLimits {
        authorization: config.session.limits,
        response_json_bytes: config.response_json_bytes,
        service_credential_audience: config.service_credential_audience.clone(),
        service_credential_max_ttl: config.service_credential_max_ttl,
    };
    store.admin_users(&engine, &limits)?;
    Ok(Router::new()
        .route("/admin/api/v1/local-users", post(create))
        .route(
            "/admin/api/v1/local-users/{username}",
            put(update).delete(remove),
        )
        .route(
            "/admin/api/v1/local-users/{username}/mfa/reset",
            post(reset_mfa),
        )
        .route(
            "/admin/api/v1/local-users/{username}/credentials",
            get(credentials).post(issue),
        )
        .route(
            "/admin/api/v1/local-users/{username}/credentials/{id}",
            delete(revoke),
        )
        .with_state(Arc::new(UserState {
            store,
            verifier,
            engine,
            config,
            limits,
        })))
}
enum Operation {
    Create,
    Update(Result<Path<String>, PathRejection>),
    Delete(Result<Path<String>, PathRejection>),
    ResetMfa(Result<Path<String>, PathRejection>),
    Credentials(Result<Path<String>, PathRejection>),
    Issue(Result<Path<String>, PathRejection>),
    Revoke(Result<Path<(String, String)>, PathRejection>),
}
impl Operation {
    fn invalid(&self) -> AdminUsersError {
        match self {
            Self::Create => AdminUsersError::CreateFailed,
            Self::Update(_) => AdminUsersError::UpdateFailed,
            Self::Delete(_) => AdminUsersError::DeleteFailed,
            Self::ResetMfa(_) => AdminUsersError::MfaResetFailed,
            Self::Credentials(_) => AdminUsersError::CredentialsReadFailed,
            Self::Issue(_) => AdminUsersError::InvalidCredential,
            Self::Revoke(_) => AdminUsersError::CredentialRevokeFailed,
        }
    }
}
async fn create(State(state): State<Arc<UserState>>, request: Request) -> Response {
    execute(state, request, Operation::Create).await
}
async fn update(
    State(state): State<Arc<UserState>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    execute(state, request, Operation::Update(path)).await
}
async fn remove(
    State(state): State<Arc<UserState>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    execute(state, request, Operation::Delete(path)).await
}
async fn reset_mfa(
    State(state): State<Arc<UserState>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    execute(state, request, Operation::ResetMfa(path)).await
}
async fn credentials(
    State(state): State<Arc<UserState>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    execute(state, request, Operation::Credentials(path)).await
}
async fn issue(
    State(state): State<Arc<UserState>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    execute(state, request, Operation::Issue(path)).await
}
async fn revoke(
    State(state): State<Arc<UserState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Response {
    execute(state, request, Operation::Revoke(path)).await
}
fn user_failure(error: AdminUsersError, id: &str) -> Response {
    let (status, code, message) = match error {
        AdminUsersError::Authorization(error) => return failure(error, id),
        AdminUsersError::CsrfFailed => (
            StatusCode::FORBIDDEN,
            "csrf_failed",
            "Administrative CSRF verification failed",
        ),
        AdminUsersError::CreateFailed => (
            StatusCode::BAD_REQUEST,
            "user_create_failed",
            "Could not create local user",
        ),
        AdminUsersError::UpdateFailed => (
            StatusCode::BAD_REQUEST,
            "user_update_failed",
            "Could not update local user",
        ),
        AdminUsersError::DeleteFailed => (
            StatusCode::BAD_REQUEST,
            "user_delete_failed",
            "Could not delete local user",
        ),
        AdminUsersError::MfaResetFailed => (
            StatusCode::BAD_REQUEST,
            "mfa_reset_failed",
            "Could not reset local MFA",
        ),
        AdminUsersError::ServiceIdentityNotFound => (
            StatusCode::NOT_FOUND,
            "service_identity_not_found",
            "Service identity does not exist",
        ),
        AdminUsersError::InvalidCredential => (
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            "Invalid service credential request",
        ),
        AdminUsersError::CredentialCreateFailed => (
            StatusCode::BAD_REQUEST,
            "credential_create_failed",
            "Could not create service credential",
        ),
        AdminUsersError::CredentialGenerationFailed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential_create_failed",
            "Could not create service credential",
        ),
        AdminUsersError::CredentialRevokeFailed => (
            StatusCode::BAD_REQUEST,
            "credential_revoke_failed",
            "Could not revoke service credential",
        ),
        AdminUsersError::CredentialsReadFailed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "credentials_read_failed",
            "Could not list service credentials",
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
async fn execute(state: Arc<UserState>, mut request: Request, operation: Operation) -> Response {
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
            let csrf = csrf_values.next().and_then(|v| v.to_str().ok());
            let csrf = if csrf_values.next().is_none() {
                csrf
            } else {
                None
            };
            DefaultBodyLimit::max(state.config.body_bytes.get()).apply(&mut request);
            let users = state.store.admin_users(&state.engine, &state.limits)?;
            let mut delivered = match operation {
                Operation::Create => {
                    let Json(input) = tokio::time::timeout_at(
                        original.into(),
                        Json::<AdminUserInput>::from_request(request, &state),
                    )
                    .await
                    .map_err(|_| ControlError::Deadline)?
                    .map_err(|_| invalid)?;
                    users
                        .execute(
                            authentication,
                            AdminUsersRequest::Create(&input),
                            csrf,
                            original,
                        )
                        .await?
                }
                Operation::Update(path) => {
                    let Path(username) = path.map_err(|_| invalid)?;
                    let Json(user) = tokio::time::timeout_at(
                        original.into(),
                        Json::<AdminUserInput>::from_request(request, &state),
                    )
                    .await
                    .map_err(|_| ControlError::Deadline)?
                    .map_err(|_| invalid)?;
                    users
                        .execute(
                            authentication,
                            AdminUsersRequest::Update {
                                username: &username,
                                user: &user,
                            },
                            csrf,
                            original,
                        )
                        .await?
                }
                Operation::Delete(path) => {
                    let Path(username) = path.map_err(|_| invalid)?;
                    users
                        .execute(
                            authentication,
                            AdminUsersRequest::Delete {
                                username: &username,
                            },
                            csrf,
                            original,
                        )
                        .await?
                }
                Operation::ResetMfa(path) => {
                    let Path(username) = path.map_err(|_| invalid)?;
                    users
                        .execute(
                            authentication,
                            AdminUsersRequest::ResetMfa {
                                username: &username,
                            },
                            csrf,
                            original,
                        )
                        .await?
                }
                Operation::Credentials(path) => {
                    let Path(username) = path.map_err(|_| invalid)?;
                    users
                        .execute(
                            authentication,
                            AdminUsersRequest::Credentials {
                                username: &username,
                            },
                            csrf,
                            original,
                        )
                        .await?
                }
                Operation::Issue(path) => {
                    let Path(username) = path.map_err(|_| invalid)?;
                    let Json(input) = tokio::time::timeout_at(
                        original.into(),
                        Json::<AdminServiceCredentialInput>::from_request(request, &state),
                    )
                    .await
                    .map_err(|_| ControlError::Deadline)?
                    .map_err(|_| invalid)?;
                    users
                        .execute(
                            authentication,
                            AdminUsersRequest::IssueCredential {
                                username: &username,
                                input: &input,
                            },
                            csrf,
                            original,
                        )
                        .await?
                }
                Operation::Revoke(path) => {
                    let Path((username, id)) = path.map_err(|_| invalid)?;
                    users
                        .execute(
                            authentication,
                            AdminUsersRequest::RevokeCredential {
                                username: &username,
                                id: &id,
                            },
                            csrf,
                            original,
                        )
                        .await?
                }
            };
            delivered.check()?;
            let status = StatusCode::from_u16(delivered.status())
                .map_err(|_| ControlError::Configuration)?;
            let response = response(status, delivered.take_body(), &id);
            delivered.check()?;
            Ok::<_, AdminUsersError>(response)
        }
        .await;
    match result {
        Ok(response) => response,
        Err(error) => user_failure(error, &id),
    }
}
