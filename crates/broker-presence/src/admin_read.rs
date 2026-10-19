//! Administrative read routes share the configured ingress, not session.read authority.
use super::{
    AdminCookieHttpConfig, AdminLocalBearerHttpConfig, AdminSessionHttpConfig,
    admin_session::{cookie_credential, failure, request_id, response},
};
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
    routing::get,
};
use broker_control::{
    AdminBrokerSessionError, AdminReadAuthentication, AdminReadError, AdminReadKind,
    AdminReadLimits, AdminReadRequest, BrokerAccessError, BrokerAccessVerifier, ControlError,
    PostgresControlStore, SqliteControlStore, UpstreamBearerVerifier,
};
use serde::Serialize;
use std::{io::Write, sync::Arc, time::Instant};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct AdminReadHttpConfig {
    pub limits: AdminReadLimits,
    pub provider_command: String,
    pub configuration_yaml: String,
}
struct Count {
    used: usize,
    maximum: usize,
}
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|v| *v <= self.maximum)
            .ok_or(std::io::ErrorKind::FileTooLarge)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl AdminReadHttpConfig {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.limits.validate()?;
        #[derive(Serialize)]
        struct PublicConfig<'a> {
            source: &'static str,
            restart_required: bool,
            yaml: &'a str,
        }
        #[derive(Serialize)]
        struct EmptyCatalog<'a> {
            projects: [(); 0],
            all_projects: bool,
            authorization_revision: i64,
            provider_command: &'a str,
        }
        let maximum = self.limits.response_json_bytes.get();
        serde_json::to_writer(
            &mut Count { used: 0, maximum },
            &PublicConfig {
                source: "deployment",
                restart_required: true,
                yaml: &self.configuration_yaml,
            },
        )
        .map_err(|_| ControlError::Configuration)?;
        serde_json::to_writer(
            &mut Count { used: 0, maximum },
            &EmptyCatalog {
                projects: [],
                all_projects: false,
                authorization_revision: i64::MAX,
                provider_command: &self.provider_command,
            },
        )
        .map_err(|_| ControlError::Configuration)?;
        Ok(())
    }
}
enum ReadBackend {
    Postgres {
        store: Arc<PostgresControlStore>,
        verifier: Arc<BrokerAccessVerifier>,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
    },
    Sqlite {
        store: Arc<SqliteControlStore>,
        verifier: Arc<BrokerAccessVerifier>,
        upstream: Option<Arc<UpstreamBearerVerifier>>,
    },
}
struct ReadState {
    backend: ReadBackend,
    session: AdminSessionHttpConfig,
    config: AdminReadHttpConfig,
    local: Option<AdminLocalBearerHttpConfig>,
    cookie: Option<AdminCookieHttpConfig>,
}
pub fn admin_read_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    session: AdminSessionHttpConfig,
    config: AdminReadHttpConfig,
    local: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<AdminCookieHttpConfig>,
) -> Result<Router, ControlError> {
    validate_limits(&session, &config)?;
    store.admin_reads(config.limits)?;
    if let Some(local) = &local {
        local.validate()?;
    }
    if let Some(cookie) = &cookie {
        cookie.validate()?;
    }
    Ok(routes(ReadState {
        backend: ReadBackend::Postgres {
            store,
            verifier,
            upstream,
        },
        session,
        config,
        local,
        cookie,
    }))
}

/// Seven action-specific projections over all configured genuine SQLite ingresses.
pub fn sqlite_admin_read_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    session: AdminSessionHttpConfig,
    config: AdminReadHttpConfig,
    local: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<AdminCookieHttpConfig>,
) -> Result<Router, ControlError> {
    validate_limits(&session, &config)?;
    store.admin_reads(config.limits)?;
    if let Some(local) = &local {
        local.validate()?;
    }
    if let Some(cookie) = &cookie {
        cookie.validate()?;
        validate_limits(
            &AdminSessionHttpConfig {
                limits: cookie.limits.authorization,
                request_timeout: session.request_timeout,
            },
            &config,
        )?;
    }
    Ok(sqlite_routes(ReadState {
        backend: ReadBackend::Sqlite {
            store,
            verifier,
            upstream,
        },
        session,
        config,
        local,
        cookie,
    }))
}

fn sqlite_routes(state: ReadState) -> Router {
    routes(state).layer(axum::middleware::map_response(
        |mut response: Response| async move {
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
                .headers_mut()
                .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            response
        },
    ))
}

fn validate_limits(
    session: &AdminSessionHttpConfig,
    config: &AdminReadHttpConfig,
) -> Result<(), ControlError> {
    session.validate()?;
    config.validate()?;
    let a = session.limits;
    let b = config.limits.authorization;
    if a.profile_json_bytes != b.profile_json_bytes
        || [
            a.identity.username_bytes,
            a.identity.subject_bytes,
            a.identity.role_bytes,
            a.identity.roles,
            a.identity.rows,
        ] != [
            b.identity.username_bytes,
            b.identity.subject_bytes,
            b.identity.role_bytes,
            b.identity.roles,
            b.identity.rows,
        ]
    {
        return Err(ControlError::Configuration);
    }
    Ok(())
}

fn routes(state: ReadState) -> Router {
    Router::new()
        .route("/admin/api/v1/projects", get(projects))
        .route("/admin/api/v1/roles", get(roles))
        .route("/admin/api/v1/role-assignments", get(assignments))
        .route("/admin/api/v1/local-users", get(users))
        .route("/admin/api/v1/principals", get(principals))
        .route("/admin/api/v1/grants", get(grants))
        .route("/admin/api/v1/config", get(configuration))
        .with_state(Arc::new(state))
}
macro_rules! endpoint {
    ($name:ident,$kind:ident) => {
        async fn $name(State(state): State<Arc<ReadState>>, request: Request) -> Response {
            read(state, request, AdminReadKind::$kind).await
        }
    };
}
endpoint!(projects, Projects);
endpoint!(roles, Roles);
endpoint!(assignments, Assignments);
endpoint!(users, Users);
endpoint!(principals, Principals);
endpoint!(grants, Grants);
endpoint!(configuration, Configuration);

fn read_failure(error: AdminReadError, id: &str) -> Response {
    match error {
        AdminReadError::Authorization(error)=>failure(error,id),
        AdminReadError::Projection(kind)=>response(
            if kind==AdminReadKind::Projects {StatusCode::SERVICE_UNAVAILABLE}else{StatusCode::INTERNAL_SERVER_ERROR},
            serde_json::json!({"error":{"code":kind.error_code(),"message":"Administrative projection unavailable"},"request_id":id}).to_string().into_bytes(),id),
    }
}
async fn read(state: Arc<ReadState>, mut request: Request, kind: AdminReadKind) -> Response {
    let start = Instant::now();
    for (name, value) in request.headers_mut().iter_mut() {
        if name == header::AUTHORIZATION
            || name == header::COOKIE
            || name.as_str() == "x-csrf-token"
        {
            value.set_sensitive(true);
        }
    }
    let headers = request.into_parts().0.headers;
    let id = match request_id(&headers) {
        Ok(id) => id,
        Err(e) => return failure(e, ""),
    };
    let result = async {
        let original = start
            .checked_add(state.session.request_timeout)
            .ok_or(ControlError::Configuration)?;
        if Instant::now() >= original {
            return Err(ControlError::Deadline.into());
        }
        let command = match kind {
            AdminReadKind::Projects => AdminReadRequest::Projects {
                provider_command: &state.config.provider_command,
            },
            AdminReadKind::Roles => AdminReadRequest::Roles,
            AdminReadKind::Assignments => AdminReadRequest::Assignments,
            AdminReadKind::Users => AdminReadRequest::Users,
            AdminReadKind::Principals => AdminReadRequest::Principals,
            AdminReadKind::Grants => AdminReadRequest::Grants,
            AdminReadKind::Configuration => AdminReadRequest::Configuration {
                yaml: &state.config.configuration_yaml,
            },
        };
        let observation =
            match &state.backend {
                ReadBackend::Postgres {
                    store,
                    verifier,
                    upstream,
                } => {
                    let reader = store.admin_reads(state.config.limits)?;
                    if let Some(raw) = cookie_credential(&headers)? {
                        let cookie = state.cookie.as_ref().ok_or(
                            AdminBrokerSessionError::Authentication(
                                BrokerAccessError::InvalidToken,
                            ),
                        )?;
                        reader
                            .read(
                                AdminReadAuthentication::Cookie {
                                    raw: &raw,
                                    limits: cookie.limits,
                                    policy: cookie.policy,
                                    upstream: upstream.clone(),
                                },
                                command,
                                original,
                            )
                            .await?
                    } else {
                        let bearer = super::bearer(&headers).map_err(|_| {
                            AdminBrokerSessionError::Authentication(BrokerAccessError::InvalidToken)
                        })?;
                        let raw = Zeroizing::new(bearer.token().to_owned());
                        let authentication = if let Some(local) = &state.local
                            && (raw.starts_with("gb_at_") || raw.starts_with("gb_sc_"))
                        {
                            AdminReadAuthentication::Opaque {
                                raw: &raw,
                                audience: &local.audience,
                                identity_json_bytes: local.identity_json_bytes,
                                required_scopes: &local.required_scopes,
                            }
                        } else if let Some(upstream) = &upstream
                            && !upstream.selects_native(&raw, original)?
                        {
                            AdminReadAuthentication::Upstream {
                                raw: &raw,
                                verifier: upstream,
                            }
                        } else {
                            AdminReadAuthentication::Broker {
                                verifier,
                                proof: verifier
                                    .verify(&raw, &[], original)
                                    .map_err(AdminBrokerSessionError::from)?,
                            }
                        };
                        reader.read(authentication, command, original).await?
                    }
                }
                ReadBackend::Sqlite {
                    store,
                    verifier,
                    upstream,
                } => {
                    let reader = store.admin_reads(state.config.limits)?;
                    if let Some(raw) = cookie_credential(&headers)? {
                        let cookie = state.cookie.as_ref().ok_or(
                            AdminBrokerSessionError::Authentication(
                                BrokerAccessError::InvalidToken,
                            ),
                        )?;
                        reader
                            .read(
                                AdminReadAuthentication::Cookie {
                                    raw: &raw,
                                    limits: cookie.limits,
                                    policy: cookie.policy,
                                    upstream: upstream.clone(),
                                },
                                command,
                                original,
                            )
                            .await?
                    } else {
                        let bearer = super::bearer(&headers).map_err(|_| {
                            AdminBrokerSessionError::Authentication(BrokerAccessError::InvalidToken)
                        })?;
                        let raw = Zeroizing::new(bearer.token().to_owned());
                        let authentication = if let Some(local) = &state.local
                            && (raw.starts_with("gb_at_") || raw.starts_with("gb_sc_"))
                        {
                            AdminReadAuthentication::Opaque {
                                raw: &raw,
                                audience: &local.audience,
                                identity_json_bytes: local.identity_json_bytes,
                                required_scopes: &local.required_scopes,
                            }
                        } else if let Some(upstream) = &upstream
                            && !upstream.selects_native(&raw, original)?
                        {
                            AdminReadAuthentication::Upstream {
                                raw: &raw,
                                verifier: upstream,
                            }
                        } else {
                            AdminReadAuthentication::Broker {
                                verifier,
                                proof: verifier
                                    .verify(&raw, &[], original)
                                    .map_err(AdminBrokerSessionError::from)?,
                            }
                        };
                        reader.read(authentication, command, original).await?
                    }
                }
            };
        observation.check()?;
        let mut response = response(StatusCode::OK, observation.body().to_vec(), &id);
        if let Some(revision) = observation.revision() {
            response.headers_mut().insert(
                header::ETAG,
                HeaderValue::from_str(&format!("\"{revision}\""))
                    .map_err(|_| AdminReadError::Projection(kind))?,
            );
        }
        observation.check()?;
        Ok::<_, AdminReadError>(response)
    }
    .await;
    match result {
        Ok(response) => response,
        Err(error) => read_failure(error, &id),
    }
}
