use crate::config::{OwnedLocalLogin, PreparedDatabase, PreparedPresenceAuthentication};
use crate::{PreparedConfig, ServerError};
use axum::{Json, Router, http::StatusCode, routing::get};
use broker_control::{LocalPasswordEngine, PostgresControlStore, SqliteControlStore};
use broker_presence::{
    AdminLocalLoginHttpConfig, AdminUpstreamLoginHttpConfig, BrokerStorageCredentialsHttpConfig,
    FilesystemStorageHttp, InstanceInventoryReadHttpConfig, InstanceRegistryHttpConfig,
    LocalRealtimeHttpConfig, LocalStorageCredentialsHttpConfig, OidcBrowserHttpConfig,
    OidcRevocationHttpConfig, OidcUpstreamLoginHttpConfig, OidcUserInfoHttpConfig,
    RealtimeServerRuntime, UpstreamLoginHttpConfig, admin_local_login_router, admin_read_router,
    admin_session_router_with_cookie, broker_instance_inventory_router,
    broker_project_authorization_router, broker_realtime_router, instance_inventory_router,
    local_realtime_router, oidc_browser_router, oidc_registration_router, oidc_revocation_router,
    oidc_token_router, oidc_userinfo_router, storage_credentials_router, upstream_login_router,
};
use broker_storage::{FilesystemGatewayConfig, FilesystemStore, FilesystemStoreError};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
use tokio_io_timeout::TimeoutStream;
use tower_http::timeout::{RequestBodyTimeoutLayer, ResponseBodyTimeoutLayer};

enum OwnedDatabase {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
impl OwnedDatabase {
    async fn shutdown(&self, end: Instant) -> Result<(), ServerError> {
        match self {
            Self::Postgres(store) => store.shutdown(end).await.map_err(|_| ServerError::Shutdown),
            Self::Sqlite(store) => store.shutdown(end).await.map_err(|_| ServerError::Shutdown),
        }
    }
}

async fn close_local(
    local: Option<&OwnedLocalLogin>,
    passwords: Option<&Arc<LocalPasswordEngine>>,
) {
    if let Some(local) = local {
        local.close().await;
    } else if let Some(passwords) = passwords {
        passwords.close().await;
    }
}
async fn close_partial(
    store: &OwnedDatabase,
    timeout: Duration,
    local: Option<&OwnedLocalLogin>,
    passwords: Option<&Arc<LocalPasswordEngine>>,
) {
    let end = Instant::now().checked_add(timeout);
    close_local(local, passwords).await;
    if let Some(end) = end {
        let _ = store.shutdown(end).await;
    }
}

async fn shutdown_realtime(
    runtime: Option<RealtimeServerRuntime>,
    end: Instant,
) -> Result<(), ServerError> {
    let Some(runtime) = runtime else {
        return Ok(());
    };
    let shutdown = runtime.shutdown();
    tokio::pin!(shutdown);
    match tokio::time::timeout_at(end.into(), &mut shutdown).await {
        Ok(result) => result.map_err(|_| ServerError::Shutdown),
        Err(_) => {
            // Keep the started shutdown and confirm its joins before SQL closes.
            // Draining cleanup does not renew the expired operation's budget.
            let _ = shutdown.await;
            Err(ServerError::Shutdown)
        }
    }
}
async fn close_partial_presence(
    store: &OwnedDatabase,
    runtime: Option<RealtimeServerRuntime>,
    timeout: Duration,
    local: Option<&OwnedLocalLogin>,
    passwords: Option<&Arc<LocalPasswordEngine>>,
) {
    let end = Instant::now().checked_add(timeout);
    if let Some(end) = end {
        let _ = shutdown_realtime(runtime, end).await;
    }
    close_local(local, passwords).await;
    if let Some(end) = end {
        let _ = store.shutdown(end).await;
    }
}

/// Initialize the first LOCAL administrator through the deployment's SQL owner.
/// The caller supplies protected standard input; no HTTP or session is started.
pub async fn bootstrap_local_administrator(
    config: PreparedConfig,
    password: &str,
) -> Result<(), ServerError> {
    config.shutdown_models().await?;
    if config.local_login.is_none()
        || config.local_password.is_none()
        || config
            .administration
            .as_ref()
            .is_none_or(|admin| admin.cookie.is_none())
    {
        return Err(ServerError::AdministratorConfiguration);
    }
    broker_control::validate_initial_administrator_password(password)
        .map_err(|_| ServerError::AdministratorInput)?;
    let startup = Instant::now()
        .checked_add(config.startup_timeout)
        .ok_or(ServerError::Configuration)?;
    let shutdown_timeout = config.server.shutdown_timeout();
    let passwords = config
        .local_password
        .ok_or(ServerError::AdministratorConfiguration)?
        .start(startup)
        .await
        .map_err(|error| match error {
            broker_control::LocalPasswordVerificationError::Control(
                broker_control::ControlError::Deadline,
            ) => ServerError::Startup,
            _ => ServerError::Configuration,
        })?;
    let hash = match passwords.hash(password, startup).await {
        Ok(hash) => hash,
        Err(error) => {
            passwords.close().await;
            return Err(match error {
                broker_control::LocalPasswordVerificationError::Control(
                    broker_control::ControlError::Deadline,
                ) => ServerError::Startup,
                broker_control::LocalPasswordVerificationError::Password(
                    broker_security::LocalPasswordError::InvalidPassword,
                ) => ServerError::AdministratorInput,
                _ => ServerError::Administrator,
            });
        }
    };
    let opened = match config.database {
        PreparedDatabase::Postgres(database) => {
            PostgresControlStore::open(*database, config.digester, startup)
                .await
                .map(|store| OwnedDatabase::Postgres(Arc::new(store)))
                .map_err(|error| {
                    if error == broker_control::ControlError::Deadline {
                        ServerError::Startup
                    } else {
                        ServerError::Database
                    }
                })
        }
        PreparedDatabase::Sqlite(database) => {
            SqliteControlStore::open(database, config.digester, startup)
                .await
                .map(|store| OwnedDatabase::Sqlite(Arc::new(store)))
                .map_err(|error| {
                    if error == broker_control::SqliteControlError::Deadline {
                        ServerError::Startup
                    } else {
                        ServerError::SqliteDatabase(error)
                    }
                })
        }
    };
    let store = match opened {
        Ok(store) => store,
        Err(error) => {
            passwords.close().await;
            return Err(error);
        }
    };
    let result = match &store {
        OwnedDatabase::Postgres(store) => store.bootstrap_local_administrator(&hash, startup).await,
        OwnedDatabase::Sqlite(store) => store.bootstrap_local_administrator(&hash, startup).await,
    }
    .map_err(|error| match error {
        broker_control::LocalAdministratorBootstrapError::AlreadyInitialized => {
            ServerError::AdministratorExists
        }
        broker_control::LocalAdministratorBootstrapError::Control(
            broker_control::ControlError::Deadline,
        ) => ServerError::Startup,
        broker_control::LocalAdministratorBootstrapError::Control(
            broker_control::ControlError::OutcomeUncertain,
        ) => ServerError::AdministratorOutcomeUncertain,
        _ => ServerError::Administrator,
    });
    // Use one shutdown Original for the physical engine and SQL drain.
    let shutdown = Instant::now().checked_add(shutdown_timeout);
    passwords.close().await;
    let closed = match shutdown {
        Some(end) => store.shutdown(end).await,
        None => {
            // An invalid cleanup budget must not abandon an existing owner.
            // Retain the existing startup Original and preserve the failure.
            let _ = store.shutdown(startup).await;
            Err(ServerError::Configuration)
        }
    };
    match (result, closed) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(_)) => Err(ServerError::AdministratorShutdown),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// Serve the configured SQL/HTTP stack until an owned shutdown signal.
/// The signal future is also used by embedders; the binary supplies SIGINT/SIGTERM.
pub async fn serve(
    config: PreparedConfig,
    shutdown: impl Future<Output = Result<(), ServerError>>,
) -> Result<(), ServerError> {
    let embeddings = config.embeddings.as_ref().map(|e| e.backend.clone());
    let rerank = config.rerank.as_ref().map(|r| r.backend.clone());
    let timeout = config.server.shutdown_timeout();
    let mut config = config;
    let native_sdk = config.native_sdk.take();
    let result = serve_inner(config, shutdown).await;
    let cancel = graphit_core::file_lock::Cancellation::default();
    let end = Instant::now()
        .checked_add(timeout)
        .ok_or(ServerError::Configuration)?;
    let context = graphit_ai::context::InferenceContext::new(&cancel, end);
    let (a, b) = tokio::join!(
        async {
            match &embeddings {
                Some(backend) => backend
                    .shutdown(context)
                    .await
                    .map_err(|_| ServerError::Shutdown),
                None => Ok(()),
            }
        },
        async {
            match &rerank {
                Some(backend) => backend
                    .shutdown(context)
                    .await
                    .map_err(|_| ServerError::Shutdown),
                None => Ok(()),
            }
        },
    );
    drop(embeddings);
    drop(rerank);
    drop(native_sdk);
    a?;
    b?;
    result
}
async fn serve_inner(
    config: PreparedConfig,
    shutdown: impl Future<Output = Result<(), ServerError>>,
) -> Result<(), ServerError> {
    let PreparedConfig {
        server,
        database,
        digester,
        verifier,
        upstream,
        jwks,
        credentials,
        stores: configs,
        storage,
        default_route,
        grant_routes,
        audience,
        startup_timeout,
        oidc,
        administration,
        upstream_cookie_secure,
        local_login,
        local_password,
        service_credential_max_ttl,
        project_access,
        presence,
        embeddings,
        rerank,
        configuration_yaml,
        instruction_overrides_file,
        native_sdk: _,
    } = config;
    let embeddings_backend = embeddings.as_ref().map(|e| e.backend.clone());
    let embeddings_http = embeddings.as_ref().map(|e| e.http.clone());
    let rerank_backend = rerank.as_ref().map(|r| r.backend.clone());
    let rerank_http = rerank.as_ref().map(|r| r.http.clone());
    let storage_enabled = storage.enabled && credentials.is_some();
    let services_metadata = if oidc.is_none() {
        crate::discovery::services_discovery_router(
            server.public_url(),
            embeddings_http.as_ref(),
            rerank_http.as_ref(),
            storage_enabled,
        )
    } else {
        Router::new()
    };
    let startup = Instant::now()
        .checked_add(startup_timeout)
        .ok_or(ServerError::Configuration)?;
    // Every started owner uses this startup Original.
    let local_password = match local_password {
        Some(prepared) => match prepared.start(startup).await {
            Ok(owner) => Some(owner),
            Err(_) => {
                if let Some(backend) = embeddings_backend.as_ref() {
                    backend.stop();
                }
                if let Some(backend) = rerank_backend.as_ref() {
                    backend.stop();
                }
                return Err(ServerError::Configuration);
            }
        },
        None => None,
    };
    let local_login = match local_login {
        Some(prepared) => {
            let engine = local_password.as_ref().ok_or(ServerError::Configuration)?;
            match prepared.start(engine.clone(), &database) {
                Ok(local) => Some(local),
                Err(error) => {
                    engine.close().await;
                    if let Some(backend) = embeddings_backend.as_ref() {
                        backend.stop();
                    }
                    if let Some(backend) = rerank_backend.as_ref() {
                        backend.stop();
                    }
                    return Err(error);
                }
            }
        }
        None => None,
    };
    let opened = match database {
        PreparedDatabase::Postgres(database) => {
            PostgresControlStore::open(*database, digester, startup)
                .await
                .map(|store| OwnedDatabase::Postgres(Arc::new(store)))
                .map_err(|_| ServerError::Database)
        }
        PreparedDatabase::Sqlite(database) => SqliteControlStore::open(database, digester, startup)
            .await
            .map(|store| OwnedDatabase::Sqlite(Arc::new(store)))
            .map_err(ServerError::SqliteDatabase),
    };
    let store = match opened {
        Ok(store) => store,
        Err(error) => {
            close_local(local_login.as_ref(), local_password.as_ref()).await;
            if let Some(backend) = embeddings_backend.as_ref() {
                backend.stop();
            }
            if let Some(backend) = rerank_backend.as_ref() {
                backend.stop();
            }
            return Err(error);
        }
    };
    let mut stores = Vec::new();
    for config in configs {
        match FilesystemStore::open(config) {
            Ok(volume) => stores.push(Arc::new(volume)),
            Err(error) => {
                close_partial(
                    &store,
                    server.shutdown_timeout(),
                    local_login.as_ref(),
                    local_password.as_ref(),
                )
                .await;
                if let Some(backend) = embeddings_backend.as_ref() {
                    backend.stop();
                }
                if let Some(backend) = rerank_backend.as_ref() {
                    backend.stop();
                }
                return Err(match error {
                    FilesystemStoreError::Io(error) => ServerError::StorageIo {
                        kind: error.kind(),
                        code: error.raw_os_error(),
                    },
                    _ => ServerError::Storage,
                });
            }
        }
    }
    let realtime_runtime = match presence.as_ref() {
        Some(config) => {
            match RealtimeServerRuntime::new(config.heartbeat_timeout, config.broadcast_capacity) {
                Ok(runtime) => Some(runtime),
                Err(_) => {
                    close_partial(
                        &store,
                        server.shutdown_timeout(),
                        local_login.as_ref(),
                        local_password.as_ref(),
                    )
                    .await;
                    if let Some(backend) = embeddings_backend.as_ref() {
                        backend.stop();
                    }
                    if let Some(backend) = rerank_backend.as_ref() {
                        backend.stop();
                    }
                    return Err(ServerError::Configuration);
                }
            }
        }
        None => None,
    };
    let prepared = (|| {
        let gateways = match &credentials {
            Some(service) => service
                .filesystem_gateways(
                    stores.clone(),
                    FilesystemGatewayConfig {
                        request_timeout: storage.request_timeout(),
                        request_head_bytes: storage.head_bytes,
                    },
                )
                .map_err(|_| ServerError::Storage)?,
            None => Vec::new(),
        };
        let filesystem = FilesystemStorageHttp::new(
            gateways.into_iter().map(Arc::new).collect(),
            storage.request_timeout(),
        )
        .map_err(|_| ServerError::Storage)?;
        let catalog_router = match &credentials {
            Some(service) => match &store {
                OwnedDatabase::Postgres(store) => broker_presence::hub_catalog_router(
                    store.clone(),
                    verifier.clone(),
                    Arc::new(broker_storage::HubCatalogReader::new(
                        service.clone(),
                        stores.clone(),
                        server.body_bytes(),
                    )),
                    broker_presence::HubCatalogHttpConfig {
                        audience: audience.clone(),
                        identity_json_bytes: storage.identity_json_bytes,
                        grants_json_bytes: storage.grants_json_bytes,
                        default_route: default_route.clone(),
                        query_bytes: storage.head_bytes,
                        request_timeout: storage.request_timeout(),
                    },
                )
                .map_err(|_| ServerError::Configuration),
                OwnedDatabase::Sqlite(store) => broker_presence::sqlite_hub_catalog_router(
                    store.clone(),
                    verifier.clone(),
                    Arc::new(broker_storage::HubCatalogReader::new(
                        service.clone(),
                        stores.clone(),
                        server.body_bytes(),
                    )),
                    broker_presence::HubCatalogHttpConfig {
                        audience: audience.clone(),
                        identity_json_bytes: storage.identity_json_bytes,
                        grants_json_bytes: storage.grants_json_bytes,
                        default_route: default_route.clone(),
                        query_bytes: storage.head_bytes,
                        request_timeout: storage.request_timeout(),
                    },
                )
                .map_err(|_| ServerError::Configuration),
            }?,
            None => Router::new(),
        };
        let credentials_router = match &store {
            OwnedDatabase::Postgres(store) => storage_credentials_router(
                store.clone(),
                verifier.clone(),
                credentials,
                BrokerStorageCredentialsHttpConfig {
                    required_scopes: storage.required_scopes(),
                    grants_json_bytes: storage.grants_json_bytes,
                    default_route: default_route.clone(),
                    body_bytes: server.body_bytes(),
                    request_timeout: storage.request_timeout(),
                    enabled: storage.enabled,
                },
                LocalStorageCredentialsHttpConfig {
                    required_scopes: storage.required_scopes(),
                    audience: audience.clone(),
                    identity_json_bytes: storage.identity_json_bytes,
                    grants_json_bytes: storage.grants_json_bytes,
                    default_route,
                    body_bytes: server.body_bytes(),
                    request_timeout: storage.request_timeout(),
                    enabled: storage.enabled,
                },
            )
            .map_err(|_| ServerError::Configuration),
            OwnedDatabase::Sqlite(store) => broker_presence::sqlite_storage_credentials_router(
                store.clone(),
                verifier.clone(),
                credentials,
                BrokerStorageCredentialsHttpConfig {
                    required_scopes: storage.required_scopes(),
                    grants_json_bytes: storage.grants_json_bytes,
                    default_route: default_route.clone(),
                    body_bytes: server.body_bytes(),
                    request_timeout: storage.request_timeout(),
                    enabled: storage.enabled,
                },
                LocalStorageCredentialsHttpConfig {
                    required_scopes: storage.required_scopes(),
                    audience: audience.clone(),
                    identity_json_bytes: storage.identity_json_bytes,
                    grants_json_bytes: storage.grants_json_bytes,
                    default_route,
                    body_bytes: server.body_bytes(),
                    request_timeout: storage.request_timeout(),
                    enabled: storage.enabled,
                },
            )
            .map_err(|_| ServerError::Configuration),
        }?;
        let upstream_login = match &store {
            OwnedDatabase::Postgres(store) => upstream_login_router(
                store.clone(),
                upstream.clone(),
                UpstreamLoginHttpConfig {
                    input_bytes: server.body_bytes(),
                    cookie_secure: upstream_cookie_secure,
                    administration: administration.as_ref().map(|config| {
                        AdminUpstreamLoginHttpConfig {
                            response_json_bytes: config.read_limits.response_json_bytes,
                            request_timeout: config.http.request_timeout,
                            cookie: config.cookie,
                        }
                    }),
                    oidc: oidc.as_ref().map(|config| OidcUpstreamLoginHttpConfig {
                        authorization: config.authorization.clone(),
                        request_timeout: config.request_timeout,
                    }),
                },
            )
            .map_err(|_| ServerError::Configuration),
            OwnedDatabase::Sqlite(store) => broker_presence::sqlite_upstream_login_router(
                store.clone(),
                upstream.clone(),
                UpstreamLoginHttpConfig {
                    input_bytes: server.body_bytes(),
                    cookie_secure: upstream_cookie_secure,
                    administration: administration.as_ref().map(|config| {
                        AdminUpstreamLoginHttpConfig {
                            response_json_bytes: config.read_limits.response_json_bytes,
                            request_timeout: config.http.request_timeout,
                            cookie: config.cookie,
                        }
                    }),
                    oidc: oidc.as_ref().map(|config| OidcUpstreamLoginHttpConfig {
                        authorization: config.authorization.clone(),
                        request_timeout: config.request_timeout,
                    }),
                },
            )
            .map_err(|_| ServerError::Configuration),
        }?;
        let token_router = match oidc {
            Some(config) => {
                let device_available = local_login.is_some();
                let device = match &store {
                    OwnedDatabase::Postgres(store) => broker_presence::oidc_device_router(
                        store.clone(),
                        broker_presence::OidcDeviceHttpConfig {
                            authorization: config.authorization.clone(),
                            policy: config.device.clone(),
                            issuer: config.issuer.clone(),
                            verification_uri: config
                                .device_verification_uri
                                .as_str()
                                .parse()
                                .map_err(|_| ServerError::Configuration)?,
                            body_bytes: config.body_bytes,
                            request_timeout: config.request_timeout,
                        },
                        match local_login.as_ref() {
                            Some(OwnedLocalLogin::Postgres(owner)) => Some(owner.clone()),
                            None => None,
                            Some(_) => return Err(ServerError::Configuration),
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => {
                        broker_presence::sqlite_local_oidc_device_router(
                            store.clone(),
                            broker_presence::OidcDeviceHttpConfig {
                                authorization: config.authorization.clone(),
                                policy: config.device.clone(),
                                issuer: config.issuer.clone(),
                                verification_uri: config
                                    .device_verification_uri
                                    .as_str()
                                    .parse()
                                    .map_err(|_| ServerError::Configuration)?,
                                body_bytes: config.body_bytes,
                                request_timeout: config.request_timeout,
                            },
                            match local_login.as_ref() {
                                Some(OwnedLocalLogin::Sqlite(owner)) => Some(owner.clone()),
                                None => None,
                                Some(_) => return Err(ServerError::Configuration),
                            },
                        )
                        .map_err(|_| ServerError::Configuration)
                    }
                }?;
                let browser = match &store {
                    OwnedDatabase::Postgres(store) => oidc_browser_router(
                        store.clone(),
                        OidcBrowserHttpConfig {
                            authorization: config.authorization.clone(),
                            body_bytes: config.body_bytes,
                            request_timeout: config.request_timeout,
                            cookie_secure: upstream_cookie_secure,
                        },
                        match local_login.as_ref() {
                            Some(OwnedLocalLogin::Postgres(owner)) => Some(owner.clone()),
                            None => None,
                            Some(_) => return Err(ServerError::Configuration),
                        },
                        upstream.clone(),
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => match upstream.as_ref() {
                        Some(upstream) => broker_presence::sqlite_oidc_browser_router(
                            store.clone(),
                            OidcBrowserHttpConfig {
                                authorization: config.authorization.clone(),
                                body_bytes: config.body_bytes,
                                request_timeout: config.request_timeout,
                                cookie_secure: upstream_cookie_secure,
                            },
                            match local_login.as_ref() {
                                Some(OwnedLocalLogin::Sqlite(owner)) => Some(owner.clone()),
                                None => None,
                                Some(_) => return Err(ServerError::Configuration),
                            },
                            upstream.clone(),
                        )
                        .map_err(|_| ServerError::Configuration),
                        None => broker_presence::sqlite_local_oidc_browser_router(
                            store.clone(),
                            OidcBrowserHttpConfig {
                                authorization: config.authorization.clone(),
                                body_bytes: config.body_bytes,
                                request_timeout: config.request_timeout,
                                cookie_secure: upstream_cookie_secure,
                            },
                            match local_login.as_ref() {
                                Some(OwnedLocalLogin::Sqlite(owner)) => Some(owner.clone()),
                                None => None,
                                Some(_) => return Err(ServerError::Configuration),
                            },
                        )
                        .map_err(|_| ServerError::Configuration),
                    },
                }?;
                let registration = match &store {
                    OwnedDatabase::Postgres(store) => oidc_registration_router(
                        store.clone(),
                        config.authorization.clone(),
                        config.registration_http,
                    ),
                    OwnedDatabase::Sqlite(store) => {
                        broker_presence::sqlite_oidc_registration_router(
                            store.clone(),
                            config.authorization.clone(),
                            config.registration_http,
                        )
                    }
                };
                let http = match upstream.as_ref() {
                    Some(verifier) => config.http.with_upstream(verifier.clone()),
                    None => config.http,
                };
                let http = if device_available {
                    http.with_device(config.device.clone())
                } else {
                    http
                };
                let introspection = match &store {
                    OwnedDatabase::Postgres(store) => broker_presence::oidc_introspection_router(
                        store.clone(),
                        verifier.clone(),
                        config.authorization.clone(),
                        broker_presence::OidcIntrospectionHttpConfig {
                            request_timeout: config.request_timeout,
                            body_bytes: config.body_bytes,
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => {
                        broker_presence::sqlite_oidc_introspection_router(
                            store.clone(),
                            verifier.clone(),
                            config.authorization.clone(),
                            broker_presence::OidcIntrospectionHttpConfig {
                                request_timeout: config.request_timeout,
                                body_bytes: config.body_bytes,
                            },
                        )
                        .map_err(|_| ServerError::Configuration)
                    }
                }?;
                let userinfo = match &store {
                    OwnedDatabase::Postgres(store) => oidc_userinfo_router(
                        store.clone(),
                        verifier.clone(),
                        config.authorization.clone(),
                        upstream.clone(),
                        OidcUserInfoHttpConfig {
                            request_timeout: config.request_timeout,
                            body_bytes: config.body_bytes,
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => broker_presence::sqlite_oidc_userinfo_router(
                        store.clone(),
                        verifier.clone(),
                        config.authorization.clone(),
                        upstream.clone(),
                        OidcUserInfoHttpConfig {
                            request_timeout: config.request_timeout,
                            body_bytes: config.body_bytes,
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                }?;
                let end_session = match &store {
                    OwnedDatabase::Postgres(store) => broker_presence::oidc_end_session_router(
                        store.clone(),
                        verifier.clone(),
                        config.authorization.clone(),
                        broker_presence::OidcEndSessionHttpConfig {
                            request_timeout: config.request_timeout,
                            body_bytes: config.body_bytes,
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => {
                        broker_presence::sqlite_oidc_end_session_router(
                            store.clone(),
                            verifier.clone(),
                            config.authorization.clone(),
                            broker_presence::OidcEndSessionHttpConfig {
                                request_timeout: config.request_timeout,
                                body_bytes: config.body_bytes,
                            },
                        )
                        .map_err(|_| ServerError::Configuration)
                    }
                }?;
                let revocation = match &store {
                    OwnedDatabase::Postgres(store) => oidc_revocation_router(
                        store.clone(),
                        verifier.clone(),
                        config.authorization.clone(),
                        OidcRevocationHttpConfig {
                            request_timeout: config.request_timeout,
                            body_bytes: config.body_bytes,
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => broker_presence::sqlite_oidc_revocation_router(
                        store.clone(),
                        verifier.clone(),
                        config.authorization.clone(),
                        OidcRevocationHttpConfig {
                            request_timeout: config.request_timeout,
                            body_bytes: config.body_bytes,
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                }?;
                let router = match &store {
                    OwnedDatabase::Postgres(store) => oidc_token_router(
                        store.clone(),
                        config.issuer,
                        config.authorization,
                        config.policy,
                        http,
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => {
                        if upstream.is_some() {
                            broker_presence::sqlite_oidc_token_router(
                                store.clone(),
                                config.issuer,
                                config.authorization,
                                config.policy,
                                http,
                            )
                            .map_err(|_| ServerError::Configuration)
                        } else {
                            broker_presence::sqlite_local_oidc_token_router(
                                store.clone(),
                                config.issuer,
                                config.authorization,
                                config.policy,
                                http,
                            )
                            .map_err(|_| ServerError::Configuration)
                        }
                    }
                }?;
                let mut discovery = config.discovery;
                discovery.storage(storage_enabled);
                if let Some(http) = embeddings_http.as_ref() {
                    discovery.embeddings(http);
                }
                if let Some(http) = rerank_http.as_ref() {
                    discovery.rerank(http);
                }
                discovery.device_authorization_endpoint = device_available
                    .then(|| format!("{}/authorize", config.device_verification_uri));
                let router = router
                    .merge(introspection)
                    .merge(userinfo)
                    .merge(revocation)
                    .merge(end_session)
                    .merge(registration)
                    .merge(browser)
                    .merge(device)
                    .merge(discovery.router());
                match config.cors {
                    Some(layer) => router.layer(layer),
                    None => router,
                }
            }
            None => Router::new(),
        };
        let token_router = token_router.merge(services_metadata);
        let embeddings_router = match embeddings {
            Some(prepared) => match &store {
                OwnedDatabase::Postgres(store) => broker_presence::postgres_embeddings_router(
                    store.clone(),
                    verifier.clone(),
                    upstream.clone(),
                    prepared.http,
                    prepared.backend,
                )
                .map_err(|_| ServerError::Configuration),
                OwnedDatabase::Sqlite(store) => broker_presence::sqlite_embeddings_router(
                    store.clone(),
                    verifier.clone(),
                    upstream.clone(),
                    prepared.http,
                    prepared.backend,
                )
                .map_err(|_| ServerError::Configuration),
            }?,
            None => broker_presence::disabled_embeddings_router(),
        };
        let rerank_router = match rerank {
            Some(prepared) => match &store {
                OwnedDatabase::Postgres(store) => broker_presence::postgres_rerank_router(
                    store.clone(),
                    verifier.clone(),
                    upstream.clone(),
                    prepared.http,
                    prepared.backend,
                ),
                OwnedDatabase::Sqlite(store) => broker_presence::sqlite_rerank_router(
                    store.clone(),
                    verifier.clone(),
                    upstream.clone(),
                    prepared.http,
                    prepared.backend,
                ),
            }
            .map_err(|_| ServerError::Configuration)?,
            None => broker_presence::disabled_rerank_router(),
        };
        let administration_router = match administration {
            Some(config) => {
                let instructions = match config.cookie {
                    Some(cookie) => broker_presence::instruction_overrides_router(
                        match &store {
                            OwnedDatabase::Postgres(store) => {
                                broker_presence::InstructionStore::Postgres(store.clone())
                            }
                            OwnedDatabase::Sqlite(store) => {
                                broker_presence::InstructionStore::Sqlite(store.clone())
                            }
                        },
                        verifier.clone(),
                        upstream.clone(),
                        broker_presence::InstructionHttpConfig {
                            file: instruction_overrides_file,
                            timeout: config.http.request_timeout,
                            audience: audience.clone(),
                            identity_json_bytes: config.http.limits.profile_json_bytes,
                            cookie,
                        },
                    ),
                    None => Router::new(),
                };
                let reads = match &store {
                    OwnedDatabase::Postgres(store) => admin_read_router(
                        store.clone(),
                        verifier.clone(),
                        config.http,
                        broker_presence::AdminReadHttpConfig {
                            limits: config.read_limits,
                            provider_command: config.provider_command,
                            configuration_yaml: configuration_yaml
                                .ok_or(ServerError::Configuration)?,
                        },
                        config.local_bearer.clone(),
                        upstream.clone(),
                        config.cookie,
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => broker_presence::sqlite_admin_read_router(
                        store.clone(),
                        verifier.clone(),
                        config.http,
                        broker_presence::AdminReadHttpConfig {
                            limits: config.read_limits,
                            provider_command: config.provider_command,
                            configuration_yaml: configuration_yaml
                                .ok_or(ServerError::Configuration)?,
                        },
                        config.local_bearer.clone(),
                        upstream.clone(),
                        config.cookie,
                    )
                    .map_err(|_| ServerError::Configuration),
                }?;
                let rbac = match &store {
                    OwnedDatabase::Postgres(store) => broker_presence::admin_rbac_router(
                        store.clone(),
                        verifier.clone(),
                        config.http,
                        server.body_bytes(),
                        config.local_bearer.clone(),
                        upstream.clone(),
                        config.cookie,
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => broker_presence::sqlite_admin_rbac_router(
                        store.clone(),
                        verifier.clone(),
                        config.http,
                        server.body_bytes(),
                        config.local_bearer.clone(),
                        upstream.clone(),
                        config.cookie,
                    )
                    .map_err(|_| ServerError::Configuration),
                }?;
                let grants = match &store {
                    OwnedDatabase::Postgres(store) => broker_presence::admin_grants_router(
                        store.clone(),
                        verifier.clone(),
                        broker_presence::AdminGrantsHttpConfig {
                            session: config.http,
                            body_bytes: server.body_bytes(),
                            grants_json_bytes: config.read_limits.grants_json_bytes,
                            response_json_bytes: config.read_limits.response_json_bytes,
                            local: config.local_bearer.clone(),
                            upstream: upstream.clone(),
                            cookie: config.cookie,
                            routes: grant_routes,
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => broker_presence::sqlite_admin_grants_router(
                        store.clone(),
                        verifier.clone(),
                        broker_presence::AdminGrantsHttpConfig {
                            session: config.http,
                            body_bytes: server.body_bytes(),
                            grants_json_bytes: config.read_limits.grants_json_bytes,
                            response_json_bytes: config.read_limits.response_json_bytes,
                            local: config.local_bearer.clone(),
                            upstream: upstream.clone(),
                            cookie: config.cookie,
                            routes: grant_routes,
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                }?;
                let users = match &store {
                    OwnedDatabase::Postgres(store) => broker_presence::admin_users_router(
                        store.clone(),
                        verifier.clone(),
                        local_password
                            .as_ref()
                            .ok_or(ServerError::Configuration)?
                            .clone(),
                        broker_presence::AdminUsersHttpConfig {
                            session: config.http,
                            body_bytes: server.body_bytes(),
                            response_json_bytes: config.read_limits.response_json_bytes,
                            local: config.local_bearer.clone(),
                            upstream: upstream.clone(),
                            cookie: config.cookie,
                            service_credential_audience: audience,
                            service_credential_max_ttl,
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => broker_presence::sqlite_admin_users_router(
                        store.clone(),
                        verifier.clone(),
                        local_password
                            .as_ref()
                            .ok_or(ServerError::Configuration)?
                            .clone(),
                        broker_presence::AdminUsersHttpConfig {
                            session: config.http,
                            body_bytes: server.body_bytes(),
                            response_json_bytes: config.read_limits.response_json_bytes,
                            local: config.local_bearer.clone(),
                            upstream: upstream.clone(),
                            cookie: config.cookie,
                            service_credential_audience: audience,
                            service_credential_max_ttl,
                        },
                    )
                    .map_err(|_| ServerError::Configuration),
                }?;
                let session = match &store {
                    OwnedDatabase::Postgres(store) => admin_session_router_with_cookie(
                        store.clone(),
                        verifier.clone(),
                        config.http,
                        config.local_bearer,
                        upstream.clone(),
                        config.cookie,
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => {
                        broker_presence::sqlite_admin_session_router_with_cookie(
                            store.clone(),
                            verifier.clone(),
                            config.http,
                            config.local_bearer,
                            upstream.clone(),
                            config.cookie,
                        )
                        .map_err(|_| ServerError::Configuration)
                    }
                }?;
                let login = match &store {
                    OwnedDatabase::Postgres(store) => admin_local_login_router(
                        store.clone(),
                        AdminLocalLoginHttpConfig {
                            body_bytes: server.body_bytes(),
                            response_json_bytes: config.read_limits.response_json_bytes,
                            request_timeout: config.http.request_timeout,
                            cookie: config.cookie,
                        },
                        if config.cookie.is_some() {
                            match local_login.as_ref() {
                                Some(OwnedLocalLogin::Postgres(owner)) => Some(owner.clone()),
                                None => None,
                                Some(_) => return Err(ServerError::Configuration),
                            }
                        } else {
                            None
                        },
                        upstream.clone(),
                    )
                    .map_err(|_| ServerError::Configuration),
                    OwnedDatabase::Sqlite(store) => {
                        broker_presence::sqlite_admin_local_login_router_with_upstream(
                            store.clone(),
                            AdminLocalLoginHttpConfig {
                                body_bytes: server.body_bytes(),
                                response_json_bytes: config.read_limits.response_json_bytes,
                                request_timeout: config.http.request_timeout,
                                cookie: config.cookie,
                            },
                            if config.cookie.is_some() {
                                match local_login.as_ref() {
                                    Some(OwnedLocalLogin::Sqlite(owner)) => Some(owner.clone()),
                                    None => None,
                                    Some(_) => return Err(ServerError::Configuration),
                                }
                            } else {
                                None
                            },
                            upstream.clone(),
                        )
                        .map_err(|_| ServerError::Configuration)
                    }
                }?;
                session
                    .merge(login)
                    .merge(reads)
                    .merge(rbac)
                    .merge(grants)
                    .merge(users)
                    .merge(instructions)
            }
            None => Router::new(),
        };
        let project_router = match project_access {
            Some(config) => match &store {
                OwnedDatabase::Postgres(store) => {
                    broker_project_authorization_router(store.clone(), verifier.clone(), config)
                        .map_err(|_| ServerError::Configuration)
                }
                OwnedDatabase::Sqlite(store) => {
                    broker_presence::sqlite_broker_project_authorization_router(
                        store.clone(),
                        verifier.clone(),
                        config,
                    )
                    .map_err(|_| ServerError::Configuration)
                }
            }?
            .reset_fallback(),
            None => Router::new(),
        };
        let project_router = project_router.merge(embeddings_router).merge(rerank_router);
        let (inventory_router, realtime_router) = match presence {
            Some(config) => {
                let runtime = realtime_runtime
                    .as_ref()
                    .ok_or(ServerError::Configuration)?;
                let (inventory, realtime) = match config.authentication {
                    PreparedPresenceAuthentication::BrokerJwt => (
                        match &store {
                            OwnedDatabase::Postgres(store) => broker_instance_inventory_router(
                                store.clone(),
                                verifier.clone(),
                                config.publish,
                                config.read,
                            )
                            .map_err(|_| ServerError::Configuration),
                            OwnedDatabase::Sqlite(store) => {
                                broker_presence::sqlite_broker_instance_inventory_router(
                                    store.clone(),
                                    verifier.clone(),
                                    config.publish,
                                    config.read,
                                )
                                .map_err(|_| ServerError::Configuration)
                            }
                        }?,
                        match &store {
                            OwnedDatabase::Postgres(store) => broker_realtime_router(
                                store.clone(),
                                verifier,
                                config.realtime,
                                runtime,
                            )
                            .map_err(|_| ServerError::Configuration),
                            OwnedDatabase::Sqlite(store) => {
                                broker_presence::sqlite_broker_realtime_router(
                                    store.clone(),
                                    verifier,
                                    config.realtime,
                                    runtime,
                                )
                                .map_err(|_| ServerError::Configuration)
                            }
                        }?,
                    ),
                    PreparedPresenceAuthentication::LocalOpaque {
                        audience,
                        identity_json_bytes,
                        list,
                    } => (
                        match &store {
                            OwnedDatabase::Postgres(store) => instance_inventory_router(
                                store.clone(),
                                InstanceRegistryHttpConfig {
                                    audience: audience.clone(),
                                    identity_json_bytes,
                                    required_scopes: config.publish.required_scopes,
                                    grants_json_bytes: config.publish.grants_json_bytes,
                                    body_bytes: config.publish.body_bytes,
                                    request_timeout: config.publish.request_timeout,
                                },
                                InstanceInventoryReadHttpConfig {
                                    audience: audience.clone(),
                                    identity_json_bytes,
                                    required_scopes: config.read.required_scopes,
                                    grants_json_bytes: config.read.grants_json_bytes,
                                    inventory_json_bytes: config.read.inventory_json_bytes,
                                    request_timeout: config.read.request_timeout,
                                },
                                list,
                            )
                            .map_err(|_| ServerError::Configuration),
                            OwnedDatabase::Sqlite(store) => {
                                broker_presence::sqlite_instance_inventory_router(
                                    store.clone(),
                                    InstanceRegistryHttpConfig {
                                        audience: audience.clone(),
                                        identity_json_bytes,
                                        required_scopes: config.publish.required_scopes,
                                        grants_json_bytes: config.publish.grants_json_bytes,
                                        body_bytes: config.publish.body_bytes,
                                        request_timeout: config.publish.request_timeout,
                                    },
                                    InstanceInventoryReadHttpConfig {
                                        audience: audience.clone(),
                                        identity_json_bytes,
                                        required_scopes: config.read.required_scopes,
                                        grants_json_bytes: config.read.grants_json_bytes,
                                        inventory_json_bytes: config.read.inventory_json_bytes,
                                        request_timeout: config.read.request_timeout,
                                    },
                                    list,
                                )
                                .map_err(|_| ServerError::Configuration)
                            }
                        }?,
                        match &store {
                            OwnedDatabase::Postgres(store) => local_realtime_router(
                                store.clone(),
                                LocalRealtimeHttpConfig {
                                    audience,
                                    identity_json_bytes,
                                    realtime: config.realtime,
                                },
                                runtime,
                            )
                            .map_err(|_| ServerError::Configuration),
                            OwnedDatabase::Sqlite(store) => {
                                broker_presence::sqlite_local_realtime_router(
                                    store.clone(),
                                    LocalRealtimeHttpConfig {
                                        audience,
                                        identity_json_bytes,
                                        realtime: config.realtime,
                                    },
                                    runtime,
                                )
                                .map_err(|_| ServerError::Configuration)
                            }
                        }?,
                    ),
                };
                (inventory.reset_fallback(), realtime)
            }
            None => (Router::new(), Router::new()),
        };
        Ok::<_, ServerError>((
            filesystem,
            credentials_router.merge(catalog_router.reset_fallback()),
            token_router,
            administration_router.merge(upstream_login),
            project_router,
            inventory_router,
            realtime_router,
        ))
    })();
    let (
        filesystem,
        credentials_router,
        token_router,
        administration_router,
        project_router,
        inventory_router,
        realtime_router,
    ) = match prepared {
        Ok(value) => value,
        Err(error) => {
            if let Some(backend) = embeddings_backend.as_ref() {
                backend.stop();
            }
            if let Some(backend) = rerank_backend.as_ref() {
                backend.stop();
            }
            close_partial_presence(
                &store,
                realtime_runtime,
                server.shutdown_timeout(),
                local_login.as_ref(),
                local_password.as_ref(),
            )
            .await;
            return Err(error);
        }
    };
    let ready = Arc::new(AtomicBool::new(false));
    let ready_route = ready.clone();
    let router = Router::new()
        .route(
            "/favicon.svg",
            get(|| async {
                (
                    [
                        ("content-type", "image/svg+xml; charset=utf-8"),
                        ("cache-control", "public, max-age=31536000, immutable"),
                        ("x-content-type-options", "nosniff"),
                    ],
                    include_bytes!("../assets/favicon.svg").as_slice(),
                )
            }),
        )
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({"status":"ok"})) }),
        )
        .route(
            "/readyz",
            get(move || {
                let ready = ready_route.clone();
                async move {
                    if ready.load(Ordering::Acquire) {
                        (StatusCode::OK, Json(serde_json::json!({"status":"ready"})))
                    } else {
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(serde_json::json!({"status":"not_ready"})),
                        )
                    }
                }
            }),
        )
        .route(
            "/v1/oidc/keys",
            get(move || {
                let keys = jwks.clone();
                async move { Json(keys) }
            }),
        )
        .merge(credentials_router)
        .merge(token_router)
        .merge(administration_router)
        .merge(project_router)
        .merge(inventory_router)
        .merge(realtime_router)
        .merge(filesystem.router())
        .layer(RequestBodyTimeoutLayer::new(server.read_timeout()))
        .layer(ResponseBodyTimeoutLayer::new(server.write_timeout()));
    let listener =
        match tokio::time::timeout_at(startup.into(), TcpListener::bind(server.address)).await {
            Ok(Ok(listener)) if Instant::now() < startup => listener,
            result => {
                let error = if matches!(result, Ok(Err(_))) {
                    ServerError::Bind
                } else {
                    ServerError::Startup
                };
                if let Some(backend) = embeddings_backend.as_ref() {
                    backend.stop();
                }
                if let Some(backend) = rerank_backend.as_ref() {
                    backend.stop();
                }
                let end = Instant::now()
                    .checked_add(server.shutdown_timeout())
                    .ok_or(ServerError::Configuration)?;
                let _ = filesystem.shutdown(end).await;
                let _ = filesystem.join_closed().await;
                let _ = shutdown_realtime(realtime_runtime, end).await;
                close_local(local_login.as_ref(), local_password.as_ref()).await;
                let _ = store.shutdown(end).await;
                return Err(error);
            }
        };
    let (http_stop, http_stopped) = watch::channel(false);
    let mut connections = JoinSet::new();
    ready.store(true, Ordering::Release);
    tokio::pin!(shutdown);
    let outcome = loop {
        tokio::select! {
            result=&mut shutdown => break result,
            accepted=listener.accept() => {
                let (socket,_) = match accepted {Ok(value)=>value,Err(_)=>break Err(ServerError::Listener)};
                let mut io=TimeoutStream::new(socket);
                io.set_read_timeout(Some(server.idle_timeout()));
                io.set_write_timeout(Some(server.write_timeout()));
                let io=TokioIo::new(Box::pin(io));
                let mut builder=http1::Builder::new();
                builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5));
                let connection=builder.serve_connection(io,TowerToHyperService::new(router.clone())).with_upgrades();
                // Subscribe before spawning so shutdown reaches a just accepted connection.
                let mut stopped=http_stopped.clone();
                connections.spawn(async move {
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = stopped.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
        }
    };
    ready.store(false, Ordering::Release);
    drop(listener);
    drop(router);
    let end = Instant::now()
        .checked_add(server.shutdown_timeout())
        .ok_or(ServerError::Configuration)?;
    if let Some(backend) = embeddings_backend.as_ref() {
        backend.stop();
    }
    if let Some(backend) = rerank_backend.as_ref() {
        backend.stop();
    }
    if let Some(local) = &local_login {
        local.stop_admission();
    }
    let _ = http_stop.send(true);
    drop(http_stop);
    drop(http_stopped);
    let (fs_result, http_result, realtime_result) = tokio::join!(
        filesystem.shutdown(end),
        tokio::time::timeout_at(end.into(), async {
            while connections.join_next().await.is_some() {}
        }),
        shutdown_realtime(realtime_runtime, end),
    );
    if http_result.is_err() {
        connections.abort_all();
    }
    while connections.join_next().await.is_some() {}
    let fs_join = filesystem.join_closed().await;
    close_local(local_login.as_ref(), local_password.as_ref()).await;
    let db_result = store.shutdown(end).await;
    drop(filesystem);
    drop(store);
    drop(stores);
    if fs_result.is_err()
        || fs_join.is_err()
        || http_result.is_err()
        || realtime_result.is_err()
        || db_result.is_err()
    {
        return Err(ServerError::Shutdown);
    }
    outcome
}
