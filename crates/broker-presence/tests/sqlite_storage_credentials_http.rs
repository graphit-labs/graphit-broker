#[path = "../../broker-control/tests/support/sqlite_storage_admission_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared physical fixtures serve independent SQL and HTTP targets"
)]
mod fixture;
use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use broker_control::{StorageModule, StorageScope};
use broker_presence::{
    BrokerStorageCredentialsHttpConfig, FilesystemStorageHttp, LocalStorageCredentialsHttpConfig,
    sqlite_broker_storage_credentials_router, sqlite_local_storage_credentials_router,
    sqlite_storage_credentials_router,
};
use broker_storage::{
    FilesystemGatewayConfig, FilesystemStorageIssuer, FilesystemStorageRoute,
    FilesystemStorageRouteConfig, FilesystemStore, FilesystemStoreConfig,
    StorageCredentialsService, StorageIssuer,
};
use fixture::*;
use http_body_util::BodyExt;
use hyper::body::Body as _;
use hyper_util::rt::TokioIo;
use object_store::{
    ObjectStoreExt,
    aws::{AmazonS3, AmazonS3Builder, S3ConditionalPut},
    path::Path as ObjectPath,
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
use zeroize::Zeroizing;

struct Server {
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl Server {
    async fn start(router: Router) -> Self {
        Self::listener(TcpListener::bind("127.0.0.1:0").await.unwrap(), router).await
    }
    async fn listener(listener: TcpListener, router: Router) -> Self {
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            address,
            stop: Some(stop),
            task: Some(task),
        }
    }
    async fn close(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(5), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
struct Reply {
    status: StatusCode,
    data: Value,
    challenge: Option<String>,
}
impl Reply {
    fn error(self, status: u16, code: &str) {
        assert_eq!(
            self.status.as_u16(),
            status,
            "actual finite code {}",
            self.data["error"]["code"].as_str().unwrap_or("[non-error]")
        );
        assert!(
            self.data == json!({"error":{"code":code}}),
            "finite error shape"
        );
        let challenge = if status == 401 {
            Some("Bearer")
        } else if code == "insufficient_scope" {
            Some("Bearer error=\"insufficient_scope\"")
        } else {
            None
        };
        assert_eq!(self.challenge.as_deref(), challenge);
    }
    fn credentials(self, scope: &StorageScope, revision: i64) -> Value {
        assert_eq!(self.status, StatusCode::OK);
        assert!(self.challenge.is_none());
        let object = self.data.as_object().unwrap();
        let mut fields = vec![
            "access_key_id",
            "secret_access_key",
            "session_token",
            "expires_at",
            "bucket",
            "region",
            "endpoint",
            "conditional_delete",
            "copy_if_not_exists",
            "prefixes",
            "authorization_revision",
            "scope",
            "project_id",
            "module",
        ];
        if scope.installation_id().is_some() {
            fields.push("installation_id");
        }
        let actual = object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, fields.into_iter().collect());
        for key in [
            "access_key_id",
            "secret_access_key",
            "session_token",
            "expires_at",
            "bucket",
            "region",
            "endpoint",
        ] {
            assert!(!self.data[key].as_str().unwrap().is_empty());
        }
        assert_eq!(self.data["authorization_revision"], revision.to_string());
        assert_eq!(self.data["conditional_delete"], true);
        assert_eq!(self.data["copy_if_not_exists"], "if_none_match");
        let expires =
            chrono::DateTime::parse_from_rfc3339(self.data["expires_at"].as_str().unwrap())
                .unwrap()
                .timestamp();
        assert!(
            expires > i64::try_from(seconds() + 850).unwrap(),
            "issuer TTL is independent of bearer expiry"
        );
        assert_eq!(self.data["bucket"], "private-bucket");
        assert_eq!(self.data["region"], "us-east-1");
        assert_eq!(self.data["prefixes"], json!(["tenant"]));
        assert_eq!(self.data["module"], scope.module().as_str());
        assert_eq!(self.data["project_id"], scope.project_id().unwrap_or(""));
        if let Some(installation) = scope.installation_id() {
            assert_eq!(self.data["scope"], "user");
            assert_eq!(self.data["installation_id"], installation);
        } else {
            assert!(object.get("installation_id").is_none());
            assert_eq!(
                self.data["scope"],
                if scope.project_id().is_some() {
                    "project"
                } else {
                    "hub"
                }
            );
        }
        self.data
    }
}
async fn post(address: SocketAddr, auth: &[&str], body: Body) -> Reply {
    let streaming = body.size_hint().exact().is_none();
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/s3/credentials")
        .header(header::HOST, address.to_string())
        .header(header::CONTENT_TYPE, "application/json");
    for value in auth {
        request = request.header(header::AUTHORIZATION, *value);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(8),
        sender.send_request(request.body(body).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = tokio::time::timeout(Duration::from_secs(3), response.into_body().collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    let wire = Zeroizing::new(bytes.to_vec());
    let data = serde_json::from_slice(&wire).unwrap();
    drop(sender);
    let result = tokio::time::timeout(Duration::from_secs(3), driver)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = result {
        assert!(
            streaming
                && matches!(
                    status,
                    StatusCode::UNAUTHORIZED
                        | StatusCode::FORBIDDEN
                        | StatusCode::NOT_FOUND
                        | StatusCode::PAYLOAD_TOO_LARGE
                        | StatusCode::GATEWAY_TIMEOUT
                )
                && error.is_incomplete_message(),
            "unexpected HTTP driver result"
        );
    }
    Reply {
        status,
        data,
        challenge,
    }
}
fn body(scope: &StorageScope) -> Body {
    Body::from(
        if let Some(project) = scope.project_id() {
            json!({"scope":"project","project_id":project,"module":scope.module().as_str()})
        } else if let Some(installation) = scope.installation_id() {
            json!({"scope":"user","module":"memory","installation_id":installation})
        } else {
            json!({"scope":"hub","module":"hub"})
        }
        .to_string(),
    )
}
fn native_config(enabled: bool) -> BrokerStorageCredentialsHttpConfig {
    BrokerStorageCredentialsHttpConfig {
        required_scopes: vec!["storage".into()],
        grants_json_bytes: n(65536),
        default_route: if enabled {
            "configured".into()
        } else {
            String::new()
        },
        body_bytes: n(1024),
        request_timeout: Duration::from_secs(5),
        enabled,
    }
}
fn local_config(enabled: bool) -> LocalStorageCredentialsHttpConfig {
    LocalStorageCredentialsHttpConfig {
        required_scopes: vec!["storage".into()],
        audience: if enabled {
            AUDIENCE.into()
        } else {
            String::new()
        },
        identity_json_bytes: n(8192),
        grants_json_bytes: n(65536),
        default_route: if enabled {
            "configured".into()
        } else {
            String::new()
        },
        body_bytes: n(1024),
        request_timeout: Duration::from_secs(5),
        enabled,
    }
}
fn issuer(endpoint: &str) -> StorageCredentialsService {
    StorageCredentialsService::new(vec![StorageIssuer::Filesystem(
        FilesystemStorageIssuer::new(
            vec![
                FilesystemStorageRoute::new(FilesystemStorageRouteConfig {
                    name: "configured".into(),
                    bucket: "private-bucket".into(),
                    region: "us-east-1".into(),
                    base_prefix: "tenant".into(),
                    endpoint: endpoint.into(),
                    session_duration: Duration::from_secs(900),
                    token_bytes: n(65536),
                })
                .unwrap(),
            ],
            Zeroizing::new(vec![31; 32]),
        )
        .unwrap(),
    )])
    .unwrap()
}
fn objects(keys: &Value) -> AmazonS3 {
    AmazonS3Builder::new()
        .with_bucket_name(keys["bucket"].as_str().unwrap())
        .with_region(keys["region"].as_str().unwrap())
        .with_endpoint(keys["endpoint"].as_str().unwrap())
        .with_virtual_hosted_style_request(false)
        .with_access_key_id(keys["access_key_id"].as_str().unwrap())
        .with_secret_access_key(keys["secret_access_key"].as_str().unwrap())
        .with_token(keys["session_token"].as_str().unwrap())
        .with_conditional_put(S3ConditionalPut::ETagMatch)
        .with_client_options(
            object_store::ClientOptions::new()
                .with_allow_http(true)
                .with_pool_max_idle_per_host(0)
                .with_timeout(Duration::from_secs(3))
                .with_connect_timeout(Duration::from_secs(2)),
        )
        .with_retry(object_store::RetryConfig {
            max_retries: 0,
            retry_timeout: Duration::from_secs(3),
            ..Default::default()
        })
        .build()
        .unwrap()
}
async fn gateway(
    service: &StorageCredentialsService,
    directory: &std::path::Path,
) -> (FilesystemStorageHttp, Arc<FilesystemStore>) {
    let disk = Arc::new(
        FilesystemStore::open(FilesystemStoreConfig {
            directory: directory.into(),
            bucket: "private-bucket".into(),
            max_object_bytes: NonZeroU64::new(1024 * 1024).unwrap(),
            metadata_bytes: n(8192),
        })
        .unwrap(),
    );
    let gateways = service
        .filesystem_gateways(
            vec![disk.clone()],
            FilesystemGatewayConfig {
                request_timeout: Duration::from_secs(2),
                request_head_bytes: n(70000),
            },
        )
        .unwrap();
    (
        FilesystemStorageHttp::new(
            gateways.into_iter().map(Arc::new).collect(),
            Duration::from_secs(3),
        )
        .unwrap(),
        disk,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real TCP mixed SQLite admission and mature Filesystem credentials/S3 gateway"]
async fn sqlite_storage_credentials_real_issuer_seven_scopes_and_fresh_acl() {
    let f = Fixture::new().await;
    f.grant("all", &Rule::all());
    let raw = f.signer.sign(&f.signer.claims());
    let bearer = Zeroizing::new(format!("Bearer {}", raw.as_str()));
    let access = Zeroizing::new(format!("Bearer {}", f.access.as_str()));
    let service = Zeroizing::new(format!("Bearer {}", f.service.as_str()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let issuer = Arc::new(issuer(&endpoint));
    let volume = tempfile::tempdir().unwrap();
    let (s3, disk) = gateway(&issuer, volume.path()).await;
    let verifier = Arc::new(f.signer.verifier());
    let router = sqlite_storage_credentials_router(
        f.store.clone(),
        verifier.clone(),
        Some(issuer.clone()),
        native_config(true),
        local_config(true),
    )
    .unwrap()
    .merge(s3.router());
    let server = Server::listener(listener, router).await;
    let all_scopes = scopes();
    let mut retained = None;
    for (kind, raw) in [
        (&bearer, None),
        (&access, Some(f.access.as_str())),
        (&service, Some(f.service.as_str())),
    ]
    .into_iter()
    .enumerate()
    {
        let (authorization, opaque_raw) = raw;
        for (index, scope) in all_scopes.iter().enumerate() {
            let roots = if let Some(opaque_raw) = opaque_raw {
                opaque(&f, opaque_raw, scope).await.unwrap().access[0].clone()
            } else {
                native(&f, raw_token(&bearer), scope).await.unwrap().access[0].clone()
            };
            let keys = post(server.address, &[authorization.as_str()], body(scope))
                .await
                .credentials(scope, f.revision());
            let client = objects(&keys);
            let object = ObjectPath::from(format!("tenant/{}/probe-{kind}-{index}", roots[0]));
            client
                .put(&object, Bytes::from_static(b"sqlite-real-issuer").into())
                .await
                .unwrap();
            assert_eq!(
                client.get(&object).await.unwrap().bytes().await.unwrap(),
                Bytes::from_static(b"sqlite-real-issuer")
            );
            assert!(
                client
                    .put(
                        &ObjectPath::from(format!("tenant/v1/projects/{B}/corpora/task/outside")),
                        Bytes::from_static(b"denied").into()
                    )
                    .await
                    .is_err()
            );
            if kind == 0 && scope.module() == StorageModule::Task {
                retained = Some((keys, object));
            }
        }
    }
    let (task_keys, object) = retained.unwrap();
    let task_scope = StorageScope::project(A, StorageModule::Task).unwrap();
    f.clear();
    f.grant(
        "read-only",
        &Rule {
            caps: &["s3:read"],
            operations: &["read"],
            ..Rule::all()
        },
    );
    let read_only = post(server.address, &[&bearer], body(&task_scope))
        .await
        .credentials(&task_scope, f.revision());
    let reader = objects(&read_only);
    assert_eq!(
        reader.get(&object).await.unwrap().bytes().await.unwrap(),
        Bytes::from_static(b"sqlite-real-issuer")
    );
    assert!(
        reader
            .put(&object, Bytes::from_static(b"denied").into())
            .await
            .is_err()
    );
    f.clear();
    post(server.address, &[&bearer], body(&task_scope))
        .await
        .error(403, "forbidden");
    let previous = objects(&task_keys);
    previous
        .put(
            &object,
            Bytes::from_static(b"issued-session-survives-acl-removal").into(),
        )
        .await
        .unwrap();
    f.grant("all", &Rule::all());
    f.grant(
        "conflict",
        &Rule {
            route: "other",
            ..Rule::all()
        },
    );
    post(server.address, &[&bearer], body(&task_scope))
        .await
        .error(503, "conflicting_routes");
    f.clear();
    f.grant(
        "unavailable",
        &Rule {
            route: "missing-route",
            ..Rule::all()
        },
    );
    post(server.address, &[&bearer], body(&task_scope))
        .await
        .error(503, "route_unavailable");
    f.clear();
    f.grant("all", &Rule::all());
    f.db.execute("UPDATE resource_grants SET principal=zeroblob(1)", [])
        .unwrap();
    post(server.address, &[&bearer], body(&task_scope))
        .await
        .error(503, "authorization_unavailable");
    f.db.execute("UPDATE resource_grants SET principal=''", [])
        .unwrap();

    // Issuer duration remains independent of the short bearer; an already issued session survives.
    let mut claims = f.signer.claims();
    let expires = seconds() + 2;
    claims["exp"] = json!(expires);
    let short = f.signer.sign(&claims);
    let short = Zeroizing::new(format!("Bearer {}", short.as_str()));
    let short_keys = post(server.address, &[&short], body(&task_scope))
        .await
        .credentials(&task_scope, f.revision());
    let until = UNIX_EPOCH + Duration::from_secs(expires) + Duration::from_millis(80);
    tokio::time::sleep(until.duration_since(SystemTime::now()).unwrap_or_default()).await;
    post(server.address, &[&short], body(&task_scope))
        .await
        .error(401, "unauthenticated");
    objects(&short_keys)
        .get(&object)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();

    drop(previous);
    drop(reader);
    s3.shutdown(end()).await.unwrap();
    server.close().await;
    drop(s3);
    drop(disk);
    drop(volume);
    f.close().await;
}
fn raw_token(value: &str) -> &str {
    value.strip_prefix("Bearer ").unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real HTTP authentication before pending/malformed body, strict wire and temporal checks"]
async fn sqlite_storage_credentials_auth_before_body_and_finite_errors() {
    let f = Fixture::new().await;
    f.grant("all", &Rule::all());
    let issuer = Arc::new(issuer("http://127.0.0.1:1"));
    let verifier = Arc::new(f.signer.verifier());
    let raw = f.signer.sign(&f.signer.claims());
    let bearer = Zeroizing::new(format!("Bearer {}", raw.as_str()));
    let access = Zeroizing::new(format!("Bearer {}", f.access.as_str()));
    assert!(
        sqlite_broker_storage_credentials_router(
            f.store.clone(),
            verifier.clone(),
            None,
            native_config(true)
        )
        .is_err()
    );
    assert!(
        sqlite_local_storage_credentials_router(f.store.clone(), None, local_config(true)).is_err()
    );
    let mut mismatched = local_config(true);
    mismatched.body_bytes = n(2);
    assert!(
        sqlite_storage_credentials_router(
            f.store.clone(),
            verifier.clone(),
            Some(issuer.clone()),
            native_config(true),
            mismatched
        )
        .is_err()
    );
    let mut zero = native_config(false);
    zero.request_timeout = Duration::ZERO;
    assert!(
        sqlite_broker_storage_credentials_router(f.store.clone(), verifier.clone(), None, zero)
            .is_err()
    );
    let router = sqlite_storage_credentials_router(
        f.store.clone(),
        verifier.clone(),
        Some(issuer.clone()),
        native_config(true),
        local_config(true),
    )
    .unwrap();
    let server = Server::start(router).await;
    let pending =
        || Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
    let started = Instant::now();
    post(server.address, &["Bearer invalid"], pending())
        .await
        .error(401, "unauthenticated");
    assert!(started.elapsed() < Duration::from_secs(3));
    for auth in [
        vec![],
        vec!["Bearer invalid"],
        vec!["Bearer gb_at_invalid"],
        vec!["Bearer gb_sc_invalid"],
        vec![bearer.as_str(), bearer.as_str()],
        vec!["bearer invalid"],
    ] {
        post(server.address, &auth, Body::from("{invalid"))
            .await
            .error(401, "unauthenticated");
    }
    let mut no_scope = f.signer.claims();
    no_scope["scope"] = json!("");
    let no_scope = f.signer.sign(&no_scope);
    let no_scope = Zeroizing::new(format!("Bearer {}", no_scope.as_str()));
    post(server.address, &[&no_scope], pending())
        .await
        .error(403, "insufficient_scope");
    f.db.execute(
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
        [],
    )
    .unwrap();
    post(server.address, &[&access], pending())
        .await
        .error(401, "unauthenticated");
    f.db.execute(
        "UPDATE local_users SET enabled=1 WHERE username='alice'",
        [],
    )
    .unwrap();
    f.db.execute(
        "UPDATE local_tokens SET last_used_at=NULL WHERE token_kind='access'",
        [],
    )
    .unwrap();
    post(server.address, &[&access], Body::from("{invalid"))
        .await
        .error(400, "invalid_json");
    assert!(
        f.db.query_row(
            "SELECT last_used_at FROM local_tokens WHERE token_kind='access'",
            [],
            |r| r.get::<_, Option<i64>>(0)
        )
        .unwrap()
        .is_none()
    );
    for invalid in [
        "null",
        "[]",
        r#"["project","task"]"#,
        r#"{"scope":"project","module":"task"}"#,
        r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task","route":"injected"}"#,
        r#"{"scope":"project","scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task"}"#,
        r#"{"scope":"project","project_id":null,"module":"task"}"#,
        r#"{"scope":"user","module":"memory","installation_id":"Install-A","project_id":null}"#,
        r#"{"scope":"hub","module":"hub","installation_id":null}"#,
        r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task"} {}"#,
    ] {
        post(server.address, &[&bearer], Body::from(invalid))
            .await
            .error(400, "invalid_json");
    }
    for invalid in [
        json!({"scope":"project","project_id":A,"module":"dream"}),
        json!({"scope":"project","project_id":"../other","module":"task"}),
        json!({"scope":"user","module":"task","installation_id":"Install-A"}),
        json!({"scope":"user","module":"memory","installation_id":"../bad"}),
        json!({"scope":"hub","module":"Hub"}),
        json!({"scope":"global","module":"hub"}),
    ] {
        post(server.address, &[&bearer], Body::from(invalid.to_string()))
            .await
            .error(400, "invalid_scope");
    }
    let oversized = format!(
        "{}{}",
        json!({"scope":"hub","module":"hub"}),
        " ".repeat(1200)
    );
    post(server.address, &[&bearer], Body::from(oversized))
        .await
        .error(413, "body_too_large");

    let mut claims = f.signer.claims();
    let expires = seconds() + 2;
    claims["exp"] = json!(expires);
    let short = f.signer.sign(&claims);
    let short = Zeroizing::new(format!("Bearer {}", short.as_str()));
    let delayed = futures_util::stream::once(async move {
        let until = UNIX_EPOCH + Duration::from_secs(expires) + Duration::from_millis(80);
        tokio::time::sleep(until.duration_since(SystemTime::now()).unwrap_or_default()).await;
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"{invalid"))
    });
    post(server.address, &[&short], Body::from_stream(delayed))
        .await
        .error(401, "unauthenticated");
    let mut short_config = native_config(true);
    short_config.request_timeout = Duration::from_millis(120);
    let deadline = Server::start(
        sqlite_broker_storage_credentials_router(
            f.store.clone(),
            verifier.clone(),
            Some(issuer.clone()),
            short_config,
        )
        .unwrap(),
    )
    .await;
    post(deadline.address, &[&bearer], pending())
        .await
        .error(504, "deadline");
    deadline.close().await;
    f.store.shutdown(end()).await.unwrap();
    let disabled = Server::start(
        sqlite_storage_credentials_router(
            f.store.clone(),
            verifier,
            None,
            native_config(false),
            local_config(false),
        )
        .unwrap(),
    )
    .await;
    post(disabled.address, &[], pending())
        .await
        .error(404, "capability_disabled");
    disabled.close().await;
    server.close().await;
}
