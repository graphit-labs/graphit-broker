#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
#[path = "../../broker-storage/tests/support_aws/mod.rs"]
mod support_aws;
use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessVerifier, ConnectionLimits, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint,
};
use broker_presence::{
    BrokerStorageCredentialsHttpConfig, LocalStorageCredentialsHttpConfig,
    broker_storage_credentials_router, local_storage_credentials_router,
};
use broker_security::TokenKind;
use broker_storage::{
    AwsCredentialSource, AwsEndpointTransport, AwsStorageIssuer, AwsStorageRoute,
    AwsStorageRouteConfig, PrivateStaticCredentials, StorageCredentialsService, StorageIssuer,
};
use futures_util::{StreamExt, TryStreamExt, stream};
use http_body_util::BodyExt;
use hyper::body::Body as _;
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use object_store::{
    ClientOptions, ObjectStore, ObjectStoreExt, PutMode, PutOptions,
    aws::{AmazonS3, AmazonS3Builder, S3ConditionalPut},
    path::Path as ObjectPath,
};
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use support_aws::Minio;
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const ISSUER: &str = "https://broker.example.test";
const RESOURCE: &str = "https://broker.example.test/v1";
const RAW: &str = "gb_at_ephemeral-hub-access";
const SERVICE: &str = "gb_sc_ephemeral-hub-service";
struct Signer {
    key: EncodingKey,
    keys: jsonwebtoken::jwk::JwkSet,
}
impl Signer {
    fn new() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self { key: EncodingKey::from_ed_der(&pair.serialize_der()), keys: serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"hub-key","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())}]})).unwrap() }
    }
    fn verifier(&self, resource: Option<&str>) -> BrokerAccessVerifier {
        BrokerAccessVerifier::new(ISSUER, "hub-api", resource, &self.keys, n(8192)).unwrap()
    }
    fn claims(&self) -> Value {
        let now = seconds();
        json!({"iss":ISSUER,"sub":"hub-subject","aud":["hub-api",RESOURCE],"iat":now-1,"exp":now+600,"token_use":"access","client_id":"explicit-client","jti":"hub-token","scope":"","preferred_username":"alice","organization":"engineering","groups":["dev"],"roles":["admin"]})
    }
    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("hub-key".into());
        encode(&header, claims, &self.key).unwrap()
    }
}
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn micros() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new("hub_owner".into(), Zeroizing::new("ephemeral-owner".into())),
        f.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap()
}
async fn clear(c: &mut PgConnection) {
    c.execute("DELETE FROM public.resource_grants; UPDATE public.resource_acl_state SET revision=revision+1,updated_at=0 WHERE id=1").await.unwrap();
}
async fn seed_local(c: &mut PgConnection) {
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','current-name','current-email','current-org','[\"current-team\"]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','Automation','[]',1,0,1,0,0)").await.unwrap();
    for (raw, id, kind, token_kind, subject) in [
        (
            RAW,
            "hub-access",
            "access",
            TokenKind::LocalAccess,
            "alice-subject",
        ),
        (
            SERVICE,
            "hub-service",
            "service",
            TokenKind::ServiceCredential,
            "bot-subject",
        ),
    ] {
        let digest = support::digester()
            .token(token_kind, raw.as_bytes())
            .unwrap();
        let principal = json!({"issuer":"local","subject":subject,"username":"stale-name","auth_method":"local-token","organization":"stale-org","teams":["stale-team"],"local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'pseudonymous-other',$5,'explicit-client','explicit-audience','','[]',1,'',0,$6,0)").bind(digest.to_sql_hex()).bind(id).bind(kind).bind(subject).bind(principal).bind(micros()+600_000_000).execute(&mut *c).await.unwrap();
    }
}

struct Rule<'a> {
    kind: &'a str,
    principal: &'a str,
    caps: &'a [&'a str],
    projects: &'a [&'a str],
    operations: &'a [&'a str],
    prefixes: &'a [&'a str],
    route: &'a str,
}
async fn grant(c: &mut PgConnection, id: &str, r: &Rule<'_>) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture',$2,$3,$4,0,0)")
        .bind(id).bind(r.kind).bind(r.principal).bind(r.route).execute(&mut *c).await.unwrap();
    for (query, values) in [
        (
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
            r.caps,
        ),
        (
            "INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)",
            r.projects,
        ),
        (
            "INSERT INTO public.grant_s3_operations(grant_id,value) VALUES($1,$2)",
            r.operations,
        ),
        (
            "INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES($1,$2)",
            r.prefixes,
        ),
    ] {
        for value in values {
            sqlx_core::query::query(query)
                .bind(id)
                .bind(*value)
                .execute(&mut *c)
                .await
                .unwrap();
        }
    }
}
#[track_caller]
fn ok<T, E>(result: Result<T, E>, label: &str) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("{label}"),
    }
}

fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().expect("required wire string")
}
fn objects(keys: &Value) -> AmazonS3 {
    ok(
        AmazonS3Builder::new()
            .with_bucket_name(field(keys, "bucket"))
            .with_region(field(keys, "region"))
            .with_endpoint(field(keys, "endpoint"))
            .with_virtual_hosted_style_request(false)
            .with_access_key_id(field(keys, "access_key_id"))
            .with_secret_access_key(field(keys, "secret_access_key"))
            .with_token(field(keys, "session_token"))
            .with_conditional_put(S3ConditionalPut::ETagMatch)
            .with_client_options(
                ClientOptions::new()
                    .with_allow_http(true)
                    .with_pool_max_idle_per_host(0)
                    .with_timeout(Duration::from_secs(5))
                    .with_connect_timeout(Duration::from_secs(2)),
            )
            .with_retry(object_store::RetryConfig {
                max_retries: 0,
                retry_timeout: Duration::from_secs(5),
                ..Default::default()
            })
            .build(),
        "HTTP-issued S3 client",
    )
}

struct Server {
    address: std::net::SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl Server {
    async fn start(app: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self::start_listener(listener, app).await
    }
    async fn start_listener(listener: TcpListener, app: Router) -> Self {
        let address = listener.local_addr().unwrap();
        let (stop, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
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
    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        let task = self.task.as_mut().unwrap();
        match tokio::time::timeout(Duration::from_secs(5), &mut *task).await {
            Ok(result) => result.expect("owned HTTP server task failed"),
            Err(_) => {
                task.abort();
                let _ = task.await;
                panic!("owned HTTP server shutdown deadline");
            }
        }
        self.task.take();
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
fn request(method: &str, path: &str, auth: &[&str], body: Body) -> Request<Body> {
    let mut r = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    for value in auth {
        r = r.header(header::AUTHORIZATION, *value);
    }
    r.body(body).unwrap()
}
struct Reply {
    status: StatusCode,
    data: Value,
    challenge: Option<String>,
}
async fn exchange(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    auth: &[&str],
    body: Body,
) -> Reply {
    let streaming = body.size_hint().exact().is_none();
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let reply = ok(
        tokio::time::timeout(
            Duration::from_secs(12),
            sender.send_request(request(method, path, auth, body)),
        )
        .await,
        "HTTP response deadline",
    );
    let reply = ok(reply, "HTTP response");
    let status = reply.status();
    let challenge = reply
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_owned());
    assert_eq!(
        reply.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        reply.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let bytes = ok(reply.into_body().collect().await, "HTTP response body").to_bytes();
    let data = if method == "HEAD" {
        assert!(bytes.is_empty());
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("finite HTTP JSON")
    };
    drop(sender);
    let connection = ok(
        ok(
            tokio::time::timeout(Duration::from_secs(3), worker).await,
            "HTTP driver deadline",
        ),
        "HTTP driver join",
    );
    if let Err(error) = connection {
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

async fn post(address: std::net::SocketAddr, auth: &[&str], body: Body) -> Reply {
    exchange(address, "POST", "/v1/s3/credentials", auth, body).await
}
fn error(reply: Reply, status: StatusCode, code: &str) {
    assert_eq!(
        reply.status,
        status,
        "expected finite code {code}; actual code {}",
        reply.data["error"]["code"]
            .as_str()
            .unwrap_or("[non-error]")
    );
    assert_eq!(reply.data, json!({"error":{"code":code}}));
    let expected = if status == StatusCode::UNAUTHORIZED {
        Some("Bearer")
    } else if code == "insufficient_scope" {
        Some("Bearer error=\"insufficient_scope\"")
    } else {
        None
    };
    assert_eq!(reply.challenge.as_deref(), expected);
}

fn native_config(enabled: bool) -> BrokerStorageCredentialsHttpConfig {
    BrokerStorageCredentialsHttpConfig {
        required_scopes: vec![],
        grants_json_bytes: n(65536),
        default_route: if enabled {
            "primary".into()
        } else {
            String::new()
        },
        body_bytes: n(8192),
        request_timeout: Duration::from_secs(25),
        enabled,
    }
}
fn local_config(enabled: bool) -> LocalStorageCredentialsHttpConfig {
    LocalStorageCredentialsHttpConfig {
        required_scopes: vec![],
        audience: if enabled {
            "explicit-audience".into()
        } else {
            String::new()
        },
        identity_json_bytes: n(65536),
        grants_json_bytes: n(65536),
        default_route: if enabled {
            "primary".into()
        } else {
            String::new()
        },
        body_bytes: n(8192),
        request_timeout: Duration::from_secs(25),
        enabled,
    }
}

#[derive(Clone)]
struct Proxy {
    endpoint: String,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    failure: Arc<std::sync::atomic::AtomicU8>,
}
async fn proxy(
    axum::extract::State(state): axum::extract::State<Proxy>,
    request: Request<Body>,
) -> axum::response::Response {
    use std::sync::atomic::Ordering;
    state.calls.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = request.into_parts();
    assert!(
        parts.headers[header::AUTHORIZATION]
            .to_str()
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256 ")
    );
    let bytes = body.collect().await.unwrap().to_bytes();
    let fields = form_urlencoded::parse(&bytes).collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(fields.get("Action").unwrap(), "AssumeRole");
    assert_eq!(fields.get("DurationSeconds").unwrap(), "900");
    let policy: Value = serde_json::from_str(fields.get("Policy").unwrap()).unwrap();
    assert_eq!(policy["Version"], "2012-10-17");
    assert!(!policy["Statement"].as_array().unwrap().is_empty());
    if state.failure.load(Ordering::SeqCst) == 1 {
        return axum::response::Response::builder().status(403).header(header::CONTENT_TYPE,"text/xml").body(Body::from("<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>owned rejection</Message></Error><RequestId>owned-negative</RequestId></ErrorResponse>")).unwrap();
    }
    let address = state.endpoint.strip_prefix("http://").unwrap();
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let mut request = Request::from_parts(parts, Body::from(bytes));
    *request.uri_mut() = "/".parse().unwrap();
    let response = ok(
        sender.send_request(request).await,
        "real MinIO STS response",
    );
    let (parts, body) = response.into_parts();
    let bytes = ok(body.collect().await, "real STS body").to_bytes();
    drop(sender);
    ok(ok(worker.await, "STS driver join"), "STS driver");
    axum::response::Response::from_parts(parts, Body::from(bytes))
}
fn aws(service: &Minio, endpoint: &str, name: &str) -> AwsStorageIssuer {
    AwsStorageIssuer::new(
        vec![
            AwsStorageRoute::new(AwsStorageRouteConfig {
                name: name.into(),
                region: "us-east-1".into(),
                bucket: service.bucket.clone(),
                base_prefix: "tenant".into(),
                conditional_delete: false,
                s3_endpoint: Some(service.endpoint.clone()),
                sts_endpoint: Some(endpoint.into()),
                role_arn: "arn:aws:iam::123456789012:role/fixture".into(),
                session_name: "graphit-broker".into(),
                session_duration: Duration::from_secs(900),
                endpoint_transport: AwsEndpointTransport::LoopbackHttp,
                credential_source: AwsCredentialSource::StaticPair(
                    PrivateStaticCredentials::new(
                        Zeroizing::new(service.caller_key.to_string()),
                        Zeroizing::new(service.caller_secret.to_string()),
                    )
                    .unwrap(),
                ),
            })
            .unwrap(),
        ],
        Duration::from_millis(700),
    )
    .unwrap()
}
fn filesystem(
    endpoint: &str,
    name: &str,
    bucket: &str,
    pepper: u8,
) -> broker_storage::FilesystemStorageIssuer {
    broker_storage::FilesystemStorageIssuer::new(
        vec![
            broker_storage::FilesystemStorageRoute::new(
                broker_storage::FilesystemStorageRouteConfig {
                    name: name.into(),
                    bucket: bucket.into(),
                    region: "us-east-1".into(),
                    base_prefix: "tenant".into(),
                    endpoint: endpoint.into(),
                    session_duration: Duration::from_secs(900),
                    token_bytes: n(65536),
                },
            )
            .unwrap(),
        ],
        Zeroizing::new(vec![pepper; 32]),
    )
    .unwrap()
}
fn volume(path: &std::path::Path, bucket: &str) -> Arc<broker_storage::FilesystemStore> {
    Arc::new(
        broker_storage::FilesystemStore::open(broker_storage::FilesystemStoreConfig {
            directory: path.into(),
            bucket: bucket.into(),
            max_object_bytes: std::num::NonZeroU64::new(1024 * 1024).unwrap(),
            metadata_bytes: n(8192),
        })
        .unwrap(),
    )
}
fn ingress(
    service: &StorageCredentialsService,
    stores: Vec<Arc<broker_storage::FilesystemStore>>,
) -> broker_presence::FilesystemStorageHttp {
    let gateways = service
        .filesystem_gateways(
            stores,
            broker_storage::FilesystemGatewayConfig {
                request_timeout: Duration::from_secs(2),
                request_head_bytes: n(70000),
            },
        )
        .unwrap();
    broker_presence::FilesystemStorageHttp::new(
        gateways.into_iter().map(Arc::new).collect(),
        Duration::from_secs(3),
    )
    .unwrap()
}
async fn rules(c: &mut PgConnection, route: &str, operation: &str) {
    clear(c).await;
    grant(
        c,
        "current",
        &Rule {
            kind: "authenticated",
            principal: "",
            caps: &["s3", "hub"],
            projects: &[],
            operations: &[operation],
            prefixes: &["v1"],
            route,
        },
    )
    .await;
}
async fn root(
    store: &PostgresControlStore,
    verifier: &BrokerAccessVerifier,
    bearer: &str,
    scope: &broker_control::StorageScope,
    local: bool,
) -> String {
    let raw = bearer.strip_prefix("Bearer ").unwrap();
    let prefix = if local {
        let factory = store
            .local_storage_authorizer("explicit-audience", n(65536), n(65536), "primary")
            .unwrap();
        let caller = factory.authenticate(raw, &[], deadline()).await.unwrap();
        let grant = factory
            .authorize_authenticated(caller, scope)
            .await
            .unwrap();
        grant.prefixes(broker_control::StorageOperation::Publish)[0].clone()
    } else {
        let factory = store
            .broker_storage_authorizer(verifier, n(65536), "primary")
            .unwrap();
        let caller = factory.authenticate(raw, &[], deadline()).unwrap();
        let grant = factory
            .authorize_authenticated(caller, scope)
            .await
            .unwrap();
        grant.prefixes(broker_control::StorageOperation::Publish)[0].clone()
    };
    format!("tenant/{prefix}")
}
fn wire(reply: Reply, scope: &Value, bucket: &str, endpoint: &str, fs: bool) -> Value {
    assert_eq!(reply.status, StatusCode::OK, "issuance status");
    let keys = reply.data;
    let mut expected = vec![
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
    if scope["scope"] == "user" {
        expected.push("installation_id");
        assert_eq!(keys["installation_id"], scope["installation_id"]);
    }
    let actual = keys
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected.into_iter().collect());
    for name in ["access_key_id", "secret_access_key", "session_token"] {
        assert!(!field(&keys, name).is_empty());
    }
    assert_eq!(field(&keys, "session_token").starts_with("rust-fs1."), fs);
    assert_eq!(keys["scope"], scope["scope"]);
    assert_eq!(keys["module"], scope["module"]);
    assert_eq!(
        field(&keys, "project_id"),
        scope["project_id"].as_str().unwrap_or("")
    );
    assert_eq!(field(&keys, "bucket"), bucket);
    assert_eq!(field(&keys, "endpoint"), endpoint);
    assert_eq!(field(&keys, "region"), "us-east-1");
    assert_eq!(keys["prefixes"], json!(["tenant"]));
    assert_eq!(keys["conditional_delete"], fs);
    assert_eq!(
        keys["copy_if_not_exists"],
        if fs { "if_none_match" } else { "multipart" }
    );
    assert!(
        field(&keys, "authorization_revision")
            .parse::<u64>()
            .unwrap()
            > 0
    );
    let expiry = chrono::DateTime::parse_from_rfc3339(field(&keys, "expires_at"))
        .unwrap()
        .timestamp();
    assert!(
        expiry > i64::try_from(seconds() + 850).unwrap(),
        "storage TTL is independent of the 600-second bearer"
    );
    keys
}
fn denied<T>(result: object_store::Result<T>) {
    match result {
        Err(object_store::Error::PermissionDenied { .. }) => {}
        Err(object_store::Error::Generic { source, .. }) => {
            let text = Zeroizing::new(source.to_string());
            assert!(
                text.contains("403 Forbidden") || text.ends_with("(code: AccessDenied)"),
                "actual S3 permission denial required"
            );
        }
        _ => panic!("actual S3 permission denial required"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "owned PostgreSQL TLS and actual MinIO STS/S3 required"]
async fn mixed_storage_credentials_http_contract() {
    use broker_control::{StorageModule, StorageScope};
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE hub_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner';DROP SCHEMA public CASCADE;CREATE SCHEMA public AUTHORIZATION hub_owner;GRANT CONNECT,TEMP ON DATABASE postgres TO hub_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    assert!(
        !sqlx_core::query_scalar::query_scalar::<_, bool>(
            "SELECT rolsuper FROM pg_roles WHERE rolname='hub_owner'"
        )
        .fetch_one(&mut c)
        .await
        .unwrap()
    );
    seed_local(&mut c).await;
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier(Some(RESOURCE)));
    let auth = Zeroizing::new(format!("Bearer {}", signer.sign(&signer.claims())));
    let access = Zeroizing::new(format!("Bearer {RAW}"));
    let service_auth = Zeroizing::new(format!("Bearer {SERVICE}"));
    let mut minio = Minio::start().await;
    minio.seed("tenant/foreign-seed", b"foreign");
    let calls = Arc::new(AtomicUsize::new(0));
    let failure = Arc::new(AtomicU8::new(0));
    let proxied = Server::start(
        Router::new()
            .route("/", axum::routing::post(proxy))
            .with_state(Proxy {
                endpoint: minio.endpoint.clone(),
                calls: calls.clone(),
                failure: failure.clone(),
            }),
    )
    .await;
    let sts = format!("http://{}", proxied.address);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = format!("http://{address}");
    const BUCKET: &str = "native-mixed";
    assert!(StorageCredentialsService::new(vec![]).is_err());
    assert!(
        StorageCredentialsService::new(vec![
            StorageIssuer::Aws(aws(&minio, &sts, "primary")),
            StorageIssuer::Filesystem(filesystem(&endpoint, "primary", BUCKET, 31))
        ])
        .is_err()
    );
    assert!(
        StorageCredentialsService::new(vec![
            StorageIssuer::Filesystem(filesystem(&endpoint, "one", BUCKET, 31)),
            StorageIssuer::Filesystem(filesystem(&endpoint, "two", BUCKET, 32))
        ])
        .is_err()
    );
    let issuers = || {
        vec![
            StorageIssuer::Aws(aws(&minio, &sts, "primary")),
            StorageIssuer::Filesystem(filesystem(&endpoint, "local", BUCKET, 31)),
        ]
    };
    let mixed = Arc::new(StorageCredentialsService::new(issuers()).unwrap());
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("volume");
    let disk = volume(&path, BUCKET);
    let cfg = || broker_storage::FilesystemGatewayConfig {
        request_timeout: Duration::from_secs(2),
        request_head_bytes: n(70000),
    };
    assert!(mixed.filesystem_gateways(vec![], cfg()).is_err());
    assert!(
        mixed
            .filesystem_gateways(vec![disk.clone(), disk.clone()], cfg())
            .is_err()
    );
    let extra = volume(&folder.path().join("extra"), "extra-native");
    assert!(
        mixed
            .filesystem_gateways(vec![disk.clone(), extra], cfg())
            .is_err()
    );
    let s3 = ingress(&mixed, vec![disk.clone()]);
    let native_app = broker_storage_credentials_router(
        store.clone(),
        verifier.clone(),
        Some(mixed.clone()),
        native_config(true),
    )
    .unwrap()
    .merge(s3.router());
    let native = Server::start_listener(listener, native_app).await;
    let local = Server::start(
        local_storage_credentials_router(store.clone(), Some(mixed.clone()), local_config(true))
            .unwrap(),
    )
    .await;
    let callers = [
        ("native", native.address, auth.as_str(), false),
        ("access", local.address, access.as_str(), true),
        ("service", local.address, service_auth.as_str(), true),
    ];
    let mut scopes = Vec::new();
    for (name, module) in [
        ("hub", StorageModule::Hub),
        ("task", StorageModule::Task),
        ("memory", StorageModule::Memory),
        ("knowledge", StorageModule::Knowledge),
        ("ast", StorageModule::Ast),
    ] {
        scopes.push((
            json!({"scope":"project","project_id":A,"module":name}),
            StorageScope::project(A, module).unwrap(),
        ));
    }
    scopes.push((
        json!({"scope":"user","installation_id":"Install-A","module":"memory"}),
        StorageScope::user_memory("Install-A").unwrap(),
    ));
    scopes.push((
        json!({"scope":"hub","module":"hub"}),
        StorageScope::global_hub(),
    ));
    let mut retained = None;
    for (scope, typed) in &scopes {
        for (actor, http, bearer, is_local) in callers {
            rules(&mut c, "local", "publish").await;
            let count = calls.load(Ordering::SeqCst);
            let keys = wire(
                post(http, &[bearer], Body::from(scope.to_string())).await,
                scope,
                BUCKET,
                &endpoint,
                true,
            );
            assert_eq!(calls.load(Ordering::SeqCst), count, "FS never calls AWS");
            let root = root(&store, &verifier, bearer, typed, is_local).await;
            let object = ObjectPath::from(format!("{root}/mixed-{actor}"));
            let client = objects(&keys);
            ok(
                client.put(&object, "native bytes".into()).await,
                "FS SDK PUT",
            );
            assert_eq!(
                ok(
                    ok(client.get(&object).await, "FS SDK GET").bytes().await,
                    "FS GET bytes"
                ),
                "native bytes"
            );
            let foreign = ObjectPath::from(format!("tenant/v1/projects/{B}/corpora/task/escape"));
            denied(client.put(&foreign, "escape".into()).await);
            assert!(!path.join("data").join(foreign.as_ref()).exists());
            assert_eq!(
                std::fs::read(path.join("data").join(object.as_ref())).unwrap(),
                b"native bytes"
            );
            // The same router sees the new SQL route; old sessions retain their captured policy.
            rules(&mut c, "primary", "publish").await;
            let aws_keys = wire(
                post(http, &[bearer], Body::from(scope.to_string())).await,
                scope,
                &minio.bucket,
                &minio.endpoint,
                false,
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                count + 1,
                "exact selected AWS request"
            );
            let remote = objects(&aws_keys);
            ok(remote.put(&object, "AWS bytes".into()).await, "AWS SDK PUT");
            assert!(minio.exists(object.as_ref()));
            assert_eq!(
                ok(
                    ok(
                        client.get(&object).await,
                        "old FS session after route switch"
                    )
                    .bytes()
                    .await,
                    "old FS bytes"
                ),
                "native bytes"
            );
            if actor == "native" && scope["module"] == "task" && scope["scope"] == "project" {
                retained = Some((keys, object));
            }
        }
    }
    let (keys, object) = retained.unwrap();
    let client = objects(&keys);
    // Preserve both signed bucket-root spellings without redirects or URI rewriting.
    for slash in ["", "/"] {
        for query in [
            "?list-type=2&prefix=tenant%2Fv1%2Fprojects%2F01D39ZY06FGSCTVN4T2V9PKHFZ%2Fcorpora%2Ftask",
            "?location",
        ] {
            let url = format!("{endpoint}/{BUCKET}{slash}{query}");
            let response = ok(
                s3_send(
                    &endpoint,
                    signed(&keys, "GET", &url, b"", Body::empty(), &[], false),
                )
                .await,
                "signed bucket root",
            );
            assert_eq!(
                response.0,
                StatusCode::OK,
                "signed root must reach mature S3 gateway"
            );
        }
    }
    let info = ok(client.head(&object).await, "FS HEAD");
    assert_eq!(ok(client.get_range(&object, 1..4).await, "FS range"), "ati");
    assert!(matches!(
        client
            .put_opts(
                &object,
                "race".into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                }
            )
            .await,
        Err(object_store::Error::AlreadyExists { .. })
            | Err(object_store::Error::Precondition { .. })
    ));
    let updated = ok(
        client
            .put_opts(
                &object,
                "updated".into(),
                PutOptions {
                    mode: PutMode::Update(object_store::UpdateVersion {
                        e_tag: info.e_tag,
                        version: None,
                    }),
                    ..Default::default()
                },
            )
            .await,
        "FS CAS",
    );
    assert!(updated.e_tag.is_some());
    let copy = ObjectPath::from(format!(
        "{}/copy",
        object.as_ref().rsplit_once('/').unwrap().0
    ));
    ok(client.copy(&object, &copy).await, "FS COPY");
    let prefix = ObjectPath::from(object.as_ref().rsplit_once('/').unwrap().0);
    let listed = ok(
        client.list(Some(&prefix)).try_collect::<Vec<_>>().await,
        "FS list",
    );
    assert!(listed.iter().any(|m| m.location == copy));
    let deleted = ok(
        client
            .delete_stream(Box::pin(stream::iter(vec![Ok(copy.clone())])))
            .try_collect::<Vec<_>>()
            .await,
        "FS batch",
    );
    assert_eq!(deleted, vec![copy]);
    mixed_multipart(&keys, &endpoint, &object).await;
    // These failures cannot select the valid FS driver or reach either bucket.
    rules(&mut c, "missing", "publish").await;
    let before = calls.load(Ordering::SeqCst);
    error(
        post(
            native.address,
            &[auth.as_str()],
            Body::from(scopes[1].0.to_string()),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "route_unavailable",
    );
    assert_eq!(calls.load(Ordering::SeqCst), before);
    rules(&mut c, "primary", "publish").await;
    failure.store(1, Ordering::SeqCst);
    error(
        post(
            native.address,
            &[auth.as_str()],
            Body::from(scopes[1].0.to_string()),
        )
        .await,
        StatusCode::BAD_GATEWAY,
        "storage_credentials_refused",
    );
    assert_eq!(calls.load(Ordering::SeqCst), before + 1);
    failure.store(0, Ordering::SeqCst);
    minio.pause();
    error(
        post(
            native.address,
            &[auth.as_str()],
            Body::from(scopes[1].0.to_string()),
        )
        .await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    minio.resume();
    rules(&mut c, "local", "read").await;
    let read = wire(
        post(
            native.address,
            &[auth.as_str()],
            Body::from(scopes[1].0.to_string()),
        )
        .await,
        &scopes[1].0,
        BUCKET,
        &endpoint,
        true,
    );
    denied(objects(&read).put(&object, "denied".into()).await);
    rules(&mut c, "local", "publish").await;
    c.execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
        .await
        .unwrap();
    let before = calls.load(Ordering::SeqCst);
    error(
        post(
            local.address,
            &[access.as_str()],
            Body::from(scopes[1].0.to_string()),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    assert_eq!(calls.load(Ordering::SeqCst), before);
    c.execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'")
        .await
        .unwrap();
    error(
        post(
            native.address,
            &["Bearer invalid"],
            Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>()),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    error(
        post(
            native.address,
            &[auth.as_str()],
            Body::from(
                json!({"scope":"project","project_id":A,"module":"task","route":"primary"})
                    .to_string(),
            ),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_json",
    );
    let mut short = signer.claims();
    short["exp"] = json!(seconds() + 2);
    let short = Zeroizing::new(format!("Bearer {}", signer.sign(&short)));
    let short_keys = wire(
        post(
            native.address,
            &[short.as_str()],
            Body::from(scopes[1].0.to_string()),
        )
        .await,
        &scopes[1].0,
        BUCKET,
        &endpoint,
        true,
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;
    error(
        post(
            native.address,
            &[short.as_str()],
            Body::from(scopes[1].0.to_string()),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    ok(
        objects(&short_keys).get(&object).await,
        "session outlives actual expired bearer",
    );
    stalled_shutdown(&s3, &keys, &endpoint, &path, &object).await;
    // End HTTP connections before dropping the volume; same pepper survives a native restart.
    s3.shutdown(deadline()).await.unwrap();
    native.stop().await;
    local.stop().await;
    drop(s3);
    drop(disk);
    drop(mixed);
    drop(client);
    let disk = volume(&path, BUCKET);
    let mixed = StorageCredentialsService::new(vec![StorageIssuer::Filesystem(filesystem(
        &endpoint, "local", BUCKET, 31,
    ))])
    .unwrap();
    let s3 = ingress(&mixed, vec![disk.clone()]);
    let listener = TcpListener::bind(address).await.unwrap();
    let restarted = Server::start_listener(listener, s3.router()).await;
    assert_eq!(
        ok(
            ok(
                objects(&keys).get(&object).await,
                "old session survives native restart"
            )
            .bytes()
            .await,
            "restart bytes"
        ),
        "updated"
    );
    s3.shutdown(deadline()).await.unwrap();
    restarted.stop().await;
    drop(s3);
    drop(disk);
    let rotated = StorageCredentialsService::new(vec![StorageIssuer::Filesystem(filesystem(
        &endpoint, "local", BUCKET, 32,
    ))])
    .unwrap();
    let disk = volume(&path, BUCKET);
    let s3 = ingress(&rotated, vec![disk]);
    let listener = TcpListener::bind(address).await.unwrap();
    let restarted = Server::start_listener(listener, s3.router()).await;
    let result = objects(&keys).get(&object).await;
    assert!(
        result.is_err(),
        "old MAC denied after explicit pepper rotation"
    );
    s3.shutdown(deadline()).await.unwrap();
    restarted.stop().await;
    proxied.stop().await;
    drop(store);
    c.close().await.unwrap();
    drop(minio);
    drop(f);
}

fn signed(
    keys: &Value,
    method: &str,
    url: &str,
    payload: &[u8],
    body: Body,
    extra: &[(&str, &str)],
    unsigned: bool,
) -> Request<Body> {
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
        UriPathNormalizationMode, sign,
    };
    let credentials = aws_credential_types::Credentials::new(
        field(keys, "access_key_id"),
        field(keys, "secret_access_key"),
        Some(field(keys, "session_token").into()),
        None,
        "mixed-fixture",
    );
    let identity = credentials.into();
    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    let params = aws_sigv4::sign::v4::SigningParams::builder()
        .identity(&identity)
        .region(field(keys, "region"))
        .name("s3")
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let mut request = Request::builder()
        .method(method)
        .uri(url)
        .body(body)
        .unwrap();
    let uri: axum::http::Uri = url.parse().unwrap();
    request.headers_mut().insert(
        header::HOST,
        uri.authority().unwrap().as_str().parse().unwrap(),
    );
    for (name, value) in extra {
        request.headers_mut().insert(
            header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    let payload = if unsigned {
        SignableBody::UnsignedPayload
    } else {
        SignableBody::Bytes(payload)
    };
    let signable = SignableRequest::new(
        method,
        url,
        request
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap())),
        payload,
    )
    .unwrap();
    let (instructions, _) = sign(signable, &params).unwrap().into_parts();
    instructions.apply_to_request_http1x(&mut request);
    request
}
async fn s3_send(
    endpoint: &str,
    mut request: Request<Body>,
) -> Result<(StatusCode, axum::http::HeaderMap, Bytes), hyper::Error> {
    let stream = TcpStream::connect(endpoint.strip_prefix("http://").unwrap())
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let uri = request
        .uri()
        .path_and_query()
        .unwrap()
        .as_str()
        .parse()
        .unwrap();
    *request.uri_mut() = uri;
    let result = sender.send_request(request).await;
    let result = match result {
        Ok(response) => {
            let status = response.status();
            let headers = response.headers().clone();
            response
                .into_body()
                .collect()
                .await
                .map(|body| (status, headers, body.to_bytes()))
        }
        Err(error) => Err(error),
    };
    drop(sender);
    let _ = worker.await;
    result
}
async fn s3_call(
    keys: &Value,
    endpoint: &str,
    method: &str,
    path: &str,
    bytes: &[u8],
) -> (StatusCode, axum::http::HeaderMap, Bytes) {
    let url = format!("{endpoint}/{}/{}", field(keys, "bucket"), path);
    ok(
        s3_send(
            endpoint,
            signed(
                keys,
                method,
                &url,
                bytes,
                Body::from(bytes.to_vec()),
                &[],
                false,
            ),
        )
        .await,
        "signed S3 HTTP",
    )
}
fn xml<T: s3s::xml::Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut s3s::xml::Serializer::new(&mut bytes))
        .unwrap();
    bytes
}
fn upload_id(body: &[u8]) -> String {
    let mut d = s3s::xml::Deserializer::new(body);
    let mut id = None;
    d.named_element("InitiateMultipartUploadResult", |d| {
        d.for_each_element(|d, name| {
            let value = d.text(|s| Ok(s.to_owned()))?;
            if name == b"UploadId" {
                assert!(id.replace(value).is_none());
            }
            Ok(())
        })
    })
    .unwrap();
    id.unwrap()
}
async fn mixed_multipart(keys: &Value, endpoint: &str, object: &ObjectPath) {
    let path = format!("{}/multipart", object.as_ref().rsplit_once('/').unwrap().0);
    let (status, _, body) = s3_call(keys, endpoint, "POST", &format!("{path}?uploads"), b"").await;
    assert_eq!(status, StatusCode::OK);
    let id = upload_id(&body);
    let mut parts = Vec::new();
    for (number, payload) in [(1, b"ab".as_slice()), (3, b"cde".as_slice())] {
        let (status, headers, _) = s3_call(
            keys,
            endpoint,
            "PUT",
            &format!("{path}?partNumber={number}&uploadId={id}"),
            payload,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        parts.push(s3s::dto::CompletedPart {
            part_number: Some(number),
            e_tag: Some(s3s::dto::ETag::parse_http_header(headers["etag"].as_bytes()).unwrap()),
            ..Default::default()
        });
    }
    let (status, _, bytes) =
        s3_call(keys, endpoint, "GET", &format!("{path}?uploadId={id}"), b"").await;
    assert_eq!(status, StatusCode::OK);
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(
        text.contains("<PartNumber>1</PartNumber>") && text.contains("<PartNumber>3</PartNumber>")
    );
    let mut bad = parts.clone();
    bad[0].e_tag = Some(s3s::dto::ETag::Strong("0".repeat(64)));
    let result = s3_call(
        keys,
        endpoint,
        "POST",
        &format!("{path}?uploadId={id}"),
        &xml(&s3s::dto::CompletedMultipartUpload { parts: Some(bad) }),
    )
    .await;
    assert_eq!(result.0, StatusCode::BAD_REQUEST);
    let result = s3_call(
        keys,
        endpoint,
        "POST",
        &format!("{path}?uploadId={id}"),
        &xml(&s3s::dto::CompletedMultipartUpload { parts: Some(parts) }),
    )
    .await;
    assert_eq!(result.0, StatusCode::OK);
    assert_eq!(
        ok(
            ok(
                objects(keys).get(&ObjectPath::from(path)).await,
                "mixed multipart object"
            )
            .bytes()
            .await,
            "multipart bytes"
        ),
        "abcde"
    );
}
async fn stalled_shutdown(
    s3: &broker_presence::FilesystemStorageHttp,
    keys: &Value,
    endpoint: &str,
    path: &std::path::Path,
    object: &ObjectPath,
) {
    let target = format!("{}/stalled", object.as_ref().rsplit_once('/').unwrap().0);
    let url = format!("{endpoint}/{}/{target}", field(keys, "bucket"));
    let input = stream::once(async { Ok::<_, std::io::Error>(Bytes::from_static(b"partial")) })
        .chain(stream::pending());
    let request = signed(
        keys,
        "PUT",
        &url,
        b"",
        Body::from_stream(input),
        &[("content-length", "4096")],
        true,
    );
    let owned_endpoint = endpoint.to_owned();
    let worker = tokio::spawn(async move { s3_send(&owned_endpoint, request).await });
    let until = std::time::Instant::now() + Duration::from_secs(1);
    while std::fs::read_dir(path.join("tmp")).unwrap().count() == 0 {
        assert!(
            std::time::Instant::now() < until,
            "actual stalled IO must enter staging"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    s3.shutdown(deadline()).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(
        result.is_err() || result.is_ok_and(|r| !r.0.is_success()),
        "cancelled request cannot succeed"
    );
    assert_eq!(std::fs::read_dir(path.join("tmp")).unwrap().count(), 0);
    assert!(!path.join("data").join(target).exists());
    let result = s3_call(keys, endpoint, "GET", object.as_ref(), b"").await;
    assert_eq!(result.0, StatusCode::SERVICE_UNAVAILABLE);
}
