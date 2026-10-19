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
use futures_util::TryStreamExt;
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
fn credential_free_error(error: &(dyn std::error::Error + 'static), keys: &Value) -> String {
    let mut parts = Vec::new();
    let mut current = Some(error);
    while let Some(error) = current {
        let mut text = Zeroizing::new(error.to_string());
        for name in ["access_key_id", "secret_access_key", "session_token"] {
            *text = text.replace(field(keys, name), "[credential]");
        }
        parts.push(
            text.split_whitespace()
                .map(|part| if part.contains("://") { "[url]" } else { part })
                .collect::<Vec<_>>()
                .join(" "),
        );
        current = error.source();
    }
    parts.join(" <- ")
}
#[track_caller]
fn s3_ok<T>(result: object_store::Result<T>, label: &str, keys: &Value) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            let category = match &error {
                object_store::Error::PermissionDenied { .. } => "permission",
                object_store::Error::Precondition { .. } => "precondition",
                object_store::Error::AlreadyExists { .. } => "already_exists",
                object_store::Error::NotFound { .. } => "not_found",
                object_store::Error::Generic { .. } => "generic",
                _ => "other",
            };
            let message = credential_free_error(&error, keys);
            panic!("{label}: {category}: {message}");
        }
    }
}
fn route(service: &Minio, key: &str, secret: &str) -> AwsStorageRoute {
    ok(
        AwsStorageRoute::new(AwsStorageRouteConfig {
            name: "primary".into(),
            region: "us-east-1".into(),
            bucket: service.bucket.clone(),
            base_prefix: "tenant".into(),
            conditional_delete: false,
            s3_endpoint: Some(service.endpoint.clone()),
            sts_endpoint: None,
            role_arn: "arn:aws:iam::123456789012:role/fixture".into(),
            session_name: "  graphit-broker  ".into(),
            session_duration: Duration::from_secs(900),
            endpoint_transport: AwsEndpointTransport::LoopbackHttp,
            credential_source: AwsCredentialSource::StaticPair(ok(
                PrivateStaticCredentials::new(
                    Zeroizing::new(key.into()),
                    Zeroizing::new(secret.into()),
                ),
                "static pair",
            )),
        }),
        "explicit route",
    )
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
#[track_caller]
fn denied<T>(result: object_store::Result<T>, keys: &Value) {
    match result {
        Err(object_store::Error::PermissionDenied { .. }) => {}
        Err(object_store::Error::Generic { source, .. }) => {
            let text = Zeroizing::new(source.to_string());
            assert!(
                text.contains("403 Forbidden") || text.ends_with("(code: AccessDenied)"),
                "causal S3 denial required: {}",
                credential_free_error(source.as_ref(), keys)
            );
        }
        _ => panic!("causal S3 permission denial required"),
    }
}
async fn restricted(c: &mut PgConnection, operation: &str, module: &str) {
    let prefix = format!("v1/projects/{{project}}/corpora/{module}");
    clear(c).await;
    grant(
        c,
        "current",
        &Rule {
            kind: "authenticated",
            principal: "",
            caps: &["s3"],
            projects: &[A],
            operations: &[operation],
            prefixes: &[&prefix],
            route: "primary",
        },
    )
    .await;
}
struct Server {
    address: std::net::SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl Server {
    async fn start(app: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
fn body(project: &str, module: &str) -> Body {
    Body::from(json!({"scope":"project","project_id":project,"module":module}).to_string())
}
fn pending_body() -> Body {
    Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>())
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
fn success(reply: Reply, service: &Minio, claims: &Value, module: &str) -> Value {
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.challenge.is_none());
    let keys = reply.data;
    let actual = keys
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = [
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
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(keys["conditional_delete"], false);
    assert_eq!(keys["copy_if_not_exists"], "multipart");
    for name in ["access_key_id", "secret_access_key", "session_token"] {
        assert!(!field(&keys, name).is_empty());
    }
    assert!(field(&keys, "access_key_id") != service.caller_key.as_str());
    assert_eq!(field(&keys, "bucket"), service.bucket);
    assert_eq!(field(&keys, "region"), "us-east-1");
    assert_eq!(field(&keys, "endpoint"), service.endpoint);
    assert_eq!(field(&keys, "scope"), "project");
    assert_eq!(field(&keys, "project_id"), A);
    assert_eq!(field(&keys, "module"), module);
    assert_eq!(keys["prefixes"], json!(["tenant"]));
    assert!(
        field(&keys, "authorization_revision")
            .parse::<u64>()
            .unwrap()
            > 0
    );
    let expiry = chrono::DateTime::parse_from_rfc3339(field(&keys, "expires_at")).unwrap();
    assert!(field(&keys, "expires_at").ends_with('Z'));
    assert!(u64::try_from(expiry.timestamp()).unwrap() > claims["exp"].as_u64().unwrap() + 200);
    keys
}

#[tokio::test]
#[ignore = "actual TCP, PostgreSQL TLS NOSUPERUSER, Native/opaque grants, SDK STS and signed S3 corpus isolation"]
async fn project_corpus_storage_credentials_http_contract() {
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
    let claims = signer.claims();
    let auth = Zeroizing::new(format!("Bearer {}", signer.sign(&claims)));
    for app in [
        broker_storage_credentials_router(
            store.clone(),
            verifier.clone(),
            None,
            native_config(false),
        )
        .unwrap(),
        local_storage_credentials_router(store.clone(), None, local_config(false)).unwrap(),
    ] {
        let disabled = Server::start(app).await;
        error(
            post(disabled.address, &["Bearer invalid"], pending_body()).await,
            StatusCode::NOT_FOUND,
            "capability_disabled",
        );
        disabled.stop().await;
    }
    assert!(
        broker_storage_credentials_router(
            store.clone(),
            verifier.clone(),
            None,
            native_config(true)
        )
        .is_err()
    );
    assert!(local_storage_credentials_router(store.clone(), None, local_config(true)).is_err());
    let mut service = Minio::start().await;
    let issuer = Arc::new(
        StorageCredentialsService::new(vec![StorageIssuer::Aws(
            AwsStorageIssuer::new(
                vec![route(&service, &service.caller_key, &service.caller_secret)],
                Duration::from_secs(5),
            )
            .unwrap(),
        )])
        .unwrap(),
    );
    let native = Server::start(
        broker_storage_credentials_router(
            store.clone(),
            verifier.clone(),
            Some(issuer.clone()),
            native_config(true),
        )
        .unwrap(),
    )
    .await;
    let local = Server::start(
        local_storage_credentials_router(store.clone(), Some(issuer.clone()), local_config(true))
            .unwrap(),
    )
    .await;
    error(
        post(native.address, &["Bearer invalid"], pending_body()).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    error(
        post(native.address, &[], Body::from("broken")).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    error(
        post(local.address, &[auth.as_str()], body(A, "task")).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    error(
        post(native.address, &[&format!("Bearer {RAW}")], body(A, "task")).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    for bad in [
        "broken",
        r#"["project","01D39ZY06FGSCTVN4T2V9PKHFZ","task"]"#,
        r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task","installation_id":"injected"}"#,
        r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task","installation_id":null}"#,
        r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task","route":"injected"}"#,
        r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task","operation":"publish"}"#,
        r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task","duration":900}"#,
        r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":null}"#,
        r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task","module":"memory"}"#,
        r#"{"scope":"project","module":"task"}"#,
        r#"{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task"}{}"#,
    ] {
        error(
            post(native.address, &[auth.as_str()], Body::from(bad)).await,
            StatusCode::BAD_REQUEST,
            "invalid_json",
        );
    }
    for bad in [
        json!({"scope":"project","project_id":A,"module":"Task"}),
        json!({"scope":"project","project_id":A,"module":"dream"}),
        json!({"scope":"project","project_id":"00000000000000000000000000","module":"task"}),
        json!({"scope":"user","project_id":A,"module":"memory"}),
        json!({"scope":"hub","project_id":A,"module":"hub"}),
    ] {
        error(
            post(
                native.address,
                &[auth.as_str()],
                Body::from(bad.to_string()),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "invalid_scope",
        );
    }
    error(
        post(
            native.address,
            &[auth.as_str()],
            Body::from(vec![b'x'; 20_000]),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "body_too_large",
    );
    let access_auth = Zeroizing::new(format!("Bearer {RAW}"));
    let service_auth = Zeroizing::new(format!("Bearer {SERVICE}"));
    let callers = [
        ("native", native.address, auth.as_str()),
        ("access", local.address, access_auth.as_str()),
        ("service", local.address, service_auth.as_str()),
    ];
    let modules = ["task", "memory", "knowledge", "ast"];
    for module in modules {
        let root = format!("tenant/v1/projects/{A}/corpora/{module}");
        let seed = format!("{root}/dataset/seed");
        let sibling = format!("tenant/v1/projects/{B}/corpora/{module}/dataset/seed");
        let boundary = format!("{root}2/dataset/seed");
        let hub = format!("tenant/v1/projects/{A}/artifacts/seed");
        let user = "tenant/v1/installations/install/users/literal/corpora/memory/seed";
        let global = "tenant/v1/hub/global/registry/seed";
        for key in [&seed, &sibling, &boundary, &hub, user, global] {
            service.seed(key, b"seed");
        }
        for other in modules.into_iter().filter(|other| *other != module) {
            service.seed(
                &format!("tenant/v1/projects/{A}/corpora/{other}/seed"),
                b"other",
            );
        }
        restricted(&mut c, "read", module).await;
        error(
            post(native.address, &[auth.as_str()], body(B, module)).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
        for other in modules
            .into_iter()
            .filter(|other| *other != module)
            .chain(["hub"])
        {
            error(
                post(native.address, &[auth.as_str()], body(A, other)).await,
                StatusCode::FORBIDDEN,
                "forbidden",
            );
        }
        for (actor, address, bearer) in callers {
            eprintln!("corpus read actor {module}/{actor}");
            let keys = success(
                post(address, &[bearer], body(A, module)).await,
                &service,
                &claims,
                module,
            );
            let read = objects(&keys);
            assert_eq!(
                ok(
                    ok(
                        read.get(&ObjectPath::from(seed.clone())).await,
                        "corpus read"
                    )
                    .bytes()
                    .await,
                    "corpus read bytes"
                ),
                Bytes::from_static(b"seed")
            );
            let listing = ok(
                read.list(Some(&ObjectPath::from(root.clone())))
                    .try_collect::<Vec<_>>()
                    .await,
                "corpus listing",
            );
            assert!(listing.iter().any(|m| m.location.as_ref() == seed));
            denied(read.list(None).try_collect::<Vec<_>>().await, &keys);
            denied(
                read.put(
                    &ObjectPath::from(format!("{root}/forbidden")),
                    "forbidden".into(),
                )
                .await,
                &keys,
            );
            denied(read.delete(&ObjectPath::from(seed.clone())).await, &keys);
            for other in [&sibling, &boundary, &hub, user, global] {
                eprintln!("corpus cross-root denial {module}/{actor}/{other}");
                denied(read.get(&ObjectPath::from(other.to_owned())).await, &keys);
                denied(
                    read.list(Some(&ObjectPath::from(other.to_owned())))
                        .try_collect::<Vec<_>>()
                        .await,
                    &keys,
                );
            }
            for other in modules.into_iter().filter(|other| *other != module) {
                denied(
                    read.get(&ObjectPath::from(format!(
                        "tenant/v1/projects/{A}/corpora/{other}/seed"
                    )))
                    .await,
                    &keys,
                );
            }
        }
        for (actor, address, bearer) in callers {
            restricted(&mut c, "write", module).await;
            let keys = success(
                post(address, &[bearer], body(A, module)).await,
                &service,
                &claims,
                module,
            );
            let write = objects(&keys);
            let path = ObjectPath::from(format!("{root}/created-{actor}"));
            let version = ok(
                write
                    .put_opts(
                        &path,
                        "first".into(),
                        PutOptions {
                            mode: PutMode::Create,
                            ..Default::default()
                        },
                    )
                    .await,
                "corpus conditional create",
            );
            assert!(matches!(
                write
                    .put_opts(
                        &path,
                        "duplicate".into(),
                        PutOptions {
                            mode: PutMode::Create,
                            ..Default::default()
                        }
                    )
                    .await,
                Err(object_store::Error::AlreadyExists { .. })
                    | Err(object_store::Error::Precondition { .. })
            ));
            let version = object_store::UpdateVersion {
                e_tag: version.e_tag,
                version: version.version,
            };
            s3_ok(
                write
                    .put_opts(
                        &path,
                        "update".into(),
                        PutOptions {
                            mode: PutMode::Update(version.clone()),
                            ..Default::default()
                        },
                    )
                    .await,
                &format!("corpus CAS update {module}/{actor}"),
                &keys,
            );
            assert!(matches!(
                write
                    .put_opts(
                        &path,
                        "stale".into(),
                        PutOptions {
                            mode: PutMode::Update(version),
                            ..Default::default()
                        }
                    )
                    .await,
                Err(object_store::Error::Precondition { .. })
            ));
            denied(write.delete(&path).await, &keys);
            denied(
                write
                    .put(&ObjectPath::from(sibling.clone()), "escape".into())
                    .await,
                &keys,
            );
            if module == "task" {
                let path = ObjectPath::from(format!("{root}/multipart-{actor}"));
                let mut upload = ok(write.put_multipart(&path).await, "corpus multipart");
                ok(
                    upload.put_part("part".into()).await,
                    "corpus multipart part",
                );
                ok(upload.complete().await, "corpus multipart complete");
                assert!(service.exists(path.as_ref()));
            }
            restricted(&mut c, "publish", module).await;
            let publish_keys = success(
                post(address, &[bearer], body(A, module)).await,
                &service,
                &claims,
                module,
            );
            let publish = objects(&publish_keys);
            ok(publish.get(&path).await, "publish read");
            ok(publish.put(&path, "published".into()).await, "publish put");
            ok(publish.delete(&path).await, "publish delete");
            assert!(!service.exists(path.as_ref()));
            denied(
                publish
                    .put(&ObjectPath::from(hub.clone()), "escape".into())
                    .await,
                &publish_keys,
            );
            restricted(&mut c, "delete", module).await;
            let delete_keys = success(
                post(address, &[bearer], body(A, module)).await,
                &service,
                &claims,
                module,
            );
            let delete = objects(&delete_keys);
            let key = format!("{root}/delete-only-{actor}");
            service.seed(&key, b"delete");
            ok(
                delete.delete(&ObjectPath::from(key.clone())).await,
                "corpus delete only",
            );
            assert!(!service.exists(&key));
            denied(
                delete.get(&ObjectPath::from(seed.clone())).await,
                &delete_keys,
            );
            denied(
                delete.delete(&ObjectPath::from(sibling.clone())).await,
                &delete_keys,
            );
        }
        // A broad project prefix stays restricted to the admitted Hub domain.
        clear(&mut c).await;
        grant(
            &mut c,
            "broad",
            &Rule {
                kind: "authenticated",
                principal: "",
                caps: &["s3"],
                projects: &[A],
                operations: &[],
                prefixes: &["v1/projects/{project}"],
                route: "primary",
            },
        )
        .await;
        let hub_keys = success(
            post(native.address, &[auth.as_str()], body(A, "hub")).await,
            &service,
            &claims,
            "hub",
        );
        let hub_client = objects(&hub_keys);
        ok(
            hub_client.get(&ObjectPath::from(hub.clone())).await,
            "Hub remains admitted",
        );
        denied(
            hub_client.get(&ObjectPath::from(seed.clone())).await,
            &hub_keys,
        );
        denied(
            hub_client
                .put(
                    &ObjectPath::from(format!("{root}/hub-escape")),
                    "escape".into(),
                )
                .await,
            &hub_keys,
        );
        denied(
            hub_client.delete(&ObjectPath::from(seed.clone())).await,
            &hub_keys,
        );
        denied(
            hub_client
                .list(Some(&ObjectPath::from(root.clone())))
                .try_collect::<Vec<_>>()
                .await,
            &hub_keys,
        );
        let current = success(
            post(native.address, &[auth.as_str()], body(A, module)).await,
            &service,
            &claims,
            module,
        );
        clear(&mut c).await;
        error(
            post(native.address, &[auth.as_str()], body(A, module)).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
        // An already-issued STS session keeps its fixed policy; withdrawal denies new issuance.
        ok(
            objects(&current).get(&ObjectPath::from(seed)).await,
            "existing STS session after SQL withdrawal",
        );
    }
    restricted(&mut c, "read", "task").await;
    c.execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
        .await
        .unwrap();
    error(
        post(local.address, &[&format!("Bearer {RAW}")], body(A, "task")).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    c.execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'")
        .await
        .unwrap();
    success(
        post(local.address, &[&format!("Bearer {RAW}")], body(A, "task")).await,
        &service,
        &claims,
        "task",
    );
    grant(
        &mut c,
        "invalid",
        &Rule {
            kind: "authenticated",
            principal: "",
            caps: &["s3"],
            projects: &[B],
            operations: &[],
            prefixes: &["v1/{unknown}"],
            route: "other",
        },
    )
    .await;
    error(
        post(native.address, &[auth.as_str()], body(A, "task")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid_policy",
    );
    restricted(&mut c, "read", "task").await;
    grant(
        &mut c,
        "conflict",
        &Rule {
            kind: "authenticated",
            principal: "",
            caps: &["s3:read"],
            projects: &[A],
            operations: &[],
            prefixes: &["v1/projects/{project}/corpora/task"],
            route: "other",
        },
    )
    .await;
    error(
        post(native.address, &[auth.as_str()], body(A, "task")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "conflicting_routes",
    );
    restricted(&mut c, "read", "task").await;
    c.execute("ALTER TABLE public.resource_acl_state OWNER TO postgres;REVOKE SELECT ON public.resource_acl_state FROM hub_owner").await.unwrap();
    error(
        post(native.address, &[auth.as_str()], body(A, "task")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    error(
        post(local.address, &[&format!("Bearer {RAW}")], body(A, "task")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    c.execute("GRANT SELECT ON public.resource_acl_state TO hub_owner")
        .await
        .unwrap();
    success(
        post(native.address, &[auth.as_str()], body(A, "task")).await,
        &service,
        &claims,
        "task",
    );
    let mut expired = claims.clone();
    expired["iat"] = json!(seconds() - 10);
    expired["exp"] = json!(seconds() - 1);
    error(
        post(
            native.address,
            &[&format!("Bearer {}", signer.sign(&expired))],
            body(A, "task"),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    let mut short = native_config(true);
    short.request_timeout = Duration::from_millis(400);
    let deadline_server = Server::start(
        broker_storage_credentials_router(
            store.clone(),
            verifier.clone(),
            Some(issuer.clone()),
            short,
        )
        .unwrap(),
    )
    .await;
    error(
        post(deadline_server.address, &[auth.as_str()], pending_body()).await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    service.pause();
    error(
        post(deadline_server.address, &[auth.as_str()], body(A, "task")).await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    service.resume();
    deadline_server.stop().await;
    success(
        post(native.address, &[auth.as_str()], body(A, "task")).await,
        &service,
        &claims,
        "task",
    );
    let bad_issuer = Arc::new(
        StorageCredentialsService::new(vec![StorageIssuer::Aws(
            AwsStorageIssuer::new(
                vec![route(&service, &service.caller_key, "wrong-server-secret")],
                Duration::from_secs(5),
            )
            .unwrap(),
        )])
        .unwrap(),
    );
    let bad = Server::start(
        broker_storage_credentials_router(
            store.clone(),
            verifier.clone(),
            Some(bad_issuer),
            native_config(true),
        )
        .unwrap(),
    )
    .await;
    let failed = post(bad.address, &[auth.as_str()], body(A, "task")).await;
    assert_eq!(failed.status, StatusCode::BAD_GATEWAY);
    assert!(matches!(
        field(&failed.data["error"], "code"),
        "storage_credentials_refused" | "storage_credentials_unavailable"
    ));
    bad.stop().await;
    success(
        post(native.address, &[auth.as_str()], body(A, "task")).await,
        &service,
        &claims,
        "task",
    );
    native.stop().await;
    local.stop().await;
    drop(issuer);
    drop(service);
    c.close().await.unwrap();
    drop(f);
}
