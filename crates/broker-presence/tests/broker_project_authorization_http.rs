#[allow(
    dead_code,
    reason = "shared PostgreSQL fixture also serves other control suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::BrokerAccessVerifier;
use broker_control::{
    ConnectionLimits, PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use broker_presence::{BrokerProjectAuthorizationHttpConfig, broker_project_authorization_router};
use http_body_util::BodyExt;
use hyper::body::Body as _;
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use tokio::net::{TcpListener, TcpStream};

const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const PATH: &str = "/v1/project/access/authorize";
const ISSUER: &str = "https://broker.example.test";
const RESOURCE: &str = "https://broker.example.test/v1";
const SUBJECT: &str = "broker-subject";
const JTI: &str = "jwt-native-token";
struct Signer {
    key: EncodingKey,
    keys: jsonwebtoken::jwk::JwkSet,
}
impl Signer {
    fn new() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self {
            key: EncodingKey::from_ed_der(&pair.serialize_der()),
            keys: serde_json::from_value(json!({"keys":[{
                "kty":"OKP","crv":"Ed25519","kid":"project-key",
                "x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())
            }]}))
            .unwrap(),
        }
    }
    fn verifier(&self) -> BrokerAccessVerifier {
        BrokerAccessVerifier::new(ISSUER, "project-api", Some(RESOURCE), &self.keys, n(8192))
            .unwrap()
    }
    fn claims(&self) -> Value {
        let now = seconds();
        json!({"iss":ISSUER,"sub":SUBJECT,"aud":["project-api",RESOURCE],"iat":now-1,"exp":now+600,
            "token_use":"access","client_id":"approved-client","jti":JTI,"scope":"project-sdk",
            "preferred_username":"alice","organization":"engineering","groups":["dev"],"roles":["admin"]})
    }
    fn sign(&self, claims: &Value) -> String {
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("project-key".into());
        encode(&h, claims, &self.key).unwrap()
    }
}
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn config() -> BrokerProjectAuthorizationHttpConfig {
    BrokerProjectAuthorizationHttpConfig {
        required_scopes: vec!["project-sdk".into()],
        grants_json_bytes: n(65536),
        body_bytes: n(1024),
        request_timeout: Duration::from_secs(4),
    }
}
fn store_config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "jwt_http_owner".into(),
            zeroize::Zeroizing::new("ephemeral-owner".into()),
        ),
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
fn input(project: &str, module: &str, action: &str) -> String {
    serde_json::json!({"project_id":project,"module":module,"action":action}).to_string()
}
async fn clear(c: &mut PgConnection) {
    c.execute("DELETE FROM public.resource_grants; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
}
async fn grant(c: &mut PgConnection, id: &str, who: &str, cap: &str, project: &str) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture','subject',$2,'',0,0)").bind(id).bind(who).execute(&mut *c).await.unwrap();
    sqlx_core::query::query("INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)")
        .bind(id)
        .bind(cap)
        .execute(&mut *c)
        .await
        .unwrap();
    sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
        .bind(id)
        .bind(project)
        .execute(&mut *c)
        .await
        .unwrap();
}
struct Server {
    address: std::net::SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
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
            stop,
            task,
        }
    }
    async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(6), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}
async fn exchange(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    auth: &[&str],
    content_type: Option<&str>,
    body: Body,
) -> (StatusCode, serde_json::Value, bool) {
    let streaming = body.size_hint().exact().is_none();
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let mut request = Request::builder().method(method).uri(path);
    if let Some(ct) = content_type {
        request = request.header(header::CONTENT_TYPE, ct);
    }
    for a in auth {
        request = request.header(header::AUTHORIZATION, *a);
    }
    let reply = tokio::time::timeout(
        Duration::from_secs(8),
        sender.send_request(request.body(body).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let status = reply.status();
    let scope_challenge = reply.headers().get(header::WWW_AUTHENTICATE).cloned();
    let challenge = reply
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .is_some_and(|v| v == "Bearer");
    assert_eq!(
        reply.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let bytes = reply.into_body().collect().await.unwrap().to_bytes();
    let json = if method == "HEAD" {
        assert!(bytes.is_empty());
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    if json["error"]["code"] == "insufficient_scope" {
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            scope_challenge.unwrap(),
            "Bearer error=\"insufficient_scope\""
        );
    }
    drop(sender);
    let outcome = tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = outcome {
        assert!(
            streaming && status == StatusCode::GATEWAY_TIMEOUT && error.is_incomplete_message(),
            "HTTP connection failed after response: status={status}, streaming={streaming}, error={error}"
        );
    }
    (status, json, challenge)
}
async fn post(
    address: std::net::SocketAddr,
    auth: &[&str],
    raw: String,
) -> (StatusCode, serde_json::Value, bool) {
    exchange(
        address,
        "POST",
        PATH,
        auth,
        Some("application/json"),
        Body::from(raw),
    )
    .await
}
fn error(reply: (StatusCode, serde_json::Value, bool), status: StatusCode, code: &str) {
    assert_eq!(reply.0, status);
    assert_eq!(reply.1, serde_json::json!({"error":{"code":code}}));
    assert_eq!(reply.2, status == StatusCode::UNAUTHORIZED);
}
async fn observe_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='jwt_http_owner' AND wait_event_type='Lock' AND query LIKE '%resource_acl_state%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(
            Instant::now() < end,
            "HTTP request reaches real ACL SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "real TCP Broker JWT PROJECT endpoint and PostgreSQL TLS ordinary owner"]
async fn broker_project_authorization_http_postgres_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE jwt_http_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION jwt_http_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO jwt_http_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(store_config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='jwt_http_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let raw = signer.sign(&signer.claims());
    let auth = format!("Bearer {raw}");
    let server = Server::start(
        broker_project_authorization_router(store.clone(), verifier.clone(), config()).unwrap(),
    )
    .await;
    // JWT authentication needs no auth tables. Privilege denial is effective, not a mock.
    c.execute("REVOKE SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients FROM jwt_http_owner").await.unwrap();
    let privilege: bool = sqlx_core::query_scalar::query_scalar("SELECT has_table_privilege('jwt_http_owner','public.local_users','SELECT') OR has_table_privilege('jwt_http_owner','public.local_tokens','SELECT') OR has_table_privilege('jwt_http_owner','public.oauth_dynamic_clients','SELECT')").fetch_one(&mut c).await.unwrap();
    assert!(!privilege);

    // Logical Hub PROJECT read does not inherit Knowledge or S3 permissions.
    clear(&mut c).await;
    grant(&mut c, "hub", &format!("{ISSUER}|{SUBJECT}"), "hub", A).await;
    let hub = post(server.address, &[&auth], input(A, "hub", "read")).await;
    let revision: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT revision FROM public.resource_acl_state WHERE id=1",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(hub.0, StatusCode::OK);
    assert_eq!(
        hub.1,
        serde_json::json!({"subject":{"issuer":ISSUER,"subject":SUBJECT},"authorization_revision":revision,"project_id":A,"module":"hub","action":"read"})
    );
    error(
        post(server.address, &[&auth], input(A, "hub", "write")).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    );
    error(
        post(server.address, &[&auth], input(B, "hub", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    error(
        post(server.address, &["Bearer invalid"], input(A, "hub", "read")).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    c.execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
        .await
        .unwrap();
    let next = post(server.address, &[&auth], input(A, "hub", "read")).await;
    assert_eq!(next.0, StatusCode::OK);
    assert_eq!(
        next.1["authorization_revision"].as_i64().unwrap(),
        revision + 1
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='hub'")
        .await
        .unwrap();
    error(
        post(server.address, &[&auth], input(A, "hub", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    for cap in ["knowledge:read", "s3", "s3:read", "hub:read", "hub:write"] {
        clear(&mut c).await;
        grant(&mut c, "substitute", &format!("{ISSUER}|{SUBJECT}"), cap, A).await;
        error(
            post(server.address, &[&auth], input(A, "hub", "read")).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
    }
    clear(&mut c).await;
    grant(&mut c, "hub-b", &format!("{ISSUER}|{SUBJECT}"), "hub", B).await;
    grant(
        &mut c,
        "project-a",
        &format!("{ISSUER}|{SUBJECT}"),
        "knowledge:read",
        A,
    )
    .await;
    grant(&mut c, "other", "other", "hub", A).await;
    error(
        post(server.address, &[&auth], input(A, "hub", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    for module in ["task", "memory", "knowledge", "ast"] {
        for action in ["read", "write"] {
            clear(&mut c).await;
            grant(
                &mut c,
                "logical",
                &format!("{ISSUER}|{SUBJECT}"),
                &format!("{module}:{action}"),
                A,
            )
            .await;
            let reply = post(server.address, &[&auth], input(A, module, action)).await;
            let revision: i64 = sqlx_core::query_scalar::query_scalar(
                "SELECT revision FROM public.resource_acl_state WHERE id=1",
            )
            .fetch_one(&mut c)
            .await
            .unwrap();
            assert_eq!(reply.0, StatusCode::OK);
            assert!(!reply.2);
            assert_eq!(
                reply.1,
                json!({"subject":{"issuer":ISSUER,"subject":SUBJECT},"authorization_revision":revision,"project_id":A,"module":module,"action":action})
            );
            for (project, m, a) in [
                (B, module, action),
                (A, module, if action == "read" { "write" } else { "read" }),
                (A, if module == "task" { "ast" } else { "task" }, action),
            ] {
                error(
                    post(server.address, &[&auth], input(project, m, a)).await,
                    StatusCode::FORBIDDEN,
                    "forbidden",
                );
            }
        }
    }
    clear(&mut c).await;
    grant(&mut c, "other-subject", "other", "task:read", A).await;
    error(
        post(server.address, &[&auth], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    clear(&mut c).await;
    grant(&mut c, "cap-b", SUBJECT, "task:read", B).await;
    grant(&mut c, "project-a", SUBJECT, "task:write", A).await;
    error(
        post(server.address, &[&auth], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    clear(&mut c).await;
    grant(&mut c, "logical", SUBJECT, "task:read", A).await;
    let first = post(server.address, &[&auth], input(A, "task", "read")).await;
    c.execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
        .await
        .unwrap();
    let second = post(server.address, &[&auth], input(A, "task", "read")).await;
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(
        second.1["authorization_revision"].as_i64().unwrap(),
        first.1["authorization_revision"].as_i64().unwrap() + 1
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='logical'")
        .await
        .unwrap();
    error(
        post(server.address, &[&auth], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    grant(&mut c, "logical", SUBJECT, "task:read", A).await;
    // Rejections authenticate before any SQL grants read.
    c.execute("REVOKE SELECT ON public.resource_grants FROM jwt_http_owner")
        .await
        .unwrap();
    for field in ["iss", "aud", "token_use", "client_id", "exp"] {
        let mut claims = signer.claims();
        claims[field] = match field {
            "exp" => json!(seconds() - 1),
            "aud" => json!(["project-api", "other-resource"]),
            "scope" => json!("other-scope"),
            "client_id" => json!(""),
            _ => json!("wrong"),
        };
        error(
            post(
                server.address,
                &[&format!("Bearer {}", signer.sign(&claims))],
                input(A, "task", "read"),
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    let mut scope_claims = signer.claims();
    scope_claims["scope"] = json!("other");
    error(
        post(
            server.address,
            &[&format!("Bearer {}", signer.sign(&scope_claims))],
            input(A, "task", "read"),
        )
        .await,
        StatusCode::FORBIDDEN,
        "insufficient_scope",
    );
    let rogue = Signer::new();
    error(
        post(
            server.address,
            &[&format!("Bearer {}", rogue.sign(&rogue.claims()))],
            input(A, "task", "read"),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    for headers in [
        vec![],
        vec![auth.as_str(), auth.as_str()],
        vec!["Basic fake"],
        vec!["Bearer gb_at_opaque"],
        vec!["Bearer a.b.c"],
    ] {
        error(
            post(server.address, &headers, input(A, "task", "read")).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    error(
        post(server.address, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    c.execute("GRANT SELECT ON public.resource_grants TO jwt_http_owner")
        .await
        .unwrap();
    grant(&mut c, "unrelated", "nobody", "task:read", "[").await;
    error(
        post(server.address, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid_policy",
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='unrelated'")
        .await
        .unwrap();
    let mut cfg = config();
    cfg.grants_json_bytes = n(1);
    let capped = Server::start(
        broker_project_authorization_router(store.clone(), verifier.clone(), cfg).unwrap(),
    )
    .await;
    error(
        post(capped.address, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    capped.stop().await;
    let saved_revision: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT revision FROM public.resource_acl_state WHERE id=1",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    c.execute("DELETE FROM public.resource_acl_state WHERE id=1")
        .await
        .unwrap();
    error(
        post(server.address, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    sqlx_core::query::query(
        "INSERT INTO public.resource_acl_state(id,revision,updated_at) VALUES(1,$1,0)",
    )
    .bind(saved_revision)
    .execute(&mut c)
    .await
    .unwrap();
    // The exact shared HTTP parser and finite fallbacks are exercised by both factories.
    for raw in [
        "{}".into(),
        serde_json::json!([A, "task", "read"]).to_string(),
        serde_json::json!({"project_id":A,"module":{"task":null},"action":"read"}).to_string(),
        serde_json::json!({"project_id":A,"module":"task","action":{"read":null}}).to_string(),
        serde_json::json!({"project_id":A,"module":[],"action":"read"}).to_string(),
        serde_json::json!({"project_id":A,"module":"task","action":[]}).to_string(),
        input(A, "Task", "read"),
        input(A, "task", "Read"),
        input(A, "hub", "write"),
        input(A, "task", "delete"),
        format!(r#"{{"project_id":"{A}","module":"task","action":"read","subject":"forged"}}"#),
        format!(r#"{{"project_id":"{A}","module":"task","action":"read","version":"main"}}"#),
        format!(r#"{{"project_id":"{A}","project_id":"{B}","module":"task","action":"read"}}"#),
        format!(r#"{{"project_id":"{A}","module":"task","module":"ast","action":"read"}}"#),
        format!(r#"{{"project_id":"{A}","module":"task","action":"read","action":"write"}}"#),
        r#"{"project_id":null,"module":"task","action":"read"}"#.to_string(),
        format!(r#"{{"project_id":"{A}","module":1,"action":"read"}}"#),
        format!("{} {{}}", input(A, "task", "read")),
        input("00000000000000000000000000", "task", "read"),
        input(&A.to_lowercase(), "task", "read"),
        input("project", "task", "read"),
    ] {
        error(
            post(server.address, &[auth.as_str()], raw).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
    }
    error(
        exchange(
            server.address,
            "POST",
            &format!("{PATH}?subject=forged"),
            &[auth.as_str()],
            Some("application/json"),
            Body::from(input(A, "task", "read")),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    );
    error(
        exchange(
            server.address,
            "POST",
            PATH,
            &[auth.as_str()],
            Some("application/json"),
            Body::from(vec![0xff]),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    );
    error(
        exchange(
            server.address,
            "POST",
            PATH,
            &[auth.as_str()],
            None,
            Body::from(input(A, "task", "read")),
        )
        .await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    );
    error(
        exchange(
            server.address,
            "POST",
            PATH,
            &[auth.as_str()],
            Some("text/plain"),
            Body::from(input(A, "task", "read")),
        )
        .await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    );
    error(
        post(server.address, &[auth.as_str()], " ".repeat(2048)).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "body_too_large",
    );
    let chunks =
        futures_util::stream::iter([Ok::<Bytes, std::io::Error>(Bytes::from(vec![b' '; 2048]))]);
    error(
        exchange(
            server.address,
            "POST",
            PATH,
            &[auth.as_str()],
            Some("application/json"),
            Body::from_stream(chunks),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "body_too_large",
    );
    for headers in [
        vec![],
        vec![auth.as_str(), auth.as_str()],
        vec!["Basic fake"],
        vec!["Bearer invalid"],
        vec!["Bearer gb_rt_refresh"],
        vec!["Bearer a.b.c"],
        vec!["Bearer gb_at_not-issued"],
    ] {
        error(
            post(server.address, &headers, input(A, "task", "read")).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    for method in ["GET", "PUT", "PATCH", "DELETE"] {
        error(
            exchange(server.address, method, PATH, &[], None, Body::empty()).await,
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
        );
    }
    let head = exchange(server.address, "HEAD", PATH, &[], None, Body::empty()).await;
    assert_eq!(head.0, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(head.1, serde_json::Value::Null);
    assert!(!head.2);
    for path in [
        "/v1/project/access/authorize/",
        "/v1/project/access",
        "/v1/hub/access/resolve",
    ] {
        error(
            exchange(server.address, "POST", path, &[], None, Body::empty()).await,
            StatusCode::NOT_FOUND,
            "not_found",
        );
    }

    // Expiration after a real SQL lock must beat both allow and forbidden.
    for allowed in [true, false] {
        clear(&mut c).await;
        if allowed {
            grant(&mut c, "logical", SUBJECT, "task:read", A).await;
        }
        let mut claims = signer.claims();
        let exp = seconds() + 2;
        claims["exp"] = json!(exp);
        let credential = format!("Bearer {}", signer.sign(&claims));
        let mut held = c.begin().await.unwrap();
        held.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let address = server.address;
        let request =
            tokio::spawn(
                async move { post(address, &[&credential], input(A, "task", "read")).await },
            );
        let mut monitor = f.connection().await;
        observe_lock(&mut monitor).await;
        assert!(!request.is_finished());
        assert!(seconds() < exp, "JWT is still valid at observed SQL lock");
        while seconds() < exp {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        held.rollback().await.unwrap();
        error(
            request.await.unwrap(),
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
        monitor.close().await.unwrap();
    }
    clear(&mut c).await;
    grant(&mut c, "logical", SUBJECT, "task:read", A).await;
    let mut cfg = config();
    cfg.request_timeout = Duration::from_secs(2);
    let timed = Server::start(
        broker_project_authorization_router(store.clone(), verifier.clone(), cfg).unwrap(),
    )
    .await;
    let chunks = futures_util::stream::once(async {
        tokio::time::sleep(Duration::from_secs(3)).await;
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"{}"))
    });
    error(
        exchange(
            timed.address,
            "POST",
            PATH,
            &[&auth],
            Some("application/json"),
            Body::from_stream(chunks),
        )
        .await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    let mut held = c.begin().await.unwrap();
    held.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let address = timed.address;
    let credential = auth.clone();
    let chunks = futures_util::stream::once(async {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        Ok::<Bytes, std::io::Error>(Bytes::from(input(A, "task", "read")))
    });
    let started = Instant::now();
    let request = tokio::spawn(async move {
        exchange(
            address,
            "POST",
            PATH,
            &[&credential],
            Some("application/json"),
            Body::from_stream(chunks),
        )
        .await
    });
    let mut monitor = f.connection().await;
    observe_lock(&mut monitor).await;
    error(
        request.await.unwrap(),
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    assert!(
        started.elapsed() < Duration::from_millis(2900),
        "body and SQL share Original end"
    );
    held.rollback().await.unwrap();
    monitor.close().await.unwrap();
    assert_eq!(
        post(timed.address, &[&auth], input(A, "task", "read"))
            .await
            .0,
        StatusCode::OK
    );
    timed.stop().await;
    // Drop a real client transport during SQL; do not retain its response or authority.
    let mut held = c.begin().await.unwrap();
    held.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let stream = TcpStream::connect(server.address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let outgoing = Request::builder()
        .method("POST")
        .uri(PATH)
        .header(header::AUTHORIZATION, &auth)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(input(A, "task", "read")))
        .unwrap();
    let request = tokio::spawn(async move { sender.send_request(outgoing).await });
    let mut monitor = f.connection().await;
    observe_lock(&mut monitor).await;
    assert!(!request.is_finished());
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    request.abort();
    match request.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(response) => assert!(
            response.is_err(),
            "transport closure cannot produce an authorization response"
        ),
    }
    held.rollback().await.unwrap();
    monitor.close().await.unwrap();
    assert_eq!(
        post(server.address, &[&auth], input(A, "task", "read"))
            .await
            .0,
        StatusCode::OK
    );
    store.shutdown(deadline()).await.unwrap();
    error(
        post(server.address, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "closed",
    );
    server.stop().await;
    let reopened = PostgresControlStore::open(store_config(&f), support::digester(), deadline())
        .await
        .unwrap();
    reopened.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
