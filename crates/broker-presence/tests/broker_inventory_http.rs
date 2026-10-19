#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other control suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
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
    BrokerOwnReadHttpConfig, BrokerPublishHttpConfig, broker_instance_inventory_router,
};
use broker_security::TokenKind;
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
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
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
        BrokerAccessVerifier::new(ISSUER, "presence-api", Some(RESOURCE), &self.keys, n(8192))
            .unwrap()
    }
    fn claims(&self) -> Value {
        let now = seconds();
        json!({"iss":ISSUER,"sub":SUBJECT,"aud":["presence-api",RESOURCE],"iat":now-1,"exp":now+600,
            "token_use":"access","client_id":"approved-client","jti":JTI,"scope":"presence-sdk",
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
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "native_http_owner".into(),
            Zeroizing::new("ephemeral-owner".into()),
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
async fn grant(
    c: &mut PgConnection,
    id: &str,
    kind: &str,
    principal: &str,
    caps: &[&str],
    projects: &[&str],
) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture',$2,$3,'',0,0)")
        .bind(id).bind(kind).bind(principal).execute(&mut *c).await.unwrap();
    for cap in caps {
        sqlx_core::query::query(
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
        )
        .bind(id)
        .bind(*cap)
        .execute(&mut *c)
        .await
        .unwrap();
    }
    for project in projects {
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(*project)
            .execute(&mut *c)
            .await
            .unwrap();
    }
}
async fn oracle(c: &mut PgConnection) -> String {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('instances',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.broker_instances ORDER BY instance_id COLLATE \"C\") t),'versions',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.broker_instance_project_versions ORDER BY instance_id COLLATE \"C\",project_id COLLATE \"C\",position) t))::text").fetch_one(c).await.unwrap()
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
        tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}
fn request(method: &str, path: &str, auth: &[&str], body: Body) -> Request<Body> {
    let mut r = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    for auth in auth {
        r = r.header(header::AUTHORIZATION, *auth);
    }
    r.body(body).unwrap()
}
async fn exchange(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    auth: &[&str],
    body: Body,
) -> (StatusCode, serde_json::Value, Option<String>) {
    let streaming = body.size_hint().exact().is_none();
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let reply = tokio::time::timeout(
        Duration::from_secs(10),
        sender.send_request(request(method, path, auth, body)),
    )
    .await
    .unwrap()
    .unwrap();
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
    let bytes = reply.into_body().collect().await.unwrap().to_bytes();
    let json = if method == "HEAD" {
        assert!(bytes.is_empty());
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    drop(sender);
    let connection_result = tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = connection_result {
        assert!(
            streaming && status == StatusCode::GATEWAY_TIMEOUT && error.is_incomplete_message(),
            "unexpected HTTP connection error method={method} status={status} streaming={streaming}: {error:?}"
        );
    }
    (status, json, challenge)
}
async fn get(
    address: std::net::SocketAddr,
    id: &str,
    auth: &[&str],
) -> (StatusCode, serde_json::Value, Option<String>) {
    exchange(
        address,
        "GET",
        &format!("/v1/instances/{id}/inventory"),
        auth,
        Body::empty(),
    )
    .await
}
fn error(reply: (StatusCode, Value, Option<String>), status: StatusCode, code: &str) {
    assert_eq!(reply.0, status);
    assert_eq!(reply.1, json!({"error":{"code":code}}));
    let expected = if status == StatusCode::UNAUTHORIZED {
        Some("Bearer")
    } else if code == "insufficient_scope" {
        Some("Bearer error=\"insufficient_scope\"")
    } else {
        None
    };
    assert_eq!(reply.2.as_deref(), expected);
}

fn publish_config() -> BrokerPublishHttpConfig {
    BrokerPublishHttpConfig {
        required_scopes: vec!["presence-sdk".into()],
        grants_json_bytes: n(65536),
        body_bytes: n(8192),
        request_timeout: Duration::from_secs(6),
    }
}
fn read_config() -> BrokerOwnReadHttpConfig {
    BrokerOwnReadHttpConfig {
        required_scopes: vec!["presence-sdk".into()],
        grants_json_bytes: n(65536),
        inventory_json_bytes: n(65536),
        request_timeout: Duration::from_secs(6),
    }
}
fn input(projects: &[(&str, &[&str])]) -> String {
    json!({"projects":projects.iter().map(|(p,v)|json!({"project_id":p,"versions":v})).collect::<Vec<_>>()}).to_string()
}
async fn put(
    address: std::net::SocketAddr,
    id: &str,
    auth: &str,
    body: String,
) -> (StatusCode, Value, Option<String>) {
    exchange(
        address,
        "PUT",
        &format!("/v1/instances/{id}/inventory"),
        &[auth],
        Body::from(body),
    )
    .await
}
async fn observe_lock(c: &mut PgConnection, inventory: bool) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='native_http_owner' AND wait_event_type='Lock' AND query LIKE $1)")
            .bind(if inventory {"%broker_instances%"} else {"%resource_acl_state%"}).fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(Instant::now() < end, "HTTP reaches actual SQL lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real TCP Axum/Hyper, PostgreSQL TLS, Ed25519 and Native inventory producers"]
async fn broker_inventory_http_postgres_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE native_http_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION native_http_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO native_http_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let privileged: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='native_http_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!privileged);
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let raw = signer.sign(&signer.claims());
    let auth = format!("Bearer {raw}");
    assert_eq!(
        format!("{:?}", publish_config()),
        "BrokerPublishHttpConfig([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", read_config()),
        "BrokerOwnReadHttpConfig([REDACTED])"
    );
    for publish in [true, false] {
        for case in 0..if publish { 4 } else { 5 } {
            let mut p = publish_config();
            let mut r = read_config();
            if publish {
                match case {
                    0 => p.request_timeout = Duration::ZERO,
                    1 => p.request_timeout = Duration::MAX,
                    2 => p.required_scopes = vec![" ".into()],
                    3 => p.grants_json_bytes = n(usize::MAX),
                    _ => p.grants_json_bytes = n(usize::MAX),
                }
            } else {
                match case {
                    0 => r.request_timeout = Duration::ZERO,
                    1 => r.request_timeout = Duration::MAX,
                    2 => r.required_scopes = vec![" ".into()],
                    3 => r.grants_json_bytes = n(usize::MAX),
                    _ => r.inventory_json_bytes = n(usize::MAX),
                }
            }
            assert!(
                broker_instance_inventory_router(store.clone(), verifier.clone(), p, r).is_err()
            );
        }
    }
    let server = Server::start(
        broker_instance_inventory_router(
            store.clone(),
            verifier.clone(),
            publish_config(),
            read_config(),
        )
        .unwrap(),
    )
    .await;
    let path = "/v1/instances/station/inventory";
    for method in ["GET", "PUT"] {
        for headers in [
            vec![],
            vec!["Basic ignored"],
            vec!["Bearer "],
            vec!["Bearer opaque-local"],
            vec![auth.as_str(), auth.as_str()],
        ] {
            error(
                exchange(
                    server.address,
                    method,
                    path,
                    &headers,
                    Body::from("{\"projects\":[]}"),
                )
                .await,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
            );
        }
        let mut invalid = signer.claims();
        invalid["scope"] = json!("other");
        error(
            exchange(
                server.address,
                method,
                path,
                &[&format!("Bearer {}", signer.sign(&invalid))],
                Body::from("{\"projects\":[]}"),
            )
            .await,
            StatusCode::FORBIDDEN,
            "insufficient_scope",
        );
        for (field, value) in [
            ("aud", json!(["other", RESOURCE])),
            ("token_use", json!("id")),
            ("exp", json!(seconds() - 1)),
        ] {
            let mut invalid = signer.claims();
            invalid[field] = value;
            error(
                exchange(
                    server.address,
                    method,
                    path,
                    &[&format!("Bearer {}", signer.sign(&invalid))],
                    Body::from("{\"projects\":[]}"),
                )
                .await,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
            );
        }
        let wrong = Signer::new();
        error(
            exchange(
                server.address,
                method,
                path,
                &[&format!("Bearer {}", wrong.sign(&wrong.claims()))],
                Body::from("{\"projects\":[]}"),
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    error(
        exchange(
            server.address,
            "GET",
            &format!("{path}?access_token={raw}"),
            &[],
            Body::empty(),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    error(
        exchange(
            server.address,
            "GET",
            path,
            &[],
            Body::from(json!({"access_token":raw}).to_string()),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    for bad in [
        r#"[[]]"#,
        r#"{"projects":[["01D39ZY06FGSCTVN4T2V9PKHFZ",["main"]]]}"#,
        r#"{"projects":[],"projects":[]}"#,
        r#"{"projects":[],"owner":"fake"}"#,
        r#"{"projects":[{"project_id":"x","project_id":"y","versions":["main"]}]}"#,
        r#"{"projects":[{"project_id":"x"}]}"#,
        r#"{"projects":[]} {}"#,
        r#"{"projects":null}"#,
        r#"{}"#,
    ] {
        let before = oracle(&mut c).await;
        error(
            put(server.address, "station", &auth, bad.into()).await,
            StatusCode::BAD_REQUEST,
            "invalid_json",
        );
        assert_eq!(oracle(&mut c).await, before);
    }
    for bad in [
        input(&[("bad", &["main"])]),
        input(&[(A, &[])]),
        input(&[(A, &[" main "])]),
        input(&[(A, &["main", "main"])]),
        input(&[(A, &["main"]), (A, &["main"])]),
    ] {
        error(
            put(server.address, "station", &auth, bad).await,
            StatusCode::BAD_REQUEST,
            "invalid_inventory",
        );
    }
    for method in ["GET", "PUT"] {
        for id in ["bad%20id", "%FF"] {
            error(
                exchange(
                    server.address,
                    method,
                    &format!("/v1/instances/{id}/inventory"),
                    &[&auth],
                    Body::from("{\"projects\":[]}"),
                )
                .await,
                StatusCode::BAD_REQUEST,
                "invalid_inventory",
            );
        }
    }
    error(
        put(
            server.address,
            "station",
            &auth,
            input(&[(A, &["main"]), (B, &["main"])]),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    grant(
        &mut c,
        "pub-a",
        "subject",
        SUBJECT,
        &["presence:publish"],
        &[A],
    )
    .await;
    error(
        put(
            server.address,
            "station",
            &auth,
            input(&[(A, &["main"]), (B, &["main"])]),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    grant(
        &mut c,
        "pub-b",
        "user",
        "alice",
        &["presence:publish"],
        &[B],
    )
    .await;
    let body = input(&[(B, &["release.1", "main"]), (A, &["main", "branch/ação"])]);
    let created = put(server.address, "station", &auth, body.clone()).await;
    assert_eq!(created.0, StatusCode::CREATED);
    assert_eq!(created.1["change"], "created");
    assert_eq!(created.1.as_object().unwrap().len(), 4);
    let unchanged = put(server.address, "station", &auth, body).await;
    assert_eq!(unchanged.0, StatusCode::OK);
    assert_eq!(unchanged.1["change"], "unchanged");
    assert_eq!(unchanged.1["created_at"], created.1["created_at"]);
    assert_eq!(unchanged.1["updated_at"], created.1["updated_at"]);
    error(
        get(server.address, "station", &[&auth]).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    grant(
        &mut c,
        "read-a",
        "subject",
        &format!("{ISSUER}|{SUBJECT}"),
        &["presence:read"],
        &[A],
    )
    .await;
    error(
        get(server.address, "station", &[&auth]).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    grant(&mut c, "read-b", "user", "alice", &["presence:read"], &[B]).await;
    let read = get(server.address, "station", &[&auth]).await;
    assert_eq!(read.0, StatusCode::OK);
    assert_eq!(
        read.1,
        json!({"instance_id":"station","projects":[{"project_id":A,"versions":["branch/ação","main"]},{"project_id":B,"versions":["main","release.1"]}],"created_at":created.1["created_at"],"updated_at":created.1["updated_at"]})
    );
    let modified = put(server.address, "station", &auth, input(&[(A, &["main"])])).await;
    assert_eq!(modified.0, StatusCode::OK);
    assert_eq!(modified.1["change"], "updated");
    assert_eq!(modified.1["created_at"], created.1["created_at"]);
    assert_eq!(
        get(server.address, "station", &[&auth]).await.1["projects"],
        json!([{"project_id":A,"versions":["main"]}])
    );
    error(
        get(server.address, "absent", &[&auth]).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    let mut other = signer.claims();
    other["sub"] = json!("foreign");
    let other_auth = format!("Bearer {}", signer.sign(&other));
    for method in ["GET", "PUT"] {
        error(
            exchange(
                server.address,
                method,
                path,
                &[&other_auth],
                Body::from(input(&[(A, &["main"])])),
            )
            .await,
            if method == "PUT" {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::CONFLICT
            },
            if method == "PUT" {
                "forbidden"
            } else {
                "owner_conflict"
            },
        );
    }
    grant(
        &mut c,
        "other-publish",
        "authenticated",
        "",
        &["presence:publish"],
        &["*"],
    )
    .await;
    error(
        put(
            server.address,
            "station",
            &other_auth,
            input(&[(A, &["main"])]),
        )
        .await,
        StatusCode::CONFLICT,
        "owner_conflict",
    );
    c.execute("INSERT INTO public.broker_instances(instance_id,owner_issuer,owner_subject,created_at,updated_at) VALUES('opaque','local','broker-subject',0,0)").await.unwrap();
    error(
        get(server.address, "opaque", &[&auth]).await,
        StatusCode::CONFLICT,
        "owner_conflict",
    );
    error(
        put(server.address, "opaque", &auth, input(&[])).await,
        StatusCode::CONFLICT,
        "owner_conflict",
    );
    // Empty Any Publish exists but finite Read selectors still deny empty data.
    assert_eq!(
        put(server.address, "empty", &auth, input(&[])).await.0,
        StatusCode::CREATED
    );
    error(
        get(server.address, "empty", &[&auth]).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    grant(
        &mut c,
        "any-read",
        "subject",
        SUBJECT,
        &["presence:read"],
        &[],
    )
    .await;
    assert_eq!(
        get(server.address, "empty", &[&auth]).await.1["projects"],
        json!([])
    );
    for (method, headers, status) in [
        ("HEAD", vec![auth.as_str()], StatusCode::OK),
        ("HEAD", vec![], StatusCode::UNAUTHORIZED),
    ] {
        let reply = exchange(server.address, method, path, &headers, Body::empty()).await;
        assert_eq!(reply.0, status);
        assert!(reply.1.is_null());
    }
    error(
        exchange(server.address, "DELETE", path, &[&auth], Body::empty()).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    );
    error(
        exchange(
            server.address,
            "GET",
            "/v1/instances",
            &[&auth],
            Body::empty(),
        )
        .await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    let before = oracle(&mut c).await;
    for (change, restore, status, code) in [
        (
            "DELETE FROM public.resource_grants WHERE id='any-read'; DELETE FROM public.grant_capabilities WHERE grant_id='read-a'; INSERT INTO public.grant_capabilities(grant_id,value) VALUES('read-a','presence:publish'); UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1",
            "DELETE FROM public.grant_capabilities WHERE grant_id='read-a'; INSERT INTO public.grant_capabilities(grant_id,value) VALUES('read-a','presence:read')",
            StatusCode::FORBIDDEN,
            "forbidden",
        ),
        (
            "UPDATE public.resource_grants SET principal='[' WHERE id='read-b'",
            "UPDATE public.resource_grants SET principal='alice' WHERE id='read-b'",
            StatusCode::SERVICE_UNAVAILABLE,
            "invalid_policy",
        ),
        (
            "UPDATE public.broker_instance_project_versions SET position=4 WHERE instance_id='station'",
            "UPDATE public.broker_instance_project_versions SET position=1 WHERE instance_id='station'",
            StatusCode::SERVICE_UNAVAILABLE,
            "inventory_unavailable",
        ),
        (
            "REVOKE SELECT ON public.resource_grants FROM native_http_owner",
            "GRANT SELECT ON public.resource_grants TO native_http_owner",
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization_unavailable",
        ),
        (
            "REVOKE SELECT ON public.broker_instance_project_versions FROM native_http_owner",
            "GRANT SELECT ON public.broker_instance_project_versions TO native_http_owner",
            StatusCode::SERVICE_UNAVAILABLE,
            "inventory_unavailable",
        ),
    ] {
        c.execute(change).await.unwrap();
        let corrupted = oracle(&mut c).await;
        error(get(server.address, "station", &[&auth]).await, status, code);
        assert_eq!(oracle(&mut c).await, corrupted);
        c.execute(restore).await.unwrap();
        assert_eq!(
            get(server.address, "station", &[&auth]).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(oracle(&mut c).await, before);
    for index in 0..3 {
        let mut p = publish_config();
        let mut r = read_config();
        match index {
            0 => p.body_bytes = n(1),
            1 => r.grants_json_bytes = n(1),
            _ => r.inventory_json_bytes = n(1),
        }
        let limited = Server::start(
            broker_instance_inventory_router(store.clone(), verifier.clone(), p, r).unwrap(),
        )
        .await;
        if index == 0 {
            error(
                put(limited.address, "station", &auth, input(&[])).await,
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
            );
        } else {
            error(
                get(limited.address, "station", &[&auth]).await,
                StatusCode::SERVICE_UNAVAILABLE,
                if index == 1 {
                    "authorization_unavailable"
                } else {
                    "inventory_unavailable"
                },
            );
        }
        limited.stop().await;
    }
    // Signed identity remains the actual Native window after real SQL revocation.
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','original-subject','human','','Old','','old','[]',1,0,1,0,0); INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('approved-client','Fixture','[\"https://client.example.test/callback\"]','[\"presence-sdk\"]','web',0)").await.unwrap();
    let digest = support::digester()
        .token(TokenKind::OidcStoredAccess, JTI.as_bytes())
        .unwrap();
    let principal=json!({"issuer":"local","subject":"original-subject","username":"alice","auth_method":"oidc","local_user_revision":1,"name":"Old","email":null,"organization":"old","teams":[],"scopes":["presence-sdk"],"roles":[],"roles_from_claim":false,"role_claim_selector":""}).to_string();
    sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,'oidc_access','original-subject','broker-subject',$3,'approved-client','presence-api','https://broker.example.test/v1','[\"presence-sdk\"]',1,'',0,9223372036854775807,0)").bind(digest.to_sql_hex()).bind(JTI).bind(principal).execute(&mut c).await.unwrap();
    c.execute("UPDATE public.local_users SET enabled=0,revision=2; UPDATE public.local_tokens SET revoked_at=1,expires_at=0; DELETE FROM public.oauth_dynamic_clients; REVOKE SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients FROM native_http_owner").await.unwrap();
    assert_eq!(
        get(server.address, "station", &[&auth]).await.0,
        StatusCode::OK
    );
    let mut blocker = f.connection().await;
    for (inventory, method) in [(false, "PUT"), (false, "GET"), (true, "GET")] {
        let before = oracle(&mut c).await;
        let expiry = seconds() + 4;
        let mut claims = signer.claims();
        claims["exp"] = json!(expiry);
        let short = format!("Bearer {}", signer.sign(&claims));
        blocker
            .execute(if inventory {
                "BEGIN; LOCK TABLE public.broker_instances IN ACCESS EXCLUSIVE MODE"
            } else {
                "BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE"
            })
            .await
            .unwrap();
        let address = server.address;
        let pending = tokio::spawn(async move {
            exchange(
                address,
                method,
                "/v1/instances/station/inventory",
                &[&short],
                Body::from(input(&[(A, &["changed"])])),
            )
            .await
        });
        observe_lock(&mut c, inventory).await;
        assert!(seconds() < expiry);
        assert!(!pending.is_finished());
        let remaining = (UNIX_EPOCH + Duration::from_secs(expiry))
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        tokio::time::sleep(remaining + Duration::from_millis(30)).await;
        blocker.execute("COMMIT").await.unwrap();
        error(
            pending.await.unwrap(),
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
        assert_eq!(oracle(&mut c).await, before);
    }
    let mut p = publish_config();
    p.request_timeout = Duration::from_secs(2);
    let mut r = read_config();
    r.request_timeout = Duration::from_secs(2);
    let short = Server::start(
        broker_instance_inventory_router(store.clone(), verifier.clone(), p, r).unwrap(),
    )
    .await;
    for (inventory, method) in [(false, "PUT"), (false, "GET"), (true, "GET")] {
        let before = oracle(&mut c).await;
        blocker
            .execute(if inventory {
                "BEGIN; LOCK TABLE public.broker_instances IN ACCESS EXCLUSIVE MODE"
            } else {
                "BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE"
            })
            .await
            .unwrap();
        let address = short.address;
        let token = auth.clone();
        let pending = tokio::spawn(async move {
            exchange(
                address,
                method,
                "/v1/instances/station/inventory",
                &[&token],
                Body::from(input(&[(A, &["changed"])])),
            )
            .await
        });
        observe_lock(&mut c, inventory).await;
        error(
            pending.await.unwrap(),
            StatusCode::GATEWAY_TIMEOUT,
            "deadline",
        );
        blocker.execute("COMMIT").await.unwrap();
        assert_eq!(oracle(&mut c).await, before);
        assert_eq!(
            get(server.address, "station", &[&auth]).await.0,
            StatusCode::OK
        );
    }
    short.stop().await;
    // Body input shares Original; a never-completing SDK body times out before any write.
    let mut p = publish_config();
    p.request_timeout = Duration::from_millis(300);
    let slow = Server::start(
        broker_instance_inventory_router(store.clone(), verifier.clone(), p, read_config())
            .unwrap(),
    )
    .await;
    let stalled =
        Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
    error(
        exchange(slow.address, "PUT", path, &[&auth], stalled).await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    slow.stop().await;
    // A real transport disconnect need not cancel the Axum handler. Its Read is
    // bounded and cannot write, and releasing the SQL wait recovers the pool.
    let before = oracle(&mut c).await;
    blocker
        .execute("BEGIN; LOCK TABLE public.broker_instances IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let stream = TcpStream::connect(server.address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let io = tokio::spawn(connection);
    let token = auth.clone();
    let pending = tokio::spawn(async move {
        sender
            .send_request(request(
                "GET",
                "/v1/instances/station/inventory",
                &[&token],
                Body::empty(),
            ))
            .await
    });
    observe_lock(&mut c, true).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    io.abort();
    let _ = io.await;
    blocker.execute("COMMIT").await.unwrap();
    assert_eq!(
        get(server.address, "station", &[&auth]).await.0,
        StatusCode::OK
    );
    assert_eq!(oracle(&mut c).await, before);
    let final_read = get(server.address, "station", &[&auth]).await.1;
    store.shutdown(deadline()).await.unwrap();
    error(
        get(server.address, "station", &[&auth]).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "closed",
    );
    server.stop().await;
    let reopened = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let again = Server::start(
        broker_instance_inventory_router(
            reopened.clone(),
            verifier.clone(),
            publish_config(),
            read_config(),
        )
        .unwrap(),
    )
    .await;
    assert_eq!(get(again.address, "station", &[&auth]).await.1, final_read);
    assert_eq!(oracle(&mut c).await, before);
    again.stop().await;
    reopened.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
