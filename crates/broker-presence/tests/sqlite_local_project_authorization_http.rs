use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{FlowLimits, SqliteControlConfig, SqliteControlStore};
use broker_presence::{ProjectAuthorizationHttpConfig, sqlite_project_authorization_router};
use broker_security::{CredentialDigester, DigestLimits, TokenKind};
use http_body_util::BodyExt;
use hyper::body::Body as _;
use hyper_util::rt::TokioIo;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    num::NonZeroUsize,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const PATH: &str = "/v1/project/access/authorize";
fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(vec![81; 32].into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
fn config() -> ProjectAuthorizationHttpConfig {
    ProjectAuthorizationHttpConfig {
        audience: "aud".into(),
        required_scopes: vec!["project-api".into()],
        identity_json_bytes: n(8192),
        grants_json_bytes: n(65536),
        body_bytes: n(1024),
        request_timeout: Duration::from_secs(2),
    }
}
struct Fixture {
    _root: tempfile::TempDir,
    path: PathBuf,
    store: Arc<SqliteControlStore>,
    access: String,
    service: String,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private/broker.db");
        let store = Arc::new(
            SqliteControlStore::open(
                SqliteControlConfig::new(
                    path.clone(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                    FlowLimits {
                        provider_bytes: n(128),
                        request_bytes: n(256),
                        continuation_bytes: n(1024),
                    },
                )
                .unwrap(),
                digester(),
                end(),
            )
            .await
            .unwrap(),
        );
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).unwrap();
        let access = format!("gb_at_{}", URL_SAFE_NO_PAD.encode(bytes));
        getrandom::fill(&mut bytes).unwrap();
        let service = format!("gb_sc_{}", URL_SAFE_NO_PAD.encode(bytes));
        let f = Self {
            _root: root,
            path,
            store,
            access,
            service,
        };
        let db = f.db();
        for (raw, kind, username, subject, identitykind) in [
            (
                &f.access,
                TokenKind::LocalAccess,
                "alice",
                "alice-subject",
                "human",
            ),
            (
                &f.service,
                TokenKind::ServiceCredential,
                "bot",
                "bot-subject",
                "service",
            ),
        ] {
            db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES(?1,?2,?3,'not-selected','Current','','engineering','[\"dev\"]',1,1,1,0,0)",params![username,subject,identitykind]).unwrap();
            let principal=json!({"issuer":"local","subject":subject,"username":"stale","auth_method":"stale","roles":["admin"],"teams":["stale"],"local_user_revision":1}).to_string();
            let expiry = i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_micros(),
            )
            .unwrap()
                + 60_000_000;
            db.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES(?1,?2,?3,?4,'pseudo',?5,'client','aud','','[\"project-api\"]',1,'',0,?6,0)",params![digester().token(kind,raw.as_bytes()).unwrap().to_sql_hex(),raw,if identitykind=="human"{"access"}else{"service"},subject,principal,expiry]).unwrap();
        }
        f
    }
    fn db(&self) -> Connection {
        let db = Connection::open(&self.path).unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db
    }
}
fn clear(db: &Connection) {
    db.execute_batch(
        "DELETE FROM resource_grants; UPDATE resource_acl_state SET revision=revision+1 WHERE id=1",
    )
    .unwrap();
}
fn grant(db: &Connection, id: &str, kind: &str, principal: &str, cap: &str, project: &str) {
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES(?1,'fixture',?2,?3,'',0,0)",params![id,kind,principal]).unwrap();
    db.execute(
        "INSERT INTO grant_capabilities(grant_id,value) VALUES(?1,?2)",
        params![id, cap],
    )
    .unwrap();
    db.execute(
        "INSERT INTO grant_projects(grant_id,value) VALUES(?1,?2)",
        params![id, project],
    )
    .unwrap();
}
fn revision(db: &Connection) -> i64 {
    db.query_row(
        "SELECT revision FROM resource_acl_state WHERE id=1",
        [],
        |r| r.get(0),
    )
    .unwrap()
}
fn input(project: &str, module: &str, action: &str) -> String {
    json!({"project_id":project,"module":module,"action":action}).to_string()
}

#[tokio::test]
async fn local_human_and_service_use_current_project_policy_over_real_http() {
    let f = Fixture::new().await;
    let db = f.db();
    let auth = format!("Bearer {}", f.access);
    let server =
        Server::start(sqlite_project_authorization_router(f.store.clone(), config()).unwrap())
            .await;
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    for (module, action, cap) in [
        ("task", "read", "task:read"),
        ("task", "write", "task:write"),
        ("memory", "read", "memory:read"),
        ("memory", "write", "memory:write"),
        ("knowledge", "read", "knowledge:read"),
        ("knowledge", "write", "knowledge:write"),
        ("ast", "read", "ast:read"),
        ("ast", "write", "ast:write"),
        ("hub", "read", "hub"),
    ] {
        clear(&db);
        grant(&db, "logical", "subject", "local|alice-subject", cap, A);
        let reply = post(&server, &[&auth], input(A, module, action)).await;
        assert_eq!(reply.0, StatusCode::OK);
        assert_eq!(
            reply.1,
            json!({"subject":{"issuer":"local","subject":"alice-subject"},"authorization_revision":revision(&db),"project_id":A,"module":module,"action":action})
        );
        error(
            post(&server, &[&auth], input(B, module, action)).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
        if module != "hub" {
            error(
                post(
                    &server,
                    &[&auth],
                    input(A, module, if action == "read" { "write" } else { "read" }),
                )
                .await,
                StatusCode::FORBIDDEN,
                "forbidden",
            );
        }
    }
    error(
        post(&server, &["Bearer invalid"], input(A, "hub", "write")).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    );
    clear(&db);
    grant(&db, "one", "subject", "local|alice-subject", "task:read", B);
    grant(
        &db,
        "two",
        "subject",
        "local|alice-subject",
        "task:write",
        A,
    );
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    clear(&db);
    grant(&db, "current-team", "team", "dev", "task:read", A);
    assert_eq!(
        post(&server, &[&auth], input(A, "task", "read")).await.0,
        StatusCode::OK
    );
    db.execute(
        "UPDATE local_users SET teams_json='[]' WHERE username='alice'",
        [],
    )
    .unwrap();
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    clear(&db);
    grant(&db, "bot", "subject", "local|bot-subject", "task:read", A);
    assert_eq!(
        post(
            &server,
            &[&format!("Bearer {}", f.service)],
            input(A, "task", "read")
        )
        .await
        .0,
        StatusCode::OK
    );
    clear(&db);
    error(
        post(
            &server,
            &[&format!("Bearer {}", f.service)],
            input(A, "task", "read"),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test]
async fn local_http_denies_auth_state_policy_limits_and_closed_store() {
    let f = Fixture::new().await;
    let db = f.db();
    let auth = format!("Bearer {}", f.access);
    grant(
        &db,
        "logical",
        "subject",
        "local|alice-subject",
        "task:read",
        A,
    );
    let server =
        Server::start(sqlite_project_authorization_router(f.store.clone(), config()).unwrap())
            .await;
    for headers in [
        vec![],
        vec!["Bearer bad"],
        vec![auth.as_str(), auth.as_str()],
    ] {
        error(
            post(&server, &headers, input(A, "task", "read")).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    for sql in [
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
        "UPDATE local_users SET revision=2 WHERE username='alice'",
        "UPDATE local_tokens SET scopes_json='[\" project-api \"]' WHERE token_kind='access'",
    ] {
        db.execute_batch(sql).unwrap();
        error(
            post(&server, &[&auth], input(A, "task", "read")).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
        db.execute_batch("UPDATE local_users SET enabled=1,revision=1; UPDATE local_tokens SET scopes_json='[\"project-api\"]'").unwrap();
    }
    db.execute(
        "UPDATE local_users SET teams_json='not-json' WHERE username='alice'",
        [],
    )
    .unwrap();
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authentication_unavailable",
    );
    db.execute(
        "UPDATE local_users SET teams_json='[]' WHERE username='alice'",
        [],
    )
    .unwrap();
    grant(&db, "invalid", "user", "[", "task:read", B);
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid_policy",
    );
    db.execute("DELETE FROM resource_grants WHERE id='invalid'", [])
        .unwrap();
    for identity in [true, false] {
        let mut cfg = config();
        if identity {
            cfg.identity_json_bytes = n(1)
        } else {
            cfg.grants_json_bytes = n(1)
        };
        let capped =
            Server::start(sqlite_project_authorization_router(f.store.clone(), cfg).unwrap()).await;
        error(
            post(&capped, &[&auth], input(A, "task", "read")).await,
            StatusCode::SERVICE_UNAVAILABLE,
            if identity {
                "authentication_unavailable"
            } else {
                "authorization_unavailable"
            },
        );
        capped.stop().await;
    }
    f.store.shutdown(end()).await.unwrap();
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "closed",
    );
    server.stop().await;
}

#[tokio::test]
async fn local_http_preserves_wire_and_original_sql_deadline() {
    let f = Fixture::new().await;
    let db = f.db();
    let auth = format!("Bearer {}", f.access);
    let mut cfg = config();
    cfg.request_timeout = Duration::from_millis(60);
    let server =
        Server::start(sqlite_project_authorization_router(f.store.clone(), cfg).unwrap()).await;
    for body in [
        "[]",
        "{}",
        "{\"project_id\":\"p\",\"module\":\"Task\",\"action\":\"read\"}",
        "{\"project_id\":\"p\",\"module\":\"task\",\"action\":\"read\",\"extra\":1}",
    ] {
        error(
            post(&server, &[&auth], body.into()).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
    }
    error(
        exchange(server.address, "GET", PATH, &[&auth], None, Body::empty()).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    );
    error(
        exchange(
            server.address,
            "POST",
            PATH,
            &[&auth],
            Some("text/plain"),
            Body::from(input(A, "task", "read")),
        )
        .await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    );
    error(
        post(&server, &[&auth], " ".repeat(2048)).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "body_too_large",
    );
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    db.execute_batch("COMMIT").unwrap();
    grant(
        &db,
        "logical",
        "subject",
        "local|alice-subject",
        "task:read",
        A,
    );
    assert_eq!(
        post(&server, &[&auth], input(A, "task", "read")).await.0,
        StatusCode::OK
    );
    for mutate in [0, 1, 2] {
        let mut invalid = config();
        match mutate {
            0 => invalid.audience = " ".into(),
            1 => invalid.required_scopes = vec!["".into()],
            _ => invalid.request_timeout = Duration::ZERO,
        };
        assert!(sqlite_project_authorization_router(f.store.clone(), invalid).is_err());
    }
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
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
) -> (StatusCode, Value, bool) {
    let streaming = body.size_hint().exact().is_none();
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let mut request = Request::builder().method(method).uri(path);
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
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
    let challenge = response.headers().get(header::WWW_AUTHENTICATE).cloned();
    let bearer = challenge.as_ref().is_some_and(|value| value == "Bearer");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if method == "HEAD" {
        assert!(bytes.is_empty());
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    if value["error"]["code"] == "insufficient_scope" {
        assert_eq!(challenge.unwrap(), "Bearer error=\"insufficient_scope\"");
    }
    drop(sender);
    if let Err(error) = tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap()
    {
        assert!(
            streaming && status == StatusCode::GATEWAY_TIMEOUT && error.is_incomplete_message()
        );
    }
    (status, value, bearer)
}
async fn post(server: &Server, auth: &[&str], raw: String) -> (StatusCode, Value, bool) {
    exchange(
        server.address,
        "POST",
        PATH,
        auth,
        Some("application/json"),
        Body::from(raw),
    )
    .await
}
fn error(reply: (StatusCode, Value, bool), status: StatusCode, code: &str) {
    assert_eq!(reply.0, status);
    assert_eq!(reply.1, json!({"error":{"code":code}}));
    assert_eq!(reply.2, status == StatusCode::UNAUTHORIZED);
}
