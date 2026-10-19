#[path = "../../broker-control/tests/support/sqlite_admin_fixture.rs"]
mod fixture;
use axum::{Router, body::Body};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    AdminCookieSessionLimits, AdminCookieSessionPolicy, NewAdminSession, SessionLimits,
    SessionPrincipal, SessionProfile,
};
use broker_presence::{
    AdminCookieHttpConfig, AdminLocalBearerHttpConfig, AdminSessionHttpConfig,
    sqlite_local_admin_session_router,
};
use fixture::{Fixture, end, limits, n, now};
use http_body_util::BodyExt;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
use zeroize::Zeroizing;
fn local() -> AdminLocalBearerHttpConfig {
    AdminLocalBearerHttpConfig {
        audience: "admin-api".into(),
        identity_json_bytes: n(8192),
        required_scopes: vec!["admin:session".into()],
    }
}
fn config() -> AdminSessionHttpConfig {
    AdminSessionHttpConfig {
        limits: limits(),
        request_timeout: Duration::from_millis(100),
    }
}
fn cookie() -> AdminCookieHttpConfig {
    AdminCookieHttpConfig {
        limits: AdminCookieSessionLimits {
            authorization: limits(),
            metadata: SessionLimits {
                text_bytes: n(2048),
                csrf_bytes: n(43),
                team_bytes: n(512),
                role_bytes: n(128),
                max_teams: n(16),
                max_roles: n(16),
                teams_json_bytes: n(8192),
                roles_json_bytes: n(8192),
                max_lifetime: Duration::from_secs(3600),
            },
        },
        policy: AdminCookieSessionPolicy {
            session_ttl: Duration::from_secs(600),
        },
        secure: false,
    }
}
struct Server {
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    worker: JoinHandle<()>,
}
impl Server {
    async fn start(router: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let worker = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            address,
            stop,
            worker,
        }
    }
    async fn close(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.worker)
            .await
            .unwrap()
            .unwrap();
    }
    async fn send(&self, method: &str, auth: &[&str], cookies: &[&str]) -> (StatusCode, Value) {
        let stream = TcpStream::connect(self.address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let worker = tokio::spawn(connection);
        let mut req = Request::builder()
            .method(method)
            .uri("/admin/api/v1/session")
            .header("host", self.address.to_string())
            .header("connection", "close")
            .header("x-request-id", "opaque-sqlite");
        for a in auth {
            req = req.header("authorization", *a)
        }
        for c in cookies {
            req = req.header("cookie", *c)
        }
        let reply = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(req.body(Body::empty()).unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        let status = reply.status();
        assert_eq!(reply.headers()["cache-control"], "no-store");
        assert_eq!(reply.headers()["pragma"], "no-cache");
        assert_eq!(reply.headers()["x-request-id"], "opaque-sqlite");
        assert!(reply.headers().get("set-cookie").is_none());
        let bytes = reply.into_body().collect().await.unwrap().to_bytes();
        let value = if method == "HEAD" {
            assert!(bytes.is_empty());
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        drop(sender);
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        (status, value)
    }
}
fn error(reply: (StatusCode, Value), status: StatusCode, code: &str) {
    assert_eq!(reply.0, status);
    assert_eq!(reply.1["error"]["code"], code);
    let text = reply.1.to_string();
    assert!(!text.contains("SELECT") && !text.contains("broker.db") && !text.contains("gb_at_"));
}
#[tokio::test]
async fn human_service_admin_session_uses_current_sql_and_finite_http_errors() {
    let f = Fixture::new().await;
    let db = f.db();
    let router =
        sqlite_local_admin_session_router(f.store.clone(), config(), Some(local()), None).unwrap();
    let server = Server::start(router).await;
    for (raw, user, subject) in [
        (&f.access, "alice", "alice-subject"),
        (&f.service, "bot", "bot-subject"),
    ] {
        let auth = format!("Bearer {raw}");
        let reply = server.send("GET", &[&auth], &[]).await;
        assert_eq!(reply.0, StatusCode::OK);
        assert_eq!(
            reply.1,
            json!({"subject":subject,"name":"Current","email":"current@example.invalid","username":user,"organization":"org","teams":["a","z"],"roles":["user"],"role_source":"database","permissions":["projects.read","session.read"],"csrf_token":""})
        );
        assert_eq!(server.send("HEAD", &[&auth], &[]).await.0, StatusCode::OK);
    }
    let auth = format!("Bearer {}", f.access);
    assert_eq!(
        db.query_row("SELECT count(*) FROM admin_sessions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    for values in [
        vec![],
        vec!["Basic bad"],
        vec!["Bearer ey.jwt.fake"],
        vec![auth.as_str(), auth.as_str()],
    ] {
        error(
            server.send("GET", &values, &[]).await,
            StatusCode::UNAUTHORIZED,
            "admin_unauthorized",
        );
    }
    db.execute("DELETE FROM role_permissions WHERE role='user'", [])
        .unwrap();
    error(
        server.send("GET", &[&auth], &[]).await,
        StatusCode::FORBIDDEN,
        "admin_forbidden",
    );
    db.execute(
        "INSERT INTO role_permissions(role,action)VALUES('user','session.read')",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE local_users SET name='Fresh' WHERE username='alice'",
        [],
    )
    .unwrap();
    assert_eq!(server.send("GET", &[&auth], &[]).await.1["name"], "Fresh");
    db.execute(
        "UPDATE local_users SET name=?1 WHERE username='alice'",
        ["x".repeat(513)],
    )
    .unwrap();
    error(
        server.send("GET", &[&auth], &[]).await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "authorization_failed",
    );
    db.execute(
        "UPDATE local_users SET name='Fresh' WHERE username='alice'",
        [],
    )
    .unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    error(
        server.send("GET", &[&auth], &[]).await,
        StatusCode::GATEWAY_TIMEOUT,
        "administration_unavailable",
    );
    db.execute_batch("ROLLBACK").unwrap();
    f.store.shutdown(end()).await.unwrap();
    error(
        server.send("GET", &[&auth], &[]).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "administration_unavailable",
    );
    server.close().await;
}
#[tokio::test]
async fn known_cookie_priority_and_cookie_only_gates_do_not_fall_back() {
    let f = Fixture::new().await;
    let db = f.db();
    let config_cookie = cookie();
    let server = Server::start(
        sqlite_local_admin_session_router(
            f.store.clone(),
            config(),
            Some(local()),
            Some(config_cookie),
        )
        .unwrap(),
    )
    .await;
    let auth = format!("Bearer {}", f.service);
    for cookies in [
        vec!["graphit_admin_session=bad"],
        vec!["graphit_admin_session=bad; graphit_admin_session=other"],
        vec!["unrelated=x", "unrelated=y"],
    ] {
        error(
            server.send("GET", &[&auth], &cookies).await,
            StatusCode::UNAUTHORIZED,
            "admin_unauthorized",
        );
    }
    for empty in [
        "graphit_admin_session=",
        r#"graphit_admin_session="""#,
        "unrelated=x",
    ] {
        assert_eq!(
            server.send("GET", &[&auth], &[empty]).await.0,
            StatusCode::OK
        );
    }
    // cbcc is the trusted metadata fixture; cookie issuance is qualified in 8802/ceed.
    let raw = URL_SAFE_NO_PAD.encode([31; 32]);
    let csrf = URL_SAFE_NO_PAD.encode([32; 32]);
    let session = NewAdminSession::new(
        SessionProfile {
            subject: "alice-subject".into(),
            name: "Stale".into(),
            email: String::new(),
        },
        SessionPrincipal {
            issuer: "local".into(),
            username: "alice".into(),
            organization: String::new(),
            teams: vec![],
            local_user_revision: 1,
        },
        Zeroizing::new(csrf.clone()),
        None,
        SystemTime::now() + Duration::from_secs(600),
        &config_cookie.limits.metadata,
    )
    .unwrap();
    f.store
        .admin_sessions(config_cookie.limits.metadata)
        .unwrap()
        .create_session(&raw, &session, end())
        .await
        .unwrap();
    let known = format!("graphit_admin_session={raw}");
    // Mandatory change is a cookie/login gate, not an opaque gate.
    error(
        server.send("GET", &[&auth], &[&known]).await,
        StatusCode::UNAUTHORIZED,
        "admin_unauthorized",
    );
    db.execute(
        "UPDATE local_users SET password_change_required=0 WHERE username='alice'",
        [],
    )
    .unwrap();
    let reply = server.send("GET", &["not a bearer"], &[&known]).await;
    assert_eq!(reply.0, StatusCode::OK);
    assert_eq!(reply.1["username"], "alice");
    assert_eq!(reply.1["csrf_token"], csrf);
    db.execute("UPDATE admin_sessions SET expires_at=?1", [now() - 1])
        .unwrap();
    error(
        server.send("GET", &[&auth], &[&known]).await,
        StatusCode::UNAUTHORIZED,
        "admin_unauthorized",
    );
    server.close().await;
    let no_cookie = Server::start(
        sqlite_local_admin_session_router(f.store.clone(), config(), Some(local()), None).unwrap(),
    )
    .await;
    error(
        no_cookie.send("GET", &[&auth], &[&known]).await,
        StatusCode::UNAUTHORIZED,
        "admin_unauthorized",
    );
    assert_eq!(no_cookie.send("GET", &[&auth], &[]).await.0, StatusCode::OK);
    no_cookie.close().await;
    let mut bad = local();
    bad.audience = " ".into();
    assert!(sqlite_local_admin_session_router(f.store.clone(), config(), Some(bad), None).is_err());
    let mut bad = cookie();
    bad.limits.authorization.identity.rows = n(127);
    assert!(sqlite_local_admin_session_router(f.store.clone(), config(), None, Some(bad)).is_err());
    f.store.shutdown(end()).await.unwrap();
}
