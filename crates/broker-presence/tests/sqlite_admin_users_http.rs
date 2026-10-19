#[path = "../../broker-control/tests/support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine fixtures serve independent native ingress targets"
)]
mod ingress;
use broker_control::{FlowPurpose, UpstreamBearerVerifier};
use broker_presence::{
    AdminCookieHttpConfig, AdminLocalBearerHttpConfig, AdminSessionHttpConfig,
    AdminUsersHttpConfig, sqlite_admin_users_router,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, StatusCode,
    http::{HeaderMap, header},
};
use hyper_util::rt::TokioIo;
use ingress::fixture::{Arc, Duration, Fixture, Zeroizing, end, json, n};
use rusqlite::Connection;
use serde_json::Value;
use std::net::SocketAddr;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
fn action(db: &Connection, permission: &str) {
    db.execute("DELETE FROM role_permissions WHERE role='user'", [])
        .unwrap();
    db.execute(
        "INSERT INTO role_permissions(role,action)VALUES('user',?1)",
        [permission],
    )
    .unwrap();
}
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Zeroizing<Vec<u8>>,
}
impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    fn headers(&self) {
        assert_eq!(self.headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(self.headers[header::PRAGMA], "no-cache");
        assert_eq!(self.headers["x-request-id"], "sqlite-admin-users-http");
        assert!(!self.headers.contains_key(header::SET_COOKIE));
    }
    fn finite(&self, status: u16, code: &str) {
        self.headers();
        assert_eq!(self.status.as_u16(), status);
        assert_eq!(self.json()["error"]["code"], code);
        assert_eq!(self.json()["request_id"], "sqlite-admin-users-http");
    }
    fn no_content(&self) {
        self.headers();
        assert_eq!(self.status, StatusCode::NO_CONTENT);
        assert!(self.body.is_empty());
        assert!(!self.headers.contains_key(header::ETAG));
    }
}
async fn send(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Vec<u8>,
    headers: &[(&str, &str)],
) -> Reply {
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", address.to_string())
        .header("content-type", "application/json")
        .header("connection", "close")
        .header("x-request-id", "sqlite-admin-users-http");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        sender.send_request(
            builder
                .body(Full::new(hyper::body::Bytes::from(body)))
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = tokio::time::timeout(Duration::from_secs(5), body.collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    drop(sender);
    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: Zeroizing::new(bytes.to_vec()),
    }
}

async fn serve(
    store: Arc<broker_control::SqliteControlStore>,
    verifier: Arc<broker_control::BrokerAccessVerifier>,
    engine: Arc<broker_control::LocalPasswordEngine>,
    timeout: Duration,
    gate: Option<Arc<Gate>>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    JoinHandle<std::io::Result<()>>,
) {
    let router = sqlite_admin_users_router(
        store,
        verifier,
        engine,
        AdminUsersHttpConfig {
            session: AdminSessionHttpConfig {
                limits: ingress::limits().authorization,
                request_timeout: timeout,
            },
            body_bytes: n(2048),
            response_json_bytes: n(65536),
            local: Some(AdminLocalBearerHttpConfig {
                audience: "admin-api".into(),
                identity_json_bytes: n(8192),
                required_scopes: vec!["admin:session".into()],
            }),
            upstream,
            cookie: Some(AdminCookieHttpConfig {
                limits: ingress::limits(),
                policy: ingress::policy(),
                secure: true,
            }),
            service_credential_audience: "admin-api".into(),
            service_credential_max_ttl: Duration::from_secs(365 * 86400),
        },
    )
    .unwrap();
    activate_gate(gate);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
    });
    (address, stop, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real TCP seven SQLite admin routes with genuine factors, minimal actions and closed wire"]
async fn sqlite_users_http_seven_routes_current_factors_and_closed_wire() {
    let f = Fixture::new().await;
    ingress::allow_session(&f);
    let jwt = ingress::jwt(&f).await;
    let opaque = ingress::persisted_opaque(&f);
    let local = ingress::local_cookie(&f).await;
    let mut bearer = ingress::upstream::UpstreamFixture::new().await;
    let mut op = ingress::browser_op().await;
    let mut bearer_config = ingress::config(&bearer.issuer, &bearer.ca, false, Some("roles"));
    bearer_config.id = "bearer".into();
    let trust = ingress::trust(vec![
        ingress::config(&op.issuer, &op.ca, true, Some("roles")),
        bearer_config,
    ]);
    let raw = bearer.sign(&bearer.claims(), "upstream-key", "at+jwt");
    let proof = ingress::h1(&f, &op, &trust, FlowPurpose::Admin, end()).await;
    let sessions = f
        .store
        .admin_cookie_sessions(ingress::limits(), ingress::policy(), Some(trust.clone()))
        .unwrap();
    let federated = sessions.issue_upstream(proof, end()).await.unwrap();
    let local_csrf = Zeroizing::new(
        sessions
            .read(local.secret(), end())
            .await
            .unwrap()
            .csrf_token()
            .to_owned(),
    );
    let federated_csrf = Zeroizing::new(
        sessions
            .read(federated.secret(), end())
            .await
            .unwrap()
            .csrf_token()
            .to_owned(),
    );
    let jwt = Zeroizing::new(format!("Bearer {}", jwt.as_str()));
    let opaque = Zeroizing::new(format!("Bearer {}", opaque.as_str()));
    let raw = Zeroizing::new(format!("Bearer {}", raw.as_str()));
    let local = Zeroizing::new(format!("graphit_admin_session={}", local.secret()));
    let federated = Zeroizing::new(format!("graphit_admin_session={}", federated.secret()));
    let factors = [
        vec![("authorization", jwt.as_str())],
        vec![("authorization", opaque.as_str())],
        vec![("authorization", raw.as_str())],
        vec![
            ("cookie", local.as_str()),
            ("x-csrf-token", local_csrf.as_str()),
        ],
        vec![
            ("cookie", federated.as_str()),
            ("x-csrf-token", federated_csrf.as_str()),
        ],
    ];

    f.add_user("http-human", "http-human-subject").await;
    let verifier = f.verifier();
    let engine = Arc::new(f.engine);
    let (address, stop, task) = serve(
        f.store.clone(),
        verifier,
        engine,
        Duration::from_secs(10),
        None,
        Some(trust),
    )
    .await;

    for (index, factor) in factors.iter().enumerate() {
        action(&f.db, "users.write");
        let username = format!("http-service-{index}");
        let path = format!("/admin/api/v1/local-users/{username}");
        let creds = format!("{path}/credentials");
        let create =
            json!({"username":username,"subject":format!("http-subject-{index}"),"kind":"service"});
        let r = send(
            address,
            "POST",
            "/admin/api/v1/local-users",
            serde_json::to_vec(&create).unwrap(),
            factor,
        )
        .await;
        r.headers();
        assert_eq!(r.status.as_u16(), 201);
        assert!(r.body.is_empty());
        let update = json!({"username":username,"subject":format!("http-subject-{index}"),"kind":"service","name":" updated "});
        send(
            address,
            "PUT",
            &path,
            serde_json::to_vec(&update).unwrap(),
            factor,
        )
        .await
        .no_content();
        let r = send(
            address,
            "POST",
            &creds,
            br#"{"scopes":["admin:session"],"expires_in":3600}"#.to_vec(),
            factor,
        )
        .await;
        r.headers();
        assert_eq!(r.status.as_u16(), 201);
        let v = r.json();
        let id = v["id"].as_str().unwrap();
        let token = Zeroizing::new(v["token"].as_str().unwrap().to_owned());
        assert!(token.starts_with("gb_sc_"));
        let proof = f
            .store
            .local_bearer_verifier("admin-api", n(8192))
            .unwrap()
            .verify(&token, &["admin:session".into()], end())
            .await
            .unwrap();
        assert_eq!(proof.current_local_user().username(), username);
        action(&f.db, "users.read");
        let read_factor: Vec<_> = factor
            .iter()
            .filter(|(h, _)| *h != "x-csrf-token")
            .copied()
            .collect();
        let r = send(address, "GET", &creds, vec![], &read_factor).await;
        r.headers();
        assert_eq!(r.status.as_u16(), 200);
        assert_eq!(r.json()["credentials"][0]["id"], id);
        assert!(r.json()["credentials"][0].get("revoked_at").is_none());
        assert!(!String::from_utf8_lossy(&r.body).contains(token.as_str()));
        send(address, "DELETE", &path, vec![], factor)
            .await
            .finite(403, "admin_forbidden");
        action(&f.db, "users.write");
        send(address, "DELETE", &format!("{creds}/{id}"), vec![], factor)
            .await
            .no_content();
        assert!(
            f.store
                .local_bearer_verifier("admin-api", n(8192))
                .unwrap()
                .verify(&token, &[], end())
                .await
                .is_err()
        );
        send(address, "DELETE", &path, vec![], factor)
            .await
            .no_content();
    }
    action(&f.db, "users.write");
    send(
        address,
        "POST",
        "/admin/api/v1/local-users/http-human/mfa/reset",
        vec![],
        &factors[0],
    )
    .await
    .no_content();
    for body in [
        br#"{"username":"bad","subject":"s","kind":"service","unknown":true}"#.to_vec(),
        br#"{"username":"a","username":"b","subject":"s","kind":"service"}"#.to_vec(),
        b"null".to_vec(),
        b"{} trailing".to_vec(),
    ] {
        let r = send(
            address,
            "POST",
            "/admin/api/v1/local-users",
            body,
            &factors[0],
        )
        .await;
        r.headers();
        assert_eq!(r.status.as_u16(), 400);
    }
    let r = send(
        address,
        "POST",
        "/admin/api/v1/local-users",
        vec![b' '; 2049],
        &factors[0],
    )
    .await;
    assert_eq!(r.status.as_u16(), 400);
    let create = serde_json::to_vec(
        &json!({"username":"csrf-denied","subject":"csrf-denied","kind":"service"}),
    )
    .unwrap();
    send(
        address,
        "POST",
        "/admin/api/v1/local-users",
        create.clone(),
        &[("cookie", local.as_str())],
    )
    .await
    .finite(403, "csrf_failed");
    send(
        address,
        "POST",
        "/admin/api/v1/local-users",
        create.clone(),
        &[
            ("cookie", "graphit_admin_session=invalid"),
            ("authorization", jwt.as_str()),
        ],
    )
    .await
    .finite(401, "admin_unauthorized");
    send(address, "POST", "/admin/api/v1/local-users", create, &[])
        .await
        .finite(401, "admin_unauthorized");
    // A known cookie self-edit returns its ACK before the next request rejects that cookie.
    let self_profile=serde_json::to_vec(&json!({"username":"alice","subject":"alice-subject","kind":"human","name":"Current self profile"})).unwrap();
    send(
        address,
        "PUT",
        "/admin/api/v1/local-users/alice",
        self_profile,
        &factors[3],
    )
    .await
    .no_content();
    send(
        address,
        "GET",
        "/admin/api/v1/local-users/alice/credentials",
        vec![],
        &[("cookie", local.as_str())],
    )
    .await
    .finite(401, "admin_unauthorized");
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    bearer.close().await;
    op.close().await;
    f.store.shutdown(end()).await.unwrap();
}

struct Gate {
    target: &'static str,
    count: AtomicUsize,
    needed: usize,
    notify: tokio::sync::Notify,
    released: Mutex<bool>,
    changed: Condvar,
}
impl Gate {
    fn new(target: &'static str, needed: usize) -> Arc<Self> {
        Arc::new(Self {
            target,
            count: AtomicUsize::new(0),
            needed,
            notify: tokio::sync::Notify::new(),
            released: Mutex::new(false),
            changed: Condvar::new(),
        })
    }
    async fn wait(&self) {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let notified = self.notify.notified();
                if self.count.load(Ordering::SeqCst) >= self.needed {
                    break;
                }
                notified.await;
            }
        })
        .await
        .unwrap();
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}
struct GateLayer(Arc<Gate>);
impl Layer<Registry> for GateLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, Registry>) {
        if event.metadata().target() != self.0.target {
            return;
        }
        assert_eq!(event.metadata().fields().len(), 1);
        if self.0.count.fetch_add(1, Ordering::SeqCst) >= self.0.needed {
            return;
        }
        self.0.notify.notify_waiters();
        let released = self.0.released.lock().unwrap();
        let (_released, timed) = self
            .0
            .changed
            .wait_timeout_while(released, Duration::from_secs(25), |v| !*v)
            .unwrap();
        assert!(
            !timed.timed_out(),
            "owned test observation was not released"
        );
    }
}

use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tracing_subscriber::{Layer, Registry, layer::Context, prelude::*};
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real TCP corruption, SQL deadline, committed credential without ACK and expired KDF factor"]
async fn sqlite_users_http_failure_categories_do_not_release_credentials() {
    use broker_control::{
        AdminReadAuthentication as A, AdminServiceCredentialInput, AdminUserInput,
        AdminUsersLimits, AdminUsersRequest as R,
    };
    let f = Fixture::new().await;
    let raw = ingress::persisted_opaque(&f);
    action(&f.db, "users.write");
    let limits = AdminUsersLimits {
        authorization: ingress::limits().authorization,
        response_json_bytes: n(65536),
        service_credential_audience: "admin-api".into(),
        service_credential_max_ttl: Duration::from_secs(86400),
    };
    let mut u = AdminUserInput::default();
    u.username = "http-errors".into();
    u.subject = "http-errors-subject".into();
    u.kind = "service".into();
    let auth = || A::Opaque {
        raw: &raw,
        audience: "admin-api",
        identity_json_bytes: n(8192),
        required_scopes: &[],
    };
    f.store
        .admin_users(&f.engine, &limits)
        .unwrap()
        .execute(auth(), R::Create(&u), None, end())
        .await
        .unwrap()
        .check()
        .unwrap();
    f.store
        .admin_users(&f.engine, &limits)
        .unwrap()
        .execute(
            auth(),
            R::IssueCredential {
                username: "http-errors",
                input: &AdminServiceCredentialInput::default(),
            },
            None,
            end(),
        )
        .await
        .unwrap()
        .check()
        .unwrap();
    let verifier = f.verifier();
    let engine = Arc::new(f.engine);
    let header = Zeroizing::new(format!("Bearer {}", raw.as_str()));
    let path = "/admin/api/v1/local-users/http-errors/credentials";
    let (address, stop, task) = serve(
        f.store.clone(),
        verifier.clone(),
        engine.clone(),
        Duration::from_millis(250),
        None,
        None,
    )
    .await;
    action(&f.db, "users.read");
    f.db.execute(
        "UPDATE local_tokens SET scopes_json='{' WHERE subject='http-errors-subject'",
        [],
    )
    .unwrap();
    let r = send(address, "GET", path, vec![], &[("authorization", &header)]).await;
    r.headers();
    assert_eq!(r.status.as_u16(), 500);
    assert!(r.json()["error"]["code"].is_string());
    assert!(!String::from_utf8_lossy(&r.body).contains("SELECT"));
    f.db.execute(
        "UPDATE local_tokens SET scopes_json='[]' WHERE subject='http-errors-subject'",
        [],
    )
    .unwrap();
    action(&f.db, "users.write");
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let r = send(
        address,
        "POST",
        path,
        b"{}".to_vec(),
        &[("authorization", &header)],
    )
    .await;
    f.db.execute_batch("ROLLBACK").unwrap();
    r.headers();
    assert_eq!(r.status.as_u16(), 504);
    assert_eq!(
        f.db.query_row::<i64, _, _>(
            "SELECT count(*) FROM local_tokens WHERE subject='http-errors-subject'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    let gate = Gate::new("broker_control::sqlite::admin_users_commit_ack", 1);
    let (address, stop, task) = serve(
        f.store.clone(),
        verifier.clone(),
        engine.clone(),
        Duration::from_millis(750),
        Some(gate.clone()),
        None,
    )
    .await;
    let request = tokio::spawn({
        let h = Zeroizing::new(header.to_string());
        async move {
            send(
                address,
                "POST",
                path,
                b"{}".to_vec(),
                &[("authorization", &h)],
            )
            .await
        }
    });
    gate.wait().await;
    assert_eq!(
        f.db.query_row::<i64, _, _>(
            "SELECT count(*) FROM local_tokens WHERE subject='http-errors-subject'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
    let r = request.await.unwrap();
    r.headers();
    assert_eq!(r.status.as_u16(), 503);
    assert!(!String::from_utf8_lossy(&r.body).contains("gb_sc_"));
    assert!(r.json().get("token").is_none());
    gate.release();
    f.store
        .resource_grants(n(65536))
        .unwrap()
        .read(end())
        .await
        .unwrap();
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    f.db.execute(
        "UPDATE local_tokens SET expires_at=?1 WHERE token_id='persisted-opaque'",
        [ingress::fixture::utc() + 700_000],
    )
    .unwrap();
    let gate = Gate::new("broker_control::sqlite::admin_users_before_hash", 1);
    let (address, stop, task) = serve(
        f.store.clone(),
        verifier,
        engine,
        Duration::from_secs(10),
        Some(gate.clone()),
        None,
    )
    .await;
    let request = tokio::spawn({
        let h = Zeroizing::new(header.to_string());
        async move {
            send(address,"POST","/admin/api/v1/local-users",serde_json::to_vec(&json!({"username":"expired-http-kdf","subject":"expired-http-kdf","password":ingress::fixture::PASSWORD})).unwrap(),&[("authorization",&h)]).await
        }
    });
    gate.wait().await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    gate.release();
    let r = request.await.unwrap();
    r.headers();
    assert_eq!(r.status.as_u16(), 401);
    assert_eq!(
        f.db.query_row::<i64, _, _>(
            "SELECT count(*) FROM local_users WHERE username='expired-http-kdf'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    f.store.shutdown(end()).await.unwrap();
}

struct HttpGateLayer(Arc<Mutex<Option<Arc<Gate>>>>);
impl Layer<Registry> for HttpGateLayer {
    fn on_event(&self, event: &tracing::Event<'_>, context: Context<'_, Registry>) {
        let gate = self.0.lock().unwrap().clone();
        if let Some(gate) = gate {
            GateLayer(gate).on_event(event, context);
        }
    }
}
fn activate_gate(gate: Option<Arc<Gate>>) {
    static STATE: std::sync::OnceLock<Arc<Mutex<Option<Arc<Gate>>>>> = std::sync::OnceLock::new();
    let state = STATE.get_or_init(|| {
        let state = Arc::new(Mutex::new(None));
        tracing::subscriber::set_global_default(
            Registry::default().with(HttpGateLayer(state.clone())),
        )
        .unwrap();
        state
    });
    *state.lock().unwrap() = gate;
}
