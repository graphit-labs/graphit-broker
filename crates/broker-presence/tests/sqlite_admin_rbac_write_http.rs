#[path = "../../broker-control/tests/support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine fixtures serve independent native ingress targets"
)]
mod ingress;
use broker_control::{FlowPurpose, UpstreamBearerVerifier};
use broker_presence::{
    AdminCookieHttpConfig, AdminLocalBearerHttpConfig, AdminSessionHttpConfig,
    sqlite_admin_rbac_router,
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
fn revision(db: &Connection) -> i64 {
    db.query_row(
        "SELECT revision FROM resource_acl_state WHERE id=1",
        [],
        |r| r.get(0),
    )
    .unwrap()
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
        assert_eq!(self.headers["x-request-id"], "sqlite-admin-rbac-http");
        assert!(!self.headers.contains_key(header::SET_COOKIE));
    }
    fn finite(&self, status: u16, code: &str) {
        self.headers();
        assert_eq!(self.status.as_u16(), status);
        assert_eq!(self.json()["error"]["code"], code);
        assert_eq!(self.json()["request_id"], "sqlite-admin-rbac-http");
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
        .header("x-request-id", "sqlite-admin-rbac-http");
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
    f: &Fixture,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    JoinHandle<std::io::Result<()>>,
) {
    let router = sqlite_admin_rbac_router(
        f.store.clone(),
        f.verifier(),
        AdminSessionHttpConfig {
            limits: ingress::limits().authorization,
            request_timeout: Duration::from_secs(10),
        },
        n(1024),
        Some(AdminLocalBearerHttpConfig {
            audience: "admin-api".into(),
            identity_json_bytes: n(8192),
            required_scopes: vec!["admin:session".into()],
        }),
        upstream,
        Some(AdminCookieHttpConfig {
            limits: ingress::limits(),
            policy: ingress::policy(),
            secure: true,
        }),
    )
    .unwrap();
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
#[ignore = "real TCP RBAC wire, genuine four classes, cookie priority and known self-demotion"]
async fn sqlite_admin_rbac_http_four_ingresses_closed_wire_and_self_demotion() {
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

    let (address, stop, task) = serve(&f, Some(trust)).await;
    action(&f.db, "roles.write");
    let initial = revision(&f.db);
    let valid = serde_json::to_vec(&json!({"permissions":["roles.read"]})).unwrap();
    for (index, factor) in factors.iter().enumerate() {
        let role = format!("http-{index}");
        let path = format!("/admin/api/v1/roles/{role}");
        // RBAC has no If-Match contract, regardless of a supplied irrelevant header.
        let mut headers = factor.clone();
        headers.push(("if-match", "not-a-revision"));
        send(address, "PUT", &path, valid.clone(), &headers)
            .await
            .no_content();
        let assignment =
            serde_json::to_vec(&json!({"subject":format!("external|{index}"),"role":role}))
                .unwrap();
        send(
            address,
            "POST",
            "/admin/api/v1/role-assignments",
            assignment.clone(),
            factor,
        )
        .await
        .no_content();
        send(
            address,
            "DELETE",
            "/admin/api/v1/role-assignments",
            assignment,
            factor,
        )
        .await
        .no_content();
        send(address, "DELETE", &path, vec![], factor)
            .await
            .no_content();
        assert_eq!(revision(&f.db), initial);
    }
    let auth = [("authorization", jwt.as_str())];
    for invalid in [
        br#"{}"#.to_vec(),
        br#"{"permissions":null}"#.to_vec(),
        br#"{"permissions":"roles.read"}"#.to_vec(),
        br#"{"permissions":[]}"#.to_vec(),
        br#"{"permissions":["unknown"]}"#.to_vec(),
        br#"{"permissions":["roles.read"],"permissions":["roles.read"]}"#.to_vec(),
        br#"{"permissions":["roles.read"],"name":"body-role"}"#.to_vec(),
        br#"{"permissions":["roles.read"]} {}"#.to_vec(),
        {
            let mut bytes = valid.clone();
            bytes.resize(1200, b' ');
            bytes
        },
    ] {
        send(
            address,
            "PUT",
            "/admin/api/v1/roles/invalid",
            invalid,
            &auth,
        )
        .await
        .finite(400, "invalid_role");
    }
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM roles WHERE name IN ('invalid','body-role')",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    for builtin in ["admin", "user"] {
        let path = format!("/admin/api/v1/roles/{builtin}");
        send(address, "PUT", &path, valid.clone(), &auth)
            .await
            .finite(400, "invalid_role");
        send(address, "DELETE", &path, vec![], &auth)
            .await
            .finite(400, "role_delete_failed");
    }
    send(
        address,
        "DELETE",
        "/admin/api/v1/roles/absent",
        vec![],
        &auth,
    )
    .await
    .finite(400, "role_delete_failed");
    send(
        address,
        "PUT",
        "/admin/api/v1/roles/wire",
        valid.clone(),
        &auth,
    )
    .await
    .no_content();
    for invalid in [
        br#"{}"#.to_vec(),
        br#"{"subject":null,"role":"wire"}"#.to_vec(),
        br#"{"subject":"s","role":1}"#.to_vec(),
        br#"{"subject":"s","subject":"other","role":"wire"}"#.to_vec(),
        br#"{"subject":"s","role":"wire","extra":0}"#.to_vec(),
        br#"{"subject":"s","role":"wire"} {}"#.to_vec(),
    ] {
        send(
            address,
            "POST",
            "/admin/api/v1/role-assignments",
            invalid,
            &auth,
        )
        .await
        .finite(400, "assignment_failed");
    }
    send(
        address,
        "DELETE",
        "/admin/api/v1/role-assignments",
        serde_json::to_vec(&json!({"subject":"absent","role":"missing"})).unwrap(),
        &auth,
    )
    .await
    .no_content();
    send(
        address,
        "PUT",
        "/admin/api/v1/roles/denied",
        valid.clone(),
        &[("authorization", "Bearer invalid")],
    )
    .await
    .finite(401, "admin_unauthorized");
    for bearer in [jwt.as_str(), opaque.as_str(), raw.as_str()] {
        send(
            address,
            "PUT",
            "/admin/api/v1/roles/denied",
            valid.clone(),
            &[
                ("authorization", bearer),
                ("cookie", "graphit_admin_session=invalid"),
            ],
        )
        .await
        .finite(401, "admin_unauthorized");
    }
    let noncanonical = format!("{}B", "A".repeat(42));
    for cookie in [local.as_str(), federated.as_str()] {
        for csrf in [
            None,
            Some("invalid"),
            Some(noncanonical.as_str()),
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ] {
            let mut headers = vec![("cookie", cookie)];
            if let Some(csrf) = csrf {
                headers.push(("x-csrf-token", csrf));
            }
            send(
                address,
                "PUT",
                "/admin/api/v1/roles/denied",
                valid.clone(),
                &headers,
            )
            .await
            .finite(403, "csrf_failed");
        }
        send(
            address,
            "PUT",
            "/admin/api/v1/roles/denied",
            valid.clone(),
            &[
                ("cookie", cookie),
                ("x-csrf-token", local_csrf.as_str()),
                ("x-csrf-token", local_csrf.as_str()),
            ],
        )
        .await
        .finite(403, "csrf_failed");
    }
    action(&f.db, "session.read");
    for factor in &factors {
        send(
            address,
            "PUT",
            "/admin/api/v1/roles/denied",
            valid.clone(),
            factor,
        )
        .await
        .finite(403, "admin_forbidden");
    }
    assert_eq!(
        f.db.query_row("SELECT count(*) FROM roles WHERE name='denied'", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
    action(&f.db, "roles.write");
    f.db.execute("DELETE FROM role_assignments WHERE role='admin'", [])
        .unwrap();
    f.db.execute(
        "INSERT INTO role_assignments(subject,role,created_at)VALUES('external|last','admin',0)",
        [],
    )
    .unwrap();
    let last = serde_json::to_vec(&json!({"subject":"external|last","role":"admin"})).unwrap();
    send(
        address,
        "DELETE",
        "/admin/api/v1/role-assignments",
        last.clone(),
        &auth,
    )
    .await
    .finite(400, "assignment_failed");
    f.db.execute(
        "INSERT INTO role_assignments(subject,role,created_at)VALUES('external|other','admin',0)",
        [],
    )
    .unwrap();
    send(
        address,
        "DELETE",
        "/admin/api/v1/role-assignments",
        last,
        &auth,
    )
    .await
    .no_content();

    send(
        address,
        "PUT",
        "/admin/api/v1/roles/operators",
        serde_json::to_vec(&json!({"permissions":["roles.write"]})).unwrap(),
        &auth,
    )
    .await
    .no_content();
    let subject: String =
        f.db.query_row(
            "SELECT 'local|'||subject FROM local_users WHERE username='alice'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    send(
        address,
        "POST",
        "/admin/api/v1/role-assignments",
        serde_json::to_vec(&json!({"subject":subject,"role":"operators"})).unwrap(),
        &auth,
    )
    .await
    .no_content();
    f.db.execute("DELETE FROM role_permissions WHERE role='user'", [])
        .unwrap();
    send(
        address,
        "PUT",
        "/admin/api/v1/roles/operators",
        valid,
        &auth,
    )
    .await
    .no_content();
    send(address, "DELETE", "/admin/api/v1/roles/wire", vec![], &auth)
        .await
        .finite(403, "admin_forbidden");
    assert_eq!(
        f.db.query_row(
            "SELECT action FROM role_permissions WHERE role='operators'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "roles.read"
    );
    assert_eq!(revision(&f.db), initial);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    f.store.shutdown(end()).await.unwrap();
    op.close().await;
    bearer.close().await;
}
