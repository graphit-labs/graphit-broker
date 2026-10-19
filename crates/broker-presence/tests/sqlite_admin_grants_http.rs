#[path = "../../broker-control/tests/support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine fixtures serve different native ingress targets"
)]
mod ingress;

use broker_control::{AdminGrantRoutes, AdminReadLimits, FlowPurpose, UpstreamBearerVerifier};
use broker_presence::{
    AdminCookieHttpConfig, AdminGrantsHttpConfig, AdminLocalBearerHttpConfig, AdminReadHttpConfig,
    AdminSessionHttpConfig, sqlite_admin_grants_router, sqlite_admin_read_router,
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
fn revision(db: &Connection) -> u64 {
    let revision: i64 = db
        .query_row(
            "SELECT revision FROM resource_acl_state WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    u64::try_from(revision).unwrap()
}
fn body(id: &str) -> Value {
    json!({"id":id,"name":" HTTP Grant ","access":"authenticated","principal":"","capabilities":["hub"],"projects":["01M1YEAE1WYMWG9KJKV1XQC4T4"],"s3_operations":[],"s3_prefixes":[],"s3_route":""})
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
        assert_eq!(self.headers["x-request-id"], "sqlite-admin-grants-http");
        assert!(!self.headers.contains_key(header::SET_COOKIE));
    }
    fn finite(&self, status: u16, code: &str) {
        self.headers();
        assert_eq!(self.status.as_u16(), status);
        assert_eq!(self.json()["error"]["code"], code);
        assert_eq!(self.json()["request_id"], "sqlite-admin-grants-http");
    }
    fn document(&self, status: StatusCode, revision: u64) {
        self.headers();
        assert_eq!(self.status, status);
        assert_eq!(self.json()["revision"], revision);
        assert_eq!(self.headers[header::ETAG], format!("\"{revision}\""));
        assert_eq!(self.json()["v"], 1);
        assert!(self.json()["rules"].is_array());
        assert_eq!(self.json().get("csrf_token"), None);
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
        .header("x-request-id", "sqlite-admin-grants-http");
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
    response_bytes: usize,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    JoinHandle<std::io::Result<()>>,
) {
    let session = AdminSessionHttpConfig {
        limits: ingress::limits().authorization,
        request_timeout: Duration::from_secs(10),
    };
    let local = || {
        Some(AdminLocalBearerHttpConfig {
            audience: "admin-api".into(),
            identity_json_bytes: n(8192),
            required_scopes: vec!["admin:session".into()],
        })
    };
    let cookie = Some(AdminCookieHttpConfig {
        limits: ingress::limits(),
        policy: ingress::policy(),
        secure: true,
    });
    let router = sqlite_admin_grants_router(
        f.store.clone(),
        f.verifier(),
        AdminGrantsHttpConfig {
            session,
            body_bytes: n(1024),
            grants_json_bytes: n(65536),
            response_json_bytes: n(response_bytes),
            local: local(),
            upstream: upstream.clone(),
            cookie,
            routes: Arc::new(
                AdminGrantRoutes::new(vec!["primary".into()], "primary".into()).unwrap(),
            ),
        },
    )
    .unwrap()
    .merge(
        sqlite_admin_read_router(
            f.store.clone(),
            f.verifier(),
            session,
            AdminReadHttpConfig {
                limits: AdminReadLimits {
                    authorization: ingress::limits().authorization,
                    grants_json_bytes: n(65536),
                    response_json_bytes: n(65536),
                },
                provider_command: "literal provider".into(),
                configuration_yaml: "redacted: true\n".into(),
            },
            local(),
            upstream,
            cookie,
        )
        .unwrap(),
    );
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
#[ignore = "real TCP SQLite CAS and genuine JWT/opaque/F1/LOCAL/federated cookie possession"]
async fn sqlite_admin_grants_http_four_ingresses_cas_csrf_and_wire() {
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
    let (address, stop, task) = serve(&f, Some(trust), 65536).await;
    action(&f.db, "grants.write");
    let mut expected = revision(&f.db);
    for (index, factor) in factors.iter().enumerate() {
        let id = format!("http-{index}");
        let expected_header = expected.to_string();
        let mut headers = factor.clone();
        headers.push(("if-match", &expected_header));
        let created = send(
            address,
            "POST",
            "/admin/api/v1/grants",
            serde_json::to_vec(&body(&id)).unwrap(),
            &headers,
        )
        .await;
        expected += 1;
        created.document(StatusCode::CREATED, expected);
        assert!(
            created.json()["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["id"] == id && r["name"] == "HTTP Grant")
        );
        let mut updated = body("body-id-must-not-win");
        updated["name"] = json!("Updated");
        let expected_header = format!("W/\"{expected}\"");
        let mut headers = factor.clone();
        headers.push(("if-match", &expected_header));
        let updated = send(
            address,
            "PUT",
            &format!("/admin/api/v1/grants/{id}"),
            serde_json::to_vec(&updated).unwrap(),
            &headers,
        )
        .await;
        expected += 1;
        updated.document(StatusCode::OK, expected);
        assert_eq!(
            f.db.query_row(
                "SELECT count(*) FROM resource_grants WHERE id='body-id-must-not-win'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        let expected_header = format!("\"{expected}\"");
        let mut headers = factor.clone();
        headers.push(("if-match", &expected_header));
        let deleted = send(
            address,
            "DELETE",
            &format!("/admin/api/v1/grants/{id}"),
            vec![],
            &headers,
        )
        .await;
        expected += 1;
        deleted.document(StatusCode::OK, expected);
        assert_eq!(deleted.json()["rules"], json!([]));
    }
    // No read permission was needed to return those complete documents.
    send(
        address,
        "GET",
        "/admin/api/v1/grants",
        vec![],
        &[("authorization", jwt.as_str())],
    )
    .await
    .finite(403, "admin_forbidden");
    let valid = serde_json::to_vec(&body("must-not-apply")).unwrap();
    for value in [
        None,
        Some("0"),
        Some("garbage"),
        Some("-1"),
        Some("18446744073709551616"),
        Some("\"unclosed"),
    ] {
        let mut headers = vec![("authorization", jwt.as_str())];
        if let Some(value) = value {
            headers.push(("if-match", value));
        }
        send(
            address,
            "POST",
            "/admin/api/v1/grants",
            valid.clone(),
            &headers,
        )
        .await
        .finite(428, "precondition_required");
    }
    let expected_header = expected.to_string();
    send(
        address,
        "POST",
        "/admin/api/v1/grants",
        valid.clone(),
        &[
            ("authorization", jwt.as_str()),
            ("if-match", &expected_header),
            ("if-match", &expected_header),
        ],
    )
    .await
    .finite(428, "precondition_required");
    for stale in ["1", "18446744073709551615"] {
        send(
            address,
            "POST",
            "/admin/api/v1/grants",
            valid.clone(),
            &[("authorization", jwt.as_str()), ("if-match", stale)],
        )
        .await
        .finite(409, "revision_conflict");
    }
    let headers = [
        ("authorization", jwt.as_str()),
        ("if-match", expected_header.as_str()),
    ];
    let mut unknown = body("closed-json");
    unknown["unexpected"] = json!(true);
    send(
        address,
        "POST",
        "/admin/api/v1/grants",
        serde_json::to_vec(&unknown).unwrap(),
        &headers,
    )
    .await
    .finite(400, "invalid_grant");
    let mut padded = serde_json::to_vec(&body("body-cap")).unwrap();
    padded.extend(vec![b' '; 2048]);
    send(address, "POST", "/admin/api/v1/grants", padded, &headers)
        .await
        .finite(400, "invalid_grant");
    send(
        address,
        "PUT",
        "/admin/api/v1/grants/absent",
        valid.clone(),
        &headers,
    )
    .await
    .finite(400, "grant_write_failed");
    send(
        address,
        "DELETE",
        "/admin/api/v1/grants/absent",
        vec![],
        &headers,
    )
    .await
    .finite(400, "grant_write_failed");
    for bearer in [jwt.as_str(), opaque.as_str(), raw.as_str()] {
        send(
            address,
            "POST",
            "/admin/api/v1/grants",
            valid.clone(),
            &[
                ("cookie", "graphit_admin_session=invalid"),
                ("authorization", bearer),
                ("if-match", &expected_header),
            ],
        )
        .await
        .finite(401, "admin_unauthorized");
    }
    for cookie in [local.as_str(), federated.as_str()] {
        let noncanonical = format!("{}B", "A".repeat(42));
        for csrf in [None, Some("noncanonical="), Some(noncanonical.as_str())] {
            let mut headers = vec![("cookie", cookie), ("if-match", "1")];
            if let Some(csrf) = csrf {
                headers.push(("x-csrf-token", csrf));
            }
            send(
                address,
                "POST",
                "/admin/api/v1/grants",
                valid.clone(),
                &headers,
            )
            .await
            .finite(403, "csrf_failed");
        }
    }
    send(
        address,
        "POST",
        "/admin/api/v1/grants",
        valid.clone(),
        &[
            ("authorization", "Bearer invalid"),
            ("if-match", &expected_header),
        ],
    )
    .await
    .finite(401, "admin_unauthorized");
    action(&f.db, "session.read");
    for factor in &factors {
        let mut headers = factor.clone();
        headers.push(("if-match", &expected_header));
        send(
            address,
            "POST",
            "/admin/api/v1/grants",
            valid.clone(),
            &headers,
        )
        .await
        .finite(403, "admin_forbidden");
    }
    assert_eq!(revision(&f.db), expected);
    action(&f.db, "grants.read");
    let get = send(
        address,
        "GET",
        "/admin/api/v1/grants",
        vec![],
        &[("authorization", jwt.as_str())],
    )
    .await;
    get.document(StatusCode::OK, expected);
    let head = send(
        address,
        "HEAD",
        "/admin/api/v1/grants",
        vec![],
        &[("authorization", jwt.as_str())],
    )
    .await;
    head.headers();
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.body.is_empty());
    assert_eq!(head.headers[header::ETAG], get.headers[header::ETAG]);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    f.store.shutdown(end()).await.unwrap();
    op.close().await;
    bearer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real HTTP DATA serialization failure after a known SQLite write ACK"]
async fn sqlite_admin_grants_http_post_ack_failure_keeps_committed_write() {
    let f = Fixture::new().await;
    let jwt = ingress::jwt(&f).await;
    let bearer = Zeroizing::new(format!("Bearer {}", jwt.as_str()));
    action(&f.db, "grants.write");
    let (address, stop, task) = serve(&f, None, 2).await;
    let headers = [("authorization", bearer.as_str()), ("if-match", "1")];
    let payload = serde_json::to_vec(&body("known-commit")).unwrap();
    send(
        address,
        "POST",
        "/admin/api/v1/grants",
        payload.clone(),
        &headers,
    )
    .await
    .finite(500, "grants_read_failed");
    assert_eq!(revision(&f.db), 2);
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM resource_grants WHERE id='known-commit'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    send(address, "POST", "/admin/api/v1/grants", payload, &headers)
        .await
        .finite(409, "revision_conflict");
    assert_eq!(revision(&f.db), 2);
    action(&f.db, "grants.read");
    let current = send(
        address,
        "GET",
        "/admin/api/v1/grants",
        vec![],
        &[("authorization", bearer.as_str())],
    )
    .await;
    current.document(StatusCode::OK, 2);
    assert_eq!(current.json()["rules"][0]["id"], "known-commit");
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    f.store.shutdown(end()).await.unwrap();
}
