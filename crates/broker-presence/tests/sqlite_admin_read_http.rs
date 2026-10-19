#[path = "../../broker-control/tests/support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine ingress fixtures serve multiple targets"
)]
mod ingress;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    AdminBrokerSessionLimits, AdminCookieSessionLimits, AdminCookieSessionPolicy, AdminReadLimits,
    FlowLimits, IdentityReadLimits, LocalAuthPolicy, LocalCaptcha, LocalCaptchaConfiguration,
    LocalMfaAttemptLimiter, LocalMfaAttemptPolicy, LocalPasswordAdmission,
    LocalPasswordAdmissionPolicy, LocalPasswordEngine, SessionLimits, SqliteControlConfig,
    SqliteControlStore,
};
use broker_presence::{
    AdminCookieHttpConfig, AdminLocalBearerHttpConfig, AdminLocalLoginHttpConfig,
    AdminReadHttpConfig, AdminSessionHttpConfig, SqliteLocalLoginRuntime,
    sqlite_admin_local_login_router, sqlite_admin_read_router,
};
use broker_security::{
    CredentialDigester, DigestLimits, LocalMfaProtector, LocalPasswordHasher, TokenKind,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, StatusCode,
    http::{HeaderMap, header},
};
use hyper_util::rt::TokioIo;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
use zeroize::Zeroizing;

const PASSWORD: &str = "synthetic SQLite AdminReads HTTP password";
const YAML: &str = "source: deployment\nstorage:\n  secret: '[configured-secret]'\n";
const ROUTES: [(&str, &str); 7] = [
    ("projects", "projects.read"),
    ("roles", "roles.read"),
    ("role-assignments", "roles.read"),
    ("local-users", "users.read"),
    ("principals", "grants.read"),
    ("grants", "grants.read"),
    ("config", "configuration.read"),
];
fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(60)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
        .try_into()
        .unwrap()
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(vec![41; 32].into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
fn cookie_limits() -> AdminCookieSessionLimits {
    AdminCookieSessionLimits {
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
        authorization: AdminBrokerSessionLimits {
            identity: IdentityReadLimits {
                username_bytes: n(128),
                subject_bytes: n(512),
                role_bytes: n(128),
                roles: n(16),
                rows: n(128),
            },
            profile_json_bytes: n(8192),
        },
    }
}
fn read_config() -> AdminReadHttpConfig {
    AdminReadHttpConfig {
        limits: AdminReadLimits {
            authorization: cookie_limits().authorization,
            grants_json_bytes: n(65536),
            response_json_bytes: n(65536),
        },
        provider_command: "literal 'provider' command".into(),
        configuration_yaml: YAML.into(),
    }
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
    fn read_headers(&self) {
        assert_eq!(self.headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(self.headers[header::PRAGMA], "no-cache");
        assert!(!self.headers.contains_key(header::SET_COOKIE));
        if self.status != StatusCode::METHOD_NOT_ALLOWED {
            assert_eq!(self.headers["x-request-id"], "sqlite-admin-read-http");
        }
    }
    fn finite(&self, status: u16, code: &str) {
        self.read_headers();
        assert_eq!(self.status.as_u16(), status);
        assert_eq!(self.json()["error"]["code"], code);
        assert_eq!(self.json()["request_id"], "sqlite-admin-read-http");
    }
}
struct Fixture {
    _root: tempfile::TempDir,
    store: Arc<SqliteControlStore>,
    db: Connection,
    runtime: Arc<SqliteLocalLoginRuntime>,
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    server: JoinHandle<std::io::Result<()>>,
    access: Zeroizing<String>,
    service: Zeroizing<String>,
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
                    Duration::from_secs(10),
                    Duration::from_secs(5),
                    FlowLimits {
                        provider_bytes: n(128),
                        request_bytes: n(1024),
                        continuation_bytes: n(4096),
                    },
                )
                .unwrap(),
                digester(),
                end(),
            )
            .await
            .unwrap(),
        );
        let db = Connection::open(path).unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        let engine = Arc::new(
            LocalPasswordEngine::new(
                LocalPasswordHasher::new(Zeroizing::new(vec![43; 32].into_boxed_slice())).unwrap(),
                n(1),
                end(),
            )
            .await
            .unwrap(),
        );
        let hash = engine.hash(PASSWORD, end()).await.unwrap();
        db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',?1,'Current','current@example.invalid','org','[\"a\",\"z\"]',1,0,1,0,0)",[hash.as_str()]).unwrap();
        db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('bot','bot-subject','service','not-selected','','','','[]',1,1,1,0,0)",[]).unwrap();
        db.execute_batch("DELETE FROM role_permissions WHERE role='user';INSERT INTO role_permissions(role,action) VALUES('user','session.read')").unwrap();
        let admission = Arc::new(
            LocalPasswordAdmission::new(
                LocalPasswordAdmissionPolicy {
                    max_failures: n(32),
                    window: Duration::from_secs(60),
                    lockout: Duration::from_secs(60),
                    workers: n(1),
                    saturation_multiplier: n(2),
                    max_tracked: n(4096),
                },
                &engine,
                LocalCaptcha::new(LocalCaptchaConfiguration::Disabled, n(1), n(2)).unwrap(),
            )
            .unwrap(),
        );
        let runtime = Arc::new(SqliteLocalLoginRuntime::new(
            engine,
            admission,
            Arc::new(digester()),
            Arc::new(
                LocalMfaProtector::new(Zeroizing::new(vec![47; 32].into_boxed_slice())).unwrap(),
            ),
            Arc::new(
                LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(120))
                    .unwrap(),
            ),
            Arc::new(LocalMfaAttemptLimiter::new(
                LocalMfaAttemptPolicy::new(
                    NonZeroU32::new(16).unwrap(),
                    Duration::from_secs(60),
                    Duration::from_secs(60),
                    n(16),
                )
                .unwrap(),
            )),
        ));
        let issue = |subject: &str, username: &str, kind: TokenKind| {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).unwrap();
            let raw = Zeroizing::new(format!(
                "{}{}",
                if matches!(kind, TokenKind::LocalAccess) {
                    "gb_at_"
                } else {
                    "gb_sc_"
                },
                URL_SAFE_NO_PAD.encode(bytes)
            ));
            let hash = digester().token(kind, raw.as_bytes()).unwrap().to_sql_hex();
            let principal=json!({"issuer":"local","subject":subject,"username":username,"auth_method":"local-token","roles":[],"teams":[],"local_user_revision":1}).to_string();
            db.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES(?1,?2,?3,?4,'different-pseudonym',?5,'client','admin-api','','[\"admin:session\"]',1,'',0,?6,0)",params![hash,username,if matches!(kind,TokenKind::LocalAccess){"access"}else{"service"},subject,principal,now()+60_000_000]).unwrap();
            raw
        };
        let access = issue("alice-subject", "alice", TokenKind::LocalAccess);
        let service = issue("bot-subject", "bot", TokenKind::ServiceCredential);
        let cookie = AdminCookieHttpConfig {
            limits: cookie_limits(),
            policy: AdminCookieSessionPolicy {
                session_ttl: Duration::from_secs(600),
            },
            secure: true,
        };
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let issuer = broker_control::BrokerAccessIssuer::new(
            "https://broker.example",
            "graphit-broker",
            "sqlite-read-key",
            &key.serialize_der(),
        )
        .unwrap();
        let verifier = Arc::new(
            broker_control::BrokerAccessVerifier::new(
                "https://broker.example",
                "graphit-broker",
                None,
                issuer.jwks(),
                n(8192),
            )
            .unwrap(),
        );
        let router = sqlite_admin_local_login_router(
            store.clone(),
            AdminLocalLoginHttpConfig {
                body_bytes: n(32768),
                response_json_bytes: n(32768),
                request_timeout: Duration::from_secs(30),
                cookie: Some(cookie),
            },
            Some(runtime.clone()),
        )
        .unwrap()
        .merge(
            sqlite_admin_read_router(
                store.clone(),
                verifier,
                AdminSessionHttpConfig {
                    limits: cookie_limits().authorization,
                    request_timeout: Duration::from_millis(200),
                },
                read_config(),
                Some(AdminLocalBearerHttpConfig {
                    audience: "admin-api".into(),
                    identity_json_bytes: n(8192),
                    required_scopes: vec!["admin:session".into()],
                }),
                None,
                Some(cookie),
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        Self {
            _root: root,
            store,
            db,
            runtime,
            address,
            stop: Some(stop),
            server,
            access,
            service,
        }
    }
    fn action(&self, action: &str) {
        self.db
            .execute("DELETE FROM role_permissions WHERE role='user'", [])
            .unwrap();
        self.db
            .execute(
                "INSERT INTO role_permissions(role,action) VALUES('user',?1)",
                [action],
            )
            .unwrap();
    }
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        headers: &[(&str, &str)],
    ) -> Reply {
        send_to(self.address, method, path, body, headers).await
    }
    async fn close(mut self) {
        self.runtime.stop_admission();
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(35), &mut self.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.runtime.close().await;
        self.store.shutdown(end()).await.unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
            self.server.abort();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real TCP, native Argon2 login, SQLite cookie and opaque possession"]
async fn sqlite_admin_reads_http_real_local_cookie_and_opaque_contract() {
    let f = Fixture::new().await;
    let login = f
        .send(
            "POST",
            "/admin/auth/local",
            serde_json::to_vec(&json!({"username":"alice","password":PASSWORD})).unwrap(),
            &[],
        )
        .await;
    assert_eq!(login.status, StatusCode::NO_CONTENT);
    assert!(login.body.is_empty());
    let cookie = Zeroizing::new(
        login.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned(),
    );
    let bearer = Zeroizing::new(format!("Bearer {}", f.access.as_str()));
    let service = Zeroizing::new(format!("Bearer {}", f.service.as_str()));
    for (route, permission) in ROUTES {
        f.action(permission);
        let path = format!("/admin/api/v1/{route}");
        let get = f
            .send("GET", &path, vec![], &[("cookie", cookie.as_str())])
            .await;
        get.read_headers();
        assert_eq!(get.status, StatusCode::OK);
        let head = f
            .send("HEAD", &path, vec![], &[("cookie", cookie.as_str())])
            .await;
        head.read_headers();
        assert_eq!(head.status, StatusCode::OK);
        assert!(head.body.is_empty());
        for name in [
            header::CACHE_CONTROL,
            header::PRAGMA,
            header::CONTENT_TYPE,
            header::ETAG,
        ] {
            assert_eq!(get.headers.get(&name), head.headers.get(&name));
        }
        for token in [bearer.as_str(), service.as_str()] {
            let opaque = f
                .send("GET", &path, vec![], &[("authorization", token)])
                .await;
            opaque.read_headers();
            assert_eq!(opaque.status, StatusCode::OK);
            let opaque_head = f
                .send("HEAD", &path, vec![], &[("authorization", token)])
                .await;
            opaque_head.read_headers();
            assert_eq!(opaque_head.status, StatusCode::OK);
            assert!(opaque_head.body.is_empty());
        }
        assert_eq!(get.json().get("csrf_token"), None);
        if route == "config" {
            assert_eq!(
                get.json(),
                json!({"source":"deployment","restart_required":true,"yaml":YAML})
            );
        }
        if route == "grants" {
            assert_eq!(
                get.headers[header::ETAG].to_str().unwrap(),
                format!("\"{}\"", get.json()["revision"].as_i64().unwrap())
            );
        }
        f.action("session.read");
        f.send("GET", &path, vec![], &[("cookie", cookie.as_str())])
            .await
            .finite(403, "admin_forbidden");
    }
    f.action("*");
    let path = "/admin/api/v1/roles";
    let accepted = f
        .send(
            "GET",
            path,
            vec![],
            &[
                ("cookie", cookie.as_str()),
                ("x-csrf-token", "not-required-on-read"),
            ],
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK);
    accepted.read_headers();
    for headers in [
        vec![
            ("cookie", "graphit_admin_session=invalid"),
            ("authorization", bearer.as_str()),
        ],
        vec![("cookie", cookie.as_str()), ("cookie", cookie.as_str())],
        vec![
            ("cookie", "graphit_admin_session=a; graphit_admin_session=b"),
            ("authorization", bearer.as_str()),
        ],
        vec![
            ("authorization", bearer.as_str()),
            ("authorization", bearer.as_str()),
        ],
        vec![("authorization", "Basic malformed")],
    ] {
        f.send("GET", path, vec![], &headers)
            .await
            .finite(401, "admin_unauthorized");
    }
    let empty = f
        .send(
            "GET",
            path,
            vec![],
            &[
                ("cookie", "graphit_admin_session="),
                ("authorization", bearer.as_str()),
            ],
        )
        .await;
    empty.read_headers();
    assert_eq!(empty.status, StatusCode::OK);
    f.send("GET", path, vec![], &[])
        .await
        .finite(401, "admin_unauthorized");
    let method = f
        .send("POST", path, vec![], &[("cookie", cookie.as_str())])
        .await;
    method.read_headers();
    assert_eq!(method.status, StatusCode::METHOD_NOT_ALLOWED);
    let config = f
        .send(
            "GET",
            "/admin/api/v1/config",
            br#"{"yaml":"untrusted request secret"}"#.to_vec(),
            &[("cookie", cookie.as_str())],
        )
        .await;
    assert_eq!(config.json()["yaml"], YAML);
    f.db.execute(
        "UPDATE local_users SET password_change_required=1 WHERE username='alice'",
        [],
    )
    .unwrap();
    f.send(
        "GET",
        path,
        vec![],
        &[
            ("cookie", cookie.as_str()),
            ("authorization", bearer.as_str()),
        ],
    )
    .await
    .finite(401, "admin_unauthorized");
    assert_eq!(
        f.send("GET", path, vec![], &[("authorization", bearer.as_str())])
            .await
            .status,
        StatusCode::OK
    );
    f.db.execute(
        "UPDATE local_users SET password_change_required=0 WHERE username='alice'",
        [],
    )
    .unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    f.send("GET", path, vec![], &[("cookie", cookie.as_str())])
        .await
        .finite(504, "administration_unavailable");
    f.db.execute_batch("ROLLBACK").unwrap();
    f.db.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    f.db.execute("UPDATE resource_acl_state SET revision=0", [])
        .unwrap();
    f.send(
        "GET",
        "/admin/api/v1/projects",
        vec![],
        &[("cookie", cookie.as_str())],
    )
    .await
    .finite(503, "projects_read_failed");
    f.send(
        "GET",
        "/admin/api/v1/grants",
        vec![],
        &[("cookie", cookie.as_str())],
    )
    .await
    .finite(500, "grants_read_failed");
    f.db.execute("UPDATE resource_acl_state SET revision=1", [])
        .unwrap();
    f.db.execute(
        "UPDATE local_users SET name=?1 WHERE username='alice'",
        [vec![0xffu8]],
    )
    .unwrap();
    f.send("GET", path, vec![], &[("cookie", cookie.as_str())])
        .await
        .finite(500, "authorization_failed");
    f.db.execute(
        "UPDATE local_users SET name='Current' WHERE username='alice'",
        [],
    )
    .unwrap();
    f.db.execute(
        "UPDATE local_tokens SET revoked_at=?1 WHERE token_kind='access'",
        [now()],
    )
    .unwrap();
    f.send("GET", path, vec![], &[("authorization", bearer.as_str())])
        .await
        .finite(401, "admin_unauthorized");
    f.store.shutdown(end()).await.unwrap();
    f.send("GET", path, vec![], &[("cookie", cookie.as_str())])
        .await
        .finite(503, "administration_unavailable");
    f.close().await;
}

async fn send_to(
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
        .header("x-request-id", "sqlite-admin-read-http");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(hyper::body::Bytes::from(body)))
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(40), sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    let (parts, body) = response.into_parts();
    let body = tokio::time::timeout(Duration::from_secs(5), body.collect())
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
        body: Zeroizing::new(body.to_vec()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real TCP plus signed Broker, HTTPS F1 and genuine LOCAL/federated cookies"]
async fn sqlite_admin_reads_http_full_ingresses_per_action_and_precedence() {
    let f = ingress::fixture::Fixture::new().await;
    f.db.execute("UPDATE local_users SET teams_json='[\"engineering\"]'", [])
        .unwrap();
    ingress::allow_session(&f);
    let jwt = ingress::jwt(&f).await;
    let opaque = ingress::persisted_opaque(&f);
    let local_cookie = ingress::local_cookie(&f).await;
    let mut bearer = ingress::upstream::UpstreamFixture::new().await;
    let mut op = ingress::browser_op().await;
    let mut bearer_config = ingress::config(&bearer.issuer, &bearer.ca, false, Some("roles"));
    bearer_config.id = "bearer".into();
    let trust = ingress::trust(vec![
        ingress::config(&op.issuer, &op.ca, true, Some("roles")),
        bearer_config,
    ]);
    let raw = bearer.sign(&bearer.claims(), "upstream-key", "at+jwt");
    let login = ingress::h1(&f, &op, &trust, broker_control::FlowPurpose::Admin, end()).await;
    let federated = f
        .store
        .admin_cookie_sessions(ingress::limits(), ingress::policy(), Some(trust.clone()))
        .unwrap()
        .issue_upstream(login, end())
        .await
        .unwrap();
    let network = (op.token_hits(), op.userinfo_hits(), op.jwks_hits());
    let router = sqlite_admin_read_router(
        f.store.clone(),
        f.verifier(),
        AdminSessionHttpConfig {
            limits: ingress::limits().authorization,
            request_timeout: Duration::from_secs(10),
        },
        read_config(),
        Some(AdminLocalBearerHttpConfig {
            audience: "admin-api".into(),
            identity_json_bytes: n(8192),
            required_scopes: vec!["admin:session".into()],
        }),
        Some(trust),
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
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
    });
    let jwt = Zeroizing::new(format!("Bearer {}", jwt.as_str()));
    let raw = Zeroizing::new(format!("Bearer {}", raw.as_str()));
    let opaque = Zeroizing::new(format!("Bearer {}", opaque.as_str()));
    let local = Zeroizing::new(format!("graphit_admin_session={}", local_cookie.secret()));
    let federated = Zeroizing::new(format!("graphit_admin_session={}", federated.secret()));
    let credentials = [
        ("authorization", jwt.as_str()),
        ("authorization", raw.as_str()),
        ("authorization", opaque.as_str()),
        ("cookie", local.as_str()),
        ("cookie", federated.as_str()),
    ];
    for (route, permission) in ROUTES {
        let path = format!("/admin/api/v1/{route}");
        for (permission, allowed) in [(permission, true), ("session.read", false)] {
            action(&f.db, permission);
            for credential in credentials {
                let get = send_to(address, "GET", &path, vec![], &[credential]).await;
                let head = send_to(address, "HEAD", &path, vec![], &[credential]).await;
                get.read_headers();
                head.read_headers();
                assert_eq!(
                    get.status,
                    if allowed {
                        StatusCode::OK
                    } else {
                        StatusCode::FORBIDDEN
                    },
                    "{route} with {}",
                    credential.0
                );
                assert_eq!(head.status, get.status);
                assert!(head.body.is_empty());
                for name in [
                    header::CACHE_CONTROL,
                    header::PRAGMA,
                    header::CONTENT_TYPE,
                    header::ETAG,
                ] {
                    assert_eq!(get.headers.get(&name), head.headers.get(&name));
                }
                assert_eq!(get.json().get("csrf_token"), None);
                if allowed && route == "grants" {
                    assert_eq!(
                        get.headers[header::ETAG].to_str().unwrap(),
                        format!("\"{}\"", get.json()["revision"].as_i64().unwrap())
                    );
                }
            }
        }
    }
    action(&f.db, "*");
    for bearer in [jwt.as_str(), raw.as_str(), opaque.as_str()] {
        send_to(
            address,
            "GET",
            "/admin/api/v1/roles",
            vec![],
            &[
                ("cookie", "graphit_admin_session=invalid"),
                ("authorization", bearer),
            ],
        )
        .await
        .finite(401, "admin_unauthorized");
    }
    assert_eq!(
        network,
        (op.token_hits(), op.userinfo_hits(), op.jwks_hits())
    );
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    f.store.shutdown(end()).await.unwrap();
    op.close().await;
    bearer.close().await;
}
fn action(db: &Connection, permission: &str) {
    db.execute("DELETE FROM role_permissions WHERE role='user'", [])
        .unwrap();
    db.execute(
        "INSERT INTO role_permissions(role,action)VALUES('user',?1)",
        [permission],
    )
    .unwrap();
}
