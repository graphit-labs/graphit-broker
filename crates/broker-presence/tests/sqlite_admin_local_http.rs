use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    AdminBrokerSessionLimits, AdminCookieSessionLimits, AdminCookieSessionPolicy, FlowLimits,
    IdentityReadLimits, LocalAuthPolicy, LocalAuthStep, LocalCaptcha, LocalCaptchaConfiguration,
    LocalMfaAttemptLimiter, LocalMfaAttemptPolicy, LocalPasswordAdmission,
    LocalPasswordAdmissionPolicy, LocalPasswordEngine, SessionLimits, SqliteControlConfig,
    SqliteControlStore,
};
use broker_presence::{
    AdminCookieHttpConfig, AdminLocalLoginHttpConfig, AdminSessionHttpConfig,
    SqliteLocalLoginRuntime, sqlite_admin_local_login_router, sqlite_local_admin_session_router,
};
use broker_security::{
    CredentialDigester, DigestLimits, LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher,
    TokenKind,
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
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
use zeroize::Zeroizing;
const PASSWORD: &str = "synthetic LOCAL HTTP initial password";
const NEXT: &str = "synthetic LOCAL HTTP changed password";
fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(60)
}
fn utc() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
fn limits() -> AdminCookieSessionLimits {
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
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(vec![41; 32].into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
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
    fn finite(&self, status: u16, code: &str) {
        assert_eq!(self.status.as_u16(), status);
        assert_eq!(self.json()["error"]["code"], code);
        assert!(!self.headers.contains_key(header::SET_COOKIE));
    }
    fn cookie(&self) -> Zeroizing<String> {
        let h = self
            .headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        for flag in [
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Expires=",
            "Max-Age=",
            "Secure",
        ] {
            assert!(h.contains(flag));
        }
        Zeroizing::new(h.split(';').next().unwrap().to_owned())
    }
    fn clear(&self) {
        assert_eq!(self.status, StatusCode::NO_CONTENT);
        let h = self
            .headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(h.starts_with("graphit_admin_session=;"));
        assert!(h.contains("Max-Age=0"));
        assert!(h.contains("HttpOnly") && h.contains("SameSite=Lax") && h.contains("Secure"));
        assert!(self.body.is_empty());
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    store: Arc<SqliteControlStore>,
    db: Connection,
    engine: Arc<LocalPasswordEngine>,
    runtime: Arc<SqliteLocalLoginRuntime>,
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    server: JoinHandle<std::io::Result<()>>,
}
impl Fixture {
    async fn new(required: bool, change: bool, enabled: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private/broker.db");
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
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
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
        db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',?1,'Initial','initial@example.test','org','[\"beta\",\"alpha\"]',1,?2,1,0,0)",params![hash.as_str(),i64::from(change)]).unwrap();
        db.execute_batch("INSERT OR IGNORE INTO roles(name,created_at) VALUES('user',0);DELETE FROM role_permissions WHERE role='user';INSERT INTO role_permissions(role,action) VALUES('user','session.read')").unwrap();
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
            engine.clone(),
            admission,
            Arc::new(digester()),
            Arc::new(
                LocalMfaProtector::new(Zeroizing::new(vec![47; 32].into_boxed_slice())).unwrap(),
            ),
            Arc::new(
                LocalAuthPolicy::new(required, "Graphit Broker".into(), Duration::from_secs(120))
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
        assert_eq!(
            format!("{runtime:?}"),
            "SqliteLocalLoginRuntime([REDACTED])"
        );
        let cookie = AdminCookieHttpConfig {
            limits: limits(),
            policy: AdminCookieSessionPolicy {
                session_ttl: Duration::from_secs(600),
            },
            secure: true,
        };
        let router = sqlite_admin_local_login_router(
            store.clone(),
            AdminLocalLoginHttpConfig {
                body_bytes: n(32768),
                response_json_bytes: n(32768),
                request_timeout: Duration::from_secs(30),
                cookie: Some(cookie),
            },
            enabled.then(|| runtime.clone()),
        )
        .unwrap()
        .merge(
            sqlite_local_admin_session_router(
                store.clone(),
                AdminSessionHttpConfig {
                    limits: limits().authorization,
                    request_timeout: Duration::from_millis(100),
                },
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
            _temp: temp,
            path,
            store,
            db,
            engine,
            runtime,
            address,
            stop: Some(stop),
            server,
        }
    }
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        cookie: Option<&str>,
        csrf: Option<&str>,
    ) -> Reply {
        let stream = TcpStream::connect(self.address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let driver = tokio::spawn(connection);
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", self.address.to_string())
            .header("content-type", "application/json")
            .header("connection", "close")
            .header("x-request-id", "sqlite-local-http");
        if let Some(c) = cookie {
            builder = builder.header("cookie", c);
        }
        if let Some(c) = csrf {
            builder = builder.header("x-csrf-token", c);
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
        assert_eq!(parts.headers["cache-control"], "no-store");
        assert_eq!(parts.headers["pragma"], "no-cache");
        assert_eq!(parts.headers["x-request-id"], "sqlite-local-http");
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: Zeroizing::new(body.to_vec()),
        }
    }
    async fn initial(&self, password: &str) -> Reply {
        self.send(
            "POST",
            "/admin/auth/local",
            serde_json::to_vec(&json!({"username":" alice ","password":password})).unwrap(),
            None,
            None,
        )
        .await
    }
    async fn next(&self, input: Value) -> Reply {
        self.send(
            "POST",
            "/admin/auth/local/continue",
            serde_json::to_vec(&input).unwrap(),
            None,
            None,
        )
        .await
    }
    async fn session(&self, cookie: &str) -> Reply {
        self.send("GET", "/admin/api/v1/session", vec![], Some(cookie), None)
            .await
    }
    async fn logout(&self, cookie: Option<&str>, csrf: Option<&str>) -> Reply {
        self.send("POST", "/admin/auth/logout", vec![], cookie, csrf)
            .await
    }
    fn count(&self) -> i64 {
        self.db
            .query_row("SELECT count(*) FROM admin_sessions", [], |r| r.get(0))
            .unwrap()
    }
    fn hash(&self, cookie: &str) -> String {
        digester()
            .token(
                TokenKind::AdminSession,
                cookie.split_once('=').unwrap().1.as_bytes(),
            )
            .unwrap()
            .to_sql_hex()
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
        }
        self.server.abort();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine TCP/SQLite/Argon2 administrative login, current session and confirmed logout"]
async fn sqlite_admin_local_http_cookie_session_logout_contract() {
    let f = Fixture::new(false, false, true).await;
    for path in ["/admin", "/admin/"] {
        let r = f.send("GET", path, vec![], None, None).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(
            r.headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert!(!r.body.is_empty());
        let r = f.send("HEAD", path, vec![], None, None).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(r.body.is_empty());
    }
    let options = f
        .send("GET", "/admin/api/v1/login-options", vec![], None, None)
        .await;
    assert_eq!(options.json()["local"], true);
    assert_eq!(options.json()["oidc_providers"], json!([]));
    assert!(options.json().get("captcha").is_none());
    f.send("GET", "/admin/api/v1/session", vec![], None, None)
        .await
        .finite(401, "admin_unauthorized");
    f.session("graphit_admin_session=bad")
        .await
        .finite(401, "admin_unauthorized");
    f.logout(Some("graphit_admin_session=bad"), None)
        .await
        .clear();
    let issued = f.initial(PASSWORD).await;
    assert_eq!(issued.status, StatusCode::NO_CONTENT);
    assert!(issued.body.is_empty());
    let cookie = issued.cookie();
    assert_eq!(cookie.split_once('=').unwrap().1.len(), 43);
    assert_eq!(f.count(), 1);
    let stored: String =
        f.db.query_row("SELECT token_hash FROM admin_sessions", [], |r| r.get(0))
            .unwrap();
    assert_eq!(stored, f.hash(&cookie));
    assert_eq!(stored.len(), 64);
    assert_ne!(stored, cookie.split_once('=').unwrap().1);
    let current = f.session(&cookie).await;
    assert_eq!(current.status, StatusCode::OK);
    assert!(!current.headers.contains_key(header::SET_COOKIE));
    let value = current.json();
    assert_eq!(value["username"], "alice");
    assert_eq!(value["subject"], "alice-subject");
    assert_eq!(value["teams"], json!(["alpha", "beta"]));
    assert_eq!(value["role_source"], "database");
    assert_eq!(value["roles"], json!(["user"]));
    assert_eq!(value["permissions"], json!(["session.read"]));
    let csrf = Zeroizing::new(value["csrf_token"].as_str().unwrap().to_owned());
    assert_eq!(csrf.len(), 43);
    let expires: i64 =
        f.db.query_row("SELECT expires_at FROM admin_sessions", [], |r| r.get(0))
            .unwrap();
    let head = f
        .send("HEAD", "/admin/api/v1/session", vec![], Some(&cookie), None)
        .await;
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.body.is_empty());
    assert!(!head.headers.contains_key(header::SET_COOKIE));
    assert_eq!(
        f.db.query_row::<i64, _, _>("SELECT expires_at FROM admin_sessions", [], |r| r.get(0))
            .unwrap(),
        expires
    );
    f.db.execute_batch("UPDATE local_users SET name='Current HTTP',teams_json='[\"current\"]';INSERT INTO roles(name,created_at) VALUES('reader',0);INSERT INTO role_permissions(role,action) VALUES('reader','roles.read');INSERT INTO role_assignments(subject,role,created_at) VALUES('local|alice-subject','reader',0)").unwrap();
    let value = f.session(&cookie).await.json();
    assert_eq!(value["name"], "Current HTTP");
    assert_eq!(value["teams"], json!(["current"]));
    assert_eq!(value["roles"], json!(["reader", "user"]));
    assert_eq!(value["permissions"], json!(["roles.read", "session.read"]));
    for change in ["revision=2", "enabled=0"] {
        f.db.execute(&format!("UPDATE local_users SET {change}"), [])
            .unwrap();
        f.session(&cookie).await.finite(401, "admin_unauthorized");
        f.db.execute_batch("UPDATE local_users SET revision=1,enabled=1")
            .unwrap();
    }
    f.db.execute_batch("DELETE FROM role_permissions WHERE role='user'")
        .unwrap();
    f.session(&cookie).await.finite(403, "admin_forbidden");
    f.initial(PASSWORD).await.finite(403, "admin_forbidden");
    assert_eq!(f.count(), 1);
    f.logout(Some(&cookie), None)
        .await
        .finite(403, "csrf_failed");
    f.logout(Some(&cookie), Some(&URL_SAFE_NO_PAD.encode([99; 32])))
        .await
        .finite(403, "csrf_failed");
    assert_eq!(f.count(), 1);
    f.db.execute_batch("UPDATE local_users SET enabled=0")
        .unwrap();
    f.logout(Some(&cookie), Some(&csrf)).await.clear();
    assert_eq!(f.count(), 0);
    f.logout(Some(&cookie), Some("bad")).await.clear();
    f.db.execute_batch("UPDATE local_users SET enabled=1;INSERT INTO role_permissions(role,action) VALUES('user','session.read')").unwrap();
    let c = f.initial(PASSWORD).await.cookie();
    f.db.execute(
        "UPDATE admin_sessions SET created_at=?1,expires_at=?2 WHERE token_hash=?3",
        params![utc() - 2_000_000, utc() - 1_000_000, f.hash(&c)],
    )
    .unwrap();
    f.session(&c).await.finite(401, "admin_unauthorized");
    assert_eq!(f.count(), 0);
    f.logout(Some(&c), Some("bad")).await.clear();
    let c = f.initial(PASSWORD).await.cookie();
    f.db.execute(
        "UPDATE admin_sessions SET created_at=?1,expires_at=?2 WHERE token_hash=?3",
        params![utc() - 2_000_000, utc() - 1_000_000, f.hash(&c)],
    )
    .unwrap();
    f.logout(Some(&c), Some("bad")).await.clear();
    assert_eq!(f.count(), 0);
    let c = f.initial(PASSWORD).await.cookie();
    let csrf = Zeroizing::new(
        f.session(&c).await.json()["csrf_token"]
            .as_str()
            .unwrap()
            .to_owned(),
    );
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    f.session(&c)
        .await
        .finite(504, "administration_unavailable");
    f.logout(Some(&c), Some(&csrf))
        .await
        .finite(504, "administration_unavailable");
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.count(), 1);
    let mut peer = TcpStream::connect(f.address).await.unwrap();
    peer.write_all(b"POST /admin/auth/local HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"username\":\"alice\"").await.unwrap();
    drop(peer);
    assert_eq!(f.session(&c).await.status, StatusCode::OK);
    f.db.execute(
        "UPDATE admin_sessions SET csrf_token='bad' WHERE token_hash=?1",
        [f.hash(&c)],
    )
    .unwrap();
    f.logout(Some(&c), None)
        .await
        .finite(500, "authorization_failed");
    assert_eq!(f.count(), 1);
    f.db.execute(
        "UPDATE admin_sessions SET csrf_token=?1 WHERE token_hash=?2",
        params![csrf.as_str(), f.hash(&c)],
    )
    .unwrap();
    f.store.shutdown(end()).await.unwrap();
    f.session(&c)
        .await
        .finite(503, "administration_unavailable");
    f.logout(Some(&c), Some(&csrf))
        .await
        .finite(503, "administration_unavailable");
    assert_eq!(f.count(), 1);
    assert!(f.path.exists());
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real HTTP password-change admission, TOTP enrollment/QR, recovery and server-purpose bindings"]
async fn sqlite_admin_local_http_password_mfa_recovery_contract() {
    let f = Fixture::new(true, true, true).await;
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", PASSWORD, end())
        .await
        .unwrap();
    let foreign = match f
        .runtime
        .authentication(&f.store)
        .begin(
            proof,
            LocalAuthBinding::OauthAuthorize(b"foreign-request"),
            end(),
        )
        .await
        .unwrap()
    {
        LocalAuthStep::Pending(p) => p,
        _ => panic!("genuine pending password change expected"),
    };
    f.next(json!({"challenge_token":foreign.challenge(),"new_password":NEXT}))
        .await
        .finite(401, "local_login_step_failed");
    assert_eq!(f.count(), 0);
    let r = f.initial(PASSWORD).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(!r.headers.contains_key(header::SET_COOKIE));
    let p = r.json();
    assert_eq!(p["status"], "password-change");
    let challenge = Zeroizing::new(p["challenge_token"].as_str().unwrap().to_owned());
    f.next(json!({"challenge_token":challenge.as_str(),"new_password":"short"}))
        .await
        .finite(400, "invalid_request");
    let r = f
        .next(json!({"challenge_token":challenge.as_str(),"new_password":NEXT}))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(!r.headers.contains_key(header::SET_COOKIE));
    let p = r.json();
    assert_eq!(p["status"], "mfa-enrollment");
    assert!(
        p["qr_code_data_url"]
            .as_str()
            .unwrap()
            .starts_with("data:image/png;base64,")
    );
    let uri = Zeroizing::new(p["otpauth_uri"].as_str().unwrap().to_owned());
    let challenge = Zeroizing::new(p["challenge_token"].as_str().unwrap().to_owned());
    let sdk = totp_rs::Totp::from_url(&uri).unwrap();
    let code = Zeroizing::new(sdk.generate(utc() as u64 / 1_000_000).to_string());
    let r = f
        .next(json!({"challenge_token":challenge.as_str(),"code":code.as_str()}))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let cookie = r.cookie();
    let value = r.json();
    assert_eq!(value["status"], "complete");
    assert_eq!(value["recovery_codes"].as_array().unwrap().len(), 10);
    let recovery = Zeroizing::new(value["recovery_codes"][0].as_str().unwrap().to_owned());
    assert_eq!(f.session(&cookie).await.status, StatusCode::OK);
    f.next(json!({"challenge_token":challenge.as_str(),"code":code.as_str()}))
        .await
        .finite(401, "local_login_step_failed");
    let p = f.initial(NEXT).await.json();
    assert_eq!(p["status"], "mfa");
    let r = f
        .next(json!({"challenge_token":p["challenge_token"],"code":recovery.as_str()}))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.body.is_empty());
    let second = r.cookie();
    let p = f.initial(NEXT).await.json();
    let before = f.count();
    let r = f
        .next(json!({"challenge_token":p["challenge_token"],"code":recovery.as_str()}))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(!r.headers.contains_key(header::SET_COOKIE));
    assert_eq!(r.json()["status"], "mfa");
    assert!(r.json().get("recovery_codes").is_none());
    assert_eq!(f.count(), before);
    assert_eq!(
        f.db.query_row::<i64, _, _>("SELECT count(*) FROM local_mfa_recovery_codes", [], |r| r
            .get(0))
            .unwrap(),
        9
    );
    let session = f.session(&second).await.json();
    f.logout(Some(&second), session["csrf_token"].as_str())
        .await
        .clear();
    let session = f.session(&cookie).await.json();
    f.logout(Some(&cookie), session["csrf_token"].as_str())
        .await
        .clear();
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real disabled owner, strict shared JSON/limits and finite admission errors"]
async fn sqlite_admin_local_http_disabled_and_input_contract() {
    let f = Fixture::new(false, false, false).await;
    let options = f
        .send("GET", "/admin/api/v1/login-options", vec![], None, None)
        .await;
    assert_eq!(options.json()["local"], false);
    f.initial(PASSWORD)
        .await
        .finite(503, "administration_unavailable");
    assert_eq!(f.count(), 0);
    f.close().await;
    let f = Fixture::new(false, false, true).await;
    for raw in [
        br#"{"username":"alice","username":"bob","password":"synthetic"}"#.to_vec(),
        br#"{"username":"alice","password":"synthetic","purpose":"admin-login"}"#.to_vec(),
        br#"{"username":"alice","password":null}"#.to_vec(),
        b"{".to_vec(),
    ] {
        f.send("POST", "/admin/auth/local", raw, None, None)
            .await
            .finite(400, "invalid_request");
        assert_eq!(f.count(), 0);
    }
    f.send("POST", "/admin/auth/local", vec![b' '; 32769], None, None)
        .await
        .finite(413, "invalid_request");
    f.initial("wrong synthetic password")
        .await
        .finite(401, "local_login_failed");
    assert_eq!(f.count(), 0);
    let unknown = format!("graphit_admin_session={}", URL_SAFE_NO_PAD.encode([90; 32]));
    f.session(&unknown).await.finite(401, "admin_unauthorized");
    f.logout(Some(&unknown), Some("malformed")).await.clear();
    let duplicate = format!("{unknown}; {unknown}");
    f.session(&duplicate)
        .await
        .finite(401, "admin_unauthorized");
    f.logout(Some(&duplicate), None)
        .await
        .finite(401, "admin_unauthorized");
    f.close().await;
}
