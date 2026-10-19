use broker_control::{
    BrokerAccessIssuer, BrokerAccessVerifier, DeviceAuthorizationPolicy, FlowLimits,
    LocalAuthPolicy, LocalAuthStep, LocalCaptcha, LocalCaptchaConfiguration, LocalCaptchaProvider,
    LocalMfaAttemptLimiter, LocalMfaAttemptPolicy, LocalPasswordAdmission,
    LocalPasswordAdmissionPolicy, LocalPasswordEngine, OidcAuthorizationConfiguration,
    OidcAuthorizationLimits, OidcAuthorizationPolicy, OidcTokenExchangePolicy, SqliteControlConfig,
    SqliteControlStore,
};
use broker_presence::{
    BrokerProjectAuthorizationHttpConfig, OidcDeviceHttpConfig, OidcTokenHttpConfig,
    SqliteLocalLoginRuntime, sqlite_broker_project_authorization_router,
    sqlite_local_oidc_device_router, sqlite_local_oidc_token_router,
};
use broker_security::{
    CredentialDigester, DigestLimits, LocalAuthBinding, LocalAuthPurpose, LocalMfaProtector,
    LocalPasswordHasher,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, StatusCode,
    http::{HeaderMap, header},
};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
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
const PASSWORD: &str = "synthetic SQLite Device HTTP password";
const NEXT: &str = "different synthetic SQLite Device password";
const CLIENT: &str = "graphit-cli";
const ISSUER: &str = "https://broker.example";
const AUDIENCE: &str = "graphit-broker";
const RESOURCE: &str = "https://broker.example/v1";
const VERIFY: &str = "https://Broker.Example:443/oauth/device";
fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(60)
}
fn utc() -> i64 {
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
fn form(fields: &[(&str, &str)]) -> Zeroizing<String> {
    Zeroizing::new(
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish(),
    )
}
fn html_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}
fn input(html: &str, name: &str) -> Zeroizing<String> {
    let prefix = format!("name=\"{name}\" value=\"");
    Zeroizing::new(html_unescape(
        html.split_once(&prefix)
            .unwrap()
            .1
            .split_once('"')
            .unwrap()
            .0,
    ))
}
fn claims(issuer: &BrokerAccessIssuer, raw: &str, audience: &str) -> Value {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.set_audience(&[audience]);
    validation.set_issuer(&[ISSUER]);
    decode::<Value>(
        raw,
        &DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap(),
        &validation,
    )
    .unwrap()
    .claims
}
struct Fixture {
    _temp: tempfile::TempDir,
    store: Arc<SqliteControlStore>,
    db: Connection,
    runtime: Arc<SqliteLocalLoginRuntime>,
    authorization: Arc<OidcAuthorizationPolicy>,
    tokens: Arc<OidcTokenExchangePolicy>,
    device: Arc<DeviceAuthorizationPolicy>,
    issuer: Arc<BrokerAccessIssuer>,
}
impl Fixture {
    async fn new(mfa: bool, change: bool, captcha: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private/broker.db");
        let store = Arc::new(
            SqliteControlStore::open(
                SqliteControlConfig::new(
                    path.clone(),
                    Duration::from_secs(10),
                    Duration::from_secs(30),
                    Duration::from_secs(10),
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
        db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',?1,'Alice','alice@example.invalid','org','[\"engineering\"]',1,?2,1,?3,?3)",params![hash.as_str(),i64::from(change),utc()]).unwrap();
        let captcha = if captcha {
            LocalCaptchaConfiguration::Enabled {
                provider: LocalCaptchaProvider::Turnstile,
                site_key: "sqlite-browser-site-key".into(),
                secret_key: Zeroizing::new("synthetic-provider-secret".into()),
                public_url: ISSUER.parse().unwrap(),
                trigger_multiplier: 0.0,
                verification_timeout: Duration::from_secs(1),
            }
        } else {
            LocalCaptchaConfiguration::Disabled
        };
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
                LocalCaptcha::new(captcha, n(1), n(2)).unwrap(),
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
                LocalAuthPolicy::new(mfa, "Graphit Broker".into(), Duration::from_secs(120))
                    .unwrap(),
            ),
            Arc::new(LocalMfaAttemptLimiter::new(
                LocalMfaAttemptPolicy::new(
                    NonZeroU32::new(32).unwrap(),
                    Duration::from_secs(60),
                    Duration::from_secs(60),
                    n(4096),
                )
                .unwrap(),
            )),
        ));
        let authorization = Arc::new(
            OidcAuthorizationPolicy::new(
                OidcAuthorizationConfiguration {
                    cli_client_id: "graphit-cli".into(),
                    cli_redirect_path: "/oauth/callback".into(),
                    api_audience: AUDIENCE.into(),
                    accepted_resources: vec![RESOURCE.into()],
                    dynamic_registration: true,
                    authorization_ttl: Duration::from_secs(60),
                },
                OidcAuthorizationLimits::new(n(8192), n(8192)).unwrap(),
            )
            .unwrap(),
        );
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let issuer = Arc::new(
            BrokerAccessIssuer::new(ISSUER, AUDIENCE, "sqlite-browser-key", &key.serialize_der())
                .unwrap(),
        );
        Self {
            _temp: temp,
            store,
            db,
            runtime,
            authorization,
            tokens: Arc::new(
                OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(86400))
                    .unwrap(),
            ),
            device: Arc::new(
                DeviceAuthorizationPolicy::new(
                    Duration::from_secs(600),
                    Duration::from_secs(1),
                    Duration::from_secs(60),
                )
                .unwrap(),
            ),
            issuer,
        }
    }
    fn count(&self, sql: &str) -> i64 {
        self.db.query_row(sql, [], |r| r.get(0)).unwrap()
    }
    async fn close(self) {
        self.runtime.close().await;
        self.store.shutdown(end()).await.unwrap();
    }
}
struct Server {
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    join: JoinHandle<std::io::Result<()>>,
}
impl Server {
    async fn new(
        f: &Fixture,
        local: Option<Arc<SqliteLocalLoginRuntime>>,
        timeout: Duration,
    ) -> Self {
        let enabled = local.is_some();
        let http = OidcTokenHttpConfig::new(timeout, n(8192)).unwrap();
        let http = if enabled {
            http.with_device(f.device.clone())
        } else {
            http
        };
        let verifier = Arc::new(
            BrokerAccessVerifier::new(ISSUER, AUDIENCE, None, f.issuer.jwks(), n(8192)).unwrap(),
        );
        let router = sqlite_local_oidc_device_router(
            f.store.clone(),
            OidcDeviceHttpConfig {
                authorization: f.authorization.clone(),
                policy: f.device.clone(),
                issuer: f.issuer.clone(),
                verification_uri: VERIFY.parse().unwrap(),
                body_bytes: n(8192),
                request_timeout: timeout,
            },
            local,
        )
        .unwrap()
        .merge(
            sqlite_local_oidc_token_router(
                f.store.clone(),
                f.issuer.clone(),
                f.authorization.clone(),
                f.tokens.clone(),
                http,
            )
            .unwrap(),
        )
        .merge(
            sqlite_broker_project_authorization_router(
                f.store.clone(),
                verifier,
                BrokerProjectAuthorizationHttpConfig {
                    required_scopes: Vec::new(),
                    grants_json_bytes: n(8192),
                    body_bytes: n(8192),
                    request_timeout: timeout,
                },
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
        });
        Self {
            address,
            stop,
            join,
        }
    }
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        content: &str,
        headers: &[(&str, &str)],
    ) -> Reply {
        let stream = TcpStream::connect(self.address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let driver = tokio::spawn(connection);
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", self.address.to_string())
            .header("content-type", content)
            .header("connection", "close");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = tokio::time::timeout(
            Duration::from_secs(40),
            sender.send_request(
                request
                    .body(Full::new(hyper::body::Bytes::copy_from_slice(body)))
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let (parts, body) = response.into_parts();
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        drop(sender);
        driver.await.unwrap().unwrap();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: Zeroizing::new(body),
        }
    }
    async fn get(&self, path: &str) -> Reply {
        self.send("GET", path, b"", "application/x-www-form-urlencoded", &[])
            .await
    }
    async fn post(&self, path: &str, fields: &[(&str, &str)]) -> Reply {
        self.send(
            "POST",
            path,
            form(fields).as_bytes(),
            "application/x-www-form-urlencoded",
            &[],
        )
        .await
    }
    async fn issue(&self) -> Codes {
        let r = self
            .post("/oauth/device/authorize", &[("client_id", CLIENT)])
            .await;
        r.api();
        assert_eq!(r.status, StatusCode::OK);
        let v = r.json();
        assert_eq!(v.as_object().unwrap().len(), 6);
        assert_eq!(v["verification_uri"], VERIFY);
        assert_eq!(v["interval"], 1);
        assert!(v["expires_in"].as_u64().unwrap() <= 600);
        let user = v["user_code"].as_str().unwrap().to_owned();
        assert_eq!(
            v["verification_uri_complete"],
            format!("{VERIFY}?user_code={user}")
        );
        Codes {
            device: Zeroizing::new(v["device_code"].as_str().unwrap().to_owned()),
            user,
        }
    }
    async fn poll(&self, c: &Codes) -> Reply {
        self.post(
            "/oauth/token",
            &[
                ("grant_type", broker_control::DEVICE_GRANT_TYPE),
                ("client_id", CLIENT),
                ("device_code", &c.device),
            ],
        )
        .await
    }
    async fn decide(&self, c: &Codes, secret: &str, decision: &str) -> Reply {
        self.post(
            &c.path(),
            &[
                ("client_id", CLIENT),
                ("consent_secret", secret),
                ("decision", decision),
            ],
        )
        .await
    }
    async fn password(&self, c: &Codes, password: &str) -> Reply {
        self.post(&c.path(), &[("username", "alice"), ("password", password)])
            .await
    }
    async fn close(self) {
        let _ = self.stop.send(());
        self.join.await.unwrap().unwrap();
    }
}
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Zeroizing<Vec<u8>>,
}
impl Reply {
    fn html(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap()
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    fn privacy(&self) {
        for (name, value) in [
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
        ] {
            assert_eq!(self.headers[name], value);
        }
        assert!(!self.headers.contains_key(header::SET_COOKIE));
    }
    #[track_caller]
    fn finite(&self, status: u16) {
        self.privacy();
        assert_eq!(self.status.as_u16(), status);
        assert!(!self.headers.contains_key(header::LOCATION));
        assert!(!self.html().contains("type=\"hidden\" name=\"code\""));
    }
    fn api(&self) {
        assert_eq!(self.headers["cache-control"], "no-store");
        assert_eq!(self.headers["pragma"], "no-cache");
        assert!(!self.headers.contains_key(header::SET_COOKIE));
    }
    #[track_caller]
    fn error(&self, status: u16, error: &str) {
        self.api();
        assert_eq!(self.status.as_u16(), status);
        assert_eq!(self.json(), json!({"error":error}));
    }
}
struct Codes {
    device: Zeroizing<String>,
    user: String,
}
impl Codes {
    fn path(&self) -> String {
        format!(
            "/oauth/device?{}",
            form(&[("user_code", &self.user)]).as_str()
        )
    }
}
fn reset_poll(f: &Fixture) {
    f.db.execute_batch("UPDATE oauth_device_codes SET last_poll_at=NULL")
        .unwrap();
}
fn consent(r: &Reply) -> Zeroizing<String> {
    r.privacy();
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.html().contains("Review device sign-in"));
    input(r.html(), "consent_secret")
}
fn token(f: &Fixture, r: &Reply) -> Zeroizing<String> {
    r.api();
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v.as_object().unwrap().len(), 4);
    assert_eq!(v["scope"], "");
    assert_eq!(v["token_type"], "Bearer");
    assert!(v.get("id_token").is_none() && v.get("refresh_token").is_none());
    let raw = Zeroizing::new(v["access_token"].as_str().unwrap().to_owned());
    let c = claims(&f.issuer, &raw, AUDIENCE);
    assert_eq!(c["scope"], "");
    assert_eq!(c["token_use"], "access");
    assert_eq!(c["client_id"], CLIENT);
    assert!(c.get("resource").is_none());
    assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 60);
    raw
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real SQLite Device TCP issue, consent, cadence, verified access-only JWT and PROJECT denial"]
async fn sqlite_device_http_access_consent_and_protocol() {
    let f = Fixture::new(false, false, false).await;
    let s = Server::new(&f, Some(f.runtime.clone()), Duration::from_secs(10)).await;
    for scope in [" ", "openid", "offline_access", "custom"] {
        s.post(
            "/oauth/device/authorize",
            &[("client_id", CLIENT), ("scope", scope)],
        )
        .await
        .error(400, "invalid_scope");
    }
    assert_eq!(f.count("SELECT count(*) FROM oauth_device_codes"), 0);
    s.post("/oauth/device/authorize", &[("client_id", "other")])
        .await
        .error(401, "invalid_client");
    for body in [
        "client_id=a&client_id=b",
        "client_id=graphit-cli&scope=%FF",
        "client_id=graphit-cli&resource=x",
        "client_id=graphit-cli&client_secret=",
        "client_id=graphit-cli&client_assertion=x",
    ] {
        s.send(
            "POST",
            "/oauth/device/authorize",
            body.as_bytes(),
            "application/x-www-form-urlencoded",
            &[],
        )
        .await
        .error(400, "invalid_request");
    }
    let c = s.issue().await;
    s.poll(&c).await.error(400, "authorization_pending");
    s.poll(&c).await.error(400, "slow_down");
    assert_eq!(
        f.count("SELECT interval_seconds FROM oauth_device_codes"),
        6
    );
    let page = s.get(&c.path()).await;
    page.privacy();
    assert_eq!(page.status, StatusCode::OK);
    assert!(!page.html().contains(c.device.as_str()));
    s.password(&c, "invalid synthetic password")
        .await
        .finite(401);
    let review = s.password(&c, PASSWORD).await;
    let secret = consent(&review);
    assert_eq!(
        f.count("SELECT count(*) FROM oauth_device_codes WHERE status='pending'"),
        1
    );
    assert_eq!(f.count("SELECT count(*) FROM local_tokens"), 0);
    reset_poll(&f);
    s.poll(&c).await.error(400, "authorization_pending");
    s.post(
        &c.path(),
        &[
            ("client_id", "other"),
            ("consent_secret", &secret),
            ("decision", "allow"),
        ],
    )
    .await
    .finite(401);
    let allowed = s.decide(&c, &secret, "allow").await;
    allowed.finite(200);
    assert!(allowed.html().contains("Return to your device"));
    s.decide(&c, &secret, "allow").await.finite(400);
    reset_poll(&f);
    let raw = token(&f, &s.poll(&c).await);
    s.poll(&c).await.error(400, "invalid_grant");
    assert_eq!(f.count("SELECT count(*) FROM oauth_device_codes"), 0);
    assert_eq!(
        f.count("SELECT count(*) FROM local_tokens WHERE family_id<>''"),
        0
    );
    let authorization = Zeroizing::new(format!("Bearer {}", raw.as_str()));
    let denied = s
        .send(
            "POST",
            "/v1/project/access/authorize",
            br#"{"project_id":"01KSH1CRFFG8Z74B5ZS78WW808","module":"hub","action":"read"}"#,
            "application/json",
            &[("authorization", &authorization)],
        )
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let c = s.issue().await;
    let secret = consent(&s.password(&c, PASSWORD).await);
    s.poll(&c).await.error(400, "authorization_pending");
    s.decide(&c, &secret, "deny").await.finite(200);
    s.poll(&c).await.error(400, "access_denied");
    s.poll(&c).await.error(400, "invalid_grant");
    let c = s.issue().await;
    let now = utc();
    f.db.execute(
        "UPDATE oauth_device_codes SET created_at=?1,expires_at=?2,last_poll_at=?3",
        params![now - 600_000_001, now - 1, now - 2],
    )
    .unwrap();
    s.poll(&c).await.error(400, "expired_token");
    assert_eq!(f.count("SELECT count(*) FROM oauth_device_codes"), 0);
    for (key, value, error) in [
        ("scope", "openid", "invalid_scope"),
        ("resource", RESOURCE, "invalid_request"),
        ("code", "opaque", "invalid_request"),
        ("refresh_token", "opaque", "invalid_request"),
    ] {
        s.post(
            "/oauth/token",
            &[
                ("grant_type", broker_control::DEVICE_GRANT_TYPE),
                ("client_id", CLIENT),
                ("device_code", &c.device),
                (key, value),
            ],
        )
        .await
        .error(400, error);
    }
    s.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real password change, TOTP, recovery-before-review, purpose and current identity"]
async fn sqlite_device_http_factors_recovery_and_current_identity() {
    let f = Fixture::new(true, true, false).await;
    let s = Server::new(&f, Some(f.runtime.clone()), Duration::from_secs(15)).await;
    let c = s.issue().await;
    let change = s.password(&c, PASSWORD).await;
    change.finite(200);
    assert!(change.html().contains("Choose a new password"));
    let challenge = input(change.html(), "challenge_token");
    s.post(
        &c.path(),
        &[
            ("challenge_token", &challenge),
            ("new_password", NEXT),
            ("confirm_password", "mismatch"),
        ],
    )
    .await
    .finite(400);
    let enrollment = s
        .post(
            &c.path(),
            &[
                ("challenge_token", &challenge),
                ("new_password", NEXT),
                ("confirm_password", NEXT),
            ],
        )
        .await;
    enrollment.finite(200);
    assert!(enrollment.html().contains("Set up two-step verification"));
    let challenge = input(enrollment.html(), "challenge_token");
    let setup = enrollment
        .html()
        .split_once("Setup key: <code>")
        .unwrap()
        .1
        .split_once("</code>")
        .unwrap()
        .0;
    let sdk=totp_rs::Totp::from_url(format!("otpauth://totp/Graphit%20Broker:alice?secret={setup}&issuer=Graphit%20Broker&algorithm=SHA1&digits=6&period=30")).unwrap();
    s.post(
        &c.path(),
        &[("challenge_token", &challenge), ("code", "invalid")],
    )
    .await
    .finite(401);
    let otp = Zeroizing::new(sdk.generate((utc() as u64) / 1_000_000).to_string());
    let review = s
        .post(
            &c.path(),
            &[("challenge_token", &challenge), ("code", &otp)],
        )
        .await;
    let secret = consent(&review);
    let html = review.html();
    assert!(html.find("Recovery codes").unwrap() < html.find("name=\"decision\"").unwrap());
    assert!(!html.contains("<script"));
    let recovery: Vec<Zeroizing<String>> = html
        .split("<li><code>")
        .skip(1)
        .map(|p| Zeroizing::new(p.split_once("</code>").unwrap().0.to_owned()))
        .collect();
    assert_eq!(recovery.len(), 10);
    assert_eq!(
        f.count("SELECT count(*) FROM oauth_device_codes WHERE status='pending'"),
        1
    );
    assert_eq!(f.count("SELECT count(*) FROM local_tokens"), 0);
    s.poll(&c).await.error(400, "authorization_pending");
    s.decide(&c, &secret, "allow").await.finite(200);
    reset_poll(&f);
    token(&f, &s.poll(&c).await);
    let c = s.issue().await;
    let factor = s.password(&c, NEXT).await;
    factor.finite(200);
    let challenge = input(factor.html(), "challenge_token");
    let proof = f
        .runtime
        .passwords(&f.store, LocalAuthPurpose::AdminLogin)
        .unwrap()
        .authenticate("alice", NEXT, None, end())
        .await
        .unwrap();
    let LocalAuthStep::Pending(admin) = f
        .runtime
        .authentication(&f.store)
        .begin(proof, LocalAuthBinding::AdminLogin, end())
        .await
        .unwrap()
    else {
        panic!("real Admin MFA pending")
    };
    s.post(
        &c.path(),
        &[
            ("challenge_token", admin.challenge()),
            ("code", &recovery[0]),
        ],
    )
    .await
    .finite(401);
    assert_eq!(f.count("SELECT count(*) FROM local_mfa_recovery_codes"), 10);
    let review = s
        .post(
            &c.path(),
            &[("challenge_token", &challenge), ("code", &recovery[0])],
        )
        .await;
    let secret = consent(&review);
    assert!(!review.html().contains("Save your recovery codes"));
    assert_eq!(f.count("SELECT count(*) FROM local_mfa_recovery_codes"), 9);
    let other = s.issue().await;
    s.decide(&other, &secret, "allow").await.finite(400);
    s.decide(&c, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "allow")
        .await
        .finite(400);
    let replay_factor = s.password(&other, NEXT).await;
    let replay_challenge = input(replay_factor.html(), "challenge_token");
    s.post(
        &other.path(),
        &[
            ("challenge_token", &replay_challenge),
            ("code", &recovery[0]),
        ],
    )
    .await
    .finite(401);
    assert_eq!(f.count("SELECT count(*) FROM local_mfa_recovery_codes"), 9);
    // The genuine consent is no longer eligible after the current identity changes.
    f.db.execute_batch("UPDATE local_users SET enabled=0,revision=2 WHERE username='alice'")
        .unwrap();
    s.decide(&c, &secret, "allow").await.finite(400);
    assert_eq!(
        f.count("SELECT count(*) FROM oauth_device_codes WHERE status='approved'"),
        0
    );
    s.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Device CAPTCHA presentation and demand from startup owner"]
async fn sqlite_device_http_captcha() {
    let f = Fixture::new(false, false, true).await;
    let s = Server::new(&f, Some(f.runtime.clone()), Duration::from_secs(10)).await;
    let c = s.issue().await;
    let view = s.get(&c.path()).await;
    view.privacy();
    assert!(
        view.html().contains("device-login") && view.html().contains("sqlite-browser-site-key")
    );
    assert!(
        view.headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("https://challenges.cloudflare.com")
    );
    let missing = s.password(&c, PASSWORD).await;
    missing.finite(403);
    assert!(!missing.html().contains(PASSWORD));
    s.post(
        &c.path(),
        &[
            ("username", "alice"),
            ("password", PASSWORD),
            ("g-recaptcha-response", "wrong-provider"),
        ],
    )
    .await
    .finite(400);
    assert_eq!(f.count("SELECT count(*) FROM local_tokens"), 0);
    assert_eq!(f.count("SELECT count(*) FROM local_auth_challenges"), 0);
    f.runtime.stop_admission();
    s.get(&c.path()).await.finite(503);
    s.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Device forms, disabled owner, original SQLite lock and closed owner"]
async fn sqlite_device_http_forms_disabled_and_deadline() {
    let f = Fixture::new(false, false, false).await;
    let s = Server::new(&f, Some(f.runtime.clone()), Duration::from_secs(10)).await;
    s.send(
        "HEAD",
        "/oauth/device",
        b"",
        "application/x-www-form-urlencoded",
        &[],
    )
    .await
    .finite(405);
    assert_eq!(f.count("SELECT count(*) FROM oauth_device_codes"), 0);
    let c = s.issue().await;
    for suffix in [
        "&password=bad",
        "&user_code=AAAA2345",
        "&consent_secret=bad",
        "&provider=upstream",
    ] {
        s.get(&format!("{}{suffix}", c.path())).await.finite(400);
    }
    s.post(
        &c.path(),
        &[
            ("user_code", "AAAA2345"),
            ("username", "alice"),
            ("password", PASSWORD),
        ],
    )
    .await
    .finite(400);
    s.send(
        "POST",
        &c.path(),
        b"username=%FF&password=x",
        "application/x-www-form-urlencoded",
        &[],
    )
    .await
    .finite(400);
    s.send(
        "POST",
        &c.path(),
        &vec![b'x'; 8193],
        "application/x-www-form-urlencoded",
        &[],
    )
    .await
    .finite(400);
    let view = s
        .send(
            "GET",
            &c.path(),
            b"",
            "application/x-www-form-urlencoded",
            &[
                ("authorization", "Bearer synthetic-not-authority"),
                ("cookie", "graphit_admin_session=synthetic-not-authority"),
            ],
        )
        .await;
    view.finite(400);
    let cookie = s
        .send(
            "GET",
            &c.path(),
            b"",
            "application/x-www-form-urlencoded",
            &[("cookie", "graphit_admin_session=synthetic-not-authority")],
        )
        .await;
    cookie.finite(200);
    assert!(!cookie.html().contains("consent_secret"));
    let disabled = Server::new(&f, None, Duration::from_secs(10)).await;
    disabled.get(&c.path()).await.finite(503);
    disabled
        .post("/oauth/device/authorize", &[("client_id", CLIENT)])
        .await
        .error(503, "temporarily_unavailable");
    disabled
        .poll(&c)
        .await
        .error(503, "temporarily_unavailable");
    let short = Server::new(&f, Some(f.runtime.clone()), Duration::from_millis(100)).await;
    let lock = f.db.path().unwrap().to_owned();
    let lock = Connection::open(lock).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    short
        .post("/oauth/device/authorize", &[("client_id", CLIENT)])
        .await
        .error(504, "temporarily_unavailable");
    short.password(&c, PASSWORD).await.finite(504);
    lock.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.count("SELECT count(*) FROM local_tokens"), 0);
    f.store.shutdown(end()).await.unwrap();
    s.post("/oauth/device/authorize", &[("client_id", CLIENT)])
        .await
        .error(503, "temporarily_unavailable");
    short.close().await;
    disabled.close().await;
    s.close().await;
    f.close().await;
}
