use broker_control::{
    BrokerAccessIssuer, FlowLimits, LocalAuthPolicy, LocalAuthStep, LocalCaptcha,
    LocalCaptchaConfiguration, LocalCaptchaProvider, LocalMfaAttemptLimiter, LocalMfaAttemptPolicy,
    LocalPasswordAdmission, LocalPasswordAdmissionPolicy, LocalPasswordEngine,
    OidcAuthorizationConfiguration, OidcAuthorizationLimits, OidcAuthorizationPolicy,
    OidcTokenExchangePolicy, SqliteControlConfig, SqliteControlStore,
};
use broker_presence::{
    OidcBrowserHttpConfig, OidcTokenHttpConfig, SqliteLocalLoginRuntime,
    sqlite_local_oidc_browser_router, sqlite_local_oidc_token_router,
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
const PASSWORD: &str = "synthetic native SQLite public browser password";
const NEXT: &str = "different synthetic native SQLite browser password";
const CLIENT: &str = "-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA";
const REDIRECT: &str = "https://client.example/cb?kept=%2F";
const STATE: &str = " literal state café +%<>&\"' ";
const ISSUER: &str = "https://broker.example";
const AUDIENCE: &str = "graphit-broker";
const RESOURCE: &str = "https://broker.example/v1";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
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
fn authorize_fields(mode: &str) -> Vec<(&str, &str)> {
    vec![
        ("client_id", CLIENT),
        ("redirect_uri", REDIRECT),
        ("response_type", "code"),
        ("scope", "openid profile email offline_access"),
        ("state", STATE),
        ("nonce", "browser nonce"),
        (
            "code_challenge",
            "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
        ),
        ("code_challenge_method", "S256"),
        ("response_mode", mode),
        ("resource", RESOURCE),
    ]
}
fn parameter(raw: &str, key: &str) -> String {
    form_urlencoded::parse(raw.as_bytes())
        .find(|(k, _)| k == key)
        .unwrap()
        .1
        .into_owned()
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
        db.execute("INSERT INTO oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES(?1,'Browser application',?2,'[\"openid\",\"offline_access\"]','web',?3)",params![CLIENT,serde_json::to_string(&[REDIRECT]).unwrap(),utc()]).unwrap();
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
        let router = sqlite_local_oidc_browser_router(
            f.store.clone(),
            OidcBrowserHttpConfig {
                authorization: f.authorization.clone(),
                body_bytes: n(8192),
                request_timeout: timeout,
                cookie_secure: true,
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
                OidcTokenHttpConfig::new(timeout, n(8192)).unwrap(),
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
    async fn authorize(&self, mode: &str) -> String {
        let fields = authorize_fields(mode);
        let response = if mode == "fragment" {
            let path = format!("/oauth/authorize?client_id={CLIENT}");
            self.post(&path, &fields[1..]).await
        } else {
            self.get(&format!("/oauth/authorize?{}", form(&fields).as_str()))
                .await
        };
        response.privacy();
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        let location = response.headers[header::LOCATION].to_str().unwrap();
        assert!(location.starts_with("/oauth/login?id="));
        location.to_owned()
    }
    async fn tokens(&self, code: &str) -> Reply {
        self.post(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", CLIENT),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
                ("resource", RESOURCE),
            ],
        )
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
    fn destination_csp(&self) {
        assert!(
            self.headers["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("form-action 'self' https://client.example;")
        );
    }
}
fn code(
    response: &Reply,
    mode: &str,
    recovery: bool,
) -> (Zeroizing<String>, Vec<Zeroizing<String>>) {
    response.privacy();
    let mut codes = Vec::new();
    if mode == "form_post" || recovery {
        assert_eq!(response.status, StatusCode::OK);
        let html = response.html();
        let csp = response.headers["content-security-policy"]
            .to_str()
            .unwrap();
        if recovery {
            assert!(
                html.contains("Save your recovery codes")
                    && html.contains("Continue to application")
            );
            assert!(!html.contains("<script") && !csp.contains("sha256-"));
            for part in html.split("<li><code>").skip(1) {
                codes.push(Zeroizing::new(
                    part.split_once("</code>").unwrap().0.to_owned(),
                ));
            }
            assert_eq!(codes.len(), 10);
        } else {
            assert!(csp.contains("sha256-"));
        }
        if mode == "form_post" {
            assert_eq!(input(html, "state").as_str(), STATE);
            return (input(html, "code"), codes);
        }
        let location = html_unescape(
            html.split_once("class=\"continue\" href=\"")
                .unwrap()
                .1
                .split_once('"')
                .unwrap()
                .0,
        );
        let encoded = if mode == "fragment" {
            location.split_once('#').unwrap().1
        } else {
            location.split_once('?').unwrap().1
        };
        assert_eq!(parameter(encoded, "state"), STATE);
        (Zeroizing::new(parameter(encoded, "code")), codes)
    } else {
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        let location = response.headers[header::LOCATION].to_str().unwrap();
        assert!(location.starts_with(REDIRECT));
        let encoded = if mode == "fragment" {
            location.split_once('#').unwrap().1
        } else {
            location.split_once('?').unwrap().1
        };
        assert_eq!(parameter(encoded, "state"), STATE);
        (Zeroizing::new(parameter(encoded, "code")), codes)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real public browser TCP, file SQLite, Argon2, S256 and verified JWT/refresh"]
async fn sqlite_public_oidc_browser_modes_and_tokens() {
    let f = Fixture::new(false, false, false).await;
    let server = Server::new(&f, Some(f.runtime.clone()), Duration::from_secs(10)).await;
    for mode in ["query", "fragment", "form_post"] {
        let path = server.authorize(mode).await;
        let view = server.get(&path).await;
        view.privacy();
        view.destination_csp();
        assert_eq!(view.status, StatusCode::OK);
        assert!(view.html().contains("Sign in to your application"));
        let wrong = server
            .post(
                &path,
                &[
                    ("username", "alice"),
                    ("password", "incorrect synthetic password"),
                ],
            )
            .await;
        wrong.finite(401);
        assert!(!wrong.html().contains("incorrect synthetic password"));
        let response = server
            .post(&path, &[("username", "alice"), ("password", PASSWORD)])
            .await;
        let (raw, recovery) = code(&response, mode, false);
        assert!(recovery.is_empty());
        assert_eq!(server.get(&path).await.status, StatusCode::BAD_REQUEST);
        let tokens = server.tokens(&raw).await;
        assert_eq!(tokens.status, StatusCode::OK);
        assert_eq!(tokens.headers[header::CACHE_CONTROL], "no-store");
        let tokens = tokens.json();
        let access = claims(
            &f.issuer,
            tokens["access_token"].as_str().unwrap(),
            AUDIENCE,
        );
        let id = claims(&f.issuer, tokens["id_token"].as_str().unwrap(), CLIENT);
        assert_eq!(id["nonce"], "browser nonce");
        assert_eq!(id["amr"], json!(["pwd"]));
        assert_eq!(id["sub"], access["sub"]);
        assert_eq!(access["aud"], json!([AUDIENCE, RESOURCE]));
        let refresh = tokens["refresh_token"].as_str().unwrap();
        let next = server
            .post(
                "/oauth/token",
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", CLIENT),
                    ("refresh_token", refresh),
                    ("scope", "openid email"),
                    ("resource", RESOURCE),
                ],
            )
            .await;
        assert_eq!(next.status, StatusCode::OK);
        let next = next.json();
        assert_eq!(next["scope"], "openid email");
        assert_eq!(
            claims(&f.issuer, next["id_token"].as_str().unwrap(), CLIENT)["auth_time"],
            id["auth_time"]
        );
        let reused = server
            .post(
                "/oauth/token",
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", CLIENT),
                    ("refresh_token", refresh),
                    ("resource", RESOURCE),
                ],
            )
            .await;
        assert_eq!(reused.status, StatusCode::BAD_REQUEST);
        assert_eq!(reused.json()["error"], "invalid_grant");
    }
    assert_eq!(
        f.count("SELECT count(*) FROM oidc_auth_requests WHERE code_hash IS NOT NULL"),
        0
    );
    assert_eq!(
        f.count("SELECT count(*) FROM local_tokens WHERE revoked_at IS NULL"),
        0
    );
    server.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real public LOCAL password change, enrollment, MFA, recovery and purpose binding"]
async fn sqlite_public_oidc_browser_change_mfa_manual_recovery() {
    let f = Fixture::new(true, true, false).await;
    let server = Server::new(&f, Some(f.runtime.clone()), Duration::from_secs(10)).await;
    let path = server.authorize("form_post").await;
    let changed = server
        .post(&path, &[("username", "alice"), ("password", PASSWORD)])
        .await;
    changed.destination_csp();
    assert_eq!(changed.status, StatusCode::OK);
    assert!(changed.html().contains("Choose a new password"));
    let challenge = input(changed.html(), "challenge_token");
    let denied = server
        .post(
            &path,
            &[
                ("challenge_token", &challenge),
                ("new_password", NEXT),
                ("confirm_password", "mismatch"),
            ],
        )
        .await;
    denied.finite(400);
    assert!(!denied.html().contains(NEXT));
    let enrollment = server
        .post(
            &path,
            &[
                ("challenge_token", &challenge),
                ("new_password", NEXT),
                ("confirm_password", NEXT),
            ],
        )
        .await;
    assert_eq!(enrollment.status, StatusCode::OK);
    enrollment.destination_csp();
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
    server
        .post(
            &path,
            &[("challenge_token", &challenge), ("code", "invalid")],
        )
        .await
        .finite(401);
    let otp = Zeroizing::new(sdk.generate((utc() as u64) / 1_000_000).to_string());
    let response = server
        .post(&path, &[("challenge_token", &challenge), ("code", &otp)])
        .await;
    let (raw, recovery) = code(&response, "form_post", true);
    let tokens = server.tokens(&raw).await;
    assert_eq!(tokens.status, StatusCode::OK);
    assert_eq!(
        claims(
            &f.issuer,
            tokens.json()["id_token"].as_str().unwrap(),
            CLIENT
        )["amr"],
        json!(["pwd", "otp"])
    );
    assert!(
        !server
            .get(&path)
            .await
            .html()
            .contains("Save your recovery codes")
    );
    assert_eq!(
        server
            .post(&path, &[("challenge_token", &challenge), ("code", &otp)])
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let again = server.authorize("query").await;
    let pending = server
        .post(&again, &[("username", "alice"), ("password", NEXT)])
        .await;
    assert!(pending.html().contains("Verify your sign-in"));
    let challenge = input(pending.html(), "challenge_token");
    let other = server.authorize("query").await;
    server
        .post(
            &other,
            &[("challenge_token", &challenge), ("code", &recovery[0])],
        )
        .await
        .finite(401);
    let attempts = [
        ("challenge_token", challenge.as_str()),
        ("code", recovery[0].as_str()),
    ];
    let (a, b) = tokio::join!(
        server.post(&again, &attempts),
        server.post(&again, &attempts)
    );
    let (winner, loser) = if a.status == StatusCode::SEE_OTHER {
        (a, b)
    } else {
        (b, a)
    };
    assert!(matches!(loser.status.as_u16(), 400 | 401 | 429));
    let (raw, codes) = code(&winner, "query", false);
    assert!(codes.is_empty());
    assert_eq!(server.tokens(&raw).await.status, StatusCode::OK);
    let next = server.authorize("query").await;
    let pending = server
        .post(&next, &[("username", "alice"), ("password", NEXT)])
        .await;
    let challenge = input(pending.html(), "challenge_token");
    server
        .post(
            &next,
            &[("challenge_token", &challenge), ("code", &recovery[0])],
        )
        .await
        .finite(401);
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
        panic!("genuine Admin factor challenge required")
    };
    server
        .post(
            &next,
            &[
                ("challenge_token", admin.challenge()),
                ("code", &recovery[1]),
            ],
        )
        .await
        .finite(401);
    server.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real public browser CAPTCHA owner presentation and admission demand"]
async fn sqlite_public_oidc_browser_captcha_owner() {
    let f = Fixture::new(false, false, true).await;
    let server = Server::new(&f, Some(f.runtime.clone()), Duration::from_secs(10)).await;
    let path = server.authorize("query").await;
    let view = server.get(&path).await;
    assert_eq!(view.status, StatusCode::OK);
    view.privacy();
    view.destination_csp();
    assert!(view.html().contains("sqlite-browser-site-key") && view.html().contains("oauth-login"));
    assert!(
        view.headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("https://challenges.cloudflare.com")
    );
    let required = server
        .post(&path, &[("username", "alice"), ("password", PASSWORD)])
        .await;
    required.finite(403);
    assert!(
        required.html().contains("sqlite-browser-site-key")
            && required.html().contains("oauth-login")
    );
    assert!(!required.html().contains(PASSWORD));
    server
        .post(
            &path,
            &[
                ("username", "alice"),
                ("password", PASSWORD),
                ("g-recaptcha-response", "wrong-provider"),
            ],
        )
        .await
        .finite(400);
    assert_eq!(
        f.count("SELECT count(*) FROM oidc_auth_requests WHERE code_hash IS NOT NULL"),
        0
    );
    assert_eq!(f.count("SELECT count(*) FROM local_tokens"), 0);
    // Provider verification is the unchanged qualified fixed-provider HTTPS producer;
    // this new consumer proves genuine demand, purpose, challenge and CSP without live secrets.
    f.runtime.stop_admission();
    server.get(&path).await.finite(503);
    server.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real browser strict forms, sealed targets, HEAD and disabled LOCAL"]
async fn sqlite_public_oidc_browser_forms_targets_and_disabled() {
    let f = Fixture::new(false, false, false).await;
    let server = Server::new(&f, Some(f.runtime.clone()), Duration::from_secs(10)).await;
    let before = f.count("SELECT count(*) FROM oidc_auth_requests");
    for path in ["/oauth/authorize", "/oauth/login"] {
        let response = server
            .send("HEAD", path, b"", "application/x-www-form-urlencoded", &[])
            .await;
        response.finite(405);
        assert!(
            response.headers[header::ALLOW]
                .to_str()
                .unwrap()
                .contains("GET")
        );
        assert!(response.body.is_empty());
    }
    assert_eq!(f.count("SELECT count(*) FROM oidc_auth_requests"), before);
    for body in [b"state=a&state=b".as_slice(), b"nonce=%FF"] {
        server
            .send(
                "POST",
                "/oauth/authorize",
                body,
                "application/x-www-form-urlencoded",
                &[],
            )
            .await
            .finite(400);
    }
    server
        .send(
            "POST",
            "/oauth/authorize",
            b"state=a",
            "application/json",
            &[],
        )
        .await
        .finite(415);
    server
        .send(
            "POST",
            "/oauth/authorize",
            &vec![b'x'; 8193],
            "application/x-www-form-urlencoded",
            &[],
        )
        .await
        .finite(400);
    let mut fields = authorize_fields("query");
    fields.retain(|(k, _)| *k != "redirect_uri");
    fields.push(("redirect_uri", "https://evil.example/cb"));
    server
        .get(&format!("/oauth/authorize?{}", form(&fields).as_str()))
        .await
        .finite(400);
    let mut fields = authorize_fields("query");
    fields.retain(|(k, _)| *k != "client_id");
    fields.push(("client_id", "unknown-client"));
    server
        .get(&format!("/oauth/authorize?{}", form(&fields).as_str()))
        .await
        .finite(400);
    for (key, value, error) in [
        ("scope", "email", "invalid_scope"),
        ("resource", "https://evil.example/v1", "invalid_target"),
        ("prompt", "none", "login_required"),
        ("response_type", "token", "invalid_request"),
    ] {
        let mut fields = authorize_fields("query");
        fields.retain(|(k, _)| *k != key);
        fields.push((key, value));
        let response = server
            .get(&format!("/oauth/authorize?{}", form(&fields).as_str()))
            .await;
        response.privacy();
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        let location = response.headers[header::LOCATION].to_str().unwrap();
        assert!(location.starts_with(REDIRECT));
        let encoded = location.split_once('?').unwrap().1;
        assert_eq!(parameter(encoded, "error"), error);
        assert!(!encoded.contains("code="));
    }
    let path = server.authorize("query").await;
    server
        .get(&format!("{path}&password=secret"))
        .await
        .finite(400);
    server
        .post(
            &path,
            &[
                ("id", "other"),
                ("username", "alice"),
                ("password", PASSWORD),
            ],
        )
        .await
        .finite(400);
    server
        .post(
            &path,
            &[
                ("username", "alice"),
                ("username", "alice"),
                ("password", PASSWORD),
            ],
        )
        .await
        .finite(400);
    let view = server
        .send(
            "GET",
            &path,
            b"",
            "application/x-www-form-urlencoded",
            &[
                ("authorization", "Bearer synthetic-not-authority"),
                ("cookie", "graphit_admin_session=synthetic-not-authority"),
            ],
        )
        .await;
    assert_eq!(view.status, StatusCode::OK);
    assert!(view.html().contains("Sign in to your application"));
    assert_eq!(
        f.count("SELECT count(*) FROM oidc_auth_requests WHERE code_hash IS NOT NULL"),
        0
    );
    server
        .post(&path, &[("access_token", "synthetic-not-authority")])
        .await
        .finite(401);
    let disabled = Server::new(&f, None, Duration::from_secs(10)).await;
    let path = disabled.authorize("query").await;
    disabled.get(&path).await.finite(503);
    disabled
        .post(&path, &[("username", "alice"), ("password", PASSWORD)])
        .await
        .finite(503);
    server
        .get(&format!("{path}&login_method=oidc&provider=absent"))
        .await
        .finite(400);
    disabled
        .get(&format!("{path}&login_method=oidc&provider=absent"))
        .await
        .finite(503);
    let service = f.store.browser_oidc_authorizations(f.authorization.clone());
    let direct = service
        .create(
            broker_control::OidcAuthorizationInput {
                client_id: CLIENT,
                redirect_uri: REDIRECT,
                response_type: "code",
                scope: "openid",
                state: "bad\0\r\nstate",
                nonce: "browser nonce",
                code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
                code_challenge_method: "S256",
                response_mode: Some("form_post"),
                resources: &[RESOURCE],
                prompts: &[],
            },
            end(),
        )
        .await
        .unwrap();
    let direct_path = format!("/oauth/login?id={}", direct.request());
    assert_eq!(server.get(&direct_path).await.status, StatusCode::OK);
    assert_eq!(
        f.count("SELECT count(*) FROM oidc_auth_requests WHERE code_hash IS NOT NULL"),
        0
    );
    server
        .post(
            &direct_path,
            &[("username", "alice"), ("password", PASSWORD)],
        )
        .await
        .finite(400);
    // The genuine completion committed; the renderer withholds the invalid FormPost.
    assert_eq!(
        f.count("SELECT count(*) FROM oidc_auth_requests WHERE code_hash IS NOT NULL"),
        1
    );
    assert_eq!(f.count("SELECT count(*) FROM local_tokens"), 0);
    assert!(matches!(
        sqlite_local_oidc_browser_router(
            f.store.clone(),
            OidcBrowserHttpConfig {
                authorization: f.authorization.clone(),
                body_bytes: n(8192),
                request_timeout: Duration::ZERO,
                cookie_secure: true
            },
            None
        ),
        Err(broker_control::ControlError::Configuration)
    ));
    disabled.close().await;
    server.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real browser identity changes, original lock wait, UTC expiry and closed owner"]
async fn sqlite_public_oidc_browser_current_identity_and_time() {
    let f = Fixture::new(true, false, false).await;
    let server = Server::new(&f, Some(f.runtime.clone()), Duration::from_secs(10)).await;
    let path = server.authorize("query").await;
    let enrollment = server
        .post(&path, &[("username", "alice"), ("password", PASSWORD)])
        .await;
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
    let otp = Zeroizing::new(sdk.generate((utc() as u64) / 1_000_000).to_string());
    f.db.execute_batch("UPDATE local_users SET enabled=0")
        .unwrap();
    server
        .post(&path, &[("challenge_token", &challenge), ("code", &otp)])
        .await
        .finite(401);
    f.db.execute_batch("UPDATE local_users SET enabled=1,revision=2")
        .unwrap();
    server
        .post(&path, &[("challenge_token", &challenge), ("code", &otp)])
        .await
        .finite(401);
    f.db.execute_batch("UPDATE local_users SET revision=1")
        .unwrap();
    assert_eq!(
        f.count("SELECT count(*) FROM oidc_auth_requests WHERE code_hash IS NOT NULL"),
        0
    );
    let short = Server::new(&f, Some(f.runtime.clone()), Duration::from_millis(100)).await;
    let before = f.count("SELECT count(*) FROM oidc_auth_requests");
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    short
        .get(&format!(
            "/oauth/authorize?{}",
            form(&authorize_fields("query")).as_str()
        ))
        .await
        .finite(504);
    short.get(&path).await.finite(504);
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.count("SELECT count(*) FROM oidc_auth_requests"), before);
    let expiring = server.authorize("query").await;
    f.db.execute(
        "UPDATE oidc_auth_requests SET expires_at=?1 WHERE identity_subject=''",
        [utc() + 200_000],
    )
    .unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let release = async {
        tokio::time::sleep(Duration::from_millis(350)).await;
        f.db.execute_batch("ROLLBACK").unwrap();
    };
    let (response, ()) = tokio::join!(server.get(&expiring), release);
    response.finite(400);
    assert_eq!(
        f.count("SELECT count(*) FROM oidc_auth_requests WHERE code_hash IS NOT NULL"),
        0
    );
    f.store.shutdown(end()).await.unwrap();
    server
        .get(&format!(
            "/oauth/authorize?{}",
            form(&authorize_fields("query")).as_str()
        ))
        .await
        .finite(503);
    short.close().await;
    server.close().await;
    f.runtime.close().await;
}
