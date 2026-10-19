pub use broker_control::{
    AuthorizedOidcAuthorization, BrokerAccessIssuer, FlowLimits, LocalAuthPolicy, LocalAuthStep,
    LocalPasswordEngine, OidcAuthorizationConfiguration, OidcAuthorizationInput,
    OidcAuthorizationLimits, OidcAuthorizationPolicy, OidcTokenExchangePolicy, PreparedOidcLogin,
    SqliteControlConfig, SqliteControlStore,
};
pub use broker_security::{
    CredentialDigester, DigestLimits, LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher,
};
pub use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
pub use rusqlite::{Connection, params};
pub use serde_json::Value;

pub use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub use zeroize::Zeroizing;
pub const PASSWORD: &str = "synthetic native SQLite OIDC password";
pub const ISSUER: &str = "https://broker.example";
pub const AUDIENCE: &str = "graphit-broker";
pub const RESOURCE: &str = "https://broker.example/v1";
pub const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
pub const DYNAMIC: &str = "-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA";
pub fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
pub fn end() -> Instant {
    Instant::now() + Duration::from_secs(60)
}
pub fn utc() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
        .try_into()
        .unwrap()
}
pub fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(vec![41; 32].into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
pub fn config(path: &std::path::Path) -> SqliteControlConfig {
    SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(10),
        Duration::from_secs(30),
        Duration::from_secs(10),
        FlowLimits {
            provider_bytes: n(128),
            request_bytes: n(1024),
            continuation_bytes: n(4096),
        },
    )
    .unwrap()
}
pub fn authorization() -> Arc<OidcAuthorizationPolicy> {
    Arc::new(
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
    )
}
pub fn request(dynamic: bool, offline: bool) -> OidcAuthorizationInput<'static> {
    OidcAuthorizationInput {
        client_id: if dynamic { DYNAMIC } else { "graphit-cli" },
        redirect_uri: if dynamic {
            "https://client.example/cb"
        } else {
            "http://localhost:49152/oauth/callback"
        },
        response_type: "code",
        scope: if offline {
            "openid profile email offline_access"
        } else {
            "openid profile email"
        },
        state: "literal-state",
        nonce: "literal-nonce",
        code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
        code_challenge_method: "S256",
        response_mode: Some("query"),
        resources: if dynamic { &[RESOURCE] } else { &[] },
        prompts: &[],
    }
}

pub fn claims(issuer: &BrokerAccessIssuer, raw: &str, audience: &str) -> Value {
    let mut v = Validation::new(Algorithm::EdDSA);
    v.leeway = 0;
    v.set_audience(&[audience]);
    v.set_issuer(&[ISSUER]);
    decode::<Value>(
        raw,
        &DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap(),
        &v,
    )
    .unwrap()
    .claims
}
pub struct Fixture {
    pub _temp: tempfile::TempDir,
    pub store: Arc<SqliteControlStore>,
    pub db: Connection,
    pub engine: LocalPasswordEngine,
    pub authorization: Arc<OidcAuthorizationPolicy>,
    pub policy: Arc<OidcTokenExchangePolicy>,
    pub issuer: Arc<BrokerAccessIssuer>,
}
impl Fixture {
    pub async fn add_user(&self, user: &str, subject: &str) {
        let hash = self.engine.hash(PASSWORD, end()).await.unwrap();
        self.db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES(?1,?2,'human',?3,?1,'','org','[]',1,0,1,?4,?4)",params![user,subject,hash.as_str(),utc()]).unwrap();
    }
    pub fn verifier(&self) -> Arc<broker_control::BrokerAccessVerifier> {
        Arc::new(
            broker_control::BrokerAccessVerifier::new(
                ISSUER,
                AUDIENCE,
                None,
                self.issuer.jwks(),
                n(8192),
            )
            .unwrap(),
        )
    }

    pub async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private/broker.db");
        let store = Arc::new(
            SqliteControlStore::open(config(&path), digester(), end())
                .await
                .unwrap(),
        );
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        let engine = LocalPasswordEngine::new(
            LocalPasswordHasher::new(Zeroizing::new(vec![43; 32].into_boxed_slice())).unwrap(),
            n(1),
            end(),
        )
        .await
        .unwrap();
        let hash = engine.hash(PASSWORD, end()).await.unwrap();
        db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',?1,'Alice','alice@example.invalid','org','[\"engineering\",\" engineering \",\"\"]',1,0,1,?2,?2)",params![hash.as_str(),utc()]).unwrap();
        db.execute("INSERT INTO oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES(?1,'Client','[\"https://client.example/cb\"]','[\"arbitrary-registered-scope\"]','web',?2)",params![DYNAMIC,utc()]).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let issuer = Arc::new(
            BrokerAccessIssuer::new(ISSUER, AUDIENCE, "sqlite-oidc-key", &key.serialize_der())
                .unwrap(),
        );
        Self {
            _temp: temp,
            store,
            db,
            engine,
            authorization: authorization(),
            policy: Arc::new(
                OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(86400))
                    .unwrap(),
            ),
            issuer,
        }
    }
    pub async fn prepared(&self, raw: &str) -> PreparedOidcLogin {
        self.prepared_for(raw, "alice").await
    }
    pub async fn prepared_for(&self, raw: &str, user: &str) -> PreparedOidcLogin {
        let proof = self
            .store
            .local_password_verifier(&self.engine)
            .verify(user, PASSWORD, end())
            .await
            .unwrap();
        let auth = self.store.local_auth_service(
            Arc::new(digester()),
            Arc::new(
                LocalMfaProtector::new(Zeroizing::new(vec![47; 32].into_boxed_slice())).unwrap(),
            ),
            Arc::new(
                LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(120))
                    .unwrap(),
            ),
        );
        let LocalAuthStep::Complete(login) = auth
            .begin(
                proof,
                LocalAuthBinding::OauthAuthorize(raw.as_bytes()),
                end(),
            )
            .await
            .unwrap()
        else {
            panic!("genuine LOCAL completion required")
        };
        PreparedOidcLogin::try_from(login).unwrap()
    }
    pub async fn code(&self, dynamic: bool, offline: bool) -> AuthorizedOidcAuthorization {
        self.code_for(dynamic, offline, "alice").await
    }
    pub async fn code_for(
        &self,
        dynamic: bool,
        offline: bool,
        user: &str,
    ) -> AuthorizedOidcAuthorization {
        let service = self
            .store
            .browser_oidc_authorizations(self.authorization.clone());
        let pending = service
            .create(request(dynamic, offline), end())
            .await
            .unwrap();
        let login = self.prepared_for(pending.request(), user).await;
        service
            .complete(pending.request(), login, end())
            .await
            .unwrap()
    }
    pub fn tokens(&self) -> i64 {
        self.db
            .query_row("SELECT count(*) FROM local_tokens", [], |r| r.get(0))
            .unwrap()
    }

    pub async fn close(self) {
        self.engine.close().await;
        self.store.shutdown(end()).await.unwrap();
    }
}

pub use broker_presence::{OidcTokenHttpConfig, sqlite_local_oidc_token_router};
pub use http_body_util::{BodyExt, Full};
pub use hyper::{
    Request, StatusCode,
    http::{HeaderMap, header},
};
pub use hyper_util::rt::TokioIo;
pub use std::net::SocketAddr;
pub use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
pub struct Server {
    pub address: SocketAddr,
    pub stop: oneshot::Sender<()>,
    pub join: JoinHandle<std::io::Result<()>>,
}
impl Server {
    pub async fn new(f: &Fixture, timeout: Duration) -> Self {
        let router = sqlite_local_oidc_token_router(
            f.store.clone(),
            f.issuer.clone(),
            f.authorization.clone(),
            f.policy.clone(),
            OidcTokenHttpConfig::new(timeout, n(8192)).unwrap(),
        )
        .unwrap();
        Self::router(router).await
    }
    pub async fn router(router: axum::Router) -> Self {
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
    pub async fn send(&self, path: &str, body: &[u8], basic: Option<&str>, content: &str) -> Reply {
        self.send_method("POST", path, body, basic, content).await
    }
    pub async fn send_method(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        basic: Option<&str>,
        content: &str,
    ) -> Reply {
        let mut headers = vec![("content-type", content)];
        if let Some(value) = basic {
            headers.push(("authorization", value));
        }
        self.send_headers(method, path, body, &headers).await
    }
    pub async fn send_headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
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
            .header("connection", "close");
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        let response = tokio::time::timeout(
            Duration::from_secs(10),
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
    pub async fn form(&self, fields: &[(&str, &str)]) -> Reply {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish();
        self.send(
            "/oauth/token",
            body.as_bytes(),
            None,
            "application/x-www-form-urlencoded",
        )
        .await
    }
    pub async fn close(self) {
        let _ = self.stop.send(());
        self.join.await.unwrap().unwrap();
    }
}
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}
impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    pub fn policy(&self) {
        assert_eq!(self.headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(self.headers[header::PRAGMA], "no-cache");
        assert!(!self.headers.contains_key(header::SET_COOKIE));
    }
    pub fn error(&self, status: u16, code: &str) {
        self.policy();
        assert_eq!(self.status.as_u16(), status);
        assert_eq!(self.json()["error"], code);
        assert!(self.json().get("access_token").is_none());
    }
}
pub fn code_form(raw: &str) -> Vec<(&str, &str)> {
    vec![
        ("grant_type", "authorization_code"),
        ("client_id", "graphit-cli"),
        ("code", raw),
        ("redirect_uri", "http://localhost:49152/oauth/callback"),
        ("code_verifier", VERIFIER),
    ]
}
