use broker_control::{
    BrokerAccessIssuer, CompletedLocalLogin, ControlError, DeviceAuthorizationPolicy, DeviceError,
    FlowLimits, LocalAuthPolicy, LocalAuthStep, LocalPasswordEngine,
    OidcAuthorizationConfiguration, OidcAuthorizationLimits, OidcAuthorizationPolicy,
    OidcTokenExchangeError as Protocol, SqliteControlConfig, SqliteControlStore,
    SqliteDeviceAuthorizations,
};
use broker_security::{
    CredentialDigester, DigestLimits, LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher,
    TokenKind,
};
use rusqlite::{Connection, params};
use std::{
    num::NonZeroUsize,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
const ISSUER: &str = "https://broker.example";
const AUDIENCE: &str = "graphit-broker";
const RESOURCE: &str = "https://broker.example/v1";
const PASSWORD: &str = "synthetic SQLite Device native password";
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
fn config(path: &std::path::Path) -> SqliteControlConfig {
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
fn authorization() -> Arc<OidcAuthorizationPolicy> {
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

struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    store: Arc<SqliteControlStore>,
    db: Connection,
    authorization: Arc<OidcAuthorizationPolicy>,
    policy: Arc<DeviceAuthorizationPolicy>,
    issuer: Arc<BrokerAccessIssuer>,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private/broker.db");
        let store = Arc::new(
            SqliteControlStore::open(config(&path), digester(), end())
                .await
                .unwrap(),
        );
        let db = Connection::open(&path).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let issuer = Arc::new(
            BrokerAccessIssuer::new(ISSUER, AUDIENCE, "sqlite-device-key", &key.serialize_der())
                .unwrap(),
        );
        Self {
            _temp: temp,
            path,
            store,
            db,
            authorization: authorization(),
            policy: Arc::new(
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
    fn service(&self) -> SqliteDeviceAuthorizations<'_> {
        self.store
            .device_authorizations(
                self.authorization.clone(),
                self.policy.clone(),
                self.issuer.clone(),
            )
            .unwrap()
    }
    fn count(&self, table: &str) -> i64 {
        self.db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
    async fn close(self) {
        self.store.shutdown(end()).await.unwrap();
    }
    async fn login(&self, engine: &LocalPasswordEngine, code: &str) -> CompletedLocalLogin {
        let proof = self
            .store
            .local_password_verifier(engine)
            .verify("alice", PASSWORD, end())
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
        let code = broker_control::normalize_device_user_code(code).unwrap();
        let LocalAuthStep::Complete(login) = auth
            .begin(
                proof,
                LocalAuthBinding::DeviceApprove(code.as_bytes()),
                end(),
            )
            .await
            .unwrap()
        else {
            panic!("genuine LOCAL completion required")
        };
        login
    }
}
#[tokio::test]
async fn sqlite_device_issue_scope_hashes_and_owner_bounds() {
    let f = Fixture::new().await;
    let s = f.service();
    for scope in [" ", "openid", "profile", "offline_access", "custom"] {
        assert_eq!(
            s.issue("graphit-cli", scope, end()).await.unwrap_err(),
            DeviceError::Protocol(Protocol::InvalidScope)
        );
    }
    assert_eq!(f.count("oauth_device_codes"), 0);
    assert_eq!(
        s.issue("other", "", end()).await.unwrap_err(),
        DeviceError::Protocol(Protocol::InvalidClient)
    );
    let codes = s.issue("graphit-cli", "", end()).await.unwrap();
    assert!(codes.device_code().starts_with("gb_dc_") && codes.device_code().len() == 49);
    let canonical = broker_control::normalize_device_user_code(codes.user_code()).unwrap();
    assert_eq!(canonical.len(), 8);
    assert_eq!(codes.user_code().len(), 9);
    assert_eq!(codes.interval_seconds(), 1);
    assert!(codes.expires_in(end()).unwrap() <= 600);
    let row:(String,String,String,String,i64)=f.db.query_row("SELECT device_hash,user_hash,scopes_json,status,local_user_revision FROM oauth_device_codes",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
    assert_eq!(
        row.0,
        digester()
            .token(TokenKind::DeviceCode, codes.device_code().as_bytes())
            .unwrap()
            .to_sql_hex()
    );
    assert_eq!(
        row.1,
        digester()
            .token(TokenKind::DeviceUserCode, canonical.as_bytes())
            .unwrap()
            .to_sql_hex()
    );
    assert_ne!(row.0, row.1);
    assert_eq!(
        (row.2.as_str(), row.3.as_str(), row.4),
        ("[]", "pending", 0)
    );
    assert_eq!(f.count("local_tokens"), 0);
    f.store.shutdown(end()).await.unwrap();
    assert_eq!(
        s.issue("graphit-cli", "openid", end()).await.unwrap_err(),
        DeviceError::Protocol(Protocol::InvalidScope)
    );
    assert!(matches!(
        s.issue("graphit-cli", "", end()).await,
        Err(DeviceError::Protocol(Protocol::Control(
            ControlError::Closed
        )))
    ));
    f.close().await;
}
#[tokio::test]
async fn sqlite_device_cadence_terminal_and_reopen() {
    let mut f = Fixture::new().await;
    let codes = f.service().issue("graphit-cli", "", end()).await.unwrap();
    assert_eq!(
        f.service()
            .poll("graphit-cli", codes.device_code(), end())
            .await
            .unwrap_err(),
        DeviceError::AuthorizationPending
    );
    assert_eq!(
        f.service()
            .poll("graphit-cli", codes.device_code(), end())
            .await
            .unwrap_err(),
        DeviceError::SlowDown
    );
    let row: (i64, i64) =
        f.db.query_row(
            "SELECT interval_seconds,last_poll_at FROM oauth_device_codes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(row.0, 6);
    assert!(row.1 > 0);
    f.store.shutdown(end()).await.unwrap();
    f.store = Arc::new(
        SqliteControlStore::open(config(&f.path), digester(), end())
            .await
            .unwrap(),
    );
    assert_eq!(
        f.service()
            .poll("graphit-cli", codes.device_code(), end())
            .await
            .unwrap_err(),
        DeviceError::SlowDown
    );
    assert_eq!(
        f.db.query_row("SELECT interval_seconds FROM oauth_device_codes", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        11
    );
    // Move a genuine pending row's coherent lifetime across expiry, without sleeping ten minutes.
    let now = utc();
    f.db.execute(
        "UPDATE oauth_device_codes SET created_at=?1,expires_at=?2,last_poll_at=?3",
        params![now - 600_000_001, now - 1, now - 2],
    )
    .unwrap();
    assert_eq!(
        f.service()
            .poll("graphit-cli", codes.device_code(), end())
            .await
            .unwrap_err(),
        DeviceError::ExpiredToken
    );
    assert_eq!(f.count("oauth_device_codes"), 0);
    assert_eq!(
        f.service()
            .poll("graphit-cli", codes.device_code(), end())
            .await
            .unwrap_err(),
        DeviceError::Protocol(Protocol::InvalidGrant)
    );
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_device_malformed_and_original_lock() {
    let f = Fixture::new().await;
    let codes = f.service().issue("graphit-cli", "", end()).await.unwrap();
    for mutation in [
        "scopes_json='[\"custom\"]'",
        "interval_seconds=2",
        "status='other'",
        "local_user_revision=1",
        "last_poll_at=1",
        "client_id=zeroblob(4096)",
    ] {
        f.db.execute_batch(&format!("UPDATE oauth_device_codes SET {mutation}"))
            .unwrap();
        assert_eq!(
            f.service()
                .poll("graphit-cli", codes.device_code(), end())
                .await
                .unwrap_err(),
            DeviceError::Protocol(Protocol::MalformedStored)
        );
        f.db.execute_batch("UPDATE oauth_device_codes SET scopes_json='[]',interval_seconds=1,status='pending',local_user_revision=0,last_poll_at=NULL,client_id='graphit-cli'").unwrap();
    }
    f.db.execute(
        "UPDATE oauth_device_codes SET scopes_json=?1",
        params![" ".repeat(8193)],
    )
    .unwrap();
    assert_eq!(
        f.service()
            .poll("graphit-cli", codes.device_code(), end())
            .await
            .unwrap_err(),
        DeviceError::Protocol(Protocol::ReadLimitExceeded)
    );
    f.db.execute_batch("UPDATE oauth_device_codes SET scopes_json='[]'")
        .unwrap();
    let lock = Connection::open(&f.path).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let short = Instant::now() + Duration::from_millis(80);
    assert_eq!(
        f.service()
            .poll("graphit-cli", codes.device_code(), short)
            .await
            .unwrap_err(),
        DeviceError::Protocol(Protocol::Control(ControlError::Deadline))
    );
    lock.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.count("local_tokens"), 0);
    assert_eq!(
        f.service()
            .poll("graphit-cli", codes.device_code(), end())
            .await
            .unwrap_err(),
        DeviceError::AuthorizationPending
    );
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native Argon2 proof, protected consent and two-owner one-winner redemption"]
async fn sqlite_device_genuine_consent_two_owner_redemption() {
    let f = Fixture::new().await;
    let engine = LocalPasswordEngine::new(
        LocalPasswordHasher::new(Zeroizing::new(vec![43; 32].into_boxed_slice())).unwrap(),
        n(1),
        end(),
    )
    .await
    .unwrap();
    let hash = engine.hash(PASSWORD, end()).await.unwrap();
    f.db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',?1,'Alice','','','[]',1,0,1,?2,?2)",params![hash.as_str(),utc()]).unwrap();
    let codes = f.service().issue("graphit-cli", "", end()).await.unwrap();
    let mut consent = f
        .service()
        .prepare(
            codes.user_code(),
            f.login(&engine, codes.user_code()).await,
            end(),
        )
        .await
        .unwrap();
    assert!(consent.take_recovery_codes().is_none());
    let secret = Zeroizing::new(consent.secret(end()).unwrap().to_owned());
    assert_eq!(
        f.db.query_row("SELECT status FROM oauth_device_codes", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "pending"
    );
    assert!(
        f.service()
            .decide(codes.user_code(), "other", &secret, true, end())
            .await
            .is_err()
    );
    f.service()
        .decide(codes.user_code(), "graphit-cli", &secret, true, end())
        .await
        .unwrap();
    assert!(
        f.service()
            .decide(codes.user_code(), "graphit-cli", &secret, true, end())
            .await
            .is_err()
    );
    let second = SqliteControlStore::open(config(&f.path), digester(), end())
        .await
        .unwrap();
    let one = f.service();
    let two = second
        .device_authorizations(f.authorization.clone(), f.policy.clone(), f.issuer.clone())
        .unwrap();
    let (a, b) = tokio::join!(
        one.poll("graphit-cli", codes.device_code(), end()),
        two.poll("graphit-cli", codes.device_code(), end())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let token = a.or(b).unwrap();
    assert_eq!(token.scope(), "");
    assert!(token.access_token().split('.').count() == 3);
    assert_eq!(f.count("oauth_device_codes"), 0);
    assert_eq!(f.count("local_tokens"), 1);
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM local_tokens WHERE family_id<>''",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let denied = f.service().issue("graphit-cli", "", end()).await.unwrap();
    let mut review = f
        .service()
        .prepare(
            denied.user_code(),
            f.login(&engine, denied.user_code()).await,
            end(),
        )
        .await
        .unwrap();
    assert!(review.take_recovery_codes().is_none());
    let secret = Zeroizing::new(review.secret(end()).unwrap().to_owned());
    assert_eq!(
        f.service()
            .poll("graphit-cli", denied.device_code(), end())
            .await
            .unwrap_err(),
        DeviceError::AuthorizationPending
    );
    f.service()
        .decide(denied.user_code(), "graphit-cli", &secret, false, end())
        .await
        .unwrap();
    assert_eq!(
        f.service()
            .poll("graphit-cli", denied.device_code(), end())
            .await
            .unwrap_err(),
        DeviceError::AccessDenied
    );
    let current = f.service().issue("graphit-cli", "", end()).await.unwrap();
    let mut review = f
        .service()
        .prepare(
            current.user_code(),
            f.login(&engine, current.user_code()).await,
            end(),
        )
        .await
        .unwrap();
    assert!(review.take_recovery_codes().is_none());
    let secret = Zeroizing::new(review.secret(end()).unwrap().to_owned());
    f.service()
        .decide(current.user_code(), "graphit-cli", &secret, true, end())
        .await
        .unwrap();
    f.db.execute_batch("UPDATE local_users SET revision=2 WHERE username='alice'")
        .unwrap();
    assert_eq!(
        f.service()
            .poll("graphit-cli", current.device_code(), end())
            .await
            .unwrap_err(),
        DeviceError::Protocol(Protocol::InvalidGrant)
    );
    assert_eq!(f.count("local_tokens"), 1);
    assert_eq!(f.count("oauth_device_codes"), 1);
    second.shutdown(end()).await.unwrap();
    engine.close().await;
    f.close().await;
}
