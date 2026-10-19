use broker_control::{
    CompletedLocalLogin, ControlError, FlowLimits, LocalAuthError as Error, LocalAuthPolicy,
    LocalAuthStage as Stage, LocalAuthStep, LocalCaptcha, LocalCaptchaConfiguration,
    LocalMfaAttemptLimiter, LocalMfaAttemptPolicy, LocalPasswordAdmission,
    LocalPasswordAdmissionError, LocalPasswordAdmissionPolicy, LocalPasswordEngine,
    LocalPasswordVerificationError, PendingLocalAuth, SqliteControlConfig, SqliteControlStore,
};
use broker_security::{
    CredentialDigester, DigestLimits, LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher,
};
use rusqlite::{Connection, params, types::ValueRef};
use sha2::{Digest, Sha256};
use std::{
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::{Layer, Registry, layer::Context, prelude::*};
use zeroize::Zeroizing;
const PASSWORD: &str = "synthetic SQLite native LOCAL password";
const NEXT: &str = "different synthetic SQLite LOCAL password";
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
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(vec![41; 32].into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
fn limits() -> FlowLimits {
    FlowLimits {
        provider_bytes: n(128),
        request_bytes: n(1024),
        continuation_bytes: n(4096),
    }
}
fn config(path: &std::path::Path) -> SqliteControlConfig {
    SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(10),
        Duration::from_secs(30),
        Duration::from_secs(10),
        limits(),
    )
    .unwrap()
}
fn pending(step: LocalAuthStep) -> PendingLocalAuth {
    match step {
        LocalAuthStep::Pending(v) => v,
        _ => panic!("pending LOCAL step expected"),
    }
}
fn complete(step: LocalAuthStep) -> CompletedLocalLogin {
    match step {
        LocalAuthStep::Complete(v) => v,
        _ => panic!("completed genuine LOCAL login expected"),
    }
}
fn limiter(max: u32) -> Arc<LocalMfaAttemptLimiter> {
    Arc::new(LocalMfaAttemptLimiter::new(
        LocalMfaAttemptPolicy::new(
            NonZeroU32::new(max).unwrap(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            n(16),
        )
        .unwrap(),
    ))
}
struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    store: Arc<SqliteControlStore>,
    db: Connection,
    engine: Arc<LocalPasswordEngine>,
    d: Arc<CredentialDigester>,
    m: Arc<LocalMfaProtector>,
    required: Arc<LocalAuthPolicy>,
    exempt: Arc<LocalAuthPolicy>,
    hash: Zeroizing<String>,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private").join("broker.db");
        let store = Arc::new(
            SqliteControlStore::open(config(&path), digester(), end())
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
        db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',?1,'','','','[]',1,0,1,0,0)",[hash.as_str()]).unwrap();
        Self {
            _temp: temp,
            path,
            store,
            db,
            engine,
            hash,
            d: Arc::new(digester()),
            m: Arc::new(
                LocalMfaProtector::new(Zeroizing::new(vec![47; 32].into_boxed_slice())).unwrap(),
            ),
            required: Arc::new(
                LocalAuthPolicy::new(true, "Graphit Broker".into(), Duration::from_secs(120))
                    .unwrap(),
            ),
            exempt: Arc::new(
                LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(120))
                    .unwrap(),
            ),
        }
    }
    fn auth(&self, required: bool) -> broker_control::SqliteLocalAuthService<'_> {
        self.store.local_auth_service(
            self.d.clone(),
            self.m.clone(),
            if required {
                self.required.clone()
            } else {
                self.exempt.clone()
            },
        )
    }
    async fn proof(&self) -> broker_control::VerifiedLocalPassword {
        self.store
            .local_password_verifier(&self.engine)
            .verify("alice", PASSWORD, end())
            .await
            .unwrap()
    }
    async fn challenge(&self, context: LocalAuthBinding<'_>, required: bool) -> PendingLocalAuth {
        pending(
            self.auth(required)
                .begin(self.proof().await, context, end())
                .await
                .unwrap(),
        )
    }
    fn reset(&self, change: bool) {
        self.db.execute_batch("DELETE FROM local_auth_challenges;DELETE FROM local_mfa_recovery_codes;DELETE FROM local_mfa;DELETE FROM local_tokens;DELETE FROM oidc_auth_requests;DELETE FROM oauth_device_codes;DELETE FROM local_users WHERE username<>'alice'").unwrap();
        self.db.execute("UPDATE local_users SET subject='alice-subject',identity_kind='human',password_hash=?1,enabled=1,password_change_required=?2,revision=1,updated_at=0",params![self.hash.as_str(),i64::from(change)]).unwrap();
    }
    fn count(&self, statement: &str) -> i64 {
        self.db.query_row(statement, [], |r| r.get(0)).unwrap()
    }
    fn snapshot(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        for table in [
            "local_users",
            "local_tokens",
            "oidc_auth_requests",
            "oauth_device_codes",
            "local_auth_challenges",
            "local_mfa",
            "local_mfa_recovery_codes",
        ] {
            hash.update(table.as_bytes());
            let mut statement = self
                .db
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let mut rows = statement.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                for i in 0..columns {
                    match row.get_ref(i).unwrap() {
                        ValueRef::Null => hash.update([0]),
                        ValueRef::Integer(v) => {
                            hash.update([1]);
                            hash.update(v.to_le_bytes());
                        }
                        ValueRef::Real(v) => {
                            hash.update([2]);
                            hash.update(v.to_bits().to_le_bytes());
                        }
                        ValueRef::Text(v) | ValueRef::Blob(v) => {
                            hash.update([3]);
                            hash.update((v.len() as u64).to_le_bytes());
                            hash.update(v);
                        }
                    }
                }
            }
        }
        hash.finalize().into()
    }
    fn artifacts(&self) {
        self.db.execute("INSERT INTO local_users SELECT 'bob','bob-subject','human',?1,'','','','[]',1,0,1,0,0",[self.hash.as_str()]).unwrap();
        for (byte, id, subject, revision, revoked) in [
            ('a', "active", "alice-subject", 1, None),
            ('b', "revoked", "alice-subject", 1, Some(12345)),
            ('c', "other", "bob-subject", 1, None),
            ('d', "federated", "alice-subject", 0, None),
        ] {
            self.db.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,revoked_at,consumed_at,last_used_at,created_at) VALUES(?1,?2,'access',?3,'','{}','','','','[]',?4,'',1,9999999999999999,?5,NULL,NULL,1)",params![byte.to_string().repeat(64),id,subject,revision,revoked]).unwrap();
        }
        let federated = r#"{"format":"rust-broker-authorization-v1","phase":"authorized","principal":{"issuer":"https://issuer.example","auth_method":"oidc","local_user_revision":0}}"#;
        for (byte, subject, json) in [
            ('a', "alice-subject", "{}"),
            ('b', "", "{}"),
            ('c', "bob-subject", "{}"),
            ('d', "alice-subject", federated),
        ] {
            self.db.execute("INSERT INTO oidc_auth_requests(request_hash,identity_subject,request_json,expires_at,created_at) VALUES(?1,?2,?3,9999999999999999,1)",params![byte.to_string().repeat(64),subject,json]).unwrap();
        }
        for (byte, subject, status) in [
            ('a', "alice-subject", "approved"),
            ('b', "alice-subject", "pending"),
            ('c', "bob-subject", "approved"),
            ('d', "", "pending"),
            ('e', "alice-subject", "denied"),
        ] {
            self.db.execute("INSERT INTO oauth_device_codes(device_hash,user_hash,client_id,scopes_json,subject,local_user_revision,status,interval_seconds,expires_at,created_at) VALUES(?1,?1,'client','[]',?2,?3,?4,5,9999999999999999,1)",params![byte.to_string().repeat(64),subject,if subject.is_empty(){0}else{1},status]).unwrap();
        }
    }
    fn invalidation(&self, device: bool) {
        assert_eq!(self.count("SELECT COUNT(*) FROM local_tokens WHERE token_id='active' AND revoked_at IS NOT NULL"),1);
        assert_eq!(
            self.count("SELECT revoked_at FROM local_tokens WHERE token_id='revoked'"),
            12345
        );
        assert_eq!(self.count("SELECT COUNT(*) FROM local_tokens WHERE token_id IN('other','federated') AND revoked_at IS NULL"),2);
        assert_eq!(self.count("SELECT COUNT(*) FROM oidc_auth_requests"), 3);
        assert_eq!(
            self.count(
                "SELECT COUNT(*) FROM oidc_auth_requests WHERE identity_subject='alice-subject'"
            ),
            1
        );
        assert_eq!(
            self.count("SELECT COUNT(*) FROM oauth_device_codes WHERE subject='alice-subject'"),
            if device { 3 } else { 0 }
        );
        assert_eq!(
            self.count("SELECT COUNT(*) FROM oauth_device_codes WHERE subject<>'alice-subject'"),
            2
        );
    }
    async fn close(self) {
        self.engine.close().await;
        self.store.shutdown(end()).await.unwrap();
        drop(self.db);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real file SQLite, native Argon2, AES-GCM, TOTP/QR and recovery consumption"]
async fn sqlite_local_stages_mfa_and_admission() {
    let f = Fixture::new().await;
    let admission = LocalPasswordAdmission::new(
        LocalPasswordAdmissionPolicy {
            max_failures: n(1),
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(60),
            workers: n(1),
            saturation_multiplier: n(2),
            max_tracked: n(4096),
        },
        &f.engine,
        LocalCaptcha::new(LocalCaptchaConfiguration::Disabled, n(1), n(2)).unwrap(),
    )
    .unwrap();
    let owner = f
        .store
        .admitted_local_passwords(
            &f.engine,
            &admission,
            broker_security::LocalAuthPurpose::AdminLogin,
        )
        .unwrap();
    assert!(matches!(
        owner.authenticate("alice", "wrong", None, end()).await,
        Err(LocalPasswordAdmissionError::Unauthenticated)
    ));
    assert!(matches!(
        owner.authenticate("alice", PASSWORD, None, end()).await,
        Err(LocalPasswordAdmissionError::RateLimited(_))
    ));
    for (name, password) in [
        ("missing", PASSWORD),
        ("alice", "wrong"),
        (" alice ", "wrong"),
        ("Alice", PASSWORD),
    ] {
        assert!(matches!(
            f.store
                .local_password_verifier(&f.engine)
                .verify(name, password, end())
                .await,
            Err(LocalPasswordVerificationError::Unauthenticated)
        ));
    }
    assert_eq!(
        f.store
            .local_password_verifier(&f.engine)
            .verify(" \talice\n", PASSWORD, end())
            .await
            .unwrap()
            .username(),
        "alice"
    );
    for mutation in [
        "UPDATE local_users SET enabled=0",
        "UPDATE local_users SET identity_kind='service'",
        "UPDATE local_users SET password_hash='malformed'",
        "UPDATE local_users SET password_hash=zeroblob(600)",
        "UPDATE local_users SET password_change_required=3",
        "UPDATE local_users SET revision=0",
    ] {
        f.reset(false);
        f.db.execute_batch(mutation).unwrap();
        assert!(matches!(
            f.store
                .local_password_verifier(&f.engine)
                .verify("alice", PASSWORD, end())
                .await,
            Err(LocalPasswordVerificationError::Unauthenticated)
        ));
    }
    f.reset(false);
    let earlier = f.proof().await;
    f.db.execute("UPDATE local_users SET enabled=0", [])
        .unwrap();
    assert!(matches!(
        f.auth(false)
            .begin(earlier, LocalAuthBinding::AdminLogin, end())
            .await,
        Err(Error::Unauthenticated)
    ));
    for context in [
        LocalAuthBinding::AdminLogin,
        LocalAuthBinding::OauthAuthorize(b"native-request"),
        LocalAuthBinding::DeviceApprove(b"NATIVE123"),
    ] {
        f.reset(false);
        let auth = f.auth(true);
        let p = f.challenge(context, true).await;
        assert_eq!(p.stage(), Stage::Enrollment);
        assert_eq!(p.challenge().len(), 43);
        let enrollment = p.enrollment().unwrap();
        let png = enrollment.qr_png();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert!(u32::from_be_bytes(png[16..20].try_into().unwrap()) > 0);
        let sdk = totp_rs::Totp::from_url(enrollment.otpauth_uri()).unwrap();
        assert_eq!(
            auth.load(p.challenge(), context, end())
                .await
                .unwrap()
                .stage(),
            Stage::Enrollment
        );
        let wrong = LocalAuthBinding::OauthAuthorize(b"wrong-request");
        assert!(matches!(
            auth.load(p.challenge(), wrong, end()).await,
            Err(Error::InvalidChallenge)
        ));
        let hash =
            f.d.token(
                broker_security::TokenKind::LocalAuthChallenge,
                p.challenge().as_bytes(),
            )
            .unwrap()
            .to_sql_hex();
        f.db.execute(
            "UPDATE local_auth_challenges SET expires_at=1 WHERE challenge_hash=?1",
            [&hash],
        )
        .unwrap();
        assert!(matches!(
            auth.load(p.challenge(), context, end()).await,
            Err(Error::InvalidChallenge)
        ));
        f.db.execute(
            "UPDATE local_auth_challenges SET expires_at=?1 WHERE challenge_hash=?2",
            params![utc() + 120_000_000, &hash],
        )
        .unwrap();
        f.db.execute("INSERT INTO local_mfa_recovery_codes(subject,code_hash,created_at) VALUES('alice-subject',?1,1)",["f".repeat(64)]).unwrap();
        assert!(matches!(
            auth.complete_mfa(limiter(10), p.challenge(), context, "000000", end())
                .await,
            Err(Error::InvalidChallenge)
        ));
        f.db.execute("DELETE FROM local_mfa_recovery_codes", [])
            .unwrap();
        let native_cipher = Zeroizing::new(
            f.db.query_row::<String, _, _>(
                "SELECT secret_ciphertext FROM local_auth_challenges WHERE challenge_hash=?1",
                [&hash],
                |r| r.get(0),
            )
            .unwrap(),
        );
        f.db.execute(
            "UPDATE local_auth_challenges SET secret_ciphertext=?1 WHERE challenge_hash=?2",
            params![format!("rust-mfa1.{}", "A".repeat(80)), &hash],
        )
        .unwrap();
        assert!(matches!(
            auth.load(p.challenge(), context, end()).await,
            Err(Error::Mfa(_))
        ));
        assert!(matches!(
            auth.complete_mfa(limiter(1), p.challenge(), context, "000000", end())
                .await,
            Err(Error::Mfa(_))
        ));
        f.db.execute(
            "UPDATE local_auth_challenges SET secret_ciphertext=?1 WHERE challenge_hash=?2",
            params![native_cipher.as_str(), &hash],
        )
        .unwrap();
        assert!(matches!(
            auth.complete_mfa(limiter(1), p.challenge(), context, &"x".repeat(65), end())
                .await,
            Err(Error::InvalidMfaCode)
        ));
        let lim = limiter(10);
        let state = f.snapshot();
        assert!(matches!(
            auth.complete_mfa(lim.clone(), p.challenge(), context, "not-a-code", end())
                .await
                .unwrap(),
            LocalAuthStep::Pending(_)
        ));
        assert!(
            f.snapshot() == state,
            "incorrect enrollment must preserve durable state"
        );
        f.artifacts();
        let code = Zeroizing::new(sdk.generate(utc() as u64 / 1_000_000).to_string());
        let mut login = complete(
            auth.complete_mfa(lim.clone(), p.challenge(), context, &code, end())
                .await
                .unwrap(),
        );
        assert_eq!(login.auth_method(), "local-password+totp");
        assert_eq!(login.revision(), 2);
        login.verify_binding(&f.d, context).unwrap();
        let codes = login.take_recovery_codes().unwrap();
        assert!(login.take_recovery_codes().is_none());
        assert_eq!(f.count("SELECT COUNT(*) FROM local_mfa_recovery_codes"), 10);
        f.invalidation(matches!(context, LocalAuthBinding::DeviceApprove(_)));
        let recovery = Zeroizing::new(codes.iter().next().unwrap().to_owned());
        for code in codes.iter() {
            let normalized = broker_security::normalize_local_recovery_code(code).unwrap();
            let digest =
                f.d.recovery(b"alice-subject", normalized.as_bytes())
                    .unwrap()
                    .to_sql_hex();
            assert_eq!(
                f.db.query_row::<i64, _, _>(
                    "SELECT COUNT(*) FROM local_mfa_recovery_codes WHERE code_hash=?1",
                    [digest],
                    |r| r.get(0)
                )
                .unwrap(),
                1
            );
        }
        assert!(matches!(
            auth.complete_mfa(lim.clone(), p.challenge(), context, &code, end())
                .await,
            Err(Error::InvalidChallenge)
        ));
        let exempt = complete(
            f.auth(false)
                .begin(f.proof().await, context, end())
                .await
                .unwrap(),
        );
        assert_eq!(exempt.auth_method(), "local-password");
        let next = f.challenge(context, true).await;
        assert_eq!(next.stage(), Stage::Mfa);
        assert!(matches!(
            auth.complete_mfa(lim.clone(), next.challenge(), context, &code, end())
                .await
                .unwrap(),
            LocalAuthStep::Pending(_)
        ));
        let recovered = complete(
            auth.complete_mfa(lim.clone(), next.challenge(), context, &recovery, end())
                .await
                .unwrap(),
        );
        assert_eq!(recovered.auth_method(), "local-password+totp");
        assert_eq!(f.count("SELECT COUNT(*) FROM local_mfa_recovery_codes"), 9);
        let next = f.challenge(context, true).await;
        assert!(matches!(
            auth.complete_mfa(lim, next.challenge(), context, &recovery, end())
                .await
                .unwrap(),
            LocalAuthStep::Pending(_)
        ));
        let limited = limiter(1);
        assert!(matches!(
            auth.complete_mfa(limited.clone(), next.challenge(), context, "invalid", end())
                .await
                .unwrap(),
            LocalAuthStep::Pending(_)
        ));
        assert!(matches!(
            auth.complete_mfa(limited, next.challenge(), context, "invalid", end())
                .await,
            Err(Error::MfaRateLimited(_))
        ));
    }
    admission.close();
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real mandatory password mutation, native KDF and transactional invalidation"]
async fn sqlite_local_password_change_and_rollback() {
    let f = Fixture::new().await;
    for (context, required) in [
        (LocalAuthBinding::AdminLogin, false),
        (LocalAuthBinding::OauthAuthorize(b"request"), true),
        (LocalAuthBinding::DeviceApprove(b"NATIVE123"), false),
    ] {
        f.reset(true);
        let auth = f.auth(required);
        let p = f.challenge(context, required).await;
        assert_eq!(p.stage(), Stage::PasswordChange);
        let before = f.snapshot();
        assert!(matches!(
            auth.complete_password_change(&f.engine, p.challenge(), context, PASSWORD, end())
                .await,
            Err(Error::PasswordUnchanged)
        ));
        assert!(before == f.snapshot());
        assert!(matches!(
            auth.complete_password_change(&f.engine, p.challenge(), context, "short", end())
                .await,
            Err(Error::Password(
                broker_security::LocalPasswordError::InvalidPassword
            ))
        ));
        f.artifacts();
        let admission = LocalPasswordAdmission::new(
            LocalPasswordAdmissionPolicy {
                max_failures: n(5),
                window: Duration::from_secs(60),
                lockout: Duration::from_secs(60),
                workers: n(1),
                saturation_multiplier: n(2),
                max_tracked: n(4096),
            },
            &f.engine,
            LocalCaptcha::new(LocalCaptchaConfiguration::Disabled, n(1), n(2)).unwrap(),
        )
        .unwrap();
        let step = admission
            .admit_password_change(&f.engine, end())
            .unwrap()
            .complete_sqlite(&auth, p.challenge(), context, NEXT)
            .await
            .unwrap();
        if required {
            assert_eq!(pending(step).stage(), Stage::Enrollment);
        } else {
            assert_eq!(complete(step).auth_method(), "local-password");
        }
        assert_eq!(
            f.count("SELECT revision FROM local_users WHERE username='alice'"),
            2
        );
        assert_eq!(
            f.count("SELECT password_change_required FROM local_users WHERE username='alice'"),
            0
        );
        f.invalidation(matches!(context, LocalAuthBinding::DeviceApprove(_)));
        assert!(
            f.store
                .local_password_verifier(&f.engine)
                .verify("alice", PASSWORD, end())
                .await
                .is_err()
        );
        assert_eq!(
            f.store
                .local_password_verifier(&f.engine)
                .verify("alice", NEXT, end())
                .await
                .unwrap()
                .revision(),
            2
        );
        assert!(matches!(
            auth.complete_password_change(&f.engine, p.challenge(), context, NEXT, end())
                .await,
            Err(Error::InvalidChallenge)
        ));
        admission.close();
    }
    for blob in [false, true] {
        f.reset(true);
        let p = f.challenge(LocalAuthBinding::AdminLogin, false).await;
        f.artifacts();
        if blob {
            f.db.execute("UPDATE oidc_auth_requests SET request_json=?1 WHERE identity_subject='alice-subject'",[b"SQL driver decoding failure".as_slice()]).unwrap();
        } else {
            f.db.execute("UPDATE oidc_auth_requests SET request_json='{' WHERE identity_subject='alice-subject'",[]).unwrap();
        }
        let before = f.snapshot();
        assert!(matches!(
            f.auth(false)
                .complete_password_change(
                    &f.engine,
                    p.challenge(),
                    LocalAuthBinding::AdminLogin,
                    NEXT,
                    end()
                )
                .await,
            Err(Error::Control(ControlError::Storage))
        ));
        assert!(
            before == f.snapshot(),
            "failure after staged password/token mutations must roll everything back"
        );
    }
    f.reset(true);
    let p = f.challenge(LocalAuthBinding::AdminLogin, false).await;
    f.artifacts();
    let before = f.snapshot();
    let invalid = Arc::new(
        LocalAuthPolicy::new(true, "invalid:issuer".into(), Duration::from_secs(120)).unwrap(),
    );
    assert!(matches!(
        f.store
            .local_auth_service(f.d.clone(), f.m.clone(), invalid)
            .complete_password_change(
                &f.engine,
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                NEXT,
                end()
            )
            .await,
        Err(Error::Mfa(_))
    ));
    assert!(
        before == f.snapshot(),
        "native SDK presentation failure must roll back all staged writes"
    );
    f.close().await;
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real snapshot/KDF/write races, cancellation, independent SQLite owners and close"]
async fn sqlite_local_races_and_lifecycle() {
    let f = Fixture::new().await;
    let gate = Gate::new("broker_control::sqlite::password_snapshot", 1);
    let job = tokio::spawn({
        let s = f.store.clone();
        let engine = f.engine.clone();
        let gate = gate.clone();
        async move {
            s.local_password_verifier(&engine)
                .verify("alice", PASSWORD, end())
                .await
        }
        .with_subscriber(Registry::default().with(GateLayer(gate)))
    });
    gate.wait().await;
    f.db.execute(
        "UPDATE local_users SET revision=revision+1 WHERE username='alice'",
        [],
    )
    .unwrap();
    gate.release();
    assert!(matches!(
        job.await.unwrap(),
        Err(LocalPasswordVerificationError::Unauthenticated)
    ));
    for mutation in [
        "UPDATE local_auth_challenges SET binding_hash=replace(binding_hash,'a','b')",
        "UPDATE local_users SET password_hash='changed-after-snapshot'",
        "UPDATE local_users SET revision=2",
        "UPDATE local_users SET password_change_required=0",
    ] {
        f.reset(true);
        let p = f.challenge(LocalAuthBinding::AdminLogin, false).await;
        let gate = Gate::new("broker_control::sqlite::password_change_snapshot", 1);
        let raw = Zeroizing::new(p.challenge().to_owned());
        let job = tokio::spawn({
            let s = f.store.clone();
            let engine = f.engine.clone();
            let d = f.d.clone();
            let m = f.m.clone();
            let policy = f.exempt.clone();
            let gate = gate.clone();
            async move {
                s.local_auth_service(d, m, policy)
                    .complete_password_change(
                        &engine,
                        &raw,
                        LocalAuthBinding::AdminLogin,
                        NEXT,
                        end(),
                    )
                    .await
            }
            .with_subscriber(Registry::default().with(GateLayer(gate)))
        });
        gate.wait().await;
        if mutation.contains("binding_hash") {
            f.db.execute("DELETE FROM local_auth_challenges", [])
                .unwrap();
        } else {
            f.db.execute_batch(mutation).unwrap();
        }
        let expected = f.snapshot();
        gate.release();
        assert!(matches!(job.await.unwrap(), Err(Error::InvalidChallenge)));
        assert!(expected == f.snapshot());
    }
    f.reset(true);
    let p = f.challenge(LocalAuthBinding::AdminLogin, false).await;
    let other = Arc::new(
        SqliteControlStore::open(config(&f.path), digester(), end())
            .await
            .unwrap(),
    );
    let gate = Gate::new("broker_control::sqlite::password_change_snapshot", 2);
    let mut jobs = Vec::new();
    for s in [f.store.clone(), other.clone()] {
        let raw = Zeroizing::new(p.challenge().to_owned());
        let engine = f.engine.clone();
        let d = f.d.clone();
        let m = f.m.clone();
        let policy = f.exempt.clone();
        let layer = gate.clone();
        jobs.push(tokio::spawn(
            async move {
                s.local_auth_service(d, m, policy)
                    .complete_password_change(
                        &engine,
                        &raw,
                        LocalAuthBinding::AdminLogin,
                        NEXT,
                        end(),
                    )
                    .await
            }
            .with_subscriber(Registry::default().with(GateLayer(layer))),
        ));
    }
    gate.wait().await;
    gate.release();
    let a = jobs.remove(0).await.unwrap();
    let b = jobs.remove(0).await.unwrap();
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(
        f.count("SELECT revision FROM local_users WHERE username='alice'"),
        2
    );
    other.shutdown(end()).await.unwrap();
    f.reset(false);
    let p = f.challenge(LocalAuthBinding::AdminLogin, true).await;
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let error = f
        .auth(true)
        .load(
            p.challenge(),
            LocalAuthBinding::AdminLogin,
            Instant::now() + Duration::from_millis(50),
        )
        .await
        .unwrap_err();
    assert_eq!(error, Error::Control(ControlError::Deadline));
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        f.auth(true)
            .load(p.challenge(), LocalAuthBinding::AdminLogin, end())
            .await
            .unwrap()
            .stage(),
        Stage::Enrollment
    );
    let s = f.store.clone();
    let d = f.d.clone();
    let m = f.m.clone();
    let policy = f.required.clone();
    let raw = Zeroizing::new(p.challenge().to_owned());
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let job = tokio::spawn(async move {
        s.local_auth_service(d, m, policy)
            .load(&raw, LocalAuthBinding::AdminLogin, end())
            .await
    });
    tokio::task::yield_now().await;
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    f.db.execute_batch("ROLLBACK").unwrap();
    assert!(
        f.auth(true)
            .load(p.challenge(), LocalAuthBinding::AdminLogin, end())
            .await
            .is_ok()
    );
    f.engine.close().await;
    f.store.shutdown(end()).await.unwrap();
    assert_eq!(
        f.auth(true)
            .load(p.challenge(), LocalAuthBinding::AdminLogin, end())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Closed)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real cancelled SQLite reader retains genuine password admission until native worker exits"]
async fn sqlite_cancelled_password_read_retains_admission() {
    let f = Fixture::new().await;
    let admission = Arc::new(
        LocalPasswordAdmission::new(
            LocalPasswordAdmissionPolicy {
                max_failures: n(5),
                window: Duration::from_secs(60),
                lockout: Duration::from_secs(60),
                workers: n(1),
                saturation_multiplier: n(1),
                max_tracked: n(4096),
            },
            &f.engine,
            LocalCaptcha::new(LocalCaptchaConfiguration::Disabled, n(1), n(1)).unwrap(),
        )
        .unwrap(),
    );
    let observed = Gate::new("broker_control::sqlite::password_read_started", 1);
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let job = tokio::spawn({
        let store = f.store.clone();
        let engine = f.engine.clone();
        let admission = admission.clone();
        let observed = observed.clone();
        async move {
            store
                .admitted_local_passwords(
                    &engine,
                    &admission,
                    broker_security::LocalAuthPurpose::AdminLogin,
                )
                .unwrap()
                .authenticate("alice", PASSWORD, None, end())
                .await
        }
        .with_subscriber(Registry::default().with(GateLayer(observed)))
    });
    observed.wait().await;
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    let view = f
        .store
        .admitted_local_passwords(
            &f.engine,
            &admission,
            broker_security::LocalAuthPurpose::AdminLogin,
        )
        .unwrap();
    assert!(
        matches!(
            view.authenticate(
                "alice",
                PASSWORD,
                None,
                Instant::now() + Duration::from_millis(60)
            )
            .await,
            Err(LocalPasswordAdmissionError::RateLimited(_))
        ),
        "cancelled caller released admission before the blocked native SQL reader exited"
    );
    observed.release();
    f.db.execute_batch("ROLLBACK").unwrap();
    let wait = Instant::now() + Duration::from_secs(10);
    loop {
        match view.authenticate("alice", PASSWORD, None, end()).await {
            Ok(proof) => {
                assert_eq!(proof.subject(), "alice-subject");
                break;
            }
            Err(LocalPasswordAdmissionError::RateLimited(_)) => {
                assert!(Instant::now() < wait);
                tokio::task::yield_now().await;
            }
            Err(_) => panic!("fresh login must recover after actual cancelled worker exit"),
        }
    }
    admission.close();
    f.close().await;
}
