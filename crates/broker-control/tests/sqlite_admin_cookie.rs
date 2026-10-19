use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    AdminBrokerSessionLimits, AdminCookieLogoutDisposition as Disposition,
    AdminCookieSessionError as Error, AdminCookieSessionLimits, AdminCookieSessionPolicy,
    AdminLoginPreparationError, CompletedLocalLogin, ControlError, FlowLimits, IdentityReadLimits,
    LocalAuthPolicy, LocalAuthStep, LocalMfaAttemptLimiter, LocalMfaAttemptPolicy,
    LocalPasswordEngine, NewAdminSession, PreparedAdminLogin, SessionClaimRoles, SessionLimits,
    SessionPrincipal, SessionProfile, SqliteControlConfig, SqliteControlStore, SystemAction,
    SystemPermission,
};
use broker_security::{
    CredentialDigester, DigestLimits, LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher,
    TokenKind,
};
use broker_store::time::TimestampMicros;
use rusqlite::{Connection, params};
use std::{
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;
const PASSWORD: &str = "synthetic SQLite admin cookie password";
fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn utc() -> i64 {
    TimestampMicros::try_from(SystemTime::now())
        .unwrap()
        .as_i64()
}
fn secret(byte: u8) -> String {
    URL_SAFE_NO_PAD.encode([byte; 32])
}
fn digester(byte: u8) -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(vec![byte; 32].into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
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
fn policy() -> AdminCookieSessionPolicy {
    AdminCookieSessionPolicy {
        session_ttl: Duration::from_secs(600),
    }
}
fn config(path: &Path) -> SqliteControlConfig {
    SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(5),
        FlowLimits {
            provider_bytes: n(128),
            request_bytes: n(1024),
            continuation_bytes: n(4096),
        },
    )
    .unwrap()
}
fn complete(step: LocalAuthStep) -> CompletedLocalLogin {
    match step {
        LocalAuthStep::Complete(v) => v,
        _ => panic!("genuine completed login expected"),
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    store: Arc<SqliteControlStore>,
    db: Connection,
    engine: Arc<LocalPasswordEngine>,
    d: Arc<CredentialDigester>,
    m: Arc<LocalMfaProtector>,
    exempt: Arc<LocalAuthPolicy>,
    required: Arc<LocalAuthPolicy>,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private/broker.db");
        let store = Arc::new(
            SqliteControlStore::open(config(&path), digester(41), end())
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
        db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',?1,'Initial','initial@example.test','org','[\" beta \",\"alpha\",\"alpha\"]',1,0,1,0,0)",[hash.as_str()]).unwrap();
        db.execute_batch("INSERT OR IGNORE INTO roles(name,created_at) VALUES('user',0);DELETE FROM role_permissions WHERE role='user';INSERT INTO role_permissions(role,action) VALUES('user','session.read');INSERT INTO roles(name,created_at) VALUES('reader',0);INSERT INTO role_permissions(role,action) VALUES('reader','projects.read');INSERT INTO role_assignments(subject,role,created_at) VALUES('local|alice-subject','reader',0)").unwrap();
        Self {
            _temp: temp,
            path,
            store,
            db,
            engine,
            d: Arc::new(digester(41)),
            m: Arc::new(
                LocalMfaProtector::new(Zeroizing::new(vec![47; 32].into_boxed_slice())).unwrap(),
            ),
            exempt: Arc::new(
                LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(120))
                    .unwrap(),
            ),
            required: Arc::new(
                LocalAuthPolicy::new(true, "Graphit Broker".into(), Duration::from_secs(120))
                    .unwrap(),
            ),
        }
    }
    fn cookies(&self) -> broker_control::SqliteLocalAdminCookieSessions<'_> {
        self.store
            .local_admin_cookie_sessions(limits(), policy())
            .unwrap()
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
    async fn login(&self, binding: LocalAuthBinding<'_>) -> CompletedLocalLogin {
        let p = self
            .store
            .local_password_verifier(&self.engine)
            .verify("alice", PASSWORD, end())
            .await
            .unwrap();
        complete(self.auth(false).begin(p, binding, end()).await.unwrap())
    }
    async fn prepared(&self) -> PreparedAdminLogin {
        PreparedAdminLogin::try_from(self.login(LocalAuthBinding::AdminLogin).await).unwrap()
    }
    async fn issue(&self) -> broker_control::IssuedAdminCookie {
        self.cookies()
            .issue_local(self.prepared().await, &self.exempt, end())
            .await
            .unwrap()
    }
    fn count(&self) -> i64 {
        self.db
            .query_row("SELECT count(*) FROM admin_sessions", [], |r| r.get(0))
            .unwrap()
    }
    fn reset_user(&self) {
        self.db.execute_batch("UPDATE local_users SET username='alice',subject='alice-subject',identity_kind='human',enabled=1,revision=1,password_change_required=0,name='Initial',email='initial@example.test',organization='org',teams_json='[\"alpha\",\"beta\"]'").unwrap();
    }
    async fn seed(&self, byte: u8, issuer: &str, claims: Option<Vec<String>>) -> (String, String) {
        let raw = secret(byte);
        let csrf = secret(byte.wrapping_add(1));
        let session = NewAdminSession::new(
            SessionProfile {
                subject: "alice-subject".into(),
                name: "Stored".into(),
                email: String::new(),
            },
            SessionPrincipal {
                issuer: issuer.into(),
                username: "alice".into(),
                organization: String::new(),
                teams: vec![],
                local_user_revision: if issuer == "local" { 1 } else { 0 },
            },
            Zeroizing::new(csrf.clone()),
            claims.map(|roles| SessionClaimRoles {
                selector: "roles".into(),
                roles,
            }),
            SystemTime::now() + Duration::from_secs(600),
            &limits().metadata,
        )
        .unwrap();
        self.store
            .admin_sessions(limits().metadata)
            .unwrap()
            .create_session(&raw, &session, end())
            .await
            .unwrap();
        (raw, csrf)
    }
    fn hash(&self, raw: &str) -> String {
        self.d
            .token(TokenKind::AdminSession, raw.as_bytes())
            .unwrap()
            .to_sql_hex()
    }
    async fn close(self) {
        self.engine.close().await;
        self.store.shutdown(end()).await.unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native Argon2/TOTP login and transactional SQLite administrative cookie"]
async fn sqlite_cookie_genuine_login_preparation_and_current_issuance() {
    let f = Fixture::new().await;
    let wrong = f.login(LocalAuthBinding::OauthAuthorize(b"request")).await;
    let e = PreparedAdminLogin::try_from(wrong).unwrap_err();
    assert!(matches!(e, AdminLoginPreparationError::InvalidPurpose(_)));
    e.into_login()
        .verify_binding(&f.d, LocalAuthBinding::OauthAuthorize(b"request"))
        .unwrap();
    assert_eq!(
        f.cookies()
            .issue_local(f.prepared().await, &f.required, end())
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(f.count(), 0);
    let other = SqliteControlStore::open(config(&f.path), digester(99), end())
        .await
        .unwrap();
    assert_eq!(
        other
            .local_admin_cookie_sessions(limits(), policy())
            .unwrap()
            .issue_local(f.prepared().await, &f.exempt, end())
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    other.shutdown(end()).await.unwrap();
    assert_eq!(f.count(), 0);
    let password = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", PASSWORD, end())
        .await
        .unwrap();
    let pending = match f
        .auth(true)
        .begin(password, LocalAuthBinding::AdminLogin, end())
        .await
        .unwrap()
    {
        LocalAuthStep::Pending(p) => p,
        _ => panic!("native MFA enrollment expected"),
    };
    let sdk = totp_rs::Totp::from_url(pending.enrollment().unwrap().otpauth_uri()).unwrap();
    let code = Zeroizing::new(sdk.generate(utc() as u64 / 1_000_000).to_string());
    let limiter = Arc::new(LocalMfaAttemptLimiter::new(
        LocalMfaAttemptPolicy::new(
            NonZeroU32::new(5).unwrap(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            n(16),
        )
        .unwrap(),
    ));
    let login = complete(
        f.auth(true)
            .complete_mfa(
                limiter,
                pending.challenge(),
                LocalAuthBinding::AdminLogin,
                &code,
                end(),
            )
            .await
            .unwrap(),
    );
    let e = PreparedAdminLogin::try_from(login).unwrap_err();
    assert!(matches!(
        e,
        AdminLoginPreparationError::RecoveryCodesPending(_)
    ));
    let mut login = e.into_login();
    let codes = login.take_recovery_codes().unwrap();
    assert_eq!(codes.iter().count(), 10);
    assert!(login.take_recovery_codes().is_none());
    f.db.execute_batch(
        "UPDATE local_users SET name='Current at issue',teams_json='[\" z \",\"a\",\"a\"]'",
    )
    .unwrap();
    let issued = f
        .cookies()
        .issue_local(
            PreparedAdminLogin::try_from(login).unwrap(),
            &f.required,
            end(),
        )
        .await
        .unwrap();
    issued.check().unwrap();
    assert_eq!(issued.secret().len(), 43);
    let current = f.cookies().read(issued.secret(), end()).await.unwrap();
    assert_eq!(current.profile().name, "Current at issue");
    assert_eq!(current.principal().teams, ["a", "z"]);
    assert_eq!(current.roles(), ["reader", "user"]);
    assert_eq!(current.role_source(), "database");
    assert!(
        current
            .permissions()
            .contains(&SystemPermission::Action(SystemAction::SessionRead))
    );
    assert_ne!(issued.secret(), current.csrf_token());
    let (hash,issuer,claimed):(String,String,i64)=f.db.query_row("SELECT s.token_hash,p.issuer,(SELECT count(*) FROM admin_session_claim_roles) FROM admin_sessions s JOIN admin_session_principals p USING(token_hash)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(hash, f.hash(issued.secret()));
    assert_eq!(hash.len(), 64);
    assert_eq!(issuer, "local");
    assert_eq!(claimed, 0);
    assert_ne!(hash, issued.secret());
    let expiry = current.authentication_expiry();
    f.db.execute_batch("UPDATE local_users SET name='Read current',teams_json='[\"b\"]';DELETE FROM role_assignments").unwrap();
    let newer = f.cookies().read(issued.secret(), end()).await.unwrap();
    assert_eq!(newer.profile().name, "Read current");
    assert_eq!(newer.roles(), ["user"]);
    assert_eq!(newer.authentication_expiry().0, expiry.0);
    f.db.execute_batch("DELETE FROM role_permissions WHERE role='user'")
        .unwrap();
    assert_eq!(
        f.cookies().read(issued.secret(), end()).await.unwrap_err(),
        Error::Forbidden
    );
    f.db.execute_batch("UPDATE local_users SET enabled=0")
        .unwrap();
    assert_eq!(
        f.cookies()
            .logout(issued.secret(), Some(current.csrf_token()), end())
            .await
            .unwrap()
            .disposition(),
        Disposition::Revoked
    );
    assert_eq!(f.count(), 0);
    drop(codes);
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native LOCAL bindings, current SQL identity/profile/RBAC and concrete bounds"]
async fn sqlite_cookie_revalidates_bindings_and_bounds() {
    let f = Fixture::new().await;
    for mutation in [
        "username='renamed'",
        "subject='changed-subject'",
        "revision=revision+1",
        "enabled=0",
        "identity_kind='service'",
        "password_change_required=1",
    ] {
        let prepared = f.prepared().await;
        f.db.execute(&format!("UPDATE local_users SET {mutation}"), [])
            .unwrap();
        assert_eq!(
            f.cookies()
                .issue_local(prepared, &f.exempt, end())
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
        assert_eq!(f.count(), 0);
        f.reset_user();
    }
    let issued = f.issue().await;
    for mutation in [
        "username='renamed'",
        "subject='changed-subject'",
        "revision=revision+1",
        "enabled=0",
        "identity_kind='service'",
        "password_change_required=1",
    ] {
        f.db.execute(&format!("UPDATE local_users SET {mutation}"), [])
            .unwrap();
        assert_eq!(
            f.cookies().read(issued.secret(), end()).await.unwrap_err(),
            Error::Unauthorized
        );
        assert_eq!(f.count(), 1);
        f.reset_user();
    }
    for mutation in [
        "name='".to_owned() + &"x".repeat(513) + "'",
        "teams_json='{'".into(),
        "teams_json=CAST('[]' AS BLOB)".into(),
    ] {
        f.db.execute(&format!("UPDATE local_users SET {mutation}"), [])
            .unwrap();
        assert!(matches!(
            f.cookies().read(issued.secret(), end()).await,
            Err(Error::Control(ControlError::CorruptIdentity))
        ));
        f.reset_user();
    }
    let mut caps = Vec::new();
    let mut l = limits();
    l.authorization.identity.username_bytes = n(3);
    caps.push(l);
    let mut l = limits();
    l.authorization.identity.subject_bytes = n(3);
    caps.push(l);
    let mut l = limits();
    l.authorization.identity.role_bytes = n(4);
    caps.push(l);
    let mut l = limits();
    l.authorization.identity.roles = n(1);
    caps.push(l);
    let mut l = limits();
    l.authorization.identity.rows = n(1);
    caps.push(l);
    let mut l = limits();
    l.authorization.profile_json_bytes = n(32);
    caps.push(l);
    for l in caps {
        assert!(
            f.store
                .local_admin_cookie_sessions(l, policy())
                .unwrap()
                .read(issued.secret(), end())
                .await
                .is_err()
        );
        assert_eq!(f.count(), 1);
    }
    f.db.execute_batch(
        "INSERT INTO role_permissions(role,action) VALUES('reader','unsupported.action')",
    )
    .unwrap();
    assert_eq!(
        f.cookies().read(issued.secret(), end()).await.unwrap_err(),
        Error::Control(ControlError::CorruptRbac)
    );
    f.db.execute_batch("DELETE FROM role_permissions WHERE action='unsupported.action'")
        .unwrap();
    let csrf = f.cookies().read(issued.secret(), end()).await.unwrap();
    assert_eq!(
        f.cookies()
            .logout(issued.secret(), Some(csrf.csrf_token()), end())
            .await
            .unwrap()
            .disposition(),
        Disposition::Revoked
    );
    for (l, p) in [
        (
            limits(),
            AdminCookieSessionPolicy {
                session_ttl: Duration::from_secs(299),
            },
        ),
        (
            {
                let mut l = limits();
                l.metadata.csrf_bytes = n(42);
                l
            },
            policy(),
        ),
        (
            {
                let mut l = limits();
                l.metadata.max_lifetime = Duration::from_secs(300);
                l
            },
            policy(),
        ),
    ] {
        assert!(matches!(
            f.store.local_admin_cookie_sessions(l, p),
            Err(ControlError::Configuration)
        ));
    }
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "strict metadata, canonical CSRF, expiry/cascade and nonlocal own-session logout"]
async fn sqlite_cookie_metadata_expiry_and_logout() {
    let f = Fixture::new().await;
    assert_eq!(
        f.cookies().read("invalid", end()).await.unwrap_err(),
        Error::MalformedCookie
    );
    assert_eq!(
        f.cookies()
            .logout(&secret(1), Some("bad"), end())
            .await
            .unwrap()
            .disposition(),
        Disposition::Absent
    );
    let (raw, csrf) = f.seed(2, "local", None).await;
    for supplied in [None, Some("bad"), Some(secret(99).as_str())] {
        assert_eq!(
            f.cookies().logout(&raw, supplied, end()).await.unwrap_err(),
            Error::CsrfFailed
        );
        assert_eq!(f.count(), 1);
    }
    let duplicate = NewAdminSession::new(
        SessionProfile {
            subject: "other-subject".into(),
            name: "Other".into(),
            email: String::new(),
        },
        SessionPrincipal {
            issuer: "local".into(),
            username: "other".into(),
            organization: String::new(),
            teams: vec![],
            local_user_revision: 1,
        },
        Zeroizing::new(secret(9)),
        None,
        SystemTime::now() + Duration::from_secs(300),
        &limits().metadata,
    )
    .unwrap();
    assert_eq!(
        f.store
            .admin_sessions(limits().metadata)
            .unwrap()
            .create_session(&raw, &duplicate, end())
            .await
            .unwrap_err(),
        ControlError::SessionExists
    );
    assert_eq!(
        f.cookies().read(&raw, end()).await.unwrap().csrf_token(),
        csrf
    );
    let mut small = limits();
    small.metadata.text_bytes = n(3);
    assert_eq!(
        f.store
            .local_admin_cookie_sessions(small, policy())
            .unwrap()
            .read(&raw, end())
            .await
            .unwrap_err(),
        Error::Control(ControlError::CorruptSession)
    );
    f.db.execute("UPDATE admin_sessions SET csrf_token='bad',created_at=?1,expires_at=?2 WHERE token_hash=?3",params![utc()-2_000_000,utc()-1_000_000,f.hash(&raw)]).unwrap();
    assert_eq!(
        f.cookies().read(&raw, end()).await.unwrap_err(),
        Error::Control(ControlError::CorruptSession)
    );
    assert_eq!(
        f.cookies().logout(&raw, None, end()).await.unwrap_err(),
        Error::Control(ControlError::CorruptSession)
    );
    assert_eq!(f.count(), 1);
    f.db.execute(
        "UPDATE admin_sessions SET csrf_token=?1 WHERE token_hash=?2",
        params![csrf, f.hash(&raw)],
    )
    .unwrap();
    assert_eq!(
        f.cookies().read(&raw, end()).await.unwrap_err(),
        Error::Control(ControlError::SessionExpired)
    );
    assert_eq!(f.count(), 0);
    let (local, _) = f.seed(4, "local", Some(vec![])).await;
    assert_eq!(
        f.cookies().read(&local, end()).await.unwrap_err(),
        Error::Unauthorized
    );
    f.store
        .admin_sessions(limits().metadata)
        .unwrap()
        .revoke_session(&local, end())
        .await
        .unwrap();
    let (raw, csrf) = f.seed(6, "federated", Some(vec!["reader".into()])).await;
    assert_eq!(
        f.cookies().read(&raw, end()).await.unwrap_err(),
        Error::Unauthorized
    );
    let (foreign, foreign_csrf) = f.seed(7, "local", None).await;
    assert_eq!(
        f.cookies()
            .logout(&raw, Some(&csrf), end())
            .await
            .unwrap()
            .disposition(),
        Disposition::Revoked
    );
    assert_eq!(f.count(), 1);
    assert_eq!(
        f.cookies()
            .read(&foreign, end())
            .await
            .unwrap()
            .csrf_token(),
        foreign_csrf
    );
    assert_eq!(
        f.db.query_row::<i64, _, _>("SELECT count(*) FROM admin_session_claim_roles", [], |r| r
            .get(0))
            .unwrap(),
        0
    );
    f.cookies()
        .logout(&foreign, Some(&foreign_csrf), end())
        .await
        .unwrap();
    let (raw, _) = f.seed(8, "federated", Some(vec![])).await;
    f.db.execute(
        "UPDATE admin_sessions SET created_at=?1,expires_at=?2 WHERE token_hash=?3",
        params![utc() - 2_000_000, utc() - 1_000_000, f.hash(&raw)],
    )
    .unwrap();
    assert_eq!(
        f.cookies()
            .logout(&raw, Some("bad"), end())
            .await
            .unwrap()
            .disposition(),
        Disposition::Expired
    );
    let (raw, csrf) = f.seed(10, "federated", None).await;
    f.db.execute(
        "UPDATE admin_session_principals SET local_user_revision=1 WHERE token_hash=?1",
        [f.hash(&raw)],
    )
    .unwrap();
    assert_eq!(
        f.cookies()
            .logout(&raw, Some(&csrf), end())
            .await
            .unwrap_err(),
        Error::Control(ControlError::CorruptSession)
    );
    assert_eq!(f.count(), 1);
    f.db.execute(
        "UPDATE admin_session_principals SET local_user_revision=0 WHERE token_hash=?1",
        [f.hash(&raw)],
    )
    .unwrap();
    f.cookies().logout(&raw, Some(&csrf), end()).await.unwrap();
    let (raw, _) = f.seed(12, "local", None).await;
    f.db.execute(
        "DELETE FROM admin_session_principals WHERE token_hash=?1",
        [f.hash(&raw)],
    )
    .unwrap();
    assert_eq!(
        f.cookies().read(&raw, end()).await.unwrap_err(),
        Error::Control(ControlError::CorruptSession)
    );
    assert_eq!(
        f.cookies().logout(&raw, None, end()).await.unwrap_err(),
        Error::Control(ControlError::CorruptSession)
    );
    assert_eq!(f.count(), 1);
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real writer deadline, queued cancellation, stale writer authority, close and recovery"]
async fn sqlite_cookie_deadline_cancel_close_and_current_writer() {
    let f = Fixture::new().await;
    let prepared = f.prepared().await;
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        f.cookies()
            .issue_local(
                prepared,
                &f.exempt,
                Instant::now() + Duration::from_millis(80)
            )
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.count(), 0);
    let prepared = f.prepared().await;
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    {
        let view = f.cookies();
        let pending = view.issue_local(prepared, &f.exempt, end());
        tokio::pin!(pending);
        assert!(futures_util::poll!(&mut pending).is_pending());
        f.db.execute_batch("UPDATE local_users SET enabled=0;COMMIT")
            .unwrap();
        assert_eq!(pending.await.unwrap_err(), Error::Unauthorized);
    }
    assert_eq!(f.count(), 0);
    f.reset_user();
    let issued = f.issue().await;
    let current = f.cookies().read(issued.secret(), end()).await.unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        f.cookies()
            .read(issued.secret(), Instant::now() + Duration::from_millis(80))
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    assert_eq!(
        f.cookies()
            .logout(
                issued.secret(),
                Some(current.csrf_token()),
                Instant::now() + Duration::from_millis(80)
            )
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.count(), 1);
    let prepared = f.prepared().await;
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    {
        let view = f.cookies();
        let pending = view.issue_local(prepared, &f.exempt, end());
        tokio::pin!(pending);
        assert!(futures_util::poll!(&mut pending).is_pending());
    }
    f.db.execute_batch("ROLLBACK").unwrap();
    assert!(f.cookies().read(issued.secret(), end()).await.is_ok());
    assert_eq!(f.count(), 1);
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    {
        let view = f.cookies();
        let pending = view.logout(issued.secret(), Some(current.csrf_token()), end());
        tokio::pin!(pending);
        assert!(futures_util::poll!(&mut pending).is_pending());
    }
    f.db.execute_batch("ROLLBACK").unwrap();
    assert!(f.cookies().read(issued.secret(), end()).await.is_ok());
    assert_eq!(f.count(), 1);
    f.store.shutdown(end()).await.unwrap();
    assert_eq!(
        f.cookies().read(issued.secret(), end()).await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    assert_eq!(
        f.cookies()
            .logout(issued.secret(), Some(current.csrf_token()), end())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    let reopened = SqliteControlStore::open(config(&f.path), digester(41), end())
        .await
        .unwrap();
    let c = reopened
        .local_admin_cookie_sessions(limits(), policy())
        .unwrap();
    assert!(c.read(issued.secret(), end()).await.is_ok());
    c.logout(issued.secret(), Some(current.csrf_token()), end())
        .await
        .unwrap();
    assert_eq!(f.count(), 0);
    reopened.shutdown(end()).await.unwrap();
    f.close().await;
}
