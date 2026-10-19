use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    ControlError, FlowLimits, LocalBearerKind, LocalBearerStateError,
    LocalBearerVerificationError as Error, SqliteControlConfig, SqliteControlStore,
    VerifiedLocalBearer,
};
use broker_security::{CredentialDigester, DigestLimits};
use broker_store::time::TimestampMicros;
use rusqlite::{Connection, params};
use serde_json::json;
use std::{
    num::NonZeroUsize,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;
fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn now() -> i64 {
    TimestampMicros::try_from(SystemTime::now())
        .unwrap()
        .as_i64()
}
fn digester(key: &[u8]) -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(key.to_vec().into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
fn raw(kind: &str) -> String {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).unwrap();
    format!("{kind}{}", URL_SAFE_NO_PAD.encode(bytes))
}
struct Fixture {
    _root: tempfile::TempDir,
    path: PathBuf,
    store: Arc<SqliteControlStore>,
    key: [u8; 32],
    access: String,
    service: String,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private/broker.db");
        let mut key = [0; 32];
        getrandom::fill(&mut key).unwrap();
        let config = SqliteControlConfig::new(
            path.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            FlowLimits {
                provider_bytes: n(128),
                request_bytes: n(256),
                continuation_bytes: n(1024),
            },
        )
        .unwrap();
        let store = Arc::new(
            SqliteControlStore::open(config, digester(&key), end())
                .await
                .unwrap(),
        );
        let f = Self {
            _root: root,
            path,
            store,
            key,
            access: raw("gb_at_"),
            service: raw("gb_sc_"),
        };
        let db = f.db();
        for (username, subject, kind) in [
            ("alice", "alice-subject", "human"),
            ("bot", "bot-subject", "service"),
        ] {
            db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES(?1,?2,?3,'not-selected-phc','current-name','current-email','current-org','[\" team \",\"team\",\"a,b\"]',1,1,1,0,0)",params![username,subject,kind]).unwrap();
        }
        for (token, kind, subject) in [
            (&f.access, LocalBearerKind::Access, "alice-subject"),
            (
                &f.service,
                LocalBearerKind::ServiceCredential,
                "bot-subject",
            ),
        ] {
            db.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES(?1,?2,?3,?4,'other-pseudonym',?5,'client','aud','','[\"project-api\",\" padded \",\"a,b\",\"project-api\",\"\"]',1,'',0,?6,0)",params![f.hash(token,kind),token,kind.as_str(),subject,principal(subject),now()+60_000_000]).unwrap();
        }
        f
    }
    fn db(&self) -> Connection {
        let db = Connection::open(&self.path).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db
    }
    fn hash(&self, raw: &str, kind: LocalBearerKind) -> String {
        digester(&self.key)
            .token(kind.token_kind(), raw.as_bytes())
            .unwrap()
            .to_sql_hex()
    }
    async fn verify(&self, raw: &str, scopes: &[String]) -> Result<VerifiedLocalBearer, Error> {
        self.store
            .local_bearer_verifier(" aud ", n(8192))
            .unwrap()
            .verify(raw, scopes, end())
            .await
    }
    fn used(&self) -> Option<i64> {
        self.db()
            .query_row(
                "SELECT last_used_at FROM local_tokens WHERE token_hash=?1",
                [self.hash(&self.access, LocalBearerKind::Access)],
                |r| r.get(0),
            )
            .unwrap()
    }
    fn used_by_kind(&self) -> Option<i64> {
        self.db()
            .query_row(
                "SELECT last_used_at FROM local_tokens WHERE token_kind=\'access\'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }
    fn snapshot(&self) -> [Vec<Vec<rusqlite::types::Value>>; 2] {
        let db = self.db();
        [
            "SELECT * FROM local_users ORDER BY username",
            "SELECT * FROM local_tokens ORDER BY token_hash",
        ]
        .map(|sql| {
            let mut statement = db.prepare(sql).unwrap();
            let columns = statement.column_count();
            statement
                .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        })
    }
    async fn close(self) {
        self.store.shutdown(end()).await.unwrap();
    }
}
fn principal(subject: &str) -> String {
    json!({"issuer":"local","subject":subject,"username":"stale-user","auth_method":"stale-method","name":"stale-name","teams":["stale-team"],"roles":["admin"],"local_user_revision":1}).to_string()
}
fn unauth(value: Result<VerifiedLocalBearer, Error>) {
    assert!(matches!(value, Err(Error::Unauthenticated)), "{value:?}");
}

#[tokio::test]
async fn sqlite_bearer_authenticates_current_human_service_and_exact_raw_contracts() {
    let f = Fixture::new().await;
    for bad in [
        "".into(),
        "gb_rt_refresh".into(),
        f.access.to_uppercase(),
        format!(" {}", f.access),
        format!("{} ", f.access),
        "eyJ.jwt.token".into(),
        raw("gb_at_"),
    ] {
        unauth(f.verify(&bad, &[]).await);
    }
    unauth(f.verify(&f.access, &["padded".into()]).await);
    unauth(f.verify(&f.access, &["a".into()]).await);
    assert_eq!(f.used(), None);
    let original_hash = f.hash(&f.access, LocalBearerKind::Access);
    for wrong_hash in [
        digester(&f.key)
            .token(
                broker_security::TokenKind::ServiceCredential,
                f.access.as_bytes(),
            )
            .unwrap()
            .to_sql_hex(),
        digester(&[82; 32])
            .token(broker_security::TokenKind::LocalAccess, f.access.as_bytes())
            .unwrap()
            .to_sql_hex(),
    ] {
        f.db()
            .execute(
                "UPDATE local_tokens SET token_hash=?1 WHERE token_kind=\'access\'",
                [wrong_hash],
            )
            .unwrap();
        unauth(f.verify(&f.access, &[]).await);
        assert_eq!(f.used_by_kind(), None);
    }
    f.db()
        .execute(
            "UPDATE local_tokens SET token_hash=?1 WHERE token_kind=\'access\'",
            [original_hash],
        )
        .unwrap();
    let before = f.snapshot();
    let p = f
        .verify(
            &f.access,
            &[" project-api ".into(), "".into(), "a,b".into()],
        )
        .await
        .unwrap();
    assert_eq!(p.auth_method(), "local-token");
    assert_eq!(p.kind(), LocalBearerKind::Access);
    assert_eq!(p.scopes(), ["a,b", "padded", "project-api"]);
    let u = p.current_local_user();
    assert_eq!(
        (
            u.username(),
            u.subject(),
            u.name(),
            u.email(),
            u.organization()
        ),
        (
            "alice",
            "alice-subject",
            "current-name",
            "current-email",
            "current-org"
        )
    );
    assert_eq!(u.teams(), ["a,b", "team"]);
    assert_eq!(p.audience(), "aud");
    assert_eq!(f.used(), None);
    let pair = p.authentication_expiry();
    assert!(pair.1 > Instant::now());
    assert_eq!(format!("{p:?}"), "VerifiedLocalBearer([REDACTED])");
    let s = f.verify(&f.service, &[]).await.unwrap();
    assert_eq!(s.auth_method(), "service-credential");
    assert_eq!(s.current_local_user().username(), "bot");
    assert_eq!(f.snapshot(), before);
    let db = f.db();
    db.execute(
        "UPDATE local_tokens SET audience='' WHERE token_kind='access'",
        [],
    )
    .unwrap();
    assert!(
        f.store
            .local_bearer_verifier("", n(8192))
            .unwrap()
            .verify(&f.access, &[], end())
            .await
            .is_ok()
    );
    unauth(
        f.store
            .local_bearer_verifier("AUD", n(8192))
            .unwrap()
            .verify(&f.access, &[], end())
            .await,
    );
    // Prefix alone is not given a new suffix grammar: possession still requires its genuine HMAC row.
    let hash = f.hash("gb_at_", LocalBearerKind::Access);
    db.execute(
        "UPDATE local_tokens SET token_hash=?1,audience='aud' WHERE token_kind='access'",
        [hash],
    )
    .unwrap();
    assert!(f.verify("gb_at_", &[]).await.is_ok());
    drop(db);
    f.close().await;
}

#[tokio::test]
async fn sqlite_bearer_rejects_current_identity_and_token_ineligibility_without_usage() {
    let f = Fixture::new().await;
    let db = f.db();
    for sql in [
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
        "UPDATE local_users SET revision=2 WHERE username='alice'",
        "UPDATE local_users SET identity_kind='service' WHERE username='alice'",
        "UPDATE local_tokens SET revoked_at=0 WHERE token_kind='access'",
        "UPDATE local_tokens SET expires_at=0 WHERE token_kind='access'",
        "UPDATE local_tokens SET local_user_revision=2 WHERE token_kind='access'",
        "UPDATE local_tokens SET token_kind='service' WHERE token_kind='access'",
    ] {
        db.execute_batch(sql).unwrap();
        unauth(f.verify(&f.access, &[]).await);
        assert_eq!(f.used(), None);
        db.execute("UPDATE local_users SET enabled=1,revision=1,identity_kind='human' WHERE username='alice'",[]).unwrap();
        db.execute("UPDATE local_tokens SET token_kind='access',revoked_at=NULL,expires_at=?1,local_user_revision=1 WHERE subject='alice-subject'",[now()+60_000_000]).unwrap();
    }
    for value in [
        json!({"issuer":"upstream","subject":"alice-subject","username":"u","auth_method":"x","local_user_revision":1}),
        json!({"issuer":"local","subject":"different","username":"u","auth_method":"x","local_user_revision":1}),
    ] {
        db.execute(
            "UPDATE local_tokens SET principal_json=?1 WHERE token_kind='access'",
            [value.to_string()],
        )
        .unwrap();
        unauth(f.verify(&f.access, &[]).await);
    }
    db.execute(
        "UPDATE local_tokens SET principal_json=?1 WHERE token_kind='access'",
        [principal("alice-subject")],
    )
    .unwrap();
    db.execute("DELETE FROM local_users WHERE username='alice'", [])
        .unwrap();
    unauth(f.verify(&f.access, &[]).await);
    assert_eq!(f.used(), None);
    drop(db);
    f.close().await;
}

#[tokio::test]
async fn sqlite_bearer_limits_and_dynamic_types_fail_closed_and_preserve_rows() {
    let f = Fixture::new().await;
    let db = f.db();
    for sql in [
        "UPDATE local_tokens SET principal_json='{}' WHERE token_kind='access'",
        "UPDATE local_tokens SET scopes_json='[1]' WHERE token_kind='access'",
        "UPDATE local_tokens SET principal_json=x'7b7d' WHERE token_kind='access'",
        "UPDATE local_tokens SET local_user_revision=x'31' WHERE token_kind='access'",
        "UPDATE local_users SET teams_json='null' WHERE username='alice'",
        "UPDATE local_users SET name=x'61' WHERE username='alice'",
        "UPDATE local_users SET enabled=2 WHERE username='alice'",
        "UPDATE local_users SET name=printf('%0513d',0) WHERE username='alice'",
    ] {
        db.execute_batch(sql).unwrap();
        let bad = f.verify(&f.access, &[]).await;
        assert!(
            matches!(
                bad,
                Err(Error::State(LocalBearerStateError::MalformedStored))
            ),
            "{sql}: {bad:?}"
        );
        assert_eq!(f.used(), None);
        db.execute("UPDATE local_tokens SET principal_json=?1,scopes_json='[\"project-api\"]',local_user_revision=1 WHERE token_kind='access'",[principal("alice-subject")]).unwrap();
        db.execute("UPDATE local_users SET teams_json='[]',name='current-name',enabled=1 WHERE username='alice'",[]).unwrap();
    }
    let json = principal("alice-subject");
    let cap = json.len();
    assert!(
        f.store
            .local_bearer_verifier("aud", n(cap))
            .unwrap()
            .verify(&f.access, &[], end())
            .await
            .is_ok()
    );
    assert!(matches!(
        f.store
            .local_bearer_verifier("aud", n(cap - 1))
            .unwrap()
            .verify(&f.access, &[], end())
            .await,
        Err(Error::State(LocalBearerStateError::ReadLimitExceeded))
    ));
    db.execute(
        "UPDATE local_users SET name=?1 WHERE username='alice'",
        ["😀".repeat(512)],
    )
    .unwrap();
    assert_eq!(
        f.verify(&f.access, &[])
            .await
            .unwrap()
            .current_local_user()
            .name()
            .chars()
            .count(),
        512
    );
    db.execute(
        "UPDATE local_tokens SET scopes_json=?1,last_used_at=NULL WHERE token_kind='access'",
        [json!(["x".repeat(9000)]).to_string()],
    )
    .unwrap();
    assert!(matches!(
        f.verify(&f.access, &[]).await,
        Err(Error::State(LocalBearerStateError::ReadLimitExceeded))
    ));
    assert_eq!(f.used(), None);
    db.execute(
        "UPDATE local_tokens SET scopes_json=\'[]\' WHERE token_kind=\'access\'",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE local_users SET teams_json=?1 WHERE username=\'alice\'",
        [json!(["x".repeat(9000)]).to_string()],
    )
    .unwrap();
    assert!(matches!(
        f.verify(&f.access, &[]).await,
        Err(Error::State(LocalBearerStateError::ReadLimitExceeded))
    ));
    assert!(matches!(
        f.store.local_bearer_verifier("aud", n(usize::MAX)),
        Err(Error::State(LocalBearerStateError::InvalidLimits))
    ));
    drop(db);
    f.close().await;
}

#[tokio::test]
async fn sqlite_bearer_deadline_expiry_cancellation_and_store_recovery_are_real() {
    let f = Fixture::new().await;
    let db = f.db();
    let view = f.store.local_bearer_verifier("aud", n(8192)).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let denied = view
        .verify(&f.access, &[], Instant::now() + Duration::from_millis(40))
        .await;
    assert!(
        matches!(denied, Err(Error::Control(ControlError::Deadline))),
        "{denied:?}"
    );
    db.execute_batch("COMMIT").unwrap();
    assert!(view.verify(&f.access, &[], end()).await.is_ok());
    db.execute(
        "UPDATE local_tokens SET expires_at=?1,last_used_at=NULL WHERE token_kind='access'",
        [now() + 60_000],
    )
    .unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut pending = Box::pin(view.verify(&f.access, &[], end()));
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    tokio::time::sleep(Duration::from_millis(100)).await;
    db.execute_batch("COMMIT").unwrap();
    unauth(pending.await);
    assert_eq!(f.used(), None);
    db.execute(
        "UPDATE local_tokens SET expires_at=?1 WHERE token_kind='access'",
        [now() + 60_000_000],
    )
    .unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut cancelled = Box::pin(view.verify(&f.access, &[], end()));
    assert!(futures_util::poll!(cancelled.as_mut()).is_pending());
    drop(cancelled);
    db.execute_batch("COMMIT").unwrap();
    assert!(view.verify(&f.access, &[], end()).await.is_ok());
    f.store.shutdown(end()).await.unwrap();
    assert!(matches!(
        view.verify(&f.access, &[], end()).await,
        Err(Error::Control(ControlError::Closed))
    ));
    drop(db);
    drop(f);
}
