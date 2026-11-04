use broker_control::{
    ControlError, FlowLimits, NewAdminSession, SessionClaimRoles, SessionLimits, SessionPrincipal,
    SessionProfile, SessionRevocation, SqliteControlConfig, SqliteControlStore,
};
use broker_security::{CredentialDigester, DigestLimits, TokenKind};
use broker_store::time::TimestampMicros;
use rusqlite::{Connection, TransactionBehavior, params, types::Value};
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;

const TOKEN_BYTES: usize = 256;

fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn limits() -> SessionLimits {
    SessionLimits {
        text_bytes: n(8192),
        csrf_bytes: n(512),
        team_bytes: n(512),
        role_bytes: n(512),
        max_teams: n(8),
        max_roles: n(8),
        teams_json_bytes: n(1024),
        roles_json_bytes: n(1024),
        max_lifetime: Duration::from_secs(3600),
    }
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(
            b"session-fixture-only-pepper-32-bytes"
                .to_vec()
                .into_boxed_slice(),
        ),
        DigestLimits::new(n(256), n(TOKEN_BYTES), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
fn hash(token: &str) -> String {
    digester()
        .token(TokenKind::AdminSession, token.as_bytes())
        .unwrap()
        .to_sql_hex()
}
fn input(label: &str, claims: Option<Vec<String>>, ttl: Duration) -> NewAdminSession {
    NewAdminSession::new(
        SessionProfile {
            subject: format!("subject-{label}"),
            name: label.into(),
            email: String::new(),
        },
        SessionPrincipal {
            issuer: format!("issuer-{label}"),
            username: label.into(),
            organization: String::new(),
            teams: vec![" beta ".into(), "alpha".into(), "alpha".into()],
            local_user_revision: 42,
        },
        Zeroizing::new(format!("csrf-{label}")),
        claims.map(|roles| SessionClaimRoles {
            selector: " selector ".into(),
            roles,
        }),
        SystemTime::now() + ttl,
        &limits(),
    )
    .unwrap()
}
fn normal(label: &str) -> NewAdminSession {
    input(
        label,
        Some(vec![" unknown ".into(), "Admin".into(), "Admin".into()]),
        Duration::from_secs(60),
    )
}
struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    store: Arc<SqliteControlStore>,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private").join("broker.db");
        let store = Arc::new(open(&path, Duration::from_secs(5)).await);
        Self {
            _temp: temp,
            path,
            store,
        }
    }
    fn db(&self) -> Connection {
        let db = Connection::open(&self.path).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        db
    }
}
async fn open(path: &Path, operation: Duration) -> SqliteControlStore {
    let config = SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(5),
        operation,
        Duration::from_secs(5),
        FlowLimits {
            provider_bytes: n(128),
            request_bytes: n(256),
            continuation_bytes: n(1024),
        },
    )
    .unwrap();
    SqliteControlStore::open(config, digester(), end())
        .await
        .unwrap()
}
fn counts(db: &Connection) -> (i64, i64, i64) {
    db.query_row("SELECT (SELECT count(*) FROM admin_sessions),(SELECT count(*) FROM admin_session_principals),(SELECT count(*) FROM admin_session_claim_roles)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
}
fn snapshot(db: &Connection) -> (String, String, String) {
    db.query_row("SELECT (SELECT json_group_array(json_array(quote(token_hash),quote(subject),quote(name),quote(email),quote(csrf_token),quote(expires_at),quote(created_at))) FROM (SELECT * FROM admin_sessions ORDER BY token_hash)),(SELECT json_group_array(json_array(quote(token_hash),quote(issuer),quote(username),quote(organization),quote(teams_json),quote(local_user_revision))) FROM (SELECT * FROM admin_session_principals ORDER BY token_hash)),(SELECT json_group_array(json_array(quote(token_hash),quote(claim_selector),quote(roles_json))) FROM (SELECT * FROM admin_session_claim_roles ORDER BY token_hash))",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
}
fn micros() -> i64 {
    TimestampMicros::try_from(SystemTime::now())
        .unwrap()
        .as_i64()
}

#[tokio::test]
async fn roundtrip_three_tables_hmac_claims_and_duplicate_preserve_metadata() {
    let f = Fixture::new().await;
    let db = f.db();
    let view = f.store.admin_sessions(limits()).unwrap();
    view.create_session("private-session-token", &normal("federated"), end())
        .await
        .unwrap();
    assert_eq!(counts(&db), (1, 1, 1));
    let before = snapshot(&db);
    assert!(before.0.contains(&hash("private-session-token")));
    assert!(!before.0.contains("private-session-token"));
    assert_ne!(
        hash("private-session-token"),
        digester()
            .token(TokenKind::OidcFlowState, b"private-session-token")
            .unwrap()
            .to_sql_hex()
    );
    let session = view.session("private-session-token", end()).await.unwrap();
    assert_eq!(session.profile().subject, "subject-federated");
    assert_eq!(session.profile().name, "federated");
    assert_eq!(session.principal().issuer, "issuer-federated");
    assert_eq!(session.principal().teams, ["alpha", "beta"]);
    assert_eq!(session.principal().local_user_revision, 42);
    assert_eq!(session.csrf_token(), "csrf-federated");
    assert_eq!(session.claimed_roles().unwrap().roles, ["Admin", "unknown"]);
    assert_eq!(session.claimed_roles().unwrap().selector, " selector ");
    assert!(session.created_at().as_i64() > 0);
    assert!(session.expires_at() > session.created_at());
    assert_eq!(snapshot(&db), before);
    for rendered in [
        format!("{session:?}"),
        format!("{view:?}"),
        format!("{:?}", normal("federated")),
    ] {
        for secret in [
            "private-session-token",
            "csrf-federated",
            "subject-federated",
            "issuer-federated",
        ] {
            assert!(!rendered.contains(secret));
        }
    }
    assert_eq!(
        view.create_session("private-session-token", &normal("replacement"), end())
            .await,
        Err(ControlError::SessionExists)
    );
    assert_eq!(snapshot(&db), before);
    view.create_session(
        "local",
        &input("local", None, Duration::from_secs(60)),
        end(),
    )
    .await
    .unwrap();
    view.create_session(
        "empty-claims",
        &input("empty", Some(Vec::new()), Duration::from_secs(60)),
        end(),
    )
    .await
    .unwrap();
    assert!(
        view.session("local", end())
            .await
            .unwrap()
            .claimed_roles()
            .is_none()
    );
    let empty = view.session("empty-claims", end()).await.unwrap();
    assert!(empty.claimed_roles().unwrap().roles.is_empty());
    assert_eq!(empty.claimed_roles().unwrap().selector, " selector ");
    assert_eq!(counts(&db), (3, 3, 2));
}

#[tokio::test]
async fn strict_view_limits_and_invalid_tokens_have_no_sql_effects() {
    let f = Fixture::new().await;
    let db = f.db();
    let value = normal("wide");
    let before = snapshot(&db);
    for field in [
        "text",
        "csrf",
        "team",
        "role",
        "team-count",
        "role-count",
        "teams-json",
        "roles-json",
        "lifetime",
    ] {
        let mut restricted = limits();
        match field {
            "text" => restricted.text_bytes = n(1),
            "csrf" => restricted.csrf_bytes = n(1),
            "team" => restricted.team_bytes = n(1),
            "role" => restricted.role_bytes = n(1),
            "team-count" => restricted.max_teams = n(1),
            "role-count" => restricted.max_roles = n(1),
            "teams-json" => restricted.teams_json_bytes = n(2),
            "roles-json" => restricted.roles_json_bytes = n(2),
            _ => restricted.max_lifetime = Duration::from_secs(1),
        }
        assert_eq!(
            f.store
                .admin_sessions(restricted)
                .unwrap()
                .create_session("strict", &value, end())
                .await,
            Err(ControlError::InvalidSession),
            "{field}"
        );
        assert_eq!(snapshot(&db), before);
    }
    let view = f.store.admin_sessions(limits()).unwrap();
    for token in [String::new(), "x".repeat(TOKEN_BYTES + 1)] {
        assert_eq!(
            view.create_session(&token, &value, end()).await,
            Err(ControlError::InvalidSession)
        );
        assert!(matches!(
            view.session(&token, end()).await,
            Err(ControlError::InvalidSession)
        ));
        assert_eq!(
            view.revoke_session(&token, end()).await,
            Err(ControlError::InvalidSession)
        );
    }
    let mut invalid = limits();
    invalid.text_bytes = NonZeroUsize::MAX;
    assert!(matches!(
        f.store.admin_sessions(invalid),
        Err(ControlError::Configuration)
    ));
    invalid = limits();
    invalid.max_lifetime = Duration::ZERO;
    assert!(matches!(
        f.store.admin_sessions(invalid),
        Err(ControlError::Configuration)
    ));
    let unicode = NewAdminSession::new(
        SessionProfile {
            subject: "unicode".into(),
            name: "é".repeat(512),
            email: String::new(),
        },
        SessionPrincipal {
            issuer: "issuer".into(),
            username: String::new(),
            organization: String::new(),
            teams: Vec::new(),
            local_user_revision: 0,
        },
        Zeroizing::new("csrf".into()),
        None,
        SystemTime::now() + Duration::from_secs(60),
        &limits(),
    )
    .unwrap();
    view.create_session("unicode", &unicode, end())
        .await
        .unwrap();
    assert_eq!(
        view.session("unicode", end()).await.unwrap().profile().name,
        "é".repeat(512)
    );
    let mut byte_cap = limits();
    byte_cap.text_bytes = n(512);
    assert!(matches!(
        f.store
            .admin_sessions(byte_cap)
            .unwrap()
            .session("unicode", end())
            .await,
        Err(ControlError::CorruptSession)
    ));
    assert_eq!(counts(&db), (1, 1, 0));
}

#[tokio::test]
async fn corrupt_types_caps_json_children_and_times_never_repair_or_cleanup() {
    let f = Fixture::new().await;
    let db = f.db();
    let view = f.store.admin_sessions(limits()).unwrap();
    view.create_session("corrupt", &normal("corrupt"), end())
        .await
        .unwrap();
    let digest = hash("corrupt");
    db.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    let mut cases: Vec<(&str, &str, Value)> = vec![
        ("admin_sessions", "subject", Value::Blob(vec![0, 1])),
        ("admin_sessions", "name", Value::Text("x".repeat(8193))),
        ("admin_sessions", "email", Value::Text("x".repeat(513))),
        ("admin_sessions", "csrf_token", Value::Text("x".repeat(513))),
        ("admin_session_principals", "issuer", Value::Blob(vec![1])),
        (
            "admin_session_principals",
            "username",
            Value::Text("x".repeat(8193)),
        ),
        (
            "admin_session_principals",
            "organization",
            Value::Blob(vec![1]),
        ),
        (
            "admin_session_principals",
            "local_user_revision",
            Value::Integer(-1),
        ),
        (
            "admin_session_principals",
            "local_user_revision",
            Value::Text("wrong-type".into()),
        ),
        (
            "admin_session_claim_roles",
            "claim_selector",
            Value::Text(String::new()),
        ),
        (
            "admin_session_claim_roles",
            "claim_selector",
            Value::Text("x".repeat(8193)),
        ),
        (
            "admin_session_claim_roles",
            "roles_json",
            Value::Blob(vec![1]),
        ),
        ("admin_sessions", "created_at", Value::Integer(-1)),
        ("admin_sessions", "created_at", Value::Real(1.25)),
        ("admin_sessions", "expires_at", Value::Integer(0)),
        (
            "admin_sessions",
            "expires_at",
            Value::Integer(micros() + 7_200_000_000),
        ),
    ];
    for bad in [
        "null",
        "{}",
        "[null]",
        "[1]",
        "[\"a\"] trailing",
        "[\" b \",\"a\"]",
        "[\"a\",\"a\"]",
        "[\"a\\u0000\"]",
    ] {
        cases.push((
            "admin_session_principals",
            "teams_json",
            Value::Text(bad.into()),
        ));
        cases.push((
            "admin_session_claim_roles",
            "roles_json",
            Value::Text(bad.into()),
        ));
    }
    cases.push((
        "admin_session_principals",
        "teams_json",
        Value::Text(format!("[\"{}\"]", "x".repeat(1024))),
    ));
    cases.push((
        "admin_session_claim_roles",
        "roles_json",
        Value::Text(format!("[\"{}\"]", "x".repeat(1024))),
    ));
    for (table, column, bad) in cases {
        let original: Value = db
            .query_row(
                &format!("SELECT {column} FROM {table} WHERE token_hash=?1"),
                [&digest],
                |r| r.get(0),
            )
            .unwrap();
        let update = format!("UPDATE {table} SET {column}=?1 WHERE token_hash=?2");
        db.execute(&update, params![bad, digest]).unwrap();
        let before = snapshot(&db);
        assert!(
            matches!(
                view.session("corrupt", end()).await,
                Err(ControlError::CorruptSession)
            ),
            "{table}.{column}"
        );
        assert_eq!(
            snapshot(&db),
            before,
            "corruption must not mutate {table}.{column}"
        );
        db.execute(&update, params![original, digest]).unwrap();
    }
    let future = micros() + 60_000_000;
    let original_times: (i64, i64) = db
        .query_row(
            "SELECT created_at,expires_at FROM admin_sessions WHERE token_hash=?1",
            [&digest],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    db.execute(
        "UPDATE admin_sessions SET created_at=?1,expires_at=?2 WHERE token_hash=?3",
        params![future, future + 60_000_000, digest],
    )
    .unwrap();
    let before = snapshot(&db);
    assert!(matches!(
        view.session("corrupt", end()).await,
        Err(ControlError::CorruptSession)
    ));
    assert_eq!(snapshot(&db), before);
    db.execute(
        "UPDATE admin_sessions SET created_at=?1,expires_at=?2 WHERE token_hash=?3",
        params![original_times.0, original_times.1, digest],
    )
    .unwrap();
    db.execute(
        "DELETE FROM admin_session_principals WHERE token_hash=?1",
        [&digest],
    )
    .unwrap();
    let before = snapshot(&db);
    assert!(matches!(
        view.session("corrupt", end()).await,
        Err(ControlError::CorruptSession)
    ));
    assert_eq!(snapshot(&db), before);
    assert_eq!(
        view.revoke_session("corrupt", end()).await.unwrap(),
        SessionRevocation::Revoked
    );
    assert_eq!(counts(&db), (0, 0, 0));
    view.create_session("missing-claims", &normal("missing"), end())
        .await
        .unwrap();
    db.execute(
        "DELETE FROM admin_session_claim_roles WHERE token_hash=?1",
        [hash("missing-claims")],
    )
    .unwrap();
    assert!(
        view.session("missing-claims", end())
            .await
            .unwrap()
            .claimed_roles()
            .is_none()
    );
}

#[tokio::test]
async fn corruption_precedes_expiry_and_confirmed_cleanup_and_revoke_cascade_only_match() {
    let f = Fixture::new().await;
    let db = f.db();
    let view = f.store.admin_sessions(limits()).unwrap();
    for token in ["expired", "foreign", "corrupt-revoke"] {
        view.create_session(token, &normal(token), end())
            .await
            .unwrap();
    }
    let at = micros();
    db.execute(
        "UPDATE admin_sessions SET created_at=?1,expires_at=?2,name=?3 WHERE token_hash=?4",
        params![at - 10_000_000, at - 1, vec![1u8], hash("expired")],
    )
    .unwrap();
    let before = snapshot(&db);
    assert!(matches!(
        view.session("expired", end()).await,
        Err(ControlError::CorruptSession)
    ));
    assert_eq!(snapshot(&db), before);
    db.execute(
        "UPDATE admin_sessions SET name='expired' WHERE token_hash=?1",
        [hash("expired")],
    )
    .unwrap();
    assert!(matches!(
        view.session("expired", end()).await,
        Err(ControlError::SessionExpired)
    ));
    assert!(matches!(
        view.session("expired", end()).await,
        Err(ControlError::SessionUnavailable)
    ));
    assert_eq!(counts(&db), (2, 2, 2));
    db.execute(
        "UPDATE admin_session_principals SET teams_json='broken' WHERE token_hash=?1",
        [hash("corrupt-revoke")],
    )
    .unwrap();
    assert_eq!(
        view.revoke_session("corrupt-revoke", end()).await.unwrap(),
        SessionRevocation::Revoked
    );
    assert_eq!(
        view.revoke_session("corrupt-revoke", end()).await.unwrap(),
        SessionRevocation::Absent
    );
    assert_eq!(
        view.session("foreign", end())
            .await
            .unwrap()
            .profile()
            .subject,
        "subject-foreign"
    );
    assert_eq!(counts(&db), (1, 1, 1));
    assert_eq!(
        view.revoke_session("foreign", end()).await.unwrap(),
        SessionRevocation::Revoked
    );
    assert_eq!(counts(&db), (0, 0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_owners_create_and_read_revoke_observe_whole_committed_sessions() {
    let f = Fixture::new().await;
    let second = Arc::new(open(&f.path, Duration::from_secs(5)).await);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let first = tokio::spawn({
        let store = f.store.clone();
        let barrier = barrier.clone();
        async move {
            let value = normal("left");
            barrier.wait().await;
            store
                .admin_sessions(limits())
                .unwrap()
                .create_session("race", &value, end())
                .await
        }
    });
    let other = tokio::spawn({
        let store = second.clone();
        async move {
            let value = normal("right");
            barrier.wait().await;
            store
                .admin_sessions(limits())
                .unwrap()
                .create_session("race", &value, end())
                .await
        }
    });
    let a = first.await.unwrap();
    let b = other.await.unwrap();
    assert!(matches!(
        (a, b),
        (Ok(()), Err(ControlError::SessionExists)) | (Err(ControlError::SessionExists), Ok(()))
    ));
    let view = f.store.admin_sessions(limits()).unwrap();
    let session = view.session("race", end()).await.unwrap();
    let label = &session.principal().username;
    assert!(["left", "right"].contains(&label.as_str()));
    assert_eq!(session.profile().name, *label);
    assert_eq!(session.profile().subject, format!("subject-{label}"));
    assert_eq!(session.csrf_token(), format!("csrf-{label}"));
    assert_eq!(counts(&f.db()), (1, 1, 1));
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let read = tokio::spawn({
        let store = f.store.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store
                .admin_sessions(limits())
                .unwrap()
                .session("race", end())
                .await
        }
    });
    let revoke = tokio::spawn(async move {
        barrier.wait().await;
        second
            .admin_sessions(limits())
            .unwrap()
            .revoke_session("race", end())
            .await
    });
    match read.await.unwrap() {
        Ok(session) => assert_eq!(session.principal().teams, ["alpha", "beta"]),
        Err(error) => assert_eq!(error, ControlError::SessionUnavailable),
    }
    assert_eq!(revoke.await.unwrap().unwrap(), SessionRevocation::Revoked);
    assert_eq!(counts(&f.db()), (0, 0, 0));
}

async fn poll_pending(future: std::pin::Pin<&mut impl std::future::Future>) {
    let mut future = future;
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
}
async fn cancel_pending(future: impl std::future::Future) {
    let mut future = std::pin::pin!(future);
    poll_pending(future.as_mut()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_expiry_is_checked_after_writer_lock_without_renewal() {
    let f = Fixture::new().await;
    let mut db = f.db();
    let view = f.store.admin_sessions(limits()).unwrap();
    let value = input("short", Some(Vec::new()), Duration::from_secs(2));
    let expiry = value.expires_at();
    view.create_session("short", &value, end()).await.unwrap();
    view.create_session("foreign", &normal("foreign"), end())
        .await
        .unwrap();
    let writer = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(SystemTime::now() < expiry);
    let mut read = std::pin::pin!(view.session("short", end()));
    poll_pending(read.as_mut()).await;
    tokio::time::sleep(
        expiry.duration_since(SystemTime::now()).unwrap_or_default() + Duration::from_millis(1),
    )
    .await;
    writer.rollback().unwrap();
    assert!(matches!(read.await, Err(ControlError::SessionExpired)));
    assert_eq!(counts(&db), (1, 1, 1));
    let writer = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let value = input("too-late", None, Duration::from_millis(100));
    let expiry = value.expires_at();
    let mut create = std::pin::pin!(view.create_session("too-late", &value, end()));
    poll_pending(create.as_mut()).await;
    tokio::time::sleep(
        expiry.duration_since(SystemTime::now()).unwrap_or_default() + Duration::from_millis(1),
    )
    .await;
    writer.rollback().unwrap();
    assert_eq!(create.await, Err(ControlError::InvalidSession));
    assert_eq!(counts(&db), (1, 1, 1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_writer_deadline_caller_drop_close_and_recovery_preserve_three_tables() {
    let f = Fixture::new().await;
    let mut db = f.db();
    let view = f.store.admin_sessions(limits()).unwrap();
    view.create_session("existing", &normal("existing"), end())
        .await
        .unwrap();
    let before = snapshot(&db);
    for operation in ["create", "read", "revoke"] {
        let writer = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let deadline = Instant::now() + Duration::from_millis(30);
        match operation {
            "create" => assert_eq!(
                view.create_session("pending", &normal("pending"), deadline)
                    .await,
                Err(ControlError::Deadline)
            ),
            "read" => assert!(matches!(
                view.session("existing", deadline).await,
                Err(ControlError::Deadline)
            )),
            _ => assert_eq!(
                view.revoke_session("existing", deadline).await,
                Err(ControlError::Deadline)
            ),
        }
        writer.rollback().unwrap();
        view.session("existing", end()).await.unwrap();
        assert_eq!(snapshot(&db), before);
        let writer = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        match operation {
            "create" => {
                let value = normal("pending");
                cancel_pending(view.create_session("pending", &value, end())).await;
            }
            "read" => cancel_pending(view.session("existing", end())).await,
            _ => cancel_pending(view.revoke_session("existing", end())).await,
        }
        writer.rollback().unwrap();
        view.session("existing", end()).await.unwrap();
        assert_eq!(snapshot(&db), before);
    }
    let short = open(&f.path, Duration::from_millis(40)).await;
    let short_view = short.admin_sessions(limits()).unwrap();
    let writer = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(matches!(
        short_view.session("existing", end()).await,
        Err(ControlError::Deadline)
    ));
    writer.rollback().unwrap();
    // The caller can time out while SQLite still owns the interrupted transaction.
    // Drain that worker before checking recovery under the normal operation budget.
    short.shutdown(end()).await.unwrap();
    view.session("existing", end()).await.unwrap();
    assert_eq!(snapshot(&db), before);
    let writer = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let mut pending = std::pin::pin!(view.revoke_session("existing", end()));
    poll_pending(pending.as_mut()).await;
    let close = f.store.shutdown(end());
    writer.rollback().unwrap();
    let (closed, pending) = tokio::join!(close, pending);
    closed.unwrap();
    assert_eq!(pending, Err(ControlError::Closed));
    assert_eq!(snapshot(&db), before);
    assert_eq!(
        view.create_session("closed", &normal("closed"), end())
            .await,
        Err(ControlError::Closed)
    );
    assert!(matches!(
        view.session("existing", end()).await,
        Err(ControlError::Closed)
    ));
    assert_eq!(
        view.revoke_session("existing", end()).await,
        Err(ControlError::Closed)
    );
}
