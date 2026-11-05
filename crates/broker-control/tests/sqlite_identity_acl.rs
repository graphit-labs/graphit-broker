use broker_control::{
    ControlError, FlowLimits, IdentityReadLimits, LocalIdentityKind, LocalIdentityRead,
    LocalIdentityReference, LocalIdentityUnavailable, ResourceGrantReadError, SqliteControlConfig,
    SqliteControlStore, SystemAction, SystemPermission,
};
use broker_security::{CredentialDigester, DigestLimits};
use broker_store::{seeds::BuiltinRole, time::TimestampMicros};
use rusqlite::{Connection, TransactionBehavior, params};
use std::{
    num::NonZeroUsize,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn limits() -> IdentityReadLimits {
    IdentityReadLimits {
        username_bytes: n(128),
        subject_bytes: n(512),
        role_bytes: n(128),
        roles: n(16),
        rows: n(128),
    }
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
        let store = Arc::new(open(&path).await);
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
async fn open(path: &std::path::Path) -> SqliteControlStore {
    let flows = FlowLimits {
        provider_bytes: n(128),
        request_bytes: n(256),
        continuation_bytes: n(1024),
    };
    let config = SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        flows,
    )
    .unwrap();
    let digester = CredentialDigester::new(
        Zeroizing::new(
            b"identity-acl-fixture-pepper-32-bytes"
                .to_vec()
                .into_boxed_slice(),
        ),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap();
    SqliteControlStore::open(config, digester, deadline())
        .await
        .unwrap()
}
fn user(db: &Connection, username: &str, subject: &str, kind: &str) {
    db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES(?1,?2,?3,'not-selected-phc','fixture','fixture','fixture','not-selected-json',1,0,1,0,0)", params![username,subject,kind]).unwrap();
}
async fn read(
    store: &SqliteControlStore,
    username: &str,
    subject: &str,
    revision: i64,
) -> Result<LocalIdentityRead, ControlError> {
    let reference = LocalIdentityReference::new(username, subject, revision, &limits()).unwrap();
    store
        .local_identities(limits())
        .unwrap()
        .read(&reference, deadline())
        .await
}
fn unavailable(read: LocalIdentityRead, expected: LocalIdentityUnavailable) {
    match read {
        LocalIdentityRead::Unavailable(actual) => assert_eq!(actual, expected),
        other => panic!("unexpected identity state {other:?}"),
    }
}
fn permissions(read: LocalIdentityRead) -> Vec<String> {
    match read {
        LocalIdentityRead::Current(value) => value
            .permissions()
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect(),
        other => panic!("unexpected identity state {other:?}"),
    }
}
#[tokio::test]
async fn current_identity_has_current_roles_finite_unavailability_and_shared_limits() {
    let f = Fixture::new().await;
    let db = f.db();
    user(&db, "alice", "alice-subject", "human");
    user(&db, "robot", "robot-subject", "service");
    let LocalIdentityRead::Current(value) =
        read(&f.store, "alice", "alice-subject", 1).await.unwrap()
    else {
        panic!("current human")
    };
    assert_eq!(value.kind(), LocalIdentityKind::Human);
    assert_eq!(value.roles(), ["user"]);
    assert_eq!(
        value
            .permissions()
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>(),
        ["projects.read", "session.read"]
    );
    let LocalIdentityRead::Current(robot) =
        read(&f.store, "robot", "robot-subject", 1).await.unwrap()
    else {
        panic!("current service")
    };
    assert_eq!(robot.kind(), LocalIdentityKind::Service);
    unavailable(
        read(&f.store, "missing", "subject", 1).await.unwrap(),
        LocalIdentityUnavailable::Missing,
    );
    unavailable(
        read(&f.store, "alice", "changed", 1).await.unwrap(),
        LocalIdentityUnavailable::SubjectChanged,
    );
    unavailable(
        read(&f.store, "alice", "alice-subject", 2).await.unwrap(),
        LocalIdentityUnavailable::RevisionChanged,
    );
    db.execute(
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
        [],
    )
    .unwrap();
    unavailable(
        read(&f.store, "alice", "alice-subject", 1).await.unwrap(),
        LocalIdentityUnavailable::Disabled,
    );
    db.execute(
        "UPDATE local_users SET enabled=1 WHERE username='alice'",
        [],
    )
    .unwrap();
    f.store
        .set_role("custom", &[SystemPermission::All], deadline())
        .await
        .unwrap();
    db.execute("INSERT INTO role_assignments(subject,role,created_at) VALUES('local|alice-subject','custom',0)",[]).unwrap();
    let LocalIdentityRead::Current(current) =
        read(&f.store, "alice", "alice-subject", 1).await.unwrap()
    else {
        panic!("current assigned")
    };
    assert_eq!(current.roles(), ["custom", "user"]);
    assert!(current.allows(SystemAction::UsersWrite));
    let reference = LocalIdentityReference::new("alice", "alice-subject", 1, &limits()).unwrap();
    for field in ["rows", "roles"] {
        let mut small = limits();
        if field == "rows" {
            small.rows = n(1)
        } else {
            small.roles = n(1)
        };
        assert_eq!(
            f.store
                .local_identities(small)
                .unwrap()
                .read(&reference, deadline())
                .await
                .unwrap_err(),
            ControlError::IdentityLimitExceeded
        );
    }
    let mut small = limits();
    small.role_bytes = n(4);
    assert_eq!(
        f.store
            .local_identities(small)
            .unwrap()
            .read(&reference, deadline())
            .await
            .unwrap_err(),
        ControlError::CorruptRbac
    );
    let mut small = limits();
    small.subject_bytes = n(5);
    assert_eq!(
        f.store
            .local_identities(small)
            .unwrap()
            .read(&reference, deadline())
            .await
            .unwrap_err(),
        ControlError::InvalidIdentity
    );
    let mut invalid = limits();
    invalid.rows = NonZeroUsize::MAX;
    assert_eq!(
        f.store.local_identities(invalid).unwrap_err(),
        ControlError::Configuration
    );
    db.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    for statement in [
        "UPDATE local_users SET enabled=2 WHERE username='alice'",
        "UPDATE local_users SET identity_kind='other' WHERE username='alice'",
        "UPDATE local_users SET revision=0 WHERE username='alice'",
        "UPDATE local_users SET subject=' untrimmed' WHERE username='alice'",
    ] {
        db.execute(statement, []).unwrap();
        assert_eq!(
            read(&f.store, "alice", "alice-subject", 1)
                .await
                .unwrap_err(),
            ControlError::CorruptIdentity
        );
        db.execute("UPDATE local_users SET enabled=1,identity_kind='human',revision=1,subject='alice-subject' WHERE username='alice'",[]).unwrap();
    }
    db.execute(
        "UPDATE local_users SET subject=?1 WHERE username='alice'",
        ["s".repeat(513)],
    )
    .unwrap();
    assert_eq!(
        read(&f.store, "alice", "alice-subject", 1)
            .await
            .unwrap_err(),
        ControlError::CorruptIdentity
    );
    db.execute(
        "UPDATE local_users SET subject='alice-subject' WHERE username='alice'",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO role_permissions(role,action) VALUES('custom','invalid.action')",
        [],
    )
    .unwrap();
    assert_eq!(
        read(&f.store, "alice", "alice-subject", 1)
            .await
            .unwrap_err(),
        ControlError::CorruptRbac
    );
    db.execute(
        "DELETE FROM role_permissions WHERE role='custom' AND action='invalid.action'",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO role_permissions(role,action) VALUES('custom',?1)",
        ["x".repeat(129)],
    )
    .unwrap();
    assert_eq!(
        read(&f.store, "alice", "alice-subject", 1)
            .await
            .unwrap_err(),
        ControlError::CorruptRbac
    );
    let excluded: (String, String) = db
        .query_row(
            "SELECT password_hash,teams_json FROM local_users WHERE username='alice'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        excluded,
        ("not-selected-phc".into(), "not-selected-json".into())
    );
    assert_eq!(
        format!("{:?}", f.store.local_identities(limits()).unwrap()),
        "SqliteLocalIdentities([REDACTED])"
    );
}
fn role_rows(db: &Connection, name: &str) -> Vec<String> {
    db.prepare("SELECT action FROM role_permissions WHERE role=?1 ORDER BY action COLLATE BINARY")
        .unwrap()
        .query_map([name], |r| r.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn role_replacement_preserves_builtins_creation_and_atomic_independent_writers() {
    let f = Fixture::new().await;
    let second = Arc::new(open(&f.path).await);
    let db = f.db();
    for name in ["", "_invalid", "é", "a/b", &"x".repeat(129)] {
        assert_eq!(
            f.store
                .set_role(name, &[SystemPermission::All], deadline())
                .await,
            Err(ControlError::InvalidRole)
        );
    }
    assert_eq!(
        f.store.set_role("custom", &[], deadline()).await,
        Err(ControlError::InvalidRole)
    );
    f.store
        .set_role(
            " Mixed.Case ",
            &[
                SystemPermission::All,
                SystemPermission::Action(SystemAction::UsersWrite),
                SystemPermission::All,
            ],
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(role_rows(&db, "Mixed.Case"), ["*", "users.write"]);
    assert!(role_rows(&db, "mixed.case").is_empty());
    for role in BuiltinRole::ALL {
        let created: i64 = db
            .query_row(
                "SELECT created_at FROM roles WHERE name=?1",
                [role.name()],
                |r| r.get(0),
            )
            .unwrap();
        f.store
            .set_role(role.name(), &[], deadline())
            .await
            .unwrap();
        let mut expected = role
            .actions()
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>();
        expected.sort_unstable();
        assert_eq!(role_rows(&db, role.name()), expected);
        f.store
            .set_role(role.name(), &[SystemPermission::All], deadline())
            .await
            .unwrap();
        assert_eq!(role_rows(&db, role.name()), expected);
        assert_eq!(
            db.query_row::<i64, _, _>(
                "SELECT created_at FROM roles WHERE name=?1",
                [role.name()],
                |r| r.get(0)
            )
            .unwrap(),
            created
        );
    }
    f.store
        .set_role("concurrent", &[SystemPermission::All], deadline())
        .await
        .unwrap();
    user(&db, "alice", "alice-subject", "human");
    db.execute("INSERT INTO role_assignments(subject,role,created_at) VALUES('local|alice-subject','concurrent',0)",[]).unwrap();
    let before: i64 = db
        .query_row(
            "SELECT created_at FROM roles WHERE name='concurrent'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let first = f.store.clone();
    let other = second.clone();
    let reader = f.store.clone();
    let a = async move {
        for _ in 0..12 {
            first
                .set_role("concurrent", &[SystemPermission::All], deadline())
                .await
                .unwrap();
        }
    };
    let b = async move {
        for _ in 0..12 {
            other
                .set_role(
                    "concurrent",
                    &[SystemPermission::Action(SystemAction::UsersWrite)],
                    deadline(),
                )
                .await
                .unwrap();
        }
    };
    let c = async move {
        for _ in 0..24 {
            let values = permissions(read(&reader, "alice", "alice-subject", 1).await.unwrap());
            assert!(
                values == ["*", "projects.read", "session.read"]
                    || values == ["projects.read", "session.read", "users.write"],
                "partial role bundle"
            );
        }
    };
    tokio::join!(a, b, c);
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT created_at FROM roles WHERE name='concurrent'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        before
    );
    assert_eq!(db.query_row::<i64,_,_>("SELECT COUNT(*) FROM role_assignments WHERE subject='local|alice-subject' AND role='concurrent'",[],|r|r.get(0)).unwrap(),1);
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT revision FROM local_users WHERE username='alice'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
}
fn acl(db: &mut Connection, marker: &str, revision: i64) {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    for table in [
        "grant_capabilities",
        "grant_projects",
        "grant_s3_operations",
        "grant_s3_prefixes",
    ] {
        tx.execute(&format!("DELETE FROM {table}"), []).unwrap();
    }
    tx.execute("DELETE FROM resource_grants", []).unwrap();
    tx.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES(?1,?1,' raw kind ',' team* ','',?2,?2)",params![marker,revision]).unwrap();
    for (table, values) in [
        ("grant_capabilities", vec![" a,b ", "presence:read"]),
        ("grant_projects", vec!["project-*", "é"]),
        ("grant_s3_operations", vec!["GetObject", "PutObject"]),
        ("grant_s3_prefixes", vec![marker, "v2/{project}"]),
    ] {
        for value in values {
            tx.execute(
                &format!("INSERT INTO {table}(grant_id,value) VALUES(?1,?2)"),
                params![marker, value],
            )
            .unwrap();
        }
    }
    tx.execute(
        "UPDATE resource_acl_state SET revision=?1,updated_at=?1 WHERE id=1",
        [revision],
    )
    .unwrap();
    tx.commit().unwrap();
}
#[tokio::test]
async fn acl_snapshot_preserves_raw_arrays_closed_decoder_and_sql_byte_ceiling() {
    let f = Fixture::new().await;
    let mut db = f.db();
    assert!(
        f.store
            .resource_grants(n(2))
            .unwrap()
            .read(deadline())
            .await
            .unwrap()
            .rules()
            .is_empty()
    );
    assert_eq!(
        f.store
            .resource_grants(n(1))
            .unwrap()
            .read(deadline())
            .await
            .unwrap_err(),
        ResourceGrantReadError::ReadLimitExceeded
    );
    assert_eq!(
        f.store.resource_grants(NonZeroUsize::MAX).unwrap_err(),
        ResourceGrantReadError::InvalidLimits
    );
    acl(&mut db, "z", 10);
    let view = f.store.resource_grants(n(8192)).unwrap();
    let snapshot = view.read(deadline()).await.unwrap();
    assert_eq!(snapshot.revision(), 10);
    let rule = &snapshot.rules()[0];
    assert_eq!(rule.access_kind(), " raw kind ");
    assert_eq!(rule.principal(), " team* ");
    assert_eq!(rule.s3_route(), "");
    assert_eq!(rule.capabilities(), [" a,b ", "presence:read"]);
    assert_eq!(rule.projects(), ["project-*", "é"]);
    assert_eq!(rule.s3_operations(), ["GetObject", "PutObject"]);
    assert_eq!(rule.s3_prefixes(), ["v2/{project}", "z"]);
    assert_eq!(
        f.store
            .resource_grants(n(8))
            .unwrap()
            .read(deadline())
            .await
            .unwrap_err(),
        ResourceGrantReadError::ReadLimitExceeded
    );
    db.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    for sql in [
        "UPDATE resource_acl_state SET revision=0",
        "UPDATE resource_acl_state SET updated_at=-1",
    ] {
        db.execute(sql, []).unwrap();
        assert_eq!(
            view.read(deadline()).await.unwrap_err(),
            ResourceGrantReadError::MalformedStored
        );
        db.execute(
            "UPDATE resource_acl_state SET revision=10,updated_at=10",
            [],
        )
        .unwrap();
    }
    db.execute("UPDATE resource_grants SET name=?1", [vec![0xffu8]])
        .unwrap();
    assert_eq!(
        view.read(deadline()).await.unwrap_err(),
        ResourceGrantReadError::MalformedStored
    );
    db.execute("UPDATE resource_grants SET name='z'", [])
        .unwrap();
    db.execute("UPDATE resource_grants SET created_at=-1", [])
        .unwrap();
    assert_eq!(
        view.read(deadline()).await.unwrap_err(),
        ResourceGrantReadError::MalformedStored
    );
    db.execute("UPDATE resource_grants SET created_at=10", [])
        .unwrap();
    db.execute(
        "INSERT INTO grant_capabilities(grant_id,value) VALUES('z',?1)",
        [vec![0xffu8]],
    )
    .unwrap();
    assert_eq!(
        view.read(deadline()).await.unwrap_err(),
        ResourceGrantReadError::MalformedStored
    );
    db.execute(
        "DELETE FROM grant_capabilities WHERE typeof(value)='blob'",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('é','unicode','literal','raw','',0,0)",[]).unwrap();
    let snapshot = view.read(deadline()).await.unwrap();
    assert_eq!(
        snapshot.rules().iter().map(|r| r.id()).collect::<Vec<_>>(),
        ["z", "é"]
    );
    db.execute("DELETE FROM resource_acl_state", []).unwrap();
    assert_eq!(
        view.read(deadline()).await.unwrap_err(),
        ResourceGrantReadError::MalformedStored
    );
    assert_eq!(format!("{view:?}"), "SqliteResourceGrants([REDACTED])");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acl_snapshot_is_whole_old_or_new_under_atomic_sql_writer() {
    let f = Fixture::new().await;
    let mut db = f.db();
    acl(&mut db, "old", 10);
    let path = f.path.clone();
    let start = Arc::new(std::sync::Barrier::new(2));
    let ready = start.clone();
    let writer = std::thread::spawn(move || {
        let mut db = Connection::open(path).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        ready.wait();
        for revision in 11..35 {
            let marker = if revision % 2 == 0 { "old" } else { "new" };
            acl(&mut db, marker, revision);
        }
    });
    start.wait();
    for _ in 0..35 {
        let snapshot = f
            .store
            .resource_grants(n(8192))
            .unwrap()
            .read(deadline())
            .await
            .unwrap();
        let marker = if snapshot.revision() % 2 == 0 {
            "old"
        } else {
            "new"
        };
        assert_eq!(snapshot.rules().len(), 1);
        let rule = &snapshot.rules()[0];
        assert_eq!(rule.id(), marker);
        assert_eq!(rule.name(), marker);
        assert_eq!(
            rule.updated_at(),
            TimestampMicros::new(snapshot.revision()).unwrap()
        );
        assert_eq!(snapshot.updated_at(), rule.updated_at());
        let mut prefixes = vec![marker, "v2/{project}"];
        prefixes.sort_unstable();
        assert_eq!(rule.s3_prefixes(), prefixes);
    }
    writer.join().unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn affected_operations_keep_deadline_cancel_shutdown_and_no_partial_role_effect() {
    let f = Fixture::new().await;
    let mut db = f.db();
    user(&db, "alice", "alice-subject", "human");
    f.store
        .set_role("held", &[SystemPermission::All], deadline())
        .await
        .unwrap();
    for operation in ["identity", "role", "acl"] {
        let writer = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let permissions = [SystemPermission::All];
        let mut held = Box::pin(f.store.set_role("held", &permissions, deadline()));
        if operation == "acl" {
            assert!(futures_util::poll!(held.as_mut()).is_pending());
        }
        let end = Instant::now() + Duration::from_millis(30);
        match operation {
            "identity" => {
                let reference =
                    LocalIdentityReference::new("alice", "alice-subject", 1, &limits()).unwrap();
                assert_eq!(
                    f.store
                        .local_identities(limits())
                        .unwrap()
                        .read(&reference, end)
                        .await
                        .unwrap_err(),
                    ControlError::Deadline
                );
            }
            "role" => assert_eq!(
                f.store
                    .set_role(
                        "held",
                        &[SystemPermission::Action(SystemAction::UsersWrite)],
                        end
                    )
                    .await,
                Err(ControlError::Deadline)
            ),
            _ => assert_eq!(
                f.store
                    .resource_grants(n(8192))
                    .unwrap()
                    .read(end)
                    .await
                    .unwrap_err(),
                ResourceGrantReadError::Control(ControlError::Deadline)
            ),
        }
        writer.rollback().unwrap();
        if operation == "acl" {
            held.await.unwrap();
        }
        assert_eq!(role_rows(&db, "held"), ["*"]);
        assert!(matches!(
            read(&f.store, "alice", "alice-subject", 1).await.unwrap(),
            LocalIdentityRead::Current(_)
        ));
    }
    for operation in ["identity", "role", "acl"] {
        let writer = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let permissions = [SystemPermission::All];
        let mut held = Box::pin(f.store.set_role("held", &permissions, deadline()));
        if operation == "acl" {
            assert!(futures_util::poll!(held.as_mut()).is_pending());
        }
        match operation {
            "identity" => {
                let reference =
                    LocalIdentityReference::new("alice", "alice-subject", 1, &limits()).unwrap();
                let identities = f.store.local_identities(limits()).unwrap();
                cancel_pending(identities.read(&reference, deadline())).await;
            }
            "role" => {
                let replacement = [SystemPermission::Action(SystemAction::UsersWrite)];
                cancel_pending(f.store.set_role("held", &replacement, deadline())).await;
            }
            _ => {
                let grants = f.store.resource_grants(n(8192)).unwrap();
                cancel_pending(grants.read(deadline())).await;
            }
        }
        writer.rollback().unwrap();
        if operation == "acl" {
            held.await.unwrap();
        }
        assert!(matches!(
            read(&f.store, "alice", "alice-subject", 1).await.unwrap(),
            LocalIdentityRead::Current(_)
        ));
        assert_eq!(role_rows(&db, "held"), ["*"]);
    }
    let writer = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let permissions = [SystemPermission::Action(SystemAction::UsersWrite)];
    let mut pending = std::pin::pin!(f.store.set_role("held", &permissions, deadline()));
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    let mut close = std::pin::pin!(f.store.shutdown(deadline()));
    // Poll shutdown before releasing SQLite: it closes admission immediately.
    let closed = futures_util::poll!(close.as_mut());
    writer.rollback().unwrap();
    let (closed, pending) = tokio::join!(
        async {
            match closed {
                std::task::Poll::Ready(result) => result,
                std::task::Poll::Pending => close.await,
            }
        },
        pending,
    );
    closed.unwrap();
    assert_eq!(pending, Err(ControlError::Closed));
    assert_eq!(role_rows(&db, "held"), ["*"]);
    assert_eq!(
        read(&f.store, "alice", "alice-subject", 1)
            .await
            .unwrap_err(),
        ControlError::Closed
    );
    assert_eq!(
        f.store
            .set_role("held", &[SystemPermission::All], deadline())
            .await,
        Err(ControlError::Closed)
    );
    assert_eq!(
        f.store
            .resource_grants(n(8192))
            .unwrap()
            .read(deadline())
            .await
            .unwrap_err(),
        ResourceGrantReadError::Control(ControlError::Closed)
    );
}

async fn cancel_pending(future: impl std::future::Future) {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
}
