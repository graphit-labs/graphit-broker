use broker_control::{
    FlowContinuation, FlowLimits, OidcFlow, SqliteControlConfig, SqliteControlError as Error,
    SqliteControlStore,
};
use broker_security::{CredentialDigester, DigestLimits};
use rusqlite::{Connection, params};
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;
fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn limits() -> FlowLimits {
    FlowLimits {
        provider_bytes: n(128),
        request_bytes: n(256),
        continuation_bytes: n(1024),
    }
}
fn config(path: &Path) -> SqliteControlConfig {
    SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        limits(),
    )
    .unwrap()
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(
            b"SQLite-contract-fixture-pepper-32"
                .to_vec()
                .into_boxed_slice(),
        ),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
async fn open(path: &Path) -> SqliteControlStore {
    SqliteControlStore::open(config(path), digester(), deadline())
        .await
        .unwrap()
}
fn flow(ttl: Duration) -> OidcFlow {
    OidcFlow::new(
        "fixture-nonce".into(),
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".into(),
        FlowContinuation::OAuth {
            provider_id: "upstream".into(),
            request_id: "request".into(),
        },
        SystemTime::now() + ttl,
        limits(),
    )
    .unwrap()
}
fn location() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private").join("broker.db");
    (temp, path)
}

#[test]
fn explicit_configuration_has_no_memory_uri_or_budget_default() {
    for path in ["", ":memory:", "file:db?mode=memory"] {
        assert_eq!(
            SqliteControlConfig::new(
                path.into(),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                limits()
            )
            .unwrap_err(),
            Error::Configuration
        );
    }
    assert_eq!(
        SqliteControlConfig::new(
            "db".into(),
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1),
            limits()
        )
        .unwrap_err(),
        Error::Configuration
    );
}

#[tokio::test]
async fn sqlite_private_bootstrap_reopen_and_known_flow_commit() {
    let (_temp, path) = location();
    let store = open(&path).await;
    let state = b"raw-state-that-must-not-be-stored-1234567890";
    let binding = b"raw-browser-binding-that-is-not-stored-12345";
    store
        .save_flow(state, binding, flow(Duration::from_secs(60)), deadline())
        .await
        .unwrap();
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        25
    );
    assert_eq!(
        db.query_row::<(String, i64), _, _>("SELECT format,epoch FROM schema_meta", [], |r| Ok((
            r.get(0)?,
            r.get(1)?
        )))
        .unwrap(),
        ("rust-broker-v1".into(), 2)
    );
    assert_eq!(
        db.query_row::<String, _, _>("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap(),
        "wal"
    );
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM role_permissions WHERE role='admin'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        9
    );
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM role_permissions WHERE role='user'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT revision FROM resource_acl_state WHERE id=1",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    let (stored_state, stored_binding): (String, String) = db
        .query_row(
            "SELECT state_hash,browser_binding_hash FROM oidc_flows",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored_state.len(), 64);
    assert_eq!(stored_binding.len(), 64);
    assert_ne!(stored_state, stored_binding);
    for file in [&path, path.with_file_name("broker.db-wal").as_path()] {
        let bytes = std::fs::read(file).unwrap();
        assert!(!bytes.windows(state.len()).any(|v| v == state));
        assert!(!bytes.windows(binding.len()).any(|v| v == binding));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o7777,
            0o700
        );
        for file in [
            &path,
            path.with_file_name("broker.db-wal").as_path(),
            path.with_file_name("broker.db-shm").as_path(),
        ] {
            let m = std::fs::metadata(file).unwrap();
            assert_eq!(m.mode() & 0o7777, 0o600);
            assert_eq!(m.nlink(), 1);
        }
    }
    drop(db);
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        store
            .consume_flow(state, binding, deadline())
            .await
            .unwrap_err(),
        Error::Closed
    );
    let store = open(&path).await;
    let restored = store
        .consume_flow(state, binding, deadline())
        .await
        .unwrap();
    assert_eq!(restored.nonce(), "fixture-nonce");
    assert_eq!(restored.continuation().request_id(), Some("request"));
    assert_eq!(
        store
            .consume_flow(state, binding, deadline())
            .await
            .unwrap_err(),
        Error::Unavailable
    );
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
async fn sqlite_binding_duplicate_corruption_and_limits_fail_closed() {
    let (_temp, path) = location();
    let store = open(&path).await;
    let state = [b'a'; 43];
    let binding = [b'b'; 43];
    store
        .save_flow(&state, &binding, flow(Duration::from_secs(60)), deadline())
        .await
        .unwrap();
    assert_eq!(
        store
            .consume_flow(&state, &[b'c'; 43], deadline())
            .await
            .unwrap_err(),
        Error::Unavailable
    );
    assert_eq!(
        store
            .save_flow(
                &state,
                &[b'c'; 43],
                flow(Duration::from_secs(60)),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::FlowExists
    );
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT COUNT(*) FROM oidc_flows", [], |r| r.get(0))
            .unwrap(),
        1
    );
    db.execute("UPDATE oidc_flows SET continuation_json=?1", ["bad-json"])
        .unwrap();
    assert_eq!(
        store
            .consume_flow(&state, &binding, deadline())
            .await
            .unwrap_err(),
        Error::CorruptFlow
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT COUNT(*) FROM oidc_flows", [], |r| r.get(0))
            .unwrap(),
        1
    );
    db.execute(
        "UPDATE oidc_flows SET continuation_json=?1,nonce=?2",
        params![
            r#"{"provider_id":"upstream","request_id":"request"}"#,
            "x".repeat(129)
        ],
    )
    .unwrap();
    assert_eq!(
        store
            .consume_flow(&state, &binding, deadline())
            .await
            .unwrap_err(),
        Error::CorruptFlow
    );
    assert_eq!(
        store
            .save_flow(
                &[b'e'; 43],
                &binding,
                flow(Duration::from_secs(601)),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::InvalidFlow
    );
    let large = OidcFlow::new(
        "n".into(),
        "x".repeat(43),
        FlowContinuation::Admin {
            provider_id: "p".repeat(129),
        },
        SystemTime::now() + Duration::from_secs(60),
        FlowLimits {
            provider_bytes: n(256),
            ..limits()
        },
    )
    .unwrap();
    assert_eq!(
        store
            .save_flow(&[b'e'; 43], &binding, large, deadline())
            .await
            .unwrap_err(),
        Error::InvalidFlow
    );
    drop(db);
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_independent_owners_have_one_consumer_and_concurrent_bootstrap() {
    let (_temp, path) = location();
    let (one, two) = tokio::join!(
        SqliteControlStore::open(config(&path), digester(), deadline()),
        SqliteControlStore::open(config(&path), digester(), deadline())
    );
    let one = Arc::new(one.unwrap());
    let two = Arc::new(two.unwrap());
    let state = [b'a'; 43];
    let binding = [b'b'; 43];
    one.save_flow(&state, &binding, flow(Duration::from_secs(60)), deadline())
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        one.consume_flow(&state, &binding, deadline()),
        two.consume_flow(&state, &binding, deadline())
    );
    assert!(matches!(
        (&a, &b),
        (Ok(_), Err(Error::Unavailable)) | (Err(Error::Unavailable), Ok(_))
    ));
    one.shutdown(deadline()).await.unwrap();
    two.shutdown(deadline()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_expiry_after_writer_wait_consumes_expired_row() {
    let (_temp, path) = location();
    let store = open(&path).await;
    let state = [b'a'; 43];
    let binding = [b'b'; 43];
    store
        .save_flow(
            &state,
            &binding,
            flow(Duration::from_millis(200)),
            deadline(),
        )
        .await
        .unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(350));
        db.execute_batch("ROLLBACK").unwrap();
    });
    assert_eq!(
        store
            .consume_flow(&state, &binding, deadline())
            .await
            .unwrap_err(),
        Error::Expired
    );
    release.join().unwrap();
    assert_eq!(
        store
            .consume_flow(&state, &binding, deadline())
            .await
            .unwrap_err(),
        Error::Unavailable
    );
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_cancelled_writer_wait_cannot_consume_later_or_interrupt_next() {
    let (_temp, path) = location();
    let store = Arc::new(open(&path).await);
    let state = [b'a'; 43];
    let binding = [b'b'; 43];
    store
        .save_flow(&state, &binding, flow(Duration::from_secs(60)), deadline())
        .await
        .unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        store
            .consume_flow(&state, &binding, Instant::now() + Duration::from_millis(60))
            .await
            .unwrap_err(),
        Error::Deadline
    );
    db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        store
            .consume_flow(&state, &binding, deadline())
            .await
            .unwrap()
            .nonce(),
        "fixture-nonce"
    );
    store
        .save_flow(&state, &binding, flow(Duration::from_secs(60)), deadline())
        .await
        .unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let pending = tokio::spawn({
        let store = store.clone();
        async move { store.consume_flow(&state, &binding, deadline()).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        store
            .consume_flow(&state, &binding, deadline())
            .await
            .unwrap()
            .nonce(),
        "fixture-nonce"
    );
    drop(db);
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
async fn sqlite_schema_and_marker_mutations_are_rejected_without_reset() {
    for mutation in [
        "DROP TABLE embedding_cache",
        "CREATE TABLE foreign_data(value TEXT)",
        "CREATE INDEX extra_index ON roles(created_at)",
        "CREATE VIEW extra_view AS SELECT name FROM roles",
        "CREATE TRIGGER extra_trigger AFTER INSERT ON oidc_flows BEGIN DELETE FROM oidc_flows; END",
        "ALTER TABLE local_users ADD COLUMN surprise TEXT",
        "UPDATE schema_meta SET format='foreign-format'",
        "UPDATE schema_meta SET epoch=1",
        "INSERT INTO schema_meta(id,format,epoch) VALUES(NULL,'rust-broker-v1',2)",
        "INSERT INTO role_permissions(role,action) VALUES('foreign-role','users.write')",
    ] {
        let (_temp, path) = location();
        let store = open(&path).await;
        store.shutdown(deadline()).await.unwrap();
        let db = Connection::open(&path).unwrap();
        db.pragma_update(None, "foreign_keys", "OFF").unwrap();
        db.execute_batch(mutation).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |r| r.get(0))
            .unwrap();
        drop(db);
        assert_eq!(
            SqliteControlStore::open(config(&path), digester(), deadline())
                .await
                .unwrap_err(),
            Error::SchemaRejected,
            "mutation {mutation}"
        );
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row::<i64, _, _>("SELECT COUNT(*) FROM sqlite_schema", [], |r| r.get(0))
                .unwrap(),
            count
        );
        assert!(path.exists());
    }
}

#[tokio::test]
async fn sqlite_runtime_schema_change_does_not_emit_stored_flow() {
    let (_temp, path) = location();
    let store = open(&path).await;
    store
        .save_flow(
            &[b'a'; 43],
            &[b'b'; 43],
            flow(Duration::from_secs(60)),
            deadline(),
        )
        .await
        .unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE VIEW surprise AS SELECT name FROM roles")
        .unwrap();
    assert_eq!(
        store
            .consume_flow(&[b'a'; 43], &[b'b'; 43], deadline())
            .await
            .unwrap_err(),
        Error::SchemaRejected
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT COUNT(*) FROM oidc_flows", [], |r| r.get(0))
            .unwrap(),
        1
    );
    drop(db);
    store.shutdown(deadline()).await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn sqlite_insecure_files_and_links_are_rejected_without_repair() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (_temp, path) = location();
    std::fs::create_dir(path.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert_eq!(
        SqliteControlStore::open(config(&path), digester(), deadline())
            .await
            .unwrap_err(),
        Error::PrivateFile
    );
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    std::fs::set_permissions(
        path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let foreign = path.with_file_name("foreign");
    std::fs::write(&foreign, b"foreign bytes").unwrap();
    std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&foreign, &path).unwrap();
    assert_eq!(
        SqliteControlStore::open(config(&path), digester(), deadline())
            .await
            .unwrap_err(),
        Error::PrivateFile
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::hard_link(&foreign, &path).unwrap();
    assert_eq!(
        SqliteControlStore::open(config(&path), digester(), deadline())
            .await
            .unwrap_err(),
        Error::PrivateFile
    );
    std::fs::remove_file(&path).unwrap();
    assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign bytes");
    let store = open(&path).await;
    store.shutdown(deadline()).await.unwrap();
    let wal = path.with_file_name("broker.db-wal");
    symlink(&foreign, &wal).unwrap();
    assert_eq!(
        SqliteControlStore::open(config(&path), digester(), deadline())
            .await
            .unwrap_err(),
        Error::PrivateFile
    );
    std::fs::remove_file(&wal).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        SqliteControlStore::open(config(&path), digester(), deadline())
            .await
            .unwrap_err(),
        Error::PrivateFile
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
}
