#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture also serves other SQL suites"
)]
mod support;
use broker_control::{
    ControlError, LocalAdministratorBootstrapError as Error, LocalPasswordEngine,
    PostgresControlStore, SqliteControlConfig, SqliteControlStore,
};
use broker_security::LocalPasswordHasher;
use rusqlite::Connection as SqliteConnection;
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use support::{Fixture, deadline, digester, limits, n};
use zeroize::Zeroizing;
async fn hash() -> Zeroizing<String> {
    let engine = LocalPasswordEngine::new(
        LocalPasswordHasher::new(Zeroizing::new(vec![0x91; 32].into_boxed_slice())).unwrap(),
        n(1),
        deadline(),
    )
    .await
    .unwrap();
    let hash = engine
        .hash("first administrator test password", deadline())
        .await
        .unwrap();
    engine.close().await;
    hash
}
async fn sqlite(path: &Path) -> SqliteControlStore {
    SqliteControlStore::open(
        SqliteControlConfig::new(
            path.into(),
            Duration::from_secs(5),
            Duration::from_secs(3),
            Duration::from_secs(2),
            limits(),
        )
        .unwrap(),
        digester(),
        deadline(),
    )
    .await
    .unwrap()
}
fn sqlite_counts(db: &SqliteConnection) -> (i64, i64) {
    (
        db.query_row("SELECT count(*) FROM local_users", [], |r| r.get(0))
            .unwrap(),
        db.query_row("SELECT count(*) FROM role_assignments", [], |r| r.get(0))
            .unwrap(),
    )
}
#[tokio::test]
async fn sqlite_first_administrator_atomic_concurrent_rollback_and_deadline() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("private/broker.db");
    let store = Arc::new(sqlite(&path).await);
    let hash = hash().await;
    assert!(matches!(
        store
            .bootstrap_local_administrator("invalid PHC", deadline())
            .await,
        Err(Error::InvalidPasswordHash)
    ));
    let db = SqliteConnection::open(&path).unwrap();
    assert_eq!(sqlite_counts(&db), (0, 0));
    // Unapproved schema drift must fail closed before either bootstrap write.
    // Second-write rollback is exercised on PostgreSQL; SQLite retains its mature
    // IMMEDIATE transaction/commit owner and genuine lock/deadline proof below.
    db.execute_batch("CREATE TRIGGER reject_initial_assignment BEFORE INSERT ON role_assignments BEGIN SELECT RAISE(ABORT,'synthetic fixture rejection'); END;").unwrap();
    assert!(matches!(
        store.bootstrap_local_administrator(&hash, deadline()).await,
        Err(Error::Control(_))
    ));
    assert_eq!(sqlite_counts(&db), (0, 0));
    db.execute_batch("DROP TRIGGER reject_initial_assignment; BEGIN IMMEDIATE;")
        .unwrap();
    assert!(matches!(
        store
            .bootstrap_local_administrator(&hash, Instant::now() + Duration::from_millis(80))
            .await,
        Err(Error::Control(ControlError::Deadline))
    ));
    db.execute_batch("ROLLBACK").unwrap();
    store.shutdown(deadline()).await.unwrap();
    drop(store);
    let store = Arc::new(sqlite(&path).await);
    assert_eq!(sqlite_counts(&db), (0, 0));
    let (a, b) = tokio::join!(
        store.bootstrap_local_administrator(&hash, deadline()),
        store.bootstrap_local_administrator(&hash, deadline())
    );
    assert!(matches!(
        (&a, &b),
        (Ok(()), Err(Error::AlreadyInitialized)) | (Err(Error::AlreadyInitialized), Ok(()))
    ));
    assert_eq!(sqlite_counts(&db), (1, 1));
    assert_eq!(
        db.query_row(
            "SELECT subject FROM role_assignments WHERE role='admin'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "local|admin"
    );
    db.execute_batch("DELETE FROM role_assignments; DELETE FROM local_users; INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at)VALUES('existing-service','existing-service','service','','','','','[]',1,0,1,0,0)").unwrap();
    assert!(matches!(
        store.bootstrap_local_administrator(&hash, deadline()).await,
        Err(Error::AlreadyInitialized)
    ));
    assert_eq!(sqlite_counts(&db), (1, 0));
    drop(db);
    store.shutdown(deadline()).await.unwrap();
    let reopened = sqlite(&path).await;
    reopened.shutdown(deadline()).await.unwrap();
}
async fn postgres_counts(conn: &mut sqlx_postgres::PgConnection) -> (i64, i64) {
    sqlx_core::query_as::query_as(
        "SELECT (SELECT count(*) FROM local_users),(SELECT count(*) FROM role_assignments)",
    )
    .fetch_one(conn)
    .await
    .unwrap()
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS first administrator transaction and physical pool drain"]
async fn postgres_first_administrator_atomic_concurrent_rollback_and_physical_shutdown() {
    let fixture = Fixture::new(true).await;
    let hash = hash().await;
    let store = Arc::new(fixture.open(2).await);
    let mut conn = fixture.connection().await;
    assert!(matches!(
        store
            .bootstrap_local_administrator("invalid PHC", deadline())
            .await,
        Err(Error::InvalidPasswordHash)
    ));
    assert_eq!(postgres_counts(&mut conn).await, (0, 0));
    conn.execute("CREATE FUNCTION public.reject_initial_assignment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic fixture rejection'; END $$; CREATE TRIGGER reject_initial_assignment BEFORE INSERT ON public.role_assignments FOR EACH ROW EXECUTE FUNCTION public.reject_initial_assignment()").await.unwrap();
    assert!(matches!(
        store.bootstrap_local_administrator(&hash, deadline()).await,
        Err(Error::Control(_))
    ));
    assert_eq!(postgres_counts(&mut conn).await, (0, 0));
    conn.execute("DROP TRIGGER reject_initial_assignment ON public.role_assignments; DROP FUNCTION public.reject_initial_assignment()").await.unwrap();
    let (a, b) = tokio::join!(
        store.bootstrap_local_administrator(&hash, deadline()),
        store.bootstrap_local_administrator(&hash, deadline())
    );
    assert!(matches!(
        (&a, &b),
        (Ok(()), Err(Error::AlreadyInitialized)) | (Err(Error::AlreadyInitialized), Ok(()))
    ));
    assert_eq!(postgres_counts(&mut conn).await, (1, 1));
    conn.execute("DELETE FROM role_assignments; DELETE FROM local_users; INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at)VALUES('existing-service','existing-service','service','','','','','[]',1,0,1,0,0)").await.unwrap();
    assert!(matches!(
        store.bootstrap_local_administrator(&hash, deadline()).await,
        Err(Error::AlreadyInitialized)
    ));
    assert_eq!(postgres_counts(&mut conn).await, (1, 0));
    conn.execute("DELETE FROM local_users").await.unwrap();
    let mut locker = fixture.connection().await;
    let mut lock = locker.begin().await.unwrap();
    lock.execute("SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
        .await
        .unwrap();
    assert!(matches!(
        store
            .bootstrap_local_administrator(&hash, Instant::now() + Duration::from_millis(80))
            .await,
        Err(Error::Control(ControlError::Deadline))
    ));
    lock.rollback().await.unwrap();
    locker.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    drop(store);
    assert_eq!(postgres_counts(&mut conn).await, (0, 0));
    for expired_at_entry in [true, false] {
        let store = Arc::new(fixture.open(2).await);
        let mut locker = fixture.connection().await;
        let mut lock = locker.begin().await.unwrap();
        lock.execute("SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
            .await
            .unwrap();
        let operation_store = store.clone();
        let operation_hash = hash.clone();
        let operation = tokio::spawn(async move {
            operation_store
                .bootstrap_local_administrator(&operation_hash, deadline())
                .await
        });
        let waiting_until = deadline();
        loop {
            let active:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND state='active' AND wait_event_type='Lock' AND query LIKE '%SELECT name FROM public.roles%FOR UPDATE%'").fetch_one(&mut conn).await.unwrap();
            if active > 0 {
                break;
            }
            assert!(
                Instant::now() < waiting_until,
                "real bootstrap must hold a pool connection"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let close_store = store.clone();
        let original = Instant::now()
            + if expired_at_entry {
                Duration::ZERO
            } else {
                Duration::from_millis(30)
            };
        let close = tokio::spawn(async move { close_store.shutdown(original).await });
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            !close.is_finished(),
            "Deadline must not release physical pool ownership"
        );
        lock.rollback().await.unwrap();
        locker.close().await.unwrap();
        operation.await.unwrap().unwrap();
        assert_eq!(close.await.unwrap(), Err(ControlError::Deadline));
        drop(store);
        assert_eq!(postgres_counts(&mut conn).await, (1, 1));
        let still_open:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control'").fetch_one(&mut conn).await.unwrap();
        assert_eq!(still_open, 0, "close physically drained the pool");
        conn.execute("DELETE FROM role_assignments; DELETE FROM local_users")
            .await
            .unwrap();
        let reopened = PostgresControlStore::open(fixture.config(2), digester(), deadline())
            .await
            .unwrap();
        reopened.shutdown(deadline()).await.unwrap();
    }
    conn.close().await.unwrap();
    fixture.shutdown().unwrap();
}

#[test]
fn first_administrator_password_uses_current_unicode_and_byte_limits() {
    use broker_control::validate_initial_administrator_password as validate;
    assert!(validate("").is_err());
    assert!(validate(&"é".repeat(14)).is_err());
    assert!(validate(&"é".repeat(15)).is_ok());
    assert!(validate(&"x".repeat(4096)).is_ok());
    assert!(validate(&"x".repeat(4097)).is_err());
    assert!(validate(&"é".repeat(2048)).is_ok());
    assert!(validate(&"é".repeat(2049)).is_err());
}
