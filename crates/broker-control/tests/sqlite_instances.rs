use broker_control::{
    ControlError, FlowLimits, InstanceInventory, InstanceOwner, InstanceProjectVersions,
    InstanceRegistryError as Error, RegistrationChange as Change, SqliteControlConfig,
    SqliteControlStore,
};
use broker_security::{CredentialDigester, DigestLimits};
use rusqlite::Connection;
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const P1: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const P2: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
async fn open(path: &Path) -> Arc<SqliteControlStore> {
    Arc::new(
        SqliteControlStore::open(
            SqliteControlConfig::new(
                path.into(),
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
                FlowLimits {
                    provider_bytes: n(128),
                    request_bytes: n(256),
                    continuation_bytes: n(1024),
                },
            )
            .unwrap(),
            CredentialDigester::new(
                Zeroizing::new(
                    b"instance-fixture-synthetic-pepper-32"
                        .to_vec()
                        .into_boxed_slice(),
                ),
                DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
            )
            .unwrap(),
            end(),
        )
        .await
        .unwrap(),
    )
}
struct Fixture {
    _root: tempfile::TempDir,
    path: PathBuf,
    store: Arc<SqliteControlStore>,
    db: Connection,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private").join("broker.db");
        let store = open(&path).await;
        let db = Connection::open(&path).unwrap();
        Self {
            _root: root,
            path,
            store,
            db,
        }
    }
    async fn close(self) {
        drop(self.db);
        self.store.shutdown(end()).await.unwrap();
    }
    fn rows(&self, instance: &str) -> Vec<(String, i64, String)> {
        self.db.prepare("SELECT project_id,position,version FROM broker_instance_project_versions WHERE instance_id=?1 ORDER BY project_id COLLATE BINARY,position").unwrap()
            .query_map([instance], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap()
    }
    fn parents(&self) -> i64 {
        self.db
            .query_row("SELECT COUNT(*) FROM broker_instances", [], |r| r.get(0))
            .unwrap()
    }
}
fn raw_children(
    db: &Connection,
    instance: &str,
) -> Vec<(
    rusqlite::types::Value,
    rusqlite::types::Value,
    rusqlite::types::Value,
)> {
    db.prepare("SELECT project_id,position,version FROM broker_instance_project_versions WHERE instance_id=?1 ORDER BY project_id COLLATE BINARY,position").unwrap()
        .query_map([instance], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap()
}
fn owner() -> InstanceOwner {
    InstanceOwner::new("Issuer ", "Subject ").unwrap()
}
fn inventory(id: &str, projects: &[(&str, &[&str])]) -> InstanceInventory {
    InstanceInventory::new(
        id.into(),
        projects
            .iter()
            .map(|(p, v)| {
                InstanceProjectVersions::new((*p).into(), v.iter().map(|s| (*s).into()).collect())
                    .unwrap()
            })
            .collect(),
    )
    .unwrap()
}
#[tokio::test]
async fn sqlite_instances_atomic_replacement_reopen_and_literal_values() {
    let f = Fixture::new().await;
    let unicode = "界😀".repeat(10000);
    let input = inventory(
        "Station._-1",
        &[
            (P2, &["z", "a"]),
            (P1, &[unicode.as_str(), "feature/topic"]),
        ],
    );
    let principal = InstanceOwner::new(&"界".repeat(1024), &"😀".repeat(512)).unwrap();
    let created = f
        .store
        .replace_instance_inventory(&principal, &input, end())
        .await
        .unwrap();
    assert_eq!(created.change(), Change::Created);
    assert_eq!(created.instance_id(), "Station._-1");
    assert!(created.created_at_micros() >= 0);
    assert_eq!(created.created_at_micros(), created.updated_at_micros());
    assert_eq!(
        f.rows("Station._-1"),
        vec![
            (P1.into(), 1, "feature/topic".into()),
            (P1.into(), 2, unicode),
            (P2.into(), 1, "a".into()),
            (P2.into(), 2, "z".into())
        ]
    );
    let unchanged = f
        .store
        .replace_instance_inventory(&principal, &input, end())
        .await
        .unwrap();
    assert_eq!(unchanged.change(), Change::Unchanged);
    assert_eq!(unchanged.created_at_micros(), created.created_at_micros());
    assert_eq!(unchanged.updated_at_micros(), created.updated_at_micros());
    let before = f.rows("Station._-1");
    for alien in [
        InstanceOwner::new("界", principal.subject()).unwrap(),
        InstanceOwner::new(principal.issuer(), "😀 ").unwrap(),
    ] {
        assert_eq!(
            f.store
                .replace_instance_inventory(&alien, &input, end())
                .await
                .unwrap_err(),
            Error::OwnerConflict
        );
        assert_eq!(f.rows("Station._-1"), before);
    }
    let fresh = inventory("Station._-1", &[(P2, &["new"])]);
    let updated = f
        .store
        .replace_instance_inventory(&principal, &fresh, end())
        .await
        .unwrap();
    assert_eq!(updated.change(), Change::Updated);
    assert_eq!(updated.created_at_micros(), created.created_at_micros());
    assert_eq!(f.rows("Station._-1"), vec![(P2.into(), 1, "new".into())]);
    f.store.shutdown(end()).await.unwrap();
    let reopened = open(&f.path).await;
    let same = reopened
        .replace_instance_inventory(&principal, &fresh, end())
        .await
        .unwrap();
    assert_eq!(same.change(), Change::Unchanged);
    assert_eq!(same.updated_at_micros(), updated.updated_at_micros());
    let empty = inventory("Station._-1", &[]);
    assert_eq!(
        reopened
            .replace_instance_inventory(&principal, &empty, end())
            .await
            .unwrap()
            .change(),
        Change::Updated
    );
    assert!(f.rows("Station._-1").is_empty());
    assert_eq!(f.parents(), 1);
    let binding: (String, String) =
        f.db.query_row(
            "SELECT owner_issuer,owner_subject FROM broker_instances",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        binding,
        (principal.issuer().into(), principal.subject().into())
    );
    reopened.shutdown(end()).await.unwrap();
    drop(f.db);
}
#[tokio::test]
async fn sqlite_instances_corruption_is_preserved() {
    let f = Fixture::new().await;
    let input = inventory("station", &[(P1, &["a", "z"])]);
    f.store
        .replace_instance_inventory(&owner(), &input, end())
        .await
        .unwrap();
    for mutation in [
        "UPDATE broker_instances SET owner_issuer=''",
        "UPDATE broker_instances SET owner_subject=zeroblob(3000)",
        "UPDATE broker_instances SET created_at=-1",
        "UPDATE broker_instances SET updated_at=-1",
        "UPDATE broker_instance_project_versions SET project_id='bad'",
        "UPDATE broker_instance_project_versions SET position=7 WHERE position=2",
        "UPDATE broker_instance_project_versions SET version=' a' WHERE position=1",
        "UPDATE broker_instance_project_versions SET version='a' WHERE position=2",
        "UPDATE broker_instance_project_versions SET version='0' WHERE position=2",
        "UPDATE broker_instance_project_versions SET version=x'00' WHERE position=1",
    ] {
        f.db.execute_batch("SAVEPOINT malformed_fixture").unwrap();
        f.db.execute_batch(mutation).unwrap();
        let before = raw_children(&f.db, "station");
        let parent_before: (rusqlite::types::Value, rusqlite::types::Value, i64, i64) =
            f.db.query_row(
                "SELECT owner_issuer,owner_subject,created_at,updated_at FROM broker_instances",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        // End the writer transaction so the independent real owner can observe
        // this malformed durable state. Restore exact known rows after each case.
        f.db.execute_batch("RELEASE malformed_fixture").unwrap();
        assert_eq!(
            f.store
                .replace_instance_inventory(&owner(), &inventory("station", &[]), end())
                .await
                .unwrap_err(),
            Error::MalformedStored
        );
        assert_eq!(raw_children(&f.db, "station"), before);
        let parent_after: (rusqlite::types::Value, rusqlite::types::Value, i64, i64) =
            f.db.query_row(
                "SELECT owner_issuer,owner_subject,created_at,updated_at FROM broker_instances",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(parent_before, parent_after);
        f.db.execute_batch(
            "DELETE FROM broker_instance_project_versions;DELETE FROM broker_instances;",
        )
        .unwrap();
        f.store
            .replace_instance_inventory(&owner(), &input, end())
            .await
            .unwrap();
    }
    // The existing contract permits nonnegative time values in either order.
    f.db.execute_batch("UPDATE broker_instances SET created_at=100,updated_at=1")
        .unwrap();
    let same = f
        .store
        .replace_instance_inventory(&owner(), &input, end())
        .await
        .unwrap();
    assert_eq!(
        (same.created_at_micros(), same.updated_at_micros()),
        (100, 1)
    );
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_instances_independent_creators_and_replacements_are_whole() {
    let f = Fixture::new().await;
    let second = open(&f.path).await;
    for (id, same_owner) in [("race-different", false), ("race-same", true)] {
        let first = inventory(id, &[(P1, &["a", "b"])]);
        let other = inventory(id, &[(P2, &["x", "y"])]);
        let literal = owner();
        let peer = if same_owner {
            owner()
        } else {
            InstanceOwner::new("OtherIssuer", "OtherSubject").unwrap()
        };
        // Both actual owner operations are submitted while a third writer
        // holds SQLite admission, before either can complete its transaction.
        f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut left = Box::pin(f.store.replace_instance_inventory(&literal, &first, end()));
        let mut right = Box::pin(second.replace_instance_inventory(&peer, &other, end()));
        assert!(futures_util::poll!(left.as_mut()).is_pending());
        assert!(futures_util::poll!(right.as_mut()).is_pending());
        f.db.execute_batch("ROLLBACK").unwrap();
        let (a, b) = tokio::join!(left, right);
        if same_owner {
            let a = a.as_ref().unwrap();
            let b = b.as_ref().unwrap();
            assert!(matches!(
                (a.change(), b.change()),
                (Change::Created, Change::Updated) | (Change::Updated, Change::Created)
            ));
        } else {
            assert!(
                matches!((&a,&b),(Ok(r),Err(Error::OwnerConflict)) if r.change()==Change::Created)
                    || matches!((&a,&b),(Err(Error::OwnerConflict),Ok(r)) if r.change()==Change::Created)
            );
        }
        let winner = if a.is_ok() { &literal } else { &peer };
        f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut left = Box::pin(f.store.replace_instance_inventory(winner, &first, end()));
        let mut right = Box::pin(second.replace_instance_inventory(winner, &other, end()));
        assert!(futures_util::poll!(left.as_mut()).is_pending());
        assert!(futures_util::poll!(right.as_mut()).is_pending());
        f.db.execute_batch("ROLLBACK").unwrap();
        let (a, b) = tokio::join!(left, right);
        assert!(a.is_ok() && b.is_ok());
        let final_rows = f.rows(id);
        assert!(
            final_rows == vec![(P1.into(), 1, "a".into()), (P1.into(), 2, "b".into())]
                || final_rows == vec![(P2.into(), 1, "x".into()), (P2.into(), 2, "y".into())]
        );
    }
    assert_eq!(f.parents(), 2);
    second.shutdown(end()).await.unwrap();
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_instances_deadline_cancel_close_and_recovery() {
    let f = Fixture::new().await;
    let input = inventory("blocked", &[(P1, &["one"])]);
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        f.store
            .replace_instance_inventory(
                &owner(),
                &input,
                Instant::now() + Duration::from_millis(30)
            )
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.parents(), 0);
    // One explicit poll submits the real worker while the independent writer
    // holds the lock. Dropping this future cancels actual submitted work.
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let principal = owner();
    let mut operation = Box::pin(
        f.store
            .replace_instance_inventory(&principal, &input, end()),
    );
    assert!(futures_util::poll!(operation.as_mut()).is_pending());
    drop(operation);
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        f.store
            .replace_instance_inventory(&principal, &input, end())
            .await
            .unwrap()
            .change(),
        Change::Created
    );
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut operation = Box::pin(
        f.store
            .replace_instance_inventory(&principal, &input, end()),
    );
    assert!(futures_util::poll!(operation.as_mut()).is_pending());
    let close = f.store.shutdown(end());
    assert_eq!(
        operation.await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    f.db.execute_batch("ROLLBACK").unwrap();
    close.await.unwrap();
    assert_eq!(
        f.store
            .replace_instance_inventory(&principal, &input, end())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    let reopened = open(&f.path).await;
    assert_eq!(
        reopened
            .replace_instance_inventory(&principal, &input, end())
            .await
            .unwrap()
            .change(),
        Change::Unchanged
    );
    reopened.shutdown(end()).await.unwrap();
    drop(f.db);
}
