use broker_control::{
    ControlError, FlowLimits, InstanceInventory, InstanceOwner, InstanceProjectVersions,
    InstanceReadError as Error, SqliteControlConfig, SqliteControlStore,
};
use broker_security::{CredentialDigester, DigestLimits};
use rusqlite::{Connection, types::Value};
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const PROJECT: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
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
                    b"sqlite-reader-synthetic-fixture-pepper"
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
    async fn seed(&self, versions: &[&str]) -> broker_control::RegistrationResult {
        let input = InstanceInventory::new(
            "station".into(),
            if versions.is_empty() {
                vec![]
            } else {
                vec![
                    InstanceProjectVersions::new(
                        PROJECT.into(),
                        versions.iter().map(|v| (*v).into()).collect(),
                    )
                    .unwrap(),
                ]
            },
        )
        .unwrap();
        self.store
            .replace_instance_inventory(
                &InstanceOwner::new("Issuer ", "界😀 ").unwrap(),
                &input,
                end(),
            )
            .await
            .unwrap()
    }
    async fn close(self) {
        drop(self.db);
        self.store.shutdown(end()).await.unwrap();
    }
    fn snapshot(&self) -> [Vec<Vec<Value>>; 2] {
        ["SELECT instance_id,owner_issuer,owner_subject,created_at,updated_at FROM broker_instances ORDER BY instance_id",
         "SELECT instance_id,project_id,position,version FROM broker_instance_project_versions ORDER BY instance_id,project_id,position"]
            .map(|sql| {
                let mut q=self.db.prepare(sql).unwrap();let count=q.column_count();
                q.query_map([],|row|(0..count).map(|i|row.get(i)).collect()).unwrap().collect::<rusqlite::Result<_>>().unwrap()
            })
    }
}
#[tokio::test]
async fn sqlite_inventory_reader_roundtrip_absence_empty_unicode_and_exact_caps() {
    let f = Fixture::new().await;
    let reader = f.store.instance_inventories(n(200000)).unwrap();
    assert_eq!(
        format!("{reader:?}"),
        "SqliteInstanceInventories([REDACTED])"
    );
    for invalid in ["", " station", "station ", "x/1", "_station", "é"] {
        assert_eq!(
            reader.read(invalid, end()).await.unwrap_err(),
            Error::InvalidInstanceId
        );
    }
    assert!(reader.read("station", end()).await.unwrap().is_none());
    assert_eq!(
        f.store.instance_inventories(n(usize::MAX)).unwrap_err(),
        Error::InvalidLimits
    );
    f.seed(&[]).await;
    let empty = reader.read("station", end()).await.unwrap().unwrap();
    assert!(empty.inventory().projects().is_empty());
    let large = "界😀".repeat(10000);
    let written = f.seed(&["a", large.as_str()]).await;
    let snapshot = reader.read("station", end()).await.unwrap().unwrap();
    assert_eq!(snapshot.owner().issuer(), "Issuer ");
    assert_eq!(snapshot.owner().subject(), "界😀 ");
    assert_eq!(
        snapshot.inventory().projects()[0].versions(),
        &["a".to_string(), large.clone()]
    );
    assert_eq!(
        (snapshot.created_at_micros(), snapshot.updated_at_micros()),
        (written.created_at_micros(), written.updated_at_micros())
    );
    assert_eq!(
        format!("{snapshot:?}"),
        "StoredInstanceInventory([REDACTED])"
    );
    let expected = serde_json::json!({"instance_id":"station","owner_issuer":"Issuer ","owner_subject":"界😀 ",
        "created_at":written.created_at_micros(),"updated_at":written.updated_at_micros(),
        "versions":[{"project_id":PROJECT,"position":1,"version":"a"},{"project_id":PROJECT,"position":2,"version":large}]});
    let bytes = expected.to_string().len();
    assert!(
        f.store
            .instance_inventories(n(bytes))
            .unwrap()
            .read("station", end())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        f.store
            .instance_inventories(n(bytes - 1))
            .unwrap()
            .read("station", end())
            .await
            .unwrap_err(),
        Error::ReadLimitExceeded
    );
    assert_eq!(
        f.store
            .instance_inventories(n(1))
            .unwrap()
            .read("station", end())
            .await
            .unwrap_err(),
        Error::ReadLimitExceeded
    );
    f.store.shutdown(end()).await.unwrap();
    let reopened = open(&f.path).await;
    assert_eq!(
        reopened
            .instance_inventories(n(bytes))
            .unwrap()
            .read("station", end())
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .projects()[0]
            .versions()[1]
            .len(),
        70000
    );
    reopened.shutdown(end()).await.unwrap();
    drop(f.db);
}
#[tokio::test]
async fn sqlite_inventory_reader_corruption_is_not_repaired_or_coerced() {
    let f = Fixture::new().await;
    for mutation in [
        "UPDATE broker_instances SET owner_issuer=''",
        "UPDATE broker_instances SET owner_subject=char(0)",
        "UPDATE broker_instances SET owner_issuer=x'00'",
        "UPDATE broker_instances SET created_at=-1",
        "UPDATE broker_instances SET updated_at=1.5",
        "UPDATE broker_instance_project_versions SET project_id='bad'",
        "UPDATE broker_instance_project_versions SET project_id=x'00'",
        "UPDATE broker_instance_project_versions SET position=3 WHERE position=2",
        "UPDATE broker_instance_project_versions SET position='bad' WHERE position=1",
        "UPDATE broker_instance_project_versions SET version='a' WHERE position=2",
        "UPDATE broker_instance_project_versions SET version='0' WHERE position=2",
        "UPDATE broker_instance_project_versions SET version=' a' WHERE position=1",
        "UPDATE broker_instance_project_versions SET version=x'00' WHERE position=1",
    ] {
        f.db.execute_batch(
            "DELETE FROM broker_instance_project_versions;DELETE FROM broker_instances;",
        )
        .unwrap();
        f.seed(&["a", "z"]).await;
        f.db.execute_batch(mutation).unwrap();
        let before = f.snapshot();
        assert_eq!(
            f.store
                .instance_inventories(n(10000))
                .unwrap()
                .read("station", end())
                .await
                .unwrap_err(),
            Error::MalformedStored,
            "{mutation}"
        );
        assert_eq!(f.snapshot(), before);
    }
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_inventory_reader_observes_coherent_state_while_writer_is_pending() {
    let f = Fixture::new().await;
    f.seed(&["before"]).await;
    let reader = f.store.instance_inventories(n(10000)).unwrap();
    for commit in [false, true] {
        f.db.execute_batch("BEGIN IMMEDIATE;UPDATE broker_instances SET updated_at=17;DELETE FROM broker_instance_project_versions;").unwrap();
        f.db.execute("INSERT INTO broker_instance_project_versions(instance_id,project_id,position,version) VALUES('station',?1,1,'after')",[PROJECT]).unwrap();
        let before = reader.read("station", end()).await.unwrap().unwrap();
        assert_eq!(before.inventory().projects()[0].versions(), &["before"]);
        f.db.execute_batch(if commit { "COMMIT" } else { "ROLLBACK" })
            .unwrap();
        let snapshot = reader.read("station", end()).await.unwrap().unwrap();
        assert_eq!(
            snapshot.inventory().projects()[0].versions(),
            &[if commit { "after" } else { "before" }]
        );
        if commit {
            assert_eq!(snapshot.updated_at_micros(), 17);
        }
    }
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_inventory_reader_deadline_cancel_close_and_recovery() {
    let f = Fixture::new().await;
    f.seed(&["current"]).await;
    let reader = f.store.instance_inventories(n(10000)).unwrap();
    let owner = InstanceOwner::new("Issuer ", "界😀 ").unwrap();
    let input = InstanceInventory::new("held-writer".into(), vec![]).unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    // A genuine write owns the executor while waiting on the external writer.
    // DEFERRED readers do not themselves wait on that external WAL writer.
    let mut writer = Box::pin(f.store.replace_instance_inventory(&owner, &input, end()));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    assert_eq!(
        reader
            .read("station", Instant::now() + Duration::from_millis(30))
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    f.db.execute_batch("ROLLBACK").unwrap();
    writer.await.unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut writer = Box::pin(f.store.replace_instance_inventory(&owner, &input, end()));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    let mut pending = Box::pin(reader.read("station", end()));
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    drop(pending);
    f.db.execute_batch("ROLLBACK").unwrap();
    writer.await.unwrap();
    assert_eq!(
        reader
            .read("station", end())
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .projects()[0]
            .versions(),
        &["current"]
    );
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut writer = Box::pin(f.store.replace_instance_inventory(&owner, &input, end()));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    let mut pending = Box::pin(reader.read("station", end()));
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    let close = f.store.shutdown(end());
    assert_eq!(
        pending.await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    f.db.execute_batch("ROLLBACK").unwrap();
    assert!(writer.await.is_err());
    close.await.unwrap();
    assert_eq!(
        reader.read("station", end()).await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    let reopened = open(&f.path).await;
    assert!(
        reopened
            .instance_inventories(n(10000))
            .unwrap()
            .read("station", end())
            .await
            .unwrap()
            .is_some()
    );
    reopened.shutdown(end()).await.unwrap();
    drop(f.db);
}
