// Shared helpers also serve other active control tests.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture contains helpers used by other suites"
)]
mod support;
use broker_control::{
    ConnectionLimits, ControlError, InstanceInventory, InstanceOwner, InstanceProjectVersions,
    InstanceReadError, PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant},
};
use support::{Fixture, deadline, n};
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "inventory_owner".into(),
            Zeroizing::new("ephemeral-owner".into()),
        ),
        f.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap()
}
fn inventory(id: &str, projects: &[(&str, &[&str])]) -> InstanceInventory {
    InstanceInventory::new(
        id.into(),
        projects
            .iter()
            .map(|(id, versions)| {
                InstanceProjectVersions::new(
                    (*id).into(),
                    versions.iter().map(|v| (*v).into()).collect(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap()
}
#[derive(Debug, PartialEq)]
struct SqlSnapshot {
    parent: Option<(String, String, i64, i64)>,
    rows: Vec<(String, i64, String)>,
}
async fn snapshot(c: &mut sqlx_postgres::PgConnection, id: &str) -> SqlSnapshot {
    let parent=sqlx_core::query_as::query_as("SELECT owner_issuer,owner_subject,created_at,updated_at FROM public.broker_instances WHERE instance_id=$1").bind(id).fetch_optional(&mut *c).await.unwrap();
    let rows=sqlx_core::query_as::query_as("SELECT project_id,position,version FROM public.broker_instance_project_versions WHERE instance_id=$1 ORDER BY project_id COLLATE \"C\",position").bind(id).fetch_all(&mut *c).await.unwrap();
    SqlSnapshot { parent, rows }
}
async fn expect_malformed(
    store: &PostgresControlStore,
    c: &mut sqlx_postgres::PgConnection,
    sql: &'static str,
) {
    c.execute("BEGIN").await.unwrap();
    sqlx_core::raw_sql::raw_sql(sql)
        .execute(&mut *c)
        .await
        .unwrap();
    c.execute("COMMIT").await.unwrap();
    let before = snapshot(c, "corrupt").await;
    assert_eq!(
        store
            .instance_inventories(n(8192))
            .unwrap()
            .read("corrupt", deadline())
            .await
            .unwrap_err(),
        InstanceReadError::MalformedStored
    );
    assert_eq!(snapshot(c, "corrupt").await, before);
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS inventory reads, snapshots, limits, cancellation and recovery"]
async fn postgres_instance_inventory_read_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE inventory_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION inventory_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO inventory_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='inventory_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    assert!(store.instance_inventories(n(usize::MAX)).is_err());
    let view = store.instance_inventories(n(100_000)).unwrap();
    assert_eq!(
        format!("{view:?}"),
        "PostgresInstanceInventories([REDACTED])"
    );
    assert!(view.read("absent", deadline()).await.unwrap().is_none());
    for id in ["", " x", "x/1", "é", "_x", "x-"] {
        assert_eq!(
            view.read(id, deadline()).await.unwrap_err(),
            InstanceReadError::InvalidInstanceId
        );
    }
    let owner = InstanceOwner::new("Issuer ", "Subject ").unwrap();
    let empty = inventory("empty", &[]);
    let written = store
        .replace_instance_inventory(&owner, &empty, deadline())
        .await
        .unwrap();
    let before = snapshot(&mut c, "empty").await;
    let read = view.read("empty", deadline()).await.unwrap().unwrap();
    assert!(read.inventory().projects().is_empty());
    assert_eq!(
        (read.owner().issuer(), read.owner().subject()),
        ("Issuer ", "Subject ")
    );
    assert_eq!(
        (read.created_at_micros(), read.updated_at_micros()),
        (written.created_at_micros(), written.updated_at_micros())
    );
    assert_eq!(snapshot(&mut c, "empty").await, before);

    let long = "界😀".repeat(10_000);
    let original = inventory(
        "station",
        &[(B, &["main"]), (A, &[&long, "release", "main"])],
    );
    let written = store
        .replace_instance_inventory(&owner, &original, deadline())
        .await
        .unwrap();
    let before = snapshot(&mut c, "station").await;
    let read = view.read("station", deadline()).await.unwrap().unwrap();
    assert_eq!(read.inventory(), &original);
    assert_eq!(
        (read.created_at_micros(), read.updated_at_micros()),
        (written.created_at_micros(), written.updated_at_micros())
    );
    assert_eq!(snapshot(&mut c, "station").await, before);
    assert_eq!(
        store
            .instance_inventories(n(8192))
            .unwrap()
            .read("station", deadline())
            .await
            .unwrap_err(),
        InstanceReadError::ReadLimitExceeded
    );
    assert_eq!(snapshot(&mut c, "station").await, before);
    let unicode = InstanceOwner::new(&"界".repeat(1024), &"😀".repeat(512)).unwrap();
    store
        .replace_instance_inventory(
            &unicode,
            &inventory("unicode", &[(A, &["界😀"])]),
            deadline(),
        )
        .await
        .unwrap();
    let read = view.read("unicode", deadline()).await.unwrap().unwrap();
    assert_eq!(
        (read.owner().issuer(), read.owner().subject()),
        (unicode.issuer(), unicode.subject())
    );
    let payload:String=sqlx_core::query_scalar::query_scalar("SELECT json_build_object('instance_id',i.instance_id,'owner_issuer',i.owner_issuer,'owner_subject',i.owner_subject,'created_at',i.created_at,'updated_at',i.updated_at,'versions',COALESCE((SELECT json_agg(json_build_object('project_id',v.project_id,'position',v.position,'version',v.version) ORDER BY v.project_id COLLATE \"C\",v.position) FROM public.broker_instance_project_versions v WHERE v.instance_id=i.instance_id),'[]'::json))::text FROM public.broker_instances i WHERE instance_id='unicode'").fetch_one(&mut c).await.unwrap();
    assert!(payload.len() > payload.chars().count());
    assert_eq!(
        store
            .instance_inventories(n(payload.len() - 1))
            .unwrap()
            .read("unicode", deadline())
            .await
            .unwrap_err(),
        InstanceReadError::ReadLimitExceeded
    );
    assert!(
        store
            .instance_inventories(n(payload.len()))
            .unwrap()
            .read("unicode", deadline())
            .await
            .unwrap()
            .is_some()
    );

    // The reader sees the old committed statement snapshot while both tables are being updated.
    c.execute("BEGIN; UPDATE public.broker_instances SET owner_subject='Replacement ',updated_at=updated_at+1 WHERE instance_id='station'; DELETE FROM public.broker_instance_project_versions WHERE instance_id='station'").await.unwrap();
    sqlx_core::query::query("INSERT INTO public.broker_instance_project_versions(instance_id,project_id,position,version) VALUES('station',$1,1,'new')").bind(B).execute(&mut c).await.unwrap();
    let read = view.read("station", deadline()).await.unwrap().unwrap();
    assert_eq!(read.inventory(), &original);
    assert_eq!(read.owner().subject(), "Subject ");
    assert_eq!(read.updated_at_micros(), written.updated_at_micros());
    c.execute("COMMIT").await.unwrap();
    let changed = inventory("station", &[(B, &["new"])]);
    let read = view.read("station", deadline()).await.unwrap().unwrap();
    assert_eq!(read.inventory(), &changed);
    assert_eq!(read.owner().subject(), "Replacement ");
    assert_eq!(read.updated_at_micros(), written.updated_at_micros() + 1);

    store
        .replace_instance_inventory(&owner, &inventory("corrupt", &[(A, &["main"])]), deadline())
        .await
        .unwrap();
    expect_malformed(
        &store,
        &mut c,
        "UPDATE public.broker_instance_project_versions SET position=2 WHERE instance_id='corrupt'",
    )
    .await;
    c.execute(
        "UPDATE public.broker_instance_project_versions SET position=1 WHERE instance_id='corrupt'",
    )
    .await
    .unwrap();
    expect_malformed(&store,&mut c,"UPDATE public.broker_instance_project_versions SET version=' main' WHERE instance_id='corrupt'").await;
    c.execute("UPDATE public.broker_instance_project_versions SET version='main' WHERE instance_id='corrupt'").await.unwrap();
    expect_malformed(&store,&mut c,"UPDATE public.broker_instance_project_versions SET project_id='friendly' WHERE instance_id='corrupt'").await;
    sqlx_core::query::query("UPDATE public.broker_instance_project_versions SET project_id=$1 WHERE instance_id='corrupt'").bind(A).execute(&mut c).await.unwrap();
    expect_malformed(
        &store,
        &mut c,
        "UPDATE public.broker_instances SET created_at=-1 WHERE instance_id='corrupt'",
    )
    .await;
    c.execute("UPDATE public.broker_instances SET created_at=0 WHERE instance_id='corrupt'")
        .await
        .unwrap();
    expect_malformed(
        &store,
        &mut c,
        "UPDATE public.broker_instances SET owner_issuer='' WHERE instance_id='corrupt'",
    )
    .await;
    c.execute(
        "UPDATE public.broker_instances SET owner_issuer='Issuer ' WHERE instance_id='corrupt'",
    )
    .await
    .unwrap();
    assert!(view.read("corrupt", deadline()).await.unwrap().is_some());

    c.execute("REVOKE SELECT ON public.broker_instance_project_versions FROM inventory_owner")
        .await
        .unwrap();
    assert_eq!(
        view.read("station", deadline()).await.unwrap_err(),
        InstanceReadError::Control(ControlError::Storage)
    );
    c.execute("GRANT SELECT ON public.broker_instance_project_versions TO inventory_owner")
        .await
        .unwrap();
    assert!(view.read("station", deadline()).await.unwrap().is_some());

    c.execute("BEGIN; LOCK TABLE public.broker_instance_project_versions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let start = Instant::now();
    assert_eq!(
        view.read("station", start + Duration::from_millis(300))
            .await
            .unwrap_err(),
        InstanceReadError::Control(ControlError::Deadline)
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    c.execute("ROLLBACK").await.unwrap();
    assert!(view.read("station", deadline()).await.unwrap().is_some());

    c.execute("BEGIN; LOCK TABLE public.broker_instance_project_versions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let running = store.clone();
    let job = tokio::spawn(async move {
        running
            .instance_inventories(n(100_000))
            .unwrap()
            .read("station", deadline())
            .await
    });
    let limit = deadline();
    loop {
        // Statistics snapshots remain cached inside the transaction holding the lock.
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let blocked:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='inventory_owner' AND wait_event_type='Lock' AND query LIKE '%WITH inventory AS MATERIALIZED%')").fetch_one(&mut c).await.unwrap();
        if blocked {
            break;
        }
        assert!(!job.is_finished(), "reader remains pending while lock held");
        assert!(Instant::now() < limit, "reader reached genuine SQL lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    c.execute("ROLLBACK").await.unwrap();
    assert!(view.read("station", deadline()).await.unwrap().is_some());
    assert_eq!(
        view.read("station", Instant::now()).await.unwrap_err(),
        InstanceReadError::Control(ControlError::Deadline)
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        view.read("station", deadline()).await.unwrap_err(),
        InstanceReadError::Control(ControlError::Closed)
    );
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    let read = reopened
        .instance_inventories(n(100_000))
        .unwrap()
        .read("station", deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.inventory(), &changed);
    assert_eq!(read.owner().subject(), "Replacement ");
    assert_eq!(read.updated_at_micros(), written.updated_at_micros() + 1);
    reopened.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
