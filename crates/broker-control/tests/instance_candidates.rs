// Shared helpers also serve other active control tests.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture contains helpers used by other suites"
)]
mod support;
use broker_control::{
    ConnectionLimits, ControlError, InstanceInventory, InstanceOwner, InstanceProjectVersions,
    InstanceReadError, PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
    PostgresInstanceInventoryCandidates, StoredInstanceInventory,
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
            "candidate_owner".into(),
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
    parents: Vec<(String, String, String, i64, i64)>,
    rows: Vec<(String, String, i64, String)>,
}
async fn snapshot(c: &mut sqlx_postgres::PgConnection) -> SqlSnapshot {
    let parents=sqlx_core::query_as::query_as("SELECT instance_id,owner_issuer,owner_subject,created_at,updated_at FROM public.broker_instances ORDER BY instance_id COLLATE \"C\"").fetch_all(&mut *c).await.unwrap();
    let rows=sqlx_core::query_as::query_as("SELECT instance_id,project_id,position,version FROM public.broker_instance_project_versions ORDER BY instance_id COLLATE \"C\",project_id COLLATE \"C\",position").fetch_all(&mut *c).await.unwrap();
    SqlSnapshot { parents, rows }
}
async fn checked_read(
    view: &PostgresInstanceInventoryCandidates<'_>,
    c: &mut sqlx_postgres::PgConnection,
    after: Option<&str>,
) -> Result<Option<StoredInstanceInventory>, InstanceReadError> {
    let before = snapshot(c).await;
    let result = view.read_next(after, deadline()).await;
    assert_eq!(snapshot(c).await, before);
    result
}
async fn malformed(
    view: &PostgresInstanceInventoryCandidates<'_>,
    c: &mut sqlx_postgres::PgConnection,
    sql: &'static str,
) {
    c.execute(sql).await.unwrap();
    assert_eq!(
        checked_read(view, c, Some("m")).await.unwrap_err(),
        InstanceReadError::MalformedStored
    );
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS candidate ordering, coherent data, caps and cancellation"]
async fn postgres_instance_inventory_candidates_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE candidate_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION candidate_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO candidate_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='candidate_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    let invalid = store
        .instance_inventory_candidates(n(usize::MAX))
        .unwrap_err();
    assert_eq!(invalid, InstanceReadError::InvalidLimits);
    assert_eq!(invalid.to_string(), "invalid instance inventory read limit");
    let view = store.instance_inventory_candidates(n(100_000)).unwrap();
    assert_eq!(
        format!("{view:?}"),
        "PostgresInstanceInventoryCandidates([REDACTED])"
    );
    assert!(checked_read(&view, &mut c, None).await.unwrap().is_none());
    assert!(
        checked_read(&view, &mut c, Some("absent"))
            .await
            .unwrap()
            .is_none()
    );
    for id in [
        "",
        " x",
        "x/1",
        "é",
        "_x",
        "x-",
        "x';DROP TABLE broker_instances;--",
        &"z".repeat(129),
    ] {
        assert_eq!(
            checked_read(&view, &mut c, Some(id)).await.unwrap_err(),
            InstanceReadError::InvalidInstanceId
        );
    }
    let owner = InstanceOwner::new("Issuer ", "Subject ").unwrap();
    let order = [
        "0", "A", "A-1", "A.1", "A_1", "Z", "a", "a0", "empty", "station", "v", "z",
    ];
    for id in order.into_iter().rev() {
        store
            .replace_instance_inventory(&owner, &inventory(id, &[]), deadline())
            .await
            .unwrap();
    }
    // No user, token or resource grants are needed for this DATA API.
    for sql in [
        "SELECT count(*) FROM public.local_users",
        "SELECT count(*) FROM public.local_tokens",
        "SELECT count(*) FROM public.resource_grants",
    ] {
        let count: i64 = sqlx_core::query_scalar::query_scalar(sql)
            .fetch_one(&mut c)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
    let before_scan = snapshot(&mut c).await;
    let mut cursor: Option<String> = None;
    for id in order {
        let read = checked_read(&view, &mut c, cursor.as_deref())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.inventory().instance_id(), id);
        assert!(read.inventory().projects().is_empty());
        assert_eq!(
            (read.owner().issuer(), read.owner().subject()),
            ("Issuer ", "Subject ")
        );
        assert_eq!(format!("{read:?}"), "StoredInstanceInventory([REDACTED])");
        cursor = Some(id.to_owned());
    }
    assert!(
        checked_read(&view, &mut c, cursor.as_deref())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(snapshot(&mut c).await, before_scan);
    assert_eq!(
        checked_read(&view, &mut c, Some("B"))
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .instance_id(),
        "Z"
    );
    assert_eq!(
        checked_read(&view, &mut c, Some("A-0"))
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .instance_id(),
        "A-1"
    );
    assert_eq!(
        checked_read(&view, &mut c, Some("empty"))
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .instance_id(),
        "station"
    );
    assert!(
        checked_read(&view, &mut c, Some(&"z".repeat(128)))
            .await
            .unwrap()
            .is_none()
    );
    let long = "界😀".repeat(10_000);
    let original = inventory(
        "station",
        &[(B, &["main"]), (A, &[&long, "release", "main"])],
    );
    let written = store
        .replace_instance_inventory(&owner, &original, deadline())
        .await
        .unwrap();
    let read = checked_read(&view, &mut c, Some("empty"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.inventory(), &original);
    assert_eq!(
        (read.created_at_micros(), read.updated_at_micros()),
        (written.created_at_micros(), written.updated_at_micros())
    );
    assert_eq!(
        checked_read(
            &store.instance_inventory_candidates(n(8192)).unwrap(),
            &mut c,
            Some("empty")
        )
        .await
        .unwrap_err(),
        InstanceReadError::ReadLimitExceeded
    );
    // The cap must not silently skip the oversized first candidate to return unicode.
    let unicode = InstanceOwner::new(&"界".repeat(1024), &"😀".repeat(512)).unwrap();
    store
        .replace_instance_inventory(
            &unicode,
            &inventory("unicode", &[(A, &["界😀"])]),
            deadline(),
        )
        .await
        .unwrap();
    let read = checked_read(&view, &mut c, Some("station"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (read.owner().issuer(), read.owner().subject()),
        (unicode.issuer(), unicode.subject())
    );
    let payload:String=sqlx_core::query_scalar::query_scalar("SELECT json_build_object('instance_id',i.instance_id,'owner_issuer',i.owner_issuer,'owner_subject',i.owner_subject,'created_at',i.created_at,'updated_at',i.updated_at,'versions',COALESCE((SELECT json_agg(json_build_object('project_id',v.project_id,'position',v.position,'version',v.version) ORDER BY v.project_id COLLATE \"C\",v.position) FROM public.broker_instance_project_versions v WHERE v.instance_id=i.instance_id),'[]'::json))::text FROM public.broker_instances i WHERE instance_id='unicode'").fetch_one(&mut c).await.unwrap();
    assert!(payload.len() > payload.chars().count());
    assert_eq!(
        checked_read(
            &store
                .instance_inventory_candidates(n(payload.len() - 1))
                .unwrap(),
            &mut c,
            Some("station")
        )
        .await
        .unwrap_err(),
        InstanceReadError::ReadLimitExceeded
    );
    assert!(
        checked_read(
            &store
                .instance_inventory_candidates(n(payload.len()))
                .unwrap(),
            &mut c,
            Some("station")
        )
        .await
        .unwrap()
        .is_some()
    );
    // One statement sees old parent and children together until the writer commits.
    c.execute("BEGIN; UPDATE public.broker_instances SET owner_subject='Replacement ',updated_at=updated_at+1 WHERE instance_id='station'; DELETE FROM public.broker_instance_project_versions WHERE instance_id='station'").await.unwrap();
    sqlx_core::query::query("INSERT INTO public.broker_instance_project_versions(instance_id,project_id,position,version) VALUES('station',$1,1,'new')").bind(B).execute(&mut c).await.unwrap();
    let read = checked_read(&view, &mut c, Some("empty"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.inventory(), &original);
    assert_eq!(read.owner().subject(), "Subject ");
    assert_eq!(read.updated_at_micros(), written.updated_at_micros());
    c.execute("COMMIT").await.unwrap();
    let changed = inventory("station", &[(B, &["new"])]);
    let read = checked_read(&view, &mut c, Some("empty"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.inventory(), &changed);
    assert_eq!(read.owner().subject(), "Replacement ");
    assert_eq!(read.updated_at_micros(), written.updated_at_micros() + 1);

    store
        .replace_instance_inventory(
            &owner,
            &inventory("m-corrupt", &[(A, &["main"])]),
            deadline(),
        )
        .await
        .unwrap();
    malformed(&view, &mut c, "UPDATE public.broker_instance_project_versions SET position=2 WHERE instance_id='m-corrupt'").await;
    c.execute("UPDATE public.broker_instance_project_versions SET position=1 WHERE instance_id='m-corrupt'").await.unwrap();
    malformed(&view, &mut c, "UPDATE public.broker_instance_project_versions SET version=' main' WHERE instance_id='m-corrupt'").await;
    c.execute("UPDATE public.broker_instance_project_versions SET version='main' WHERE instance_id='m-corrupt'").await.unwrap();
    malformed(&view, &mut c, "UPDATE public.broker_instance_project_versions SET project_id='friendly' WHERE instance_id='m-corrupt'").await;
    sqlx_core::query::query("UPDATE public.broker_instance_project_versions SET project_id=$1 WHERE instance_id='m-corrupt'").bind(A).execute(&mut c).await.unwrap();
    malformed(
        &view,
        &mut c,
        "UPDATE public.broker_instances SET created_at=-1 WHERE instance_id='m-corrupt'",
    )
    .await;
    c.execute("UPDATE public.broker_instances SET created_at=0 WHERE instance_id='m-corrupt'")
        .await
        .unwrap();
    malformed(
        &view,
        &mut c,
        "UPDATE public.broker_instances SET owner_issuer='' WHERE instance_id='m-corrupt'",
    )
    .await;
    c.execute(
        "UPDATE public.broker_instances SET owner_issuer='Issuer ' WHERE instance_id='m-corrupt'",
    )
    .await
    .unwrap();
    assert!(
        checked_read(&view, &mut c, Some("m"))
            .await
            .unwrap()
            .is_some()
    );
    // A malformed chosen ID is a failure, not skipped or returned.
    c.execute("INSERT INTO public.broker_instances(instance_id,owner_issuer,owner_subject,created_at,updated_at) VALUES('m~bad','Issuer ','Subject ',0,0)").await.unwrap();
    assert_eq!(
        checked_read(&view, &mut c, Some("m-corrupt"))
            .await
            .unwrap_err(),
        InstanceReadError::MalformedStored
    );
    c.execute("DELETE FROM public.broker_instances WHERE instance_id='m~bad'")
        .await
        .unwrap();

    c.execute("DELETE FROM public.broker_instance_project_versions WHERE instance_id='m-corrupt'; DELETE FROM public.broker_instances WHERE instance_id='m-corrupt'").await.unwrap();

    for (revoke, grant) in [
        (
            "REVOKE SELECT ON public.broker_instances FROM candidate_owner",
            "GRANT SELECT ON public.broker_instances TO candidate_owner",
        ),
        (
            "REVOKE SELECT ON public.broker_instance_project_versions FROM candidate_owner",
            "GRANT SELECT ON public.broker_instance_project_versions TO candidate_owner",
        ),
    ] {
        c.execute(revoke).await.unwrap();
        assert_eq!(
            checked_read(&view, &mut c, Some("empty"))
                .await
                .unwrap_err(),
            InstanceReadError::Control(ControlError::Storage)
        );
        c.execute(grant).await.unwrap();
        assert!(
            checked_read(&view, &mut c, Some("empty"))
                .await
                .unwrap()
                .is_some()
        );
    }
    let before_failures = snapshot(&mut c).await;
    c.execute("BEGIN; LOCK TABLE public.broker_instance_project_versions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let start = Instant::now();
    assert_eq!(
        view.read_next(Some("empty"), start + Duration::from_millis(300))
            .await
            .unwrap_err(),
        InstanceReadError::Control(ControlError::Deadline)
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    c.execute("ROLLBACK").await.unwrap();
    assert!(
        checked_read(&view, &mut c, Some("empty"))
            .await
            .unwrap()
            .is_some()
    );
    c.execute("BEGIN; LOCK TABLE public.broker_instance_project_versions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let running = store.clone();
    let job = tokio::spawn(async move {
        running
            .instance_inventory_candidates(n(100_000))
            .unwrap()
            .read_next(Some("empty"), deadline())
            .await
    });
    let limit = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let blocked:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='candidate_owner' AND wait_event_type='Lock' AND query LIKE '%WITH candidate AS MATERIALIZED%')").fetch_one(&mut c).await.unwrap();
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
    assert!(
        checked_read(&view, &mut c, Some("empty"))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(snapshot(&mut c).await, before_failures);
    assert_eq!(
        view.read_next(None, Instant::now()).await.unwrap_err(),
        InstanceReadError::Control(ControlError::Deadline)
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        view.read_next(None, deadline()).await.unwrap_err(),
        InstanceReadError::Control(ControlError::Closed)
    );
    // Canonical cursor validation still precedes pool access.
    assert_eq!(
        view.read_next(Some("x/1"), deadline()).await.unwrap_err(),
        InstanceReadError::InvalidInstanceId
    );
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    let read = checked_read(
        &reopened.instance_inventory_candidates(n(100_000)).unwrap(),
        &mut c,
        Some("empty"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(read.inventory(), &changed);
    assert_eq!(read.owner().subject(), "Replacement ");
    assert_eq!(read.updated_at_micros(), written.updated_at_micros() + 1);
    reopened.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
