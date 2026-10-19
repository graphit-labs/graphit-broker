mod support;

use broker_control::{
    ConnectionLimits, ControlError, IdentityReadLimits, LocalIdentityRead, LocalIdentityReference,
    PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint, SystemAction,
    SystemPermission::{Action, All},
};
use sqlx_core::connection::Connection;
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant},
};
use support::{Fixture, deadline, digester, n};
use zeroize::Zeroizing;

async fn execute(c: &mut PgConnection, sql: &'static str) {
    sqlx_core::raw_sql::raw_sql(sql).execute(c).await.unwrap();
}
async fn actions(c: &mut PgConnection, role: &str) -> Vec<String> {
    sqlx_core::query_scalar::query_scalar(
        "SELECT action FROM public.role_permissions WHERE role=$1 ORDER BY action",
    )
    .bind(role)
    .fetch_all(c)
    .await
    .unwrap()
}
async fn created(c: &mut PgConnection, role: &str) -> i64 {
    sqlx_core::query_scalar::query_scalar("SELECT created_at FROM public.roles WHERE name=$1")
        .bind(role)
        .fetch_one(c)
        .await
        .unwrap()
}
async fn current_permissions(store: &PostgresControlStore) -> Vec<&'static str> {
    let limits = IdentityReadLimits {
        username_bytes: n(128),
        subject_bytes: n(512),
        role_bytes: n(128),
        roles: n(16),
        rows: n(64),
    };
    let reference = LocalIdentityReference::new("alice", "alice-subject", 7, &limits).unwrap();
    match store
        .local_identities(limits)
        .unwrap()
        .read(&reference, deadline())
        .await
        .unwrap()
    {
        LocalIdentityRead::Current(value) => {
            assert_eq!(value.revision(), 7);
            value
                .permissions()
                .iter()
                .map(|value| value.as_str())
                .collect()
        }
        LocalIdentityRead::Unavailable(_) => panic!("current identity required"),
    }
}
async fn wait_role_lock(c: &mut PgConnection, blocked: bool) {
    let end = deadline();
    loop {
        let active: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND state='active' AND wait_event_type='Lock' AND (query LIKE 'INSERT INTO public.roles(name,created_at)%' OR query='SELECT 1 FROM public.roles WHERE name=$1 FOR UPDATE'))",
        ).fetch_one(&mut *c).await.unwrap();
        if active == blocked {
            return;
        }
        assert!(Instant::now() < end, "role writer lock wait point");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn wait_commit(c: &mut PgConnection, terminate: bool) {
    let end = deadline();
    loop {
        if terminate {
            let killed: Vec<bool> = sqlx_core::query_scalar::query_scalar(
                "WITH target AS MATERIALIZED (SELECT pid FROM pg_catalog.pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND state='active' AND query='COMMIT' AND wait_event='PgSleep') SELECT pg_terminate_backend(pid) FROM target",
            ).fetch_all(&mut *c).await.unwrap();
            if !killed.is_empty() {
                assert_eq!(killed, [true]);
                return;
            }
        } else {
            let active: bool = sqlx_core::query_scalar::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND state='active' AND query='COMMIT' AND wait_event='PgSleep')",
            ).fetch_one(&mut *c).await.unwrap();
            if active {
                return;
            }
        }
        assert!(Instant::now() < end, "role writer must reach actual COMMIT");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "requires native PostgreSQL Docker"]
async fn postgres_role_definitions_and_current_permissions() {
    let f = Fixture::new(true).await;
    f.reset().await;
    let store = f.open(2).await;
    let mut c = f.connection().await;
    store
        .set_role(
            " auditor ",
            &[Action(SystemAction::ConfigurationRead), All, All],
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        actions(&mut c, "auditor").await,
        ["*", "configuration.read"]
    );
    let first_created = created(&mut c, "auditor").await;
    assert!(first_created >= 0);
    execute(&mut c, "INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','not-selected-phc','Alice','','','[]',1,0,7,0,0); INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','auditor',0)").await;
    assert_eq!(
        current_permissions(&store).await,
        ["*", "configuration.read", "projects.read", "session.read"]
    );
    store
        .set_role(
            "auditor",
            &[
                Action(SystemAction::GrantsRead),
                Action(SystemAction::GrantsRead),
            ],
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(actions(&mut c, "auditor").await, ["grants.read"]);
    assert_eq!(created(&mut c, "auditor").await, first_created);
    assert_eq!(
        current_permissions(&store).await,
        ["grants.read", "projects.read", "session.read"]
    );
    let revision: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT revision FROM public.local_users WHERE username='alice'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(revision, 7);
    let assigned: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM public.role_assignments WHERE subject='local|alice-subject' AND role='auditor' AND created_at=0)").fetch_one(&mut c).await.unwrap();
    assert!(assigned);
    store
        .set_role("Auditor", &[Action(SystemAction::UsersRead)], deadline())
        .await
        .unwrap();
    assert_eq!(actions(&mut c, "Auditor").await, ["users.read"]);
    assert_eq!(actions(&mut c, "auditor").await, ["grants.read"]);
    store.set_role("admin", &[], deadline()).await.unwrap();
    assert_eq!(
        actions(&mut c, "admin").await,
        [
            "configuration.read",
            "grants.read",
            "grants.write",
            "projects.read",
            "roles.read",
            "roles.write",
            "session.read",
            "users.read",
            "users.write",
        ]
    );
    store.set_role("admin", &[All], deadline()).await.unwrap();
    assert!(
        !actions(&mut c, "admin")
            .await
            .iter()
            .any(|value| value == "*")
    );
    store.set_role("user", &[All], deadline()).await.unwrap();
    assert_eq!(
        actions(&mut c, "user").await,
        ["projects.read", "session.read"]
    );
    store.set_role("user", &[], deadline()).await.unwrap();
    let oversized = "r".repeat(129);
    for name in ["", ".", "..", "../bad", "x/y", "é", oversized.as_str()] {
        assert_eq!(
            store.set_role(name, &[All], deadline()).await,
            Err(ControlError::InvalidRole)
        );
    }
    assert_eq!(
        store.set_role("empty", &[], deadline()).await,
        Err(ControlError::InvalidRole)
    );
    let empty_exists: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.roles WHERE name='empty')",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!empty_exists);
    let maximum = "m".repeat(128);
    store.set_role(&maximum, &[All], deadline()).await.unwrap();
    assert_eq!(actions(&mut c, &maximum).await, ["*"]);
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        store.set_role("empty", &[], deadline()).await,
        Err(ControlError::InvalidRole)
    );
    assert_eq!(
        store.set_role("valid", &[All], deadline()).await,
        Err(ControlError::Closed)
    );
    assert_eq!(
        ControlError::InvalidRole.to_string(),
        "invalid system role definition"
    );
    c.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires native PostgreSQL Docker"]
async fn postgres_role_atomic_failure_and_concurrent_replacement() {
    let f = Fixture::new(true).await;
    f.reset().await;
    let store = Arc::new(f.open(2).await);
    let mut c = f.connection().await;
    store
        .set_role(
            "atomic",
            &[Action(SystemAction::ConfigurationRead)],
            deadline(),
        )
        .await
        .unwrap();
    let first_created = created(&mut c, "atomic").await;
    execute(&mut c, "CREATE FUNCTION public.reject_role_permission() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.role IN ('atomic','newfail') AND NEW.action='grants.write' THEN RAISE EXCEPTION 'fixture rejection'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_role_permission BEFORE INSERT ON public.role_permissions FOR EACH ROW EXECUTE FUNCTION public.reject_role_permission()").await;
    for role in ["atomic", "newfail"] {
        assert_eq!(
            store
                .set_role(
                    role,
                    &[
                        Action(SystemAction::GrantsRead),
                        Action(SystemAction::GrantsWrite)
                    ],
                    deadline()
                )
                .await,
            Err(ControlError::Storage)
        );
    }
    assert_eq!(actions(&mut c, "atomic").await, ["configuration.read"]);
    assert_eq!(created(&mut c, "atomic").await, first_created);
    let absent: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM public.roles WHERE name='newfail')",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(absent);
    execute(&mut c, "DROP TRIGGER reject_role_permission ON public.role_permissions; DROP FUNCTION public.reject_role_permission()").await;
    for role in ["fresh", "atomic"] {
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let s = store.clone();
        let b = barrier.clone();
        let left = tokio::spawn(async move {
            b.wait().await;
            s.set_role(
                role,
                &[
                    Action(SystemAction::GrantsRead),
                    Action(SystemAction::GrantsWrite),
                ],
                deadline(),
            )
            .await
        });
        let s = store.clone();
        let b = barrier.clone();
        let right = tokio::spawn(async move {
            b.wait().await;
            s.set_role(
                role,
                &[
                    Action(SystemAction::UsersRead),
                    Action(SystemAction::UsersWrite),
                ],
                deadline(),
            )
            .await
        });
        barrier.wait().await;
        left.await.unwrap().unwrap();
        right.await.unwrap().unwrap();
        let actual = actions(&mut c, role).await;
        assert!(
            actual == ["grants.read", "grants.write"] || actual == ["users.read", "users.write"]
        );
    }
    assert_eq!(created(&mut c, "atomic").await, first_created);
    let previous = actions(&mut c, "atomic").await;
    let mut lock = c.begin().await.unwrap();
    sqlx_core::query::query("SELECT 1 FROM public.roles WHERE name='atomic' FOR UPDATE")
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let s = store.clone();
    let writer = tokio::spawn(async move {
        s.set_role("atomic", &[Action(SystemAction::RolesRead)], deadline())
            .await
    });
    let mut monitor = f.connection().await;
    wait_role_lock(&mut monitor, true).await;
    assert_eq!(actions(&mut monitor, "atomic").await, previous);
    lock.commit().await.unwrap();
    writer.await.unwrap().unwrap();
    assert_eq!(actions(&mut monitor, "atomic").await, ["roles.read"]);
    monitor.close().await.unwrap();
    c.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "requires native PostgreSQL Docker"]
async fn postgres_role_permissions_deadline_cancel_and_commit() {
    let f = Fixture::new(true).await;
    let mut admin = f.connection().await;
    execute(&mut admin, "CREATE ROLE role_writer LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION role_writer; GRANT CONNECT,TEMP ON DATABASE postgres TO role_writer").await;
    let config = PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "role_writer".into(),
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
    .unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config, digester(), deadline())
            .await
            .unwrap(),
    );
    let nonsuperuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT NOT rolsuper FROM pg_catalog.pg_roles WHERE rolname='role_writer'",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert!(nonsuperuser);
    store
        .set_role(
            "healthy",
            &[Action(SystemAction::ConfigurationRead)],
            deadline(),
        )
        .await
        .unwrap();
    execute(
        &mut admin,
        "REVOKE INSERT ON public.role_permissions FROM role_writer",
    )
    .await;
    assert_eq!(
        store.set_role("healthy", &[All], deadline()).await,
        Err(ControlError::Storage)
    );
    assert_eq!(actions(&mut admin, "healthy").await, ["configuration.read"]);
    execute(
        &mut admin,
        "GRANT INSERT ON public.role_permissions TO role_writer",
    )
    .await;
    store.set_role("healthy", &[All], deadline()).await.unwrap();
    let mut monitor = f.connection().await;
    let mut lock = admin.begin().await.unwrap();
    sqlx_core::query::query("SELECT 1 FROM public.roles WHERE name='healthy' FOR UPDATE")
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let s = store.clone();
    let blocked = tokio::spawn(async move {
        s.set_role(
            "healthy",
            &[Action(SystemAction::RolesRead)],
            Instant::now() + Duration::from_secs(2),
        )
        .await
    });
    wait_role_lock(&mut monitor, true).await;
    assert_eq!(blocked.await.unwrap(), Err(ControlError::Deadline));
    assert_eq!(actions(&mut monitor, "healthy").await, ["*"]);
    lock.commit().await.unwrap();
    wait_role_lock(&mut monitor, false).await;
    let mut lock = admin.begin().await.unwrap();
    sqlx_core::query::query("SELECT 1 FROM public.roles WHERE name='healthy' FOR UPDATE")
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let s = store.clone();
    let cancelled = tokio::spawn(async move {
        s.set_role("healthy", &[Action(SystemAction::UsersWrite)], deadline())
            .await
    });
    wait_role_lock(&mut monitor, true).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    lock.commit().await.unwrap();
    wait_role_lock(&mut monitor, false).await;
    assert_eq!(actions(&mut monitor, "healthy").await, ["*"]);
    store
        .set_role("healthy", &[Action(SystemAction::RolesRead)], deadline())
        .await
        .unwrap();
    store
        .set_role(
            "commit",
            &[Action(SystemAction::ConfigurationRead)],
            deadline(),
        )
        .await
        .unwrap();
    execute(&mut admin, "CREATE FUNCTION public.role_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(10); RETURN NULL; END $$; CREATE CONSTRAINT TRIGGER role_commit_delay AFTER INSERT ON public.role_permissions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.role='commit') EXECUTE FUNCTION public.role_commit_delay()").await;
    let s = store.clone();
    let disconnected = tokio::spawn(async move {
        s.set_role("commit", &[Action(SystemAction::GrantsRead)], deadline())
            .await
    });
    wait_commit(&mut monitor, true).await;
    assert_eq!(
        disconnected.await.unwrap(),
        Err(ControlError::OutcomeUncertain)
    );
    assert_eq!(
        actions(&mut monitor, "commit").await,
        ["configuration.read"]
    );
    let s = store.clone();
    let timed = tokio::spawn(async move {
        s.set_role(
            "commit",
            &[Action(SystemAction::GrantsWrite)],
            Instant::now() + Duration::from_secs(5),
        )
        .await
    });
    wait_commit(&mut monitor, false).await;
    assert_eq!(timed.await.unwrap(), Err(ControlError::OutcomeUncertain));
    let actual = actions(&mut monitor, "commit").await;
    assert!(actual == ["configuration.read"] || actual == ["grants.write"]);
    execute(&mut admin, "DROP TRIGGER role_commit_delay ON public.role_permissions; DROP FUNCTION public.role_commit_delay()").await;
    store.set_role("healthy", &[All], deadline()).await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        store.set_role("healthy", &[All], deadline()).await,
        Err(ControlError::Closed)
    );
    monitor.close().await.unwrap();
    admin.close().await.unwrap();
}
