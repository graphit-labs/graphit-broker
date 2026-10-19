mod support;
use broker_control::{
    ConnectionLimits, ControlError, IdentityReadLimits, LocalIdentityKind, LocalIdentityRead,
    LocalIdentityReference, LocalIdentitySnapshot, LocalIdentityUnavailable, PostgresConfig,
    PostgresControlStore, PostgresCredentials, PostgresEndpoint, SystemAction,
};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant},
};
use support::{Fixture, deadline, digester, n};
use zeroize::Zeroizing;

fn limits() -> IdentityReadLimits {
    IdentityReadLimits {
        username_bytes: n(128),
        subject_bytes: n(512),
        role_bytes: n(128),
        roles: n(16),
        rows: n(64),
    }
}
async fn execute(c: &mut PgConnection, sql: &'static str) {
    sqlx_core::raw_sql::raw_sql(sql).execute(c).await.unwrap();
}
async fn insert(c: &mut PgConnection, username: &str, subject: &str, kind: &str) {
    sqlx_core::query::query("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES($1,$2,$3,'not-selected-phc','private-name','private-email','private-org','not-selected-json',1,0,1,0,0)")
        .bind(username).bind(subject).bind(kind).execute(c).await.unwrap();
}
async fn read(
    store: &PostgresControlStore,
    username: &str,
    subject: &str,
    revision: i64,
) -> Result<LocalIdentityRead, ControlError> {
    let limits = limits();
    let reference = LocalIdentityReference::new(username, subject, revision, &limits).unwrap();
    store
        .local_identities(limits)
        .unwrap()
        .read(&reference, deadline())
        .await
}
fn current(result: LocalIdentityRead) -> LocalIdentitySnapshot {
    match result {
        LocalIdentityRead::Current(value) => value,
        other => panic!("expected Current: {other:?}"),
    }
}
fn unavailable(result: LocalIdentityRead, expected: LocalIdentityUnavailable) {
    match result {
        LocalIdentityRead::Unavailable(value) => assert_eq!(value, expected),
        other => panic!("expected unavailable: {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires native PostgreSQL Docker"]
async fn postgres_identity_roundtrip_and_current_rbac() {
    let fixture = Fixture::new(true).await;
    fixture.reset().await;
    let store = fixture.open(2).await;
    let mut c = fixture.connection().await;
    insert(&mut c, "alice", "alice-subject", "human").await;
    insert(&mut c, "bot", "bot-subject", "service").await;
    let first = current(read(&store, "alice", "alice-subject", 1).await.unwrap());
    assert_eq!(first.username(), "alice");
    assert_eq!(first.subject(), "alice-subject");
    assert_eq!(first.kind(), LocalIdentityKind::Human);
    assert_eq!(first.roles(), ["user"]);
    assert!(first.allows(SystemAction::SessionRead));
    assert!(!first.allows(SystemAction::UsersWrite));
    assert_eq!(
        current(read(&store, "bot", "bot-subject", 1).await.unwrap()).kind(),
        LocalIdentityKind::Service
    );
    assert_eq!(format!("{first:?}"), "LocalIdentitySnapshot([REDACTED])");
    execute(&mut c,"INSERT INTO public.roles(name,created_at) VALUES('empty',0),('custom',0); INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','empty',0),('local|alice-subject','custom',0); INSERT INTO public.role_permissions(role,action) VALUES('custom','users.write')").await;
    let value = current(read(&store, "alice", "alice-subject", 1).await.unwrap());
    assert_eq!(value.roles(), ["custom", "empty", "user"]);
    assert!(value.allows(SystemAction::UsersWrite));
    assert!(value.allows(SystemAction::ProjectsRead));
    execute(&mut c,"DELETE FROM public.role_permissions WHERE role='user'; INSERT INTO public.role_permissions(role,action) VALUES('custom','*')").await;
    assert!(
        current(read(&store, "alice", "alice-subject", 1).await.unwrap())
            .allows(SystemAction::ConfigurationRead)
    );
    execute(&mut c,"DELETE FROM public.role_permissions WHERE role='custom'; ALTER TABLE public.role_assignments DISABLE TRIGGER ALL; INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','unknown',0); ALTER TABLE public.role_assignments ENABLE TRIGGER ALL").await;
    let empty = current(read(&store, "alice", "alice-subject", 1).await.unwrap());
    assert_eq!(empty.roles(), ["custom", "empty", "unknown", "user"]);
    assert!(empty.permissions().is_empty());
    unavailable(
        read(&store, "Alice", "alice-subject", 1).await.unwrap(),
        LocalIdentityUnavailable::Missing,
    );
    execute(
        &mut c,
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
    )
    .await;
    unavailable(
        read(&store, "alice", "alice-subject", 1).await.unwrap(),
        LocalIdentityUnavailable::Disabled,
    );
    execute(
        &mut c,
        "UPDATE public.local_users SET enabled=1,revision=2 WHERE username='alice'",
    )
    .await;
    unavailable(
        read(&store, "alice", "alice-subject", 1).await.unwrap(),
        LocalIdentityUnavailable::RevisionChanged,
    );
    unavailable(
        read(&store, "alice", "changed-subject", 2).await.unwrap(),
        LocalIdentityUnavailable::SubjectChanged,
    );
    execute(
        &mut c,
        "UPDATE public.local_users SET username='renamed' WHERE username='alice'",
    )
    .await;
    unavailable(
        read(&store, "alice", "alice-subject", 2).await.unwrap(),
        LocalIdentityUnavailable::Missing,
    );
    assert_eq!(
        current(read(&store, "renamed", "alice-subject", 2).await.unwrap()).revision(),
        2
    );
    execute(
        &mut c,
        "DELETE FROM public.local_users WHERE username='renamed'",
    )
    .await;
    unavailable(
        read(&store, "renamed", "alice-subject", 2).await.unwrap(),
        LocalIdentityUnavailable::Missing,
    );
    c.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "requires native PostgreSQL Docker"]
async fn postgres_identity_bounds_and_corruption() {
    let fixture = Fixture::new(true).await;
    let store = fixture.open(2).await;
    let mut c = fixture.connection().await;
    let long = "s".repeat(512);
    insert(&mut c, "long", &long, "human").await;
    assert_eq!(
        current(read(&store, "long", &long, 1).await.unwrap()).subject(),
        long
    );
    let unicode = "é".repeat(256);
    insert(&mut c, "unicode", &unicode, "service").await;
    sqlx_core::query::query(
        "INSERT INTO public.role_assignments(subject,role,created_at) VALUES($1,'admin',0)",
    )
    .bind(format!("local|{unicode}"))
    .execute(&mut c)
    .await
    .unwrap();
    assert!(
        current(read(&store, "unicode", &unicode, 1).await.unwrap())
            .allows(SystemAction::UsersWrite)
    );
    insert(&mut c, "alice", "alice-subject", "human").await;
    let reference = LocalIdentityReference::new("alice", "alice-subject", 1, &limits()).unwrap();
    let mut small = limits();
    small.subject_bytes = n(5);
    assert_eq!(
        store
            .local_identities(small)
            .unwrap()
            .read(&reference, deadline())
            .await
            .unwrap_err(),
        ControlError::InvalidIdentity
    );
    let mut small = limits();
    small.rows = n(1);
    assert_eq!(
        store
            .local_identities(small)
            .unwrap()
            .read(&reference, deadline())
            .await
            .unwrap_err(),
        ControlError::IdentityLimitExceeded
    );
    execute(&mut c,"INSERT INTO public.roles(name,created_at) VALUES('empty',0); INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','empty',0)").await;
    let mut small = limits();
    small.roles = n(1);
    assert_eq!(
        store
            .local_identities(small)
            .unwrap()
            .read(&reference, deadline())
            .await
            .unwrap_err(),
        ControlError::IdentityLimitExceeded
    );
    execute(
        &mut c,
        "ALTER TABLE public.local_users ALTER COLUMN enabled DROP NOT NULL",
    )
    .await;
    for corrupt in [
        "UPDATE public.local_users SET enabled=2 WHERE username='alice'",
        "UPDATE public.local_users SET enabled=NULL WHERE username='alice'",
        "UPDATE public.local_users SET identity_kind='unknown' WHERE username='alice'",
        "UPDATE public.local_users SET revision=0 WHERE username='alice'",
        "UPDATE public.local_users SET subject=' untrimmed' WHERE username='alice'",
    ] {
        execute(&mut c, corrupt).await;
        assert_eq!(
            read(&store, "alice", "alice-subject", 1).await.unwrap_err(),
            ControlError::CorruptIdentity
        );
        execute(&mut c,"UPDATE public.local_users SET enabled=1,identity_kind='human',revision=1,subject='alice-subject' WHERE username='alice'").await;
    }
    execute(
        &mut c,
        "INSERT INTO public.role_permissions(role,action) VALUES('empty','invalid.action')",
    )
    .await;
    assert_eq!(
        read(&store, "alice", "alice-subject", 1).await.unwrap_err(),
        ControlError::CorruptRbac
    );
    execute(&mut c,"DELETE FROM public.role_permissions WHERE role='empty'; ALTER TABLE public.role_permissions ALTER COLUMN action TYPE TEXT; INSERT INTO public.role_permissions(role,action) VALUES('empty',repeat('x',129))").await;
    assert_eq!(
        read(&store, "alice", "alice-subject", 1).await.unwrap_err(),
        ControlError::CorruptRbac
    );
    execute(
        &mut c,
        "DELETE FROM public.role_permissions WHERE role='empty'",
    )
    .await;
    let permission_key: String = sqlx_core::query_scalar::query_scalar(
        "SELECT conname::text FROM pg_catalog.pg_constraint WHERE conrelid='public.role_permissions'::regclass AND contype='p'",
    ).fetch_one(&mut c).await.unwrap();
    let quoted_key = permission_key.replace('"', "\"\"");
    sqlx_core::raw_sql::raw_sql(sqlx_core::sql_str::AssertSqlSafe(format!(
        "ALTER TABLE public.role_permissions DROP CONSTRAINT \"{quoted_key}\""
    )))
    .execute(&mut c)
    .await
    .unwrap();
    execute(&mut c, "ALTER TABLE public.role_permissions ALTER COLUMN action DROP NOT NULL; INSERT INTO public.role_permissions(role,action) VALUES('empty',NULL)").await;
    assert_eq!(
        read(&store, "alice", "alice-subject", 1).await.unwrap_err(),
        ControlError::CorruptRbac
    );
    execute(&mut c,"DELETE FROM public.role_permissions WHERE role='empty'; ALTER TABLE public.local_users ALTER COLUMN subject TYPE TEXT; UPDATE public.local_users SET subject=repeat('s',513) WHERE username='alice'").await;
    assert_eq!(
        read(&store, "alice", "alice-subject", 1).await.unwrap_err(),
        ControlError::CorruptIdentity
    );
    execute(
        &mut c,
        "UPDATE public.local_users SET subject='alice-subject' WHERE username='alice'",
    )
    .await;
    let mut small = limits();
    small.role_bytes = n(4);
    assert_eq!(
        store
            .local_identities(small)
            .unwrap()
            .read(&reference, deadline())
            .await
            .unwrap_err(),
        ControlError::CorruptRbac
    );
    let excluded: (String, String) = sqlx_core::query_as::query_as(
        "SELECT password_hash,teams_json FROM public.local_users WHERE username='alice'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(
        excluded,
        ("not-selected-phc".into(), "not-selected-json".into())
    );
    c.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "requires native PostgreSQL Docker"]
async fn postgres_identity_atomic_writer_snapshot() {
    let fixture = Fixture::new(true).await;
    let store = fixture.open(2).await;
    let mut c = fixture.connection().await;
    insert(&mut c, "alice", "alice-subject", "human").await;
    execute(&mut c,"INSERT INTO public.roles(name,created_at) VALUES('version1',0),('version2',0); INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','version1',0)").await;
    // An uncommitted atomic update must leave the old identity and role visible together.
    let mut held = fixture.connection().await;
    let mut held_tx = held.begin().await.unwrap();
    held_tx.execute("UPDATE public.local_users SET revision=2 WHERE username='alice'; DELETE FROM public.role_assignments WHERE subject='local|alice-subject'; INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','version2',0)").await.unwrap();
    assert_eq!(
        current(read(&store, "alice", "alice-subject", 1).await.unwrap()).roles(),
        ["user", "version1"]
    );
    held_tx.commit().await.unwrap();
    assert_eq!(
        current(read(&store, "alice", "alice-subject", 2).await.unwrap()).roles(),
        ["user", "version2"]
    );
    held.close().await.unwrap();
    let mut writer = fixture.connection().await;
    let writing = tokio::spawn(async move {
        for revision in 3..=40i64 {
            let mut tx = writer.begin().await.unwrap();
            sqlx_core::query::query(
                "UPDATE public.local_users SET revision=$1 WHERE username='alice'",
            )
            .bind(revision)
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx_core::query::query(
                "DELETE FROM public.role_assignments WHERE subject='local|alice-subject'",
            )
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx_core::query::query("INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject',$1,0)")
                .bind(if revision%2==0 {"version2"} else {"version1"}).execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
        }
        writer.close().await.unwrap();
    });
    // Keep the public reference fixed; Current must retain the old matching identity and role.
    for _ in 0..40 {
        match read(&store, "alice", "alice-subject", 2).await.unwrap() {
            LocalIdentityRead::Current(value) => assert_eq!(value.roles(), ["user", "version2"]),
            LocalIdentityRead::Unavailable(value) => {
                assert_eq!(value, LocalIdentityUnavailable::RevisionChanged)
            }
        }
    }
    writing.await.unwrap();
    let final_value = current(read(&store, "alice", "alice-subject", 40).await.unwrap());
    assert_eq!(final_value.roles(), ["user", "version2"]);
    assert_eq!(final_value.revision(), 40);
    c.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
}

async fn wait_blocked(c: &mut PgConnection) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_catalog.pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND wait_event_type='Lock' AND query LIKE 'SELECT CASE WHEN pg_catalog.octet_length(u.username)%' LIMIT 1").fetch_optional(&mut *c).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "identity query must reach the actual PostgreSQL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn wait_clear(c: &mut PgConnection) {
    let end = deadline();
    loop {
        let count:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND wait_event_type='Lock'").fetch_one(&mut *c).await.unwrap();
        if count == 0 {
            return;
        }
        assert!(
            Instant::now() < end,
            "previous cancelled query must finish before the next fault"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "requires native PostgreSQL Docker"]
async fn postgres_identity_permissions_and_lifecycle() {
    let fixture = Fixture::new(true).await;
    let mut admin = fixture.connection().await;
    execute(&mut admin,"CREATE ROLE identity_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION identity_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO identity_owner").await;
    let config = PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(fixture.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "identity_owner".into(),
            Zeroizing::new("ephemeral-owner".into()),
        ),
        fixture.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(1),
        support::limits(),
    )
    .unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config, digester(), deadline())
            .await
            .unwrap(),
    );
    insert(&mut admin, "alice", "alice-subject", "human").await;
    current(read(&store, "alice", "alice-subject", 1).await.unwrap());
    execute(
        &mut admin,
        "REVOKE SELECT ON public.role_permissions FROM identity_owner",
    )
    .await;
    assert_eq!(
        read(&store, "alice", "alice-subject", 1).await.unwrap_err(),
        ControlError::Storage
    );
    execute(
        &mut admin,
        "GRANT SELECT ON public.role_permissions TO identity_owner",
    )
    .await;
    current(read(&store, "alice", "alice-subject", 1).await.unwrap());
    let mut locker = fixture.connection().await;
    let mut tx = locker.begin().await.unwrap();
    tx.execute("LOCK TABLE public.local_users IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let short_store = Arc::clone(&store);
    let timed = tokio::spawn(async move {
        let limits = limits();
        let reference = LocalIdentityReference::new("alice", "alice-subject", 1, &limits).unwrap();
        short_store
            .local_identities(limits)
            .unwrap()
            .read(&reference, Instant::now() + Duration::from_secs(2))
            .await
    });
    wait_blocked(&mut admin).await;
    assert_eq!(timed.await.unwrap().unwrap_err(), ControlError::Deadline);
    wait_clear(&mut admin).await;
    let cancel_store = Arc::clone(&store);
    let cancelled =
        tokio::spawn(async move { read(&cancel_store, "alice", "alice-subject", 1).await });
    wait_blocked(&mut admin).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    wait_clear(&mut admin).await;
    let kill_store = Arc::clone(&store);
    let killed = tokio::spawn(async move { read(&kill_store, "alice", "alice-subject", 1).await });
    let pid = wait_blocked(&mut admin).await;
    // Kill this SELECT backend, before COMMIT; never label this as lost COMMIT ACK.
    let terminated: bool =
        sqlx_core::query_scalar::query_scalar("SELECT pg_catalog.pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(&mut admin)
            .await
            .unwrap();
    assert!(terminated);
    assert_eq!(killed.await.unwrap().unwrap_err(), ControlError::Storage);
    tx.rollback().await.unwrap();
    locker.close().await.unwrap();
    current(read(&store, "alice", "alice-subject", 1).await.unwrap());
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        read(&store, "alice", "alice-subject", 1).await.unwrap_err(),
        ControlError::Closed
    );
    let principal: (bool, String) = sqlx_core::query_as::query_as(
        "SELECT rolsuper,rolname::text FROM pg_catalog.pg_roles WHERE rolname='identity_owner'",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(principal, (false, "identity_owner".into()));
    admin.close().await.unwrap();
}
