#[allow(
    dead_code,
    reason = "shared PostgreSQL support also serves other native suites"
)]
mod support;
use broker_control::{
    ConnectionLimits, ControlError, LocalPasswordEngine, LocalPasswordVerificationError,
    PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use broker_security::LocalPasswordHasher;
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};
use support::{Fixture, deadline, digester, n};
use zeroize::Zeroizing;

const PASSWORD: &str = "fixture-only native LOCAL password";
async fn fixture() -> (
    Fixture,
    Arc<PostgresControlStore>,
    Arc<LocalPasswordEngine>,
    PgConnection,
) {
    let fixture = Fixture::new(true).await;
    let mut admin = fixture.connection().await;
    admin.execute("CREATE ROLE password_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION password_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO password_owner").await.unwrap();
    let config = PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(fixture.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "password_owner".into(),
            Zeroizing::new("ephemeral-owner".into()),
        ),
        fixture.ca.clone(),
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
    let hasher = LocalPasswordHasher::new(Zeroizing::new(vec![29; 32].into_boxed_slice())).unwrap();
    let engine = Arc::new(
        LocalPasswordEngine::new(hasher, NonZeroUsize::new(1).unwrap(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='password_owner'",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert!(!superuser);
    (fixture, store, engine, admin)
}
async fn insert(admin: &mut PgConnection, username: &str, subject: &str, phc: &str, kind: &str) {
    sqlx_core::query::query("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'','','','[]',1,0,1,0,0)")
        .bind(username).bind(subject).bind(kind).bind(phc).execute(admin).await.unwrap();
}
async fn unauthenticated(
    store: &PostgresControlStore,
    engine: &LocalPasswordEngine,
    username: &str,
    password: &str,
) {
    let result = store
        .local_password_verifier(engine)
        .verify(username, password, deadline())
        .await;
    assert!(
        matches!(result, Err(LocalPasswordVerificationError::Unauthenticated)),
        "expected redacted authentication denial"
    );
}
async fn cleanup(fixture: Fixture, store: Arc<PostgresControlStore>, admin: PgConnection) {
    admin.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    fixture.shutdown().unwrap();
}
async fn current_human_step_and_closed_denials(
    store: &Arc<PostgresControlStore>,
    engine: &Arc<LocalPasswordEngine>,
    admin: &mut PgConnection,
) {
    let phc = engine.hash(PASSWORD, deadline()).await.unwrap();
    insert(&mut *admin, "alice", "alice-subject", &phc, "human").await;
    let verifier = store.local_password_verifier(engine);
    let proof = verifier
        .verify("alice", PASSWORD, deadline())
        .await
        .unwrap();
    assert_eq!(proof.username(), "alice");
    assert_eq!(proof.subject(), "alice-subject");
    assert_eq!(proof.revision(), 1);
    assert_eq!(proof.auth_method(), "local-password");
    assert!(!proof.password_change_required());
    assert!(proof.verified_at().as_i64() > 0);
    assert_eq!(format!("{proof:?}"), "VerifiedLocalPassword([REDACTED])");
    assert_eq!(
        format!("{verifier:?}"),
        "PostgresLocalPasswordVerifier([REDACTED])"
    );
    for input in [" \talice\n ", "\u{0085}alice\u{2003}"] {
        let trimmed = verifier.verify(input, PASSWORD, deadline()).await.unwrap();
        assert_eq!(trimmed.username(), "alice");
        assert_eq!(trimmed.subject(), "alice-subject");
    }
    insert(
        &mut *admin,
        "Alice",
        "case-preserved-subject",
        &phc,
        "human",
    )
    .await;
    let mixed_case = verifier
        .verify(" Alice ", PASSWORD, deadline())
        .await
        .unwrap();
    assert_eq!(mixed_case.username(), "Alice");
    assert_eq!(mixed_case.subject(), "case-preserved-subject");
    unauthenticated(store, engine, " \t\u{2003} ", PASSWORD).await;
    admin
        .execute("UPDATE public.local_users SET password_change_required=1 WHERE username='alice'")
        .await
        .unwrap();
    // Correct password only establishes this intermediate step, including
    // mandatory change; no session/OAuth credential is produced by this API.
    assert!(
        verifier
            .verify("alice", PASSWORD, deadline())
            .await
            .unwrap()
            .password_change_required()
    );
    unauthenticated(store, engine, "alice", "incorrect password").await;
    unauthenticated(store, engine, "missing", PASSWORD).await;
    unauthenticated(store, engine, "bad username", PASSWORD).await;
    unauthenticated(store, engine, "alice", &"x".repeat(4097)).await;
    insert(&mut *admin, "service", "service-subject", &phc, "service").await;
    unauthenticated(store, engine, "service", PASSWORD).await;
    for statement in [
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_users SET enabled=2 WHERE username='alice'",
        "UPDATE public.local_users SET enabled=1,password_change_required=2 WHERE username='alice'",
        "UPDATE public.local_users SET password_change_required=0,revision=0 WHERE username='alice'",
        "UPDATE public.local_users SET revision=1,password_hash='malformed' WHERE username='alice'",
    ] {
        admin.execute(statement).await.unwrap();
        unauthenticated(store, engine, "alice", PASSWORD).await;
    }
    sqlx_core::query::query(
        "UPDATE public.local_users SET password_hash=$1 WHERE username='alice'",
    )
    .bind(phc.as_str())
    .execute(&mut *admin)
    .await
    .unwrap();
    for subject in ["", " leading", "trailing ", "\u{2003}unicode"] {
        sqlx_core::query::query("UPDATE public.local_users SET subject=$1 WHERE username='alice'")
            .bind(subject)
            .execute(&mut *admin)
            .await
            .unwrap();
        unauthenticated(store, engine, "alice", PASSWORD).await;
    }
    admin.execute("UPDATE public.local_users SET subject='alice-subject',revision=2 WHERE username='alice'").await.unwrap();
    assert_eq!(
        verifier
            .verify("alice", PASSWORD, deadline())
            .await
            .unwrap()
            .revision(),
        2
    );
}
async fn final_lock_wait(admin: &mut PgConnection) {
    let end = deadline();
    loop {
        let waiting: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='password_owner' AND wait_event_type='Lock' AND query LIKE '%WHERE subject=$1 FOR SHARE')")
            .fetch_one(&mut *admin).await.unwrap();
        if waiting {
            return;
        }
        assert!(
            Instant::now() < end,
            "actual password revalidation row lock not observed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
fn verification(
    store: &Arc<PostgresControlStore>,
    engine: &Arc<LocalPasswordEngine>,
    original: Instant,
) -> tokio::task::JoinHandle<
    Result<broker_control::VerifiedLocalPassword, LocalPasswordVerificationError>,
> {
    let store = Arc::clone(store);
    let engine = Arc::clone(engine);
    tokio::spawn(async move {
        store
            .local_password_verifier(&engine)
            .verify("alice", PASSWORD, original)
            .await
    })
}
async fn revalidates_hash_revision_and_identity_after_kdf(
    fixture: &Fixture,
    store: &Arc<PostgresControlStore>,
    engine: &Arc<LocalPasswordEngine>,
    admin: &mut PgConnection,
) {
    let phc = engine.hash(PASSWORD, deadline()).await.unwrap();
    insert(&mut *admin, "alice", "alice-subject", &phc, "human").await;
    for statement in [
        "UPDATE public.local_users SET revision=revision+1 WHERE username='alice'",
        "UPDATE public.local_users SET password_hash='different-hash-without-revision' WHERE username='alice'",
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_users SET password_change_required=1 WHERE username='alice'",
    ] {
        sqlx_core::query::query("UPDATE public.local_users SET password_hash=$1,enabled=1,password_change_required=0 WHERE username='alice'")
            .bind(phc.as_str()).execute(&mut *admin).await.unwrap();
        let mut locking = fixture.connection().await;
        locking.execute("BEGIN").await.unwrap();
        locking.execute(statement).await.unwrap();
        let caller = verification(store, engine, deadline());
        final_lock_wait(&mut *admin).await;
        locking.execute("COMMIT").await.unwrap();
        assert!(matches!(
            caller.await.unwrap(),
            Err(LocalPasswordVerificationError::Unauthenticated)
        ));
        locking.close().await.unwrap();
    }
}
async fn permissions_deadline_cancel_and_owner_lifecycle(
    fixture: &Fixture,
    store: &Arc<PostgresControlStore>,
    engine: &Arc<LocalPasswordEngine>,
    admin: &mut PgConnection,
) {
    let phc = engine.hash(PASSWORD, deadline()).await.unwrap();
    insert(&mut *admin, "alice", "alice-subject", &phc, "human").await;
    admin
        .execute("REVOKE SELECT ON public.local_users FROM password_owner")
        .await
        .unwrap();
    assert!(matches!(
        store
            .local_password_verifier(engine)
            .verify("alice", PASSWORD, deadline())
            .await,
        Err(LocalPasswordVerificationError::Control(
            ControlError::Storage
        ))
    ));
    admin
        .execute("GRANT SELECT ON public.local_users TO password_owner")
        .await
        .unwrap();
    assert!(matches!(
        store
            .local_password_verifier(engine)
            .verify("alice", PASSWORD, Instant::now())
            .await,
        Err(LocalPasswordVerificationError::Control(
            ControlError::Deadline
        ))
    ));
    let mut locking = fixture.connection().await;
    locking.execute("BEGIN").await.unwrap();
    locking
        .execute("UPDATE public.local_users SET revision=revision+1 WHERE username='alice'")
        .await
        .unwrap();
    let caller = verification(store, engine, deadline());
    final_lock_wait(&mut *admin).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    locking.execute("ROLLBACK").await.unwrap();
    locking.close().await.unwrap();
    assert_eq!(
        store
            .local_password_verifier(engine)
            .verify("alice", PASSWORD, deadline())
            .await
            .unwrap()
            .revision(),
        1
    );

    let mut locking = fixture.connection().await;
    locking.execute("BEGIN").await.unwrap();
    locking
        .execute("UPDATE public.local_users SET revision=revision+1 WHERE username='alice'")
        .await
        .unwrap();
    let caller = verification(store, engine, Instant::now() + Duration::from_secs(3));
    final_lock_wait(&mut *admin).await;
    assert!(matches!(
        caller.await.unwrap(),
        Err(LocalPasswordVerificationError::Control(
            ControlError::Deadline
        ))
    ));
    locking.execute("ROLLBACK").await.unwrap();
    locking.close().await.unwrap();
    assert_eq!(
        store
            .local_password_verifier(engine)
            .verify("alice", PASSWORD, deadline())
            .await
            .unwrap()
            .revision(),
        1
    );
    store.shutdown(deadline()).await.unwrap();
    assert!(matches!(
        store
            .local_password_verifier(engine)
            .verify("alice", PASSWORD, deadline())
            .await,
        Err(LocalPasswordVerificationError::Control(
            ControlError::Closed
        ))
    ));
}

#[tokio::test]
#[ignore = "native ordinary PostgreSQL TLS, real password KDF, races and lifecycle"]
async fn postgres_password_native_contract() {
    let (fixture, store, engine, mut admin) = fixture().await;
    current_human_step_and_closed_denials(&store, &engine, &mut admin).await;
    admin
        .execute("DELETE FROM public.local_users")
        .await
        .unwrap();
    revalidates_hash_revision_and_identity_after_kdf(&fixture, &store, &engine, &mut admin).await;
    admin
        .execute("DELETE FROM public.local_users")
        .await
        .unwrap();
    permissions_deadline_cancel_and_owner_lifecycle(&fixture, &store, &engine, &mut admin).await;
    cleanup(fixture, store, admin).await;
}
