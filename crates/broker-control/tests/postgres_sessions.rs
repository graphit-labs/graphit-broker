mod support;
use broker_control::{
    ControlError, NewAdminSession, PostgresControlStore, SessionClaimRoles, SessionLimits,
    SessionPrincipal, SessionProfile, SessionRevocation,
};
use broker_security::TokenKind;
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use support::{Fixture, deadline, digester, n};
use zeroize::Zeroizing;
fn limits() -> SessionLimits {
    SessionLimits {
        text_bytes: n(8192),
        csrf_bytes: n(512),
        team_bytes: n(512),
        role_bytes: n(512),
        max_teams: n(8),
        max_roles: n(8),
        teams_json_bytes: n(1024),
        roles_json_bytes: n(1024),
        max_lifetime: Duration::from_secs(3600),
    }
}
fn input(ttl: Duration, claims: bool) -> NewAdminSession {
    NewAdminSession::new(
        SessionProfile {
            subject: "subject".into(),
            name: String::new(),
            email: String::new(),
        },
        SessionPrincipal {
            issuer: "issuer".into(),
            username: String::new(),
            organization: String::new(),
            teams: vec![" b ".into(), "a".into(), "a".into()],
            local_user_revision: 0,
        },
        Zeroizing::new("private-csrf".into()),
        claims.then(|| SessionClaimRoles {
            selector: " selector ".into(),
            roles: vec![" unknown ".into(), "Admin".into()],
        }),
        SystemTime::now() + ttl,
        &limits(),
    )
    .unwrap()
}
fn normal(claims: bool) -> NewAdminSession {
    input(Duration::from_secs(60), claims)
}
fn hash(token: &str) -> String {
    digester()
        .token(TokenKind::AdminSession, token.as_bytes())
        .unwrap()
        .to_sql_hex()
}
async fn counts(c: &mut sqlx_postgres::PgConnection) -> (i64, i64, i64) {
    sqlx_core::query_as::query_as("SELECT (SELECT count(*) FROM public.admin_sessions),(SELECT count(*) FROM public.admin_session_principals),(SELECT count(*) FROM public.admin_session_claim_roles)").fetch_one(c).await.unwrap()
}
async fn snapshot(c: &mut sqlx_postgres::PgConnection) -> String {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(s) ORDER BY token_hash) FROM public.admin_sessions s),(SELECT jsonb_agg(to_jsonb(p) ORDER BY token_hash) FROM public.admin_session_principals p),(SELECT jsonb_agg(to_jsonb(r) ORDER BY token_hash) FROM public.admin_session_claim_roles r))::text").fetch_one(c).await.unwrap()
}
async fn wait_query(c: &mut sqlx_postgres::PgConnection, needle: &str) {
    let capacity: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT pg_size_bytes(current_setting('track_activity_query_size'))",
    )
    .fetch_one(&mut *c)
    .await
    .unwrap();
    assert!(
        (needle.len() as i64) < capacity,
        "wait prefix must fit activity capture"
    );
    let end = deadline();
    loop {
        let n:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND state='active' AND query LIKE $1").bind(format!("%{needle}%")).fetch_one(&mut *c).await.unwrap();
        if n > 0 {
            return;
        }
        assert!(Instant::now() < end, "SQL wait point: {needle}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn execute(c: &mut sqlx_postgres::PgConnection, sql: String) {
    sqlx_core::raw_sql::raw_sql(sqlx_core::sql_str::AssertSqlSafe(sql))
        .execute(c)
        .await
        .unwrap();
}
async fn f1_roundtrip(f: &Fixture) {
    let store = f.open(2).await;
    let view = store.admin_sessions(limits()).unwrap();
    let mut c = f.connection().await;
    view.create_session("private-raw-token", &normal(true), deadline())
        .await
        .unwrap();
    let (a, b, d) = counts(&mut c).await;
    let tables = a + b + d;
    assert_eq!(tables, 3, "SESSION_TABLE_ORACLE");
    let before = snapshot(&mut c).await;
    assert!(!before.contains("private-raw-token"));
    assert!(before.contains(&hash("private-raw-token")));
    assert_ne!(
        hash("private-raw-token"),
        digester()
            .token(TokenKind::OidcFlowState, b"private-raw-token")
            .unwrap()
            .to_sql_hex()
    );
    let result = view.session("private-raw-token", deadline()).await.unwrap();
    assert_eq!(result.profile().subject, "subject");
    assert_eq!(result.profile().name, "");
    assert_eq!(result.principal().issuer, "issuer");
    assert_eq!(result.principal().teams, ["a", "b"]);
    assert_eq!(result.principal().local_user_revision, 0);
    assert_eq!(result.csrf_token(), "private-csrf");
    assert_eq!(result.claimed_roles().unwrap().roles, ["Admin", "unknown"]);
    assert_eq!(result.claimed_roles().unwrap().selector, " selector ");
    assert!(result.created_at().as_i64() > 0);
    assert!(result.expires_at() > result.created_at());
    assert!(!format!("{result:?}").contains("private-csrf"));
    assert!(!format!("{view:?}").contains("private"));
    assert!(matches!(
        view.create_session("private-raw-token", &normal(false), deadline())
            .await,
        Err(ControlError::SessionExists)
    ));
    assert_eq!(snapshot(&mut c).await, before);
    let mut strict = limits();
    strict.max_teams = n(1);
    let restricted = store.admin_sessions(strict).unwrap();
    assert_eq!(
        restricted
            .create_session("strict", &normal(false), deadline())
            .await,
        Err(ControlError::InvalidSession)
    );
    assert!(matches!(
        restricted.session("private-raw-token", deadline()).await,
        Err(ControlError::CorruptSession)
    ));
    assert_eq!(snapshot(&mut c).await, before);
    assert_eq!(
        view.create_session("", &normal(false), deadline()).await,
        Err(ControlError::InvalidSession)
    );
    assert_eq!(
        view.create_session(&"x".repeat(257), &normal(false), deadline())
            .await,
        Err(ControlError::InvalidSession)
    );
    let local = NewAdminSession::new(
        SessionProfile {
            subject: "opaque-local".into(),
            name: "Local Admin".into(),
            email: "admin@example.test".into(),
        },
        SessionPrincipal {
            issuer: "https://broker.example.test".into(),
            username: "admin".into(),
            organization: "Example".into(),
            teams: vec!["team".into()],
            local_user_revision: 42,
        },
        Zeroizing::new("local-csrf".into()),
        None,
        SystemTime::now() + Duration::from_secs(60),
        &limits(),
    )
    .unwrap();
    view.create_session("no-claims", &local, deadline())
        .await
        .unwrap();
    let local_result = view.session("no-claims", deadline()).await.unwrap();
    assert!(local_result.claimed_roles().is_none());
    assert_eq!(local_result.profile().subject, "opaque-local");
    assert_eq!(local_result.profile().name, "Local Admin");
    assert_eq!(local_result.profile().email, "admin@example.test");
    assert_eq!(local_result.principal().username, "admin");
    assert_eq!(local_result.principal().organization, "Example");
    assert_eq!(local_result.principal().local_user_revision, 42);
    assert_eq!(local_result.principal().teams, ["team"]);
    assert_eq!(local_result.csrf_token(), "local-csrf");
    let users: i64 =
        sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.local_users")
            .fetch_one(&mut c)
            .await
            .unwrap();
    assert_eq!(
        users, 0,
        "session metadata does not create/authenticate a local identity"
    );
    let mut shorter = limits();
    shorter.max_lifetime = Duration::from_secs(1);
    assert_eq!(
        store
            .admin_sessions(shorter)
            .unwrap()
            .create_session("ttl-too-long", &normal(false), deadline())
            .await,
        Err(ControlError::InvalidSession)
    );
    assert_eq!(counts(&mut c).await, (2, 2, 1));
    assert_eq!(
        view.revoke_session("private-raw-token", deadline())
            .await
            .unwrap(),
        SessionRevocation::Revoked
    );
    assert_eq!(
        view.revoke_session("private-raw-token", deadline())
            .await
            .unwrap(),
        SessionRevocation::Absent
    );
    assert!(matches!(
        view.session("private-raw-token", deadline()).await,
        Err(ControlError::SessionUnavailable)
    ));
    assert_eq!(counts(&mut c).await, (1, 1, 0));
    assert_eq!(
        view.revoke_session("no-claims", deadline()).await.unwrap(),
        SessionRevocation::Revoked
    );
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
async fn f2_atomic_faults(f: &Fixture) {
    f.reset().await;
    let mut role = f.connection().await;
    role.execute("ALTER ROLE postgres SET default_transaction_isolation='repeatable read'")
        .await
        .unwrap();
    role.close().await.unwrap();
    let store = f.open(1).await;
    let view = store.admin_sessions(limits()).unwrap();
    let mut c = f.connection().await;
    c.execute("CREATE FUNCTION public.session_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned fixture'; END $$; CREATE FUNCTION public.session_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").await.unwrap();
    for table in [
        "admin_sessions",
        "admin_session_principals",
        "admin_session_claim_roles",
    ] {
        for mode in ["session_fault", "session_suppress"] {
            execute(&mut c,format!("CREATE TRIGGER session_fault BEFORE INSERT ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.{mode}()")).await;
            assert_eq!(
                view.create_session("fault", &normal(true), deadline())
                    .await,
                Err(ControlError::Storage)
            );
            assert_eq!(counts(&mut c).await, (0, 0, 0));
            execute(
                &mut c,
                format!("DROP TRIGGER session_fault ON public.{table}"),
            )
            .await;
            view.create_session("healthy", &normal(true), deadline())
                .await
                .unwrap();
            view.revoke_session("healthy", deadline()).await.unwrap();
        }
    }
    c.execute("CREATE CONSTRAINT TRIGGER session_fault AFTER INSERT ON public.admin_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.session_fault()").await.unwrap();
    assert_eq!(
        view.create_session("commit-error", &normal(true), deadline())
            .await,
        Err(ControlError::OutcomeUncertain)
    );
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    c.execute("DROP TRIGGER session_fault ON public.admin_sessions; DROP FUNCTION public.session_fault(); DROP FUNCTION public.session_suppress(); CREATE FUNCTION public.session_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$; CREATE TRIGGER session_wait BEFORE INSERT ON public.admin_session_principals FOR EACH ROW EXECUTE FUNCTION public.session_wait()").await.unwrap();
    assert_eq!(
        view.create_session(
            "expired-before-commit",
            &input(Duration::from_millis(200), true),
            deadline()
        )
        .await,
        Err(ControlError::SessionExpired)
    );
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    c.execute("DROP TRIGGER session_wait ON public.admin_session_principals; DROP FUNCTION public.session_wait(); CREATE FUNCTION public.session_isolation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF current_setting('transaction_isolation') != 'read committed' THEN RAISE EXCEPTION 'wrong isolation'; END IF; RETURN NEW; END $$; CREATE TRIGGER session_isolation BEFORE INSERT ON public.admin_sessions FOR EACH ROW EXECUTE FUNCTION public.session_isolation()").await.unwrap();
    view.create_session("healthy", &normal(true), deadline())
        .await
        .unwrap();
    view.revoke_session("healthy", deadline()).await.unwrap();
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
async fn f3_corruption_expiry(f: &Fixture) {
    f.reset().await;
    let store = Arc::new(f.open(2).await);
    let view = store.admin_sessions(limits()).unwrap();
    let mut c = f.connection().await;
    for mutation in [
        "UPDATE admin_sessions SET subject=''",
        "UPDATE admin_sessions SET subject=repeat('x',9000)",
        "UPDATE admin_sessions SET email=repeat('x',9000)",
        "UPDATE admin_sessions SET name=repeat('é',513)",
        "UPDATE admin_sessions SET name=repeat('x',9000)",
        "UPDATE admin_sessions SET csrf_token=''",
        "UPDATE admin_sessions SET csrf_token=repeat('x',513)",
        "UPDATE admin_sessions SET created_at=-1",
        "UPDATE admin_sessions SET expires_at=created_at",
        "UPDATE admin_sessions SET expires_at=created_at+3600000001",
        "UPDATE admin_sessions SET created_at=expires_at-1",
        "UPDATE admin_sessions SET created_at=1,expires_at=2; UPDATE admin_session_principals SET issuer=''",
        "DELETE FROM admin_session_principals",
        "UPDATE admin_session_principals SET issuer=''",
        "UPDATE admin_session_principals SET issuer=repeat('x',9000)",
        "UPDATE admin_session_principals SET teams_json='[\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\"]'",
        "UPDATE admin_session_principals SET teams_json='[\"'||repeat('x',513)||'\"]'",
        "UPDATE admin_session_principals SET username=repeat('x',9000)",
        "UPDATE admin_session_principals SET organization=repeat('x',9000)",
        "UPDATE admin_session_principals SET local_user_revision=-1",
        "UPDATE admin_session_principals SET teams_json='{}'",
        "UPDATE admin_session_principals SET teams_json='[null]'",
        "UPDATE admin_session_principals SET teams_json='[1]'",
        "UPDATE admin_session_principals SET teams_json='[\"a\"] trailing'",
        "UPDATE admin_session_principals SET teams_json='[\" b \"]'",
        "UPDATE admin_session_principals SET teams_json='[\"b\",\"a\"]'",
        "UPDATE admin_session_principals SET teams_json='[\"a\",\"a\"]'",
        "UPDATE admin_session_principals SET teams_json='[\"a\\u0000\"]'",
        "UPDATE admin_session_principals SET teams_json=repeat('x',10000)",
        "UPDATE admin_session_claim_roles SET claim_selector=''",
        "UPDATE admin_session_claim_roles SET claim_selector=repeat('x',9000)",
        "UPDATE admin_session_claim_roles SET roles_json='[\"a\",\"a\"]'",
        "UPDATE admin_session_claim_roles SET roles_json=repeat('x',10000)",
        "UPDATE admin_session_claim_roles SET roles_json='[\"'||repeat('é',129)||'\"]'",
    ] {
        view.create_session("corrupt", &normal(true), deadline())
            .await
            .unwrap();
        c.execute("ALTER TABLE admin_sessions ALTER COLUMN name TYPE text, ALTER COLUMN csrf_token TYPE text, ALTER COLUMN subject TYPE text, ALTER COLUMN email TYPE text; ALTER TABLE admin_session_principals ALTER COLUMN username TYPE text, ALTER COLUMN organization TYPE text, ALTER COLUMN issuer TYPE text; ALTER TABLE admin_session_claim_roles ALTER COLUMN claim_selector TYPE text").await.unwrap();
        sqlx_core::raw_sql::raw_sql(mutation)
            .execute(&mut c)
            .await
            .unwrap();
        let before = snapshot(&mut c).await;
        assert!(
            matches!(
                view.session("corrupt", deadline()).await,
                Err(ControlError::CorruptSession)
            ),
            "{mutation}"
        );
        assert_eq!(snapshot(&mut c).await, before, "corruption preserved");
        assert_eq!(
            view.revoke_session("corrupt", deadline()).await.unwrap(),
            SessionRevocation::Revoked
        );
        assert_eq!(counts(&mut c).await, (0, 0, 0));
    }
    view.create_session("other", &normal(true), deadline())
        .await
        .unwrap();
    view.create_session("expired", &normal(true), deadline())
        .await
        .unwrap();
    let h = hash("expired");
    sqlx_core::query::query(
        "UPDATE admin_sessions SET created_at=1,expires_at=2 WHERE token_hash=$1",
    )
    .bind(&h)
    .execute(&mut c)
    .await
    .unwrap();
    assert!(matches!(
        view.session("wrong", deadline()).await,
        Err(ControlError::SessionUnavailable)
    ));
    assert_eq!(counts(&mut c).await, (2, 2, 2));
    assert!(matches!(
        view.session("expired", deadline()).await,
        Err(ControlError::SessionExpired)
    ));
    assert_eq!(counts(&mut c).await, (1, 1, 1));
    assert!(view.session("other", deadline()).await.is_ok());
    view.revoke_session("other", deadline()).await.unwrap();
    view.create_session(
        "waiting-expiry",
        &input(Duration::from_millis(300), true),
        deadline(),
    )
    .await
    .unwrap();
    let mut tx = c.begin().await.unwrap();
    sqlx_core::query::query("SELECT token_hash FROM admin_sessions WHERE token_hash=$1 FOR UPDATE")
        .bind(hash("waiting-expiry"))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let s = store.clone();
    let waiting = tokio::spawn(async move {
        s.admin_sessions(limits())
            .unwrap()
            .session("waiting-expiry", deadline())
            .await
    });
    let mut monitor = f.connection().await;
    wait_query(
        &mut monitor,
        "SELECT CASE WHEN pg_catalog.octet_length(s.subject)",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    tx.commit().await.unwrap();
    assert!(matches!(
        waiting.await.unwrap(),
        Err(ControlError::SessionExpired)
    ));
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
    monitor.close().await.unwrap();
}
async fn f4_races_atomic_visibility(f: &Fixture) {
    f.reset().await;
    let store = Arc::new(f.open(2).await);
    let view = store.admin_sessions(limits()).unwrap();
    let mut c = f.connection().await;
    let mut monitor = f.connection().await;
    c.execute("CREATE FUNCTION public.session_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN NEW; END $$; CREATE TRIGGER session_pause BEFORE INSERT ON admin_session_principals FOR EACH ROW EXECUTE FUNCTION public.session_pause()").await.unwrap();
    let s = store.clone();
    let create = tokio::spawn(async move {
        s.admin_sessions(limits())
            .unwrap()
            .create_session("visibility", &normal(true), deadline())
            .await
    });
    wait_query(&mut monitor, "INSERT INTO public.admin_session_principals").await;
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    create.await.unwrap().unwrap();
    assert_eq!(counts(&mut c).await, (1, 1, 1));
    c.execute("DROP TRIGGER session_pause ON admin_session_principals; DROP FUNCTION public.session_pause()").await.unwrap();
    let (a, b) = tokio::join!(
        view.revoke_session("visibility", deadline()),
        view.revoke_session("visibility", deadline())
    );
    let mut results = [a.unwrap(), b.unwrap()];
    results.sort_by_key(|r| matches!(r, SessionRevocation::Absent));
    assert_eq!(
        results,
        [SessionRevocation::Revoked, SessionRevocation::Absent]
    );
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    view.create_session("race", &normal(true), deadline())
        .await
        .unwrap();
    let valid = view.session("race", deadline()).await.unwrap();
    assert_eq!(valid.profile().subject, "subject");
    let mut tx = c.begin().await.unwrap();
    sqlx_core::query::query("DELETE FROM admin_sessions WHERE token_hash=$1")
        .bind(hash("race"))
        .execute(&mut *tx)
        .await
        .unwrap();
    let s = store.clone();
    let read = tokio::spawn(async move {
        s.admin_sessions(limits())
            .unwrap()
            .session("race", deadline())
            .await
    });
    wait_query(
        &mut monitor,
        "SELECT CASE WHEN pg_catalog.octet_length(s.subject)",
    )
    .await;
    tx.commit().await.unwrap();
    assert!(matches!(
        read.await.unwrap(),
        Err(ControlError::SessionUnavailable)
    ));
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    // Expiry reading owns the parent lock through DELETE and terminal COMMIT.
    view.create_session("read-lock", &normal(true), deadline())
        .await
        .unwrap();
    sqlx_core::query::query(
        "UPDATE admin_sessions SET created_at=1,expires_at=2 WHERE token_hash=$1",
    )
    .bind(hash("read-lock"))
    .execute(&mut c)
    .await
    .unwrap();
    c.execute("CREATE FUNCTION public.read_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN OLD; END $$; CREATE TRIGGER read_pause BEFORE DELETE ON admin_sessions FOR EACH ROW EXECUTE FUNCTION public.read_pause()").await.unwrap();
    let s = store.clone();
    let read = tokio::spawn(async move {
        s.admin_sessions(limits())
            .unwrap()
            .session("read-lock", deadline())
            .await
    });
    wait_query(&mut monitor, "DELETE FROM public.admin_sessions").await;
    let s = store.clone();
    let revoke = tokio::spawn(async move {
        s.admin_sessions(limits())
            .unwrap()
            .revoke_session("read-lock", deadline())
            .await
    });
    let end = deadline();
    loop {
        let blocked:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND wait_event_type='Lock' AND query LIKE '%DELETE FROM public.admin_sessions%'").fetch_one(&mut monitor).await.unwrap();
        if blocked == 1 {
            break;
        }
        assert!(Instant::now() < end, "revocation blocked by session read");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(matches!(
        read.await.unwrap(),
        Err(ControlError::SessionExpired)
    ));
    assert_eq!(revoke.await.unwrap().unwrap(), SessionRevocation::Absent);
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    c.execute("DROP TRIGGER read_pause ON admin_sessions; DROP FUNCTION public.read_pause()")
        .await
        .unwrap();
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
    monitor.close().await.unwrap();
}
async fn warm(store: &PostgresControlStore) {
    let view = store.admin_sessions(limits()).unwrap();
    view.create_session("warm", &normal(true), deadline())
        .await
        .unwrap();
    view.revoke_session("warm", deadline()).await.unwrap();
}
async fn f5_lifecycle_uncertainty(f: &Fixture) {
    f.reset().await;
    let store = Arc::new(f.open(1).await);
    let view = store.admin_sessions(limits()).unwrap();
    let mut c = f.connection().await;
    let mut monitor = f.connection().await;
    view.create_session("locked", &normal(true), deadline())
        .await
        .unwrap();
    let mut tx = c.begin().await.unwrap();
    sqlx_core::query::query("SELECT token_hash FROM admin_sessions WHERE token_hash=$1 FOR UPDATE")
        .bind(hash("locked"))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert!(matches!(
        view.session("locked", Instant::now() - Duration::from_millis(1))
            .await,
        Err(ControlError::Deadline)
    ));
    let s = store.clone();
    let waiting = tokio::spawn(async move {
        s.admin_sessions(limits())
            .unwrap()
            .revoke_session("locked", deadline())
            .await
    });
    wait_query(&mut monitor, "DELETE FROM public.admin_sessions").await;
    assert!(matches!(
        view.session("locked", Instant::now() + Duration::from_millis(100))
            .await,
        Err(ControlError::Deadline)
    ));
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    tx.commit().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(view.session("locked", deadline()).await.is_ok());
    view.revoke_session("locked", deadline()).await.unwrap();
    c.execute("CREATE FUNCTION public.session_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$; CREATE TRIGGER session_delay BEFORE INSERT ON admin_sessions FOR EACH ROW EXECUTE FUNCTION public.session_delay()").await.unwrap();
    assert_eq!(
        view.create_session(
            "deadline",
            &normal(true),
            Instant::now() + Duration::from_millis(100)
        )
        .await,
        Err(ControlError::Deadline)
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    let s = store.clone();
    let cancelled = tokio::spawn(async move {
        s.admin_sessions(limits())
            .unwrap()
            .create_session("cancel-create", &normal(true), deadline())
            .await
    });
    wait_query(&mut monitor, "INSERT INTO public.admin_sessions").await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(counts(&mut c).await, (0, 0, 0));
    c.execute("DROP TRIGGER session_delay ON admin_sessions; DROP FUNCTION public.session_delay()")
        .await
        .unwrap();
    for deleting in [false, true] {
        warm(&store).await;
        if deleting {
            view.create_session("uncertain", &normal(true), deadline())
                .await
                .unwrap();
        }
        c.execute("CREATE FUNCTION public.session_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NULL; END $$").await.unwrap();
        let event = if deleting { "DELETE" } else { "INSERT" };
        execute(&mut c,format!("CREATE CONSTRAINT TRIGGER session_commit AFTER {event} ON admin_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.session_commit()")).await;
        let end = Instant::now() + Duration::from_millis(300);
        let result = if deleting {
            view.revoke_session("uncertain", end).await.map(|_| ())
        } else {
            view.create_session("uncertain", &normal(true), end).await
        };
        assert_eq!(result, Err(ControlError::OutcomeUncertain));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let state = counts(&mut c).await;
        assert!(
            state == (0, 0, 0) || state == (1, 1, 1),
            "uncertain outcome remains atomic"
        );
        c.execute(
            "DROP TRIGGER session_commit ON admin_sessions; DROP FUNCTION public.session_commit()",
        )
        .await
        .unwrap();
        view.revoke_session("uncertain", deadline()).await.unwrap();
    }
    for deleting in [false, true] {
        warm(&store).await;
        if deleting {
            view.create_session("disconnect", &normal(true), deadline())
                .await
                .unwrap();
        }
        c.execute("CREATE FUNCTION public.session_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NULL; END $$").await.unwrap();
        let event = if deleting { "DELETE" } else { "INSERT" };
        execute(&mut c,format!("CREATE CONSTRAINT TRIGGER session_commit AFTER {event} ON admin_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.session_commit()")).await;
        let s = store.clone();
        let operation = tokio::spawn(async move {
            let v = s.admin_sessions(limits()).unwrap();
            if deleting {
                v.revoke_session("disconnect", deadline()).await.map(|_| ())
            } else {
                v.create_session("disconnect", &normal(true), deadline())
                    .await
            }
        });
        let end = deadline();
        loop {
            let killed: Vec<bool> = sqlx_core::query_scalar::query_scalar(
                "WITH target AS MATERIALIZED (SELECT pid FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND query='COMMIT' AND state='active' AND wait_event='PgSleep') SELECT pg_terminate_backend(pid) FROM target",
            ).fetch_all(&mut monitor).await.unwrap();
            if !killed.is_empty() {
                assert_eq!(killed, [true]);
                break;
            }
            assert!(Instant::now() < end, "session COMMIT fault wait point");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            operation.await.unwrap(),
            Err(ControlError::OutcomeUncertain)
        );
        assert_eq!(
            counts(&mut c).await,
            if deleting { (1, 1, 1) } else { (0, 0, 0) }
        );
        c.execute(
            "DROP TRIGGER session_commit ON admin_sessions; DROP FUNCTION public.session_commit()",
        )
        .await
        .unwrap();
        view.revoke_session("disconnect", deadline()).await.unwrap();
    }
    c.execute("CREATE FUNCTION public.session_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.05); RETURN NULL; END $$; CREATE CONSTRAINT TRIGGER session_ack AFTER INSERT ON admin_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.session_ack()").await.unwrap();
    view.create_session("ack", &normal(true), deadline())
        .await
        .unwrap();
    assert!(view.session("ack", deadline()).await.is_ok());
    view.revoke_session("ack", deadline()).await.unwrap();
    c.execute("DROP TRIGGER session_ack ON admin_sessions; DROP FUNCTION public.session_ack()")
        .await
        .unwrap();
    view.create_session("shutdown", &normal(true), deadline())
        .await
        .unwrap();
    let mut tx = c.begin().await.unwrap();
    sqlx_core::query::query("SELECT token_hash FROM admin_sessions WHERE token_hash=$1 FOR UPDATE")
        .bind(hash("shutdown"))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let s = store.clone();
    let leased = tokio::spawn(async move {
        s.admin_sessions(limits())
            .unwrap()
            .revoke_session("shutdown", Instant::now() + Duration::from_millis(400))
            .await
    });
    wait_query(&mut monitor, "DELETE FROM public.admin_sessions").await;
    assert_eq!(
        store
            .shutdown(Instant::now() + Duration::from_millis(50))
            .await,
        Err(ControlError::Deadline)
    );
    assert!(matches!(
        view.session("shutdown", deadline()).await,
        Err(ControlError::Closed)
    ));
    assert_eq!(leased.await.unwrap(), Err(ControlError::Deadline));
    tx.commit().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(counts(&mut c).await, (1, 1, 1));
    c.close().await.unwrap();
    monitor.close().await.unwrap();
}
#[tokio::test]
#[ignore = "owned Docker PostgreSQL TLS fixture; explicit resource window"]
async fn postgres_admin_session_contract() {
    let start = Instant::now();
    let fixture = Fixture::new(true).await;
    eprintln!("Session F1 roundtrip");
    f1_roundtrip(&fixture).await;
    eprintln!("Session F2 atomic faults");
    f2_atomic_faults(&fixture).await;
    eprintln!("Session F3 corruption/expiry");
    f3_corruption_expiry(&fixture).await;
    eprintln!("Session F4 races/visibility");
    f4_races_atomic_visibility(&fixture).await;
    eprintln!("Session F5 lifecycle/uncertainty");
    f5_lifecycle_uncertainty(&fixture).await;
    drop(fixture);
    eprintln!(
        "PostgreSQL administrative sessions F1-F5 completed; owned container removed in {:?}",
        start.elapsed()
    );
}
