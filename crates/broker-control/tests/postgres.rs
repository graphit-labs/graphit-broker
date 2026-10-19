mod support;
use broker_control::{
    ControlError, FlowContinuation, InstanceInventory, InstanceOwner, InstanceProjectVersions,
    InstanceRegistrationError, InstanceRegistryError, LocalBearerKind, LocalBearerStateError,
    LocalBearerVerificationError, OidcFlow, PostgresControlStore, PresenceAuthorizationError,
    PresenceCapability, RegistrationChange, ResourceGrantReadError,
};
use broker_security::TokenKind;
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, digester, limits};

fn flow(seconds: u64) -> OidcFlow {
    OidcFlow::new(
        "internal-nonce".into(),
        "a".repeat(43),
        FlowContinuation::OAuth {
            provider_id: "provider".into(),
            request_id: "request".into(),
        },
        SystemTime::now() + Duration::from_secs(seconds),
        limits(),
    )
    .unwrap()
}
fn hash(state: &[u8]) -> String {
    digester()
        .token(TokenKind::OidcFlowState, state)
        .unwrap()
        .to_sql_hex()
}
async fn count(c: &mut sqlx_postgres::PgConnection) -> i64 {
    sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.oidc_flows")
        .fetch_one(c)
        .await
        .unwrap()
}
async fn snapshot(c: &mut sqlx_postgres::PgConnection) -> String {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(c) ORDER BY oid) FROM pg_class c WHERE relnamespace='public'::regnamespace),(SELECT jsonb_agg(to_jsonb(a) ORDER BY attrelid,attnum) FROM pg_attribute a WHERE attrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace)),(SELECT jsonb_agg(to_jsonb(c) ORDER BY oid) FROM pg_constraint c WHERE connamespace='public'::regnamespace),(SELECT jsonb_agg(to_jsonb(i) ORDER BY indexrelid) FROM pg_index i WHERE indrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace)),(SELECT jsonb_agg(to_jsonb(t) ORDER BY oid) FROM pg_trigger t WHERE tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace)),(SELECT jsonb_agg(to_jsonb(r) ORDER BY oid) FROM pg_rewrite r WHERE ev_class IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace)),(SELECT jsonb_agg(to_jsonb(r) ORDER BY name) FROM public.roles r),(SELECT jsonb_agg(to_jsonb(r) ORDER BY role,action) FROM public.role_permissions r),(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM public.resource_acl_state r))::text").fetch_one(c).await.unwrap()
}
async fn fresh_bootstrap_seeds_and_concurrent_open(f: &Fixture) {
    let mut c = f.connection().await;
    c.execute("ALTER ROLE postgres SET default_transaction_isolation='repeatable read'")
        .await
        .unwrap();
    c.close().await.unwrap();
    let (a, b) = tokio::join!(f.open(2), f.open(2));
    let mut c = f.connection().await;
    let tables: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(tables, 25, "PG_TABLE_ORACLE");
    let (admin,user):(i64,i64)=sqlx_core::query_as::query_as("SELECT (SELECT count(*) FROM role_permissions WHERE role='admin'),(SELECT count(*) FROM role_permissions WHERE role='user')").fetch_one(&mut c).await.unwrap();
    assert_eq!((admin, user), (9, 2));
    let version: (String, i64) =
        sqlx_core::query_as::query_as("SELECT format,epoch FROM schema_meta WHERE id=1")
            .fetch_one(&mut c)
            .await
            .unwrap();
    assert_eq!(version, ("rust-broker-v1".into(), 2));
    let stamp: i64 =
        sqlx_core::query_scalar::query_scalar("SELECT created_at FROM roles WHERE name='admin'")
            .fetch_one(&mut c)
            .await
            .unwrap();
    c.execute("INSERT INTO roles VALUES('custom',777); INSERT INTO role_permissions VALUES('custom','custom_action'); UPDATE resource_acl_state SET revision=42,updated_at=888; DELETE FROM role_permissions WHERE role='user'").await.unwrap();
    a.shutdown(deadline()).await.unwrap();
    b.shutdown(deadline()).await.unwrap();
    let reopened = f.open(1).await;
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT created_at FROM roles WHERE name='admin'"
        )
        .fetch_one(&mut c)
        .await
        .unwrap(),
        stamp
    );
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT count(*) FROM role_permissions WHERE role='user'"
        )
        .fetch_one(&mut c)
        .await
        .unwrap(),
        2
    );
    assert_eq!(
        sqlx_core::query_as::query_as::<_, (i64, i64)>(
            "SELECT revision,updated_at FROM resource_acl_state"
        )
        .fetch_one(&mut c)
        .await
        .unwrap(),
        (42, 888)
    );
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT created_at FROM roles WHERE name='custom'"
        )
        .fetch_one(&mut c)
        .await
        .unwrap(),
        777
    );
    // A child FK in another schema induces a real seed DELETE error after structural validation.
    c.execute("CREATE SCHEMA fault; CREATE TABLE fault.reference(role text,action text,FOREIGN KEY(role,action) REFERENCES public.role_permissions(role,action)); INSERT INTO fault.reference VALUES('admin','session.read')").await.unwrap();
    let before = snapshot(&mut c).await;
    assert!(matches!(
        PostgresControlStore::open(f.config(1), digester(), deadline()).await,
        Err(ControlError::Storage)
    ));
    assert_eq!(snapshot(&mut c).await, before);
    c.execute("DROP SCHEMA fault CASCADE").await.unwrap();
    reopened.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
async fn structural_rejection_is_atomic(f: &Fixture) {
    for mutation in [
        "CREATE RULE suppress_insert AS ON INSERT TO public.oidc_flows DO INSTEAD NOTHING",
        "CREATE RULE suppress_delete AS ON DELETE TO public.oidc_flows DO INSTEAD NOTHING",
        "UPDATE schema_meta SET epoch=1",
        "UPDATE schema_meta SET epoch=3",
        "DROP TABLE public.broker_instance_project_versions; DROP TABLE public.broker_instances; UPDATE schema_meta SET epoch=1",
        "DELETE FROM schema_meta",
        "CREATE TABLE public.extra(id int)",
        "DROP TABLE public.oidc_flows",
        "ALTER TABLE oidc_flows ALTER COLUMN nonce TYPE varchar(127)",
        "ALTER TABLE oidc_flows ALTER COLUMN nonce TYPE varchar(128) COLLATE \"C\"",
        "ALTER TABLE oidc_flows ADD COLUMN extra bigint GENERATED ALWAYS AS IDENTITY",
        "ALTER TABLE oidc_flows ADD COLUMN extra bigint GENERATED ALWAYS AS (expires_at-created_at) STORED",
        "CREATE UNIQUE INDEX nonce_unique ON oidc_flows(nonce)",
        "CREATE INDEX nonce_extra ON oidc_flows(nonce)",
        "CREATE INDEX partial_extra ON oidc_flows(nonce) WHERE expires_at>1",
        "ALTER TABLE oidc_flows ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE role_permissions DROP CONSTRAINT role_permissions_role_fkey; ALTER TABLE role_permissions ADD FOREIGN KEY(role) REFERENCES roles(name) ON DELETE RESTRICT",
        "ALTER TABLE role_permissions DISABLE TRIGGER ALL",
        "CREATE FUNCTION public.reject_row() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; CREATE TRIGGER foreign_trigger BEFORE INSERT ON oidc_flows FOR EACH ROW EXECUTE FUNCTION public.reject_row()",
        "ALTER TABLE oidc_flows ADD CHECK(expires_at>created_at) NOT VALID",
    ] {
        f.reset().await;
        let store = f.open(1).await;
        store.shutdown(deadline()).await.unwrap();
        let mut c = f.connection().await;
        sqlx_core::raw_sql::raw_sql(mutation)
            .execute(&mut c)
            .await
            .unwrap();
        let before = snapshot(&mut c).await;
        assert!(
            matches!(
                PostgresControlStore::open(f.config(1), digester(), deadline()).await,
                Err(ControlError::SchemaRejected)
            ),
            "structural rejection: {mutation}"
        );
        assert_eq!(snapshot(&mut c).await, before, "no public repair");
        c.close().await.unwrap();
    }
    f.reset().await;
    // Real DDL event fault: after several public tables exist, fail the next create.
    let mut c = f.connection().await;
    c.execute("CREATE SCHEMA fault; CREATE FUNCTION fault.fail_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace AND relname='roles') THEN RAISE EXCEPTION 'fixture ddl failure'; END IF; END $$; CREATE EVENT TRIGGER bootstrap_fault ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION fault.fail_ddl()").await.unwrap();
    assert!(matches!(
        PostgresControlStore::open(f.config(1), digester(), deadline()).await,
        Err(ControlError::Storage)
    ));
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace"
        )
        .fetch_one(&mut c)
        .await
        .unwrap(),
        0
    );
    c.execute("DROP EVENT TRIGGER bootstrap_fault; DROP SCHEMA fault CASCADE")
        .await
        .unwrap();
    c.close().await.unwrap();
    let good = f.open(1).await;
    good.shutdown(deadline()).await.unwrap();
}
async fn tls_rejects_downgrade_wrong_ca_host_and_auth(f: &Fixture) {
    for config in [
        f.config_fields("localhost", "ephemeral-fixture", f.ca.clone(), 1),
        f.config_fields("127.0.0.1", "wrong-password", f.ca.clone(), 1),
        f.config_fields(
            "127.0.0.1",
            "ephemeral-fixture",
            rcgen::CertificateParams::new(Vec::<String>::new())
                .unwrap()
                .self_signed(&rcgen::KeyPair::generate().unwrap())
                .unwrap()
                .pem()
                .into_bytes(),
            1,
        ),
    ] {
        assert!(matches!(
            PostgresControlStore::open(config, digester(), deadline()).await,
            Err(ControlError::Connection)
        ));
    }
    let plain = Fixture::new(false).await;
    assert!(matches!(
        PostgresControlStore::open(plain.config(1), digester(), deadline()).await,
        Err(ControlError::Connection)
    ));
}
async fn flow_domains_concurrency_and_corruption(f: &Fixture) {
    f.reset().await;
    let store = f.open(2).await;
    let mut c = f.connection().await;
    let state = b"raw-state-private";
    let binding = b"raw-binding-private";
    store
        .save_flow(state, binding, flow(60), deadline())
        .await
        .unwrap();
    let row: (String, String, String) = sqlx_core::query_as::query_as(
        "SELECT state_hash,browser_binding_hash,nonce FROM oidc_flows",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(row.0, hash(state));
    assert_eq!(
        row.1,
        digester()
            .token(TokenKind::OidcBrowserBinding, binding)
            .unwrap()
            .to_sql_hex()
    );
    assert_ne!(row.0, row.1);
    let before: String =
        sqlx_core::query_scalar::query_scalar("SELECT row_to_json(f)::text FROM oidc_flows f")
            .fetch_one(&mut c)
            .await
            .unwrap();
    assert!(!before.contains("raw-state-private") && !before.contains("raw-binding-private"));
    assert!(matches!(
        store.save_flow(state, binding, flow(40), deadline()).await,
        Err(ControlError::FlowExists)
    ));
    assert!(matches!(
        store.consume_flow(state, b"wrong", deadline()).await,
        Err(ControlError::Unavailable)
    ));
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, String>(
            "SELECT row_to_json(f)::text FROM oidc_flows f"
        )
        .fetch_one(&mut c)
        .await
        .unwrap(),
        before
    );
    let (a, b) = tokio::join!(
        store.consume_flow(state, binding, deadline()),
        store.consume_flow(state, binding, deadline())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(
        matches!(a, Err(ControlError::Unavailable)) || matches!(b, Err(ControlError::Unavailable))
    );
    assert_eq!(count(&mut c).await, 0);
    for mutation in [
        "nonce=''",
        "pkce_verifier='bad'",
        "purpose='other'",
        "continuation_json='{}'",
        "continuation_json='{\"provider_id\":\"p\",\"request_id\":\"r\",\"extra\":1}'",
        "created_at=expires_at+1",
        "created_at=expires_at-600000001",
        "created_at=expires_at-1",
        "continuation_json=repeat('x',10000)",
    ] {
        store
            .save_flow(state, binding, flow(60), deadline())
            .await
            .unwrap();
        let statement = format!("UPDATE oidc_flows SET {mutation}");
        sqlx_core::raw_sql::raw_sql(sqlx_core::sql_str::AssertSqlSafe(statement))
            .execute(&mut c)
            .await
            .unwrap();
        let before: String =
            sqlx_core::query_scalar::query_scalar("SELECT row_to_json(f)::text FROM oidc_flows f")
                .fetch_one(&mut c)
                .await
                .unwrap();
        assert!(
            matches!(
                store.consume_flow(state, binding, deadline()).await,
                Err(ControlError::CorruptFlow)
            ),
            "corruption {mutation}"
        );
        assert_eq!(
            sqlx_core::query_scalar::query_scalar::<_, String>(
                "SELECT row_to_json(f)::text FROM oidc_flows f"
            )
            .fetch_one(&mut c)
            .await
            .unwrap(),
            before
        );
        c.execute("DELETE FROM oidc_flows").await.unwrap();
    }
    assert!(matches!(
        store.save_flow(b"", binding, flow(60), deadline()).await,
        Err(ControlError::InvalidFlow)
    ));
    assert!(matches!(
        store.save_flow(state, binding, flow(601), deadline()).await,
        Err(ControlError::InvalidFlow)
    ));
    for expired in [false, true] {
        store
            .save_flow(state, binding, flow(60), deadline())
            .await
            .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        sqlx_core::query::query("UPDATE oidc_flows SET created_at=$1,expires_at=$2")
            .bind(now - 2000)
            .bind(if expired { now - 1 } else { now })
            .execute(&mut c)
            .await
            .unwrap();
        assert!(matches!(
            store.consume_flow(state, b"wrong", deadline()).await,
            Err(ControlError::Unavailable)
        ));
        assert_eq!(count(&mut c).await, 1);
        assert!(matches!(
            store.consume_flow(state, binding, deadline()).await,
            Err(ControlError::Expired)
        ));
        assert_eq!(count(&mut c).await, 0);
    }
    store
        .save_flow(state, binding, flow(1), deadline())
        .await
        .unwrap();
    let mut lock = c.begin().await.unwrap();
    lock.execute("SELECT * FROM oidc_flows FOR UPDATE")
        .await
        .unwrap();
    let release = async {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        lock.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(store.consume_flow(state, binding, deadline()), release);
    assert!(matches!(result, Err(ControlError::Expired)));
    assert_eq!(count(&mut c).await, 0);
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
async fn wait_for_query(c: &mut sqlx_postgres::PgConnection, needle: &str) {
    let end = deadline();
    loop {
        let n:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND state='active' AND query LIKE $1").bind(format!("%{needle}%")).fetch_one(&mut *c).await.unwrap();
        if n > 0 {
            return;
        }
        assert!(Instant::now() < end, "real SQL did not reach wait point");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn transaction_fault_cancel_commit_uncertainty_and_shutdown(f: &Fixture) {
    f.reset().await;
    let store = Arc::new(f.open(1).await);
    let mut c = f.connection().await;
    c.execute("CREATE FUNCTION public.suppress_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER suppress_insert BEFORE INSERT ON oidc_flows FOR EACH ROW EXECUTE FUNCTION public.suppress_insert()").await.unwrap();
    assert!(matches!(
        store
            .save_flow(b"suppressed", b"binding", flow(60), deadline())
            .await,
        Err(ControlError::Storage)
    ));
    assert_eq!(count(&mut c).await, 0);
    c.execute("DROP TRIGGER suppress_insert ON oidc_flows; DROP FUNCTION public.suppress_insert()")
        .await
        .unwrap();
    let state = b"fault-state";
    let binding = b"binding";
    store
        .save_flow(state, binding, flow(60), deadline())
        .await
        .unwrap();
    c.execute("CREATE FUNCTION public.fail_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'real sql fault'; END $$; CREATE TRIGGER fail_delete BEFORE DELETE ON oidc_flows FOR EACH ROW EXECUTE FUNCTION public.fail_delete()").await.unwrap();
    assert!(matches!(
        store.consume_flow(state, binding, deadline()).await,
        Err(ControlError::Storage)
    ));
    assert_eq!(count(&mut c).await, 1);
    c.execute("DROP TRIGGER fail_delete ON oidc_flows; DROP FUNCTION public.fail_delete()")
        .await
        .unwrap();
    let mut lock = c.begin().await.unwrap();
    lock.execute("SELECT * FROM oidc_flows FOR UPDATE")
        .await
        .unwrap();
    let s = store.clone();
    let task = tokio::spawn(async move { s.consume_flow(state, binding, deadline()).await });
    let mut monitor = f.connection().await;
    wait_for_query(&mut monitor, "FOR UPDATE").await;
    assert!(matches!(
        store
            .consume_flow(
                b"other",
                binding,
                Instant::now() + Duration::from_millis(60)
            )
            .await,
        Err(ControlError::Deadline)
    ));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    lock.commit().await.unwrap();
    assert_eq!(count(&mut c).await, 1);
    assert!(store.consume_flow(state, binding, deadline()).await.is_ok());
    assert!(matches!(
        store
            .save_flow(
                state,
                binding,
                flow(60),
                Instant::now() - Duration::from_millis(1)
            )
            .await,
        Err(ControlError::Deadline)
    ));
    // BEFORE INSERT wait proves deadline before COMMIT rolls back a save.
    c.execute("CREATE FUNCTION public.wait_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$; CREATE TRIGGER wait_insert BEFORE INSERT ON oidc_flows FOR EACH ROW EXECUTE FUNCTION public.wait_insert()").await.unwrap();
    assert!(matches!(
        store
            .save_flow(
                state,
                binding,
                flow(60),
                Instant::now() + Duration::from_millis(100)
            )
            .await,
        Err(ControlError::Deadline)
    ));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count(&mut c).await, 0);
    c.execute("DROP TRIGGER wait_insert ON oidc_flows; DROP FUNCTION public.wait_insert()")
        .await
        .unwrap();
    // Deferred triggers execute during actual COMMIT, not a mock phase.
    for event in ["INSERT", "DELETE"] {
        store
            .save_flow(b"warm", binding, flow(60), deadline())
            .await
            .unwrap();
        store
            .consume_flow(b"warm", binding, deadline())
            .await
            .unwrap();
        if event == "DELETE" {
            store
                .save_flow(state, binding, flow(60), deadline())
                .await
                .unwrap();
        }
        c.execute("CREATE FUNCTION public.wait_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1.0); RETURN NULL; END $$").await.unwrap();
        let statement = format!(
            "CREATE CONSTRAINT TRIGGER wait_commit AFTER {event} ON oidc_flows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.wait_commit()"
        );
        sqlx_core::raw_sql::raw_sql(sqlx_core::sql_str::AssertSqlSafe(statement))
            .execute(&mut c)
            .await
            .unwrap();
        let result = if event == "INSERT" {
            store
                .save_flow(
                    state,
                    binding,
                    flow(60),
                    Instant::now() + Duration::from_millis(300),
                )
                .await
        } else {
            store
                .consume_flow(state, binding, Instant::now() + Duration::from_millis(300))
                .await
                .map(|_| ())
        };
        assert!(
            matches!(result, Err(ControlError::OutcomeUncertain)),
            "actual {event} commit must be uncertain: {result:?}"
        );
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(
            count(&mut c).await,
            if event == "INSERT" { 1 } else { 0 },
            "observed eventual real DB result; caller did not replay"
        );
        c.execute("DROP TRIGGER wait_commit ON oidc_flows; DROP FUNCTION public.wait_commit()")
            .await
            .unwrap();
        if event == "INSERT" {
            store
                .consume_flow(state, binding, deadline())
                .await
                .unwrap();
        }
    }
    // A real server disconnect during COMMIT is uncertain too, even when the
    // fixture later confirms rollback. The public API cannot infer that outcome.
    for deleting in [false, true] {
        store
            .save_flow(b"warm", binding, flow(60), deadline())
            .await
            .unwrap();
        store
            .consume_flow(b"warm", binding, deadline())
            .await
            .unwrap();
        if deleting {
            store
                .save_flow(state, binding, flow(60), deadline())
                .await
                .unwrap();
        }
        c.execute("CREATE FUNCTION public.disconnect_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NULL; END $$").await.unwrap();
        let ddl = if deleting {
            "CREATE CONSTRAINT TRIGGER disconnect_commit AFTER DELETE ON oidc_flows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.disconnect_commit()"
        } else {
            "CREATE CONSTRAINT TRIGGER disconnect_commit AFTER INSERT ON oidc_flows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.disconnect_commit()"
        };
        c.execute(ddl).await.unwrap();
        let s = store.clone();
        let task = tokio::spawn(async move {
            if deleting {
                s.consume_flow(state, binding, deadline()).await.map(|_| ())
            } else {
                s.save_flow(state, binding, flow(60), deadline()).await
            }
        });
        wait_for_query(&mut monitor, "COMMIT").await;
        let killed: Vec<bool> = sqlx_core::query_scalar::query_scalar("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND query='COMMIT' AND state='active'").fetch_all(&mut monitor).await.unwrap();
        assert_eq!(killed, vec![true]);
        assert!(matches!(
            task.await.unwrap(),
            Err(ControlError::OutcomeUncertain)
        ));
        assert_eq!(count(&mut c).await, if deleting { 1 } else { 0 });
        c.execute("DROP TRIGGER disconnect_commit ON oidc_flows; DROP FUNCTION public.disconnect_commit()").await.unwrap();
        if deleting {
            store
                .consume_flow(state, binding, deadline())
                .await
                .unwrap();
        }
    }
    // Observe isolation inside a real write and require a confirmed deferred commit.
    c.execute("CREATE FUNCTION public.check_isolation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF current_setting('transaction_isolation')!='read committed' THEN RAISE EXCEPTION 'wrong isolation'; END IF; RETURN NEW; END $$; CREATE TRIGGER check_isolation BEFORE INSERT ON oidc_flows FOR EACH ROW EXECUTE FUNCTION public.check_isolation()").await.unwrap();
    store
        .save_flow(b"isolation", binding, flow(60), deadline())
        .await
        .unwrap();
    store
        .consume_flow(b"isolation", binding, deadline())
        .await
        .unwrap();
    c.execute("DROP TRIGGER check_isolation ON oidc_flows; DROP FUNCTION public.check_isolation(); CREATE FUNCTION public.confirmed_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.05); RETURN NULL; END $$; CREATE CONSTRAINT TRIGGER confirmed_commit AFTER INSERT ON oidc_flows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.confirmed_commit()").await.unwrap();
    store
        .save_flow(b"confirmed", binding, flow(60), deadline())
        .await
        .unwrap();
    store
        .consume_flow(b"confirmed", binding, deadline())
        .await
        .unwrap();
    c.execute(
        "DROP TRIGGER confirmed_commit ON oidc_flows; DROP FUNCTION public.confirmed_commit()",
    )
    .await
    .unwrap();
    // Isolation is explicit even for a role whose default is REPEATABLE READ.
    store
        .save_flow(state, binding, flow(60), deadline())
        .await
        .unwrap();
    let mut lock = c.begin().await.unwrap();
    lock.execute("SELECT * FROM oidc_flows FOR UPDATE")
        .await
        .unwrap();
    let s = store.clone();
    let task = tokio::spawn(async move {
        s.consume_flow(state, binding, Instant::now() + Duration::from_millis(500))
            .await
    });
    wait_for_query(&mut monitor, "FOR UPDATE").await;
    assert!(matches!(
        store
            .shutdown(Instant::now() + Duration::from_millis(40))
            .await,
        Err(ControlError::Deadline)
    ));
    assert!(matches!(
        store.consume_flow(b"new", binding, deadline()).await,
        Err(ControlError::Closed)
    ));
    assert!(matches!(task.await.unwrap(), Err(ControlError::Deadline)));
    lock.commit().await.unwrap();
    assert_eq!(count(&mut c).await, 1);
    store.shutdown(deadline()).await.unwrap();
    monitor.close().await.unwrap();
    c.close().await.unwrap();
}
#[tokio::test]
#[ignore = "owned Docker PostgreSQL TLS fixture; explicit resource window"]
async fn postgres_runtime_contract() {
    let start = Instant::now();
    let fixture = Fixture::new(true).await;
    fresh_bootstrap_seeds_and_concurrent_open(&fixture).await;
    structural_rejection_is_atomic(&fixture).await;
    tls_rejects_downgrade_wrong_ca_host_and_auth(&fixture).await;
    flow_domains_concurrency_and_corruption(&fixture).await;
    transaction_fault_cancel_commit_uncertainty_and_shutdown(&fixture).await;
    drop(fixture);
    eprintln!(
        "PostgreSQL TLS F1-F9 completed and owned containers removed in {:?}",
        start.elapsed()
    );
}
#[tokio::test]
async fn ambient_configuration_child() {
    if std::env::var_os("BROKER_TEST_AMBIENT_CHILD").is_none() {
        return;
    }
    let config = broker_control::PostgresConfig::new(
        broker_control::PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: std::num::NonZeroU16::new(1).unwrap(),
            database: "explicit".into(),
        },
        broker_control::PostgresCredentials::new(
            "explicit".into(),
            zeroize::Zeroizing::new("explicit".into()),
        ),
        b"explicit-pem".to_vec(),
        broker_control::ConnectionLimits {
            text_bytes: support::n(128),
            ca_bytes: support::n(128),
        },
        support::pool(1),
        limits(),
    )
    .unwrap();
    assert!(matches!(
        PostgresControlStore::open(config, digester(), deadline()).await,
        Err(ControlError::AmbientConfiguration)
    ));
}
#[test]
fn ambient_inputs_are_rejected_before_sdk_construction_in_subprocesses() {
    const VARS: [&str; 12] = [
        "PGPORT",
        "PGHOSTADDR",
        "PGHOST",
        "PGUSER",
        "PGDATABASE",
        "PGPASSWORD",
        "PGSSLROOTCERT",
        "PGSSLCERT",
        "PGSSLKEY",
        "PGSSLMODE",
        "PGAPPNAME",
        "PGOPTIONS",
    ];
    let child = || {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        for name in VARS {
            command.env_remove(name);
        }
        command
    };
    for name in VARS {
        for value in ["", "present"] {
            let result = child()
                .args(["--exact", "ambient_configuration_child"])
                .env("BROKER_TEST_AMBIENT_CHILD", "1")
                .env(name, value)
                .output()
                .unwrap();
            assert!(result.status.success(), "ambient presence rejected child");
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let result = child()
                .args(["--exact", "ambient_configuration_child"])
                .env("BROKER_TEST_AMBIENT_CHILD", "1")
                .env(name, std::ffi::OsString::from_vec(vec![0xff]))
                .output()
                .unwrap();
            assert!(result.status.success(), "non UTF8 ambient rejected child");
        }
    }
}

const REGISTRY_PROJECT_A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const REGISTRY_PROJECT_B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
fn instance_inventory(id: &str, projects: &[(&str, &[&str])]) -> InstanceInventory {
    InstanceInventory::new(
        id.into(),
        projects
            .iter()
            .map(|(project, versions)| {
                InstanceProjectVersions::new(
                    (*project).into(),
                    versions.iter().map(|v| (*v).into()).collect(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap()
}
#[derive(Debug, PartialEq)]
struct InstanceSqlSnapshot {
    parent: (String, String, i64, i64),
    versions: Vec<(String, i64, String)>,
}
async fn instance_sql_snapshot(
    c: &mut sqlx_postgres::PgConnection,
    id: &str,
) -> Option<InstanceSqlSnapshot> {
    let parent = sqlx_core::query_as::query_as("SELECT owner_issuer,owner_subject,created_at,updated_at FROM broker_instances WHERE instance_id=$1")
        .bind(id).fetch_optional(&mut *c).await.unwrap()?;
    let versions = sqlx_core::query_as::query_as("SELECT project_id,position,version FROM broker_instance_project_versions WHERE instance_id=$1 ORDER BY project_id COLLATE \"C\",position")
        .bind(id).fetch_all(&mut *c).await.unwrap();
    Some(InstanceSqlSnapshot { parent, versions })
}
#[tokio::test]
#[ignore = "real PostgreSQL installation inventory, owner races, rollback and cancellation"]
async fn postgres_instance_registry_contract() {
    let fixture = Fixture::new(true).await;
    let store = Arc::new(fixture.open(2).await);
    let mut c = fixture.connection().await;
    let mut monitor = fixture.connection().await;
    let owner = InstanceOwner::new("Issuer ", "Subject ").unwrap();
    let long = "界😀".repeat(10000);
    let original = instance_inventory(
        "station",
        &[
            (REGISTRY_PROJECT_B, &["main"]),
            (REGISTRY_PROJECT_A, &[&long, "release", "main"]),
        ],
    );
    let created = store
        .replace_instance_inventory(&owner, &original, deadline())
        .await
        .unwrap();
    assert_eq!(created.change(), RegistrationChange::Created);
    assert_eq!(created.instance_id(), "station");
    let snapshot = instance_sql_snapshot(&mut c, "station").await.unwrap();
    assert_eq!(
        (&snapshot.parent.0, &snapshot.parent.1),
        (&"Issuer ".to_owned(), &"Subject ".to_owned())
    );
    assert_eq!(snapshot.parent.2, created.created_at_micros());
    assert_eq!(snapshot.parent.3, created.updated_at_micros());
    assert_eq!(
        snapshot.versions,
        vec![
            (REGISTRY_PROJECT_A.into(), 1, "main".into()),
            (REGISTRY_PROJECT_A.into(), 2, "release".into()),
            (REGISTRY_PROJECT_A.into(), 3, long),
            (REGISTRY_PROJECT_B.into(), 1, "main".into())
        ]
    );
    store.shutdown(deadline()).await.unwrap();
    let store = Arc::new(fixture.open(2).await);
    assert_eq!(
        instance_sql_snapshot(&mut c, "station").await.unwrap(),
        snapshot
    );
    let unicode_owner = InstanceOwner::new(&"界".repeat(1024), &"😀".repeat(512)).unwrap();
    store
        .replace_instance_inventory(
            &unicode_owner,
            &instance_inventory("unicode-owner", &[]),
            deadline(),
        )
        .await
        .unwrap();
    let unicode = instance_sql_snapshot(&mut c, "unicode-owner")
        .await
        .unwrap();
    assert_eq!(
        (unicode.parent.0.as_str(), unicode.parent.1.as_str()),
        (unicode_owner.issuer(), unicode_owner.subject())
    );

    let replacement = instance_inventory("station", &[(REGISTRY_PROJECT_A, &["main", "feature"])]);
    let updated = store
        .replace_instance_inventory(&owner, &replacement, deadline())
        .await
        .unwrap();
    assert_eq!(updated.change(), RegistrationChange::Updated);
    assert_eq!(updated.created_at_micros(), created.created_at_micros());
    let before = instance_sql_snapshot(&mut c, "station").await.unwrap();
    assert_eq!(
        before.versions,
        vec![
            (REGISTRY_PROJECT_A.into(), 1, "feature".into()),
            (REGISTRY_PROJECT_A.into(), 2, "main".into())
        ]
    );
    let reordered = instance_inventory("station", &[(REGISTRY_PROJECT_A, &["feature", "main"])]);
    let noop = store
        .replace_instance_inventory(&owner, &reordered, deadline())
        .await
        .unwrap();
    assert_eq!(noop.change(), RegistrationChange::Unchanged);
    assert_eq!(noop.updated_at_micros(), updated.updated_at_micros());
    assert_eq!(
        instance_sql_snapshot(&mut c, "station").await.unwrap(),
        before
    );
    let empty = instance_inventory("station", &[]);
    assert_eq!(
        store
            .replace_instance_inventory(&owner, &empty, deadline())
            .await
            .unwrap()
            .change(),
        RegistrationChange::Updated
    );
    let empty_before = instance_sql_snapshot(&mut c, "station").await.unwrap();
    assert!(empty_before.versions.is_empty());
    assert_eq!(empty_before.parent.2, created.created_at_micros());
    assert_eq!(
        store
            .replace_instance_inventory(&owner, &empty, deadline())
            .await
            .unwrap()
            .change(),
        RegistrationChange::Unchanged
    );
    assert_eq!(
        instance_sql_snapshot(&mut c, "station").await.unwrap(),
        empty_before
    );
    for (issuer, subject) in [
        ("Issuer", "Subject "),
        ("issuer ", "Subject "),
        ("Issuer ", "Subject"),
        ("Issuer ", "subject "),
    ] {
        assert_eq!(
            store
                .replace_instance_inventory(
                    &InstanceOwner::new(issuer, subject).unwrap(),
                    &replacement,
                    deadline()
                )
                .await
                .unwrap_err(),
            InstanceRegistryError::OwnerConflict
        );
        assert_eq!(
            instance_sql_snapshot(&mut c, "station").await.unwrap(),
            empty_before
        );
    }
    let other = InstanceOwner::new("another-issuer", "another-subject").unwrap();
    let race_a = instance_inventory("first-race", &[(REGISTRY_PROJECT_A, &["main"])]);
    let race_b = instance_inventory("first-race", &[(REGISTRY_PROJECT_B, &["release"])]);
    let (a, b) = tokio::join!(
        store.replace_instance_inventory(&owner, &race_a, deadline()),
        store.replace_instance_inventory(&other, &race_b, deadline())
    );
    assert!(matches!(
        (&a, &b),
        (Ok(_), Err(InstanceRegistryError::OwnerConflict))
            | (Err(InstanceRegistryError::OwnerConflict), Ok(_))
    ));
    let raced = instance_sql_snapshot(&mut c, "first-race").await.unwrap();
    let expected = if a.is_ok() {
        (owner.issuer(), owner.subject(), REGISTRY_PROJECT_A, "main")
    } else {
        (
            other.issuer(),
            other.subject(),
            REGISTRY_PROJECT_B,
            "release",
        )
    };
    assert_eq!(
        (raced.parent.0.as_str(), raced.parent.1.as_str()),
        (expected.0, expected.1)
    );
    assert_eq!(
        raced.versions,
        vec![(expected.2.into(), 1, expected.3.into())]
    );
    let same_a = instance_inventory("same-race", &[(REGISTRY_PROJECT_A, &["a1", "a2"])]);
    let same_b = instance_inventory("same-race", &[(REGISTRY_PROJECT_B, &["b1", "b2"])]);
    let (a, b) = tokio::join!(
        store.replace_instance_inventory(&owner, &same_a, deadline()),
        store.replace_instance_inventory(&owner, &same_b, deadline())
    );
    assert!(a.is_ok() && b.is_ok());
    let raced = instance_sql_snapshot(&mut c, "same-race").await.unwrap();
    assert!(
        raced.versions
            == vec![
                (REGISTRY_PROJECT_A.into(), 1, "a1".into()),
                (REGISTRY_PROJECT_A.into(), 2, "a2".into())
            ]
            || raced.versions
                == vec![
                    (REGISTRY_PROJECT_B.into(), 1, "b1".into()),
                    (REGISTRY_PROJECT_B.into(), 2, "b2".into())
                ]
    );

    let baseline = instance_inventory("station", &[(REGISTRY_PROJECT_A, &["main", "release"])]);
    store
        .replace_instance_inventory(&owner, &baseline, deadline())
        .await
        .unwrap();
    let before = instance_sql_snapshot(&mut c, "station").await.unwrap();
    c.execute("ALTER TABLE broker_instance_project_versions ADD CONSTRAINT registry_fault CHECK(version <> 'zz-fault')").await.unwrap();
    let failed = instance_inventory(
        "station",
        &[(REGISTRY_PROJECT_A, &["aa-valid", "zz-fault"])],
    );
    assert_eq!(
        store
            .replace_instance_inventory(&owner, &failed, deadline())
            .await
            .unwrap_err(),
        InstanceRegistryError::Control(ControlError::Storage)
    );
    assert_eq!(
        instance_sql_snapshot(&mut c, "station").await.unwrap(),
        before
    );
    c.execute("ALTER TABLE broker_instance_project_versions DROP CONSTRAINT registry_fault")
        .await
        .unwrap();
    for suppress_trigger in [
        "CREATE TRIGGER registry_suppress BEFORE INSERT ON broker_instance_project_versions FOR EACH ROW EXECUTE FUNCTION public.registry_suppress()",
        "CREATE TRIGGER registry_suppress BEFORE DELETE ON broker_instance_project_versions FOR EACH ROW EXECUTE FUNCTION public.registry_suppress()",
    ] {
        c.execute("CREATE FUNCTION public.registry_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").await.unwrap();
        c.execute(suppress_trigger).await.unwrap();
        assert_eq!(
            store
                .replace_instance_inventory(&owner, &replacement, deadline())
                .await
                .unwrap_err(),
            InstanceRegistryError::Control(ControlError::Storage)
        );
        assert_eq!(
            instance_sql_snapshot(&mut c, "station").await.unwrap(),
            before
        );
        c.execute("DROP TRIGGER registry_suppress ON broker_instance_project_versions; DROP FUNCTION public.registry_suppress()").await.unwrap();
    }
    for (corrupt, restore) in [
        (
            "UPDATE broker_instance_project_versions SET position=3 WHERE instance_id='station' AND position=2",
            "UPDATE broker_instance_project_versions SET position=2 WHERE instance_id='station' AND position=3",
        ),
        (
            "UPDATE broker_instance_project_versions SET version='main' WHERE instance_id='station' AND position=2",
            "UPDATE broker_instance_project_versions SET version='release' WHERE instance_id='station' AND position=2",
        ),
        (
            "UPDATE broker_instance_project_versions SET project_id='' WHERE instance_id='station'",
            "UPDATE broker_instance_project_versions SET project_id='01D39ZY06FGSCTVN4T2V9PKHFZ' WHERE instance_id='station'",
        ),
        (
            "UPDATE broker_instance_project_versions SET project_id='00000000000000000000000000' WHERE instance_id='station'",
            "UPDATE broker_instance_project_versions SET project_id='01D39ZY06FGSCTVN4T2V9PKHFZ' WHERE instance_id='station'",
        ),
        (
            "UPDATE broker_instance_project_versions SET version=' main' WHERE instance_id='station' AND position=1",
            "UPDATE broker_instance_project_versions SET version='main' WHERE instance_id='station' AND position=1",
        ),
        (
            "UPDATE broker_instances SET owner_issuer='' WHERE instance_id='station'",
            "UPDATE broker_instances SET owner_issuer='Issuer ' WHERE instance_id='station'",
        ),
    ] {
        c.execute(corrupt).await.unwrap();
        let corrupt_before = instance_sql_snapshot(&mut c, "station").await.unwrap();
        assert_eq!(
            store
                .replace_instance_inventory(&owner, &replacement, deadline())
                .await
                .unwrap_err(),
            InstanceRegistryError::MalformedStored
        );
        assert_eq!(
            instance_sql_snapshot(&mut c, "station").await.unwrap(),
            corrupt_before
        );
        c.execute(restore).await.unwrap();
    }
    assert_eq!(
        instance_sql_snapshot(&mut c, "station").await.unwrap(),
        before
    );
    for (corrupt, restore, original_timestamp) in [
        (
            "UPDATE broker_instances SET created_at=-1 WHERE instance_id='station'",
            "UPDATE broker_instances SET created_at=$1 WHERE instance_id='station'",
            before.parent.2,
        ),
        (
            "UPDATE broker_instances SET updated_at=-1 WHERE instance_id='station'",
            "UPDATE broker_instances SET updated_at=$1 WHERE instance_id='station'",
            before.parent.3,
        ),
    ] {
        c.execute(corrupt).await.unwrap();
        let corrupt_before = instance_sql_snapshot(&mut c, "station").await.unwrap();
        assert_eq!(
            store
                .replace_instance_inventory(&owner, &baseline, deadline())
                .await
                .unwrap_err(),
            InstanceRegistryError::MalformedStored
        );
        assert_eq!(
            instance_sql_snapshot(&mut c, "station").await.unwrap(),
            corrupt_before
        );
        sqlx_core::query::query(restore)
            .bind(original_timestamp)
            .execute(&mut c)
            .await
            .unwrap();
    }
    let mut lock = c.begin().await.unwrap();
    lock.execute("SELECT * FROM broker_instances WHERE instance_id='station' FOR UPDATE")
        .await
        .unwrap();
    assert_eq!(
        store
            .replace_instance_inventory(
                &owner,
                &replacement,
                Instant::now() + Duration::from_millis(500)
            )
            .await
            .unwrap_err(),
        InstanceRegistryError::Control(ControlError::Deadline)
    );
    let s = store.clone();
    let task = tokio::spawn(async move {
        s.replace_instance_inventory(
            &InstanceOwner::new("Issuer ", "Subject ").unwrap(),
            &instance_inventory("station", &[(REGISTRY_PROJECT_A, &["cancelled"])]),
            deadline(),
        )
        .await
    });
    wait_for_query(&mut monitor, "broker_instances").await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    assert_eq!(
        instance_sql_snapshot(&mut c, "station").await.unwrap(),
        before
    );
    assert_eq!(
        store
            .replace_instance_inventory(&owner, &baseline, deadline())
            .await
            .unwrap()
            .change(),
        RegistrationChange::Unchanged
    );
    assert_eq!(
        store
            .replace_instance_inventory(&owner, &replacement, Instant::now())
            .await
            .unwrap_err(),
        InstanceRegistryError::Control(ControlError::Deadline)
    );

    c.execute("CREATE FUNCTION public.registry_commit_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NULL; END $$; CREATE CONSTRAINT TRIGGER registry_commit_wait AFTER INSERT ON broker_instance_project_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.registry_commit_wait()").await.unwrap();
    let s = store.clone();
    let task = tokio::spawn(async move {
        s.replace_instance_inventory(
            &InstanceOwner::new("Issuer ", "Subject ").unwrap(),
            &instance_inventory("uncertain", &[(REGISTRY_PROJECT_A, &["main"])]),
            deadline(),
        )
        .await
    });
    wait_for_query(&mut monitor, "COMMIT").await;
    let killed: Vec<bool> = sqlx_core::query_scalar::query_scalar("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND query='COMMIT' AND state='active'").fetch_all(&mut monitor).await.unwrap();
    assert_eq!(killed, vec![true]);
    assert_eq!(
        task.await.unwrap().unwrap_err(),
        InstanceRegistryError::Control(ControlError::OutcomeUncertain)
    );
    c.execute("DROP TRIGGER registry_commit_wait ON broker_instance_project_versions; DROP FUNCTION public.registry_commit_wait()").await.unwrap();
    // This fixture observed rollback; the API correctly reported uncertainty before observation.
    assert!(instance_sql_snapshot(&mut c, "uncertain").await.is_none());
    assert_eq!(
        store
            .replace_instance_inventory(
                &owner,
                &instance_inventory("uncertain", &[(REGISTRY_PROJECT_A, &["main"])]),
                deadline()
            )
            .await
            .unwrap()
            .change(),
        RegistrationChange::Created
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        store
            .replace_instance_inventory(&owner, &replacement, deadline())
            .await
            .unwrap_err(),
        InstanceRegistryError::Control(ControlError::Closed)
    );
    c.close().await.unwrap();
    monitor.close().await.unwrap();
}

fn bearer_principal(revision: i64) -> String {
    serde_json::json!({
        "issuer":"local","subject":"alice-subject","username":"stale-username",
        "auth_method":"local-token","name":"stale-name","email":"stale-email",
        "organization":"stale-organization","teams":["stale-team"],"roles":["admin"],
        "local_user_revision":revision
    })
    .to_string()
}
async fn bearer_sql_snapshot(c: &mut sqlx_postgres::PgConnection) -> (Vec<String>, Vec<String>) {
    let tokens = sqlx_core::query_scalar::query_scalar(
        "SELECT row_to_json(t)::text FROM public.local_tokens t ORDER BY token_hash",
    )
    .fetch_all(&mut *c)
    .await
    .unwrap();
    let users = sqlx_core::query_scalar::query_scalar(
        "SELECT row_to_json(u)::text FROM public.local_users u ORDER BY username",
    )
    .fetch_all(&mut *c)
    .await
    .unwrap();
    (tokens, users)
}
async fn bearer_read(
    store: &PostgresControlStore,
    digest: &broker_security::CredentialDigest,
    kind: LocalBearerKind,
    cap: usize,
) -> Result<Option<broker_control::LocalBearerState>, LocalBearerStateError> {
    store
        .local_bearer_states(support::n(cap))
        .unwrap()
        .read(digest, kind, deadline())
        .await
}
async fn bearer_set_principal(c: &mut sqlx_postgres::PgConnection, json: String) {
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET principal_json=$1 WHERE token_id='access-test'",
    )
    .bind(json)
    .execute(c)
    .await
    .unwrap();
}
#[tokio::test]
#[ignore = "real PostgreSQL local bearer metadata, coherent current attributes, denial and cancellation"]
async fn postgres_local_bearer_state_contract() {
    let fixture = Fixture::new(true).await;
    let mut c = fixture.connection().await;
    c.execute("CREATE ROLE bearer_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION bearer_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO bearer_owner").await.unwrap();
    let config = broker_control::PostgresConfig::new(
        broker_control::PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: std::num::NonZeroU16::new(fixture.port).unwrap(),
            database: "postgres".into(),
        },
        broker_control::PostgresCredentials::new(
            "bearer_owner".into(),
            zeroize::Zeroizing::new("ephemeral-owner".into()),
        ),
        fixture.ca.clone(),
        broker_control::ConnectionLimits {
            text_bytes: support::n(256),
            ca_bytes: support::n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config, support::digester(), deadline())
            .await
            .unwrap(),
    );
    let ordinary_super: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='bearer_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!ordinary_super);
    let digest = support::digester()
        .token(TokenKind::LocalAccess, b"ephemeral-access")
        .unwrap();
    assert!(
        bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
            .await
            .unwrap()
            .is_none()
    );
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','current-name','current-email','current-org','[\" team \",\"team\",\"a,b\",\"\"]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','','[]',1,0,1,0,0)").await.unwrap();
    sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,'access-test','access','alice-subject','oidc-different',$2,'explicit-client','explicit-audience','','[\" presence:read \",\"presence:publish\"]',1,'',0,0,0)")
        .bind(digest.to_sql_hex()).bind(bearer_principal(1)).execute(&mut c).await.unwrap();
    let before = bearer_sql_snapshot(&mut c).await;
    let state = bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
        .await
        .unwrap()
        .unwrap();
    let user = state.current_local_user();
    assert_eq!(
        (
            user.issuer(),
            user.subject(),
            user.username(),
            user.organization()
        ),
        ("local", "alice-subject", "alice", "current-org")
    );
    assert_eq!(
        (user.name(), user.email()),
        ("current-name", "current-email")
    );
    assert_eq!(user.teams(), ["a,b", "team"]);
    assert_eq!(state.audience(), "explicit-audience");
    assert_eq!(state.raw_scopes(), [" presence:read ", "presence:publish"]);
    assert!(!state.raw_scopes().iter().any(|s| s == "presence:read"));
    assert_eq!(state.expires_at().as_i64(), 0); // Expired metadata is not authentication.
    assert_eq!(state.revoked_at(), None);
    assert_eq!(format!("{state:?}"), "LocalBearerState([REDACTED])");
    assert_eq!(format!("{user:?}"), "LocalBearerUser([REDACTED])");
    assert_eq!(bearer_sql_snapshot(&mut c).await, before);
    let unicode_name = "界".repeat(512);
    sqlx_core::query::query("UPDATE public.local_users SET name=$1 WHERE username='alice'")
        .bind(&unicode_name)
        .execute(&mut c)
        .await
        .unwrap();
    assert_eq!(
        bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
            .await
            .unwrap()
            .unwrap()
            .current_local_user()
            .name(),
        unicode_name
    );
    c.execute("UPDATE public.local_users SET name='current-name' WHERE username='alice'; UPDATE public.local_tokens SET revoked_at=0 WHERE token_id='access-test'").await.unwrap();
    assert_eq!(
        bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
            .await
            .unwrap()
            .unwrap()
            .revoked_at()
            .unwrap()
            .as_i64(),
        0
    );
    c.execute("UPDATE public.local_tokens SET revoked_at=NULL WHERE token_id='access-test'")
        .await
        .unwrap();

    assert!(
        bearer_read(&store, &digest, LocalBearerKind::ServiceCredential, 4096)
            .await
            .unwrap()
            .is_none()
    );
    for (change, restore) in [
        (
            "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
            "UPDATE public.local_users SET enabled=1 WHERE username='alice'",
        ),
        (
            "UPDATE public.local_users SET revision=2 WHERE username='alice'",
            "UPDATE public.local_users SET revision=1 WHERE username='alice'",
        ),
        (
            "UPDATE public.local_users SET subject='missing-subject' WHERE username='alice'",
            "UPDATE public.local_users SET subject='alice-subject' WHERE username='alice'",
        ),
        (
            "UPDATE public.local_users SET identity_kind='service' WHERE username='alice'",
            "UPDATE public.local_users SET identity_kind='human' WHERE username='alice'",
        ),
    ] {
        c.execute(change).await.unwrap();
        let snapshot = bearer_sql_snapshot(&mut c).await;
        assert!(
            bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(bearer_sql_snapshot(&mut c).await, snapshot);
        c.execute(restore).await.unwrap();
    }
    for (field, value) in [
        ("issuer", serde_json::json!("upstream")),
        ("subject", serde_json::json!("different-subject")),
        ("local_user_revision", serde_json::json!(2)),
        ("local_user_revision", serde_json::Value::Null),
    ] {
        let mut principal: serde_json::Value = serde_json::from_str(&bearer_principal(1)).unwrap();
        principal[field] = value;
        bearer_set_principal(&mut c, principal.to_string()).await;
        assert!(
            bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
                .await
                .unwrap()
                .is_none()
        );
    }
    bearer_set_principal(&mut c, bearer_principal(1)).await;
    let service_digest = support::digester()
        .token(TokenKind::ServiceCredential, b"ephemeral-service")
        .unwrap();
    let bot_principal = serde_json::json!({"issuer":"local","subject":"bot-subject","username":"bot","auth_method":"service-credential","local_user_revision":1});
    sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,'service-test','service','bot-subject','oidc-bot',$2,'explicit-client','explicit-audience','','[]',1,'',0,0,0)")
        .bind(service_digest.to_sql_hex()).bind(bot_principal.to_string()).execute(&mut c).await.unwrap();
    assert_eq!(
        bearer_read(
            &store,
            &service_digest,
            LocalBearerKind::ServiceCredential,
            4096
        )
        .await
        .unwrap()
        .unwrap()
        .current_local_user()
        .kind(),
        broker_control::LocalIdentityKind::Service
    );
    c.execute("UPDATE public.local_users SET identity_kind='human' WHERE username='bot'")
        .await
        .unwrap();
    assert!(
        bearer_read(
            &store,
            &service_digest,
            LocalBearerKind::ServiceCredential,
            4096
        )
        .await
        .unwrap()
        .is_none()
    );
    c.execute("UPDATE public.local_users SET identity_kind='service' WHERE username='bot'")
        .await
        .unwrap();

    // An atomic writer is invisible before commit; one SELECT must see a whole state.
    let mut writer = c.begin().await.unwrap();
    writer.execute("UPDATE public.local_users SET name='version-two',organization='org-two',revision=2 WHERE username='alice'; UPDATE public.local_tokens SET local_user_revision=2 WHERE token_id='access-test'").await.unwrap();
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET principal_json=$1 WHERE token_id='access-test'",
    )
    .bind(bearer_principal(2))
    .execute(&mut *writer)
    .await
    .unwrap();
    let old = bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            old.current_local_user().revision(),
            old.current_local_user().name()
        ),
        (1, "current-name")
    );
    writer.commit().await.unwrap();
    let new = bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            new.current_local_user().revision(),
            new.current_local_user().name(),
            new.current_local_user().organization()
        ),
        (2, "version-two", "org-two")
    );

    for malformed in [
        r#"{"issuer":"local","subject":"alice-subject","username":"u","auth_method":"x","name":3,"local_user_revision":2}"#,
        r#"{"issuer":"local","subject":"alice-subject","username":"u","auth_method":"x","teams":[3],"local_user_revision":2}"#,
        r#"{"issuer":"local","issuer":"local","subject":"alice-subject","username":"u","auth_method":"x","local_user_revision":2}"#,
        r#"{"issuer":"local","subject":"alice-subject","username":"u","auth_method":"x","extra":true,"local_user_revision":2}"#,
        r#"{"issuer":"local","subject":"alice-subject","username":"u","local_user_revision":2}"#,
    ] {
        bearer_set_principal(&mut c, malformed.into()).await;
        let before = bearer_sql_snapshot(&mut c).await;
        assert_eq!(
            bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
                .await
                .unwrap_err(),
            LocalBearerStateError::MalformedStored
        );
        assert_eq!(bearer_sql_snapshot(&mut c).await, before);
    }
    bearer_set_principal(&mut c, bearer_principal(2)).await;
    for (corrupt, restore) in [
        (
            "UPDATE public.local_tokens SET scopes_json='[1]' WHERE token_id='access-test'",
            "UPDATE public.local_tokens SET scopes_json='[\" presence:read \",\"presence:publish\"]' WHERE token_id='access-test'",
        ),
        (
            "UPDATE public.local_users SET teams_json='null' WHERE username='alice'",
            "UPDATE public.local_users SET teams_json='[\" team \",\"team\",\"a,b\",\"\"]' WHERE username='alice'",
        ),
        (
            "UPDATE public.local_tokens SET expires_at=-1 WHERE token_id='access-test'",
            "UPDATE public.local_tokens SET expires_at=0 WHERE token_id='access-test'",
        ),
        (
            "UPDATE public.local_tokens SET revoked_at=-1 WHERE token_id='access-test'",
            "UPDATE public.local_tokens SET revoked_at=NULL WHERE token_id='access-test'",
        ),
        (
            "UPDATE public.local_users SET identity_kind='' WHERE username='alice'",
            "UPDATE public.local_users SET identity_kind='human' WHERE username='alice'",
        ),
        (
            "UPDATE public.local_users SET enabled=2 WHERE username='alice'",
            "UPDATE public.local_users SET enabled=1 WHERE username='alice'",
        ),
        (
            "UPDATE public.local_users SET revision=0 WHERE username='alice'",
            "UPDATE public.local_users SET revision=2 WHERE username='alice'",
        ),
        (
            "UPDATE public.local_users SET username=' alice' WHERE username='alice'",
            "UPDATE public.local_users SET username='alice' WHERE username=' alice'",
        ),
    ] {
        c.execute(corrupt).await.unwrap();
        let before = bearer_sql_snapshot(&mut c).await;
        assert_eq!(
            bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
                .await
                .unwrap_err(),
            LocalBearerStateError::MalformedStored
        );
        assert_eq!(bearer_sql_snapshot(&mut c).await, before);
        c.execute(restore).await.unwrap();
    }
    assert_eq!(
        bearer_read(&store, &digest, LocalBearerKind::Access, 8)
            .await
            .unwrap_err(),
        LocalBearerStateError::ReadLimitExceeded
    );
    let long_teams = serde_json::json!(["界".repeat(512)]).to_string();
    sqlx_core::query::query("UPDATE public.local_users SET teams_json=$1 WHERE username='alice'")
        .bind(long_teams)
        .execute(&mut c)
        .await
        .unwrap();
    assert_eq!(
        bearer_read(&store, &digest, LocalBearerKind::Access, 1024)
            .await
            .unwrap_err(),
        LocalBearerStateError::ReadLimitExceeded
    );
    c.execute("UPDATE public.local_users SET teams_json='[]' WHERE username='alice'")
        .await
        .unwrap();
    assert!(matches!(
        store.local_bearer_states(support::n(usize::MAX)),
        Err(LocalBearerStateError::InvalidLimits)
    ));

    // Least privilege proves the projection does not read password or MFA state.
    c.execute("REVOKE SELECT ON public.local_users FROM bearer_owner; GRANT SELECT(username,subject,identity_kind,name,email,organization,teams_json,enabled,revision) ON public.local_users TO bearer_owner").await.unwrap();
    assert!(
        bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
            .await
            .unwrap()
            .is_some()
    );
    c.execute("REVOKE SELECT ON public.local_tokens FROM bearer_owner")
        .await
        .unwrap();
    assert_eq!(
        bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
            .await
            .unwrap_err(),
        LocalBearerStateError::Control(ControlError::Storage)
    );
    c.execute("GRANT SELECT ON public.local_tokens TO bearer_owner; REVOKE SELECT(organization) ON public.local_users FROM bearer_owner").await.unwrap();
    assert_eq!(
        bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
            .await
            .unwrap_err(),
        LocalBearerStateError::Control(ControlError::Storage)
    );
    c.execute("GRANT SELECT(organization) ON public.local_users TO bearer_owner")
        .await
        .unwrap();

    let before = bearer_sql_snapshot(&mut c).await;
    let mut locked = c.begin().await.unwrap();
    locked
        .execute("LOCK TABLE public.local_tokens IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    assert_eq!(
        store
            .local_bearer_states(support::n(4096))
            .unwrap()
            .read(
                &digest,
                LocalBearerKind::Access,
                Instant::now() + Duration::from_millis(300)
            )
            .await
            .unwrap_err(),
        LocalBearerStateError::Control(ControlError::Deadline)
    );
    let cloned = store.clone();
    let cancelled = tokio::spawn(async move {
        let d = support::digester()
            .token(TokenKind::LocalAccess, b"ephemeral-access")
            .unwrap();
        cloned
            .local_bearer_states(support::n(4096))
            .unwrap()
            .read(&d, LocalBearerKind::Access, deadline())
            .await
    });
    let mut monitor = fixture.connection().await;
    wait_for_query(&mut monitor, "local_tokens").await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    locked.rollback().await.unwrap();
    assert_eq!(bearer_sql_snapshot(&mut c).await, before);
    assert!(
        bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .local_bearer_states(support::n(4096))
            .unwrap()
            .read(&digest, LocalBearerKind::Access, Instant::now())
            .await
            .unwrap_err(),
        LocalBearerStateError::Control(ControlError::Deadline)
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        bearer_read(&store, &digest, LocalBearerKind::Access, 4096)
            .await
            .unwrap_err(),
        LocalBearerStateError::Control(ControlError::Closed)
    );

    // Reopen under the same ordinary owner with its original rights.
    c.execute("GRANT SELECT ON public.local_users TO bearer_owner")
        .await
        .unwrap();
    let config = broker_control::PostgresConfig::new(
        broker_control::PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: std::num::NonZeroU16::new(fixture.port).unwrap(),
            database: "postgres".into(),
        },
        broker_control::PostgresCredentials::new(
            "bearer_owner".into(),
            zeroize::Zeroizing::new("ephemeral-owner".into()),
        ),
        fixture.ca.clone(),
        broker_control::ConnectionLimits {
            text_bytes: support::n(256),
            ca_bytes: support::n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap();
    let reopened = PostgresControlStore::open(config, support::digester(), deadline())
        .await
        .unwrap();
    assert!(
        bearer_read(&reopened, &digest, LocalBearerKind::Access, 4096)
            .await
            .unwrap()
            .is_some()
    );
    reopened.shutdown(deadline()).await.unwrap();
    monitor.close().await.unwrap();
    c.close().await.unwrap();
}

fn opaque_config(fixture: &Fixture) -> broker_control::PostgresConfig {
    broker_control::PostgresConfig::new(
        broker_control::PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: std::num::NonZeroU16::new(fixture.port).unwrap(),
            database: "postgres".into(),
        },
        broker_control::PostgresCredentials::new(
            "opaque_owner".into(),
            zeroize::Zeroizing::new("ephemeral-owner".into()),
        ),
        fixture.ca.clone(),
        broker_control::ConnectionLimits {
            text_bytes: support::n(256),
            ca_bytes: support::n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap()
}
fn opaque_now() -> i64 {
    broker_store::time::TimestampMicros::try_from(SystemTime::now())
        .unwrap()
        .as_i64()
}
async fn opaque_verify(
    store: &PostgresControlStore,
    raw: &str,
    required: &[String],
) -> Result<broker_control::VerifiedLocalBearer, LocalBearerVerificationError> {
    store
        .local_bearer_verifier(" explicit-audience ", support::n(4096))
        .unwrap()
        .verify(raw, required, deadline())
        .await
}
async fn opaque_failure(
    c: &mut sqlx_postgres::PgConnection,
    store: &PostgresControlStore,
    raw: &str,
    required: &[String],
    expected: LocalBearerVerificationError,
) {
    let before = bearer_sql_snapshot(c).await;
    assert_eq!(
        opaque_verify(store, raw, required).await.unwrap_err(),
        expected
    );
    assert_eq!(bearer_sql_snapshot(c).await, before);
}
#[tokio::test]
#[ignore = "real PostgreSQL raw opaque bearer authentication, current identity, scopes, clock and read-only state"]
async fn postgres_local_bearer_verifier_contract() {
    let fixture = Fixture::new(true).await;
    let mut c = fixture.connection().await;
    c.execute("CREATE ROLE opaque_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION opaque_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO opaque_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(opaque_config(&fixture), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let is_super: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='opaque_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!is_super);
    let raw = "gb_at_ephemeral-access";
    let service_raw = "gb_sc_ephemeral-service";
    let access_digest = support::digester()
        .token(TokenKind::LocalAccess, raw.as_bytes())
        .unwrap();
    let service_digest = support::digester()
        .token(TokenKind::ServiceCredential, service_raw.as_bytes())
        .unwrap();
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','current-name','current-email','current-org','[\" team \",\"team\",\"a,b\"]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','Automation','[]',1,0,1,0,0)").await.unwrap();
    for (hash,id,kind,subject,principal) in [
        (access_digest.to_sql_hex(),"access-test","access","alice-subject",bearer_principal(1)),
        (service_digest.to_sql_hex(),"service-test","service","bot-subject",serde_json::json!({"issuer":"local","subject":"bot-subject","username":"stale-bot","auth_method":"stale-method","local_user_revision":1}).to_string())
    ] {
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'pseudonymous-other',$5,'explicit-client','explicit-audience','','[\"presence:read\",\" presence:publish \",\"a,b\",\"presence:read\",\"\"]',1,'',0,$6,0)")
            .bind(hash).bind(id).bind(kind).bind(subject).bind(principal).bind(opaque_now()+60_000_000).execute(&mut c).await.unwrap();
    }
    let initial = bearer_sql_snapshot(&mut c).await;
    let verified = opaque_verify(
        &store,
        raw,
        &[
            " presence:read ".into(),
            "presence:read".into(),
            "a,b".into(),
            "".into(),
        ],
    )
    .await
    .unwrap();
    let user = verified.current_local_user();
    assert_eq!(
        (
            user.issuer(),
            user.subject(),
            user.username(),
            user.name(),
            user.email(),
            user.organization()
        ),
        (
            "local",
            "alice-subject",
            "alice",
            "current-name",
            "current-email",
            "current-org"
        )
    );
    assert_eq!(user.teams(), ["a,b", "team"]);
    assert_eq!(verified.kind(), LocalBearerKind::Access);
    assert_eq!(verified.auth_method(), "local-token");
    assert_eq!(verified.audience(), "explicit-audience");
    assert_eq!(
        verified.scopes(),
        ["a,b", "presence:publish", "presence:read"]
    );
    assert!(verified.verified_at() < verified.expires_at());
    assert_eq!(format!("{verified:?}"), "VerifiedLocalBearer([REDACTED])");
    let bot = opaque_verify(&store, service_raw, &["presence:read".into()])
        .await
        .unwrap();
    assert_eq!(bot.auth_method(), "service-credential");
    assert_eq!(
        bot.current_local_user().kind(),
        broker_control::LocalIdentityKind::Service
    );
    assert_eq!(bot.current_local_user().subject(), "bot-subject");
    assert_eq!(bearer_sql_snapshot(&mut c).await, initial);
    assert_eq!(
        format!(
            "{:?}",
            store
                .local_bearer_verifier("explicit-audience", support::n(4096))
                .unwrap()
        ),
        "PostgresLocalBearerVerifier([REDACTED])"
    );
    let deny = LocalBearerVerificationError::Unauthenticated;
    for bad in [
        "",
        "gb_rt_ephemeral-refresh",
        "GB_AT_ephemeral-access",
        " gb_at_ephemeral-access",
        "gb_at_missing",
        "gb_at_ephemeral-access ",
        "eyJ.local.jwt",
    ] {
        opaque_failure(&mut c, &store, bad, &[], deny).await;
    }
    opaque_failure(
        &mut c,
        &store,
        &format!("gb_at_{}", "x".repeat(257)),
        &[],
        deny,
    )
    .await;
    for required in ["presence:publish", "PRESENCE:read", "a"] {
        opaque_failure(&mut c, &store, raw, &[required.into()], deny).await;
    }
    let before = bearer_sql_snapshot(&mut c).await;
    assert_eq!(
        store
            .local_bearer_verifier("EXPLICIT-AUDIENCE", support::n(4096))
            .unwrap()
            .verify(raw, &[], deadline())
            .await
            .unwrap_err(),
        deny
    );
    assert_eq!(bearer_sql_snapshot(&mut c).await, before);
    c.execute("UPDATE public.local_tokens SET audience=' explicit-audience ' WHERE token_id='access-test'").await.unwrap();
    opaque_failure(&mut c, &store, raw, &[], deny).await;
    c.execute("UPDATE public.local_tokens SET audience='explicit-audience',revoked_at=0 WHERE token_id='access-test'").await.unwrap();
    opaque_failure(&mut c, &store, raw, &[], deny).await;
    c.execute(
        "UPDATE public.local_tokens SET revoked_at=NULL,expires_at=0 WHERE token_id='access-test'",
    )
    .await
    .unwrap();
    opaque_failure(&mut c, &store, raw, &[], deny).await;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-test'",
    )
    .bind(opaque_now() + 60_000_000)
    .execute(&mut c)
    .await
    .unwrap();
    for mutation_sql in [
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_users SET revision=2 WHERE username='alice'",
        "UPDATE public.local_users SET identity_kind='service' WHERE username='alice'",
    ] {
        sqlx_core::query::query(mutation_sql)
            .execute(&mut c)
            .await
            .unwrap();
        opaque_failure(&mut c, &store, raw, &[], deny).await;
        c.execute("UPDATE public.local_users SET enabled=1,revision=1,identity_kind='human' WHERE username='alice'").await.unwrap();
    }
    bearer_set_principal(&mut c, bearer_principal(2)).await;
    opaque_failure(&mut c, &store, raw, &[], deny).await;
    bearer_set_principal(&mut c, bearer_principal(1)).await;
    let wrong_domain = support::digester()
        .token(TokenKind::ServiceCredential, raw.as_bytes())
        .unwrap()
        .to_sql_hex();
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET token_hash=$1 WHERE token_id='access-test'",
    )
    .bind(wrong_domain)
    .execute(&mut c)
    .await
    .unwrap();
    opaque_failure(&mut c, &store, raw, &[], deny).await;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET token_hash=$1 WHERE token_id='access-test'",
    )
    .bind(access_digest.to_sql_hex())
    .execute(&mut c)
    .await
    .unwrap();
    let wrong_pepper = broker_security::CredentialDigester::new(
        zeroize::Zeroizing::new(vec![0x92; 32].into_boxed_slice()),
        broker_security::DigestLimits::new(
            support::n(64),
            support::n(256),
            support::n(256),
            support::n(256),
            support::n(256),
        )
        .unwrap(),
    )
    .unwrap();
    let other = PostgresControlStore::open(opaque_config(&fixture), wrong_pepper, deadline())
        .await
        .unwrap();
    opaque_failure(&mut c, &other, raw, &[], deny).await;
    other.shutdown(deadline()).await.unwrap();
    bearer_set_principal(&mut c, "{malformed".into()).await;
    opaque_failure(
        &mut c,
        &store,
        raw,
        &[],
        LocalBearerVerificationError::State(LocalBearerStateError::MalformedStored),
    )
    .await;
    bearer_set_principal(&mut c, bearer_principal(1)).await;
    let before = bearer_sql_snapshot(&mut c).await;
    assert_eq!(
        store
            .local_bearer_verifier("explicit-audience", support::n(8))
            .unwrap()
            .verify(raw, &[], deadline())
            .await
            .unwrap_err(),
        LocalBearerVerificationError::State(LocalBearerStateError::ReadLimitExceeded)
    );
    assert_eq!(bearer_sql_snapshot(&mut c).await, before);
    assert_eq!(
        store
            .local_bearer_verifier("explicit-audience", support::n(usize::MAX))
            .unwrap_err(),
        LocalBearerVerificationError::State(LocalBearerStateError::InvalidLimits)
    );

    // Only projected identity columns are readable; passwords and MFA are unavailable.
    c.execute("REVOKE SELECT ON public.local_users FROM opaque_owner; GRANT SELECT(username,subject,identity_kind,name,email,organization,teams_json,enabled,revision) ON public.local_users TO opaque_owner").await.unwrap();
    opaque_verify(&store, raw, &[]).await.unwrap();
    c.execute("UPDATE public.local_tokens SET last_used_at=NULL WHERE token_id='access-test'; REVOKE UPDATE ON public.local_tokens FROM opaque_owner").await.unwrap();
    let before = bearer_sql_snapshot(&mut c).await;
    opaque_verify(&store, raw, &[]).await.unwrap(); // Verification needs no UPDATE privilege.
    assert_eq!(bearer_sql_snapshot(&mut c).await, before);
    c.execute("REVOKE SELECT ON public.local_tokens FROM opaque_owner")
        .await
        .unwrap();
    opaque_failure(
        &mut c,
        &store,
        raw,
        &[],
        LocalBearerVerificationError::Control(ControlError::Storage),
    )
    .await;
    c.execute("GRANT SELECT,UPDATE ON public.local_tokens TO opaque_owner")
        .await
        .unwrap();
    // A concurrent row writer cannot force a read-only verifier to wait for UPDATE.
    let mut locker = fixture.connection().await;
    let mut lock = locker.begin().await.unwrap();
    sqlx_core::query::query(
        "SELECT token_id FROM public.local_tokens WHERE token_id='access-test' FOR UPDATE",
    )
    .fetch_one(&mut *lock)
    .await
    .unwrap();
    store
        .local_bearer_verifier("explicit-audience", support::n(4096))
        .unwrap()
        .verify(raw, &[], Instant::now() + Duration::from_millis(300))
        .await
        .unwrap();
    lock.rollback().await.unwrap();
    assert_eq!(bearer_sql_snapshot(&mut c).await, before);

    // Deadline and cancellation still apply to the actual state SELECT.
    let mut lock = locker.begin().await.unwrap();
    lock.execute("LOCK TABLE public.local_tokens IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    assert_eq!(
        store
            .local_bearer_verifier("explicit-audience", support::n(4096))
            .unwrap()
            .verify(raw, &[], Instant::now() + Duration::from_millis(300))
            .await
            .unwrap_err(),
        LocalBearerVerificationError::Control(ControlError::Deadline)
    );
    lock.rollback().await.unwrap();
    opaque_verify(&store, raw, &[]).await.unwrap();
    let mut lock = locker.begin().await.unwrap();
    lock.execute("LOCK TABLE public.local_tokens IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let s = store.clone();
    let cancelled = tokio::spawn(async move { opaque_verify(&s, raw, &[]).await });
    let mut monitor = fixture.connection().await;
    wait_for_query(&mut monitor, "FROM public.local_tokens t").await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    assert_eq!(bearer_sql_snapshot(&mut c).await, before);
    opaque_verify(&store, raw, &[]).await.unwrap(); // Fresh guard/pool recovery.

    let expiry = opaque_now() + 750_000;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-test'",
    )
    .bind(expiry)
    .execute(&mut c)
    .await
    .unwrap();
    let before_expiry = bearer_sql_snapshot(&mut c).await;
    let mut lock = locker.begin().await.unwrap();
    lock.execute("LOCK TABLE public.local_tokens IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let s = store.clone();
    let pending = tokio::spawn(async move { opaque_verify(&s, raw, &[]).await });
    wait_for_query(&mut monitor, "FROM public.local_tokens t").await;
    while opaque_now() <= expiry {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    lock.rollback().await.unwrap();
    assert_eq!(pending.await.unwrap().unwrap_err(), deny);
    assert_eq!(bearer_sql_snapshot(&mut c).await, before_expiry);
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-test'",
    )
    .bind(opaque_now() + 60_000_000)
    .execute(&mut c)
    .await
    .unwrap();
    opaque_verify(&store, raw, &[]).await.unwrap();
    assert_eq!(
        store
            .local_bearer_verifier("explicit-audience", support::n(4096))
            .unwrap()
            .verify(raw, &[], Instant::now())
            .await
            .unwrap_err(),
        LocalBearerVerificationError::Control(ControlError::Deadline)
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        opaque_verify(&store, raw, &[]).await.unwrap_err(),
        LocalBearerVerificationError::Control(ControlError::Closed)
    );
    let reopened =
        PostgresControlStore::open(opaque_config(&fixture), support::digester(), deadline())
            .await
            .unwrap();
    opaque_verify(&reopened, raw, &[]).await.unwrap();
    reopened.shutdown(deadline()).await.unwrap();
    locker.close().await.unwrap();
    monitor.close().await.unwrap();
    c.close().await.unwrap();
}

async fn grants_snapshot_sql(c: &mut sqlx_postgres::PgConnection) -> String {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('state',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.resource_acl_state s),'grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM public.resource_grants r),'caps',(SELECT jsonb_agg(to_jsonb(c) ORDER BY grant_id,value) FROM public.grant_capabilities c),'projects',(SELECT jsonb_agg(to_jsonb(p) ORDER BY grant_id,value) FROM public.grant_projects p),'ops',(SELECT jsonb_agg(to_jsonb(o) ORDER BY grant_id,value) FROM public.grant_s3_operations o),'prefixes',(SELECT jsonb_agg(to_jsonb(f) ORDER BY grant_id,value) FROM public.grant_s3_prefixes f))::text").fetch_one(c).await.unwrap()
}
async fn grants_read(
    store: &PostgresControlStore,
    cap: usize,
) -> Result<broker_control::ResourceGrantSnapshot, ResourceGrantReadError> {
    store
        .resource_grants(support::n(cap))
        .unwrap()
        .read(deadline())
        .await
}
#[tokio::test]
#[ignore = "real PostgreSQL current coherent resource grant metadata, limits, privileges and cancellation"]
async fn postgres_resource_grants_contract() {
    let fixture = Fixture::new(true).await;
    let mut c = fixture.connection().await;
    c.execute("CREATE ROLE opaque_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION opaque_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO opaque_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(opaque_config(&fixture), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let is_super: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='opaque_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!is_super);
    let empty = grants_read(&store, 4096).await.unwrap();
    assert_eq!(empty.revision(), 1);
    assert!(empty.rules().is_empty());
    c.execute("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('z-rule','Z','subject','local|alice-subject','private',0,1),('a-rule','A',' team ',' team* ','',0,1); INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a-rule','presence:read'),('a-rule',' a,b '),('z-rule','s3:read'); INSERT INTO public.grant_projects(grant_id,value) VALUES('a-rule','01ARZ3NDEKTSV4RRFFQ69G5FAV'),('a-rule','*'); INSERT INTO public.grant_s3_operations(grant_id,value) VALUES('z-rule','write'),('z-rule','read'); INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES('z-rule','v2/projects/{project}'),('z-rule','v2/users/{username}')").await.unwrap();
    let before = grants_snapshot_sql(&mut c).await;
    let state = grants_read(&store, 4096).await.unwrap();
    assert_eq!(
        state.rules().iter().map(|r| r.id()).collect::<Vec<_>>(),
        ["a-rule", "z-rule"]
    );
    let a = &state.rules()[0];
    assert_eq!(
        (a.name(), a.access_kind(), a.principal(), a.s3_route()),
        ("A", " team ", " team* ", "")
    );
    assert_eq!(a.capabilities(), [" a,b ", "presence:read"]);
    assert_eq!(a.projects(), ["*", "01ARZ3NDEKTSV4RRFFQ69G5FAV"]);
    assert_eq!(a.created_at().as_i64(), 0);
    assert_eq!(a.updated_at().as_i64(), 1);
    let z = &state.rules()[1];
    assert_eq!(z.s3_operations(), ["read", "write"]);
    assert_eq!(
        z.s3_prefixes(),
        ["v2/projects/{project}", "v2/users/{username}"]
    );
    assert_eq!(format!("{state:?}"), "ResourceGrantSnapshot([REDACTED])");
    assert_eq!(format!("{z:?}"), "ResourceGrantRule([REDACTED])");
    assert_eq!(
        format!("{:?}", store.resource_grants(support::n(4096)).unwrap()),
        "PostgresResourceGrants([REDACTED])"
    );
    assert_eq!(grants_snapshot_sql(&mut c).await, before);
    assert!(
        sqlx_core::query::query(
            "INSERT INTO public.grant_projects(grant_id,value) VALUES('absent','*')"
        )
        .execute(&mut c)
        .await
        .is_err()
    );
    let unicode = "界".repeat(256);
    sqlx_core::query::query("UPDATE public.resource_grants SET name=$1 WHERE id='a-rule'")
        .bind(&unicode)
        .execute(&mut c)
        .await
        .unwrap();
    assert_eq!(
        grants_read(&store, 4096).await.unwrap().rules()[0].name(),
        unicode
    );
    let before = grants_snapshot_sql(&mut c).await;
    assert_eq!(
        grants_read(&store, 8).await.unwrap_err(),
        ResourceGrantReadError::ReadLimitExceeded
    );
    // Above cap even though character count is much smaller than encoded UTF-8 bytes.
    assert_eq!(
        grants_read(&store, 1280).await.unwrap_err(),
        ResourceGrantReadError::ReadLimitExceeded
    );
    assert_eq!(
        store.resource_grants(support::n(usize::MAX)).unwrap_err(),
        ResourceGrantReadError::InvalidLimits
    );
    assert_eq!(grants_snapshot_sql(&mut c).await, before);
    c.execute("UPDATE public.resource_grants SET name='A' WHERE id='a-rule'")
        .await
        .unwrap();
    let initial_updated = grants_read(&store, 4096).await.unwrap().updated_at();
    let mut writer = fixture.connection().await;
    let mut tx = writer.begin().await.unwrap();
    tx.execute("DELETE FROM public.resource_grants; INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('new-rule','New','authenticated','','new-route',0,2); INSERT INTO public.grant_capabilities(grant_id,value) VALUES('new-rule','presence:publish'); INSERT INTO public.grant_projects(grant_id,value) VALUES('new-rule','01ARZ3NDEKTSV4RRFFQ69G5FAV'); INSERT INTO public.grant_s3_operations(grant_id,value) VALUES('new-rule','publish'); INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES('new-rule','v2/new'); UPDATE public.resource_acl_state SET revision=2,updated_at=2 WHERE id=1").await.unwrap();
    let old = grants_read(&store, 4096).await.unwrap();
    assert_eq!(old.revision(), 1);
    assert_eq!(old.updated_at(), initial_updated);
    assert_eq!(
        old.rules().iter().map(|r| r.id()).collect::<Vec<_>>(),
        ["a-rule", "z-rule"]
    );
    assert_eq!(old.rules()[0].capabilities(), [" a,b ", "presence:read"]);
    assert_eq!(old.rules()[1].s3_operations(), ["read", "write"]);
    tx.commit().await.unwrap();
    let new = grants_read(&store, 4096).await.unwrap();
    assert_eq!(new.revision(), 2);
    assert_eq!(new.updated_at().as_i64(), 2);
    assert_eq!(new.rules().len(), 1);
    let r = &new.rules()[0];
    assert_eq!(r.id(), "new-rule");
    assert_eq!(r.s3_route(), "new-route");
    assert_eq!(r.capabilities(), ["presence:publish"]);
    assert_eq!(r.projects(), ["01ARZ3NDEKTSV4RRFFQ69G5FAV"]);
    assert_eq!(r.s3_operations(), ["publish"]);
    assert_eq!(r.s3_prefixes(), ["v2/new"]);
    for bad_sql in [
        "UPDATE public.resource_acl_state SET revision=0 WHERE id=1",
        "UPDATE public.resource_acl_state SET updated_at=-1 WHERE id=1",
        "UPDATE public.resource_grants SET created_at=-1 WHERE id='new-rule'",
        "UPDATE public.resource_grants SET updated_at=-1 WHERE id='new-rule'",
    ] {
        c.execute(bad_sql).await.unwrap();
        let before = grants_snapshot_sql(&mut c).await;
        assert_eq!(
            grants_read(&store, 4096).await.unwrap_err(),
            ResourceGrantReadError::MalformedStored
        );
        assert_eq!(grants_snapshot_sql(&mut c).await, before);
        c.execute("UPDATE public.resource_acl_state SET revision=2,updated_at=2 WHERE id=1; UPDATE public.resource_grants SET created_at=0,updated_at=2 WHERE id='new-rule'").await.unwrap();
    }
    c.execute("DELETE FROM public.resource_acl_state WHERE id=1")
        .await
        .unwrap();
    assert_eq!(
        grants_read(&store, 4096).await.unwrap_err(),
        ResourceGrantReadError::MalformedStored
    );
    c.execute("INSERT INTO public.resource_acl_state(id,revision,updated_at) VALUES(1,2,2)")
        .await
        .unwrap();
    // The reader preserves raw invalid policy as DATA; the later evaluator must reject it.
    c.execute("UPDATE public.resource_grants SET access_kind='unknown' WHERE id='new-rule'; UPDATE public.grant_projects SET value='not-a-project' WHERE grant_id='new-rule'").await.unwrap();
    let raw = grants_read(&store, 4096).await.unwrap();
    assert_eq!(raw.rules()[0].access_kind(), "unknown");
    assert_eq!(raw.rules()[0].projects(), ["not-a-project"]);
    c.execute("UPDATE public.resource_grants SET access_kind='authenticated' WHERE id='new-rule'; UPDATE public.grant_projects SET value='01ARZ3NDEKTSV4RRFFQ69G5FAV' WHERE grant_id='new-rule'").await.unwrap();
    for (revoke, restore) in [
        (
            "REVOKE SELECT ON public.resource_acl_state FROM opaque_owner",
            "GRANT SELECT ON public.resource_acl_state TO opaque_owner",
        ),
        (
            "REVOKE SELECT ON public.grant_capabilities FROM opaque_owner",
            "GRANT SELECT ON public.grant_capabilities TO opaque_owner",
        ),
        (
            "REVOKE SELECT ON public.grant_projects FROM opaque_owner",
            "GRANT SELECT ON public.grant_projects TO opaque_owner",
        ),
        (
            "REVOKE SELECT ON public.grant_s3_operations FROM opaque_owner",
            "GRANT SELECT ON public.grant_s3_operations TO opaque_owner",
        ),
        (
            "REVOKE SELECT ON public.grant_s3_prefixes FROM opaque_owner",
            "GRANT SELECT ON public.grant_s3_prefixes TO opaque_owner",
        ),
    ] {
        c.execute(revoke).await.unwrap();
        assert_eq!(
            grants_read(&store, 4096).await.unwrap_err(),
            ResourceGrantReadError::Control(ControlError::Storage)
        );
        c.execute(restore).await.unwrap();
        grants_read(&store, 4096).await.unwrap();
    }
    let before = grants_snapshot_sql(&mut c).await;
    let mut lock = writer.begin().await.unwrap();
    lock.execute("LOCK TABLE public.grant_capabilities IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    assert_eq!(
        store
            .resource_grants(support::n(4096))
            .unwrap()
            .read(Instant::now() + Duration::from_millis(300))
            .await
            .unwrap_err(),
        ResourceGrantReadError::Control(ControlError::Deadline)
    );
    lock.rollback().await.unwrap();
    grants_read(&store, 4096).await.unwrap();
    let mut lock = writer.begin().await.unwrap();
    lock.execute("LOCK TABLE public.grant_capabilities IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let s = store.clone();
    let cancelled = tokio::spawn(async move { grants_read(&s, 4096).await });
    let mut monitor = fixture.connection().await;
    wait_for_query(&mut monitor, "WITH policy AS MATERIALIZED").await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    assert_eq!(grants_snapshot_sql(&mut c).await, before);
    grants_read(&store, 4096).await.unwrap();
    assert_eq!(
        store
            .resource_grants(support::n(4096))
            .unwrap()
            .read(Instant::now())
            .await
            .unwrap_err(),
        ResourceGrantReadError::Control(ControlError::Deadline)
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        grants_read(&store, 4096).await.unwrap_err(),
        ResourceGrantReadError::Control(ControlError::Closed)
    );
    let reopened =
        PostgresControlStore::open(opaque_config(&fixture), support::digester(), deadline())
            .await
            .unwrap();
    assert_eq!(grants_read(&reopened, 4096).await.unwrap().revision(), 2);
    reopened.shutdown(deadline()).await.unwrap();
    writer.close().await.unwrap();
    monitor.close().await.unwrap();
    c.close().await.unwrap();
}

struct PresenceFixtureRule<'a> {
    access: &'a str,
    principal: &'a str,
    capabilities: &'a [&'a str],
    projects: &'a [&'a str],
}
async fn presence_set_rule(c: &mut sqlx_postgres::PgConnection, rule: PresenceFixtureRule<'_>) {
    let mut tx = c.begin().await.unwrap();
    sqlx_core::query::query("DELETE FROM public.resource_grants")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('a','presence-fixture',$1,$2,'',0,0)").bind(rule.access).bind(rule.principal).execute(&mut *tx).await.unwrap();
    for cap in rule.capabilities {
        sqlx_core::query::query(
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a',$1)",
        )
        .bind(cap)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    for project in rule.projects {
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES('a',$1)")
            .bind(project)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    sqlx_core::query::query("UPDATE public.resource_acl_state SET revision=revision+1,updated_at=updated_at+1 WHERE id=1").execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}
async fn presence_authorize(
    store: &PostgresControlStore,
    raw: &str,
    cap: PresenceCapability,
    project: &str,
) -> Result<broker_control::AuthorizedLocalPresence, PresenceAuthorizationError> {
    store
        .local_presence_authorizer(" explicit-audience ", support::n(4096), support::n(16384))
        .unwrap()
        .authorize_project(raw, &["presence:read".into()], cap, project, deadline())
        .await
}
async fn presence_data_snapshot(c: &mut sqlx_postgres::PgConnection) -> serde_json::Value {
    let policy = grants_snapshot_sql(c).await;
    let users: serde_json::Value = sqlx_core::query_scalar::query_scalar("SELECT coalesce(json_agg(to_jsonb(u) ORDER BY username COLLATE \"C\"),'[]'::json) FROM public.local_users u").fetch_one(&mut *c).await.unwrap();
    serde_json::json!({"policy":policy,"users":users})
}
#[tokio::test]
#[ignore = "real PostgreSQL local raw bearer plus fresh same-rule presence authorization"]
async fn postgres_local_presence_authorization_contract() {
    let fixture = Fixture::new(true).await;
    let mut c = fixture.connection().await;
    c.execute("CREATE ROLE opaque_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION opaque_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO opaque_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(opaque_config(&fixture), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let is_super: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='opaque_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!is_super);
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Alice','','org/team','[\"dev\",\"team\"]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','Automation','[]',1,0,1,0,0)").await.unwrap();
    let raw = "gb_at_presence-access";
    let service_raw = "gb_sc_presence-service";
    for (token,kind,kind_name,id,subject,principal) in [
        (raw,TokenKind::LocalAccess,"access","access-test","alice-subject",bearer_principal(1)),
        (service_raw,TokenKind::ServiceCredential,"service","service-test","bot-subject",serde_json::json!({"issuer":"local","subject":"bot-subject","username":"stale-bot","auth_method":"old","local_user_revision":1}).to_string()),
    ] {
        let hash=support::digester().token(kind,token.as_bytes()).unwrap();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'other',$5,'explicit-client','explicit-audience','','[\"presence:read\",\"presence:publish\"]',1,'',0,$6,0)")
            .bind(hash.to_sql_hex()).bind(id).bind(kind_name).bind(subject).bind(principal).bind(opaque_now()+120_000_000).execute(&mut c).await.unwrap();
    }
    let a = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    let b = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
    let deny = PresenceAuthorizationError::Forbidden;
    let unauth =
        PresenceAuthorizationError::Authentication(LocalBearerVerificationError::Unauthenticated);
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        deny
    );
    presence_set_rule(
        &mut c,
        PresenceFixtureRule {
            access: " user ",
            principal: " ali?e ",
            capabilities: &["presence:read"],
            projects: &[a],
        },
    )
    .await;
    let before = presence_data_snapshot(&mut c).await;
    let observed = presence_authorize(&store, raw, PresenceCapability::Read, a)
        .await
        .unwrap();
    assert_eq!(observed.project_id(), a);
    assert_eq!(observed.capability(), PresenceCapability::Read);
    assert_eq!(observed.policy_revision(), 2);
    assert_eq!(
        observed.principal().current_local_user().username(),
        "alice"
    );
    assert_eq!(
        observed.principal().current_local_user().subject(),
        "alice-subject"
    );
    assert_eq!(observed.principal().auth_method(), "local-token");
    assert_eq!(
        format!("{observed:?}"),
        "AuthorizedLocalPresence([REDACTED])"
    );
    assert_eq!(
        format!(
            "{:?}",
            store
                .local_presence_authorizer("explicit-audience", support::n(4096), support::n(16384))
                .unwrap()
        ),
        "PostgresLocalPresenceAuthorizer([REDACTED])"
    );
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, b)
            .await
            .unwrap_err(),
        deny
    );
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Publish, a)
            .await
            .unwrap_err(),
        deny
    );
    assert_eq!(presence_data_snapshot(&mut c).await, before);
    let used: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT last_used_at FROM public.local_tokens WHERE token_id='access-test'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(used, None);
    // A second rule must not combine its publish capability with the first rule's project.
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('b','second','user','alice','',0,0)").execute(&mut c).await.unwrap();
    sqlx_core::query::query(
        "INSERT INTO public.grant_capabilities(grant_id,value) VALUES('b','presence:publish')",
    )
    .execute(&mut c)
    .await
    .unwrap();
    sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES('b',$1)")
        .bind(b)
        .execute(&mut c)
        .await
        .unwrap();
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Publish, a)
            .await
            .unwrap_err(),
        deny
    );
    presence_authorize(&store, raw, PresenceCapability::Publish, b)
        .await
        .unwrap();
    for (access, principal) in [
        ("team", "d[ae]v"),
        ("organization", "org/*"),
        ("subject", "local|alice-*"),
        ("subject", "alice-subject"),
        ("authenticated", ""),
        ("global", ""),
    ] {
        presence_set_rule(
            &mut c,
            PresenceFixtureRule {
                access,
                principal,
                capabilities: &["presence:*"],
                projects: &[],
            },
        )
        .await;
        presence_authorize(&store, raw, PresenceCapability::Publish, b)
            .await
            .unwrap();
    }
    presence_set_rule(
        &mut c,
        PresenceFixtureRule {
            access: "team",
            principal: "dev",
            capabilities: &["presence:read"],
            projects: &["*"],
        },
    )
    .await;
    presence_authorize(&store, raw, PresenceCapability::Read, a)
        .await
        .unwrap();
    c.execute("UPDATE public.local_users SET teams_json='[]' WHERE username='alice'")
        .await
        .unwrap();
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        deny
    );
    c.execute(
        "UPDATE public.local_users SET teams_json='[\"dev\",\"team\"]' WHERE username='alice'",
    )
    .await
    .unwrap();
    presence_authorize(&store, raw, PresenceCapability::Read, a)
        .await
        .unwrap();
    presence_set_rule(
        &mut c,
        PresenceFixtureRule {
            access: "organization",
            principal: "org/*",
            capabilities: &["presence:read"],
            projects: &[a],
        },
    )
    .await;
    c.execute("UPDATE public.local_users SET organization='other' WHERE username='alice'")
        .await
        .unwrap();
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        deny
    );
    c.execute("UPDATE public.local_users SET organization='org/team' WHERE username='alice'")
        .await
        .unwrap();
    presence_authorize(&store, raw, PresenceCapability::Read, a)
        .await
        .unwrap();
    presence_set_rule(
        &mut c,
        PresenceFixtureRule {
            access: "user",
            principal: "bot",
            capabilities: &["presence:read"],
            projects: &[a],
        },
    )
    .await;
    let bot = presence_authorize(&store, service_raw, PresenceCapability::Read, a)
        .await
        .unwrap();
    assert_eq!(bot.principal().auth_method(), "service-credential");
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        deny
    );
    // SQL owner gets no implicit capability from Hub or administrator state.
    presence_set_rule(
        &mut c,
        PresenceFixtureRule {
            access: "global",
            principal: "",
            capabilities: &["hub"],
            projects: &[],
        },
    )
    .await;
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        deny
    );
    presence_set_rule(
        &mut c,
        PresenceFixtureRule {
            access: "user",
            principal: "alice",
            capabilities: &["presence:*"],
            projects: &[a],
        },
    )
    .await;
    for bad in [
        "gb_rt_presence-refresh",
        " gb_at_presence-access",
        "gb_at_absent",
        "eyJ.jwt",
    ] {
        assert_eq!(
            presence_authorize(&store, bad, PresenceCapability::Read, a)
                .await
                .unwrap_err(),
            unauth
        );
    }
    for project in [
        "global",
        "00000000000000000000000000",
        "01arz3ndektsv4rrffq69g5fav",
    ] {
        assert_eq!(
            presence_authorize(&store, raw, PresenceCapability::Read, project)
                .await
                .unwrap_err(),
            PresenceAuthorizationError::InvalidProject
        );
    }
    for mutation in [
        "UPDATE public.local_tokens SET revoked_at=0 WHERE token_id='access-test'",
        "UPDATE public.local_tokens SET expires_at=0 WHERE token_id='access-test'",
        "UPDATE public.local_tokens SET audience='wrong' WHERE token_id='access-test'",
        "UPDATE public.local_tokens SET token_kind='service' WHERE token_id='access-test'",
        "UPDATE public.local_tokens SET scopes_json='[]' WHERE token_id='access-test'",
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_users SET revision=2 WHERE username='alice'",
    ] {
        sqlx_core::query::query(mutation)
            .execute(&mut c)
            .await
            .unwrap();
        assert_eq!(
            presence_authorize(&store, raw, PresenceCapability::Read, a)
                .await
                .unwrap_err(),
            unauth
        );
        c.execute("UPDATE public.local_users SET enabled=1,revision=1 WHERE username='alice'; UPDATE public.local_tokens SET revoked_at=NULL,audience='explicit-audience',token_kind='access',scopes_json='[\"presence:read\",\"presence:publish\"]' WHERE token_id='access-test'").await.unwrap();
        sqlx_core::query::query(
            "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-test'",
        )
        .bind(opaque_now() + 120_000_000)
        .execute(&mut c)
        .await
        .unwrap();
    }
    // Malformed unrelated rule must prevent partial activation of an otherwise allowing document.
    c.execute("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('z','invalid','user','[','',0,0); INSERT INTO public.grant_capabilities(grant_id,value) VALUES('z','presence:read')").await.unwrap();
    let before = presence_data_snapshot(&mut c).await;
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        PresenceAuthorizationError::InvalidPolicy
    );
    assert_eq!(presence_data_snapshot(&mut c).await, before);
    c.execute("DELETE FROM public.resource_grants WHERE id='z'; UPDATE public.resource_grants SET access_kind='admin'").await.unwrap();
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        PresenceAuthorizationError::InvalidPolicy
    );
    c.execute("UPDATE public.resource_grants SET access_kind='user'; UPDATE public.grant_projects SET value='global'").await.unwrap();
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        PresenceAuthorizationError::InvalidPolicy
    );
    sqlx_core::query::query("UPDATE public.grant_projects SET value=$1")
        .bind(a)
        .execute(&mut c)
        .await
        .unwrap();
    c.execute("UPDATE public.resource_acl_state SET revision=0")
        .await
        .unwrap();
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        PresenceAuthorizationError::Grants(ResourceGrantReadError::MalformedStored)
    );
    c.execute("UPDATE public.resource_acl_state SET revision=50; DELETE FROM public.resource_acl_state WHERE id=1").await.unwrap();
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        PresenceAuthorizationError::Grants(ResourceGrantReadError::MalformedStored)
    );
    c.execute("INSERT INTO public.resource_acl_state(id,revision,updated_at) VALUES(1,50,50)")
        .await
        .unwrap();
    assert_eq!(
        store
            .local_presence_authorizer("explicit-audience", support::n(4096), support::n(8))
            .unwrap()
            .authorize_project(raw, &[], PresenceCapability::Read, a, deadline())
            .await
            .unwrap_err(),
        PresenceAuthorizationError::Grants(ResourceGrantReadError::ReadLimitExceeded)
    );
    assert_eq!(
        store
            .local_presence_authorizer("explicit-audience", support::n(8), support::n(16384))
            .unwrap()
            .authorize_project(raw, &[], PresenceCapability::Read, a, deadline())
            .await
            .unwrap_err(),
        PresenceAuthorizationError::Authentication(LocalBearerVerificationError::State(
            LocalBearerStateError::ReadLimitExceeded
        ))
    );
    c.execute("REVOKE SELECT ON public.grant_capabilities FROM opaque_owner")
        .await
        .unwrap();
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        PresenceAuthorizationError::Control(ControlError::Storage)
    );
    c.execute("GRANT SELECT ON public.grant_capabilities TO opaque_owner")
        .await
        .unwrap();
    presence_authorize(&store, raw, PresenceCapability::Read, a)
        .await
        .unwrap();

    let mut locker = fixture.connection().await;
    let mut lock = locker.begin().await.unwrap();
    sqlx_core::query::query("LOCK TABLE public.grant_capabilities IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    assert_eq!(
        store
            .local_presence_authorizer("explicit-audience", support::n(4096), support::n(16384))
            .unwrap()
            .authorize_project(
                raw,
                &[],
                PresenceCapability::Read,
                a,
                Instant::now() + Duration::from_millis(300)
            )
            .await
            .unwrap_err(),
        PresenceAuthorizationError::Control(ControlError::Deadline)
    );
    lock.rollback().await.unwrap();
    presence_authorize(&store, raw, PresenceCapability::Read, a)
        .await
        .unwrap();
    let before = presence_data_snapshot(&mut c).await;
    let mut lock = locker.begin().await.unwrap();
    sqlx_core::query::query("LOCK TABLE public.grant_capabilities IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let s = store.clone();
    let cancelled =
        tokio::spawn(async move { presence_authorize(&s, raw, PresenceCapability::Read, a).await });
    let mut monitor = fixture.connection().await;
    wait_for_query(&mut monitor, "WITH policy AS MATERIALIZED").await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    assert_eq!(presence_data_snapshot(&mut c).await, before);
    presence_authorize(&store, raw, PresenceCapability::Read, a)
        .await
        .unwrap();
    // Prove expiry after initial authentication by waiting for the actual ACL query.
    let mut lock = locker.begin().await.unwrap();
    sqlx_core::query::query("LOCK TABLE public.grant_capabilities IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let expiry = opaque_now() + 2_000_000;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-test'",
    )
    .bind(expiry)
    .execute(&mut c)
    .await
    .unwrap();
    let s = store.clone();
    let pending =
        tokio::spawn(async move { presence_authorize(&s, raw, PresenceCapability::Read, a).await });
    wait_for_query(&mut monitor, "WITH policy AS MATERIALIZED").await;
    while opaque_now() <= expiry {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    lock.rollback().await.unwrap();
    assert_eq!(pending.await.unwrap().unwrap_err(), unauth);
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-test'",
    )
    .bind(opaque_now() + 120_000_000)
    .execute(&mut c)
    .await
    .unwrap();
    presence_authorize(&store, raw, PresenceCapability::Read, a)
        .await
        .unwrap();
    assert_eq!(
        store
            .local_presence_authorizer("explicit-audience", support::n(4096), support::n(16384))
            .unwrap()
            .authorize_project(raw, &[], PresenceCapability::Read, a, Instant::now())
            .await
            .unwrap_err(),
        PresenceAuthorizationError::Control(ControlError::Deadline)
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        presence_authorize(&store, raw, PresenceCapability::Read, a)
            .await
            .unwrap_err(),
        PresenceAuthorizationError::Control(ControlError::Closed)
    );
    let reopened =
        PostgresControlStore::open(opaque_config(&fixture), support::digester(), deadline())
            .await
            .unwrap();
    presence_authorize(&reopened, raw, PresenceCapability::Read, a)
        .await
        .unwrap();
    reopened.shutdown(deadline()).await.unwrap();
    monitor.close().await.unwrap();
    locker.close().await.unwrap();
    c.close().await.unwrap();
}

async fn register_local_inventory(
    store: &PostgresControlStore,
    raw: &str,
    inventory: &InstanceInventory,
    caller: Instant,
) -> Result<broker_control::RegistrationResult, InstanceRegistrationError> {
    store
        .local_instance_registrar("explicit-audience", support::n(4096), support::n(16384))
        .unwrap()
        .register(raw, &["presence:publish".into()], inventory, caller)
        .await
}
#[tokio::test]
#[ignore = "real PostgreSQL authenticated all-project registration and immutable owner"]
async fn postgres_local_instance_registration_contract() {
    let fixture = Fixture::new(true).await;
    let mut c = fixture.connection().await;
    c.execute("CREATE ROLE opaque_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION opaque_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO opaque_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(opaque_config(&fixture), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let is_super: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='opaque_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!is_super);
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Alice','','org/team','[\"dev\"]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','Automation','[]',1,0,1,0,0)").await.unwrap();
    let raw = "gb_at_registration-access";
    let service_raw = "gb_sc_registration-service";
    for (token,kind,kind_name,id,subject,principal) in [
        (raw,TokenKind::LocalAccess,"access","access-test","alice-subject",bearer_principal(1)),
        (service_raw,TokenKind::ServiceCredential,"service","service-test","bot-subject",serde_json::json!({"issuer":"local","subject":"bot-subject","username":"stale-bot","auth_method":"old","local_user_revision":1}).to_string()),
    ] {
        let hash = support::digester().token(kind,token.as_bytes()).unwrap();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'other',$5,'explicit-client','explicit-audience','','[\"presence:publish\"]',1,'',0,$6,0)")
            .bind(hash.to_sql_hex()).bind(id).bind(kind_name).bind(subject).bind(principal).bind(opaque_now()+120_000_000).execute(&mut c).await.unwrap();
    }
    let a = REGISTRY_PROJECT_A;
    let b = REGISTRY_PROJECT_B;
    let original = instance_inventory(
        "authenticated-station",
        &[(b, &["main"]), (a, &["release", "main"])],
    );
    let replacement = instance_inventory("authenticated-station", &[(a, &["feature", "main"])]);
    let empty = instance_inventory("authenticated-station", &[]);
    let empty_first = instance_inventory("empty-first", &[]);
    let deny = InstanceRegistrationError::Authorization(PresenceAuthorizationError::Forbidden);
    let unauth = InstanceRegistrationError::Authorization(
        PresenceAuthorizationError::Authentication(LocalBearerVerificationError::Unauthenticated),
    );
    let before_auth = presence_data_snapshot(&mut c).await;
    assert_eq!(
        register_local_inventory(&store, raw, &original, deadline())
            .await
            .unwrap_err(),
        deny
    );
    assert!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .is_none()
    );
    assert_eq!(presence_data_snapshot(&mut c).await, before_auth);
    presence_set_rule(
        &mut c,
        PresenceFixtureRule {
            access: "user",
            principal: "alice",
            capabilities: &["presence:publish"],
            projects: &[a],
        },
    )
    .await;
    let before = presence_data_snapshot(&mut c).await;
    assert_eq!(
        register_local_inventory(&store, raw, &original, deadline())
            .await
            .unwrap_err(),
        deny
    );
    assert_eq!(presence_data_snapshot(&mut c).await, before);
    assert!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .is_none()
    );
    presence_set_rule(
        &mut c,
        PresenceFixtureRule {
            access: "team",
            principal: "dev",
            capabilities: &["presence:publish"],
            projects: &[a, b],
        },
    )
    .await;
    let created = register_local_inventory(&store, raw, &original, deadline())
        .await
        .unwrap();
    assert_eq!(created.change(), RegistrationChange::Created);
    let first = instance_sql_snapshot(&mut c, original.instance_id())
        .await
        .unwrap();
    assert_eq!(
        (&*first.parent.0, &*first.parent.1),
        ("local", "alice-subject")
    );
    assert_eq!(
        (first.parent.2, first.parent.3),
        (created.created_at_micros(), created.updated_at_micros())
    );
    assert_eq!(
        first.versions,
        vec![
            (a.into(), 1, "main".into()),
            (a.into(), 2, "release".into()),
            (b.into(), 1, "main".into())
        ]
    );
    let repeated = register_local_inventory(&store, raw, &original, deadline())
        .await
        .unwrap();
    assert_eq!(repeated.change(), RegistrationChange::Unchanged);
    assert_eq!(repeated.updated_at_micros(), created.updated_at_micros());
    assert_eq!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .unwrap(),
        first
    );
    let updated = register_local_inventory(&store, raw, &replacement, deadline())
        .await
        .unwrap();
    assert_eq!(updated.change(), RegistrationChange::Updated);
    assert_eq!(updated.created_at_micros(), created.created_at_micros());
    let populated = instance_sql_snapshot(&mut c, original.instance_id())
        .await
        .unwrap();
    assert_eq!(
        populated.versions,
        vec![
            (a.into(), 1, "feature".into()),
            (a.into(), 2, "main".into())
        ]
    );
    c.execute("UPDATE public.local_users SET teams_json='[]' WHERE username='alice'")
        .await
        .unwrap();
    assert_eq!(
        register_local_inventory(&store, raw, &original, deadline())
            .await
            .unwrap_err(),
        deny
    );
    assert_eq!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .unwrap(),
        populated
    );
    c.execute("UPDATE public.local_users SET teams_json='[\"dev\"]' WHERE username='alice'")
        .await
        .unwrap();
    assert_eq!(
        register_local_inventory(&store, raw, &replacement, deadline())
            .await
            .unwrap()
            .change(),
        RegistrationChange::Unchanged
    );
    // A project-specific Publish rule cannot authorize a projectless registration/clear.
    for inventory in [&empty, &empty_first] {
        assert_eq!(
            register_local_inventory(&store, raw, inventory, deadline())
                .await
                .unwrap_err(),
            deny
        );
    }
    assert!(
        instance_sql_snapshot(&mut c, empty_first.instance_id())
            .await
            .is_none()
    );
    assert_eq!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .unwrap(),
        populated
    );
    // Read Any cannot lend its scope to Publish on a specific project.
    c.execute("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('b','read-any','user','alice','',0,0); INSERT INTO public.grant_capabilities(grant_id,value) VALUES('b','presence:read')").await.unwrap();
    assert_eq!(
        register_local_inventory(&store, raw, &empty, deadline())
            .await
            .unwrap_err(),
        deny
    );
    assert_eq!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .unwrap(),
        populated
    );
    for projects in [&[][..], &["*"][..]] {
        presence_set_rule(
            &mut c,
            PresenceFixtureRule {
                access: "user",
                principal: "alice",
                capabilities: &["presence:publish"],
                projects,
            },
        )
        .await;
        let result = register_local_inventory(&store, raw, &empty_first, deadline())
            .await
            .unwrap();
        assert_eq!(
            result.change(),
            if projects.is_empty() {
                RegistrationChange::Created
            } else {
                RegistrationChange::Unchanged
            }
        );
    }
    let first_empty = instance_sql_snapshot(&mut c, empty_first.instance_id())
        .await
        .unwrap();
    assert_eq!(
        (&*first_empty.parent.0, &*first_empty.parent.1),
        ("local", "alice-subject")
    );
    assert!(first_empty.versions.is_empty());
    let cleared = register_local_inventory(&store, raw, &empty, deadline())
        .await
        .unwrap();
    assert_eq!(cleared.change(), RegistrationChange::Updated);
    assert_eq!(cleared.created_at_micros(), created.created_at_micros());
    let cleared_snapshot = instance_sql_snapshot(&mut c, original.instance_id())
        .await
        .unwrap();
    assert!(cleared_snapshot.versions.is_empty());
    assert_eq!(
        register_local_inventory(&store, raw, &empty, deadline())
            .await
            .unwrap()
            .change(),
        RegistrationChange::Unchanged
    );
    assert_eq!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .unwrap(),
        cleared_snapshot
    );
    // Even an authenticated other owner with Any Publish cannot overwrite or clear.
    presence_set_rule(
        &mut c,
        PresenceFixtureRule {
            access: "authenticated",
            principal: "",
            capabilities: &["presence:publish"],
            projects: &["*"],
        },
    )
    .await;
    for inventory in [&original, &empty] {
        assert_eq!(
            register_local_inventory(&store, service_raw, inventory, deadline())
                .await
                .unwrap_err(),
            InstanceRegistrationError::Registry(InstanceRegistryError::OwnerConflict)
        );
        assert_eq!(
            instance_sql_snapshot(&mut c, original.instance_id())
                .await
                .unwrap(),
            cleared_snapshot
        );
    }
    let bot_inventory = instance_inventory("bot-station", &[(b, &["release"])]);
    register_local_inventory(&store, service_raw, &bot_inventory, deadline())
        .await
        .unwrap();
    let bot = instance_sql_snapshot(&mut c, bot_inventory.instance_id())
        .await
        .unwrap();
    assert_eq!((&*bot.parent.0, &*bot.parent.1), ("local", "bot-subject"));
    assert_eq!(
        format!(
            "{:?}",
            store
                .local_instance_registrar("explicit-audience", support::n(4096), support::n(16384))
                .unwrap()
        ),
        "PostgresLocalInstanceRegistrar([REDACTED])"
    );
    for bad in [
        "gb_rt_registration-refresh",
        " gb_at_registration-access",
        "gb_at_absent",
        "eyJ.jwt",
    ] {
        assert_eq!(
            register_local_inventory(&store, bad, &replacement, deadline())
                .await
                .unwrap_err(),
            unauth
        );
        assert_eq!(
            instance_sql_snapshot(&mut c, original.instance_id())
                .await
                .unwrap(),
            cleared_snapshot
        );
    }
    for mutation in [
        "UPDATE public.local_tokens SET revoked_at=0 WHERE token_id='access-test'",
        "UPDATE public.local_tokens SET expires_at=0 WHERE token_id='access-test'",
        "UPDATE public.local_tokens SET audience='wrong' WHERE token_id='access-test'",
        "UPDATE public.local_tokens SET scopes_json='[]' WHERE token_id='access-test'",
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_users SET revision=2 WHERE username='alice'",
        "UPDATE public.local_users SET subject='changed-subject' WHERE username='alice'",
    ] {
        sqlx_core::query::query(mutation)
            .execute(&mut c)
            .await
            .unwrap();
        assert_eq!(
            register_local_inventory(&store, raw, &replacement, deadline())
                .await
                .unwrap_err(),
            unauth
        );
        assert_eq!(
            instance_sql_snapshot(&mut c, original.instance_id())
                .await
                .unwrap(),
            cleared_snapshot
        );
        c.execute("UPDATE public.local_users SET enabled=1,revision=1,subject='alice-subject' WHERE username='alice'; UPDATE public.local_tokens SET revoked_at=NULL,audience='explicit-audience',scopes_json='[\"presence:publish\"]' WHERE token_id='access-test'").await.unwrap();
        sqlx_core::query::query(
            "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-test'",
        )
        .bind(opaque_now() + 120_000_000)
        .execute(&mut c)
        .await
        .unwrap();
    }
    assert_eq!(
        store
            .local_instance_registrar("wrong-audience", support::n(4096), support::n(16384))
            .unwrap()
            .register(raw, &[], &replacement, deadline())
            .await
            .unwrap_err(),
        unauth
    );
    assert_eq!(
        store
            .local_instance_registrar("explicit-audience", support::n(4096), support::n(16384))
            .unwrap()
            .register(raw, &["missing-scope".into()], &replacement, deadline())
            .await
            .unwrap_err(),
        unauth
    );
    assert_eq!(
        store
            .local_instance_registrar("explicit-audience", support::n(8), support::n(16384))
            .unwrap()
            .register(raw, &[], &replacement, deadline())
            .await
            .unwrap_err(),
        InstanceRegistrationError::Authorization(PresenceAuthorizationError::Authentication(
            LocalBearerVerificationError::State(LocalBearerStateError::ReadLimitExceeded)
        ))
    );
    assert_eq!(
        store
            .local_instance_registrar("explicit-audience", support::n(4096), support::n(8))
            .unwrap()
            .register(raw, &[], &replacement, deadline())
            .await
            .unwrap_err(),
        InstanceRegistrationError::Authorization(PresenceAuthorizationError::Grants(
            ResourceGrantReadError::ReadLimitExceeded
        ))
    );
    c.execute("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('z','invalid','user','[','',0,0); INSERT INTO public.grant_capabilities(grant_id,value) VALUES('z','presence:read')").await.unwrap();
    assert_eq!(
        register_local_inventory(&store, raw, &replacement, deadline())
            .await
            .unwrap_err(),
        InstanceRegistrationError::Authorization(PresenceAuthorizationError::InvalidPolicy)
    );
    assert_eq!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .unwrap(),
        cleared_snapshot
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='z'; REVOKE SELECT ON public.grant_capabilities FROM opaque_owner").await.unwrap();
    assert_eq!(
        register_local_inventory(&store, raw, &replacement, deadline())
            .await
            .unwrap_err(),
        InstanceRegistrationError::Authorization(PresenceAuthorizationError::Control(
            ControlError::Storage
        ))
    );
    c.execute("GRANT SELECT ON public.grant_capabilities TO opaque_owner")
        .await
        .unwrap();
    let mut locker = fixture.connection().await;
    let mut monitor = fixture.connection().await;
    // Final expiry check occurs after a causally observed ACL read.
    let mut lock = locker.begin().await.unwrap();
    sqlx_core::query::query("LOCK TABLE public.grant_capabilities IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let expiry = opaque_now() + 2_000_000;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-test'",
    )
    .bind(expiry)
    .execute(&mut c)
    .await
    .unwrap();
    let s = store.clone();
    let pending = tokio::spawn(async move {
        register_local_inventory(
            &s,
            raw,
            &instance_inventory(
                "authenticated-station",
                &[(REGISTRY_PROJECT_A, &["after-expiry"])],
            ),
            deadline(),
        )
        .await
    });
    wait_for_query(&mut monitor, "WITH policy AS MATERIALIZED").await;
    while opaque_now() <= expiry {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    lock.rollback().await.unwrap();
    assert_eq!(pending.await.unwrap().unwrap_err(), unauth);
    assert_eq!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .unwrap(),
        cleared_snapshot
    );
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-test'",
    )
    .bind(opaque_now() + 120_000_000)
    .execute(&mut c)
    .await
    .unwrap();
    // An owner row lock blocks the genuine SQL writer after authorization.
    let mut lock = locker.begin().await.unwrap();
    sqlx_core::query::query(
        "SELECT instance_id FROM public.broker_instances WHERE instance_id=$1 FOR UPDATE",
    )
    .bind(original.instance_id())
    .fetch_one(&mut *lock)
    .await
    .unwrap();
    assert_eq!(
        register_local_inventory(
            &store,
            raw,
            &replacement,
            Instant::now() + Duration::from_millis(300)
        )
        .await
        .unwrap_err(),
        InstanceRegistrationError::Registry(InstanceRegistryError::Control(ControlError::Deadline))
    );
    lock.rollback().await.unwrap();
    assert_eq!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .unwrap(),
        cleared_snapshot
    );
    let mut lock = locker.begin().await.unwrap();
    sqlx_core::query::query(
        "SELECT instance_id FROM public.broker_instances WHERE instance_id=$1 FOR UPDATE",
    )
    .bind(original.instance_id())
    .fetch_one(&mut *lock)
    .await
    .unwrap();
    let s = store.clone();
    let cancelled = tokio::spawn(async move {
        register_local_inventory(
            &s,
            raw,
            &instance_inventory(
                "authenticated-station",
                &[(REGISTRY_PROJECT_A, &["after-cancel"])],
            ),
            deadline(),
        )
        .await
    });
    wait_for_query(
        &mut monitor,
        "FROM public.broker_instances WHERE instance_id=$1 FOR UPDATE",
    )
    .await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    assert_eq!(
        instance_sql_snapshot(&mut c, original.instance_id())
            .await
            .unwrap(),
        cleared_snapshot
    );
    let recovered = register_local_inventory(&store, raw, &replacement, deadline())
        .await
        .unwrap();
    assert_eq!(recovered.change(), RegistrationChange::Updated);
    assert_eq!(
        register_local_inventory(&store, raw, &replacement, Instant::now())
            .await
            .unwrap_err(),
        InstanceRegistrationError::Authorization(PresenceAuthorizationError::Control(
            ControlError::Deadline
        ))
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        register_local_inventory(&store, raw, &replacement, deadline())
            .await
            .unwrap_err(),
        InstanceRegistrationError::Authorization(PresenceAuthorizationError::Control(
            ControlError::Closed
        ))
    );
    let reopened =
        PostgresControlStore::open(opaque_config(&fixture), support::digester(), deadline())
            .await
            .unwrap();
    assert_eq!(
        register_local_inventory(&reopened, raw, &replacement, deadline())
            .await
            .unwrap()
            .change(),
        RegistrationChange::Unchanged
    );
    reopened.shutdown(deadline()).await.unwrap();
    monitor.close().await.unwrap();
    locker.close().await.unwrap();
    c.close().await.unwrap();
}
