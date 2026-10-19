// Shared helpers also serve other active control tests.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture has helpers used by other suites"
)]
mod support;
use broker_control::{
    ConnectionLimits, ControlError, InstanceInventory, InstanceInventoryReadError as ReadError,
    InstanceOwner, InstanceProjectVersions, InstanceReadError, LocalBearerVerificationError,
    PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
    PresenceAuthorizationError as AuthError, ResourceGrantReadError,
};
use broker_security::TokenKind;
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const RAW: &str = "gb_at_inventory-reader";
const SERVICE: &str = "gb_sc_inventory-reader";
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
fn scopes() -> Vec<String> {
    vec!["presence:read".into()]
}
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "read_owner".into(),
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
            .map(|(id, v)| {
                InstanceProjectVersions::new((*id).into(), v.iter().map(|v| (*v).into()).collect())
                    .unwrap()
            })
            .collect(),
    )
    .unwrap()
}
async fn grant(
    c: &mut sqlx_postgres::PgConnection,
    id: &str,
    who: &str,
    cap: &str,
    project: Option<&str>,
) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture','user',$2,'',0,0)").bind(id).bind(who).execute(&mut *c).await.unwrap();
    sqlx_core::query::query("INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)")
        .bind(id)
        .bind(cap)
        .execute(&mut *c)
        .await
        .unwrap();
    if let Some(p) = project {
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(p)
            .execute(&mut *c)
            .await
            .unwrap();
    }
}
async fn sql_snapshot(
    c: &mut sqlx_postgres::PgConnection,
) -> (
    Vec<(String, String, String, i64, i64)>,
    Vec<(String, String, i64, String)>,
) {
    let parents=sqlx_core::query_as::query_as("SELECT instance_id,owner_issuer,owner_subject,created_at,updated_at FROM public.broker_instances ORDER BY instance_id COLLATE \"C\"").fetch_all(&mut *c).await.unwrap();
    let children=sqlx_core::query_as::query_as("SELECT instance_id,project_id,position,version FROM public.broker_instance_project_versions ORDER BY instance_id COLLATE \"C\",project_id COLLATE \"C\",position").fetch_all(&mut *c).await.unwrap();
    (parents, children)
}
async fn observe_lock(c: &mut sqlx_postgres::PgConnection, inventory: bool) {
    let limit = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let sql = if inventory {
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='read_owner' AND wait_event_type='Lock' AND query LIKE '%WITH inventory AS MATERIALIZED%')"
        } else {
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='read_owner' AND wait_event_type='Lock' AND query LIKE '%WITH policy AS MATERIALIZED%')"
        };
        let found: bool = sqlx_core::query_scalar::query_scalar(sql)
            .fetch_one(&mut *c)
            .await
            .unwrap();
        if found {
            break;
        }
        assert!(
            Instant::now() < limit,
            "business reader reaches genuine SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS raw local Auth, own-inventory READ ALL/Any and cancellation"]
async fn postgres_local_instance_inventory_read_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE read_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION read_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO read_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='read_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Alice','','org','[]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','org','[]',1,0,1,0,0)").await.unwrap();
    for (raw, kind, id, name, subject) in [
        (
            RAW,
            TokenKind::LocalAccess,
            "access-read",
            "access",
            "alice-subject",
        ),
        (
            SERVICE,
            TokenKind::ServiceCredential,
            "service-read",
            "service",
            "bot-subject",
        ),
    ] {
        let digest = support::digester().token(kind, raw.as_bytes()).unwrap();
        let principal=serde_json::json!({"issuer":"local","subject":subject,"username":"old-name","auth_method":"old","local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'envelope-subject',$5,'client','explicit-audience','','[\"presence:read\"]',1,'',0,$6,0)")
            .bind(digest.to_sql_hex()).bind(id).bind(name).bind(subject).bind(principal).bind(now()+120_000_000).execute(&mut c).await.unwrap();
    }
    let own = InstanceOwner::new("local", "alice-subject").unwrap();
    let bot = InstanceOwner::new("local", "bot-subject").unwrap();
    let data = inventory("station", &[(B, &["main"]), (A, &["release", "main"])]);
    let registered = store
        .replace_instance_inventory(&own, &data, deadline())
        .await
        .unwrap();
    store
        .replace_instance_inventory(&own, &inventory("empty", &[]), deadline())
        .await
        .unwrap();
    store
        .replace_instance_inventory(&bot, &inventory("service", &[(A, &["main"])]), deadline())
        .await
        .unwrap();
    store
        .replace_instance_inventory(
            &InstanceOwner::new("local", "alice-subject ").unwrap(),
            &inventory("literal", &[(A, &["main"])]),
            deadline(),
        )
        .await
        .unwrap();
    let before = sql_snapshot(&mut c).await;
    let reader = store
        .local_instance_inventory_reader("explicit-audience", n(4096), n(16384), n(16384))
        .unwrap();
    assert_eq!(
        format!("{reader:?}"),
        "PostgresLocalInstanceInventoryReader([REDACTED])"
    );
    assert!(
        reader
            .read(RAW, &scopes(), "absent", deadline())
            .await
            .unwrap()
            .is_none()
    );
    for raw in [
        "",
        "gb_rt_inventory-reader",
        "gb_at_unknown",
        "eyJhbGci.fake.jwt",
    ] {
        assert_eq!(
            reader
                .read(raw, &scopes(), "absent", deadline())
                .await
                .unwrap_err(),
            ReadError::Authorization(AuthError::Authentication(
                LocalBearerVerificationError::Unauthenticated
            ))
        );
    }
    grant(&mut c, "a", "alice", "presence:read", Some(A)).await;
    assert_eq!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Forbidden)
    );
    grant(&mut c, "b", "alice", "presence:publish", Some(B)).await;
    grant(&mut c, "wrong-principal", "bob", "presence:read", Some(B)).await;
    assert_eq!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Forbidden)
    );
    c.execute("UPDATE public.grant_capabilities SET value='presence:read' WHERE grant_id='b'")
        .await
        .unwrap();
    let read = reader
        .read(RAW, &scopes(), "station", deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.inventory(), &data);
    assert_eq!(
        (read.created_at_micros(), read.updated_at_micros()),
        (
            registered.created_at_micros(),
            registered.updated_at_micros()
        )
    );
    assert_eq!(
        format!("{read:?}"),
        "AuthorizedInstanceInventory([REDACTED])"
    );
    assert_eq!(
        reader
            .read(RAW, &scopes(), "empty", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Forbidden)
    );
    grant(&mut c, "any", "alice", "presence:publish", None).await;
    assert_eq!(
        reader
            .read(RAW, &scopes(), "empty", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Forbidden)
    );
    c.execute("UPDATE public.grant_capabilities SET value='presence:read' WHERE grant_id='any'")
        .await
        .unwrap();
    assert!(
        reader
            .read(RAW, &scopes(), "empty", deadline())
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .projects()
            .is_empty()
    );
    assert_eq!(
        reader
            .read(RAW, &scopes(), "service", deadline())
            .await
            .unwrap_err(),
        ReadError::OwnerConflict
    );
    assert_eq!(
        reader
            .read(RAW, &scopes(), "literal", deadline())
            .await
            .unwrap_err(),
        ReadError::OwnerConflict
    );
    grant(&mut c, "bot", "bot", "presence:read", Some(A)).await;
    assert_eq!(
        reader
            .read(SERVICE, &scopes(), "service", deadline())
            .await
            .unwrap()
            .unwrap()
            .inventory(),
        &inventory("service", &[(A, &["main"])])
    );
    assert_eq!(sql_snapshot(&mut c).await, before);

    // Current identity and policy observations, including attributes, are not cached.
    for sql in [
        "UPDATE public.local_tokens SET audience='other' WHERE token_id='access-read'",
        "UPDATE public.local_tokens SET scopes_json='[]' WHERE token_id='access-read'",
        "UPDATE public.local_tokens SET revoked_at=0 WHERE token_id='access-read'",
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_users SET revision=2 WHERE username='alice'",
    ] {
        c.execute(sql).await.unwrap();
        assert_eq!(
            reader
                .read(RAW, &scopes(), "station", deadline())
                .await
                .unwrap_err(),
            ReadError::Authorization(AuthError::Authentication(
                LocalBearerVerificationError::Unauthenticated
            ))
        );
        c.execute("UPDATE public.local_tokens SET audience='explicit-audience',scopes_json='[\"presence:read\"]',revoked_at=NULL WHERE token_id='access-read'; UPDATE public.local_users SET enabled=1,revision=1 WHERE username='alice'").await.unwrap();
    }
    c.execute("UPDATE public.resource_grants SET access_kind='team',principal='ops' WHERE id IN('a','b','any')").await.unwrap();
    assert_eq!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Forbidden)
    );
    c.execute("UPDATE public.local_users SET teams_json='[\"ops\"]' WHERE username='alice'")
        .await
        .unwrap();
    assert!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap()
            .is_some()
    );
    c.execute("UPDATE public.local_users SET teams_json='[]' WHERE username='alice'; UPDATE public.resource_grants SET access_kind='user',principal='alice' WHERE id IN('a','b','any')").await.unwrap();
    c.execute(
        "UPDATE public.grant_capabilities SET value='hub:admin' WHERE grant_id IN('a','b','any')",
    )
    .await
    .unwrap();
    assert_eq!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Forbidden)
    );
    c.execute("UPDATE public.grant_capabilities SET value='presence:read' WHERE grant_id IN('a','b','any')").await.unwrap();
    grant(&mut c, "malformed", "[", "presence:read", None).await;
    assert_eq!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::InvalidPolicy)
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='malformed'")
        .await
        .unwrap();

    let err = store
        .local_instance_inventory_reader("explicit-audience", n(8), n(16384), n(16384))
        .unwrap()
        .read(RAW, &scopes(), "station", deadline())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ReadError::Authorization(AuthError::Authentication(
            LocalBearerVerificationError::State(_)
        ))
    ));
    assert_eq!(
        store
            .local_instance_inventory_reader("explicit-audience", n(4096), n(8), n(16384))
            .unwrap()
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Grants(ResourceGrantReadError::ReadLimitExceeded))
    );
    assert_eq!(
        store
            .local_instance_inventory_reader("explicit-audience", n(4096), n(16384), n(8))
            .unwrap()
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Inventory(InstanceReadError::ReadLimitExceeded)
    );
    assert_eq!(
        reader
            .read(RAW, &scopes(), "invalid/id", deadline())
            .await
            .unwrap_err(),
        ReadError::Inventory(InstanceReadError::InvalidInstanceId)
    );
    c.execute(
        "UPDATE public.broker_instance_project_versions SET position=3 WHERE instance_id='service'",
    )
    .await
    .unwrap();
    assert_eq!(
        reader
            .read(SERVICE, &scopes(), "service", deadline())
            .await
            .unwrap_err(),
        ReadError::Inventory(InstanceReadError::MalformedStored)
    );
    c.execute("UPDATE public.broker_instance_project_versions SET position=1 WHERE instance_id='service'; UPDATE public.local_users SET teams_json='not-json' WHERE username='alice'").await.unwrap();
    assert!(matches!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Authentication(
            LocalBearerVerificationError::State(_)
        ))
    ));
    c.execute("UPDATE public.local_users SET teams_json='[]' WHERE username='alice'; REVOKE SELECT ON public.resource_grants FROM read_owner").await.unwrap();
    assert_eq!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Control(ControlError::Storage))
    );
    c.execute("GRANT SELECT ON public.resource_grants TO read_owner; REVOKE SELECT ON public.broker_instance_project_versions FROM read_owner").await.unwrap();
    assert_eq!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Inventory(InstanceReadError::Control(ControlError::Storage))
    );
    c.execute("GRANT SELECT ON public.broker_instance_project_versions TO read_owner")
        .await
        .unwrap();

    // Auth must remain unexpired after a causally observed wait in current ACL SQL.
    let expiry = now() + 2_000_000;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-read'",
    )
    .bind(expiry)
    .execute(&mut c)
    .await
    .unwrap();
    c.execute("BEGIN; LOCK TABLE public.resource_grants IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let running = store.clone();
    let job = tokio::spawn(async move {
        running
            .local_instance_inventory_reader("explicit-audience", n(4096), n(16384), n(16384))
            .unwrap()
            .read(RAW, &scopes(), "station", deadline())
            .await
    });
    observe_lock(&mut c, false).await;
    assert!(
        now() < expiry,
        "valid bearer reached ACL wait before expiry"
    );
    while now() <= expiry {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    c.execute("COMMIT").await.unwrap();
    assert_eq!(
        job.await.unwrap().unwrap_err(),
        ReadError::Authorization(AuthError::Authentication(
            LocalBearerVerificationError::Unauthenticated
        ))
    );
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-read'",
    )
    .bind(now() + 120_000_000)
    .execute(&mut c)
    .await
    .unwrap();

    c.execute("BEGIN; LOCK TABLE public.resource_grants IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let start = Instant::now();
    assert_eq!(
        reader
            .read(
                RAW,
                &scopes(),
                "station",
                start + Duration::from_millis(300)
            )
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Control(ControlError::Deadline))
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    c.execute("ROLLBACK").await.unwrap();
    assert!(
        reader
            .read(RAW, &scopes(), "station", deadline())
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
            .local_instance_inventory_reader("explicit-audience", n(4096), n(16384), n(16384))
            .unwrap()
            .read(RAW, &scopes(), "station", deadline())
            .await
    });
    observe_lock(&mut c, true).await;
    assert!(!job.is_finished());
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    c.execute("ROLLBACK").await.unwrap();
    assert!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(sql_snapshot(&mut c).await, before);
    assert_eq!(
        reader
            .read(RAW, &scopes(), "station", Instant::now())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Control(ControlError::Deadline))
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        reader
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap_err(),
        ReadError::Authorization(AuthError::Control(ControlError::Closed))
    );
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    assert_eq!(
        reopened
            .local_instance_inventory_reader("explicit-audience", n(4096), n(16384), n(16384))
            .unwrap()
            .read(RAW, &scopes(), "station", deadline())
            .await
            .unwrap()
            .unwrap()
            .inventory(),
        &data
    );
    reopened.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
