// Shared TLS helpers are also used by other control suites.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use broker_control::{
    AuthorizedInstanceList, ConnectionLimits, ControlError, InstanceInventory,
    InstanceListError as ListError, InstanceListQuery, InstanceOwner, InstanceProjectVersions,
    InstanceReadError, LocalBearerVerificationError, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint, PresenceAuthorizationError as AuthError,
    ResourceGrantReadError,
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
const RAW: &str = "gb_at_inventory-list";
const SERVICE: &str = "gb_sc_inventory-list";
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
fn query(
    limit: usize,
    after: Option<&str>,
    id: Option<&str>,
    project: Option<&str>,
    version: Option<&str>,
) -> InstanceListQuery {
    InstanceListQuery::new(
        n(limit),
        after.map(Into::into),
        id.map(Into::into),
        project.map(Into::into),
        version.map(Into::into),
    )
    .unwrap()
}
fn ids(page: &AuthorizedInstanceList) -> Vec<&str> {
    page.items()
        .iter()
        .map(|item| item.inventory().instance_id())
        .collect()
}
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "list_owner".into(),
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
    if let Some(project) = project {
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(project)
            .execute(&mut *c)
            .await
            .unwrap();
    }
}
async fn snapshot(
    c: &mut sqlx_postgres::PgConnection,
) -> (
    Vec<(String, String, String, i64, i64)>,
    Vec<(String, String, i64, String)>,
) {
    let parents=sqlx_core::query_as::query_as("SELECT instance_id,owner_issuer,owner_subject,created_at,updated_at FROM public.broker_instances ORDER BY instance_id COLLATE \"C\"").fetch_all(&mut *c).await.unwrap();
    let children=sqlx_core::query_as::query_as("SELECT instance_id,project_id,position,version FROM public.broker_instance_project_versions ORDER BY instance_id COLLATE \"C\",project_id COLLATE \"C\",position").fetch_all(&mut *c).await.unwrap();
    (parents, children)
}
async fn observe_inventory_lock(c: &mut sqlx_postgres::PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let blocked:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='list_owner' AND wait_event_type='Lock' AND query LIKE '%WITH candidate AS MATERIALIZED%')").fetch_one(&mut *c).await.unwrap();
        if blocked {
            return;
        }
        assert!(
            Instant::now() < end,
            "lister reaches an actual candidate SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS current local Auth and partial inventory listing"]
async fn postgres_local_instance_list_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE list_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION list_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO list_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='list_owner'",
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
            "access-list",
            "access",
            "alice-subject",
        ),
        (
            SERVICE,
            TokenKind::ServiceCredential,
            "service-list",
            "service",
            "bot-subject",
        ),
    ] {
        let digest = support::digester().token(kind, raw.as_bytes()).unwrap();
        let principal=serde_json::json!({"issuer":"local","subject":subject,"username":"obsolete","auth_method":"old","local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'envelope-subject',$5,'client','explicit-audience','','[\"presence:read\"]',1,'',0,$6,0)")
            .bind(digest.to_sql_hex()).bind(id).bind(name).bind(subject).bind(principal).bind(now()+120_000_000).execute(&mut c).await.unwrap();
    }
    let own = InstanceOwner::new("local", "alice-subject").unwrap();
    let foreign = InstanceOwner::new("local", "bot-subject").unwrap();
    let wrong_subject = InstanceOwner::new("local", "alice-subject ").unwrap();
    let wrong_issuer = InstanceOwner::new("local ", "alice-subject").unwrap();
    let first = store
        .replace_instance_inventory(
            &foreign,
            &inventory("A-visible", &[(B, &["private"]), (A, &["release", "main"])]),
            deadline(),
        )
        .await
        .unwrap();
    for (owner, data) in [
        (&foreign, inventory("B-hidden", &[(B, &["main"])])),
        (&own, inventory("C-visible", &[(A, &["main"])])),
        (&wrong_subject, inventory("D-hidden", &[])),
        (&own, inventory("E-empty", &[])),
        (&foreign, inventory("F-foreign-empty", &[])),
        (
            &foreign,
            inventory("G-visible", &[(A, &["main", "feature"])]),
        ),
        (&wrong_issuer, inventory("H-hidden", &[])),
        (&foreign, inventory("Z-hidden", &[(B, &["main"])])),
    ] {
        store
            .replace_instance_inventory(owner, &data, deadline())
            .await
            .unwrap();
    }
    let before = snapshot(&mut c).await;
    let list = store
        .local_instance_inventory_lister("explicit-audience", n(4096), n(16384), n(16384))
        .unwrap();
    assert_eq!(
        format!("{list:?}"),
        "PostgresLocalInstanceInventoryLister([REDACTED])"
    );
    assert!(
        ids(&list
            .list(
                RAW,
                &scopes(),
                &query(1, None, None, None, None),
                deadline()
            )
            .await
            .unwrap())
        .is_empty()
    );
    for raw in ["", "gb_rt_inventory-list", "gb_at_unknown", "eyJ.fake.jwt"] {
        assert_eq!(
            list.list(
                raw,
                &scopes(),
                &query(1, Some("zz"), None, None, None),
                deadline()
            )
            .await
            .unwrap_err(),
            ListError::Authorization(AuthError::Authentication(
                LocalBearerVerificationError::Unauthenticated
            ))
        );
    }
    grant(&mut c, "read-a", "alice", "presence:read", Some(A)).await;
    grant(&mut c, "publish-b", "alice", "presence:publish", Some(B)).await;
    grant(&mut c, "wrong-reader", "bob", "presence:read", Some(B)).await;
    let page = list
        .list(
            RAW,
            &scopes(),
            &query(1, None, None, None, None),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(ids(&page), ["A-visible"]);
    assert_eq!(page.next_after(), Some("A-visible"));
    assert_eq!(
        page.items()[0].inventory(),
        &inventory("A-visible", &[(A, &["main", "release"])])
    );
    assert_eq!(
        (
            page.items()[0].created_at_micros(),
            page.items()[0].updated_at_micros()
        ),
        (first.created_at_micros(), first.updated_at_micros())
    );
    assert_eq!(format!("{page:?}"), "AuthorizedInstanceList([REDACTED])");
    assert_eq!(
        format!("{:?}", page.items()[0]),
        "AuthorizedInstanceListItem([REDACTED])"
    );
    let second = list
        .list(
            RAW,
            &scopes(),
            &query(1, page.next_after(), None, None, None),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(ids(&second), ["C-visible"]);
    assert_eq!(second.next_after(), Some("C-visible"));
    let third = list
        .list(
            RAW,
            &scopes(),
            &query(1, second.next_after(), None, None, None),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(ids(&third), ["G-visible"]);
    assert_eq!(third.next_after(), None);
    assert!(
        ids(&list
            .list(
                RAW,
                &scopes(),
                &query(1, Some("G-visible"), None, None, None),
                deadline()
            )
            .await
            .unwrap())
        .is_empty()
    );
    let absent_cursor = list
        .list(
            RAW,
            &scopes(),
            &query(1, Some("B-absent"), None, None, None),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(ids(&absent_cursor), ["C-visible"]);
    let full = list
        .list(
            RAW,
            &scopes(),
            &query(3, None, None, None, None),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(ids(&full), ["A-visible", "C-visible", "G-visible"]);
    assert_eq!(full.next_after(), None); // Hidden rows after a full visible page are not "more".
    let filtered = list
        .list(
            RAW,
            &scopes(),
            &query(100, None, None, None, Some("main")),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(ids(&filtered), ["A-visible", "C-visible", "G-visible"]);
    for item in filtered.items() {
        assert_eq!(item.inventory().projects().len(), 1);
        assert_eq!(item.inventory().projects()[0].project_id(), A);
        assert_eq!(item.inventory().projects()[0].versions(), &["main"]);
    }
    assert_eq!(
        list.list(
            RAW,
            &scopes(),
            &query(100, None, None, Some(A), Some("release")),
            deadline()
        )
        .await
        .unwrap()
        .items()[0]
            .inventory(),
        &inventory("A-visible", &[(A, &["release"])])
    );
    for q in [
        query(100, None, None, Some(B), None),
        query(100, None, None, None, Some("absent")),
        query(100, None, None, Some(B), Some("main")),
        query(100, None, Some("absent"), None, None),
        query(100, Some("A-visible"), Some("A-visible"), None, None),
        query(100, Some("zz"), Some("A-visible"), None, None),
        query(100, None, Some("B-hidden"), None, None),
        query(100, None, Some("E-empty"), None, None),
    ] {
        let page = list.list(RAW, &scopes(), &q, deadline()).await.unwrap();
        assert!(page.items().is_empty());
        assert_eq!(page.next_after(), None);
    }
    let direct = list
        .list(
            RAW,
            &scopes(),
            &query(1, None, Some("A-visible"), None, None),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(ids(&direct), ["A-visible"]);
    assert_eq!(direct.next_after(), None);
    // Separate rules never splice READ from A into B; losing READ produces a valid empty page.
    c.execute("UPDATE public.grant_capabilities SET value='hub:admin' WHERE grant_id='read-a'")
        .await
        .unwrap();
    assert!(
        list.list(
            RAW,
            &scopes(),
            &query(100, page.next_after(), None, None, None),
            deadline()
        )
        .await
        .unwrap()
        .items()
        .is_empty()
    );
    c.execute("UPDATE public.grant_capabilities SET value='presence:read' WHERE grant_id='read-a'")
        .await
        .unwrap();
    grant(&mut c, "any", "alice", "presence:read", None).await;
    let any = list
        .list(
            RAW,
            &scopes(),
            &query(100, None, None, None, None),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        ids(&any),
        [
            "A-visible",
            "B-hidden",
            "C-visible",
            "E-empty",
            "G-visible",
            "Z-hidden"
        ]
    );
    assert!(
        any.items()
            .iter()
            .find(|i| i.inventory().instance_id() == "E-empty")
            .unwrap()
            .inventory()
            .projects()
            .is_empty()
    );
    for q in [
        query(100, None, Some("E-empty"), Some(A), None),
        query(100, None, Some("E-empty"), None, Some("main")),
    ] {
        assert!(
            list.list(RAW, &scopes(), &q, deadline())
                .await
                .unwrap()
                .items()
                .is_empty()
        );
    }
    c.execute("DELETE FROM public.resource_grants WHERE id='any'")
        .await
        .unwrap();
    grant(&mut c, "bot-read", "bot", "presence:read", Some(B)).await;
    assert_eq!(
        ids(&list
            .list(
                SERVICE,
                &scopes(),
                &query(100, None, None, None, None),
                deadline()
            )
            .await
            .unwrap()),
        ["A-visible", "B-hidden", "Z-hidden"]
    );
    grant(&mut c, "bot-any", "bot", "presence:read", None).await;
    assert!(
        ids(&list
            .list(
                SERVICE,
                &scopes(),
                &query(100, None, None, None, None),
                deadline()
            )
            .await
            .unwrap())
        .contains(&"F-foreign-empty")
    );
    assert_eq!(snapshot(&mut c).await, before);

    // Each new page resolves the current user and whole policy, even at EOF/direct short circuit.
    for sql in [
        "UPDATE public.local_tokens SET audience='other' WHERE token_id='access-list'",
        "UPDATE public.local_tokens SET scopes_json='[]' WHERE token_id='access-list'",
        "UPDATE public.local_tokens SET revoked_at=0 WHERE token_id='access-list'",
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_users SET revision=2 WHERE username='alice'",
    ] {
        c.execute(sql).await.unwrap();
        assert_eq!(
            list.list(
                RAW,
                &scopes(),
                &query(1, Some("zz"), Some("A-visible"), None, None),
                deadline()
            )
            .await
            .unwrap_err(),
            ListError::Authorization(AuthError::Authentication(
                LocalBearerVerificationError::Unauthenticated
            ))
        );
        c.execute("UPDATE public.local_tokens SET audience='explicit-audience',scopes_json='[\"presence:read\"]',revoked_at=NULL WHERE token_id='access-list'; UPDATE public.local_users SET enabled=1,revision=1 WHERE username='alice'").await.unwrap();
    }
    assert_eq!(
        list.list(
            RAW,
            &["other".into()],
            &query(1, None, None, None, None),
            deadline()
        )
        .await
        .unwrap_err(),
        ListError::Authorization(AuthError::Authentication(
            LocalBearerVerificationError::Unauthenticated
        ))
    );
    c.execute(
        "UPDATE public.resource_grants SET access_kind='team',principal='ops' WHERE id='read-a'",
    )
    .await
    .unwrap();
    assert!(
        list.list(
            RAW,
            &scopes(),
            &query(100, None, None, None, None),
            deadline()
        )
        .await
        .unwrap()
        .items()
        .is_empty()
    );
    c.execute("UPDATE public.local_users SET teams_json='[\"ops\"]' WHERE username='alice'")
        .await
        .unwrap();
    assert_eq!(
        ids(&list
            .list(
                RAW,
                &scopes(),
                &query(100, None, None, None, None),
                deadline()
            )
            .await
            .unwrap()),
        ["A-visible", "C-visible", "G-visible"]
    );
    c.execute("UPDATE public.local_users SET teams_json='[]' WHERE username='alice'; UPDATE public.resource_grants SET access_kind='user',principal='alice' WHERE id='read-a'").await.unwrap();
    grant(&mut c, "malformed", "[", "presence:read", None).await;
    c.execute("REVOKE SELECT ON public.broker_instances FROM list_owner")
        .await
        .unwrap();
    for q in [
        query(1, None, None, None, None),
        query(1, Some("zz"), Some("A-visible"), None, None),
    ] {
        assert_eq!(
            list.list(RAW, &scopes(), &q, deadline()).await.unwrap_err(),
            ListError::Authorization(AuthError::InvalidPolicy)
        );
    }
    c.execute("GRANT SELECT ON public.broker_instances TO list_owner; DELETE FROM public.resource_grants WHERE id='malformed'").await.unwrap();
    // The exact-ID optimization need not decode an unrelated corrupt candidate.
    c.execute("UPDATE public.broker_instance_project_versions SET position=3 WHERE instance_id='B-hidden'").await.unwrap();
    assert_eq!(
        list.list(
            RAW,
            &scopes(),
            &query(1, Some("A-visible"), None, None, None),
            deadline()
        )
        .await
        .unwrap_err(),
        ListError::Inventory(InstanceReadError::MalformedStored)
    );
    assert_eq!(
        ids(&list
            .list(
                RAW,
                &scopes(),
                &query(1, None, Some("A-visible"), None, None),
                deadline()
            )
            .await
            .unwrap()),
        ["A-visible"]
    );
    c.execute("UPDATE public.broker_instance_project_versions SET position=1 WHERE instance_id='B-hidden'").await.unwrap();

    assert!(matches!(
        store
            .local_instance_inventory_lister("explicit-audience", n(8), n(16384), n(16384))
            .unwrap()
            .list(
                RAW,
                &scopes(),
                &query(1, None, None, None, None),
                deadline()
            )
            .await
            .unwrap_err(),
        ListError::Authorization(AuthError::Authentication(
            LocalBearerVerificationError::State(_)
        ))
    ));
    assert_eq!(
        store
            .local_instance_inventory_lister("explicit-audience", n(4096), n(8), n(16384))
            .unwrap()
            .list(
                RAW,
                &scopes(),
                &query(1, None, None, None, None),
                deadline()
            )
            .await
            .unwrap_err(),
        ListError::Authorization(AuthError::Grants(ResourceGrantReadError::ReadLimitExceeded))
    );
    for id in [None, Some("A-visible")] {
        assert_eq!(
            store
                .local_instance_inventory_lister("explicit-audience", n(4096), n(16384), n(8))
                .unwrap()
                .list(RAW, &scopes(), &query(1, None, id, None, None), deadline())
                .await
                .unwrap_err(),
            ListError::Inventory(InstanceReadError::ReadLimitExceeded)
        );
    }
    assert_eq!(
        store
            .local_instance_inventory_lister("", n(4096), n(16384), n(16384))
            .unwrap()
            .list(
                RAW,
                &scopes(),
                &query(1, None, None, None, None),
                deadline()
            )
            .await
            .unwrap_err(),
        ListError::Authorization(AuthError::Authentication(
            LocalBearerVerificationError::Unauthenticated
        ))
    );
    for caps in [
        (usize::MAX, 16384, 16384),
        (4096, usize::MAX, 16384),
        (4096, 16384, usize::MAX),
    ] {
        assert!(
            store
                .local_instance_inventory_lister(
                    "explicit-audience",
                    n(caps.0),
                    n(caps.1),
                    n(caps.2)
                )
                .is_err()
        );
    }
    c.execute("REVOKE SELECT ON public.resource_grants FROM list_owner")
        .await
        .unwrap();
    assert_eq!(
        list.list(
            RAW,
            &scopes(),
            &query(1, None, None, None, None),
            deadline()
        )
        .await
        .unwrap_err(),
        ListError::Authorization(AuthError::Control(ControlError::Storage))
    );
    c.execute("GRANT SELECT ON public.resource_grants TO list_owner; REVOKE SELECT ON public.broker_instance_project_versions FROM list_owner").await.unwrap();
    assert_eq!(
        list.list(
            RAW,
            &scopes(),
            &query(1, None, None, None, None),
            deadline()
        )
        .await
        .unwrap_err(),
        ListError::Inventory(InstanceReadError::Control(ControlError::Storage))
    );
    c.execute("GRANT SELECT ON public.broker_instance_project_versions TO list_owner")
        .await
        .unwrap();

    // Admission is causal: observe inventory SQL waiting while bearer is still valid.
    let expiry = now() + 2_000_000;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-list'",
    )
    .bind(expiry)
    .execute(&mut c)
    .await
    .unwrap();
    c.execute("BEGIN; LOCK TABLE public.broker_instance_project_versions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let running = store.clone();
    let job = tokio::spawn(async move {
        running
            .local_instance_inventory_lister("explicit-audience", n(4096), n(16384), n(16384))
            .unwrap()
            .list(
                RAW,
                &scopes(),
                &query(1, None, None, None, None),
                deadline(),
            )
            .await
    });
    observe_inventory_lock(&mut c).await;
    assert!(!job.is_finished());
    assert!(now() < expiry, "valid Auth reached actual inventory wait");
    while now() <= expiry {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    c.execute("COMMIT").await.unwrap();
    assert_eq!(
        job.await.unwrap().unwrap_err(),
        ListError::Authorization(AuthError::Authentication(
            LocalBearerVerificationError::Unauthenticated
        ))
    );
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-list'",
    )
    .bind(now() + 120_000_000)
    .execute(&mut c)
    .await
    .unwrap();

    c.execute("BEGIN; LOCK TABLE public.broker_instance_project_versions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let start = Instant::now();
    assert_eq!(
        list.list(
            RAW,
            &scopes(),
            &query(1, None, None, None, None),
            start + Duration::from_millis(300)
        )
        .await
        .unwrap_err(),
        ListError::Inventory(InstanceReadError::Control(ControlError::Deadline))
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    c.execute("ROLLBACK").await.unwrap();
    assert!(
        !list
            .list(
                RAW,
                &scopes(),
                &query(1, None, None, None, None),
                deadline()
            )
            .await
            .unwrap()
            .items()
            .is_empty()
    );
    c.execute("BEGIN; LOCK TABLE public.broker_instance_project_versions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let running = store.clone();
    let job = tokio::spawn(async move {
        running
            .local_instance_inventory_lister("explicit-audience", n(4096), n(16384), n(16384))
            .unwrap()
            .list(
                RAW,
                &scopes(),
                &query(1, None, None, None, None),
                deadline(),
            )
            .await
    });
    observe_inventory_lock(&mut c).await;
    assert!(!job.is_finished());
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    c.execute("ROLLBACK").await.unwrap();
    assert_eq!(
        ids(&list
            .list(
                RAW,
                &scopes(),
                &query(100, None, None, None, None),
                deadline()
            )
            .await
            .unwrap()),
        ["A-visible", "C-visible", "G-visible"]
    );
    assert_eq!(snapshot(&mut c).await, before);
    assert_eq!(
        list.list(
            RAW,
            &scopes(),
            &query(1, None, None, None, None),
            Instant::now()
        )
        .await
        .unwrap_err(),
        ListError::Authorization(AuthError::Control(ControlError::Deadline))
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        list.list(
            RAW,
            &scopes(),
            &query(1, None, None, None, None),
            deadline()
        )
        .await
        .unwrap_err(),
        ListError::Authorization(AuthError::Control(ControlError::Closed))
    );
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    assert_eq!(
        ids(&reopened
            .local_instance_inventory_lister("explicit-audience", n(4096), n(16384), n(16384))
            .unwrap()
            .list(
                RAW,
                &scopes(),
                &query(100, None, None, None, None),
                deadline()
            )
            .await
            .unwrap()),
        ["A-visible", "C-visible", "G-visible"]
    );
    reopened.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
