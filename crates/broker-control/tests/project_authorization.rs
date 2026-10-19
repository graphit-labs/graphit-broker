// Shared TLS fixture serves other control suites.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use broker_control::{
    AuthorizedLocalProjectAccess, ConnectionLimits, ControlError, LocalBearerVerificationError,
    PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
    ProjectAuthorizationError as Error, ProjectResourceAction as Action,
    ProjectResourceModule as Module, ResourceGrantReadError,
};
use broker_security::TokenKind;
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const RAW: &str = "gb_at_project-authorizer";
const SERVICE: &str = "gb_sc_project-authorizer";
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
    vec!["project-sdk".into()]
}
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "project_owner".into(),
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
async fn clear(c: &mut PgConnection) {
    c.execute("DELETE FROM public.resource_grants; UPDATE public.resource_acl_state SET revision=revision+1,updated_at=0 WHERE id=1").await.unwrap();
}
async fn grant(
    c: &mut PgConnection,
    id: &str,
    access: &str,
    principal: &str,
    caps: &[&str],
    projects: &[&str],
) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture',$2,$3,'',0,0)").bind(id).bind(access).bind(principal).execute(&mut *c).await.unwrap();
    for cap in caps {
        sqlx_core::query::query(
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
        )
        .bind(id)
        .bind(*cap)
        .execute(&mut *c)
        .await
        .unwrap();
    }
    for project in projects {
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(*project)
            .execute(&mut *c)
            .await
            .unwrap();
    }
}
async fn policy_oracle(c: &mut PgConnection) -> String {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('state',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.resource_acl_state ORDER BY id) t),'rules',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.resource_grants ORDER BY id COLLATE \"C\") t),'caps',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.grant_capabilities ORDER BY grant_id COLLATE \"C\",value COLLATE \"C\") t),'projects',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.grant_projects ORDER BY grant_id COLLATE \"C\",value COLLATE \"C\") t),'operations',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.grant_s3_operations ORDER BY grant_id COLLATE \"C\",value COLLATE \"C\") t),'prefixes',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.grant_s3_prefixes ORDER BY grant_id COLLATE \"C\",value COLLATE \"C\") t))::text").fetch_one(&mut *c).await.unwrap()
}
async fn authorize(
    store: &PostgresControlStore,
    raw: &str,
    module: Module,
    action: Action,
    project: &str,
    end: Instant,
) -> Result<AuthorizedLocalProjectAccess, Error> {
    store
        .local_project_authorizer("explicit-audience", n(4096), n(65536))
        .unwrap()
        .authorize(raw, &scopes(), module, action, project, end)
        .await
}
async fn task_read(store: &PostgresControlStore) -> Result<AuthorizedLocalProjectAccess, Error> {
    authorize(store, RAW, Module::Task, Action::Read, A, deadline()).await
}
async fn observe_acl_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='project_owner' AND wait_event_type='Lock' AND query LIKE '%resource_acl_state%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(
            Instant::now() < end,
            "authorizer reaches a real ACL SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS opaque authentication and PROJECT logical capabilities"]
async fn postgres_local_project_authorization_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE project_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION project_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO project_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let privileged: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='project_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!privileged);
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Alice','','org','[\"dev\"]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','org','[]',1,0,1,0,0)").await.unwrap();
    let principal=serde_json::json!({"issuer":"local","subject":"alice-subject","username":"stale","auth_method":"old","local_user_revision":1}).to_string();
    for (raw, kind, id, token_kind, subject) in [
        (
            RAW,
            TokenKind::LocalAccess,
            "project-access",
            "access",
            "alice-subject",
        ),
        (
            SERVICE,
            TokenKind::ServiceCredential,
            "project-service",
            "service",
            "bot-subject",
        ),
    ] {
        let digest = support::digester().token(kind, raw.as_bytes()).unwrap();
        let data=serde_json::json!({"issuer":"local","subject":subject,"username":"stale","auth_method":"old","local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'envelope',$5,'client','explicit-audience','','[\"project-sdk\"]',1,'',0,$6,0)").bind(digest.to_sql_hex()).bind(id).bind(token_kind).bind(subject).bind(data).bind(now()+3_600_000_000).execute(&mut c).await.unwrap();
    }
    // Real operators explicitly grant each logical pair; write and read remain independent.

    // Hub is a PROJECT capability of its own; only its read operation is admitted.
    assert_eq!(Module::Hub.capability(Action::Read), Some("hub"));
    assert_eq!(Module::Hub.capability(Action::Write), None);
    clear(&mut c).await;
    grant(&mut c, "hub", "user", "alice", &["hub"], &[A]).await;
    let hub = authorize(&store, RAW, Module::Hub, Action::Read, A, deadline())
        .await
        .unwrap();
    assert_eq!(hub.capability(), "hub");
    assert_eq!(hub.module(), Module::Hub);
    let seen = hub.policy_revision();
    assert_eq!(
        authorize(&store, RAW, Module::Hub, Action::Write, A, deadline())
            .await
            .unwrap_err(),
        Error::InvalidOperation
    );
    assert_eq!(
        authorize(&store, "invalid", Module::Hub, Action::Write, A, deadline())
            .await
            .unwrap_err(),
        Error::InvalidOperation
    );
    assert_eq!(
        authorize(&store, RAW, Module::Hub, Action::Read, B, deadline())
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    c.execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
        .await
        .unwrap();
    assert!(
        authorize(&store, RAW, Module::Hub, Action::Read, A, deadline())
            .await
            .unwrap()
            .policy_revision()
            > seen
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='hub'")
        .await
        .unwrap();
    assert_eq!(
        authorize(&store, RAW, Module::Hub, Action::Read, A, deadline())
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    for substitute in ["knowledge:read", "s3", "s3:read", "hub:read", "hub:write"] {
        clear(&mut c).await;
        grant(&mut c, "substitute", "user", "alice", &[substitute], &[A]).await;
        assert_eq!(
            authorize(&store, RAW, Module::Hub, Action::Read, A, deadline())
                .await
                .unwrap_err(),
            Error::Forbidden
        );
    }
    clear(&mut c).await;
    grant(&mut c, "hub-b", "user", "alice", &["hub"], &[B]).await;
    grant(
        &mut c,
        "project-a",
        "user",
        "alice",
        &["knowledge:read"],
        &[A],
    )
    .await;
    grant(&mut c, "other-principal", "user", "other", &["hub"], &[A]).await;
    assert_eq!(
        authorize(&store, RAW, Module::Hub, Action::Read, A, deadline())
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    for projects in [&[][..], &["*"][..]] {
        clear(&mut c).await;
        grant(&mut c, "hub-any", "user", "alice", &["hub"], projects).await;
        authorize(&store, RAW, Module::Hub, Action::Read, A, deadline())
            .await
            .unwrap();
        authorize(&store, RAW, Module::Hub, Action::Read, B, deadline())
            .await
            .unwrap();
    }
    for module in [Module::Task, Module::Memory, Module::Knowledge, Module::Ast] {
        for action in [Action::Read, Action::Write] {
            clear(&mut c).await;
            let cap = module.capability(action).unwrap();
            assert_eq!(cap, format!("{}:{}", module.as_str(), action.as_str()));
            grant(&mut c, "a", "user", "alice", &[cap], &[A]).await;
            let before = policy_oracle(&mut c).await;
            let revision: i64 = sqlx_core::query_scalar::query_scalar(
                "SELECT revision FROM public.resource_acl_state WHERE id=1",
            )
            .fetch_one(&mut c)
            .await
            .unwrap();
            let allowed = authorize(&store, RAW, module, action, A, deadline())
                .await
                .unwrap();
            assert_eq!(
                (
                    allowed.module(),
                    allowed.action(),
                    allowed.project_id(),
                    allowed.capability(),
                    allowed.policy_revision()
                ),
                (module, action, A, cap, revision)
            );
            assert_eq!(
                (
                    allowed.principal().current_local_user().issuer(),
                    allowed.principal().current_local_user().subject(),
                    allowed.principal().current_local_user().username()
                ),
                ("local", "alice-subject", "alice")
            );
            assert_eq!(
                format!("{allowed:?}"),
                "AuthorizedLocalProjectAccess([REDACTED])"
            );
            let opposite = match action {
                Action::Read => Action::Write,
                Action::Write => Action::Read,
            };
            assert_eq!(
                authorize(&store, RAW, module, opposite, A, deadline())
                    .await
                    .unwrap_err(),
                Error::Forbidden
            );
            let other = if module == Module::Task {
                Module::Memory
            } else {
                Module::Task
            };
            assert_eq!(
                authorize(&store, RAW, other, action, A, deadline())
                    .await
                    .unwrap_err(),
                Error::Forbidden
            );
            assert_eq!(
                authorize(&store, RAW, module, action, B, deadline())
                    .await
                    .unwrap_err(),
                Error::Forbidden
            );
            assert_eq!(
                authorize(&store, SERVICE, module, action, A, deadline())
                    .await
                    .unwrap_err(),
                Error::Forbidden
            );
            assert_eq!(policy_oracle(&mut c).await, before);
        }
    }
    clear(&mut c).await;
    grant(&mut c, "a", "user", "alice", &["task:read"], &[B]).await;
    grant(&mut c, "b", "user", "bob", &["task:read"], &[A]).await;
    grant(&mut c, "c", "user", "alice", &["memory:read"], &[A]).await;
    assert_eq!(task_read(&store).await.unwrap_err(), Error::Forbidden);
    // No old resource grant, storage field or administrator role implies a logical PROJECT cap.
    clear(&mut c).await;
    grant(
        &mut c,
        "a",
        "user",
        "alice",
        &["hub", "presence:*", "s3:read"],
        &[A],
    )
    .await;
    c.execute("INSERT INTO public.grant_s3_operations(grant_id,value) VALUES('a','read'); INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES('a','private/{project}'); INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','admin',0)").await.unwrap();
    let before = policy_oracle(&mut c).await;
    assert_eq!(task_read(&store).await.unwrap_err(), Error::Forbidden);
    assert_eq!(policy_oracle(&mut c).await, before);
    // These fields remain storage-only even on a distinct explicit logical grant.
    c.execute("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a','task:read'); UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    let allowed = task_read(&store).await.unwrap();
    let seen = allowed.policy_revision();
    c.execute("DELETE FROM public.grant_capabilities WHERE grant_id='a' AND value='task:read'; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    assert_eq!(task_read(&store).await.unwrap_err(), Error::Forbidden);
    c.execute("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a','task:read')")
        .await
        .unwrap();
    assert!(task_read(&store).await.unwrap().policy_revision() > seen);
    for projects in [&[][..], &["*"][..]] {
        clear(&mut c).await;
        grant(
            &mut c,
            "a",
            "authenticated",
            "",
            &["{task,memory}:*"],
            projects,
        )
        .await;
        assert!(
            authorize(
                &store,
                SERVICE,
                Module::Memory,
                Action::Write,
                B,
                deadline()
            )
            .await
            .is_ok()
        );
        assert!(
            authorize(&store, RAW, Module::Task, Action::Read, B, deadline())
                .await
                .is_ok()
        );
        assert_eq!(
            authorize(&store, RAW, Module::Knowledge, Action::Read, B, deadline())
                .await
                .unwrap_err(),
            Error::Forbidden
        );
    }
    for (access, who, allowed) in [
        ("user", "Alice", false),
        ("team", "de?", true),
        ("organization", "org", true),
        ("subject", "local|alice-*", true),
        ("anonymous", "", false),
    ] {
        clear(&mut c).await;
        grant(&mut c, "a", access, who, &["task:read"], &[A]).await;
        assert_eq!(task_read(&store).await.is_ok(), allowed);
    }
    clear(&mut c).await;
    grant(&mut c, "a", "user", "alice", &["task:read"], &[A]).await;
    grant(&mut c, "z", "team", "[", &["memory:read"], &[B]).await;
    assert_eq!(task_read(&store).await.unwrap_err(), Error::InvalidPolicy);
    c.execute("DELETE FROM public.resource_grants WHERE id='z'")
        .await
        .unwrap();
    for project in [
        "",
        "00000000000000000000000000",
        "01d39zy06fgsctvn4t2v9pkhfz",
        "*",
        "global",
    ] {
        assert_eq!(
            authorize(&store, RAW, Module::Task, Action::Read, project, deadline())
                .await
                .unwrap_err(),
            Error::InvalidProject
        );
    }
    // Current proof is reacquired from SQL for every call.
    let unauth = Error::Authentication(LocalBearerVerificationError::Unauthenticated);
    for raw in ["bad", "gb_rt_refresh", "gb_at_absent"] {
        assert_eq!(
            authorize(&store, raw, Module::Task, Action::Read, A, deadline())
                .await
                .unwrap_err(),
            unauth
        );
    }
    assert_eq!(
        store
            .local_project_authorizer("wrong", n(4096), n(65536))
            .unwrap()
            .authorize(RAW, &scopes(), Module::Task, Action::Read, A, deadline())
            .await
            .unwrap_err(),
        unauth
    );
    assert_eq!(
        store
            .local_project_authorizer("explicit-audience", n(4096), n(65536))
            .unwrap()
            .authorize(
                RAW,
                &["missing".into()],
                Module::Task,
                Action::Read,
                A,
                deadline()
            )
            .await
            .unwrap_err(),
        unauth
    );
    for (set, restore) in [
        (
            "UPDATE public.local_tokens SET revoked_at=1 WHERE token_id='project-access'",
            "UPDATE public.local_tokens SET revoked_at=NULL WHERE token_id='project-access'",
        ),
        (
            "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
            "UPDATE public.local_users SET enabled=1 WHERE username='alice'",
        ),
        (
            "UPDATE public.local_users SET revision=2 WHERE username='alice'",
            "UPDATE public.local_users SET revision=1 WHERE username='alice'",
        ),
        (
            "UPDATE public.local_tokens SET expires_at=0 WHERE token_id='project-access'",
            "UPDATE public.local_tokens SET expires_at=9223372036854775807 WHERE token_id='project-access'",
        ),
        (
            "UPDATE public.local_tokens SET scopes_json='[]' WHERE token_id='project-access'",
            "UPDATE public.local_tokens SET scopes_json='[\"project-sdk\"]' WHERE token_id='project-access'",
        ),
    ] {
        c.execute(set).await.unwrap();
        assert_eq!(task_read(&store).await.unwrap_err(), unauth);
        c.execute(restore).await.unwrap();
    }
    c.execute("UPDATE public.local_tokens SET principal_json='{\"unknown\":true}' WHERE token_id='project-access'").await.unwrap();
    assert!(matches!(
        task_read(&store).await.unwrap_err(),
        Error::Authentication(_)
    ));
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET principal_json=$1 WHERE token_id='project-access'",
    )
    .bind(&principal)
    .execute(&mut c)
    .await
    .unwrap();
    assert!(matches!(
        store
            .local_project_authorizer("explicit-audience", n(1), n(65536))
            .unwrap()
            .authorize(RAW, &scopes(), Module::Task, Action::Read, A, deadline())
            .await
            .unwrap_err(),
        Error::Authentication(_)
    ));
    assert_eq!(
        store
            .local_project_authorizer("explicit-audience", n(4096), n(1))
            .unwrap()
            .authorize(RAW, &scopes(), Module::Task, Action::Read, A, deadline())
            .await
            .unwrap_err(),
        Error::Grants(ResourceGrantReadError::ReadLimitExceeded)
    );
    let revision: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT revision FROM public.resource_acl_state WHERE id=1",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    c.execute("DELETE FROM public.resource_acl_state WHERE id=1")
        .await
        .unwrap();
    assert_eq!(
        task_read(&store).await.unwrap_err(),
        Error::Grants(ResourceGrantReadError::MalformedStored)
    );
    sqlx_core::query::query(
        "INSERT INTO public.resource_acl_state(id,revision,updated_at) VALUES(1,$1,0)",
    )
    .bind(revision)
    .execute(&mut c)
    .await
    .unwrap();
    c.execute("REVOKE SELECT ON public.grant_capabilities FROM project_owner")
        .await
        .unwrap();
    assert_eq!(
        task_read(&store).await.unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    c.execute("GRANT SELECT ON public.grant_capabilities TO project_owner")
        .await
        .unwrap();
    assert!(task_read(&store).await.is_ok());
    assert_eq!(task_read(&store).await.unwrap().policy_revision(), revision);
    // A real grants lock is reached after authentication; expiry is checked again at return.
    let expiry = now() + 5_000_000;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='project-access'",
    )
    .bind(expiry)
    .execute(&mut c)
    .await
    .unwrap();
    let mut blocker = f.connection().await;
    blocker
        .execute("BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let worker = store.clone();
    let pending = tokio::spawn(async move { task_read(&worker).await });
    observe_acl_lock(&mut c).await;
    assert!(!pending.is_finished());
    assert!(
        now() < expiry,
        "bearer is alive when the real ACL lock is observed"
    );
    let remaining = expiry.saturating_sub(now());
    if remaining > 0 {
        tokio::time::sleep(Duration::from_micros(remaining as u64)).await;
    }
    blocker.execute("COMMIT").await.unwrap();
    assert_eq!(pending.await.unwrap().unwrap_err(), unauth);
    c.execute("UPDATE public.local_tokens SET expires_at=9223372036854775807 WHERE token_id='project-access'").await.unwrap();
    blocker
        .execute("BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let worker = store.clone();
    let pending = tokio::spawn(async move {
        authorize(
            &worker,
            RAW,
            Module::Task,
            Action::Read,
            A,
            Instant::now() + Duration::from_secs(2),
        )
        .await
    });
    observe_acl_lock(&mut c).await;
    assert_eq!(
        pending.await.unwrap().unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    blocker.execute("COMMIT").await.unwrap();
    assert!(task_read(&store).await.is_ok());
    blocker
        .execute("BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let worker = store.clone();
    let pending = tokio::spawn(async move { task_read(&worker).await });
    observe_acl_lock(&mut c).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    blocker.execute("COMMIT").await.unwrap();
    assert!(task_read(&store).await.is_ok());
    assert_eq!(
        authorize(&store, RAW, Module::Task, Action::Read, A, Instant::now())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    let before = policy_oracle(&mut c).await;
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        task_read(&store).await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    assert!(task_read(&reopened).await.is_ok());
    assert_eq!(policy_oracle(&mut c).await, before);
    assert_eq!(Error::Forbidden.to_string(), "project access denied");
    assert_eq!(format!("{:?}", Error::InvalidPolicy), "InvalidPolicy");
    reopened.shutdown(deadline()).await.unwrap();
    blocker.close().await.unwrap();
    c.close().await.unwrap();
}
