// Shared TLS fixture also serves other control suites.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use broker_control::{
    ConnectionLimits, ControlError, LocalIdentityKind, OidcAccessGrantReadError as Error,
    OidcAccessGrantSnapshot, OidcClientApplicationType, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint,
};
use broker_security::{CredentialDigest, TokenKind};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant},
};
use support::{Fixture, deadline, n};
use zeroize::Zeroizing;
const JTI: &str = "native-oidc-access";
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "oidc_data_owner".into(),
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
fn digest() -> CredentialDigest {
    support::digester()
        .token(TokenKind::OidcStoredAccess, JTI.as_bytes())
        .unwrap()
}
fn principal() -> serde_json::Value {
    serde_json::json!({"issuer":"local","subject":"subject","username":"old-name","auth_method":"local-token","local_user_revision":1,
        "name":"Old","email":null,"organization":"","teams":[" old ","old"],"scopes":["stored-principal-scope"],
        "roles":["r","r"],"roles_from_claim":false,"role_claim_selector":""})
}
async fn read(store: &PostgresControlStore) -> Result<OidcAccessGrantSnapshot, Error> {
    Ok(store
        .oidc_access_grants(n(4096))
        .unwrap()
        .read(&digest(), deadline())
        .await?
        .expect("present DATA"))
}
async fn principal_json(c: &mut PgConnection, raw: &str) {
    sqlx_core::query::query("UPDATE public.local_tokens SET principal_json=$1 WHERE token_id=$2")
        .bind(raw)
        .bind(JTI)
        .execute(c)
        .await
        .unwrap();
}
async fn oracle(c: &mut PgConnection) -> String {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('tokens',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.local_tokens ORDER BY token_id) t),'users',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.local_users ORDER BY username) t),'clients',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.oauth_dynamic_clients ORDER BY client_id) t))::text").fetch_one(c).await.unwrap()
}
async fn observe_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='oidc_data_owner' AND wait_event_type='Lock' AND query LIKE '%t.oidc_subject%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(Instant::now() < end, "reader reaches SQL table lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS ordinary OIDC stored grant DATA contract"]
async fn postgres_oidc_access_grant_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE oidc_data_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION oidc_data_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO oidc_data_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='oidc_data_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    assert_eq!(
        store.oidc_access_grants(n(usize::MAX)).unwrap_err(),
        Error::InvalidLimits
    );
    let initial = oracle(&mut c).await;
    assert!(
        store
            .oidc_access_grants(n(4096))
            .unwrap()
            .read(&digest(), deadline())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(oracle(&mut c).await, initial);
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('current-user','subject','human','not-read','Current','mail','organization','[\" b \",\"\",\" b \"]',1,0,1,0,0)").await.unwrap();
    c.execute("INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('web-client','Client','[\"https://client.example/callback\",\"\",\"https://client.example/callback\"]','[\" openid \",\"openid\",\"openid\"]','web',0)").await.unwrap();
    sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,revoked_at,consumed_at,last_used_at,created_at) VALUES($1,$2,'oidc_access','subject','stable-broker-sub',$3,'web-client','api-audience','https://broker.example/v1','[\" exact \",\"exact\",\"exact\"]',1,'family',0,0,NULL,NULL,7,0)")
        .bind(digest().to_sql_hex()).bind(JTI).bind(principal().to_string()).execute(&mut c).await.unwrap();
    let before = oracle(&mut c).await;
    let g = read(&store).await.unwrap();
    assert_eq!(g.token_id(), JTI);
    assert_eq!(g.subject(), "subject");
    assert_eq!(g.oidc_subject(), "stable-broker-sub");
    assert_eq!(g.client_id(), "web-client");
    assert_eq!(g.audience(), "api-audience");
    assert_eq!(g.resource(), "https://broker.example/v1");
    assert_eq!(g.scopes(), [" exact ", "exact", "exact"]);
    assert_eq!(g.local_user_revision(), 1);
    assert_eq!(g.family_id(), "family");
    assert_eq!(g.auth_time().as_i64(), 0);
    assert_eq!(g.expires_at().as_i64(), 0);
    assert_eq!(g.revoked_at(), None);
    assert_eq!(g.created_at().as_i64(), 0);
    let p = g.stored_principal();
    assert_eq!(p.issuer(), "local");
    assert_eq!(p.username(), "old-name");
    assert_eq!(p.auth_method(), "local-token");
    assert_eq!(p.local_user_revision(), 1);
    assert_eq!(p.name(), Some("Old"));
    assert_eq!(p.email(), None);
    assert_eq!(p.organization(), Some(""));
    assert_eq!(p.teams().unwrap(), [" old ", "old"]);
    assert_eq!(p.scopes().unwrap(), ["stored-principal-scope"]);
    assert_eq!(p.roles().unwrap(), ["r", "r"]);
    assert_eq!(p.roles_from_claim(), Some(false));
    assert_eq!(p.role_claim_selector(), Some(""));
    let u = g.current_local_user().unwrap();
    assert_eq!(u.username(), "current-user");
    assert_eq!(u.subject(), "subject");
    assert_eq!(u.kind(), LocalIdentityKind::Human);
    assert!(u.enabled());
    assert_eq!(u.name(), "Current");
    assert_eq!(u.email(), "mail");
    assert_eq!(u.organization(), "organization");
    assert_eq!(u.teams(), [" b ", "", " b "]);
    assert_eq!(u.revision(), 1);
    let d = g.dynamic_registration().unwrap();
    assert_eq!(d.client_id(), "web-client");
    assert_eq!(d.client_name(), "Client");
    assert_eq!(d.application_type(), OidcClientApplicationType::Web);
    assert_eq!(d.created_at().as_i64(), 0);
    assert_eq!(
        d.redirect_uris(),
        [
            "https://client.example/callback",
            "",
            "https://client.example/callback"
        ]
    );
    assert_eq!(d.scopes(), [" openid ", "openid", "openid"]);
    for debug in [
        format!("{g:?}"),
        format!("{u:?}"),
        format!("{d:?}"),
        format!("{:?}", store.oidc_access_grants(n(4096)).unwrap()),
    ] {
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("subject"));
        assert!(!debug.contains("client.example"));
    }
    assert_eq!(oracle(&mut c).await, before);
    for kind in ["access", "service", "refresh", "unexpected"] {
        sqlx_core::query::query("UPDATE public.local_tokens SET token_kind=$1")
            .bind(kind)
            .execute(&mut c)
            .await
            .unwrap();
        assert!(
            store
                .oidc_access_grants(n(4096))
                .unwrap()
                .read(&digest(), deadline())
                .await
                .unwrap()
                .is_none()
        );
    }
    c.execute("UPDATE public.local_tokens SET token_kind='oidc_access'")
        .await
        .unwrap();
    for other in [
        support::digester()
            .token(TokenKind::LocalAccess, JTI.as_bytes())
            .unwrap(),
        support::digester()
            .token(TokenKind::OidcStoredAccess, b"other-jti")
            .unwrap(),
    ] {
        assert!(
            store
                .oidc_access_grants(n(4096))
                .unwrap()
                .read(&other, deadline())
                .await
                .unwrap()
                .is_none()
        );
    }
    // Parsed SQL digest is also DATA input, so the reader cannot establish its origin.
    let metadata = CredentialDigest::parse_sql_hex(&digest().to_sql_hex()).unwrap();
    assert!(
        store
            .oidc_access_grants(n(4096))
            .unwrap()
            .read(&metadata, deadline())
            .await
            .unwrap()
            .is_some()
    );
    c.execute("UPDATE public.local_tokens SET revoked_at=0; UPDATE public.local_users SET enabled=0,revision=2,name='Changed'").await.unwrap();
    let g = read(&store).await.unwrap();
    assert_eq!(g.revoked_at().unwrap().as_i64(), 0);
    let u = g.current_local_user().unwrap();
    assert!(!u.enabled());
    assert_eq!(u.revision(), 2);
    assert_eq!(u.name(), "Changed");
    c.execute("UPDATE public.local_users SET subject='changed-subject'")
        .await
        .unwrap();
    assert!(read(&store).await.unwrap().current_local_user().is_none());
    c.execute("UPDATE public.local_users SET subject='subject',enabled=1,revision=1,name='Current'; UPDATE public.local_tokens SET revoked_at=NULL").await.unwrap();
    c.execute("UPDATE public.oauth_dynamic_clients SET client_id='other-client'")
        .await
        .unwrap();
    assert!(read(&store).await.unwrap().dynamic_registration().is_none());
    c.execute(
        "UPDATE public.oauth_dynamic_clients SET client_id='web-client',application_type='native'",
    )
    .await
    .unwrap();
    assert_eq!(
        read(&store)
            .await
            .unwrap()
            .dynamic_registration()
            .unwrap()
            .application_type(),
        OidcClientApplicationType::Native
    );
    // Local service/current kind remains DATA even when the stored method differs.
    c.execute("UPDATE public.local_users SET identity_kind='service'")
        .await
        .unwrap();
    assert_eq!(
        read(&store)
            .await
            .unwrap()
            .current_local_user()
            .unwrap()
            .kind(),
        LocalIdentityKind::Service
    );
    let mut service = principal();
    service["auth_method"] = serde_json::json!("service-credential");
    principal_json(&mut c, &service.to_string()).await;
    assert_eq!(
        read(&store).await.unwrap().stored_principal().auth_method(),
        "service-credential"
    );
    let mut federated = principal();
    federated["issuer"] = serde_json::json!("https://upstream.example");
    federated["auth_method"] = serde_json::json!("oidc");
    federated["local_user_revision"] = serde_json::json!(0);
    principal_json(&mut c, &federated.to_string()).await;
    c.execute("UPDATE public.local_tokens SET local_user_revision=0; UPDATE public.local_users SET teams_json='invalid'").await.unwrap();
    let g = read(&store).await.unwrap();
    assert!(g.current_local_user().is_none());
    assert_eq!(g.stored_principal().issuer(), "https://upstream.example");
    c.execute("UPDATE public.local_users SET teams_json='[]',identity_kind='human'; UPDATE public.local_tokens SET local_user_revision=1").await.unwrap();
    principal_json(&mut c, &principal().to_string()).await;
    let base = principal().to_string();
    for raw in [
        "[]".to_string(),
        "null".to_string(),
        format!("{base} null"),
        base.replace(
            "\"issuer\":\"local\"",
            "\"issuer\":\"local\",\"issuer\":\"local\"",
        ),
        base.replace("\"subject\":\"subject\"", "\"subject\":\"another\""),
        base.replace("\"local_user_revision\":1", "\"local_user_revision\":2"),
        base.replace("\"roles\":[\"r\",\"r\"]", "\"roles\":1"),
        base.replace("\"name\":\"Old\"", "\"unknown\":\"Old\""),
        base.replace("\"local_user_revision\":1", "\"local_user_revision\":null"),
    ] {
        principal_json(&mut c, &raw).await;
        assert_eq!(read(&store).await.unwrap_err(), Error::MalformedStored);
    }
    principal_json(&mut c, &base).await;
    for (set, restore) in [
        (
            "UPDATE public.local_tokens SET audience=''",
            "UPDATE public.local_tokens SET audience='api-audience'",
        ),
        (
            "UPDATE public.local_tokens SET oidc_subject=' padded'",
            "UPDATE public.local_tokens SET oidc_subject='stable-broker-sub'",
        ),
        (
            "UPDATE public.local_tokens SET family_id=' padded'",
            "UPDATE public.local_tokens SET family_id='family'",
        ),
        (
            "UPDATE public.local_tokens SET auth_time=-1",
            "UPDATE public.local_tokens SET auth_time=0",
        ),
        (
            "UPDATE public.local_tokens SET expires_at=-1",
            "UPDATE public.local_tokens SET expires_at=0",
        ),
        (
            "UPDATE public.local_tokens SET created_at=-1",
            "UPDATE public.local_tokens SET created_at=0",
        ),
        (
            "UPDATE public.local_tokens SET revoked_at=-1",
            "UPDATE public.local_tokens SET revoked_at=NULL",
        ),
        (
            "UPDATE public.local_users SET enabled=2",
            "UPDATE public.local_users SET enabled=1",
        ),
        (
            "UPDATE public.local_users SET revision=0",
            "UPDATE public.local_users SET revision=1",
        ),
        (
            "UPDATE public.local_users SET identity_kind='unknown'",
            "UPDATE public.local_users SET identity_kind='human'",
        ),
        (
            "UPDATE public.local_users SET username='bad/name'",
            "UPDATE public.local_users SET username='current-user'",
        ),
        (
            "UPDATE public.oauth_dynamic_clients SET application_type='unknown'",
            "UPDATE public.oauth_dynamic_clients SET application_type='web'",
        ),
        (
            "UPDATE public.oauth_dynamic_clients SET created_at=-1",
            "UPDATE public.oauth_dynamic_clients SET created_at=0",
        ),
    ] {
        c.execute(set).await.unwrap();
        assert_eq!(read(&store).await.unwrap_err(), Error::MalformedStored);
        c.execute(restore).await.unwrap();
    }
    // Dynamic fixture identifiers below are fixed literals in these test loops; values remain bound.
    // Each native text array must be JSON strings, even though values need not be recognized URLs/scopes.
    for (table, column, restore) in [
        (
            "local_tokens",
            "scopes_json",
            "[\" exact \",\"exact\",\"exact\"]",
        ),
        ("local_users", "teams_json", "[]"),
        ("oauth_dynamic_clients", "redirect_uris_json", "[]"),
        ("oauth_dynamic_clients", "scopes_json", "[]"),
    ] {
        for raw in ["null", "[1]", "{}", "[\"x\"] []", "\"a,b\""] {
            sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
                "UPDATE public.{table} SET {column}=$1"
            )))
            .bind(raw)
            .execute(&mut c)
            .await
            .unwrap();
            assert_eq!(read(&store).await.unwrap_err(), Error::MalformedStored);
        }
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "UPDATE public.{table} SET {column}=$1"
        )))
        .bind(restore)
        .execute(&mut c)
        .await
        .unwrap();
    }
    // Per-field caps check physical UTF8 bytes; equality succeeds and one byte less fails.
    for (table, column, restore) in [
        ("local_tokens", "principal_json", base.clone()),
        (
            "local_tokens",
            "scopes_json",
            "[\" exact \",\"exact\",\"exact\"]".into(),
        ),
        ("local_users", "teams_json", "[]".into()),
        ("oauth_dynamic_clients", "redirect_uris_json", "[]".into()),
        ("oauth_dynamic_clients", "scopes_json", "[]".into()),
    ] {
        let raw = if column == "principal_json" {
            let mut p = principal();
            p["name"] = serde_json::json!("é".repeat(400));
            p.to_string()
        } else {
            serde_json::json!(["é".repeat(500)]).to_string()
        };
        assert!(raw.len() > base.len());
        assert!(raw.len() > raw.chars().count());
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "UPDATE public.{table} SET {column}=$1"
        )))
        .bind(&raw)
        .execute(&mut c)
        .await
        .unwrap();
        assert!(
            store
                .oidc_access_grants(n(raw.len()))
                .unwrap()
                .read(&digest(), deadline())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store
                .oidc_access_grants(n(raw.len() - 1))
                .unwrap()
                .read(&digest(), deadline())
                .await
                .unwrap_err(),
            Error::ReadLimitExceeded
        );
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "UPDATE public.{table} SET {column}=$1"
        )))
        .bind(restore)
        .execute(&mut c)
        .await
        .unwrap();
    }
    // Ordinary SQL privileges are exercised, not mocked or interpreted as an empty result.
    for table in ["local_tokens", "local_users", "oauth_dynamic_clients"] {
        sqlx_core::raw_sql::raw_sql(sqlx_core::sql_str::AssertSqlSafe(format!(
            "REVOKE SELECT ON public.{table} FROM oidc_data_owner"
        )))
        .execute(&mut c)
        .await
        .unwrap();
        assert_eq!(
            read(&store).await.unwrap_err(),
            Error::Control(ControlError::Storage)
        );
        sqlx_core::raw_sql::raw_sql(sqlx_core::sql_str::AssertSqlSafe(format!(
            "GRANT SELECT ON public.{table} TO oidc_data_owner"
        )))
        .execute(&mut c)
        .await
        .unwrap();
        assert!(read(&store).await.is_ok());
    }
    let before = oracle(&mut c).await;
    let mut locker = f.connection().await;
    let mut tx = locker.begin().await.unwrap();
    tx.execute("LOCK TABLE public.oauth_dynamic_clients IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let s = Arc::clone(&store);
    let end = Instant::now() + Duration::from_millis(1500);
    let op = tokio::spawn(async move {
        s.oidc_access_grants(n(4096))
            .unwrap()
            .read(&digest(), end)
            .await
    });
    observe_lock(&mut c).await;
    assert_eq!(
        op.await.unwrap().unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    tx.rollback().await.unwrap();
    assert!(read(&store).await.is_ok());
    let mut tx = locker.begin().await.unwrap();
    tx.execute("LOCK TABLE public.oauth_dynamic_clients IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let s = Arc::clone(&store);
    let op = tokio::spawn(async move {
        s.oidc_access_grants(n(4096))
            .unwrap()
            .read(&digest(), deadline())
            .await
    });
    observe_lock(&mut c).await;
    op.abort();
    assert!(op.await.unwrap_err().is_cancelled());
    tx.rollback().await.unwrap();
    assert!(read(&store).await.is_ok());
    assert_eq!(
        store
            .oidc_access_grants(n(4096))
            .unwrap()
            .read(&digest(), Instant::now())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    assert_eq!(oracle(&mut c).await, before);
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        read(&store).await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
}
