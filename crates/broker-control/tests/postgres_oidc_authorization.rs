use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use broker_control::{
    ConnectionLimits, ControlError, OidcAuthorizationConfiguration,
    OidcAuthorizationError as Error, OidcAuthorizationInput, OidcAuthorizationLimits,
    OidcAuthorizationPolicy, PostgresConfig, PostgresControlStore, PostgresCredentials,
    PostgresEndpoint,
};
use broker_security::{CredentialDigester, TokenKind};
use sqlx_core::{connection::Connection, executor::Executor, row::Row};
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use zeroize::Zeroizing;
const RESOURCE: &str = "https://broker.example/v1";
fn config(f: &Fixture) -> PostgresConfig {
    config_at(f, f.port, support::pool(2))
}
fn config_at(f: &Fixture, port: u16, pool: broker_control::PoolConfig) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "authorization_owner".into(),
            Zeroizing::new("ephemeral-owner".into()),
        ),
        f.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        pool,
        support::limits(),
    )
    .unwrap()
}
fn policy(dynamic: bool, json_bytes: usize) -> OidcAuthorizationPolicy {
    OidcAuthorizationPolicy::new(
        OidcAuthorizationConfiguration {
            cli_client_id: "graphit-cli".into(),
            cli_redirect_path: "/oauth/callback".into(),
            api_audience: "graphit-broker".into(),
            accepted_resources: vec![RESOURCE.into()],
            dynamic_registration: dynamic,
            authorization_ttl: Duration::from_secs(600),
        },
        OidcAuthorizationLimits::new(n(json_bytes), n(8192)).unwrap(),
    )
    .unwrap()
}
fn input<'a>(
    client: &'a str,
    redirect: &'a str,
    resources: &'a [&'a str],
) -> OidcAuthorizationInput<'a> {
    OidcAuthorizationInput {
        client_id: client,
        redirect_uri: redirect,
        response_type: "code",
        scope: "openid profile email phone address offline_access extra profile",
        state: " state ",
        nonce: " nonce ",
        code_challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        code_challenge_method: "S256",
        response_mode: None,
        resources,
        prompts: &[],
    }
}
fn micros() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
async fn snapshot(c: &mut PgConnection) -> String {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('requests',(SELECT jsonb_agg(to_jsonb(r)) FROM (SELECT * FROM public.oidc_auth_requests ORDER BY request_hash) r),'clients',(SELECT jsonb_agg(to_jsonb(r)) FROM (SELECT * FROM public.oauth_dynamic_clients ORDER BY client_id) r))::text").fetch_one(c).await.unwrap()
}
async fn client(c: &mut PgConnection, id: &str, kind: &str, redirects: &[&str]) {
    sqlx_core::query::query("INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES($1,'Client',$2,'[\"openid\"]',$3,$4) ON CONFLICT(client_id) DO UPDATE SET client_name=excluded.client_name,redirect_uris_json=excluded.redirect_uris_json,scopes_json=excluded.scopes_json,application_type=excluded.application_type,created_at=excluded.created_at")
        .bind(id).bind(serde_json::to_string(redirects).unwrap()).bind(kind).bind(micros()).execute(c).await.unwrap();
}
async fn request_json(c: &mut PgConnection, hash: &str, json: &str) {
    sqlx_core::query::query(
        "UPDATE public.oidc_auth_requests SET request_json=$1 WHERE request_hash=$2",
    )
    .bind(json)
    .bind(hash)
    .execute(c)
    .await
    .unwrap();
}
async fn observe_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='authorization_owner' AND wait_event_type='Lock' AND query LIKE '%public.oauth_dynamic_clients%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(
            Instant::now() < end,
            "operation reaches actual dynamic-client SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
fn request_hash(d: &CredentialDigester, raw: &str) -> String {
    d.token(TokenKind::OidcAuthRequest, raw.as_bytes())
        .unwrap()
        .to_sql_hex()
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS native OIDC authorization admission, current clients, deadlines and rollback"]
async fn postgres_oidc_authorization_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE authorization_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION authorization_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO authorization_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let d = Arc::new(support::digester());
    let p = Arc::new(policy(true, 4096));
    let service = store.oidc_authorization_service(&d, &p);
    let ordinary: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT NOT rolsuper FROM pg_roles WHERE rolname='authorization_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(ordinary);
    let pending = service
        .create(
            input("graphit-cli", "http://127.0.0.1:49152/oauth/callback", &[]),
            deadline(),
        )
        .await
        .unwrap();
    let raw = Zeroizing::new(pending.request().to_owned());
    let hash = request_hash(&d, &raw);
    assert_eq!(raw.len(), 43);
    assert_eq!(hash.len(), 64);
    let row =
        sqlx_core::query::query("SELECT * FROM public.oidc_auth_requests WHERE request_hash=$1")
            .bind(&hash)
            .fetch_one(&mut c)
            .await
            .unwrap();
    assert_eq!(row.get::<String, _>("identity_subject"), "");
    assert!(row.get::<Option<String>, _>("code_hash").is_none());
    assert_eq!(
        row.get::<i64, _>("expires_at") - row.get::<i64, _>("created_at"),
        600_000_000
    );
    let original_json = Zeroizing::new(row.get::<String, _>("request_json"));
    assert!(!original_json.contains(raw.as_str()));
    let json: serde_json::Value = serde_json::from_str(&original_json).unwrap();
    assert_eq!(json["format"], "rust-broker-authorization-v1");
    assert_eq!(json["phase"], "pending");
    assert_eq!(json["api_audience"], "graphit-broker");
    assert_eq!(json["resource"], serde_json::Value::Null);
    assert_eq!(
        json["redirect_uri"],
        "http://127.0.0.1:49152/oauth/callback"
    );
    assert_eq!(json["code_challenge_method"], "S256");
    assert_eq!(
        json["scopes"],
        serde_json::json!([
            "openid",
            "profile",
            "email",
            "phone",
            "address",
            "offline_access"
        ])
    );
    let before = snapshot(&mut c).await;
    for _ in 0..3 {
        let i = service.load(&raw, deadline()).await.unwrap().unwrap();
        assert_eq!(i.state(), " state ");
        assert_eq!(i.nonce(), " nonce ");
        assert_eq!(i.created_at(), pending.info().created_at());
        assert_eq!(i.expires_at(), pending.info().expires_at());
        assert_eq!(i.resource(), None);
        assert_eq!(i.redirect_uri(), pending.info().redirect_uri());
        assert_eq!(i.scopes(), pending.info().scopes());
    }
    assert_eq!(snapshot(&mut c).await, before);
    let missing = broker_security::new_local_auth_challenge().unwrap();
    assert!(service.load(&missing, deadline()).await.unwrap().is_none());
    assert_eq!(
        service.load("bad", deadline()).await.unwrap_err(),
        Error::InvalidRequest
    );
    // A row from another digest domain is absent, never repaired or imported.
    let wrong_hash = d
        .token(TokenKind::LocalAuthChallenge, raw.as_bytes())
        .unwrap()
        .to_sql_hex();
    sqlx_core::query::query(
        "UPDATE public.oidc_auth_requests SET request_hash=$1 WHERE request_hash=$2",
    )
    .bind(&wrong_hash)
    .bind(&hash)
    .execute(&mut c)
    .await
    .unwrap();
    assert!(service.load(&raw, deadline()).await.unwrap().is_none());
    sqlx_core::query::query(
        "UPDATE public.oidc_auth_requests SET request_hash=$1 WHERE request_hash=$2",
    )
    .bind(&hash)
    .bind(&wrong_hash)
    .execute(&mut c)
    .await
    .unwrap();
    assert_eq!(
        format!("{pending:?}"),
        "PendingOidcAuthorization([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", pending.info()),
        "OidcAuthorizationRequestInfo([REDACTED])"
    );
    for redirect in [
        "HTTP://LOCALHOST:49153/oauth/callback",
        "http://localhost:49153/oauth/callback",
        "https://127.0.0.2:49153/oauth/callback",
        "http://[::1]:49153/oauth/callback",
        "http://127.0.0.1:49152/oauth/callback?",
    ] {
        assert!(
            service
                .create(input("graphit-cli", redirect, &[]), deadline())
                .await
                .is_ok(),
            "valid original Native redirect"
        );
    }
    for redirect in [
        "http://127.1:49152/oauth/callback",
        "http://0x7f000001:49152/oauth/callback",
        "http://0177.0.0.1:49152/oauth/callback",
        "http://localhost:0/oauth/callback",
        "http://example.com/oauth/callback",
        "http://localhost/oauth/../oauth/callback",
        "http://localhost/other",
        "http://localhost/oauth/callback?q=x",
        "http://user@localhost/oauth/callback",
        "http://localhost/oauth/callback#x",
    ] {
        let before = snapshot(&mut c).await;
        assert_eq!(
            service
                .create(input("graphit-cli", redirect, &[]), deadline())
                .await
                .unwrap_err(),
            Error::InvalidRedirect
        );
        assert_eq!(snapshot(&mut c).await, before);
    }
    client(
        &mut c,
        "native-client",
        "native",
        &["http://127.0.0.1/oauth/callback"],
    )
    .await;
    let resources = [RESOURCE];
    let native = service
        .create(
            input(
                "native-client",
                "https://localhost:49152/oauth/callback",
                &resources,
            ),
            deadline(),
        )
        .await
        .unwrap();
    let native_raw = Zeroizing::new(native.request().to_owned());
    assert_eq!(native.info().resource(), Some(RESOURCE));
    assert_eq!(native.info().scopes(), pending.info().scopes()); // Registered scope subset does not invent scope restrictions.
    assert!(
        service
            .load(&native_raw, deadline())
            .await
            .unwrap()
            .is_some()
    );
    let disabled = policy(false, 4096);
    let no_dynamic = store.oidc_authorization_service(&d, &disabled);
    assert_eq!(
        no_dynamic
            .create(
                input(
                    "native-client",
                    "http://localhost/oauth/callback",
                    &resources
                ),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::InvalidClient
    );
    assert_eq!(
        no_dynamic.load(&native_raw, deadline()).await.unwrap_err(),
        Error::InvalidClient
    );
    assert_eq!(
        service
            .create(
                input(
                    "missing-client",
                    "http://localhost/oauth/callback",
                    &resources
                ),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::InvalidClient
    );
    assert_eq!(
        service
            .create(
                input("native-client", "http://localhost/oauth/callback", &[]),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::InvalidTarget
    );
    for (registered, requested, expected) in [
        ("http://127.0.0.1/café", "https://localhost/caf%C3%A9", true),
        ("http://127.0.0.1/%FF", "https://localhost/%ff", true),
        ("http://127.0.0.1/a+b", "https://localhost/a%2Bb", true),
        ("http://127.0.0.1/a+b", "https://localhost/a%20b", false),
        ("http://127.0.0.1/a/../b", "https://localhost/b", false),
        (
            "http://127.0.0.1/cb?q=é",
            "https://localhost/cb?q=%C3%A9",
            false,
        ),
        (
            "http://127.0.0.1/cb?q=%2f",
            "https://localhost/cb?q=%2F",
            false,
        ),
        ("http://127.0.0.1/cb?", "https://localhost/cb", true),
    ] {
        client(&mut c, "table-client", "native", &[registered]).await;
        let before = snapshot(&mut c).await;
        let result = service
            .create(input("table-client", requested, &resources), deadline())
            .await;
        assert_eq!(
            result.is_ok(),
            expected,
            "Original decoded path and RawQuery oracle"
        );
        if let Ok(result) = result {
            assert_eq!(
                service
                    .load(result.request(), deadline())
                    .await
                    .unwrap()
                    .unwrap()
                    .redirect_uri(),
                requested
            )
        } else {
            assert_eq!(snapshot(&mut c).await, before)
        }
    }
    client(
        &mut c,
        "web-client",
        "web",
        &["https://client.example/callback?q=x"],
    )
    .await;
    let web = service
        .create(
            input(
                "web-client",
                "https://client.example/callback?q=x",
                &resources,
            ),
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        service
            .load(web.request(), deadline())
            .await
            .unwrap()
            .is_some()
    );
    for redirect in [
        "https://CLIENT.example/callback?q=x",
        "https://client.example:443/callback?q=x",
        "https://client.example/callback/?q=x",
        "https://client.example/callback?q=%78",
        "http://client.example/callback?q=x",
    ] {
        assert_eq!(
            service
                .create(input("web-client", redirect, &resources), deadline())
                .await
                .unwrap_err(),
            Error::InvalidRedirect
        )
    }
    // Active DCR permits unnamed and mixed Web registrations.
    client(
        &mut c,
        "mixed-web",
        "web",
        &[
            "http://127.0.0.1/callback",
            "https://client.example/callback",
        ],
    )
    .await;
    c.execute("UPDATE public.oauth_dynamic_clients SET client_name='' WHERE client_id='mixed-web'")
        .await
        .unwrap();
    let mixed = service
        .create(
            input("mixed-web", "https://client.example/callback", &resources),
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        service
            .load(mixed.request(), deadline())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        service
            .create(
                input("mixed-web", "http://localhost/callback", &resources),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::InvalidRedirect
    );
    for (kind, uris) in [
        ("native", &["https://client.example/callback"][..]),
        ("web", &["http://127.0.0.1/callback"][..]),
        ("native", &["https://localhost/callback"][..]),
        ("web", &["https://localhost/callback"][..]),
    ] {
        client(&mut c, "invalid-catalog", kind, uris).await;
        assert_eq!(
            service
                .create(
                    input(
                        "invalid-catalog",
                        "https://client.example/callback",
                        &resources
                    ),
                    deadline()
                )
                .await
                .unwrap_err(),
            Error::MalformedStored
        );
    }
    let mut nul = input("graphit-cli", "http://localhost/oauth/callback", &[]);
    nul.state = "state\0suffix";
    nul.nonce = "nonce\0suffix";
    let nul = service.create(nul, deadline()).await.unwrap();
    let observed = service
        .load(nul.request(), deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed.state(), "state\0suffix");
    assert_eq!(observed.nonce(), "nonce\0suffix");
    let wrong_pepper = CredentialDigester::new(
        Zeroizing::new(vec![0x92; 32].into_boxed_slice()),
        broker_security::DigestLimits::new(n(64), n(256), n(256), n(256), n(256)).unwrap(),
    )
    .unwrap();
    assert!(
        store
            .oidc_authorization_service(&wrong_pepper, &p)
            .load(&raw, deadline())
            .await
            .unwrap()
            .is_none()
    );
    let unicode_name = "🦀".repeat(256);
    assert_eq!(unicode_name.len(), 1024);
    sqlx_core::query::query(
        "UPDATE public.oauth_dynamic_clients SET client_name=$1 WHERE client_id='mixed-web'",
    )
    .bind(unicode_name)
    .execute(&mut c)
    .await
    .unwrap();
    let unicode = service
        .create(
            input("mixed-web", "https://client.example/callback", &resources),
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        service
            .load(unicode.request(), deadline())
            .await
            .unwrap()
            .is_some()
    );
    client(
        &mut c,
        "upper-native",
        "native",
        &["HTTP://127.0.0.1/callback"],
    )
    .await;
    let upper = service
        .create(
            input(
                "upper-native",
                "HTTPS://LOCALHOST:49153/callback",
                &resources,
            ),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        service
            .load(upper.request(), deadline())
            .await
            .unwrap()
            .unwrap()
            .redirect_uri(),
        "HTTPS://LOCALHOST:49153/callback"
    );
    client(
        &mut c,
        "upper-web",
        "web",
        &["HTTPS://client.example/callback"],
    )
    .await;
    let upper = service
        .create(
            input("upper-web", "HTTPS://client.example/callback", &resources),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        service
            .load(upper.request(), deadline())
            .await
            .unwrap()
            .unwrap()
            .redirect_uri(),
        "HTTPS://client.example/callback"
    );
    assert_eq!(
        service
            .create(
                input("upper-web", "https://client.example/callback", &resources),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::InvalidRedirect
    );
    // Native object errors are actual stored SQL rows, never deserializer substitutes.
    for raw_json in [
        "[]".to_owned(),
        "{}".into(),
        "null".into(),
        format!("{} {{}}", original_json.as_str()),
        original_json.replacen('{', "{\"extra\":1,", 1),
        original_json.replacen('{', "{\"phase\":\"pending\",", 1),
    ] {
        request_json(&mut c, &hash, &raw_json).await;
        let before = snapshot(&mut c).await;
        assert_eq!(
            service.load(&raw, deadline()).await.unwrap_err(),
            Error::MalformedStored
        );
        assert_eq!(snapshot(&mut c).await, before);
    }
    for (field, value) in [
        ("format", "go"),
        ("phase", "authorized"),
        ("api_audience", "other"),
        ("client_id", "web-client"),
        ("code_challenge_method", "plain"),
        ("code_challenge", "wrong"),
        ("response_mode", "unknown"),
        ("nonce", " "),
    ] {
        let mut v = json.clone();
        v[field] = value.into();
        request_json(&mut c, &hash, &v.to_string()).await;
        assert_eq!(
            service.load(&raw, deadline()).await.unwrap_err(),
            Error::MalformedStored
        );
    }
    for scopes in [
        serde_json::json!(["openid", "openid"]),
        serde_json::json!(["openid", "unknown"]),
        serde_json::json!(["email"]),
        serde_json::json!([1]),
    ] {
        let mut v = json.clone();
        v["scopes"] = scopes;
        request_json(&mut c, &hash, &v.to_string()).await;
        assert_eq!(
            service.load(&raw, deadline()).await.unwrap_err(),
            Error::MalformedStored
        )
    }
    request_json(&mut c, &hash, &original_json).await;
    let narrow = policy(true, original_json.len() - 1);
    assert_eq!(
        store
            .oidc_authorization_service(&d, &narrow)
            .load(&raw, deadline())
            .await
            .unwrap_err(),
        Error::ReadLimitExceeded
    );
    let exact = policy(true, original_json.len());
    assert!(
        store
            .oidc_authorization_service(&d, &exact)
            .load(&raw, deadline())
            .await
            .unwrap()
            .is_some()
    );
    let tiny = policy(true, 1);
    let before = snapshot(&mut c).await;
    assert_eq!(
        store
            .oidc_authorization_service(&d, &tiny)
            .create(
                input("graphit-cli", "http://localhost/oauth/callback", &[]),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::ReadLimitExceeded
    );
    assert_eq!(snapshot(&mut c).await, before);
    for field in ["code_hash", "identity_subject"] {
        let sql = if field == "code_hash" {
            "UPDATE public.oidc_auth_requests SET code_hash=repeat('a',64),request_json='not pending codec' WHERE request_hash=$1"
        } else {
            "UPDATE public.oidc_auth_requests SET identity_subject='authorized-subject',request_json='not pending codec' WHERE request_hash=$1"
        };
        sqlx_core::query::query(sql)
            .bind(&hash)
            .execute(&mut c)
            .await
            .unwrap();
        assert!(service.load(&raw, deadline()).await.unwrap().is_none());
        sqlx_core::query::query("UPDATE public.oidc_auth_requests SET code_hash=NULL,identity_subject='',request_json=$2 WHERE request_hash=$1").bind(&hash).bind(&*original_json).execute(&mut c).await.unwrap();
    }
    // Current registration deletion/corruption cannot retain earlier client authority.
    for (column, value) in [
        ("redirect_uris_json", "[]"),
        ("redirect_uris_json", "[1]"),
        ("redirect_uris_json", "[\"http://example.com/cb\"]"),
        ("scopes_json", "[]"),
        ("scopes_json", "[\" openid \"]"),
        ("scopes_json", "[\"openid\",\"openid\"]"),
        ("application_type", "other"),
    ] {
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "UPDATE public.oauth_dynamic_clients SET {column}=$1 WHERE client_id='native-client'"
        )))
        .bind(value)
        .execute(&mut c)
        .await
        .unwrap();
        assert_eq!(
            service.load(&native_raw, deadline()).await.unwrap_err(),
            Error::MalformedStored
        );
        client(
            &mut c,
            "native-client",
            "native",
            &["http://127.0.0.1/oauth/callback"],
        )
        .await;
    }
    sqlx_core::query::query(
        "UPDATE public.oauth_dynamic_clients SET created_at=0 WHERE client_id='native-client'",
    )
    .execute(&mut c)
    .await
    .unwrap();
    assert_eq!(
        service.load(&native_raw, deadline()).await.unwrap_err(),
        Error::MalformedStored
    );
    client(
        &mut c,
        "native-client",
        "native",
        &["http://127.0.0.1/oauth/callback"],
    )
    .await;
    c.execute("DELETE FROM public.oauth_dynamic_clients WHERE client_id='native-client'")
        .await
        .unwrap();
    assert_eq!(
        service.load(&native_raw, deadline()).await.unwrap_err(),
        Error::InvalidClient
    );
    client(
        &mut c,
        "native-client",
        "native",
        &["http://127.0.0.1/oauth/callback"],
    )
    .await;
    // Real privileges, constraints, and a deferred COMMIT rejection never return a request.
    let before = snapshot(&mut c).await;
    c.execute("REVOKE INSERT ON public.oidc_auth_requests FROM authorization_owner")
        .await
        .unwrap();
    assert_eq!(
        service
            .create(
                input("graphit-cli", "http://localhost/oauth/callback", &[]),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    c.execute("GRANT INSERT ON public.oidc_auth_requests TO authorization_owner")
        .await
        .unwrap();
    assert_eq!(snapshot(&mut c).await, before);
    c.execute("ALTER TABLE public.oidc_auth_requests ADD CONSTRAINT reject_pending CHECK (false) NOT VALID").await.unwrap();
    assert_eq!(
        service
            .create(
                input("graphit-cli", "http://localhost/oauth/callback", &[]),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    c.execute("ALTER TABLE public.oidc_auth_requests DROP CONSTRAINT reject_pending")
        .await
        .unwrap();
    assert_eq!(snapshot(&mut c).await, before);
    c.execute("CREATE FUNCTION public.reject_authorization_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture commit rejection'; END $$; CREATE CONSTRAINT TRIGGER reject_authorization_commit AFTER INSERT ON public.oidc_auth_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_authorization_commit()").await.unwrap();
    assert_eq!(
        service
            .create(
                input("graphit-cli", "http://localhost/oauth/callback", &[]),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::Control(ControlError::OutcomeUncertain)
    );
    c.execute("DROP TRIGGER reject_authorization_commit ON public.oidc_auth_requests; DROP FUNCTION public.reject_authorization_commit()").await.unwrap();
    assert_eq!(snapshot(&mut c).await, before);
    assert!(service.load(&raw, deadline()).await.unwrap().is_some());
    let mut locker = f.connection().await;
    for create in [true, false] {
        for abort in [false, true] {
            let before = snapshot(&mut c).await;
            let mut tx = locker.begin().await.unwrap();
            tx.execute("UPDATE public.oauth_dynamic_clients SET client_name=client_name WHERE client_id='native-client'").await.unwrap();
            let (s, d, p) = (Arc::clone(&store), Arc::clone(&d), Arc::clone(&p));
            let request = Zeroizing::new(native_raw.to_string());
            let end = if abort {
                deadline()
            } else {
                Instant::now() + Duration::from_millis(1200)
            };
            let op = tokio::spawn(async move {
                let service = s.oidc_authorization_service(&d, &p);
                if create {
                    service
                        .create(
                            input(
                                "native-client",
                                "http://localhost/oauth/callback",
                                &[RESOURCE],
                            ),
                            end,
                        )
                        .await
                        .map(|_| ())
                } else {
                    service.load(&request, end).await.map(|_| ())
                }
            });
            observe_lock(&mut c).await;
            if abort {
                op.abort();
                assert!(op.await.unwrap_err().is_cancelled())
            } else {
                assert_eq!(
                    op.await.unwrap().unwrap_err(),
                    Error::Control(ControlError::Deadline)
                )
            }
            tx.rollback().await.unwrap();
            assert_eq!(snapshot(&mut c).await, before);
            assert!(
                service
                    .load(&native_raw, deadline())
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
    // Load detects a changed pending row after the client wait and never blesses its initial snapshot.
    let native_hash = request_hash(&d, &native_raw);
    let native_json: String = sqlx_core::query_scalar::query_scalar(
        "SELECT request_json FROM public.oidc_auth_requests WHERE request_hash=$1",
    )
    .bind(&native_hash)
    .fetch_one(&mut c)
    .await
    .unwrap();
    for completed in [false, true] {
        let mut tx = locker.begin().await.unwrap();
        tx.execute("UPDATE public.oauth_dynamic_clients SET client_name=client_name WHERE client_id='native-client'").await.unwrap();
        let (s, dd, pp) = (Arc::clone(&store), Arc::clone(&d), Arc::clone(&p));
        let request = Zeroizing::new(native_raw.to_string());
        let op = tokio::spawn(async move {
            s.oidc_authorization_service(&dd, &pp)
                .load(&request, deadline())
                .await
        });
        observe_lock(&mut c).await;
        if completed {
            sqlx_core::query::query("UPDATE public.oidc_auth_requests SET identity_subject='completed' WHERE request_hash=$1").bind(&native_hash).execute(&mut c).await.unwrap();
        } else {
            let mut json: serde_json::Value = serde_json::from_str(&native_json).unwrap();
            json["nonce"] = "changed-nonce".into();
            request_json(&mut c, &native_hash, &json.to_string()).await;
        }
        tx.rollback().await.unwrap();
        let result = op.await.unwrap();
        if completed {
            assert!(result.unwrap().is_none())
        } else {
            assert_eq!(result.unwrap_err(), Error::MalformedStored)
        }
        sqlx_core::query::query("UPDATE public.oidc_auth_requests SET identity_subject='',request_json=$1 WHERE request_hash=$2").bind(&native_json).bind(&native_hash).execute(&mut c).await.unwrap();
        assert!(
            service
                .load(&native_raw, deadline())
                .await
                .unwrap()
                .is_some()
        );
    }
    // Current-client change while admission is waiting is rechecked after the lock.
    let mut tx = locker.begin().await.unwrap();
    tx.execute("UPDATE public.oauth_dynamic_clients SET redirect_uris_json='[\"http://127.0.0.1/other\"]' WHERE client_id='native-client'").await.unwrap();
    let (s, dd, pp) = (Arc::clone(&store), Arc::clone(&d), Arc::clone(&p));
    let op = tokio::spawn(async move {
        s.oidc_authorization_service(&dd, &pp)
            .create(
                input(
                    "native-client",
                    "http://localhost/oauth/callback",
                    &[RESOURCE],
                ),
                deadline(),
            )
            .await
    });
    observe_lock(&mut c).await;
    tx.commit().await.unwrap();
    assert_eq!(op.await.unwrap().unwrap_err(), Error::InvalidRedirect);
    client(
        &mut c,
        "native-client",
        "native",
        &["http://127.0.0.1/oauth/callback"],
    )
    .await;
    // Actual UTC expiry during a SQL wait returns no info; original expiry is never renewed.
    let native_hash = request_hash(&d, &native_raw);
    let expiry = micros() + 1_000_000;
    sqlx_core::query::query("UPDATE public.oidc_auth_requests SET expires_at=$1,created_at=$1-600000000 WHERE request_hash=$2").bind(expiry).bind(&native_hash).execute(&mut c).await.unwrap();
    let mut tx = locker.begin().await.unwrap();
    tx.execute("UPDATE public.oauth_dynamic_clients SET client_name=client_name WHERE client_id='native-client'").await.unwrap();
    let (s, dd, pp) = (Arc::clone(&store), Arc::clone(&d), Arc::clone(&p));
    let request = Zeroizing::new(native_raw.to_string());
    let op = tokio::spawn(async move {
        s.oidc_authorization_service(&dd, &pp)
            .load(&request, deadline())
            .await
    });
    observe_lock(&mut c).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    tx.rollback().await.unwrap();
    assert!(op.await.unwrap().unwrap().is_none());
    assert!(
        service
            .load(&native_raw, deadline())
            .await
            .unwrap()
            .is_none()
    );
    sqlx_core::query::query(
        "UPDATE public.oidc_auth_requests SET expires_at=$1 WHERE request_hash=$2",
    )
    .bind(micros())
    .bind(&hash)
    .execute(&mut c)
    .await
    .unwrap();
    assert!(service.load(&raw, deadline()).await.unwrap().is_none());
    let before = snapshot(&mut c).await;
    assert_eq!(
        service
            .create(
                input("graphit-cli", "http://localhost/oauth/callback", &[]),
                Instant::now()
            )
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    assert_eq!(
        service.load(&raw, Instant::now()).await.unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    assert_eq!(snapshot(&mut c).await, before);
    // Deterministic SDK IDs exercise both public prefixes outside username syntax.
    for first in [248u8, 252u8] {
        let mut bytes = [0u8; 32];
        bytes[0] = first;
        let id = URL_SAFE_NO_PAD.encode(bytes);
        client(&mut c, &id, "web", &["https://client.example/cb"]).await;
        let pending = service
            .create(
                input(&id, "https://client.example/cb", &[RESOURCE]),
                deadline(),
            )
            .await
            .unwrap();
        let admitted = service
            .load(pending.request(), deadline())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admitted.client_id(), id);
        assert_eq!(admitted.redirect_uri(), "https://client.example/cb");
    }
    locker.close().await.unwrap();
    c.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        service.load(&raw, deadline()).await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    f.shutdown().unwrap();
}

const WEB_REDIRECT: &str = "https://client.example/%2f?kept=%2F";
const RESOURCES: &[&str] = &[RESOURCE];
async fn browser_fixture() -> (Fixture, PgConnection, Arc<PostgresControlStore>) {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE authorization_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION authorization_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO authorization_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    client(&mut c, "web-client", "web", &[WEB_REDIRECT]).await;
    (f, c, store)
}
fn browser_input() -> OidcAuthorizationInput<'static> {
    input("web-client", WEB_REDIRECT, RESOURCES)
}
fn rejection(
    result: broker_control::BrowserOidcAuthorization<'_>,
) -> broker_control::RejectedOidcAuthorization<'_> {
    match result {
        broker_control::BrowserOidcAuthorization::Rejected(r) => r,
        _ => panic!("expected protected rejection"),
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS initial Browser admission, protected errors, pre-SQL rejection and current-client locks"]
async fn postgres_oidc_browser_admission_contract() {
    use broker_control::{
        BrowserOidcAuthorization as Admission, OidcAuthorizationRejectionCode as Code,
        OidcAuthorizationResponseMode as Mode,
    };
    let (f, mut c, store) = browser_fixture().await;
    let p = policy(true, 4096);
    let service = store.browser_oidc_authorizations(&p);
    let initial = snapshot(&mut c).await;
    for mode in [
        None,
        Some("query"),
        Some("fragment"),
        Some("form_post"),
        Some(""),
        Some("unrecognized"),
    ] {
        for (case, expected) in [
            (0, Code::InvalidRequest),
            (1, Code::InvalidScope),
            (2, Code::LoginRequired),
            (3, Code::InvalidTarget),
        ] {
            let mut request = browser_input();
            request.response_mode = mode;
            request.state = " state café%<& ";
            match case {
                0 => request.nonce = "",
                1 => request.scope = "profile",
                2 => request.prompts = &["none"],
                _ => request.resources = &["https://unaccepted.example/"],
            }
            let r = rejection(service.admit_browser(request, deadline()).await.unwrap());
            assert_eq!(r.code(), expected);
            assert_eq!(
                r.code().as_str(),
                match case {
                    0 => "invalid_request",
                    1 => "invalid_scope",
                    2 => "login_required",
                    _ => "invalid_target",
                }
            );
            assert_eq!(format!("{r:?}"), "RejectedOidcAuthorization([REDACTED])");
            let target = r.into_target();
            target.check().unwrap();
            assert_eq!(target.redirect_uri(), WEB_REDIRECT);
            assert_eq!(target.origin(), "https://client.example");
            assert_eq!(target.state(), " state café%<& ");
            assert_eq!(
                target.response_mode(),
                match mode {
                    Some("fragment") => Mode::Fragment,
                    Some("form_post") => Mode::FormPost,
                    _ => Mode::Query,
                }
            );
            assert_eq!(
                format!("{target:?}"),
                "OidcAuthorizationResponseTarget([REDACTED])"
            );
        }
    }
    for state in ["", " ", " literal\0\r\n café "] {
        for mode in [None, Some("fragment")] {
            let mut request = browser_input();
            request.nonce = "";
            request.state = state;
            request.response_mode = mode;
            let r = rejection(service.admit_browser(request, deadline()).await.unwrap());
            assert_eq!(r.into_target().state(), state);
        }
    }
    assert_eq!(
        snapshot(&mut c).await,
        initial,
        "semantic rejections never insert pending requests"
    );
    // Browser destination safety precedes semantic rejection; the direct P2 precedence stays unchanged.
    let mut request = browser_input();
    request.nonce = "";
    request.redirect_uri = "https://attacker.example/cb";
    assert_eq!(
        service.create(request, deadline()).await.unwrap_err(),
        Error::InvalidRequest
    );
    let mut request = browser_input();
    request.nonce = "";
    request.redirect_uri = "https://attacker.example/cb";
    assert_eq!(
        service
            .admit_browser(request, deadline())
            .await
            .unwrap_err(),
        Error::InvalidRedirect
    );
    let mut request = browser_input();
    request.client_id = "missing-client";
    request.nonce = "";
    assert_eq!(
        service
            .admit_browser(request, deadline())
            .await
            .unwrap_err(),
        Error::InvalidClient
    );
    let mut locker = f.connection().await;
    let mut lock = locker.begin().await.unwrap();
    lock.execute("LOCK TABLE public.oauth_dynamic_clients IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    for state in ["bad\0state", "bad\rstate", "bad\nstate"] {
        let mut request = browser_input();
        request.state = state;
        request.response_mode = Some("form_post");
        assert_eq!(
            service
                .admit_browser(request, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap_err(),
            Error::InvalidRequest
        );
    }
    let state = "x".repeat(513);
    let mut request = browser_input();
    request.state = &state;
    assert_eq!(
        service
            .admit_browser(request, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap_err(),
        Error::InvalidRequest
    );
    let huge = "n".repeat(8193);
    let mut request = browser_input();
    request.nonce = &huge;
    assert_eq!(
        service
            .admit_browser(request, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap_err(),
        Error::InvalidRequest
    );
    let p2 = Arc::new(policy(true, 4096));
    let copy = store.clone();
    let pp = p2.clone();
    let waiting = tokio::spawn(async move {
        let mut r = browser_input();
        r.nonce = "";
        copy.browser_oidc_authorizations(&pp)
            .admit_browser(r, deadline())
            .await
    });
    observe_lock(&mut c).await;
    lock.rollback().await.unwrap();
    assert_eq!(
        rejection(waiting.await.unwrap().unwrap()).code(),
        Code::InvalidRequest
    );
    // READ COMMITTED observes a changed registration after waiting for its row lock.
    let mut lock = locker.begin().await.unwrap();
    lock.execute("UPDATE public.oauth_dynamic_clients SET redirect_uris_json='[\"https://client.example/changed\"]' WHERE client_id='web-client'").await.unwrap();
    let copy = store.clone();
    let pp = p2.clone();
    let waiting = tokio::spawn(async move {
        let mut r = browser_input();
        r.nonce = "";
        copy.browser_oidc_authorizations(&pp)
            .admit_browser(r, deadline())
            .await
    });
    observe_lock(&mut c).await;
    lock.commit().await.unwrap();
    assert_eq!(waiting.await.unwrap().unwrap_err(), Error::InvalidRedirect);
    client(&mut c, "web-client", "web", &[WEB_REDIRECT]).await;
    // Storage/client corruption stays local and cannot become a protected protocol error.
    c.execute("UPDATE public.oauth_dynamic_clients SET redirect_uris_json='{}' WHERE client_id='web-client'").await.unwrap();
    let mut request = browser_input();
    request.nonce = "";
    assert_eq!(
        service
            .admit_browser(request, deadline())
            .await
            .unwrap_err(),
        Error::MalformedStored
    );
    client(&mut c, "web-client", "web", &[WEB_REDIRECT]).await;
    let mut lock = locker.begin().await.unwrap();
    lock.execute("LOCK TABLE public.oauth_dynamic_clients IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let mut request = browser_input();
    request.nonce = "";
    assert_eq!(
        service
            .admit_browser(request, Instant::now() + Duration::from_millis(250))
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    lock.rollback().await.unwrap();
    // Initial targets never renew the exact caller Original.
    let end = Instant::now() + Duration::from_secs(1);
    let mut request = browser_input();
    request.nonce = "";
    let target = rejection(service.admit_browser(request, end).await.unwrap()).into_target();
    target.check().unwrap();
    tokio::time::sleep_until(end.into()).await;
    assert_eq!(
        target.check().unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    assert_eq!(
        service
            .admit_browser(browser_input(), Instant::now())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    for mode in [None, Some("fragment"), Some("form_post")] {
        let mut request = browser_input();
        request.response_mode = mode;
        let pending = match service.admit_browser(request, deadline()).await.unwrap() {
            Admission::Pending(p) => p,
            _ => panic!("expected genuine pending"),
        };
        assert_eq!(pending.request().len(), 43);
        let observed = service
            .load(pending.request(), deadline())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed.redirect_uri(), WEB_REDIRECT);
        assert_eq!(
            observed.response_mode(),
            match mode {
                Some("fragment") => Mode::Fragment,
                Some("form_post") => Mode::FormPost,
                _ => Mode::Query,
            }
        );
        observed
            .response_target(deadline())
            .unwrap()
            .check()
            .unwrap();
    }
    for mode in [None, Some("fragment")] {
        let mut request = browser_input();
        request.response_mode = mode;
        request.state = " literal\0\r\n café ";
        let pending = match service.admit_browser(request, deadline()).await.unwrap() {
            Admission::Pending(p) => p,
            _ => panic!("expected literal pending"),
        };
        let observed = service
            .load(pending.request(), deadline())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed.state(), " literal\0\r\n café ");
    }
    let before = snapshot(&mut c).await;
    store.shutdown(deadline()).await.unwrap();
    let mut request = browser_input();
    request.nonce = "";
    assert_eq!(
        service
            .admit_browser(request, deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    assert_eq!(snapshot(&mut c).await, before);
    locker.close().await.unwrap();
    c.close().await.unwrap();
    f.shutdown().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real PostgreSQL TLS read COMMIT-idle ACK withheld must not return a protected Browser rejection"]
async fn postgres_oidc_browser_rejection_uncertainty_contract() {
    let (f, mut c, initial_store) = browser_fixture().await;
    initial_store.shutdown(deadline()).await.unwrap();
    let mut relay = commit::CommitRelay::new(f.port).await;
    let mut pool = support::pool(1);
    pool.operation_timeout = Duration::from_secs(3);
    let store = PostgresControlStore::open(
        config_at(&f, relay.port, pool),
        support::digester(),
        deadline(),
    )
    .await
    .unwrap();
    let p = policy(true, 4096);
    let service = store.browser_oidc_authorizations(&p);
    let before = snapshot(&mut c).await;
    let mut locker = f.connection().await;
    let mut lock = locker.begin().await.unwrap();
    lock.execute("LOCK TABLE public.oauth_dynamic_clients IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    {
        let mut request = browser_input();
        request.nonce = "";
        let operation = service.admit_browser(request, deadline());
        tokio::pin!(operation);
        tokio::select! { _=observe_lock(&mut c)=>{}, result=&mut operation=>panic!("admission must reach real held SQL: {result:?}") };
        let pid:i32=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='authorization_owner' AND wait_event_type='Lock' LIMIT 1").fetch_one(&mut c).await.unwrap();
        relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        lock.rollback().await.unwrap();
        let hold = async {
            loop {
                let decision = tokio::time::timeout_at(deadline().into(), relay.replies.recv())
                    .await
                    .unwrap()
                    .unwrap();
                let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
                    "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
                )
                .bind(pid)
                .fetch_one(&mut c)
                .await
                .unwrap();
                if query == "COMMIT" && idle {
                    decision.send(false).unwrap();
                    break;
                }
                decision.send(true).unwrap();
            }
        };
        tokio::select! { _=hold=>{}, result=&mut operation=>panic!("read COMMIT ACK must remain held: {result:?}") };
        assert_eq!(
            operation.await.unwrap_err(),
            Error::Control(ControlError::OutcomeUncertain)
        );
    }
    assert_eq!(
        snapshot(&mut c).await,
        before,
        "read transaction committed without inserting pending or releasing a target"
    );
    relay.close().await;
    store.shutdown(deadline()).await.unwrap();
    locker.close().await.unwrap();
    c.close().await.unwrap();
    f.shutdown().unwrap();
}
