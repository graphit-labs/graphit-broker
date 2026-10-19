// The shared fixture also serves native suites with different SQL contracts.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessError, BrokerAccessVerifier, ConnectionLimits, ControlError,
    HubAccessError as Error, HubAccessResolution, LocalBearerVerificationError, PostgresConfig,
    PostgresControlStore, PostgresCredentials, PostgresEndpoint, ResourceGrantReadError,
};
use broker_security::TokenKind;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
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
const ISSUER: &str = "https://broker.example.test";
const RESOURCE: &str = "https://broker.example.test/v1";
const RAW: &str = "gb_at_ephemeral-hub-access";
const SERVICE: &str = "gb_sc_ephemeral-hub-service";
struct Signer {
    key: EncodingKey,
    keys: jsonwebtoken::jwk::JwkSet,
}
impl Signer {
    fn new() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self { key: EncodingKey::from_ed_der(&pair.serialize_der()), keys: serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"hub-key","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())}]})).unwrap() }
    }
    fn verifier(&self, resource: Option<&str>) -> BrokerAccessVerifier {
        BrokerAccessVerifier::new(ISSUER, "hub-api", resource, &self.keys, n(8192)).unwrap()
    }
    fn claims(&self) -> Value {
        let now = seconds();
        json!({"iss":ISSUER,"sub":"hub-subject","aud":["hub-api",RESOURCE],"iat":now-1,"exp":now+600,"token_use":"access","client_id":"explicit-client","jti":"hub-token","scope":"","preferred_username":"alice","organization":"engineering","groups":["dev"],"roles":["admin"]})
    }
    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("hub-key".into());
        encode(&header, claims, &self.key).unwrap()
    }
}
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new("hub_owner".into(), Zeroizing::new("ephemeral-owner".into())),
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
    kind: &str,
    principal: &str,
    caps: &[&str],
    projects: &[&str],
) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture',$2,$3,'',0,0)").bind(id).bind(kind).bind(principal).execute(&mut *c).await.unwrap();
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
    for p in projects {
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(*p)
            .execute(&mut *c)
            .await
            .unwrap();
    }
}
fn wire(mut r: HubAccessResolution<'_>) -> Value {
    r.check().unwrap();
    assert_eq!(format!("{r:?}"), "HubAccessResolution([REDACTED])");
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 4);
    assert_eq!(v["v"], 1);
    assert_eq!(v["authorization_revision"], r.authorization_revision());
    assert_eq!(v["subject"], r.subject());
    for selector in r.selectors() {
        assert_ne!(selector.id().is_some(), selector.is_all());
    }
    v
}
async fn native(
    store: &PostgresControlStore,
    verifier: &BrokerAccessVerifier,
    raw: Option<&str>,
    end: Instant,
) -> Result<Value, Error> {
    Ok(wire(
        store
            .broker_hub_access_resolver(verifier, n(65_536))?
            .resolve(raw, end)
            .await?,
    ))
}
async fn local(store: &PostgresControlStore, raw: Option<&str>) -> Result<Value, Error> {
    Ok(wire(
        store
            .local_hub_access_resolver("explicit-audience", n(8192), n(65_536))?
            .resolve(raw, deadline())
            .await?,
    ))
}
async fn observe_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='hub_owner' AND wait_event_type='Lock' AND query LIKE '%resource_acl_state%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(Instant::now() < end, "resolver reaches actual ACL SQL lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn seed_local(c: &mut PgConnection) {
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','current-name','current-email','current-org','[\"current-team\"]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','Automation','[]',1,0,1,0,0)").await.unwrap();
    for (raw, id, kind, token_kind, subject) in [
        (
            RAW,
            "hub-access",
            "access",
            TokenKind::LocalAccess,
            "alice-subject",
        ),
        (
            SERVICE,
            "hub-service",
            "service",
            TokenKind::ServiceCredential,
            "bot-subject",
        ),
    ] {
        let digest = support::digester()
            .token(token_kind, raw.as_bytes())
            .unwrap();
        let principal = json!({"issuer":"local","subject":subject,"username":"stale-name","auth_method":"local-token","organization":"stale-org","teams":["stale-team"],"local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'pseudonymous-other',$5,'explicit-client','explicit-audience','','[]',1,'',0,$6,0)").bind(digest.to_sql_hex()).bind(id).bind(kind).bind(subject).bind(principal).bind(micros()+600_000_000).execute(&mut *c).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "real PostgreSQL TLS, native Ed25519 and opaque SQL Hub authorization"]
async fn postgres_hub_access_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE hub_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION hub_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO hub_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let is_super: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='hub_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!is_super);
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier(Some(RESOURCE)));
    let token = signer.sign(&signer.claims());
    seed_local(&mut c).await;

    // C1: anonymous is an explicit variant, never an attribute-shaped fake user.
    for (kind, principal) in [
        ("authenticated", ""),
        ("user", "anonymous"),
        ("team", "anonymous"),
        ("organization", "anonymous"),
        ("subject", "anonymous|anonymous"),
    ] {
        clear(&mut c).await;
        grant(&mut c, "one", kind, principal, &["hub"], &[]).await;
        assert_eq!(
            native(&store, &verifier, None, deadline()).await.unwrap()["selectors"],
            json!([])
        );
        assert_eq!(local(&store, None).await.unwrap()["selectors"], json!([]));
    }
    clear(&mut c).await;
    grant(&mut c, "z-global", " GLOBAL ", "", &["h*"], &[A]).await;
    grant(&mut c, "a-anonymous", "anonymous", "", &["hub"], &[B]).await;
    let anonymous = native(&store, &verifier, None, deadline()).await.unwrap();
    assert_eq!(anonymous["subject"], "anonymous|anonymous");
    assert_eq!(anonymous["selectors"], json!([{"id":B},{"id":A}]));
    assert_eq!(local(&store, None).await.unwrap(), anonymous);
    let mut named = signer.claims();
    named["preferred_username"] = json!("anonymous");
    assert_eq!(
        native(&store, &verifier, Some(&signer.sign(&named)), deadline())
            .await
            .unwrap()["selectors"],
        json!([{"id":A}])
    );
    clear(&mut c).await;
    grant(&mut c, "auth", "authenticated", "", &["hub"], &[]).await;
    assert_eq!(
        native(&store, &verifier, Some(&signer.sign(&named)), deadline())
            .await
            .unwrap()["selectors"],
        json!([{"all":true}])
    );

    // C2: wildcards are literal principal data; capability globs remain supported.
    for (kind, field, literal) in [
        ("user", "preferred_username", "a*?[]"),
        ("organization", "organization", "o*?[]"),
        ("team", "groups", "t*?[]"),
    ] {
        clear(&mut c).await;
        grant(&mut c, "literal", kind, literal, &["h?b"], &[A]).await;
        assert_eq!(
            native(&store, &verifier, Some(&token), deadline())
                .await
                .unwrap()["selectors"],
            json!([])
        );
        let mut exact = signer.claims();
        exact[field] = if field == "groups" {
            json!([literal])
        } else {
            json!(literal)
        };
        assert_eq!(
            native(&store, &verifier, Some(&signer.sign(&exact)), deadline())
                .await
                .unwrap()["selectors"],
            json!([{"id":A}])
        );
        exact[field] = if field == "groups" {
            json!([literal.to_uppercase()])
        } else {
            json!(literal.to_uppercase())
        };
        assert_eq!(
            native(&store, &verifier, Some(&signer.sign(&exact)), deadline())
                .await
                .unwrap()["selectors"],
            json!([])
        );
    }
    for subject in ["hub-subject".to_string(), format!("{ISSUER}|hub-subject")] {
        clear(&mut c).await;
        grant(&mut c, "subject", "subject", &subject, &["hub"], &[A]).await;
        assert_eq!(
            native(&store, &verifier, Some(&token), deadline())
                .await
                .unwrap()["selectors"],
            json!([{"id":A}])
        );
    }
    clear(&mut c).await;
    grant(&mut c, "missing-user", "user", "", &["hub"], &[A]).await;
    grant(&mut c, "missing-org", "organization", "", &["hub"], &[A]).await;
    let mut missing = signer.claims();
    missing
        .as_object_mut()
        .unwrap()
        .remove("preferred_username");
    missing.as_object_mut().unwrap().remove("organization");
    assert_eq!(
        native(&store, &verifier, Some(&signer.sign(&missing)), deadline())
            .await
            .unwrap()["selectors"],
        json!([])
    );
    clear(&mut c).await;
    grant(&mut c, "project", "global", "", &["project:*"], &[]).await;
    let mut scopes = signer.claims();
    scopes["scope"] = json!("hub project-sdk admin");
    assert_eq!(
        native(&store, &verifier, Some(&signer.sign(&scopes)), deadline())
            .await
            .unwrap()["selectors"],
        json!([])
    );

    for (kind, principal) in [
        ("user", "alice"),
        ("organization", "current-org"),
        ("team", "current-team"),
        ("subject", "alice-subject"),
        ("subject", "local|alice-subject"),
    ] {
        clear(&mut c).await;
        grant(&mut c, "current", kind, principal, &["hub"], &[A]).await;
        let access = local(&store, Some(RAW)).await.unwrap();
        assert_eq!(access["subject"], "local|alice-subject");
        assert_eq!(access["selectors"], json!([{"id":A}]));
    }
    clear(&mut c).await;
    grant(&mut c, "stale", "team", "stale-team", &["hub"], &[]).await;
    assert_eq!(
        local(&store, Some(RAW)).await.unwrap()["selectors"],
        json!([])
    );
    clear(&mut c).await;
    grant(&mut c, "bot", "user", "bot", &["hub"], &[B]).await;
    let service = local(&store, Some(SERVICE)).await.unwrap();
    assert_eq!(service["subject"], "local|bot-subject");
    assert_eq!(service["selectors"], json!([{"id":B}]));

    clear(&mut c).await;
    grant(&mut c, "global", "global", "", &["hub"], &[]).await;
    assert!(matches!(
        native(&store, &verifier, Some(""), deadline()).await,
        Err(Error::Authentication(_))
    ));
    assert!(matches!(
        native(&store, &verifier, Some(RAW), deadline()).await,
        Err(Error::Authentication(_))
    ));
    let unauth = Error::LocalAuthentication(LocalBearerVerificationError::Unauthenticated);
    for raw in ["", "gb_at_missing", &token] {
        assert_eq!(local(&store, Some(raw)).await.unwrap_err(), unauth);
    }
    for (field, value) in [
        ("aud", json!(["wrong", RESOURCE])),
        ("aud", json!(["hub-api", "wrong"])),
        ("token_use", json!("id")),
        ("client_id", json!("")),
        ("iss", json!("https://other.test")),
    ] {
        let mut bad = signer.claims();
        bad[field] = value;
        assert_eq!(
            native(&store, &verifier, Some(&signer.sign(&bad)), deadline())
                .await
                .unwrap_err(),
            Error::Authentication(BrokerAccessError::InvalidToken)
        );
    }
    assert_eq!(
        native(
            &store,
            &verifier,
            Some(&Signer::new().sign(&signer.claims())),
            deadline()
        )
        .await
        .unwrap_err(),
        Error::Authentication(BrokerAccessError::InvalidToken)
    );
    let mut expired = signer.claims();
    expired["iat"] = json!(seconds() - 3);
    expired["exp"] = json!(seconds() - 1);
    assert_eq!(
        native(&store, &verifier, Some(&signer.sign(&expired)), deadline())
            .await
            .unwrap_err(),
        Error::Authentication(BrokerAccessError::Expired)
    );
    let no_resource = signer.verifier(None);
    let mut api_only = signer.claims();
    api_only["aud"] = json!("hub-api");
    assert_eq!(
        native(
            &store,
            &no_resource,
            Some(&signer.sign(&api_only)),
            deadline()
        )
        .await
        .unwrap()["selectors"],
        json!([{"all":true}])
    );
    for sql in [
        "UPDATE public.local_tokens SET revoked_at=0 WHERE token_id='hub-access'",
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_tokens SET audience='wrong' WHERE token_id='hub-access'",
        "UPDATE public.local_tokens SET expires_at=0 WHERE token_id='hub-access'",
    ] {
        c.execute(sql).await.unwrap();
        assert_eq!(local(&store, Some(RAW)).await.unwrap_err(), unauth);
        c.execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'; UPDATE public.local_tokens SET revoked_at=NULL,audience='explicit-audience' WHERE token_id='hub-access'").await.unwrap();
        sqlx_core::query::query(
            "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='hub-access'",
        )
        .bind(micros() + 600_000_000)
        .execute(&mut c)
        .await
        .unwrap();
    }

    // C3: SQL C order, trimmed IDs, first complete selector and IDs alongside all.
    clear(&mut c).await;
    grant(&mut c, "z", "authenticated", "", &["hub"], &[A, B]).await;
    grant(&mut c, "b", "global", "", &["*"], &[]).await;
    grant(
        &mut c,
        "a",
        "global",
        "",
        &["hub"],
        &[B, &format!(" {A} "), "*"],
    )
    .await;
    let ordered = native(&store, &verifier, Some(&token), deadline())
        .await
        .unwrap();
    assert_eq!(
        ordered["selectors"],
        json!([{"id":A},{"all":true},{"id":B}])
    );
    assert_eq!(ordered["subject"], format!("{ISSUER}|hub-subject"));
    clear(&mut c).await;
    assert_eq!(
        native(&store, &verifier, Some(&token), deadline())
            .await
            .unwrap()["selectors"],
        json!([])
    );

    // C4: a committed revision/removal is visible on the next observation.
    grant(&mut c, "current", "global", "", &["hub"], &[A]).await;
    let before = native(&store, &verifier, None, deadline()).await.unwrap();
    let mut writer = f.connection().await;
    let mut tx = writer.begin().await.unwrap();
    tx.execute("DELETE FROM public.resource_grants; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    assert_eq!(
        native(&store, &verifier, None, deadline()).await.unwrap(),
        before
    );
    tx.commit().await.unwrap();
    let after = native(&store, &verifier, None, deadline()).await.unwrap();
    assert_ne!(
        after["authorization_revision"],
        before["authorization_revision"]
    );
    assert_eq!(after["selectors"], json!([]));
    writer.close().await.unwrap();
    for (kind, caps, projects) in [
        ("unknown", vec!["hub"], vec![A]),
        ("user", vec!["["], vec![A]),
        ("user", vec![], vec![A]),
        ("user", vec!["hub"], vec!["bad-project"]),
    ] {
        clear(&mut c).await;
        grant(&mut c, "good", "global", "", &["hub"], &[]).await;
        grant(&mut c, "invalid", kind, "nobody", &caps, &projects).await;
        assert_eq!(
            native(&store, &verifier, None, deadline())
                .await
                .unwrap_err(),
            Error::InvalidPolicy
        );
    }
    clear(&mut c).await;
    grant(&mut c, "global", "global", "", &["hub"], &[]).await;
    assert_eq!(
        store
            .broker_hub_access_resolver(&verifier, n(1))
            .unwrap()
            .resolve(None, deadline())
            .await
            .unwrap_err(),
        Error::Grants(ResourceGrantReadError::ReadLimitExceeded)
    );
    c.execute("DELETE FROM public.resource_acl_state")
        .await
        .unwrap();
    assert_eq!(
        native(&store, &verifier, None, deadline())
            .await
            .unwrap_err(),
        Error::Grants(ResourceGrantReadError::MalformedStored)
    );
    c.execute("INSERT INTO public.resource_acl_state(id,revision,updated_at) VALUES(1,99,0); REVOKE SELECT ON public.resource_grants FROM hub_owner").await.unwrap();
    assert_eq!(
        native(&store, &verifier, None, deadline())
            .await
            .unwrap_err(),
        Error::Grants(ResourceGrantReadError::Control(ControlError::Storage))
    );
    c.execute("GRANT SELECT ON public.resource_grants TO hub_owner")
        .await
        .unwrap();
    assert_eq!(
        native(&store, &verifier, None, deadline()).await.unwrap()["authorization_revision"],
        "99"
    );

    // C5: expiry/deadline across an actual lock and abort drop recover the pool.
    let mut short = signer.claims();
    short["exp"] = json!(seconds() + 3);
    let short = signer.sign(&short);
    let mut lock = c.begin().await.unwrap();
    lock.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let task = {
        let store = store.clone();
        let verifier = verifier.clone();
        tokio::spawn(async move { native(&store, &verifier, Some(&short), deadline()).await })
    };
    let mut observer = f.connection().await;
    observe_lock(&mut observer).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    lock.rollback().await.unwrap();
    assert_eq!(
        task.await.unwrap().unwrap_err(),
        Error::Authentication(BrokerAccessError::Expired)
    );
    let mut lock = c.begin().await.unwrap();
    lock.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let task = {
        let store = store.clone();
        let verifier = verifier.clone();
        tokio::spawn(async move {
            native(
                &store,
                &verifier,
                None,
                Instant::now() + Duration::from_secs(1),
            )
            .await
        })
    };
    observe_lock(&mut observer).await;
    assert_eq!(
        task.await.unwrap().unwrap_err(),
        Error::Grants(ResourceGrantReadError::Control(ControlError::Deadline))
    );
    lock.rollback().await.unwrap();
    assert_eq!(
        native(&store, &verifier, None, deadline()).await.unwrap()["selectors"],
        json!([{"all":true}])
    );
    let mut lock = c.begin().await.unwrap();
    lock.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let task = {
        let store = store.clone();
        let verifier = verifier.clone();
        tokio::spawn(async move { native(&store, &verifier, None, deadline()).await })
    };
    observe_lock(&mut observer).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    for _ in 0..3 {
        assert_eq!(
            native(&store, &verifier, None, deadline()).await.unwrap()["selectors"],
            json!([{"all":true}])
        );
    }
    observer.close().await.unwrap();
    clear(&mut c).await;
    let mut retained = store
        .broker_hub_access_resolver(&verifier, n(65_536))
        .unwrap()
        .resolve(None, Instant::now() + Duration::from_millis(200))
        .await
        .unwrap();
    assert!(retained.selectors().is_empty());
    tokio::time::sleep(Duration::from_millis(210)).await;
    assert_eq!(
        retained.check().unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    let mut short = signer.claims();
    short["exp"] = json!(seconds() + 2);
    let short = signer.sign(&short);
    let mut retained = store
        .broker_hub_access_resolver(&verifier, n(65_536))
        .unwrap()
        .resolve(Some(&short), deadline())
        .await
        .unwrap();
    assert!(retained.selectors().is_empty());
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        retained.check().unwrap_err(),
        Error::Authentication(BrokerAccessError::Expired)
    );
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='hub-access'",
    )
    .bind(micros() + 500_000)
    .execute(&mut c)
    .await
    .unwrap();
    let mut retained = store
        .local_hub_access_resolver("explicit-audience", n(8192), n(65_536))
        .unwrap()
        .resolve(Some(RAW), deadline())
        .await
        .unwrap();
    assert!(retained.selectors().is_empty());
    tokio::time::sleep(Duration::from_millis(510)).await;
    assert_eq!(retained.check().unwrap_err(), unauth);
    assert_eq!(
        native(&store, &verifier, None, Instant::now())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    store.shutdown(deadline()).await.unwrap();
    assert!(matches!(
        native(&store, &verifier, None, deadline()).await,
        Err(Error::Grants(ResourceGrantReadError::Control(
            ControlError::Closed
        )))
    ));
    c.close().await.unwrap();
    f.shutdown().unwrap();
}
