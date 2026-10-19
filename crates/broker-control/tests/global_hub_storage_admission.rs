// The shared fixture also serves native suites with different SQL contracts.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    AuthorizedStorageGrant, BrokerAccessError, BrokerAccessVerifier, ConnectionLimits,
    ControlError, LocalBearerVerificationError, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint, ResourceGrantReadError, StorageAdmissionError as Error,
    StorageModule, StorageOperation, StorageScope,
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
    fn verifier(&self, issuer: &str) -> BrokerAccessVerifier {
        BrokerAccessVerifier::new(issuer, "hub-api", Some(RESOURCE), &self.keys, n(8192)).unwrap()
    }
    fn claims(&self, issuer: &str, subject: &str) -> Value {
        let now = seconds();
        json!({"iss":issuer,"sub":subject,"aud":["hub-api",RESOURCE],"iat":now-1,"exp":now+600,"token_use":"access","client_id":"explicit-client","jti":"hub-token","scope":"","preferred_username":"alice","organization":"engineering","groups":["dev"],"roles":["admin"]})
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

struct Rule<'a> {
    kind: &'a str,
    principal: &'a str,
    caps: &'a [&'a str],
    projects: &'a [&'a str],
    operations: &'a [&'a str],
    prefixes: &'a [&'a str],
    route: &'a str,
}
fn full() -> Rule<'static> {
    Rule {
        kind: "authenticated",
        principal: "",
        caps: &["hub", "s3"],
        projects: &[],
        operations: &[],
        prefixes: &[],
        route: "",
    }
}
async fn grant(c: &mut PgConnection, id: &str, r: &Rule<'_>) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture',$2,$3,$4,0,0)")
        .bind(id).bind(r.kind).bind(r.principal).bind(r.route).execute(&mut *c).await.unwrap();
    for (query, values) in [
        (
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
            r.caps,
        ),
        (
            "INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)",
            r.projects,
        ),
        (
            "INSERT INTO public.grant_s3_operations(grant_id,value) VALUES($1,$2)",
            r.operations,
        ),
        (
            "INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES($1,$2)",
            r.prefixes,
        ),
    ] {
        for value in values {
            sqlx_core::query::query(query)
                .bind(id)
                .bind(*value)
                .execute(&mut *c)
                .await
                .unwrap();
        }
    }
}
#[derive(Debug)]
struct Observation {
    project: Option<String>,
    installation: Option<String>,
    module: StorageModule,
    route: String,
    revision: i64,
    subject: String,
    access: [Vec<String>; 4],
    end: Instant,
}
fn observe(g: AuthorizedStorageGrant<'_>) -> Observation {
    g.check().unwrap();
    assert_eq!(format!("{g:?}"), "AuthorizedStorageGrant([REDACTED])");
    Observation {
        project: g.scope().project_id().map(str::to_owned),
        installation: g.scope().installation_id().map(str::to_owned),
        module: g.scope().module(),
        route: g.route().into(),
        revision: g.revision(),
        subject: g.canonical_subject(),
        end: g.request_deadline(),
        access: [
            StorageOperation::Read,
            StorageOperation::Write,
            StorageOperation::Publish,
            StorageOperation::Delete,
        ]
        .map(|op| g.prefixes(op).to_vec()),
    }
}
async fn native(
    s: &PostgresControlStore,
    v: &BrokerAccessVerifier,
    raw: &str,
    scope: &StorageScope,
    end: Instant,
) -> Result<Observation, Error> {
    let factory = s.broker_storage_authorizer(v, n(65_536), "explicit-default")?;
    Ok(observe(factory.authorize(raw, &[], scope, end).await?))
}
async fn local(
    s: &PostgresControlStore,
    raw: &str,
    scope: &StorageScope,
    end: Instant,
) -> Result<Observation, Error> {
    let factory =
        s.local_storage_authorizer("explicit-audience", n(8192), n(65_536), "explicit-default")?;
    Ok(observe(factory.authorize(raw, &[], scope, end).await?))
}

const ROOTS: [&str; 2] = ["v1/hub/global/registry", "v1/hub/global/rules"];
#[test]
fn global_scope_is_data_without_project_or_installation_alias() {
    let scope = StorageScope::global_hub();
    assert_eq!(scope.project_id(), None);
    assert_eq!(scope.installation_id(), None);
    assert_eq!(scope.module(), StorageModule::Hub);
    assert_eq!(format!("{scope:?}"), "StorageScope([REDACTED])");
    assert!(matches!(
        StorageScope::project("global", StorageModule::Hub),
        Err(Error::InvalidScope)
    ));
    assert_ne!(scope, StorageScope::project(A, StorageModule::Hub).unwrap());
    assert_ne!(scope, StorageScope::user_memory("Install-A").unwrap());
}
fn global_observation(g: &Observation, end: Instant, expected: &[&str]) {
    assert_eq!(g.project, None);
    assert_eq!(g.installation, None);
    assert_eq!(g.module, StorageModule::Hub);
    // The existing authorizer keeps the earlier Original/configured-operation bound.
    assert!(g.end <= end);
    assert!(g.end > Instant::now());
    assert!(g.revision > 0);
    let expected = expected.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
    for prefixes in &g.access {
        assert_eq!(*prefixes, expected);
    }
}
#[tokio::test]
#[ignore = "actual PostgreSQL TLS NOSUPERUSER, Native EdDSA/current opaque identity and nonPROJECT Hub/S3 global authority"]
async fn global_hub_storage_admission_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE hub_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner';DROP SCHEMA public CASCADE;CREATE SCHEMA public AUTHORIZATION hub_owner;GRANT CONNECT,TEMP ON DATABASE postgres TO hub_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    assert!(
        !sqlx_core::query_scalar::query_scalar::<_, bool>(
            "SELECT rolsuper FROM pg_roles WHERE rolname='hub_owner'"
        )
        .fetch_one(&mut c)
        .await
        .unwrap()
    );
    seed_local(&mut c).await;
    let signer = Signer::new();
    let verifier = signer.verifier(ISSUER);
    let claims = signer.claims(ISSUER, "owner-a");
    let token = Zeroizing::new(signer.sign(&claims));
    let scope = StorageScope::global_hub();
    for projects in [&[][..], &["*"][..]] {
        clear(&mut c).await;
        let mut rule = full();
        rule.projects = projects;
        grant(&mut c, "same-rule", &rule).await;
        let end = deadline();
        let seen = native(&store, &verifier, &token, &scope, end)
            .await
            .unwrap();
        global_observation(&seen, end, &ROOTS);
        assert_eq!(seen.route, "explicit-default");
        assert_eq!(seen.subject, format!("{ISSUER}|owner-a"));
        for (raw, subject) in [(RAW, "alice-subject"), (SERVICE, "bot-subject")] {
            let end = deadline();
            let seen = local(&store, raw, &scope, end).await.unwrap();
            global_observation(&seen, end, &ROOTS);
            assert_eq!(seen.subject, format!("local|{subject}"));
        }
        clear(&mut c).await;
        let mut hub = full();
        hub.caps = &["hub"];
        hub.projects = projects;
        hub.route = "noncontributing-other";
        grant(&mut c, "hub", &hub).await;
        let mut s3 = full();
        s3.caps = &["s3"];
        s3.projects = projects;
        s3.route = "primary";
        s3.prefixes = &["v1/hub"];
        grant(&mut c, "s3", &s3).await;
        let end = deadline();
        let seen = native(&store, &verifier, &token, &scope, end)
            .await
            .unwrap();
        global_observation(&seen, end, &ROOTS);
        assert_eq!(seen.route, "primary");
        for raw in [RAW, SERVICE] {
            let end = deadline();
            global_observation(&local(&store, raw, &scope, end).await.unwrap(), end, &ROOTS);
        }
    }
    // Literal Hub capability uses the existing compiled matcher, including SDK glob patterns whose compiled regex actually matches.
    for caps in [&["hub*", "s3"][..], &["*"][..]] {
        clear(&mut c).await;
        let mut rule = full();
        rule.caps = caps;
        grant(&mut c, "matching-regex", &rule).await;
        let end = deadline();
        global_observation(
            &native(&store, &verifier, &token, &scope, end)
                .await
                .unwrap(),
            end,
            &ROOTS,
        );
    }
    for caps in [
        &["hub"][..],
        &["s3"][..],
        &["hub:admin", "s3"][..],
        &["hub.*admin", "s3"][..],
    ] {
        clear(&mut c).await;
        let mut rule = full();
        rule.caps = caps;
        grant(&mut c, "incomplete", &rule).await;
        assert!(matches!(
            native(&store, &verifier, &token, &scope, deadline()).await,
            Err(Error::Forbidden)
        ));
        for raw in [RAW, SERVICE] {
            assert!(matches!(
                local(&store, raw, &scope, deadline()).await,
                Err(Error::Forbidden)
            ));
        }
    }
    for (hub_projects, s3_projects) in [
        (&[A][..], &[A][..]),
        (&[A][..], &[][..]),
        (&[][..], &[A][..]),
    ] {
        clear(&mut c).await;
        let mut hub = full();
        hub.caps = &["hub"];
        hub.projects = hub_projects;
        grant(&mut c, "hub", &hub).await;
        let mut s3 = full();
        s3.caps = &["s3"];
        s3.projects = s3_projects;
        grant(&mut c, "s3", &s3).await;
        assert!(matches!(
            native(&store, &verifier, &token, &scope, deadline()).await,
            Err(Error::Forbidden)
        ));
    }
    // Another principal's Hub capability cannot combine with this caller's S3 grant.
    clear(&mut c).await;
    let mut hub = full();
    hub.caps = &["hub"];
    hub.kind = "user";
    hub.principal = "unrelated-user";
    grant(&mut c, "hub", &hub).await;
    let mut s3 = full();
    s3.caps = &["s3"];
    grant(&mut c, "s3", &s3).await;
    for raw in [RAW, SERVICE] {
        assert!(matches!(
            local(&store, raw, &scope, deadline()).await,
            Err(Error::Forbidden)
        ));
    }
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::Forbidden)
    ));
    clear(&mut c).await;
    hub.principal = "alice";
    grant(&mut c, "hub", &hub).await;
    grant(&mut c, "s3", &s3).await;
    let end = deadline();
    global_observation(
        &native(&store, &verifier, &token, &scope, end)
            .await
            .unwrap(),
        end,
        &ROOTS,
    );
    let end = deadline();
    global_observation(&local(&store, RAW, &scope, end).await.unwrap(), end, &ROOTS);
    assert!(matches!(
        local(&store, SERVICE, &scope, deadline()).await,
        Err(Error::Forbidden)
    ));
    for prefixes in [
        &["v1"][..],
        &["v1/hub"][..],
        &["v1/hub/global"][..],
        &ROOTS[..],
    ] {
        clear(&mut c).await;
        let mut rule = full();
        rule.prefixes = prefixes;
        grant(&mut c, "bounded", &rule).await;
        let end = deadline();
        global_observation(
            &native(&store, &verifier, &token, &scope, end)
                .await
                .unwrap(),
            end,
            &ROOTS,
        );
    }
    for prefix in ["v1/hub/global/registry/child", "v1/hub/global/rules/child"] {
        clear(&mut c).await;
        let mut rule = full();
        let prefixes = [prefix];
        rule.prefixes = &prefixes;
        grant(&mut c, "descendant", &rule).await;
        let end = deadline();
        global_observation(
            &native(&store, &verifier, &token, &scope, end)
                .await
                .unwrap(),
            end,
            &[prefix],
        );
    }
    for prefix in [
        "v1/hub/global/registry2",
        "v1/hub/global/rules-sibling",
        "v1/hub/global/artifacts",
        "v1/hub/global/metadata",
        "v1/projects/{project}",
        "v1/projects/01D39ZY06FGSCTVN4T2V9PKHFZ/registry",
        "v1/installations/Install-A/users/hash/corpora/memory",
    ] {
        clear(&mut c).await;
        let mut rule = full();
        let prefixes = [prefix];
        rule.prefixes = &prefixes;
        grant(&mut c, "foreign", &rule).await;
        assert!(matches!(
            native(&store, &verifier, &token, &scope, deadline()).await,
            Err(Error::Forbidden)
        ));
    }
    let operations = [
        StorageOperation::Read,
        StorageOperation::Write,
        StorageOperation::Publish,
        StorageOperation::Delete,
    ];
    for (i, name) in ["read", "write", "publish", "delete"]
        .into_iter()
        .enumerate()
    {
        clear(&mut c).await;
        let mut rule = full();
        let cap = format!("s3:{name}");
        let capabilities = ["hub", cap.as_str()];
        rule.caps = &capabilities;
        rule.prefixes = &[ROOTS[0]];
        grant(&mut c, "op", &rule).await;
        let seen = native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap();
        for (j, _) in operations.iter().enumerate() {
            assert_eq!(
                seen.access[j],
                if i == j {
                    vec![ROOTS[0].to_owned()]
                } else {
                    vec![]
                }
            );
        }
        for raw in [RAW, SERVICE] {
            let seen = local(&store, raw, &scope, deadline()).await.unwrap();
            for j in 0..4 {
                assert_eq!(
                    seen.access[j],
                    if i == j {
                        vec![ROOTS[0].to_owned()]
                    } else {
                        vec![]
                    }
                );
            }
        }
        clear(&mut c).await;
        let mut rule = full();
        let mask = [name];
        rule.operations = &mask;
        grant(&mut c, "op-mask", &rule).await;
        let seen = native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap();
        for j in 0..4 {
            assert_eq!(
                seen.access[j],
                if i == j {
                    ROOTS.map(str::to_owned).to_vec()
                } else {
                    vec![]
                }
            );
        }
    }
    clear(&mut c).await;
    let mut rule = full();
    rule.caps = &["hub", "s3:read"];
    rule.operations = &["delete"];
    grant(&mut c, "mask-intersection", &rule).await;
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::Forbidden)
    ));
    clear(&mut c).await;
    let mut rule = full();
    rule.route = "primary";
    grant(&mut c, "actual", &rule).await;
    let mut noncontributing = full();
    noncontributing.prefixes = &["v1/projects/{project}"];
    noncontributing.route = "other";
    grant(&mut c, "no-project", &noncontributing).await;
    assert_eq!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap()
            .route,
        "primary"
    );
    let mut conflict = full();
    conflict.route = "other";
    conflict.prefixes = &[ROOTS[1]];
    grant(&mut c, "conflict", &conflict).await;
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::ConflictingRoutes)
    ));
    for (caps, ops, prefix) in [
        (&["hub"][..], &[][..], "v1/{unknown}"),
        (&["["][..], &[][..], "v1"),
        (&["hub"][..], &["["][..], "v1"),
    ] {
        clear(&mut c).await;
        grant(&mut c, "good", &full()).await;
        let mut invalid = full();
        invalid.projects = &[A];
        invalid.caps = caps;
        invalid.operations = ops;
        let prefixes = [prefix];
        invalid.prefixes = &prefixes;
        grant(&mut c, "invalid-irrelevant", &invalid).await;
        assert!(matches!(
            native(&store, &verifier, &token, &scope, deadline()).await,
            Err(Error::InvalidPolicy)
        ));
    }
    clear(&mut c).await;
    grant(&mut c, "current", &full()).await;
    let old = native(&store, &verifier, &token, &scope, deadline())
        .await
        .unwrap()
        .revision;
    clear(&mut c).await;
    let mut only_s3 = full();
    only_s3.caps = &["s3"];
    grant(&mut c, "withdrawn-hub", &only_s3).await;
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::Forbidden)
    ));
    clear(&mut c).await;
    grant(&mut c, "restored", &full()).await;
    assert!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap()
            .revision
            > old
    );
    c.execute("UPDATE public.local_users SET name='changed',organization='changed' WHERE username='alice'").await.unwrap();
    let seen = local(&store, RAW, &scope, deadline()).await.unwrap();
    assert_eq!(seen.subject, "local|alice-subject");
    c.execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
        .await
        .unwrap();
    assert!(matches!(
        local(&store, RAW, &scope, deadline()).await,
        Err(Error::Local(LocalBearerVerificationError::Unauthenticated))
    ));
    c.execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'")
        .await
        .unwrap();
    local(&store, RAW, &scope, deadline()).await.unwrap();
    assert!(matches!(
        local(&store, &token, &scope, deadline()).await,
        Err(Error::Local(LocalBearerVerificationError::Unauthenticated))
    ));
    assert!(matches!(
        native(&store, &verifier, RAW, &scope, deadline()).await,
        Err(Error::Native(BrokerAccessError::InvalidToken))
    ));
    let factory = store
        .broker_storage_authorizer(&verifier, n(65536), "explicit-default")
        .unwrap();
    let foreign = store
        .broker_storage_authorizer(&verifier, n(65536), "explicit-default")
        .unwrap();
    let caller = factory.authenticate(&token, &[], deadline()).unwrap();
    assert!(matches!(
        foreign.authorize_authenticated(caller, &scope).await,
        Err(Error::InvalidConfiguration)
    ));
    let mut expired = claims.clone();
    expired["iat"] = json!(seconds() - 10);
    expired["exp"] = json!(seconds() - 1);
    assert!(matches!(
        native(
            &store,
            &verifier,
            &signer.sign(&expired),
            &scope,
            deadline()
        )
        .await,
        Err(Error::Native(BrokerAccessError::Expired))
    ));
    assert!(matches!(
        native(
            &store,
            &verifier,
            &token,
            &scope,
            Instant::now() - Duration::from_millis(1)
        )
        .await,
        Err(Error::Control(ControlError::Deadline))
    ));
    let end = Instant::now() + Duration::from_millis(500);
    let grant = factory.authorize(&token, &[], &scope, end).await.unwrap();
    assert_eq!(grant.request_deadline(), end);
    tokio::time::sleep(Duration::from_millis(550)).await;
    assert!(matches!(grant.check(), Err(Error::Deadline)));
    drop(grant);
    c.execute("ALTER TABLE public.resource_acl_state OWNER TO postgres;REVOKE SELECT ON public.resource_acl_state FROM hub_owner").await.unwrap();
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::Grants(ResourceGrantReadError::Control(
            ControlError::Storage
        )))
    ));
    for raw in [RAW, SERVICE] {
        assert!(matches!(
            local(&store, raw, &scope, deadline()).await,
            Err(Error::Grants(ResourceGrantReadError::Control(
                ControlError::Storage
            )))
        ));
    }
    c.execute("GRANT SELECT ON public.resource_acl_state TO hub_owner")
        .await
        .unwrap();
    native(&store, &verifier, &token, &scope, deadline())
        .await
        .unwrap();
    for raw in [RAW, SERVICE] {
        local(&store, raw, &scope, deadline()).await.unwrap();
    }
    store.shutdown(deadline()).await.unwrap();
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::Grants(ResourceGrantReadError::Control(
            ControlError::Closed
        )))
    ));
    c.close().await.unwrap();
    f.shutdown().unwrap();
}
