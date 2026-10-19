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
        caps: &["s3"],
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

// Literal constants independently calculated from the qualified Core byte contract.
const VECTORS: [(&str, &str, &str); 10] = [
    (
        "https://broker.example.test",
        "owner-a",
        "fdc11204e30a927483f5d21d1ad52d8563e9ac582700dbb2de3c06c1ade91c42",
    ),
    (
        "https://broker.example.test",
        "owner-b",
        "e51129d17142a757b6449252cfb0524f03c41562251865380f74980b4e105bd6",
    ),
    (
        "https://BROKER.example.test",
        "owner-a",
        "7ddb17a5743b7310739ac4b4e9eb9b4ecb4a733b95efa884ddd7ba94eaaa39bc",
    ),
    (
        "https://broker.example.test/ü%2f",
        "é|ø",
        "731b2e0ab936afbb71a7a09fb109055aa339d63759f0a85f156b30771426718f",
    ),
    (
        "https://issuer.example/a",
        "bc",
        "8a3871b4c0ca212a3aa5b1f1c0606431151e013ad7504d2e958f50f49b763a8e",
    ),
    (
        "https://issuer.example/ab",
        "c",
        "a4471fcf14a288a3345523b43ac4c2b0a697a5cc7a1705948fab2eb8f59cfe85",
    ),
    (
        "https://issuer.example/a|b",
        "c",
        "58679f4e5c9f68fd81bb948b7f08c10c677037b4a3227ddde1016927736dd33d",
    ),
    (
        "https://issuer.example/a",
        "b|c",
        "eb003f6ef8e4adf4028b3573fbfb7098f9561b8f78f956f129b3caf762518204",
    ),
    (
        "local",
        "alice-subject",
        "a45ba9da243389dc49b0b433d16a82cc431aab4e59469c74d4eb3c4466935adb",
    ),
    (
        "local",
        "bot-subject",
        "b64e062b9005ce3496a2e505f7ac7dc470f928f9dbed013e4a871f4c0e9db423",
    ),
];
fn root(installation: &str, key: &str) -> String {
    format!("v1/installations/{installation}/users/{key}/corpora/memory")
}

#[test]
fn canonical_user_scope_is_data_and_keeps_exact_installation() {
    for valid in ["a", "Install-A", "install_a.2", &"a".repeat(128)] {
        let scope = StorageScope::user_memory(valid).unwrap();
        assert_eq!(scope.installation_id(), Some(valid));
        assert_eq!(scope.project_id(), None);
        assert_eq!(scope.module(), StorageModule::Memory);
        assert_eq!(format!("{scope:?}"), "StorageScope([REDACTED])");
    }
    for invalid in [
        "",
        ".",
        "..",
        "-a",
        "_a",
        ".a",
        "a-",
        "a_",
        "a.",
        " a",
        "a ",
        "a/b",
        "a\\b",
        "a\0",
        "é",
        &"a".repeat(129),
    ] {
        assert!(matches!(
            StorageScope::user_memory(invalid),
            Err(Error::InvalidScope)
        ));
    }
    let project = StorageScope::project(A, StorageModule::Memory).unwrap();
    assert_eq!(project.project_id(), Some(A));
    assert_eq!(project.installation_id(), None);
    assert_ne!(
        StorageScope::user_memory("Install-A").unwrap(),
        StorageScope::user_memory("install-A").unwrap()
    );
}

#[tokio::test]
#[ignore = "actual PostgreSQL TLS NOSUPERUSER, real EdDSA/opaque proof, literal USER owner and current SQL ACL"]
async fn user_memory_storage_admission_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE hub_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION hub_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO hub_owner").await.unwrap();
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
    let token = Zeroizing::new(signer.sign(&signer.claims(ISSUER, "owner-a")));
    let scope = StorageScope::user_memory("install-A").unwrap();
    let own = root("install-A", VECTORS[0].2);
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT count(*) FROM public.broker_instances"
        )
        .fetch_one(&mut c)
        .await
        .unwrap(),
        0
    );
    clear(&mut c).await;
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::Forbidden)
    ));
    for projects in [&[][..], &["*"][..]] {
        clear(&mut c).await;
        grant(&mut c, "owner", &Rule { projects, ..full() }).await;
        for &(issuer, subject, expected) in &VECTORS[..8] {
            let verifier = signer.verifier(issuer);
            let signed = Zeroizing::new(signer.sign(&signer.claims(issuer, subject)));
            for installation in ["install-A", "install-B", "Install-A", &"a".repeat(128)] {
                let data = StorageScope::user_memory(installation).unwrap();
                let original = deadline();
                let admitted = native(&store, &verifier, &signed, &data, original)
                    .await
                    .unwrap();
                assert!(admitted.end <= original);
                assert_eq!(admitted.project, None);
                assert_eq!(admitted.installation.as_deref(), Some(installation));
                assert_eq!(admitted.module, StorageModule::Memory);
                assert!(admitted.revision > 0);
                assert_eq!(admitted.subject, format!("{issuer}|{subject}"));
                assert_eq!(admitted.route, "explicit-default");
                assert_eq!(
                    admitted.access,
                    std::array::from_fn(|_| vec![root(installation, expected)])
                );
            }
        }
        for (raw, expected, subject) in [
            (RAW, VECTORS[8].2, "alice-subject"),
            (SERVICE, VECTORS[9].2, "bot-subject"),
        ] {
            let original = deadline();
            let admitted = local(&store, raw, &scope, original).await.unwrap();
            assert!(admitted.end <= original);
            assert_eq!(admitted.project, None);
            assert_eq!(admitted.installation.as_deref(), Some("install-A"));
            assert_eq!(admitted.subject, format!("local|{subject}"));
            assert_eq!(
                admitted.access,
                std::array::from_fn(|_| vec![root("install-A", expected)])
            );
        }
    }
    // These literal pairs have the same old canonical-subject observer, but different USER keys.
    assert_eq!(
        format!("{}|{}", VECTORS[6].0, VECTORS[6].1),
        format!("{}|{}", VECTORS[7].0, VECTORS[7].1)
    );
    assert_ne!(VECTORS[6].2, VECTORS[7].2);
    assert_ne!(VECTORS[4].2, VECTORS[5].2);
    assert_ne!(VECTORS[0].2, VECTORS[1].2);
    assert_ne!(VECTORS[0].2, VECTORS[2].2);
    clear(&mut c).await;
    grant(
        &mut c,
        "project-only",
        &Rule {
            projects: &[A],
            ..full()
        },
    )
    .await;
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
    let project = StorageScope::project(A, StorageModule::Memory).unwrap();
    assert_eq!(
        native(&store, &verifier, &token, &project, deadline())
            .await
            .unwrap()
            .access,
        std::array::from_fn(|_| vec![format!("v1/projects/{A}/corpora/memory")])
    );
    // A PROJECT-dependent template contributes no operation, prefix or route to USER.
    clear(&mut c).await;
    grant(
        &mut c,
        "project-template",
        &Rule {
            prefixes: &["v1/projects/{project}/corpora/memory"],
            route: "unrelated",
            ..full()
        },
    )
    .await;
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::Forbidden)
    ));
    grant(
        &mut c,
        "user-template",
        &Rule {
            prefixes: &["v1/installations"],
            route: "owner-route",
            ..full()
        },
    )
    .await;
    let admitted = native(&store, &verifier, &token, &scope, deadline())
        .await
        .unwrap();
    assert_eq!(admitted.route, "owner-route");
    assert_eq!(admitted.access, std::array::from_fn(|_| vec![own.clone()]));
    // Absence and even lack of inventory SELECT do not create or restrict USER authority.
    c.execute("ALTER TABLE public.broker_instances OWNER TO postgres; REVOKE SELECT ON public.broker_instances FROM hub_owner; ALTER TABLE public.broker_instance_project_versions OWNER TO postgres; REVOKE SELECT ON public.broker_instance_project_versions FROM hub_owner").await.unwrap();
    native(&store, &verifier, &token, &scope, deadline())
        .await
        .unwrap();
    local(&store, RAW, &scope, deadline()).await.unwrap();
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT count(*) FROM public.broker_instances"
        )
        .fetch_one(&mut c)
        .await
        .unwrap(),
        0
    );
    for prefix in ["v1", "v1/installations", "v1/installations/install-A", &own] {
        clear(&mut c).await;
        grant(
            &mut c,
            "prefix",
            &Rule {
                prefixes: &[prefix],
                ..full()
            },
        )
        .await;
        assert_eq!(
            native(&store, &verifier, &token, &scope, deadline())
                .await
                .unwrap()
                .access,
            std::array::from_fn(|_| vec![own.clone()])
        );
    }
    let child = format!("{own}/nested/leaf");
    clear(&mut c).await;
    grant(
        &mut c,
        "descendant",
        &Rule {
            prefixes: &[&child],
            ..full()
        },
    )
    .await;
    assert_eq!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap()
            .access,
        std::array::from_fn(|_| vec![child.clone()])
    );
    for prefix in [
        root("install-B", VECTORS[0].2),
        root("Install-A", VECTORS[0].2),
        root("install-A", VECTORS[1].2),
        root("install-A", VECTORS[2].2),
        format!("{own}2"),
        format!("v1/projects/{A}/corpora/memory"),
        format!("v1/projects/{A}/artifacts"),
        "v1/hub/global/registry".into(),
    ] {
        clear(&mut c).await;
        grant(
            &mut c,
            "foreign",
            &Rule {
                prefixes: &[&prefix],
                ..full()
            },
        )
        .await;
        assert!(matches!(
            native(&store, &verifier, &token, &scope, deadline()).await,
            Err(Error::Forbidden)
        ));
    }
    for op in [
        StorageOperation::Read,
        StorageOperation::Write,
        StorageOperation::Publish,
        StorageOperation::Delete,
    ] {
        let name = match op {
            StorageOperation::Read => "read",
            StorageOperation::Write => "write",
            StorageOperation::Publish => "publish",
            StorageOperation::Delete => "delete",
        };
        clear(&mut c).await;
        grant(
            &mut c,
            "operation",
            &Rule {
                caps: &[&format!("s3:{name}")],
                prefixes: &["v1/installations"],
                ..full()
            },
        )
        .await;
        let admitted = native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap();
        for (index, candidate) in [
            StorageOperation::Read,
            StorageOperation::Write,
            StorageOperation::Publish,
            StorageOperation::Delete,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                admitted.access[index],
                if candidate == op {
                    vec![own.clone()]
                } else {
                    vec![]
                }
            );
        }
    }
    clear(&mut c).await;
    grant(
        &mut c,
        "operation-mask",
        &Rule {
            operations: &["read"],
            ..full()
        },
    )
    .await;
    let current = native(&store, &verifier, &token, &scope, deadline())
        .await
        .unwrap();
    assert_eq!(current.access, [vec![own.clone()], vec![], vec![], vec![]]);
    clear(&mut c).await;
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::Forbidden)
    ));
    grant(&mut c, "restored", &full()).await;
    let restored = native(&store, &verifier, &token, &scope, deadline())
        .await
        .unwrap();
    assert!(restored.revision > current.revision);
    assert_eq!(restored.access, std::array::from_fn(|_| vec![own.clone()]));
    // Policy compilation checks every rule before selecting this domain.
    grant(
        &mut c,
        "invalid",
        &Rule {
            projects: &[A],
            prefixes: &["v1/{unknown}"],
            ..full()
        },
    )
    .await;
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::InvalidPolicy)
    ));
    clear(&mut c).await;
    grant(
        &mut c,
        "no-owner-placeholder",
        &Rule {
            prefixes: &["v1/installations/{installation}"],
            ..full()
        },
    )
    .await;
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::InvalidPolicy)
    ));
    clear(&mut c).await;
    grant(
        &mut c,
        "one",
        &Rule {
            route: "one",
            ..full()
        },
    )
    .await;
    grant(
        &mut c,
        "two",
        &Rule {
            route: "two",
            ..full()
        },
    )
    .await;
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::ConflictingRoutes)
    ));
    clear(&mut c).await;
    grant(&mut c, "identity", &full()).await;
    let prior = local(&store, RAW, &scope, deadline()).await.unwrap();
    c.execute("UPDATE public.local_users SET name='new-display',organization='new-org',teams_json='[\"new-team\"]' WHERE username='alice'").await.unwrap();
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap().access,
        prior.access
    );
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
        native(&store, &verifier, RAW, &scope, deadline()).await,
        Err(Error::Native(_))
    ));
    assert!(matches!(
        local(&store, &token, &scope, deadline()).await,
        Err(Error::Local(LocalBearerVerificationError::Unauthenticated))
    ));
    let factory = store
        .broker_storage_authorizer(&verifier, n(65_536), "default")
        .unwrap();
    let other = store
        .broker_storage_authorizer(&verifier, n(65_536), "default")
        .unwrap();
    let caller = factory.authenticate(&token, &[], deadline()).unwrap();
    assert!(matches!(
        other.authorize_authenticated(caller, &scope).await,
        Err(Error::InvalidConfiguration)
    ));
    let original = deadline();
    let caller = factory.authenticate(&token, &[], original).unwrap();
    let admitted = factory
        .authorize_authenticated(caller, &scope)
        .await
        .unwrap();
    assert!(admitted.request_deadline() <= original);
    admitted.check().unwrap();
    drop(admitted);
    let mut expired = signer.claims(ISSUER, "owner-a");
    expired["iat"] = json!(seconds() - 10);
    expired["exp"] = json!(seconds() - 1);
    let expired = Zeroizing::new(signer.sign(&expired));
    assert!(matches!(
        native(&store, &verifier, &expired, &scope, deadline()).await,
        Err(Error::Native(BrokerAccessError::Expired))
    ));
    assert!(matches!(
        native(&store, &verifier, &token, &scope, Instant::now()).await,
        Err(Error::Control(ControlError::Deadline))
    ));
    c.execute("ALTER TABLE public.resource_acl_state OWNER TO postgres; REVOKE SELECT ON public.resource_acl_state FROM hub_owner").await.unwrap();
    for raw in [RAW, SERVICE] {
        assert!(matches!(
            local(&store, raw, &scope, deadline()).await,
            Err(Error::Grants(ResourceGrantReadError::Control(
                ControlError::Storage
            )))
        ));
    }
    assert!(matches!(
        native(&store, &verifier, &token, &scope, deadline()).await,
        Err(Error::Grants(ResourceGrantReadError::Control(
            ControlError::Storage
        )))
    ));
    c.execute("GRANT SELECT ON public.resource_acl_state TO hub_owner")
        .await
        .unwrap();
    assert_eq!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap()
            .access,
        std::array::from_fn(|_| vec![own.clone()])
    );
    let original = Instant::now() + Duration::from_millis(200);
    let caller = factory.authenticate(&token, &[], original).unwrap();
    let bounded = factory
        .authorize_authenticated(caller, &scope)
        .await
        .unwrap();
    assert!(bounded.request_deadline() <= original);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(matches!(bounded.check(), Err(Error::Deadline)));
    drop(bounded);
    // Signed expiry remains an actual observation on the admitted private proof.
    let mut short = signer.claims(ISSUER, "owner-a");
    short["exp"] = json!(seconds() + 2);
    let short = Zeroizing::new(signer.sign(&short));
    let caller = factory.authenticate(&short, &[], deadline()).unwrap();
    let grant = factory
        .authorize_authenticated(caller, &scope)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2250)).await;
    assert!(matches!(
        grant.check(),
        Err(Error::Native(BrokerAccessError::Expired))
    ));
    drop(grant);
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
