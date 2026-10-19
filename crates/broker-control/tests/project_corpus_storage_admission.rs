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
    project: String,
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
        project: g.scope().project_id().expect("actual PROJECT scope").into(),
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

#[tokio::test]
#[ignore = "real PostgreSQL TLS NOSUPERUSER, actual Native/opaque authentication and PROJECT corpus ACL"]
async fn project_corpus_storage_admission_contract() {
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
    seed_local(&mut c).await;
    let signer = Signer::new();
    let verifier = signer.verifier(Some(RESOURCE));
    let token = signer.sign(&signer.claims());
    let modules = [
        StorageModule::Task,
        StorageModule::Memory,
        StorageModule::Knowledge,
        StorageModule::Ast,
    ];
    let hub_scope = StorageScope::project(A, StorageModule::Hub).unwrap();
    let hub_roots = vec![
        format!("v1/projects/{A}/artifacts"),
        format!("v1/projects/{A}/hub/events"),
        format!("v1/projects/{A}/hub/metadata"),
        format!("v1/projects/{A}/registry"),
    ];

    for module in modules {
        let scope = StorageScope::project(A, module).unwrap();
        let root = format!("v1/projects/{A}/corpora/{}", module.as_str());
        clear(&mut c).await;
        grant(
            &mut c,
            "project",
            &Rule {
                projects: &[A],
                prefixes: &["v1/projects/{project}"],
                ..full()
            },
        )
        .await;
        let end = deadline();
        let first = native(&store, &verifier, &token, &scope, end)
            .await
            .unwrap();
        assert_eq!(first.project, A);
        assert_eq!(first.module, module);
        assert_eq!(first.subject, format!("{ISSUER}|hub-subject"));
        assert_eq!(first.route, "explicit-default");
        assert!(first.end <= end);
        assert!(first.revision > 0);
        assert_eq!(first.access, std::array::from_fn(|_| vec![root.clone()]));
        for raw in [RAW, SERVICE] {
            let admitted = local(&store, raw, &scope, deadline()).await.unwrap();
            assert_eq!(admitted.access, first.access);
            assert_eq!(admitted.module, module);
            assert_eq!(
                admitted.subject,
                if raw == RAW {
                    "local|alice-subject"
                } else {
                    "local|bot-subject"
                }
            );
        }
        let other_project = StorageScope::project(B, module).unwrap();
        assert_eq!(
            native(&store, &verifier, &token, &other_project, deadline())
                .await
                .unwrap_err(),
            Error::Forbidden
        );
        let hub = native(&store, &verifier, &token, &hub_scope, deadline())
            .await
            .unwrap();
        assert_eq!(hub.access, std::array::from_fn(|_| hub_roots.clone()));
        assert!(
            hub.access
                .iter()
                .flatten()
                .all(|p| !p.contains("/corpora/"))
        );
        assert!(
            first
                .access
                .iter()
                .flatten()
                .all(|p| !p.contains("/registry") && !p.contains("/artifacts"))
        );

        // A concrete module prefix cannot become authority for a sibling module or Hub.
        clear(&mut c).await;
        grant(
            &mut c,
            "module",
            &Rule {
                projects: &[A],
                prefixes: &[&root],
                route: "module-route",
                ..full()
            },
        )
        .await;
        let scoped = native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap();
        assert_eq!(scoped.route, "module-route");
        assert_eq!(scoped.access, first.access);
        for other in modules
            .into_iter()
            .filter(|other| *other != module)
            .chain([StorageModule::Hub])
        {
            let sibling = StorageScope::project(A, other).unwrap();
            assert_eq!(
                native(&store, &verifier, &token, &sibling, deadline())
                    .await
                    .unwrap_err(),
                Error::Forbidden
            );
            assert_eq!(
                local(&store, RAW, &sibling, deadline()).await.unwrap_err(),
                Error::Forbidden
            );
        }
        for projects in [&[][..], &["*"][..]] {
            clear(&mut c).await;
            grant(
                &mut c,
                "any",
                &Rule {
                    projects,
                    prefixes: &[&root],
                    ..full()
                },
            )
            .await;
            assert_eq!(
                native(&store, &verifier, &token, &scope, deadline())
                    .await
                    .unwrap()
                    .access,
                first.access
            );
        }
        for ancestor in [
            "v1".to_owned(),
            format!("v1/projects/{A}"),
            format!("v1/projects/{A}/corpora"),
            root.clone(),
        ] {
            clear(&mut c).await;
            grant(
                &mut c,
                "ancestor",
                &Rule {
                    prefixes: &[&ancestor],
                    ..full()
                },
            )
            .await;
            assert_eq!(
                local(&store, RAW, &scope, deadline()).await.unwrap().access,
                first.access
            );
        }
        let child = format!("{root}/dataset/partition");
        clear(&mut c).await;
        grant(
            &mut c,
            "child",
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
        for unrelated in [
            format!("{root}2"),
            format!("{root}-sibling"),
            format!("v1/projects/{B}/corpora/{}", module.as_str()),
            "v1/hub/global/registry".to_owned(),
            "v1/installations/install/users/literal/corpora/memory".to_owned(),
        ] {
            clear(&mut c).await;
            grant(
                &mut c,
                "unrelated",
                &Rule {
                    prefixes: &[&unrelated],
                    ..full()
                },
            )
            .await;
            assert_eq!(
                local(&store, RAW, &scope, deadline()).await.unwrap_err(),
                Error::Forbidden
            );
        }
        for (index, operation) in ["read", "write", "publish", "delete"]
            .into_iter()
            .enumerate()
        {
            clear(&mut c).await;
            let capability = format!("s3:{operation}");
            grant(
                &mut c,
                "op",
                &Rule {
                    caps: &[&capability],
                    operations: &[operation],
                    prefixes: &[&root],
                    ..full()
                },
            )
            .await;
            let admitted = native(&store, &verifier, &token, &scope, deadline())
                .await
                .unwrap();
            for i in 0..4 {
                assert_eq!(
                    admitted.access[i],
                    if i == index {
                        vec![root.clone()]
                    } else {
                        vec![]
                    }
                );
            }
            clear(&mut c).await;
            grant(
                &mut c,
                "mask",
                &Rule {
                    caps: &["s3:read"],
                    operations: &["write"],
                    prefixes: &[&root],
                    ..full()
                },
            )
            .await;
            assert_eq!(
                local(&store, RAW, &scope, deadline()).await.unwrap_err(),
                Error::Forbidden
            );
        }
        // Only actual contributing operation/prefix pairs can choose a route.
        clear(&mut c).await;
        grant(
            &mut c,
            "a",
            &Rule {
                caps: &["s3:read"],
                prefixes: &[&root],
                route: "same",
                ..full()
            },
        )
        .await;
        grant(
            &mut c,
            "b",
            &Rule {
                caps: &["s3:write"],
                prefixes: &[&root],
                route: "same",
                ..full()
            },
        )
        .await;
        grant(
            &mut c,
            "ignored",
            &Rule {
                prefixes: &["v1/hub/global/registry"],
                route: "other",
                ..full()
            },
        )
        .await;
        let merged = local(&store, RAW, &scope, deadline()).await.unwrap();
        assert_eq!(merged.route, "same");
        assert_eq!(
            merged.access,
            [vec![root.clone()], vec![root.clone()], vec![], vec![]]
        );
        grant(
            &mut c,
            "conflict",
            &Rule {
                caps: &["s3:delete"],
                prefixes: &[&root],
                route: "other",
                ..full()
            },
        )
        .await;
        assert_eq!(
            native(&store, &verifier, &token, &scope, deadline())
                .await
                .unwrap_err(),
            Error::ConflictingRoutes
        );
        // Irrelevant malformed rules still invalidate the whole current policy.
        clear(&mut c).await;
        grant(&mut c, "valid", &full()).await;
        grant(
            &mut c,
            "invalid",
            &Rule {
                projects: &[B],
                prefixes: &["v1/{unknown}"],
                ..full()
            },
        )
        .await;
        assert_eq!(
            local(&store, RAW, &scope, deadline()).await.unwrap_err(),
            Error::InvalidPolicy
        );
        clear(&mut c).await;
        grant(&mut c, "valid", &full()).await;
        let renewed = native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap();
        assert!(renewed.revision > first.revision);
        let factory = store
            .broker_storage_authorizer(&verifier, n(65_536), "explicit-default")
            .unwrap();
        let caller = factory.authenticate(&token, &[], deadline()).unwrap();
        clear(&mut c).await;
        assert_eq!(
            factory
                .authorize_authenticated(caller, &scope)
                .await
                .unwrap_err(),
            Error::Forbidden
        );
    }
    let scope = StorageScope::project(A, StorageModule::Task).unwrap();
    grant(&mut c, "ready", &full()).await;
    let factory = store
        .broker_storage_authorizer(&verifier, n(65_536), "route")
        .unwrap();
    let other = store
        .broker_storage_authorizer(&verifier, n(65_536), "route")
        .unwrap();
    let caller = factory.authenticate(&token, &[], deadline()).unwrap();
    assert_eq!(
        other
            .authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    let opaque = store
        .local_storage_authorizer("explicit-audience", n(8192), n(65_536), "route")
        .unwrap();
    let caller = opaque.authenticate(RAW, &[], deadline()).await.unwrap();
    assert_eq!(
        factory
            .authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    assert_eq!(
        factory
            .authenticate(&token, &["required".into()], deadline())
            .unwrap_err(),
        Error::Native(BrokerAccessError::InsufficientScope)
    );
    let original = Instant::now() + Duration::from_millis(100);
    let caller = factory.authenticate(&token, &[], original).unwrap();
    tokio::time::sleep_until(original.into()).await;
    assert_eq!(
        factory
            .authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::Deadline
    );
    let mut expired = signer.claims();
    expired["iat"] = json!(seconds() - 10);
    expired["exp"] = json!(seconds() - 1);
    assert_eq!(
        native(
            &store,
            &verifier,
            &signer.sign(&expired),
            &scope,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::Native(BrokerAccessError::Expired)
    );
    c.execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
        .await
        .unwrap();
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap_err(),
        Error::Local(LocalBearerVerificationError::Unauthenticated)
    );
    assert!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .is_ok()
    );
    c.execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'")
        .await
        .unwrap();
    assert!(local(&store, RAW, &scope, deadline()).await.is_ok());
    c.execute("REVOKE SELECT ON public.resource_grants FROM hub_owner")
        .await
        .unwrap();
    assert_eq!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap_err(),
        Error::Grants(ResourceGrantReadError::Control(ControlError::Storage))
    );
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap_err(),
        Error::Grants(ResourceGrantReadError::Control(ControlError::Storage))
    );
    c.execute("GRANT SELECT ON public.resource_grants TO hub_owner")
        .await
        .unwrap();
    assert!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .is_ok()
    );
    assert!(local(&store, RAW, &scope, deadline()).await.is_ok());
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
    f.shutdown().unwrap();
}
