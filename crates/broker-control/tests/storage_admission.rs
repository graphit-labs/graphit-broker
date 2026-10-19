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
async fn observe_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='hub_owner' AND wait_event_type='Lock' AND query LIKE '%resource_acl_state%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(
            Instant::now() < end,
            "authorization reaches actual ACL SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[test]
fn scope_and_error_boundaries() {
    assert_eq!(
        StorageScope::project(A, StorageModule::Hub)
            .unwrap()
            .project_id(),
        Some(A)
    );
    for invalid in [
        "",
        "00000000000000000000000000",
        "01d39zy06fgsctvn4t2v9pkhfz",
        "../other",
        "*",
        " 01D39ZY06FGSCTVN4T2V9PKHFZ",
    ] {
        assert_eq!(
            StorageScope::project(invalid, StorageModule::Hub).unwrap_err(),
            Error::InvalidScope
        );
    }
    assert_eq!(
        format!(
            "{:?}",
            StorageScope::project(A, StorageModule::Hub).unwrap()
        ),
        "StorageScope([REDACTED])"
    );
    for origin in [
        ResourceGrantReadError::InvalidLimits,
        ResourceGrantReadError::ReadLimitExceeded,
        ResourceGrantReadError::MalformedStored,
        ResourceGrantReadError::Control(ControlError::OutcomeUncertain),
        ResourceGrantReadError::Control(ControlError::Deadline),
        ResourceGrantReadError::Control(ControlError::Closed),
    ] {
        let error = Error::from(origin);
        assert_eq!(error, Error::Grants(origin));
        assert_eq!(error.to_string(), "Hub storage authorization unavailable");
        assert!(std::error::Error::source(&error).is_none());
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS, actual Native/opaque authentication and Hub storage ACL"]
async fn hub_storage_admission_postgres_contract() {
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
    let verifier = Arc::new(signer.verifier(Some(RESOURCE)));
    let token = signer.sign(&signer.claims());
    let scope = StorageScope::project(A, StorageModule::Hub).unwrap();
    let roots = vec![
        format!("v1/projects/{A}/artifacts"),
        format!("v1/projects/{A}/hub/events"),
        format!("v1/projects/{A}/hub/metadata"),
        format!("v1/projects/{A}/registry"),
    ];
    let unauth = Error::Local(LocalBearerVerificationError::Unauthenticated);

    // Fresh whole-policy observation, explicit route and independent operation sets.
    grant(&mut c, "one", &full()).await;
    let end = deadline();
    let initial = native(&store, &verifier, &token, &scope, end)
        .await
        .unwrap();
    assert_eq!(initial.project, A);
    assert_eq!(initial.subject, format!("{ISSUER}|hub-subject"));
    assert_eq!(initial.route, "explicit-default");
    assert!(initial.end <= end);
    assert!(initial.revision > 0);
    assert_eq!(initial.access, std::array::from_fn(|_| roots.clone()));
    for raw in [RAW, SERVICE] {
        let result = local(&store, raw, &scope, deadline()).await.unwrap();
        assert_eq!(result.access, initial.access);
        assert_eq!(
            result.subject,
            if raw == RAW {
                "local|alice-subject"
            } else {
                "local|bot-subject"
            }
        );
    }
    clear(&mut c).await;
    assert_eq!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap_err(),
        Error::Forbidden
    );
    for cap in ["hub", "presence:publish", "project:write"] {
        clear(&mut c).await;
        grant(
            &mut c,
            "one",
            &Rule {
                caps: &[cap],
                ..full()
            },
        )
        .await;
        assert_eq!(
            native(&store, &verifier, &token, &scope, deadline())
                .await
                .unwrap_err(),
            Error::Forbidden
        );
    }
    clear(&mut c).await;
    grant(
        &mut c,
        "one",
        &Rule {
            caps: &["s3:read", "s3:publish"],
            operations: &["p*", "r?ad"],
            projects: &[A],
            route: " named ",
            ..full()
        },
    )
    .await;
    let r = native(&store, &verifier, &token, &scope, deadline())
        .await
        .unwrap();
    assert!(r.revision > initial.revision);
    assert_eq!(r.route, "named");
    assert_eq!(r.access, [roots.clone(), vec![], roots.clone(), vec![]]);
    assert_eq!(
        native(
            &store,
            &verifier,
            &token,
            &StorageScope::project(B, StorageModule::Hub).unwrap(),
            deadline()
        )
        .await
        .unwrap_err(),
        Error::Forbidden
    );
    for (caps, ops, index) in [
        (&["s3:read"][..], &["read"][..], 0),
        (&["s3:w*"][..], &["write"][..], 1),
        (&["s3:publish"][..], &["publish"][..], 2),
        (&["s3:delete"][..], &["delete"][..], 3),
    ] {
        clear(&mut c).await;
        grant(
            &mut c,
            "one",
            &Rule {
                caps,
                operations: ops,
                projects: &["*"],
                ..full()
            },
        )
        .await;
        let r = local(&store, RAW, &scope, deadline()).await.unwrap();
        for (i, prefixes) in r.access.iter().enumerate() {
            assert_eq!(
                prefixes.as_slice(),
                if i == index { roots.as_slice() } else { &[] }
            );
        }
    }
    clear(&mut c).await;
    grant(
        &mut c,
        "one",
        &Rule {
            caps: &["s3:read"],
            operations: &["write"],
            ..full()
        },
    )
    .await;
    assert_eq!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap_err(),
        Error::Forbidden
    );

    // Principals are literals, raw/canonical subjects work; opaque attributes come from current SQL.
    for (kind, principal, native_match, local_match) in [
        (" user ", "alice", true, true),
        ("user", "a*", false, false),
        ("team", "dev", true, false),
        ("team", "current-team", false, true),
        ("organization", "engineering", true, false),
        ("organization", "current-org", false, true),
        ("organization", "stale-org", false, false),
        ("subject", "hub-subject", true, false),
        (
            "subject",
            "https://broker.example.test|hub-subject",
            true,
            false,
        ),
        ("subject", "local|alice-subject", false, true),
        ("subject", "pseudonymous-other", false, false),
        ("anonymous", "", false, false),
        ("global", "", true, true),
        ("user", "ALICE", false, false),
    ] {
        clear(&mut c).await;
        grant(
            &mut c,
            "one",
            &Rule {
                kind,
                principal,
                ..full()
            },
        )
        .await;
        assert_eq!(
            native(&store, &verifier, &token, &scope, deadline())
                .await
                .is_ok(),
            native_match
        );
        assert_eq!(
            local(&store, RAW, &scope, deadline()).await.is_ok(),
            local_match
        );
    }
    for (kind, field, literal) in [
        ("user", "preferred_username", "a*?[]"),
        ("organization", "organization", "o*?[]"),
        ("team", "groups", "t*?[]"),
    ] {
        clear(&mut c).await;
        grant(
            &mut c,
            "one",
            &Rule {
                kind,
                principal: literal,
                ..full()
            },
        )
        .await;
        let mut claims = signer.claims();
        claims[field] = if field == "groups" {
            json!([literal])
        } else {
            json!(literal)
        };
        assert!(
            native(&store, &verifier, &signer.sign(&claims), &scope, deadline())
                .await
                .is_ok()
        );
        assert_eq!(
            native(&store, &verifier, &token, &scope, deadline())
                .await
                .unwrap_err(),
            Error::Forbidden
        );
    }
    clear(&mut c).await;
    grant(
        &mut c,
        "one",
        &Rule {
            kind: "team",
            principal: "changed-team",
            ..full()
        },
    )
    .await;
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap_err(),
        Error::Forbidden
    );
    c.execute("UPDATE public.local_users SET teams_json='[\"changed-team\"]',revision=revision+1 WHERE username='alice'").await.unwrap();
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap_err(),
        unauth
    );
    // A revision change invalidates the old credential. Restore only this isolated
    // fixture revision to inspect its current attributes with a valid credential.
    c.execute("UPDATE public.local_users SET revision=1 WHERE username='alice'")
        .await
        .unwrap();
    local(&store, RAW, &scope, deadline()).await.unwrap();

    // Exact/ancestor/descendant intersection never admits siblings, other projects or unrelated modules.
    for (prefix, expected) in [
        ("v1", Some(roots.clone())),
        (
            " /v1/projects/{project}/registry/ ",
            Some(vec![format!("v1/projects/{A}/registry")]),
        ),
        (
            "v1/projects/{project}/artifacts/task/id/version/digest",
            Some(vec![format!(
                "v1/projects/{A}/artifacts/task/id/version/digest"
            )]),
        ),
        (
            "v1/projects/{project}/hub",
            Some(vec![
                format!("v1/projects/{A}/hub/events"),
                format!("v1/projects/{A}/hub/metadata"),
            ]),
        ),
        (
            "v1/projects/{project}/hub/metadata",
            Some(vec![format!("v1/projects/{A}/hub/metadata")]),
        ),
        (
            "v1/projects/{project}/hub/events",
            Some(vec![format!("v1/projects/{A}/hub/events")]),
        ),
        ("v1/projects/{project}/hub/metadata2", None),
        ("v1/projects/{project}/hub/events2", None),
        ("v1/projects/{project}/corpora/memory", None),
        ("v1/hub/global/registry", None),
        (
            "v1/installations/Install-A/users/foreign/corpora/memory",
            None,
        ),
        ("v1/projects/{project}/artifacts2", None),
        ("v1/projects/{project}/knowledge", None),
        ("v1/projects/01D39ZY06FGSCTVN4T2V9PKHG0/artifacts", None),
    ] {
        clear(&mut c).await;
        grant(
            &mut c,
            "one",
            &Rule {
                prefixes: &[prefix],
                ..full()
            },
        )
        .await;
        match expected {
            Some(expected) => assert_eq!(
                native(&store, &verifier, &token, &scope, deadline())
                    .await
                    .unwrap()
                    .access,
                std::array::from_fn(|_| expected.clone())
            ),
            None => assert_eq!(
                native(&store, &verifier, &token, &scope, deadline())
                    .await
                    .unwrap_err(),
                Error::Forbidden
            ),
        }
    }
    clear(&mut c).await;
    grant(
        &mut c,
        "a",
        &Rule {
            prefixes: &["v1/projects/{project}/registry/{username}/{organization}/{subject}"],
            ..full()
        },
    )
    .await;
    assert_eq!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap()
            .access[0],
        vec![format!(
            "v1/projects/{A}/registry/alice/engineering/hub-subject"
        )]
    );
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap().access[0],
        vec![format!(
            "v1/projects/{A}/registry/alice/current-org/alice-subject"
        )]
    );
    let mut missing = signer.claims();
    missing.as_object_mut().unwrap().remove("organization");
    assert_eq!(
        native(
            &store,
            &verifier,
            &signer.sign(&missing),
            &scope,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::InvalidPolicy
    );
    let mut unsafe_claim = signer.claims();
    unsafe_claim["preferred_username"] = json!("../escape");
    assert_eq!(
        native(
            &store,
            &verifier,
            &signer.sign(&unsafe_claim),
            &scope,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::InvalidPolicy
    );
    clear(&mut c).await;
    grant(
        &mut c,
        "a",
        &Rule {
            caps: &["s3:read"],
            prefixes: &["v1/projects/{project}/registry"],
            route: "same",
            ..full()
        },
    )
    .await;
    grant(
        &mut c,
        "b",
        &Rule {
            caps: &["s3:read", "s3:write"],
            prefixes: &["v1/projects/{project}/registry"],
            route: "same",
            ..full()
        },
    )
    .await;
    grant(
        &mut c,
        "c",
        &Rule {
            prefixes: &["v1/projects/{project}/knowledge"],
            route: "ignored",
            ..full()
        },
    )
    .await;
    let r = native(&store, &verifier, &token, &scope, deadline())
        .await
        .unwrap();
    assert_eq!(r.route, "same");
    assert_eq!(r.access[0], vec![format!("v1/projects/{A}/registry")]);
    grant(
        &mut c,
        "d",
        &Rule {
            caps: &["s3:delete"],
            route: "other",
            ..full()
        },
    )
    .await;
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap_err(),
        Error::ConflictingRoutes
    );

    // Compile all rules, including unused ones. Unsafe templates/patterns and unknown kinds fail closed.
    for prefix in [
        "v1//registry",
        "v1/../registry",
        "v1/*",
        "v1/{unknown}",
        "v1/\nother",
        "v1/.hidden",
        "",
    ] {
        clear(&mut c).await;
        grant(&mut c, "a", &full()).await;
        grant(
            &mut c,
            "z",
            &Rule {
                kind: "user",
                principal: "nobody",
                prefixes: &[prefix],
                ..full()
            },
        )
        .await;
        assert_eq!(
            native(&store, &verifier, &token, &scope, deadline())
                .await
                .unwrap_err(),
            Error::InvalidPolicy
        );
    }
    for invalid in [
        Rule {
            kind: "unknown",
            ..full()
        },
        Rule {
            caps: &["["],
            ..full()
        },
        Rule {
            caps: &[],
            ..full()
        },
        Rule {
            operations: &["["],
            ..full()
        },
        Rule {
            projects: &["bad-project"],
            ..full()
        },
    ] {
        clear(&mut c).await;
        grant(&mut c, "a", &full()).await;
        grant(&mut c, "z", &invalid).await;
        assert_eq!(
            native(&store, &verifier, &token, &scope, deadline())
                .await
                .unwrap_err(),
            Error::InvalidPolicy
        );
    }
    clear(&mut c).await;
    grant(&mut c, "a", &full()).await;

    // Authentication precedes grants; mode and actual factory binding cannot be swapped.
    let factory = store
        .broker_storage_authorizer(&verifier, n(65_536), "one")
        .unwrap();
    let other = store
        .broker_storage_authorizer(&verifier, n(65_536), "two")
        .unwrap();
    let opaque = store
        .local_storage_authorizer("explicit-audience", n(8192), n(65_536), "one")
        .unwrap();
    assert_eq!(
        store
            .broker_storage_authorizer(&verifier, n(8192), " ")
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    assert_eq!(
        store
            .local_storage_authorizer("explicit-audience", n(8192), n(8192), "")
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    assert_eq!(
        store
            .broker_storage_authorizer(&verifier, n(usize::MAX), "one")
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    assert_eq!(
        store
            .local_storage_authorizer("explicit-audience", n(usize::MAX), n(8192), "one")
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    assert_eq!(
        store
            .local_storage_authorizer("explicit-audience", n(8192), n(usize::MAX), "one")
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    let caller = factory.authenticate(&token, &[], deadline()).unwrap();
    assert_eq!(
        format!("{caller:?}"),
        "AuthenticatedStorageCaller([REDACTED])"
    );
    assert_eq!(
        other
            .authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    let caller = opaque.authenticate(RAW, &[], deadline()).await.unwrap();
    assert_eq!(
        factory
            .authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    let caller = factory.authenticate(&token, &[], deadline()).unwrap();
    clear(&mut c).await;
    assert_eq!(
        factory
            .authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    grant(&mut c, "a", &full()).await;
    assert_eq!(
        factory
            .authenticate(&token, &["required".into()], deadline())
            .unwrap_err(),
        Error::Native(BrokerAccessError::InsufficientScope)
    );
    assert_eq!(
        opaque
            .authenticate(RAW, &["required".into()], deadline())
            .await
            .unwrap_err(),
        unauth
    );
    assert!(matches!(
        native(&store, &verifier, RAW, &scope, deadline()).await,
        Err(Error::Native(_))
    ));
    assert_eq!(
        local(&store, &token, &scope, deadline()).await.unwrap_err(),
        unauth
    );
    c.execute("REVOKE SELECT ON public.resource_grants FROM hub_owner")
        .await
        .unwrap();
    assert!(matches!(
        native(&store, &verifier, "invalid", &scope, deadline()).await,
        Err(Error::Native(_))
    ));
    assert_eq!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap_err(),
        Error::Grants(ResourceGrantReadError::Control(ControlError::Storage))
    );
    c.execute("GRANT SELECT ON public.resource_grants TO hub_owner")
        .await
        .unwrap();
    let capped = store
        .broker_storage_authorizer(&verifier, n(1), "one")
        .unwrap();
    assert_eq!(
        capped
            .authorize(&token, &[], &scope, deadline())
            .await
            .unwrap_err(),
        Error::Grants(ResourceGrantReadError::ReadLimitExceeded)
    );
    c.execute("DELETE FROM public.resource_acl_state")
        .await
        .unwrap();
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap_err(),
        Error::Grants(ResourceGrantReadError::MalformedStored)
    );
    c.execute("INSERT INTO public.resource_acl_state(id,revision,updated_at) VALUES(1,999,0)")
        .await
        .unwrap();

    // Optional resource is explicit; neither missing resource nor mode failure invokes fallback.
    let no_resource = signer.verifier(None);
    let mut api_only = signer.claims();
    api_only["aud"] = json!("hub-api");
    let api_only = signer.sign(&api_only);
    native(&store, &no_resource, &api_only, &scope, deadline())
        .await
        .unwrap();
    assert_eq!(
        native(&store, &verifier, &api_only, &scope, deadline())
            .await
            .unwrap_err(),
        Error::Native(BrokerAccessError::InvalidToken)
    );
    for (field, value) in [
        ("iss", json!("https://other.test")),
        ("aud", json!(["wrong", RESOURCE])),
        ("token_use", json!("id")),
    ] {
        let mut bad = signer.claims();
        bad[field] = value;
        assert_eq!(
            native(&store, &verifier, &signer.sign(&bad), &scope, deadline())
                .await
                .unwrap_err(),
            Error::Native(BrokerAccessError::InvalidToken)
        );
    }
    assert_eq!(
        native(
            &store,
            &verifier,
            &Signer::new().sign(&signer.claims()),
            &scope,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::Native(BrokerAccessError::InvalidToken)
    );
    // Native JWT window is unchanged by local user/opaque token revocation; opaque is current.
    c.execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
        .await
        .unwrap();
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap_err(),
        unauth
    );
    assert!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .is_ok()
    );
    c.execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'; UPDATE public.local_tokens SET revoked_at=1 WHERE token_id='hub-access'").await.unwrap();
    assert_eq!(
        local(&store, RAW, &scope, deadline()).await.unwrap_err(),
        unauth
    );
    assert!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .is_ok()
    );
    c.execute("UPDATE public.local_tokens SET revoked_at=NULL WHERE token_id='hub-access'")
        .await
        .unwrap();

    // Actual SQL locks force final expiry on both positive and negative decisions.
    let mut observer = f.connection().await;
    for decision in ["allowed", "forbidden", "invalid_policy"] {
        clear(&mut c).await;
        if decision == "allowed" {
            grant(&mut c, "a", &full()).await;
        } else if decision == "invalid_policy" {
            grant(
                &mut c,
                "a",
                &Rule {
                    caps: &["["],
                    ..full()
                },
            )
            .await;
        }
        let mut short = signer.claims();
        short["exp"] = json!(seconds() + 3);
        let short = signer.sign(&short);
        let mut lock = c.begin().await.unwrap();
        lock.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let task = {
            let s = store.clone();
            let v = verifier.clone();
            let scope = scope.clone();
            tokio::spawn(async move { native(&s, &v, &short, &scope, deadline()).await })
        };
        observe_lock(&mut observer).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        lock.rollback().await.unwrap();
        assert_eq!(
            task.await.unwrap().unwrap_err(),
            Error::Native(BrokerAccessError::Expired)
        );

        sqlx_core::query::query(
            "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='hub-access'",
        )
        .bind(micros() + 1_500_000)
        .execute(&mut c)
        .await
        .unwrap();
        let mut lock = c.begin().await.unwrap();
        lock.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let task = {
            let s = store.clone();
            let scope = scope.clone();
            tokio::spawn(async move { local(&s, RAW, &scope, deadline()).await })
        };
        observe_lock(&mut observer).await;
        tokio::time::sleep(Duration::from_millis(1510)).await;
        lock.rollback().await.unwrap();
        assert_eq!(task.await.unwrap().unwrap_err(), unauth);
        sqlx_core::query::query(
            "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='hub-access'",
        )
        .bind(micros() + 600_000_000)
        .execute(&mut c)
        .await
        .unwrap();
    }
    clear(&mut c).await;
    grant(&mut c, "a", &full()).await;
    let mut lock = c.begin().await.unwrap();
    lock.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let task = {
        let s = store.clone();
        let v = verifier.clone();
        let token = token.clone();
        let scope = scope.clone();
        tokio::spawn(async move {
            native(
                &s,
                &v,
                &token,
                &scope,
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
    let mut lock = c.begin().await.unwrap();
    lock.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let task = {
        let s = store.clone();
        let v = verifier.clone();
        let token = token.clone();
        let scope = scope.clone();
        tokio::spawn(async move { native(&s, &v, &token, &scope, deadline()).await })
    };
    observe_lock(&mut observer).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    for _ in 0..3 {
        assert!(
            native(&store, &verifier, &token, &scope, deadline())
                .await
                .is_ok()
        );
    }

    // Body-time gap preserves Original and auth expiration; observations do not renew authority.
    let original = Instant::now() + Duration::from_millis(200);
    let caller = factory.authenticate(&token, &[], original).unwrap();
    tokio::time::sleep(Duration::from_millis(210)).await;
    assert_eq!(
        factory
            .authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::Deadline
    );
    let retained = factory
        .authorize(
            &token,
            &[],
            &scope,
            Instant::now() + Duration::from_millis(200),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(210)).await;
    assert_eq!(retained.check().unwrap_err(), Error::Deadline);
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='hub-access'",
    )
    .bind(micros() + 300_000)
    .execute(&mut c)
    .await
    .unwrap();
    let retained = opaque
        .authorize(RAW, &[], &scope, deadline())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(310)).await;
    assert_eq!(retained.check().unwrap_err(), unauth);
    assert_eq!(
        native(&store, &verifier, &token, &scope, Instant::now())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    observer.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        native(&store, &verifier, &token, &scope, deadline())
            .await
            .unwrap_err(),
        Error::Grants(ResourceGrantReadError::Control(ControlError::Closed))
    );
    c.close().await.unwrap();
    f.shutdown().unwrap();
}
