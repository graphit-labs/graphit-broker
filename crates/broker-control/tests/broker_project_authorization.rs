// The existing fixture serves other native control suites.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessError, BrokerAccessVerifier, BrokerProjectAuthorizationError as Error,
    ConnectionLimits, ControlError, PostgresConfig, PostgresControlStore, PostgresCredentials,
    PostgresEndpoint, ProjectResourceAction as Action, ProjectResourceModule as Module,
    ResourceGrantReadError,
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
const SUBJECT: &str = "broker-subject";
const JTI: &str = "jwt-native-token";
struct Signer {
    key: EncodingKey,
    keys: jsonwebtoken::jwk::JwkSet,
}
impl Signer {
    fn new() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self {
            key: EncodingKey::from_ed_der(&pair.serialize_der()),
            keys: serde_json::from_value(json!({"keys":[{
                "kty":"OKP","crv":"Ed25519","kid":"project-key",
                "x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())
            }]}))
            .unwrap(),
        }
    }
    fn verifier(&self) -> BrokerAccessVerifier {
        BrokerAccessVerifier::new(ISSUER, "project-api", Some(RESOURCE), &self.keys, n(8192))
            .unwrap()
    }
    fn claims(&self) -> Value {
        let now = seconds();
        json!({"iss":ISSUER,"sub":SUBJECT,"aud":["project-api",RESOURCE],"iat":now-1,"exp":now+600,
            "token_use":"access","client_id":"approved-client","jti":JTI,"scope":"project-sdk",
            "preferred_username":"alice","organization":"engineering","groups":["dev"],"roles":["admin"]})
    }
    fn sign(&self, claims: &Value) -> String {
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("project-key".into());
        encode(&h, claims, &self.key).unwrap()
    }
}
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "jwt_project_owner".into(),
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
    kind: &str,
    principal: &str,
    caps: &[&str],
    projects: &[&str],
) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture',$2,$3,'',0,0)")
        .bind(id).bind(kind).bind(principal).execute(&mut *c).await.unwrap();
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
async fn oracle(c: &mut PgConnection) -> String {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('state',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.resource_acl_state ORDER BY id) t),'rules',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.resource_grants ORDER BY id COLLATE \"C\") t),'caps',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.grant_capabilities ORDER BY grant_id COLLATE \"C\",value COLLATE \"C\") t),'projects',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.grant_projects ORDER BY grant_id COLLATE \"C\",value COLLATE \"C\") t))::text").fetch_one(c).await.unwrap()
}
#[derive(Debug)]
struct Observation {
    issuer: String,
    subject: String,
    username: Option<String>,
    module: Module,
    action: Action,
    project: String,
    capability: &'static str,
    revision: i64,
}
async fn authorize(
    store: &PostgresControlStore,
    verifier: &BrokerAccessVerifier,
    raw: &str,
    module: Module,
    action: Action,
    project: &str,
    end: Instant,
) -> Result<Observation, Error> {
    let allowed = store
        .broker_project_authorizer(verifier, n(65536))?
        .authorize(raw, &["project-sdk".into()], module, action, project, end)
        .await?;
    assert_eq!(
        format!("{allowed:?}"),
        "AuthorizedBrokerProjectAccess([REDACTED])"
    );
    Ok(Observation {
        issuer: allowed.principal().issuer().into(),
        subject: allowed.principal().subject().into(),
        username: allowed.principal().username().map(str::to_owned),
        module: allowed.module(),
        action: allowed.action(),
        project: allowed.project_id().into(),
        capability: allowed.capability(),
        revision: allowed.policy_revision(),
    })
}
async fn task_read(
    store: &PostgresControlStore,
    verifier: &BrokerAccessVerifier,
    raw: &str,
) -> Result<Observation, Error> {
    authorize(
        store,
        verifier,
        raw,
        Module::Task,
        Action::Read,
        A,
        deadline(),
    )
    .await
}
async fn observe_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='jwt_project_owner' AND wait_event_type='Lock' AND query LIKE '%resource_acl_state%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(
            Instant::now() < end,
            "JWT authorizer reaches the actual ACL SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS, signed JWT and current PROJECT SQL authorization"]
async fn postgres_broker_project_authorization_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE jwt_project_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION jwt_project_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO jwt_project_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let privileged: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='jwt_project_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!privileged);
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let raw = signer.sign(&signer.claims());

    // Hub is a PROJECT capability of its own; only its read operation is admitted.
    assert_eq!(Module::Hub.capability(Action::Read), Some("hub"));
    assert_eq!(Module::Hub.capability(Action::Write), None);
    clear(&mut c).await;
    grant(
        &mut c,
        "hub",
        "subject",
        &format!("{ISSUER}|{SUBJECT}"),
        &["hub"],
        &[A],
    )
    .await;
    let hub = authorize(
        &store,
        &verifier,
        &raw,
        Module::Hub,
        Action::Read,
        A,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(hub.capability, "hub");
    assert_eq!(hub.module, Module::Hub);
    let seen = hub.revision;
    assert_eq!(
        authorize(
            &store,
            &verifier,
            &raw,
            Module::Hub,
            Action::Write,
            A,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::InvalidOperation
    );
    assert_eq!(
        authorize(
            &store,
            &verifier,
            "invalid",
            Module::Hub,
            Action::Write,
            A,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::InvalidOperation
    );
    assert_eq!(
        authorize(
            &store,
            &verifier,
            &raw,
            Module::Hub,
            Action::Read,
            B,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::Forbidden
    );
    c.execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
        .await
        .unwrap();
    assert!(
        authorize(
            &store,
            &verifier,
            &raw,
            Module::Hub,
            Action::Read,
            A,
            deadline()
        )
        .await
        .unwrap()
        .revision
            > seen
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='hub'")
        .await
        .unwrap();
    assert_eq!(
        authorize(
            &store,
            &verifier,
            &raw,
            Module::Hub,
            Action::Read,
            A,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::Forbidden
    );
    for substitute in ["knowledge:read", "s3", "s3:read", "hub:read", "hub:write"] {
        clear(&mut c).await;
        grant(
            &mut c,
            "substitute",
            "subject",
            &format!("{ISSUER}|{SUBJECT}"),
            &[substitute],
            &[A],
        )
        .await;
        assert_eq!(
            authorize(
                &store,
                &verifier,
                &raw,
                Module::Hub,
                Action::Read,
                A,
                deadline()
            )
            .await
            .unwrap_err(),
            Error::Forbidden
        );
    }
    clear(&mut c).await;
    grant(
        &mut c,
        "hub-b",
        "subject",
        &format!("{ISSUER}|{SUBJECT}"),
        &["hub"],
        &[B],
    )
    .await;
    grant(
        &mut c,
        "project-a",
        "subject",
        &format!("{ISSUER}|{SUBJECT}"),
        &["knowledge:read"],
        &[A],
    )
    .await;
    grant(
        &mut c,
        "other-principal",
        "subject",
        "other",
        &["hub"],
        &[A],
    )
    .await;
    assert_eq!(
        authorize(
            &store,
            &verifier,
            &raw,
            Module::Hub,
            Action::Read,
            A,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::Forbidden
    );
    for projects in [&[][..], &["*"][..]] {
        clear(&mut c).await;
        grant(
            &mut c,
            "hub-any",
            "subject",
            &format!("{ISSUER}|{SUBJECT}"),
            &["hub"],
            projects,
        )
        .await;
        authorize(
            &store,
            &verifier,
            &raw,
            Module::Hub,
            Action::Read,
            A,
            deadline(),
        )
        .await
        .unwrap();
        authorize(
            &store,
            &verifier,
            &raw,
            Module::Hub,
            Action::Read,
            B,
            deadline(),
        )
        .await
        .unwrap();
    }
    for module in [Module::Task, Module::Memory, Module::Knowledge, Module::Ast] {
        for action in [Action::Read, Action::Write] {
            clear(&mut c).await;
            let cap = module.capability(action).unwrap();
            grant(
                &mut c,
                "a",
                "subject",
                &format!("{ISSUER}|{SUBJECT}"),
                &[cap],
                &[A],
            )
            .await;
            let before = oracle(&mut c).await;
            let allowed = authorize(&store, &verifier, &raw, module, action, A, deadline())
                .await
                .unwrap();
            assert_eq!(
                (
                    allowed.issuer.as_str(),
                    allowed.subject.as_str(),
                    allowed.username.as_deref()
                ),
                (ISSUER, SUBJECT, Some("alice"))
            );
            assert_eq!(
                (
                    allowed.module,
                    allowed.action,
                    allowed.project.as_str(),
                    allowed.capability
                ),
                (module, action, A, cap)
            );
            let revision: i64 = sqlx_core::query_scalar::query_scalar(
                "SELECT revision FROM public.resource_acl_state WHERE id=1",
            )
            .fetch_one(&mut c)
            .await
            .unwrap();
            assert_eq!(allowed.revision, revision);
            let other_action = if action == Action::Read {
                Action::Write
            } else {
                Action::Read
            };
            assert_eq!(
                authorize(&store, &verifier, &raw, module, other_action, A, deadline())
                    .await
                    .unwrap_err(),
                Error::Forbidden
            );
            let other_module = if module == Module::Task {
                Module::Memory
            } else {
                Module::Task
            };
            assert_eq!(
                authorize(&store, &verifier, &raw, other_module, action, A, deadline())
                    .await
                    .unwrap_err(),
                Error::Forbidden
            );
            assert_eq!(
                authorize(&store, &verifier, &raw, module, action, B, deadline())
                    .await
                    .unwrap_err(),
                Error::Forbidden
            );
            let mut other = signer.claims();
            other["sub"] = json!("another-subject");
            assert_eq!(
                authorize(
                    &store,
                    &verifier,
                    &signer.sign(&other),
                    module,
                    action,
                    A,
                    deadline()
                )
                .await
                .unwrap_err(),
                Error::Forbidden
            );
            assert_eq!(oracle(&mut c).await, before);
        }
    }
    clear(&mut c).await;
    grant(&mut c, "a", "subject", SUBJECT, &["task:read"], &[B]).await;
    grant(&mut c, "b", "subject", "other", &["task:read"], &[A]).await;
    grant(&mut c, "c", "subject", SUBJECT, &["memory:read"], &[A]).await;
    assert_eq!(
        task_read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Forbidden
    );
    clear(&mut c).await;
    grant(
        &mut c,
        "a",
        "authenticated",
        "",
        &["hub", "presence:*", "s3:read"],
        &[A],
    )
    .await;
    c.execute("INSERT INTO public.role_assignments(subject,role,created_at) VALUES('https://broker.example.test|broker-subject','admin',0)").await.unwrap();
    assert_eq!(
        task_read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Forbidden
    );
    c.execute("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a','task:read'); UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    let seen = task_read(&store, &verifier, &raw).await.unwrap().revision;
    c.execute("DELETE FROM public.grant_capabilities WHERE grant_id='a' AND value='task:read'; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    assert_eq!(
        task_read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Forbidden
    );
    c.execute("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a','task:read')")
        .await
        .unwrap();
    assert!(task_read(&store, &verifier, &raw).await.unwrap().revision > seen);
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
                &verifier,
                &raw,
                Module::Memory,
                Action::Write,
                B,
                deadline()
            )
            .await
            .is_ok()
        );
        assert_eq!(
            authorize(
                &store,
                &verifier,
                &raw,
                Module::Knowledge,
                Action::Read,
                B,
                deadline()
            )
            .await
            .unwrap_err(),
            Error::Forbidden
        );
    }
    for (kind, principal, expected) in [
        ("subject", SUBJECT, true),
        ("subject", "upstream|original-subject", false),
        ("user", "alice", true),
        ("team", "de?", true),
        ("organization", "engineering", true),
        ("anonymous", "", false),
    ] {
        clear(&mut c).await;
        grant(&mut c, "a", kind, principal, &["task:read"], &[A]).await;
        assert_eq!(task_read(&store, &verifier, &raw).await.is_ok(), expected);
    }
    let mut absent = signer.claims();
    for field in ["preferred_username", "organization", "groups"] {
        absent.as_object_mut().unwrap().remove(field);
    }
    for kind in ["user", "organization", "team"] {
        clear(&mut c).await;
        grant(&mut c, "a", kind, "*", &["task:read"], &[A]).await;
        assert_eq!(
            task_read(&store, &verifier, &signer.sign(&absent))
                .await
                .unwrap_err(),
            Error::Forbidden
        );
    }
    // Authentication is local even when its prior SQL metadata changes or SELECT is denied.
    clear(&mut c).await;
    grant(&mut c, "a", "user", "alice", &["task:read"], &[A]).await;
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','original-subject','human','','Old','','old','[\"old\"]',1,0,1,0,0); INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('approved-client','Fixture','[\"https://client.example.test/callback\"]','[\"project-sdk\"]','web',0)").await.unwrap();
    let digest = support::digester()
        .token(TokenKind::OidcStoredAccess, JTI.as_bytes())
        .unwrap();
    let stored=json!({"issuer":"local","subject":"original-subject","username":"alice","auth_method":"oidc","local_user_revision":1,
        "name":"Old","email":null,"organization":"old","teams":["old"],"scopes":["project-sdk"],
        "roles":[],"roles_from_claim":false,"role_claim_selector":""}).to_string();
    sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,'oidc_access','original-subject','broker-subject',$3,'approved-client','project-api','https://broker.example.test/v1','[\"project-sdk\"]',1,'',0,9223372036854775807,0)")
        .bind(digest.to_sql_hex()).bind(JTI).bind(stored).execute(&mut c).await.unwrap();
    assert!(task_read(&store, &verifier, &raw).await.is_ok());
    c.execute("UPDATE public.local_users SET enabled=0,revision=2,organization='changed',teams_json='[]' WHERE username='alice'; UPDATE public.local_tokens SET revoked_at=1,expires_at=0,principal_json='{}' WHERE token_id='jwt-native-token'; DELETE FROM public.oauth_dynamic_clients WHERE client_id='approved-client'; REVOKE SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients FROM jwt_project_owner").await.unwrap();
    for table in ["local_users", "local_tokens", "oauth_dynamic_clients"] {
        let permitted: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT has_table_privilege('jwt_project_owner',$1,'SELECT')",
        )
        .bind(format!("public.{table}"))
        .fetch_one(&mut c)
        .await
        .unwrap();
        assert!(!permitted);
    }
    assert!(task_read(&store, &verifier, &raw).await.is_ok());
    let mut changed = signer.claims();
    changed["preferred_username"] = json!("changed");
    assert_eq!(
        task_read(&store, &verifier, &signer.sign(&changed))
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    // Authentication rejects before consulting SQL policy.
    c.execute("REVOKE SELECT ON public.grant_capabilities FROM jwt_project_owner")
        .await
        .unwrap();
    assert_eq!(
        task_read(&store, &verifier, "bad").await.unwrap_err(),
        Error::Authentication(BrokerAccessError::InvalidToken)
    );
    let mut wrong_scope = signer.claims();
    wrong_scope["scope"] = json!("other");
    assert_eq!(
        task_read(&store, &verifier, &signer.sign(&wrong_scope))
            .await
            .unwrap_err(),
        Error::Authentication(BrokerAccessError::InsufficientScope)
    );
    assert_eq!(
        task_read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    c.execute("GRANT SELECT ON public.grant_capabilities TO jwt_project_owner")
        .await
        .unwrap();
    assert_eq!(
        store
            .broker_project_authorizer(&verifier, n(1))
            .unwrap()
            .authorize(
                &raw,
                &["project-sdk".into()],
                Module::Task,
                Action::Read,
                A,
                deadline()
            )
            .await
            .unwrap_err(),
        Error::Grants(ResourceGrantReadError::ReadLimitExceeded)
    );
    grant(&mut c, "z", "team", "[", &["memory:read"], &[B]).await;
    assert_eq!(
        task_read(&store, &verifier, &raw).await.unwrap_err(),
        Error::InvalidPolicy
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='z'")
        .await
        .unwrap();
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
        task_read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Grants(ResourceGrantReadError::MalformedStored)
    );
    sqlx_core::query::query(
        "INSERT INTO public.resource_acl_state(id,revision,updated_at) VALUES(1,$1,0)",
    )
    .bind(revision)
    .execute(&mut c)
    .await
    .unwrap();
    for project in [
        "",
        "*",
        "global",
        "00000000000000000000000000",
        "01d39zy06fgsctvn4t2v9pkhfz",
    ] {
        assert_eq!(
            authorize(
                &store,
                &verifier,
                &raw,
                Module::Task,
                Action::Read,
                project,
                deadline()
            )
            .await
            .unwrap_err(),
            Error::InvalidProject
        );
    }
    let mut blocker = f.connection().await;
    // Expiry must win over both an otherwise allowed and an otherwise denied decision.
    for permitted in [true, false] {
        clear(&mut c).await;
        grant(
            &mut c,
            "a",
            "subject",
            if permitted { SUBJECT } else { "other" },
            &["task:read"],
            &[A],
        )
        .await;
        let mut short = signer.claims();
        let expiry = seconds() + 4;
        short["exp"] = json!(expiry);
        let token = signer.sign(&short);
        blocker
            .execute("BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let worker = store.clone();
        let trust = verifier.clone();
        let pending = tokio::spawn(async move { task_read(&worker, &trust, &token).await });
        observe_lock(&mut c).await;
        assert!(!pending.is_finished());
        assert!(seconds() < expiry, "JWT is alive when SQL lock is observed");
        let remaining = (UNIX_EPOCH + Duration::from_secs(expiry))
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        tokio::time::sleep(remaining + Duration::from_millis(30)).await;
        blocker.execute("COMMIT").await.unwrap();
        assert_eq!(
            pending.await.unwrap().unwrap_err(),
            Error::Authentication(BrokerAccessError::Expired)
        );
    }
    clear(&mut c).await;
    grant(&mut c, "a", "subject", SUBJECT, &["task:read"], &[A]).await;
    blocker
        .execute("BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let worker = store.clone();
    let trust = verifier.clone();
    let token = raw.clone();
    let pending = tokio::spawn(async move {
        authorize(
            &worker,
            &trust,
            &token,
            Module::Task,
            Action::Read,
            A,
            Instant::now() + Duration::from_secs(2),
        )
        .await
    });
    observe_lock(&mut c).await;
    assert_eq!(
        pending.await.unwrap().unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    blocker.execute("COMMIT").await.unwrap();
    assert!(task_read(&store, &verifier, &raw).await.is_ok());
    blocker
        .execute("BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let worker = store.clone();
    let trust = verifier.clone();
    let token = raw.clone();
    let pending = tokio::spawn(async move { task_read(&worker, &trust, &token).await });
    observe_lock(&mut c).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    blocker.execute("COMMIT").await.unwrap();
    assert!(task_read(&store, &verifier, &raw).await.is_ok());
    assert_eq!(
        authorize(
            &store,
            &verifier,
            &raw,
            Module::Task,
            Action::Read,
            A,
            Instant::now()
        )
        .await
        .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    c.execute("GRANT SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients TO jwt_project_owner").await.unwrap();
    let before = oracle(&mut c).await;
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        task_read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    assert!(task_read(&reopened, &verifier, &raw).await.is_ok());
    assert_eq!(oracle(&mut c).await, before);
    reopened.shutdown(deadline()).await.unwrap();
    blocker.close().await.unwrap();
    c.close().await.unwrap();
}
