// The existing fixture serves other native control suites.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessError, BrokerAccessVerifier, BrokerPresenceAuthorizationError as Error,
    ConnectionLimits, ControlError, PostgresConfig, PostgresControlStore, PostgresCredentials,
    PostgresEndpoint, PresenceCapability as Capability, ResourceGrantReadError,
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
        BrokerAccessVerifier::new(ISSUER, "presence-api", Some(RESOURCE), &self.keys, n(8192))
            .unwrap()
    }
    fn claims(&self) -> Value {
        let now = seconds();
        json!({"iss":ISSUER,"sub":SUBJECT,"aud":["presence-api",RESOURCE],"iat":now-1,"exp":now+600,
            "token_use":"access","client_id":"approved-client","jti":JTI,"scope":"presence-sdk",
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
            "jwt_presence_owner".into(),
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

async fn authorize<'a>(
    store: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    raw: &str,
    cap: Capability,
    project: &str,
    end: Instant,
) -> Result<broker_control::AuthorizedBrokerPresence<'a>, Error> {
    let authorizer = store.broker_presence_authorizer(verifier, n(65536))?;
    assert_eq!(
        format!("{authorizer:?}"),
        "PostgresBrokerPresenceAuthorizer([REDACTED])"
    );
    authorizer
        .authorize_project(raw, &["presence-sdk".into()], cap, project, end)
        .await
}
async fn read<'a>(
    store: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    raw: &str,
) -> Result<broker_control::AuthorizedBrokerPresence<'a>, Error> {
    authorize(store, verifier, raw, Capability::Read, A, deadline()).await
}
async fn observe_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='jwt_presence_owner' AND wait_event_type='Lock' AND query LIKE '%resource_acl_state%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(
            Instant::now() < end,
            "native Presence reached actual ACL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS, signed JWT and current Presence SQL authorization"]
async fn postgres_broker_presence_authorization_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE jwt_presence_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION jwt_presence_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO jwt_presence_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let privileged: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='jwt_presence_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!privileged);
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let raw = signer.sign(&signer.claims());
    for cap in [Capability::Read, Capability::Publish] {
        clear(&mut c).await;
        grant(
            &mut c,
            "a",
            "subject",
            &format!("{ISSUER}|{SUBJECT}"),
            &[cap.as_str()],
            &[A],
        )
        .await;
        let before = oracle(&mut c).await;
        let allowed = authorize(&store, &verifier, &raw, cap, A, deadline())
            .await
            .unwrap();
        assert_eq!(
            format!("{allowed:?}"),
            "AuthorizedBrokerPresence([REDACTED])"
        );
        assert_eq!(
            (
                allowed.principal().issuer(),
                allowed.principal().subject(),
                allowed.principal().username()
            ),
            (ISSUER, SUBJECT, Some("alice"))
        );
        assert_eq!((allowed.project_id(), allowed.capability()), (A, cap));
        let revision: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT revision FROM public.resource_acl_state WHERE id=1",
        )
        .fetch_one(&mut c)
        .await
        .unwrap();
        assert_eq!(allowed.policy_revision(), revision);
        let other = if cap == Capability::Read {
            Capability::Publish
        } else {
            Capability::Read
        };
        assert_eq!(
            authorize(&store, &verifier, &raw, other, A, deadline())
                .await
                .unwrap_err(),
            Error::Forbidden
        );
        assert_eq!(
            authorize(&store, &verifier, &raw, cap, B, deadline())
                .await
                .unwrap_err(),
            Error::Forbidden
        );
        let mut foreign = signer.claims();
        foreign["sub"] = json!("foreign");
        assert_eq!(
            authorize(
                &store,
                &verifier,
                &signer.sign(&foreign),
                cap,
                A,
                deadline()
            )
            .await
            .unwrap_err(),
            Error::Forbidden
        );
        assert_eq!(oracle(&mut c).await, before);
    }
    clear(&mut c).await;
    assert_eq!(
        read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Forbidden
    );
    grant(&mut c, "a", "subject", SUBJECT, &["presence:read"], &[B]).await;
    grant(&mut c, "b", "subject", "foreign", &["presence:read"], &[A]).await;
    grant(&mut c, "c", "subject", SUBJECT, &["presence:publish"], &[A]).await;
    assert_eq!(
        read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Forbidden
    );
    for projects in [&[][..], &["*"][..]] {
        clear(&mut c).await;
        grant(&mut c, "a", "authenticated", "", &["presence:*"], projects).await;
        for cap in [Capability::Read, Capability::Publish] {
            assert!(
                authorize(&store, &verifier, &raw, cap, B, deadline())
                    .await
                    .is_ok()
            );
        }
    }
    for (kind, principal, expected) in [
        ("subject", SUBJECT, true),
        ("subject", "upstream|old-subject", false),
        ("user", "a?ice", true),
        ("team", "de?", true),
        ("organization", "engineering", true),
        ("global", "", true),
        ("authenticated", "", true),
        ("anonymous", "", false),
    ] {
        clear(&mut c).await;
        grant(&mut c, "a", kind, principal, &["presence:read"], &[A]).await;
        assert_eq!(read(&store, &verifier, &raw).await.is_ok(), expected);
    }
    let mut absent = signer.claims();
    for field in ["preferred_username", "organization", "groups"] {
        absent.as_object_mut().unwrap().remove(field);
    }
    for kind in ["user", "team", "organization"] {
        clear(&mut c).await;
        grant(&mut c, "a", kind, "*", &["presence:read"], &[A]).await;
        assert_eq!(
            read(&store, &verifier, &signer.sign(&absent))
                .await
                .unwrap_err(),
            Error::Forbidden
        );
    }
    clear(&mut c).await;
    grant(
        &mut c,
        "a",
        "authenticated",
        "",
        &["hub", "s3:*", "task:*", "memory:*", "knowledge:*", "ast:*"],
        &[A],
    )
    .await;
    c.execute("INSERT INTO public.role_assignments(subject,role,created_at) VALUES('https://broker.example.test|broker-subject','admin',0)").await.unwrap();
    let mut purpose = signer.claims();
    purpose["scope"] = json!("presence-sdk presence:read presence:publish");
    assert_eq!(
        read(&store, &verifier, &signer.sign(&purpose))
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    clear(&mut c).await;
    grant(&mut c, "a", "user", "alice", &["presence:read"], &[A]).await;
    let revision = read(&store, &verifier, &raw)
        .await
        .unwrap()
        .policy_revision();
    let mut writer = f.connection().await;
    writer.execute("BEGIN; DELETE FROM public.grant_capabilities WHERE grant_id='a'; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    assert_eq!(
        read(&store, &verifier, &raw)
            .await
            .unwrap()
            .policy_revision(),
        revision
    );
    writer.execute("COMMIT").await.unwrap();
    assert_eq!(
        read(&store, &verifier, &raw).await.unwrap_err(),
        Error::InvalidPolicy
    );
    c.execute("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a','presence:publish'); UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    assert_eq!(
        read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Forbidden
    );
    c.execute("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a','presence:read'); UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    assert!(
        read(&store, &verifier, &raw)
            .await
            .unwrap()
            .policy_revision()
            > revision
    );
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','original-subject','human','','Old','','old','[\"old\"]',1,0,1,0,0); INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('approved-client','Fixture','[\"https://client.example.test/callback\"]','[\"presence-sdk\"]','web',0)").await.unwrap();
    let digest = support::digester()
        .token(TokenKind::OidcStoredAccess, JTI.as_bytes())
        .unwrap();
    let stored=json!({"issuer":"local","subject":"original-subject","username":"alice","auth_method":"oidc","local_user_revision":1,
        "name":"Old","email":null,"organization":"old","teams":["old"],"scopes":["presence-sdk"],
        "roles":[],"roles_from_claim":false,"role_claim_selector":""}).to_string();
    sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,'oidc_access','original-subject','broker-subject',$3,'approved-client','presence-api','https://broker.example.test/v1','[\"presence-sdk\"]',1,'',0,9223372036854775807,0)")
        .bind(digest.to_sql_hex()).bind(JTI).bind(stored).execute(&mut c).await.unwrap();
    assert!(read(&store, &verifier, &raw).await.is_ok());
    c.execute("UPDATE public.local_users SET enabled=0,revision=2,organization='changed',teams_json='[]' WHERE username='alice'; UPDATE public.local_tokens SET revoked_at=1,expires_at=0,principal_json='{}' WHERE token_id='jwt-native-token'; DELETE FROM public.oauth_dynamic_clients WHERE client_id='approved-client'; REVOKE SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients FROM jwt_presence_owner").await.unwrap();
    for table in ["local_users", "local_tokens", "oauth_dynamic_clients"] {
        let permitted: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT has_table_privilege('jwt_presence_owner',$1,'SELECT')",
        )
        .bind(format!("public.{table}"))
        .fetch_one(&mut c)
        .await
        .unwrap();
        assert!(!permitted);
    }
    assert!(read(&store, &verifier, &raw).await.is_ok());

    let mut changed = signer.claims();
    changed["preferred_username"] = json!("changed");
    assert_eq!(
        read(&store, &verifier, &signer.sign(&changed))
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    // Native authentication runs before any policy SQL and does not accept opaque input.
    c.execute("REVOKE SELECT ON public.grant_capabilities FROM jwt_presence_owner")
        .await
        .unwrap();
    for bad in ["bad", "opaque-local-token"] {
        assert_eq!(
            read(&store, &verifier, bad).await.unwrap_err(),
            Error::Authentication(BrokerAccessError::InvalidToken)
        );
    }
    for (field, value, error) in [
        (
            "scope",
            json!("other"),
            BrokerAccessError::InsufficientScope,
        ),
        (
            "aud",
            json!(["other", RESOURCE]),
            BrokerAccessError::InvalidToken,
        ),
    ] {
        let mut invalid = signer.claims();
        invalid[field] = value;
        assert_eq!(
            read(&store, &verifier, &signer.sign(&invalid))
                .await
                .unwrap_err(),
            Error::Authentication(error)
        );
    }
    assert_eq!(
        read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    c.execute("GRANT SELECT ON public.grant_capabilities TO jwt_presence_owner")
        .await
        .unwrap();
    assert_eq!(
        store
            .broker_presence_authorizer(&verifier, n(1))
            .unwrap()
            .authorize_project(
                &raw,
                &["presence-sdk".into()],
                Capability::Read,
                A,
                deadline()
            )
            .await
            .unwrap_err(),
        Error::Grants(ResourceGrantReadError::ReadLimitExceeded)
    );
    grant(&mut c, "z", "team", "[", &["presence:publish"], &[B]).await;
    assert_eq!(
        read(&store, &verifier, &raw).await.unwrap_err(),
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
        read(&store, &verifier, &raw).await.unwrap_err(),
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
                Capability::Read,
                project,
                deadline()
            )
            .await
            .unwrap_err(),
            Error::InvalidProject
        );
    }
    let mut blocker = f.connection().await;
    for permitted in [true, false] {
        clear(&mut c).await;
        grant(
            &mut c,
            "a",
            "subject",
            if permitted { SUBJECT } else { "foreign" },
            &["presence:read"],
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
        let pending = tokio::spawn(async move {
            read(&worker, &trust, &token)
                .await
                .map(|p| p.policy_revision())
        });
        observe_lock(&mut c).await;
        assert!(!pending.is_finished());
        assert!(
            seconds() < expiry,
            "JWT alive when actual SQL lock observed"
        );
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
    grant(&mut c, "a", "subject", SUBJECT, &["presence:read"], &[A]).await;
    let mut short = signer.claims();
    let expiry = seconds() + 2;
    short["exp"] = json!(expiry);
    let observed = read(&store, &verifier, &signer.sign(&short)).await.unwrap();
    let remaining = (UNIX_EPOCH + Duration::from_secs(expiry))
        .duration_since(SystemTime::now())
        .unwrap_or_default();
    tokio::time::sleep(remaining + Duration::from_millis(30)).await;
    assert_eq!(
        observed.principal().check(),
        Err(BrokerAccessError::Expired)
    );
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
            Capability::Read,
            A,
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .map(|p| p.policy_revision())
    });
    observe_lock(&mut c).await;
    assert_eq!(
        pending.await.unwrap().unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    blocker.execute("COMMIT").await.unwrap();
    assert!(read(&store, &verifier, &raw).await.is_ok());
    blocker
        .execute("BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let worker = store.clone();
    let trust = verifier.clone();
    let token = raw.clone();
    let pending = tokio::spawn(async move {
        read(&worker, &trust, &token)
            .await
            .map(|p| p.policy_revision())
    });
    observe_lock(&mut c).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    blocker.execute("COMMIT").await.unwrap();
    assert!(read(&store, &verifier, &raw).await.is_ok());
    assert_eq!(
        authorize(&store, &verifier, &raw, Capability::Read, A, Instant::now())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    c.execute("GRANT SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients TO jwt_presence_owner").await.unwrap();
    let before = oracle(&mut c).await;
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        read(&store, &verifier, &raw).await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    assert!(read(&reopened, &verifier, &raw).await.is_ok());
    assert_eq!(oracle(&mut c).await, before);
    reopened.shutdown(deadline()).await.unwrap();
    blocker.close().await.unwrap();
    writer.close().await.unwrap();
    c.close().await.unwrap();
}
