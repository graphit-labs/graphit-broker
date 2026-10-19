// The existing fixture serves other native control suites.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessError, BrokerAccessVerifier, BrokerInstanceRegistrationError as Error,
    BrokerPresenceAuthorizationError as AuthError, ConnectionLimits, ControlError,
    InstanceInventory, InstanceProjectVersions, InstanceRegistryError, PostgresConfig,
    PostgresControlStore, PostgresCredentials, PostgresEndpoint, RegistrationChange,
    RegistrationResult, ResourceGrantReadError,
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
            "jwt_registry_owner".into(),
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
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('instances',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.broker_instances ORDER BY instance_id COLLATE \"C\") t),'versions',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.broker_instance_project_versions ORDER BY instance_id COLLATE \"C\",project_id COLLATE \"C\",position) t))::text").fetch_one(c).await.unwrap()
}
fn super_inventory(id: &str, projects: &[&str]) -> InstanceInventory {
    InstanceInventory::new(
        id.into(),
        projects
            .iter()
            .map(|p| {
                InstanceProjectVersions::new((*p).into(), vec!["main".into(), "branch/ação".into()])
                    .unwrap()
            })
            .collect(),
    )
    .unwrap()
}
async fn register(
    store: &PostgresControlStore,
    verifier: &BrokerAccessVerifier,
    raw: &str,
    inventory: &InstanceInventory,
    end: Instant,
) -> Result<RegistrationResult, Error> {
    let registrar = store.broker_instance_registrar(verifier, n(65536))?;
    assert_eq!(
        format!("{registrar:?}"),
        "PostgresBrokerInstanceRegistrar([REDACTED])"
    );
    registrar
        .register(raw, &["presence-sdk".into()], inventory, end)
        .await
}
async fn denied(
    c: &mut PgConnection,
    store: &PostgresControlStore,
    verifier: &BrokerAccessVerifier,
    raw: &str,
    inventory: &InstanceInventory,
    expected: Error,
) {
    let before = oracle(c).await;
    assert_eq!(
        register(store, verifier, raw, inventory, deadline())
            .await
            .unwrap_err(),
        expected
    );
    assert_eq!(
        oracle(c).await,
        before,
        "prewrite rejection must leave whole inventory unchanged"
    );
}
async fn observe_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='jwt_registry_owner' AND wait_event_type='Lock' AND query LIKE '%resource_acl_state%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(
            Instant::now() < end,
            "Native registrar reached actual ACL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS, signed Native JWT and atomic inventory writer"]
async fn postgres_broker_instance_registration_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE jwt_registry_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION jwt_registry_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO jwt_registry_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let privileged: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='jwt_registry_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!privileged);
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let raw = signer.sign(&signer.claims());
    let inventory = super_inventory("native-owner", &[B, A]);
    let forbidden = Error::Authorization(AuthError::Forbidden);
    clear(&mut c).await;
    grant(
        &mut c,
        "a",
        "subject",
        &format!("{ISSUER}|{SUBJECT}"),
        &["presence:publish"],
        &[A],
    )
    .await;
    denied(&mut c, &store, &verifier, &raw, &inventory, forbidden).await;
    grant(&mut c, "b", "subject", SUBJECT, &["presence:publish"], &[B]).await;
    let created = register(&store, &verifier, &raw, &inventory, deadline())
        .await
        .unwrap();
    assert_eq!(created.change(), RegistrationChange::Created);
    let owner:(String,String)=sqlx_core::query_as::query_as("SELECT owner_issuer,owner_subject FROM public.broker_instances WHERE instance_id='native-owner'").fetch_one(&mut c).await.unwrap();
    assert_eq!(owner, (ISSUER.into(), SUBJECT.into()));
    assert_eq!(created.created_at_micros(), created.updated_at_micros());
    let before = oracle(&mut c).await;
    let noop = register(&store, &verifier, &raw, &inventory, deadline())
        .await
        .unwrap();
    assert_eq!(noop.change(), RegistrationChange::Unchanged);
    assert_eq!(noop.created_at_micros(), created.created_at_micros());
    assert_eq!(noop.updated_at_micros(), created.updated_at_micros());
    assert_eq!(oracle(&mut c).await, before);
    let replacement = super_inventory("native-owner", &[A]);
    let updated = register(&store, &verifier, &raw, &replacement, deadline())
        .await
        .unwrap();
    assert_eq!(updated.change(), RegistrationChange::Updated);
    assert_eq!(updated.created_at_micros(), created.created_at_micros());
    assert!(updated.updated_at_micros() >= created.updated_at_micros());
    let rows:Vec<(String,i64,String)>=sqlx_core::query_as::query_as("SELECT project_id,position,version FROM public.broker_instance_project_versions WHERE instance_id='native-owner' ORDER BY project_id COLLATE \"C\",position").fetch_all(&mut c).await.unwrap();
    assert_eq!(
        rows,
        vec![
            (A.into(), 1, "branch/ação".into()),
            (A.into(), 2, "main".into())
        ]
    );
    // Same rule must match identity, capability AND project; no cross-grant join.
    for (kind, principal, caps, projects) in [
        ("subject", "foreign", vec!["presence:publish"], vec![A, B]),
        ("subject", SUBJECT, vec!["presence:read"], vec![A, B]),
        (
            "authenticated",
            "",
            vec!["hub", "s3:*", "task:*", "memory:*", "knowledge:*"],
            vec![A, B],
        ),
        ("anonymous", "", vec!["presence:publish"], vec![A, B]),
    ] {
        clear(&mut c).await;
        grant(&mut c, "a", kind, principal, &caps, &projects).await;
        let mut purpose = signer.claims();
        purpose["scope"] = json!("presence-sdk presence:publish");
        denied(
            &mut c,
            &store,
            &verifier,
            &signer.sign(&purpose),
            &inventory,
            forbidden,
        )
        .await;
    }
    clear(&mut c).await;
    grant(&mut c, "a", "subject", SUBJECT, &["presence:read"], &[A, B]).await;
    grant(
        &mut c,
        "b",
        "subject",
        "foreign",
        &["presence:publish"],
        &[A, B],
    )
    .await;
    denied(&mut c, &store, &verifier, &raw, &inventory, forbidden).await;
    for (kind, principal) in [
        ("user", "alice"),
        ("team", "dev"),
        ("organization", "engineering"),
        ("authenticated", ""),
        ("global", ""),
    ] {
        clear(&mut c).await;
        grant(&mut c, "a", kind, principal, &["presence:publish"], &[A, B]).await;
        assert!(
            register(&store, &verifier, &raw, &inventory, deadline())
                .await
                .is_ok()
        );
    }
    // Removing signed optional identity claims does not invent SQL identity.
    for (kind, principal, field) in [
        ("user", "alice", "preferred_username"),
        ("team", "dev", "groups"),
        ("organization", "engineering", "organization"),
    ] {
        clear(&mut c).await;
        grant(&mut c, "a", kind, principal, &["presence:publish"], &[A, B]).await;
        let mut minimal = signer.claims();
        minimal.as_object_mut().unwrap().remove(field);
        denied(
            &mut c,
            &store,
            &verifier,
            &signer.sign(&minimal),
            &inventory,
            forbidden,
        )
        .await;
    }
    // Empty inventory still needs explicit Any Publish (empty selector or '*').
    let empty = super_inventory("native-owner", &[]);
    clear(&mut c).await;
    grant(
        &mut c,
        "a",
        "subject",
        SUBJECT,
        &["presence:publish"],
        &[A, B],
    )
    .await;
    denied(&mut c, &store, &verifier, &raw, &empty, forbidden).await;
    for projects in [vec![], vec!["*"]] {
        clear(&mut c).await;
        grant(
            &mut c,
            "a",
            "subject",
            SUBJECT,
            &["presence:publish"],
            &projects,
        )
        .await;
        assert!(
            register(&store, &verifier, &raw, &inventory, deadline())
                .await
                .is_ok()
        );
        let cleared = register(&store, &verifier, &raw, &empty, deadline())
            .await
            .unwrap();
        assert_eq!(cleared.change(), RegistrationChange::Updated);
        assert_eq!(cleared.created_at_micros(), created.created_at_micros());
        assert_eq!(
            register(&store, &verifier, &raw, &empty, deadline())
                .await
                .unwrap()
                .change(),
            RegistrationChange::Unchanged
        );
    }
    assert_eq!(
        register(
            &store,
            &verifier,
            &raw,
            &super_inventory("first-empty", &[]),
            deadline()
        )
        .await
        .unwrap()
        .change(),
        RegistrationChange::Created
    );
    // Literal Native issuer/sub pair cannot take over either a local or foreign owner.
    clear(&mut c).await;
    grant(
        &mut c,
        "a",
        "authenticated",
        "",
        &["presence:publish"],
        &["*"],
    )
    .await;
    let mut other = signer.claims();
    other["sub"] = json!("other-subject");
    denied(
        &mut c,
        &store,
        &verifier,
        &signer.sign(&other),
        &inventory,
        Error::Registry(InstanceRegistryError::OwnerConflict),
    )
    .await;
    let foreign_issuer = "https://other.example.test";
    let other_verifier = BrokerAccessVerifier::new(
        foreign_issuer,
        "presence-api",
        Some(RESOURCE),
        &signer.keys,
        n(8192),
    )
    .unwrap();
    other = signer.claims();
    other["iss"] = json!(foreign_issuer);
    denied(
        &mut c,
        &store,
        &other_verifier,
        &signer.sign(&other),
        &inventory,
        Error::Registry(InstanceRegistryError::OwnerConflict),
    )
    .await;
    c.execute("INSERT INTO public.broker_instances(instance_id,owner_issuer,owner_subject,created_at,updated_at) VALUES('local-owned','local','broker-subject',0,0)").await.unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        &super_inventory("local-owned", &[A]),
        Error::Registry(InstanceRegistryError::OwnerConflict),
    )
    .await;
    // Current whole policy is read on every call; uncommitted changes stay invisible.
    clear(&mut c).await;
    grant(&mut c, "a", "user", "alice", &["presence:publish"], &[A, B]).await;
    let mut writer = f.connection().await;
    writer.execute("BEGIN; DELETE FROM public.grant_capabilities WHERE grant_id='a'; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    assert!(
        register(&store, &verifier, &raw, &inventory, deadline())
            .await
            .is_ok()
    );
    writer.execute("COMMIT").await.unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        &inventory,
        Error::Authorization(AuthError::InvalidPolicy),
    )
    .await;
    c.execute("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a','presence:read'); UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    denied(&mut c, &store, &verifier, &raw, &inventory, forbidden).await;
    c.execute("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a','presence:publish'); UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','original-subject','human','','Old','','old','[\"old\"]',1,0,1,0,0); INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('approved-client','Fixture','[\"https://client.example.test/callback\"]','[\"presence-sdk\"]','web',0)").await.unwrap();
    let digest = support::digester()
        .token(TokenKind::OidcStoredAccess, JTI.as_bytes())
        .unwrap();
    let stored=json!({"issuer":"local","subject":"original-subject","username":"alice","auth_method":"oidc","local_user_revision":1,
        "name":"Old","email":null,"organization":"old","teams":["old"],"scopes":["presence-sdk"],
        "roles":[],"roles_from_claim":false,"role_claim_selector":""}).to_string();
    sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,'oidc_access','original-subject','broker-subject',$3,'approved-client','presence-api','https://broker.example.test/v1','[\"presence-sdk\"]',1,'',0,9223372036854775807,0)")
        .bind(digest.to_sql_hex()).bind(JTI).bind(stored).execute(&mut c).await.unwrap();
    assert!(
        register(&store, &verifier, &raw, &inventory, deadline())
            .await
            .is_ok()
    );
    c.execute("UPDATE public.local_users SET enabled=0,revision=2,organization='changed',teams_json='[]' WHERE username='alice'; UPDATE public.local_tokens SET revoked_at=1,expires_at=0,principal_json='{}' WHERE token_id='jwt-native-token'; DELETE FROM public.oauth_dynamic_clients WHERE client_id='approved-client'; REVOKE SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients FROM jwt_registry_owner").await.unwrap();
    for table in ["local_users", "local_tokens", "oauth_dynamic_clients"] {
        let permitted: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT has_table_privilege('jwt_registry_owner',$1,'SELECT')",
        )
        .bind(format!("public.{table}"))
        .fetch_one(&mut c)
        .await
        .unwrap();
        assert!(!permitted);
    }
    assert!(
        register(&store, &verifier, &raw, &inventory, deadline())
            .await
            .is_ok()
    );

    c.execute("REVOKE SELECT ON public.grant_capabilities FROM jwt_registry_owner")
        .await
        .unwrap();
    for bad in ["bad", "opaque-local-token"] {
        denied(
            &mut c,
            &store,
            &verifier,
            bad,
            &inventory,
            Error::Authorization(AuthError::Authentication(BrokerAccessError::InvalidToken)),
        )
        .await;
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
        ("token_use", json!("id"), BrokerAccessError::InvalidToken),
    ] {
        let mut invalid = signer.claims();
        invalid[field] = value;
        denied(
            &mut c,
            &store,
            &verifier,
            &signer.sign(&invalid),
            &inventory,
            Error::Authorization(AuthError::Authentication(error)),
        )
        .await;
    }
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        &inventory,
        Error::Authorization(AuthError::Control(ControlError::Storage)),
    )
    .await;
    c.execute("GRANT SELECT ON public.grant_capabilities TO jwt_registry_owner")
        .await
        .unwrap();
    let before = oracle(&mut c).await;
    assert_eq!(
        store
            .broker_instance_registrar(&verifier, n(1))
            .unwrap()
            .register(&raw, &["presence-sdk".into()], &inventory, deadline())
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Grants(ResourceGrantReadError::ReadLimitExceeded))
    );
    assert_eq!(oracle(&mut c).await, before);
    grant(&mut c, "z", "team", "[", &["presence:publish"], &[B]).await;
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        &inventory,
        Error::Authorization(AuthError::InvalidPolicy),
    )
    .await;
    c.execute("DELETE FROM public.resource_grants WHERE id='z'; DELETE FROM public.resource_acl_state WHERE id=1").await.unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        &inventory,
        Error::Authorization(AuthError::Grants(ResourceGrantReadError::MalformedStored)),
    )
    .await;
    c.execute("INSERT INTO public.resource_acl_state(id,revision,updated_at) VALUES(1,1,0)")
        .await
        .unwrap();
    let mut blocker = f.connection().await;
    for permitted in [true, false] {
        clear(&mut c).await;
        grant(
            &mut c,
            "a",
            "subject",
            if permitted { SUBJECT } else { "foreign" },
            &["presence:publish"],
            &[A, B],
        )
        .await;
        let before = oracle(&mut c).await;
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
        let input = super_inventory("expired-before-write", &[A, B]);
        let pending =
            tokio::spawn(
                async move { register(&worker, &trust, &token, &input, deadline()).await },
            );
        observe_lock(&mut c).await;
        assert!(!pending.is_finished());
        assert!(
            seconds() < expiry,
            "JWT alive at causally observed SQL wait"
        );
        let remaining = (UNIX_EPOCH + Duration::from_secs(expiry))
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        tokio::time::sleep(remaining + Duration::from_millis(30)).await;
        blocker.execute("COMMIT").await.unwrap();
        assert_eq!(
            pending.await.unwrap().unwrap_err(),
            Error::Authorization(AuthError::Authentication(BrokerAccessError::Expired))
        );
        assert_eq!(oracle(&mut c).await, before);
    }
    clear(&mut c).await;
    grant(
        &mut c,
        "a",
        "subject",
        SUBJECT,
        &["presence:publish"],
        &[A, B],
    )
    .await;
    for cancel in [false, true] {
        let before = oracle(&mut c).await;
        blocker
            .execute("BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let worker = store.clone();
        let trust = verifier.clone();
        let token = raw.clone();
        let input = super_inventory("interrupted-before-write", &[A, B]);
        let pending = tokio::spawn(async move {
            register(
                &worker,
                &trust,
                &token,
                &input,
                Instant::now() + Duration::from_secs(2),
            )
            .await
        });
        observe_lock(&mut c).await;
        if cancel {
            pending.abort();
            assert!(pending.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(
                pending.await.unwrap().unwrap_err(),
                Error::Authorization(AuthError::Control(ControlError::Deadline))
            );
        }
        blocker.execute("COMMIT").await.unwrap();
        assert_eq!(oracle(&mut c).await, before);
        assert!(
            register(&store, &verifier, &raw, &inventory, deadline())
                .await
                .is_ok()
        );
    }
    let before = oracle(&mut c).await;
    assert_eq!(
        register(&store, &verifier, &raw, &inventory, Instant::now())
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::Deadline))
    );
    assert_eq!(oracle(&mut c).await, before);
    c.execute("GRANT SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients TO jwt_registry_owner").await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        &inventory,
        Error::Authorization(AuthError::Control(ControlError::Closed)),
    )
    .await;
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    assert!(
        register(&reopened, &verifier, &raw, &inventory, deadline())
            .await
            .is_ok()
    );
    assert_eq!(oracle(&mut c).await, before);
    reopened.shutdown(deadline()).await.unwrap();
    blocker.close().await.unwrap();
    writer.close().await.unwrap();
    c.close().await.unwrap();
}
