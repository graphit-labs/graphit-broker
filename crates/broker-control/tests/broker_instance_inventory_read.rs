// The existing fixture serves other native control suites.
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    AuthorizedBrokerInstanceInventory, BrokerAccessError, BrokerAccessVerifier,
    BrokerInstanceInventoryReadError as Error, BrokerPresenceAuthorizationError as AuthError,
    ConnectionLimits, ControlError, InstanceInventory, InstanceProjectVersions, InstanceReadError,
    PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
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
            "jwt_inventory_owner".into(),
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
async fn read<'a>(
    store: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    raw: &str,
    id: &str,
    end: Instant,
) -> Result<AuthorizedBrokerInstanceInventory<'a>, Error> {
    let reader = store.broker_instance_inventory_reader(verifier, n(65536), n(65536))?;
    assert_eq!(
        format!("{reader:?}"),
        "PostgresBrokerInstanceInventoryReader([REDACTED])"
    );
    reader.read(raw, &["presence-sdk".into()], id, end).await
}
async fn denied(
    c: &mut PgConnection,
    store: &PostgresControlStore,
    verifier: &BrokerAccessVerifier,
    raw: &str,
    id: &str,
    expected: Error,
) {
    let before = oracle(c).await;
    assert_eq!(
        read(store, verifier, raw, id, deadline())
            .await
            .unwrap_err(),
        expected
    );
    assert_eq!(
        oracle(c).await,
        before,
        "read denial never mutates registry"
    );
}
async fn observe_lock(c: &mut PgConnection, inventory: bool) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='jwt_inventory_owner' AND wait_event_type='Lock' AND query LIKE $1)")
            .bind(if inventory {"%broker_instances%"} else {"%resource_acl_state%"}).fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(Instant::now() < end, "reader reached the actual SQL lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS, signed Native JWT and authorized registrar"]
async fn postgres_broker_instance_inventory_read_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE jwt_inventory_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION jwt_inventory_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO jwt_inventory_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let privileged: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='jwt_inventory_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!privileged);
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let raw = signer.sign(&signer.claims());
    grant(
        &mut c,
        "setup",
        "authenticated",
        "",
        &["presence:publish"],
        &["*"],
    )
    .await;
    for inventory in [
        super_inventory("station", &[B, A]),
        super_inventory("empty", &[]),
    ] {
        store
            .broker_instance_registrar(&verifier, n(65536))
            .unwrap()
            .register(&raw, &["presence-sdk".into()], &inventory, deadline())
            .await
            .unwrap();
    }
    // A foreign opaque owner is data from the existing registry, never a forged authorized proof.
    c.execute("INSERT INTO public.broker_instances(instance_id,owner_issuer,owner_subject,created_at,updated_at) VALUES('opaque','local','broker-subject',0,0)").await.unwrap();
    let initial = oracle(&mut c).await;
    let forbidden = Error::Authorization(AuthError::Forbidden);
    clear(&mut c).await;
    denied(&mut c, &store, &verifier, &raw, "station", forbidden).await;
    denied(&mut c, &store, &verifier, &raw, "missing", Error::NotFound).await;
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        "opaque",
        Error::OwnerConflict,
    )
    .await;
    grant(
        &mut c,
        "a",
        "subject",
        &format!("{ISSUER}|{SUBJECT}"),
        &["presence:read"],
        &[A],
    )
    .await;
    denied(&mut c, &store, &verifier, &raw, "station", forbidden).await;
    // Cannot combine capability/principal from one rule with project from another.
    grant(&mut c, "b", "subject", "foreign", &["presence:read"], &[B]).await;
    grant(
        &mut c,
        "half",
        "subject",
        SUBJECT,
        &["presence:publish"],
        &[B],
    )
    .await;
    denied(&mut c, &store, &verifier, &raw, "station", forbidden).await;
    c.execute("DELETE FROM public.resource_grants WHERE id IN ('b','half')")
        .await
        .unwrap();
    grant(&mut c, "b", "user", "alice", &["presence:read"], &[B]).await;
    let observed = read(&store, &verifier, &raw, "station", deadline())
        .await
        .unwrap();
    assert_eq!(observed.inventory(), &super_inventory("station", &[A, B]));
    assert!(observed.created_at_micros() > 0);
    assert!(observed.updated_at_micros() > 0);
    assert_eq!(
        format!("{observed:?}"),
        "AuthorizedBrokerInstanceInventory([REDACTED])"
    );
    let revision = observed.policy_revision();
    denied(&mut c, &store, &verifier, &raw, "empty", forbidden).await;
    // Empty Any selectors are explicit; finite selectors do not authorize empty parents.
    for projects in [vec![], vec!["*"]] {
        clear(&mut c).await;
        grant(
            &mut c,
            "a",
            "subject",
            SUBJECT,
            &["presence:read"],
            &projects,
        )
        .await;
        assert!(
            read(&store, &verifier, &raw, "empty", deadline())
                .await
                .unwrap()
                .inventory()
                .projects()
                .is_empty()
        );
    }
    let mut foreign = signer.claims();
    foreign["sub"] = json!("other-subject");
    denied(
        &mut c,
        &store,
        &verifier,
        &signer.sign(&foreign),
        "station",
        Error::OwnerConflict,
    )
    .await;
    let other_issuer = "https://other.example.test";
    let other_verifier = BrokerAccessVerifier::new(
        other_issuer,
        "presence-api",
        Some(RESOURCE),
        &signer.keys,
        n(8192),
    )
    .unwrap();
    foreign = signer.claims();
    foreign["iss"] = json!(other_issuer);
    denied(
        &mut c,
        &store,
        &other_verifier,
        &signer.sign(&foreign),
        "station",
        Error::OwnerConflict,
    )
    .await;
    assert_eq!(oracle(&mut c).await, initial);
    // Fresh committed policy and inventory observations; pending changes remain invisible.
    let mut writer = f.connection().await;
    writer.execute("BEGIN; DELETE FROM public.resource_grants; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1; DELETE FROM public.broker_instance_project_versions WHERE instance_id='station' AND project_id='01D39ZY06FGSCTVN4T2V9PKHG0'").await.unwrap();
    assert_eq!(
        read(&store, &verifier, &raw, "station", deadline())
            .await
            .unwrap()
            .inventory()
            .projects()
            .len(),
        2
    );
    writer.execute("COMMIT").await.unwrap();
    denied(&mut c, &store, &verifier, &raw, "station", forbidden).await;
    grant(&mut c, "a", "user", "alice", &["presence:read"], &[A]).await;
    let changed = read(&store, &verifier, &raw, "station", deadline())
        .await
        .unwrap();
    assert_eq!(changed.inventory().projects().len(), 1);
    assert!(changed.policy_revision() > revision);
    // Whole invalid policy fails even for absence/foreign and unmatched rules.
    grant(&mut c, "bad", "team", "[", &["presence:read"], &[B]).await;
    for id in ["station", "missing", "opaque"] {
        denied(
            &mut c,
            &store,
            &verifier,
            &raw,
            id,
            Error::Authorization(AuthError::InvalidPolicy),
        )
        .await;
    }
    c.execute("DELETE FROM public.resource_grants WHERE id='bad'")
        .await
        .unwrap();
    // An actual stored OIDC identity is disabled/revoked and made inaccessible.
    // This cannot remap the cryptographically signed Native window.
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','original-subject','human','','Old','','old','[]',1,0,1,0,0); INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('approved-client','Fixture','[\"https://client.example.test/callback\"]','[\"presence-sdk\"]','web',0)").await.unwrap();
    let digest = support::digester()
        .token(TokenKind::OidcStoredAccess, JTI.as_bytes())
        .unwrap();
    let stored=json!({"issuer":"local","subject":"original-subject","username":"alice","auth_method":"oidc","local_user_revision":1,"name":"Old","email":null,"organization":"old","teams":[],"scopes":["presence-sdk"],"roles":[],"roles_from_claim":false,"role_claim_selector":""}).to_string();
    sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,'oidc_access','original-subject','broker-subject',$3,'approved-client','presence-api','https://broker.example.test/v1','[\"presence-sdk\"]',1,'',0,9223372036854775807,0)")
        .bind(digest.to_sql_hex()).bind(JTI).bind(stored).execute(&mut c).await.unwrap();
    assert!(
        read(&store, &verifier, &raw, "station", deadline())
            .await
            .is_ok()
    );
    c.execute("UPDATE public.local_users SET enabled=0,revision=2,organization='changed',teams_json='[]'; UPDATE public.local_tokens SET revoked_at=1,expires_at=0,principal_json='{}'; DELETE FROM public.oauth_dynamic_clients; REVOKE SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients FROM jwt_inventory_owner").await.unwrap();
    for table in ["local_users", "local_tokens", "oauth_dynamic_clients"] {
        let allowed: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT has_table_privilege('jwt_inventory_owner',$1,'SELECT')",
        )
        .bind(format!("public.{table}"))
        .fetch_one(&mut c)
        .await
        .unwrap();
        assert!(!allowed);
    }
    assert!(
        read(&store, &verifier, &raw, "station", deadline())
            .await
            .is_ok()
    );
    clear(&mut c).await;
    denied(&mut c, &store, &verifier, &raw, "station", forbidden).await;
    grant(&mut c, "a", "subject", SUBJECT, &["presence:read"], &["*"]).await;
    c.execute("REVOKE SELECT ON public.resource_grants FROM jwt_inventory_owner")
        .await
        .unwrap();
    for bad in ["bad", "opaque-local-token"] {
        denied(
            &mut c,
            &store,
            &verifier,
            bad,
            "station",
            Error::Authorization(AuthError::Authentication(BrokerAccessError::InvalidToken)),
        )
        .await;
    }
    for (field, value, expected) in [
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
            "station",
            Error::Authorization(AuthError::Authentication(expected)),
        )
        .await;
    }
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        "missing",
        Error::Authorization(AuthError::Control(ControlError::Storage)),
    )
    .await;
    c.execute("GRANT SELECT ON public.resource_grants TO jwt_inventory_owner; REVOKE SELECT ON public.broker_instance_project_versions FROM jwt_inventory_owner").await.unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        "station",
        Error::Inventory(InstanceReadError::Control(ControlError::Storage)),
    )
    .await;
    c.execute("GRANT SELECT ON public.broker_instance_project_versions TO jwt_inventory_owner")
        .await
        .unwrap();
    let before = oracle(&mut c).await;
    for (grants, inventory, expected) in [
        (
            1,
            65536,
            Error::Authorization(AuthError::Grants(ResourceGrantReadError::ReadLimitExceeded)),
        ),
        (
            65536,
            1,
            Error::Inventory(InstanceReadError::ReadLimitExceeded),
        ),
    ] {
        assert_eq!(
            store
                .broker_instance_inventory_reader(&verifier, n(grants), n(inventory))
                .unwrap()
                .read(&raw, &["presence-sdk".into()], "station", deadline())
                .await
                .unwrap_err(),
            expected
        );
    }
    assert_eq!(oracle(&mut c).await, before);
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        "invalid/id",
        Error::Inventory(InstanceReadError::InvalidInstanceId),
    )
    .await;
    c.execute("UPDATE public.broker_instance_project_versions SET position=position+3 WHERE instance_id='station'").await.unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        "station",
        Error::Inventory(InstanceReadError::MalformedStored),
    )
    .await;
    c.execute("UPDATE public.broker_instance_project_versions SET position=position-3 WHERE instance_id='station'").await.unwrap();
    // UTC expiry wins over allowed/denied/missing/foreign/empty logical decisions
    // after a causally observed wait in either SQL reader.
    let mut blocker = f.connection().await;
    for (inventory, id, permitted) in [
        (false, "station", true),
        (false, "station", false),
        (true, "station", true),
        (true, "station", false),
        (true, "missing", true),
        (true, "opaque", true),
        (true, "empty", true),
    ] {
        clear(&mut c).await;
        grant(
            &mut c,
            "a",
            "subject",
            if permitted { SUBJECT } else { "foreign" },
            &["presence:read"],
            &["*"],
        )
        .await;
        let before = oracle(&mut c).await;
        let expiry = seconds() + 4;
        let mut short = signer.claims();
        short["exp"] = json!(expiry);
        let token = signer.sign(&short);
        blocker
            .execute(if inventory {
                "BEGIN; LOCK TABLE public.broker_instances IN ACCESS EXCLUSIVE MODE"
            } else {
                "BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE"
            })
            .await
            .unwrap();
        let worker = store.clone();
        let trust = verifier.clone();
        let pending = tokio::spawn(async move {
            read(&worker, &trust, &token, id, deadline())
                .await
                .map(|_| ())
        });
        observe_lock(&mut c, inventory).await;
        assert!(!pending.is_finished());
        assert!(
            seconds() < expiry,
            "signed JWT reached SQL wait while alive"
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
    grant(&mut c, "a", "subject", SUBJECT, &["presence:read"], &["*"]).await;
    for inventory in [false, true] {
        for cancel in [false, true] {
            let before = oracle(&mut c).await;
            blocker
                .execute(if inventory {
                    "BEGIN; LOCK TABLE public.broker_instances IN ACCESS EXCLUSIVE MODE"
                } else {
                    "BEGIN; LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE"
                })
                .await
                .unwrap();
            let worker = store.clone();
            let trust = verifier.clone();
            let token = raw.clone();
            let pending = tokio::spawn(async move {
                read(
                    &worker,
                    &trust,
                    &token,
                    "station",
                    Instant::now() + Duration::from_secs(2),
                )
                .await
                .map(|_| ())
            });
            observe_lock(&mut c, inventory).await;
            if cancel {
                pending.abort();
                assert!(pending.await.unwrap_err().is_cancelled());
            } else {
                assert_eq!(
                    pending.await.unwrap().unwrap_err(),
                    if inventory {
                        Error::Inventory(InstanceReadError::Control(ControlError::Deadline))
                    } else {
                        Error::Authorization(AuthError::Control(ControlError::Deadline))
                    }
                );
            }
            blocker.execute("COMMIT").await.unwrap();
            assert_eq!(oracle(&mut c).await, before);
            assert!(
                read(&store, &verifier, &raw, "station", deadline())
                    .await
                    .is_ok()
            );
        }
    }
    assert_eq!(
        read(&store, &verifier, &raw, "empty", Instant::now())
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::Deadline))
    );
    let before = oracle(&mut c).await;
    store.shutdown(deadline()).await.unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        "station",
        Error::Authorization(AuthError::Control(ControlError::Closed)),
    )
    .await;
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    assert!(
        read(&reopened, &verifier, &raw, "station", deadline())
            .await
            .is_ok()
    );
    assert_eq!(oracle(&mut c).await, before);
    reopened.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
