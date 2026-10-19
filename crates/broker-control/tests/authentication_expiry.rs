#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessError, BrokerAccessVerifier, BrokerPresenceAuthorizationError as Native,
    ConnectionLimits, ControlError, InstanceInventory, InstanceProjectVersions,
    LocalBearerVerificationError, NowChannelAuthorizationError as ChannelError, PostgresConfig,
    PostgresControlStore, PostgresCredentials, PostgresEndpoint,
    PresenceAuthorizationError as Local, PresenceChannel, StorageAdmissionError, StorageModule,
    StorageScope,
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
            "now_channel_owner".into(),
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
const LOCAL_RAW: &str = "gb_at_now-access";
const SERVICE_RAW: &str = "gb_sc_now-service";
const SCOPES: &[&str] = &["presence-sdk"];
fn scopes() -> Vec<String> {
    SCOPES.iter().map(|s| (*s).into()).collect()
}
fn channel(id: &str, project: &str, version: &str) -> PresenceChannel {
    PresenceChannel::new(id, project, version).unwrap()
}
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
async fn local_tokens(c: &mut PgConnection) {
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Alice','','org','[\"dev\"]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','org','[]',1,0,1,0,0)").await.unwrap();
    for (raw, kind, id, kind_name, subject) in [
        (
            LOCAL_RAW,
            TokenKind::LocalAccess,
            "now-access",
            "access",
            "alice-subject",
        ),
        (
            SERVICE_RAW,
            TokenKind::ServiceCredential,
            "now-service",
            "service",
            "bot-subject",
        ),
    ] {
        let digest = support::digester().token(kind, raw.as_bytes()).unwrap();
        let principal=json!({"issuer":"local","subject":subject,"username":"stale","auth_method":"old","local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'envelope',$5,'client','explicit-audience','','[\"presence-sdk\"]',1,'',0,$6,0)")
            .bind(digest.to_sql_hex()).bind(id).bind(kind_name).bind(subject).bind(principal).bind(now()+600_000_000).execute(&mut *c).await.unwrap();
    }
}
async fn observe_wait(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='now_channel_owner' AND wait_event_type='Lock' AND query LIKE '%local_tokens%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(Instant::now() < end, "real verifier reached SQL lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS verifier latency, opaque digests and Ed25519 temporal pair"]
async fn authentication_expiry_postgres_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE now_channel_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION now_channel_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO now_channel_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='now_channel_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    local_tokens(&mut c).await;
    let mut blocker = f.connection().await;
    for (raw, id) in [(LOCAL_RAW, "now-access"), (SERVICE_RAW, "now-service")] {
        let expiry = now() + 4_000_000;
        sqlx_core::query::query("UPDATE public.local_tokens SET expires_at=$1 WHERE token_id=$2")
            .bind(expiry)
            .bind(id)
            .execute(&mut c)
            .await
            .unwrap();
        blocker
            .execute("BEGIN; LOCK TABLE public.local_tokens IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let holder = store.clone();
        let start = Instant::now();
        let verification = tokio::spawn(async move {
            holder
                .local_bearer_verifier("explicit-audience", n(16384))
                .unwrap()
                .verify(raw, &scopes(), deadline())
                .await
        });
        observe_wait(&mut c).await;
        tokio::time::sleep(Duration::from_millis(2250)).await;
        blocker.execute("COMMIT").await.unwrap();
        let proof = verification.await.unwrap().unwrap();
        let pair = proof.authentication_expiry();
        assert_eq!(
            pair.0,
            UNIX_EPOCH + Duration::from_micros(u64::try_from(expiry).unwrap())
        );
        assert!(
            pair.0 > SystemTime::now() && pair.1 > Instant::now(),
            "a still-valid credential survives actual SQL latency"
        );
        let remaining =
            u64::try_from(proof.expires_at().as_i64() - proof.verified_at().as_i64()).unwrap();
        assert!(
            start + Duration::from_micros(remaining) < Instant::now(),
            "the rejected pre-whole-verify anchor would prematurely expire this proof"
        );
        assert_eq!(proof.scopes(), SCOPES);
        assert_eq!(proof.current_local_user().issuer(), "local");
        assert_eq!(
            proof.auth_method(),
            if raw == LOCAL_RAW {
                "local-token"
            } else {
                "service-credential"
            }
        );
        assert_eq!(format!("{proof:?}"), "VerifiedLocalBearer([REDACTED])");
        tokio::time::sleep_until(pair.1.into()).await;
        assert!(Instant::now() >= pair.1);
        // The clocks are sampled in order, not simultaneously. A new verifier
        // observes UTC independently, so witness its bound before fresh denial.
        let utc_wait = deadline();
        while SystemTime::now() < pair.0 {
            assert!(Instant::now() < utc_wait, "actual UTC expiry observed");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            store
                .local_bearer_verifier("explicit-audience", n(16384))
                .unwrap()
                .verify(raw, &scopes(), deadline())
                .await
                .unwrap_err(),
            LocalBearerVerificationError::Unauthenticated
        );
    }
    sqlx_core::query::query("UPDATE public.local_tokens SET expires_at=$1")
        .bind(now() + 60_000_000)
        .execute(&mut c)
        .await
        .unwrap();
    let signer = Signer::new();
    let verifier = signer.verifier();
    let claims = signer.claims();
    let raw = signer.sign(&claims);
    let principal = verifier.verify(&raw, &scopes(), deadline()).unwrap();
    let actual = principal.authentication_expiry();
    assert_eq!(actual.0, principal.expires_at());
    assert!(actual.1 > Instant::now());
    principal.check().unwrap();
    let expires = actual.0.duration_since(UNIX_EPOCH).unwrap().as_secs();
    assert_eq!(expires, claims["exp"].as_u64().unwrap());
    assert_eq!(
        verifier
            .verify(LOCAL_RAW, &scopes(), deadline())
            .unwrap_err(),
        BrokerAccessError::InvalidToken
    );
    assert_eq!(
        store
            .local_bearer_verifier("explicit-audience", n(16384))
            .unwrap()
            .verify(&raw, &scopes(), deadline())
            .await
            .unwrap_err(),
        LocalBearerVerificationError::Unauthenticated
    );
    // Actual Now and storage consumers use the producer pair, with their own Original.
    grant(
        &mut c,
        "temporal",
        "authenticated",
        "",
        &[
            "presence:read",
            "presence:publish",
            "task:read",
            "memory:read",
            "knowledge:read",
            "s3",
        ],
        &[A, B],
    )
    .await;
    for prefix in [
        &format!("v1/projects/{A}/registry"),
        &format!("v1/projects/{A}/artifacts"),
    ] {
        sqlx_core::query::query(
            "INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES('temporal',$1)",
        )
        .bind(prefix)
        .execute(&mut c)
        .await
        .unwrap();
    }
    store
        .local_instance_registrar("explicit-audience", n(16384), n(65536))
        .unwrap()
        .register(
            LOCAL_RAW,
            &scopes(),
            &super_inventory("local", &[A]),
            deadline(),
        )
        .await
        .unwrap();
    let ch = channel("local", A, "main");
    let end = Instant::now() + Duration::from_millis(500);
    let now_proof = store
        .local_now_channel_authorizer("explicit-audience", n(16384), n(65536), n(65536))
        .unwrap()
        .authorize_read(LOCAL_RAW, &scopes(), &ch, end)
        .await
        .unwrap();
    let (utc, mono) = now_proof.authentication_expiry();
    assert!(utc > SystemTime::now() && mono > Instant::now());
    let local_storage = store
        .local_storage_authorizer("explicit-audience", n(16384), n(65536), "explicit-route")
        .unwrap();
    let storage = local_storage
        .authorize(
            LOCAL_RAW,
            &scopes(),
            &StorageScope::project(A, StorageModule::Hub).unwrap(),
            end,
        )
        .await
        .unwrap();
    assert_eq!(storage.request_deadline(), end);
    storage.check().unwrap();
    tokio::time::sleep_until(end.into()).await;
    assert_eq!(
        now_proof.check().unwrap_err(),
        ChannelError::Local(Local::Control(ControlError::Deadline))
    );
    assert_eq!(
        storage.check().unwrap_err(),
        StorageAdmissionError::Deadline
    );
    let end = Instant::now() + Duration::from_millis(500);
    let native_storage = store
        .broker_storage_authorizer(&verifier, n(65536), "explicit-route")
        .unwrap();
    let native = native_storage
        .authorize(
            &raw,
            &scopes(),
            &StorageScope::project(A, StorageModule::Hub).unwrap(),
            end,
        )
        .await
        .unwrap();
    assert_eq!(native.request_deadline(), end);
    native.check().unwrap();
    let native_project = store
        .broker_now_channel_authorizer(&verifier, n(65536), n(65536))
        .unwrap()
        .authorize_subscriber_project(&raw, &scopes(), A, end)
        .await
        .unwrap();
    assert_eq!(native_project.authentication_expiry().0, actual.0);
    tokio::time::sleep_until(end.into()).await;
    assert_eq!(
        native_project.check().unwrap_err(),
        ChannelError::Native(Native::Control(ControlError::Deadline))
    );
    assert_eq!(native.check().unwrap_err(), StorageAdmissionError::Deadline);
    // Original cancels a real SQL wait; it never grants a renewed authentication window.
    blocker
        .execute("BEGIN; LOCK TABLE public.local_tokens IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let end = Instant::now() + Duration::from_millis(250);
    assert_eq!(
        store
            .local_bearer_verifier("explicit-audience", n(16384))
            .unwrap()
            .verify(LOCAL_RAW, &scopes(), end)
            .await
            .unwrap_err(),
        LocalBearerVerificationError::Control(ControlError::Deadline)
    );
    blocker.execute("COMMIT").await.unwrap();
    store
        .local_bearer_verifier("explicit-audience", n(16384))
        .unwrap()
        .verify(LOCAL_RAW, &scopes(), deadline())
        .await
        .unwrap();
    store.shutdown(deadline()).await.unwrap();
    blocker.close().await.unwrap();
    c.close().await.unwrap();
}
