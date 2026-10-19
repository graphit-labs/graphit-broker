#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessError, BrokerAccessVerifier, BrokerPresenceAuthorizationError as Native,
    ConnectionLimits, ControlError, InstanceInventory, InstanceProjectVersions, InstanceReadError,
    LocalBearerVerificationError, NowChannelAuthorizationError as Error, PostgresConfig,
    PostgresControlStore, PostgresCredentials, PostgresEndpoint, PostgresNowChannelAuthorizer,
    PresenceAuthorizationError as Local, PresenceChannel,
};
use broker_now_wire::NowSnapshotData;
use broker_presence::{RealtimeHub, RealtimeHubError as HubError, RealtimeHubSignalError};
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
fn data(project: &str) -> NowSnapshotData {
    let actor = "a".repeat(64);
    let available = |items: Value| json!({"availability":"available","total":items.as_array().unwrap().len(),"items":items,"has_more":false,"error":null});
    let wire = json!({"project_id":project,"generated_at":"1000000","sections":{
        "tasks":available(json!([{"id":A,"session_id":B,"title":"Task","owner":actor,"lease_expires_at":"2000000","updated_at":"1000000"}])),
        "sessions":available(json!([{"id":B,"title":"Session","owner":actor,"lease_expires_at":"2000000","updated_at":"1000000","completed_tasks":1,"total_tasks":2}])),
        "memories":available(json!([{"id":A,"title":" memory ","updated_by":actor,"updated_at":"1000000"}])),
        "knowledge":available(json!([{"slug":"known","title":"Knowledge","updated_at":null}]))
    }});
    let bytes = serde_json::to_vec(&wire).unwrap();
    NowSnapshotData::decode(&bytes, n(bytes.len())).unwrap()
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
fn authorizer<'a>(
    store: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    local: bool,
) -> PostgresNowChannelAuthorizer<'a> {
    if local {
        store.local_now_channel_authorizer("explicit-audience", n(16384), n(65536), n(65536))
    } else {
        store.broker_now_channel_authorizer(verifier, n(65536), n(65536))
    }
    .unwrap()
}
async fn policy(c: &mut PgConnection, bits: u8) {
    clear(c).await;
    let mut caps = vec!["presence:read", "presence:publish"];
    for (bit, cap) in [(1, "task:read"), (2, "memory:read"), (4, "knowledge:read")] {
        if bits & bit != 0 {
            caps.push(cap);
        }
    }
    grant(c, "live", "authenticated", "", &caps, &[A, B]).await;
}
fn assert_mask(wire: &Value, bits: u8) {
    for (name, bit) in [
        ("tasks", 1),
        ("sessions", 1),
        ("memories", 2),
        ("knowledge", 4),
    ] {
        let section = &wire["sections"][name];
        if bits & bit != 0 {
            assert_eq!(section["availability"], "available");
            assert_eq!(section["items"].as_array().unwrap().len(), 1);
        } else {
            assert_eq!(
                *section,
                json!({"availability":"failed","items":[],"total":null,"has_more":null,"error":"forbidden"})
            );
        }
    }
    let bytes = serde_json::to_vec(wire).unwrap();
    NowSnapshotData::decode(&bytes, n(bytes.len())).unwrap();
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS, Ed25519, Native/opaque proofs and owned Tokio timers"]
async fn realtime_hub_postgres_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE now_channel_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION now_channel_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO now_channel_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    assert!(
        !sqlx_core::query_scalar::query_scalar::<_, bool>(
            "SELECT rolsuper FROM pg_roles WHERE rolname='now_channel_owner'"
        )
        .fetch_one(&mut c)
        .await
        .unwrap()
    );
    local_tokens(&mut c).await;
    let signer = Signer::new();
    let verifier = signer.verifier();
    let raw = signer.sign(&signer.claims());
    policy(&mut c, 7).await;
    for id in ["native", "native-2"] {
        store
            .broker_instance_registrar(&verifier, n(65536))
            .unwrap()
            .register(&raw, &scopes(), &super_inventory(id, &[A, B]), deadline())
            .await
            .unwrap();
    }
    for (token, id) in [(LOCAL_RAW, "local"), (SERVICE_RAW, "service")] {
        store
            .local_instance_registrar("explicit-audience", n(16384), n(65536))
            .unwrap()
            .register(token, &scopes(), &super_inventory(id, &[A]), deadline())
            .await
            .unwrap();
    }
    let native = channel("native", A, "main");
    let second = channel("native-2", A, "main");
    let branch = channel("native", A, "branch/ação");
    let other = channel("native", B, "main");
    let local = channel("local", A, "main");
    let native_auth = authorizer(&store, &verifier, false);
    let local_auth = authorizer(&store, &verifier, true);
    let initial = oracle(&mut c).await;
    let hub = RealtimeHub::new(Duration::from_secs(60), n(1)).unwrap();
    let project = native_auth
        .authorize_subscriber_project(&raw, &scopes(), A, deadline())
        .await
        .unwrap();
    assert_eq!(hub.subscribe(&project).unwrap_err(), HubError::Unavailable);
    let maintenance = hub.run_maintenance().unwrap();
    let mut events = hub.subscribe(&project).unwrap();
    let other_project = native_auth
        .authorize_subscriber_project(&raw, &scopes(), B, deadline())
        .await
        .unwrap();
    let mut other_events = hub.subscribe(&other_project).unwrap();
    let empty = hub.replay(other_project, vec![]).unwrap();
    assert_eq!(
        serde_json::to_value(empty).unwrap(),
        json!({"project_id":B,"instances":[]})
    );
    let handle = hub
        .open_publisher(
            native_auth
                .authorize_publish(&raw, &scopes(), &native, deadline())
                .await
                .unwrap(),
            data(A),
        )
        .unwrap();
    events.recv().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), other_events.recv())
            .await
            .is_err()
    );
    let second_handle = hub
        .open_publisher(
            native_auth
                .authorize_publish(&raw, &scopes(), &second, deadline())
                .await
                .unwrap(),
            data(A),
        )
        .unwrap();
    let branch_handle = hub
        .open_publisher(
            native_auth
                .authorize_publish(&raw, &scopes(), &branch, deadline())
                .await
                .unwrap(),
            data(A),
        )
        .unwrap();
    assert_eq!(
        events.recv().await.unwrap_err(),
        RealtimeHubSignalError::Lagged
    );
    events.recv().await.unwrap();
    let local_handle = hub
        .open_publisher(
            local_auth
                .authorize_publish(LOCAL_RAW, &scopes(), &local, deadline())
                .await
                .unwrap(),
            data(A),
        )
        .unwrap();
    let other_handle = hub
        .open_publisher(
            native_auth
                .authorize_publish(&raw, &scopes(), &other, deadline())
                .await
                .unwrap(),
            data(B),
        )
        .unwrap();
    other_events.recv().await.unwrap();
    let mut proofs = Vec::new();
    for ch in [&second, &branch, &native, &local] {
        proofs.push(
            native_auth
                .authorize_read(&raw, &scopes(), ch, deadline())
                .await
                .unwrap(),
        );
    }
    let view = hub
        .replay(
            native_auth
                .authorize_subscriber_project(&raw, &scopes(), A, deadline())
                .await
                .unwrap(),
            proofs,
        )
        .unwrap();
    let ids: Vec<_> = view
        .instances()
        .iter()
        .map(|v| (v.instance_id(), v.version()))
        .collect();
    assert_eq!(
        ids,
        vec![
            ("local", "main"),
            ("native", "branch/ação"),
            ("native", "main"),
            ("native-2", "main")
        ]
    );
    let wire = serde_json::to_value(view).unwrap();
    assert_eq!(wire.as_object().unwrap().len(), 2);
    for item in wire["instances"].as_array().unwrap() {
        assert_eq!(item.as_object().unwrap().len(), 3);
        assert_mask(&item["now"], 7);
    }
    for (is_local, token, ch, publisher) in [
        (false, raw.as_str(), &native, &handle),
        (true, LOCAL_RAW, &local, &local_handle),
    ] {
        let auth = authorizer(&store, &verifier, is_local);
        for bits in 0..8 {
            policy(&mut c, bits).await;
            publisher
                .publish(
                    auth.authorize_publish(token, &scopes(), ch, deadline())
                        .await
                        .unwrap(),
                    data(A),
                )
                .unwrap();
            let project = auth
                .authorize_subscriber_project(token, &scopes(), A, deadline())
                .await
                .unwrap();
            let proof = auth
                .authorize_read(token, &scopes(), ch, deadline())
                .await
                .unwrap();
            let view = hub.replay(project, vec![proof]).unwrap();
            assert_mask(
                &serde_json::to_value(view).unwrap()["instances"][0]["now"],
                bits,
            );
        }
        // Already publisher-filtered DATA cannot widen under subsequent broader readers.
        policy(&mut c, 7).await;
        let view = hub
            .replay(
                auth.authorize_subscriber_project(token, &scopes(), A, deadline())
                    .await
                    .unwrap(),
                vec![
                    auth.authorize_read(token, &scopes(), ch, deadline())
                        .await
                        .unwrap(),
                ],
            )
            .unwrap();
        assert_mask(
            &serde_json::to_value(view).unwrap()["instances"][0]["now"],
            7,
        );
        policy(&mut c, 1).await;
        publisher
            .publish(
                auth.authorize_publish(token, &scopes(), ch, deadline())
                    .await
                    .unwrap(),
                data(A),
            )
            .unwrap();
        policy(&mut c, 7).await;
        let view = hub
            .replay(
                auth.authorize_subscriber_project(token, &scopes(), A, deadline())
                    .await
                    .unwrap(),
                vec![
                    auth.authorize_read(token, &scopes(), ch, deadline())
                        .await
                        .unwrap(),
                ],
            )
            .unwrap();
        assert_mask(
            &serde_json::to_value(view).unwrap()["instances"][0]["now"],
            1,
        );
        publisher
            .publish(
                auth.authorize_publish(token, &scopes(), ch, deadline())
                    .await
                    .unwrap(),
                data(A),
            )
            .unwrap();
    }
    // Real distinct native readers. Publisher ownership is independent of reader identity.
    clear(&mut c).await;
    grant(
        &mut c,
        "presence",
        "authenticated",
        "",
        &["presence:read", "presence:publish"],
        &[A, B],
    )
    .await;
    grant(
        &mut c,
        "reader-narrow",
        "subject",
        "reader-narrow",
        &["task:read"],
        &[A],
    )
    .await;
    grant(
        &mut c,
        "reader-wide",
        "subject",
        "reader-wide",
        &["task:read", "memory:read", "knowledge:read"],
        &[A],
    )
    .await;
    let mut narrow_claims = signer.claims();
    narrow_claims["sub"] = json!("reader-narrow");
    let narrow = signer.sign(&narrow_claims);
    let mut wide_claims = signer.claims();
    wide_claims["sub"] = json!("reader-wide");
    let wide = signer.sign(&wide_claims);
    for (project_raw, channel_raw) in [(&narrow, &wide), (&wide, &narrow)] {
        let project = native_auth
            .authorize_subscriber_project(project_raw, &scopes(), A, deadline())
            .await
            .unwrap();
        let proof = native_auth
            .authorize_read(channel_raw, &scopes(), &native, deadline())
            .await
            .unwrap();
        let view = hub.replay(project, vec![proof]).unwrap();
        assert_mask(
            &serde_json::to_value(view).unwrap()["instances"][0]["now"],
            1,
        );
    }
    // Actual opaque proofs with project and channel masks captured at separate SQL revisions.
    for reversed in [false, true] {
        policy(&mut c, if reversed { 7 } else { 2 }).await;
        let project = local_auth
            .authorize_subscriber_project(LOCAL_RAW, &scopes(), A, deadline())
            .await
            .unwrap();
        policy(&mut c, if reversed { 2 } else { 7 }).await;
        let proof = local_auth
            .authorize_read(LOCAL_RAW, &scopes(), &local, deadline())
            .await
            .unwrap();
        let view = hub.replay(project, vec![proof]).unwrap();
        assert_mask(
            &serde_json::to_value(view).unwrap()["instances"][0]["now"],
            2,
        );
    }
    policy(&mut c, 7).await;
    assert_eq!(
        hub.replay(
            native_auth
                .authorize_subscriber_project(&raw, &scopes(), A, deadline())
                .await
                .unwrap(),
            vec![
                native_auth
                    .authorize_read(&raw, &scopes(), &other, deadline())
                    .await
                    .unwrap()
            ]
        )
        .unwrap_err(),
        HubError::InvalidContext
    );
    let p1 = native_auth
        .authorize_read(&raw, &scopes(), &native, deadline())
        .await
        .unwrap();
    let p2 = native_auth
        .authorize_read(&raw, &scopes(), &native, deadline())
        .await
        .unwrap();
    assert_eq!(
        hub.replay(
            native_auth
                .authorize_subscriber_project(&raw, &scopes(), A, deadline())
                .await
                .unwrap(),
            vec![p1, p2]
        )
        .unwrap_err(),
        HubError::InvalidContext
    );
    let replacement = hub
        .open_publisher(
            native_auth
                .authorize_publish(&raw, &scopes(), &native, deadline())
                .await
                .unwrap(),
            data(A),
        )
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), handle.wait_inactive())
            .await
            .unwrap(),
        HubError::Superseded
    );
    assert_eq!(
        handle
            .publish(
                native_auth
                    .authorize_publish(&raw, &scopes(), &native, deadline())
                    .await
                    .unwrap(),
                data(A)
            )
            .unwrap_err(),
        HubError::Superseded
    );
    drop(handle);
    replacement.check_active().unwrap();
    let project = native_auth
        .authorize_subscriber_project(&raw, &scopes(), A, deadline())
        .await
        .unwrap();
    let proof = native_auth
        .authorize_read(&raw, &scopes(), &branch, deadline())
        .await
        .unwrap();
    drop(branch_handle);
    assert!(
        hub.replay(project, vec![proof])
            .unwrap()
            .instances()
            .is_empty()
    );
    let aborted = hub
        .open_publisher(
            native_auth
                .authorize_publish(&raw, &scopes(), &branch, deadline())
                .await
                .unwrap(),
            data(A),
        )
        .unwrap();
    let job = tokio::spawn(async move {
        let _guard = aborted;
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    let replay = hub
        .replay(
            native_auth
                .authorize_subscriber_project(&raw, &scopes(), A, deadline())
                .await
                .unwrap(),
            vec![
                native_auth
                    .authorize_read(&raw, &scopes(), &branch, deadline())
                    .await
                    .unwrap(),
            ],
        )
        .unwrap();
    assert!(replay.instances().is_empty());
    assert_eq!(
        oracle(&mut c).await,
        initial,
        "all ephemeral Hub effects preserve SQL registry"
    );
    // Actual producer re-reads current ACL and registry; storage errors are never empty views.
    clear(&mut c).await;
    assert_eq!(
        native_auth
            .authorize_publish(&raw, &scopes(), &native, deadline())
            .await
            .unwrap_err(),
        Error::Native(Native::Forbidden)
    );
    assert_eq!(
        local_auth
            .authorize_read(LOCAL_RAW, &scopes(), &local, deadline())
            .await
            .unwrap_err(),
        Error::Local(Local::Forbidden)
    );
    replacement.check_active().unwrap(); // observation cannot claim proactive SQL revocation
    policy(&mut c, 7).await;
    store
        .broker_instance_registrar(&verifier, n(65536))
        .unwrap()
        .register(
            &raw,
            &scopes(),
            &InstanceInventory::new(
                "native".into(),
                vec![
                    InstanceProjectVersions::new(A.into(), vec!["branch/ação".into()]).unwrap(),
                    InstanceProjectVersions::new(
                        B.into(),
                        vec!["main".into(), "branch/ação".into()],
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        native_auth
            .authorize_read(&raw, &scopes(), &native, deadline())
            .await
            .unwrap_err(),
        Error::NotRegistered
    );
    store
        .broker_instance_registrar(&verifier, n(65536))
        .unwrap()
        .register(
            &raw,
            &scopes(),
            &super_inventory("native", &[A, B]),
            deadline(),
        )
        .await
        .unwrap();
    // A real registry owner change cannot replace or expose the old owner's live DATA.
    c.execute("DELETE FROM public.broker_instances WHERE instance_id='native'")
        .await
        .unwrap();
    let mut foreign_claims = signer.claims();
    foreign_claims["sub"] = json!("foreign-publisher");
    let foreign = signer.sign(&foreign_claims);
    store
        .broker_instance_registrar(&verifier, n(65536))
        .unwrap()
        .register(
            &foreign,
            &scopes(),
            &super_inventory("native", &[A, B]),
            deadline(),
        )
        .await
        .unwrap();
    let observed = oracle(&mut c).await;
    let project = native_auth
        .authorize_subscriber_project(&raw, &scopes(), A, deadline())
        .await
        .unwrap();
    let read = native_auth
        .authorize_read(&raw, &scopes(), &native, deadline())
        .await
        .unwrap();
    assert_eq!(
        hub.replay(project, vec![read]).unwrap_err(),
        HubError::OwnerConflict
    );
    let publish = native_auth
        .authorize_publish(&foreign, &scopes(), &native, deadline())
        .await
        .unwrap();
    assert_eq!(
        hub.open_publisher(publish, data(A)).unwrap_err(),
        HubError::OwnerConflict
    );
    replacement.check_active().unwrap();
    assert_eq!(oracle(&mut c).await, observed);
    c.execute("DELETE FROM public.broker_instances WHERE instance_id='native'")
        .await
        .unwrap();
    store
        .broker_instance_registrar(&verifier, n(65536))
        .unwrap()
        .register(
            &raw,
            &scopes(),
            &super_inventory("native", &[A, B]),
            deadline(),
        )
        .await
        .unwrap();
    let end = Instant::now() + Duration::from_millis(250);
    let stale = native_auth
        .authorize_publish(&raw, &scopes(), &native, end)
        .await
        .unwrap();
    tokio::time::sleep_until(end.into()).await;
    assert_eq!(
        replacement.publish(stale, data(A)).unwrap_err(),
        HubError::Authorization(Error::Native(Native::Control(ControlError::Deadline)))
    );
    replacement.check_active().unwrap();
    let mismatched = native_auth
        .authorize_publish(&raw, &scopes(), &native, deadline())
        .await
        .unwrap();
    assert_eq!(
        hub.open_publisher(mismatched, data(B)).unwrap_err(),
        HubError::Authorization(Error::SnapshotProjectMismatch)
    );
    grant(&mut c, "invalid-unused", "team", "[", &["task:read"], &[B]).await;
    assert_eq!(
        native_auth
            .authorize_subscriber_project(&raw, &scopes(), A, deadline())
            .await
            .unwrap_err(),
        Error::Native(Native::InvalidPolicy)
    );
    policy(&mut c, 7).await;
    c.execute("REVOKE SELECT ON public.broker_instances FROM now_channel_owner")
        .await
        .unwrap();
    assert_eq!(
        native_auth
            .authorize_read(&raw, &scopes(), &native, deadline())
            .await
            .unwrap_err(),
        Error::Inventory(InstanceReadError::Control(ControlError::Storage))
    );
    c.execute("GRANT SELECT ON public.broker_instances TO now_channel_owner")
        .await
        .unwrap();
    // Retained proofs keep the operation's Original deadline, not a renewed timeout.
    let end = Instant::now() + Duration::from_millis(250);
    let project = native_auth
        .authorize_subscriber_project(&raw, &scopes(), A, end)
        .await
        .unwrap();
    let proof = native_auth
        .authorize_read(&raw, &scopes(), &native, end)
        .await
        .unwrap();
    let view = hub.replay(project, vec![proof]).unwrap();
    tokio::time::sleep_until(end.into()).await;
    assert!(matches!(
        view.check().unwrap_err(),
        HubError::Authorization(Error::Native(Native::Control(ControlError::Deadline)))
    ));
    assert!(serde_json::to_value(view).is_err());
    // Timer-only expiry: await a broadcast without invoking lazy prune first.
    let project = native_auth
        .authorize_subscriber_project(&raw, &scopes(), A, deadline())
        .await
        .unwrap();
    let proof = native_auth
        .authorize_publish(&raw, &scopes(), &native, deadline())
        .await
        .unwrap();
    let timer_hub = RealtimeHub::new(Duration::from_millis(150), n(4)).unwrap();
    let timer_owner = timer_hub.run_maintenance().unwrap();
    let mut timer_events = timer_hub.subscribe(&project).unwrap();
    let timed = timer_hub.open_publisher(proof, data(A)).unwrap();
    timer_events.recv().await.unwrap();
    {
        let mut inactive = Box::pin(timed.wait_inactive());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut inactive)
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(2), timer_events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inactive.await, HubError::Closed);
    }
    assert_eq!(timed.check_active().unwrap_err(), HubError::Closed);
    assert_eq!(
        timed
            .publish(
                native_auth
                    .authorize_publish(&raw, &scopes(), &native, deadline())
                    .await
                    .unwrap(),
                data(A)
            )
            .unwrap_err(),
        HubError::Closed
    );
    let reopened = timer_hub
        .open_publisher(
            native_auth
                .authorize_publish(&raw, &scopes(), &native, deadline())
                .await
                .unwrap(),
            data(A),
        )
        .unwrap();
    drop(timed);
    reopened.check_active().unwrap();
    timer_events.recv().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), timer_events.recv())
        .await
        .unwrap()
        .unwrap();
    // No receiver existed when this publication ended; the cause is retained.
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), reopened.wait_inactive())
            .await
            .unwrap(),
        HubError::Closed
    );
    timer_owner.shutdown().await.unwrap();
    // Real verifier/token expiry governs publication even when heartbeat is longer.
    for opaque in [false, true] {
        let auth = authorizer(&store, &verifier, opaque);
        let token = if opaque {
            sqlx_core::query::query(
                "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='now-access'",
            )
            .bind(now() + 3_000_000)
            .execute(&mut c)
            .await
            .unwrap();
            LOCAL_RAW.to_owned()
        } else {
            let mut claims = signer.claims();
            claims["exp"] = json!(seconds() + 3);
            signer.sign(&claims)
        };
        let ch = if opaque { &local } else { &native };
        let project = auth
            .authorize_subscriber_project(&token, &scopes(), A, deadline())
            .await
            .unwrap();
        let proof = auth
            .authorize_publish(&token, &scopes(), ch, deadline())
            .await
            .unwrap();
        let h = RealtimeHub::new(Duration::from_secs(10), n(4)).unwrap();
        let owner = h.run_maintenance().unwrap();
        let mut signal = h.subscribe(&project).unwrap();
        let p = h.open_publisher(proof, data(A)).unwrap();
        signal.recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), signal.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            p.check_active().unwrap_err(),
            HubError::AuthenticationExpired
        );
        assert_eq!(p.wait_inactive().await, HubError::AuthenticationExpired);
        assert_eq!(
            auth.authorize_publish(&token, &scopes(), ch, deadline())
                .await
                .unwrap_err(),
            if opaque {
                Error::Local(Local::Authentication(
                    LocalBearerVerificationError::Unauthenticated,
                ))
            } else {
                Error::Native(Native::Authentication(BrokerAccessError::Expired))
            }
        );
        owner.shutdown().await.unwrap();
        assert_eq!(p.wait_inactive().await, HubError::AuthenticationExpired);
    }
    // Hold this current-thread executor until both genuine bounds have elapsed,
    // so the same prune observes auth expiry and heartbeat expiry together.
    let mut claims = signer.claims();
    claims["exp"] = json!(seconds() + 3);
    let token = signer.sign(&claims);
    let proof = native_auth
        .authorize_publish(&token, &scopes(), &native, deadline())
        .await
        .unwrap();
    let authentication_end = proof.authentication_expiry().1;
    let both = RealtimeHub::new(Duration::from_millis(150), n(4)).unwrap();
    let both_owner = both.run_maintenance().unwrap();
    let p = both.open_publisher(proof, data(A)).unwrap();
    std::thread::sleep(
        authentication_end.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
    );
    assert_eq!(
        p.check_active().unwrap_err(),
        HubError::AuthenticationExpired
    );
    assert_eq!(p.wait_inactive().await, HubError::AuthenticationExpired);
    both_owner.shutdown().await.unwrap();
    assert_eq!(p.wait_inactive().await, HubError::AuthenticationExpired);
    let fenced = RealtimeHub::new(Duration::from_secs(10), n(4)).unwrap();
    let fenced_owner = fenced.run_maintenance().unwrap();
    let old = fenced
        .open_publisher(
            native_auth
                .authorize_publish(&raw, &scopes(), &native, deadline())
                .await
                .unwrap(),
            data(A),
        )
        .unwrap();
    let current = fenced
        .open_publisher(
            native_auth
                .authorize_publish(&raw, &scopes(), &native, deadline())
                .await
                .unwrap(),
            data(A),
        )
        .unwrap();
    assert_eq!(old.wait_inactive().await, HubError::Superseded);
    drop(current);
    fenced_owner.shutdown().await.unwrap();
    assert_eq!(old.check_active().unwrap_err(), HubError::Superseded);
    assert_eq!(old.wait_inactive().await, HubError::Superseded);
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='now-access'",
    )
    .bind(now() + 600_000_000)
    .execute(&mut c)
    .await
    .unwrap();
    let preserved = oracle(&mut c).await;
    let view = hub
        .replay(
            local_auth
                .authorize_subscriber_project(LOCAL_RAW, &scopes(), A, deadline())
                .await
                .unwrap(),
            vec![
                local_auth
                    .authorize_read(LOCAL_RAW, &scopes(), &local, deadline())
                    .await
                    .unwrap(),
            ],
        )
        .unwrap();
    c.execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
        .await
        .unwrap();
    assert!(
        local_auth
            .authorize_read(LOCAL_RAW, &scopes(), &local, deadline())
            .await
            .is_err()
    );
    view.check().unwrap(); // retained proof is an operation observation, not a new SQL read
    maintenance.shutdown().await.unwrap();
    assert_eq!(replacement.check_active().unwrap_err(), HubError::Closed);
    loop {
        match events.recv().await {
            Err(RealtimeHubSignalError::Closed) => break,
            Ok(()) | Err(RealtimeHubSignalError::Lagged) => {}
        }
    }
    assert_eq!(oracle(&mut c).await, preserved);
    drop((replacement, second_handle, local_handle, other_handle));
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
