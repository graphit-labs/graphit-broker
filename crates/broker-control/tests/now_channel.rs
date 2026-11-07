#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    AuthorizedNowSubscriber, BrokerAccessError, BrokerAccessVerifier,
    BrokerPresenceAuthorizationError as Native, ConnectionLimits, ControlError, InstanceInventory,
    InstanceProjectVersions, InstanceReadError, LocalBearerVerificationError,
    NowChannelAuthorizationError as Error, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint, PresenceAuthorizationError as Local, PresenceChannel,
    ResourceGrantReadError,
};
use broker_now_wire::{NowSectionAvailability, NowSectionErrorCode, NowSnapshotData};
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
    let actor = "01ARZ3NDEKTSV4RRFFQ69G5FAZ";
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
async fn read<'a>(
    store: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    raw: &str,
    ch: &PresenceChannel,
    end: Instant,
    local: bool,
) -> Result<AuthorizedNowSubscriber<'a>, Error> {
    let authorizer = if local {
        store.local_now_channel_authorizer("explicit-audience", n(16384), n(65536), n(65536))?
    } else {
        store.broker_now_channel_authorizer(verifier, n(65536), n(65536))?
    };
    authorizer.authorize_read(raw, &scopes(), ch, end).await
}
async fn denied(
    c: &mut PgConnection,
    store: &PostgresControlStore,
    verifier: &BrokerAccessVerifier,
    raw: &str,
    ch: &PresenceChannel,
    expected: Error,
    local: bool,
) {
    let before = oracle(c).await;
    assert_eq!(
        read(store, verifier, raw, ch, deadline(), local)
            .await
            .unwrap_err(),
        expected
    );
    assert_eq!(
        oracle(c).await,
        before,
        "authorization never mutates registry"
    );
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
async fn observe_lock(c: &mut PgConnection, inventory: bool) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='now_channel_owner' AND wait_event_type='Lock' AND query LIKE $1)")
            .bind(if inventory {"%broker_instances%"}else{"%resource_acl_state%"}).fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(Instant::now() < end, "operation reached real SQL lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
fn forbidden(local: bool) -> Error {
    if local {
        Error::Local(Local::Forbidden)
    } else {
        Error::Native(Native::Forbidden)
    }
}
fn expired(local: bool) -> Error {
    if local {
        Error::Local(Local::Authentication(
            LocalBearerVerificationError::Unauthenticated,
        ))
    } else {
        Error::Native(Native::Authentication(BrokerAccessError::Expired))
    }
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS, Ed25519, Native/opaque authorization and registrars"]
async fn postgres_now_channel_authorization_contract() {
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
    for (token, id) in [(LOCAL_RAW, "local"), (SERVICE_RAW, "service")] {
        store
            .local_instance_registrar("explicit-audience", n(16384), n(65536))
            .unwrap()
            .register(token, &scopes(), &super_inventory(id, &[A]), deadline())
            .await
            .unwrap();
    }
    let native = channel("native", A, "main");
    let local = channel("local", A, "main");
    let initial = oracle(&mut c).await;
    for local_mode in [false, true] {
        let token = if local_mode { LOCAL_RAW } else { &raw };
        let ch = if local_mode { &local } else { &native };
        clear(&mut c).await;
        denied(
            &mut c,
            &store,
            &verifier,
            token,
            ch,
            forbidden(local_mode),
            local_mode,
        )
        .await;
        // Denied Presence cannot reveal registry storage or absence.
        c.execute("REVOKE SELECT ON public.broker_instances FROM now_channel_owner")
            .await
            .unwrap();
        denied(
            &mut c,
            &store,
            &verifier,
            token,
            &channel("missing", A, "main"),
            forbidden(local_mode),
            local_mode,
        )
        .await;
        c.execute("GRANT SELECT ON public.broker_instances TO now_channel_owner")
            .await
            .unwrap();
        grant(
            &mut c,
            "presence",
            "authenticated",
            "",
            &["presence:read", "presence:publish"],
            &[A],
        )
        .await;
        for bits in 0..8 {
            c.execute("DELETE FROM public.resource_grants WHERE id='module'")
                .await
                .unwrap();
            let mut caps = vec!["task:write", "memory:write", "knowledge:write", "hub:*"];
            for (bit, cap) in [(1, "task:read"), (2, "memory:read"), (4, "knowledge:read")] {
                if bits & bit != 0 {
                    caps.push(cap)
                }
            }
            grant(&mut c, "module", "authenticated", "", &caps, &[A]).await;
            let proof = read(&store, &verifier, token, ch, deadline(), local_mode)
                .await
                .unwrap();
            assert_eq!(proof.channel(), ch);
            assert_eq!(proof.project_id(), A);
            assert!(proof.policy_revision() > 0);
            assert_eq!(
                proof.registered_owner().issuer(),
                if local_mode { "local" } else { ISSUER }
            );
            assert_eq!(
                proof.registered_owner().subject(),
                if local_mode { "alice-subject" } else { SUBJECT }
            );
            assert_eq!(format!("{proof:?}"), "AuthorizedNowSubscriber([REDACTED])");
            let (utc, mono) = proof.authentication_expiry();
            assert!(utc > SystemTime::now());
            assert!(mono > Instant::now());
            let captured_expiry = proof.authentication_expiry();
            proof.check().unwrap();
            assert_eq!(proof.authentication_expiry(), captured_expiry);
            let mask = proof.read_mask();
            assert_eq!(
                (mask.task_read(), mask.memory_read(), mask.knowledge_read()),
                (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0)
            );
            let masked = proof.filter_snapshot(data(A)).unwrap();
            let wire = serde_json::to_value(&masked).unwrap();
            for (name, allowed) in [
                ("tasks", bits & 1 != 0),
                ("sessions", bits & 1 != 0),
                ("memories", bits & 2 != 0),
                ("knowledge", bits & 4 != 0),
            ] {
                if allowed {
                    assert_eq!(
                        wire["sections"][name],
                        serde_json::to_value(data(A)).unwrap()["sections"][name]
                    );
                } else {
                    assert_eq!(
                        wire["sections"][name],
                        json!({"availability":"failed","items":[],"total":null,"has_more":null,"error":"forbidden"})
                    );
                }
            }
            assert_eq!(
                proof.filter_snapshot(data(B)).unwrap_err(),
                Error::SnapshotProjectMismatch
            );
            let pubproof = if local_mode {
                store
                    .local_now_channel_authorizer("explicit-audience", n(16384), n(65536), n(65536))
                    .unwrap()
                    .authorize_publish(token, &scopes(), ch, deadline())
                    .await
                    .unwrap()
            } else {
                store
                    .broker_now_channel_authorizer(&verifier, n(65536), n(65536))
                    .unwrap()
                    .authorize_publish(token, &scopes(), ch, deadline())
                    .await
                    .unwrap()
            };
            assert_eq!(pubproof.read_mask(), mask);
            assert_eq!(pubproof.channel(), ch);
            pubproof.check().unwrap();
            let masked = pubproof.filter_snapshot(data(A)).unwrap();
            assert_eq!(serde_json::to_value(masked).unwrap(), wire);
        }
        let auth = if local_mode {
            store
                .local_now_channel_authorizer("explicit-audience", n(16384), n(65536), n(65536))
                .unwrap()
        } else {
            store
                .broker_now_channel_authorizer(&verifier, n(65536), n(65536))
                .unwrap()
        };
        let empty = auth
            .authorize_subscriber_project(token, &scopes(), A, deadline())
            .await
            .unwrap();
        assert_eq!(empty.project_id(), A);
        empty.check().unwrap();
        assert!(empty.filter_snapshot(data(A)).is_ok());
        assert_eq!(
            auth.authorize_subscriber_project(token, &scopes(), "bad", deadline())
                .await
                .unwrap_err(),
            Error::InvalidProject
        );
        for bad in [
            channel("missing", A, "main"),
            channel(ch.instance_id(), A, "absent"),
            channel(ch.instance_id(), B, "main"),
        ] {
            let expected = if bad.project_id() == B {
                forbidden(local_mode)
            } else {
                Error::NotRegistered
            };
            denied(&mut c, &store, &verifier, token, &bad, expected, local_mode).await;
        }
        // Same-rule matcher: no union of capability, project and principal.
        clear(&mut c).await;
        grant(
            &mut c,
            "presence",
            "authenticated",
            "",
            &["presence:read"],
            &[A],
        )
        .await;
        grant(
            &mut c,
            "half-cap",
            "subject",
            "foreign",
            &["task:read"],
            &[A],
        )
        .await;
        grant(
            &mut c,
            "half-project",
            "authenticated",
            "",
            &["task:read"],
            &[B],
        )
        .await;
        let observed = read(&store, &verifier, token, ch, deadline(), local_mode)
            .await
            .unwrap();
        assert!(!observed.read_mask().task_read());
        grant(&mut c, "bad", "team", "[", &["task:read"], &[B]).await;
        let bad = if local_mode {
            Error::Local(Local::InvalidPolicy)
        } else {
            Error::Native(Native::InvalidPolicy)
        };
        denied(
            &mut c,
            &store,
            &verifier,
            token,
            &channel("missing", A, "main"),
            bad,
            local_mode,
        )
        .await;
        c.execute("DELETE FROM public.resource_grants WHERE id='bad'")
            .await
            .unwrap();
        clear(&mut c).await;
        grant(
            &mut c,
            "current",
            "authenticated",
            "",
            &["presence:read", "task:read"],
            &[A],
        )
        .await;
        let observed = read(&store, &verifier, token, ch, deadline(), local_mode)
            .await
            .unwrap();
        let revision = observed.policy_revision();
        c.execute("DELETE FROM public.grant_capabilities WHERE grant_id='current' AND value='task:read'; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
        observed.check().unwrap(); // check is not fresh ACL and is not a lease.
        let fresh = read(&store, &verifier, token, ch, deadline(), local_mode)
            .await
            .unwrap();
        assert!(!fresh.read_mask().task_read());
        assert!(fresh.policy_revision() > revision);
        let all_denied = fresh.filter_snapshot(data(A)).unwrap();
        assert_eq!(
            all_denied.sections().tasks().availability(),
            NowSectionAvailability::Failed
        );
        assert_eq!(
            all_denied.sections().sessions().error(),
            Some(NowSectionErrorCode::Forbidden)
        );
    }
    assert_eq!(oracle(&mut c).await, initial);
    clear(&mut c).await;
    grant(
        &mut c,
        "all",
        "authenticated",
        "",
        &["presence:*", "*:read"],
        &["*"],
    )
    .await;
    let auth = store
        .broker_now_channel_authorizer(&verifier, n(65536), n(65536))
        .unwrap();
    // Foreign read is legitimate, foreign publication is not; owner-first precedence.
    assert!(
        auth.authorize_read(&raw, &scopes(), &local, deadline())
            .await
            .is_ok()
    );
    for ch in [&local, &channel("local", B, "absent")] {
        assert_eq!(
            auth.authorize_publish(&raw, &scopes(), ch, deadline())
                .await
                .unwrap_err(),
            Error::OwnerConflict
        );
    }
    let local_auth = store
        .local_now_channel_authorizer("explicit-audience", n(16384), n(65536), n(65536))
        .unwrap();
    assert!(
        local_auth
            .authorize_read(LOCAL_RAW, &scopes(), &native, deadline())
            .await
            .is_ok()
    );
    assert_eq!(
        local_auth
            .authorize_publish(LOCAL_RAW, &scopes(), &native, deadline())
            .await
            .unwrap_err(),
        Error::OwnerConflict
    );
    assert!(
        local_auth
            .authorize_publish(
                SERVICE_RAW,
                &scopes(),
                &channel("service", A, "main"),
                deadline()
            )
            .await
            .is_ok()
    );
    // Explicit formats and purpose scopes, no mode probe/fallback.
    denied(
        &mut c,
        &store,
        &verifier,
        LOCAL_RAW,
        &native,
        Error::Native(Native::Authentication(BrokerAccessError::InvalidToken)),
        false,
    )
    .await;
    denied(&mut c, &store, &verifier, &raw, &local, expired(true), true).await;
    let mut wrong = signer.claims();
    wrong["scope"] = json!("other");
    denied(
        &mut c,
        &store,
        &verifier,
        &signer.sign(&wrong),
        &native,
        Error::Native(Native::Authentication(BrokerAccessError::InsufficientScope)),
        false,
    )
    .await;
    denied(
        &mut c,
        &store,
        &verifier,
        &Signer::new().sign(&signer.claims()),
        &native,
        Error::Native(Native::Authentication(BrokerAccessError::InvalidToken)),
        false,
    )
    .await;
    // Current opaque revocation/identity revision versus signed Native until-exp.
    c.execute("UPDATE public.local_tokens SET revoked_at=1 WHERE token_id='now-access'")
        .await
        .unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        LOCAL_RAW,
        &local,
        expired(true),
        true,
    )
    .await;
    c.execute("UPDATE public.local_tokens SET revoked_at=NULL WHERE token_id='now-access'; UPDATE public.local_users SET enabled=0,revision=2 WHERE username='alice'").await.unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        LOCAL_RAW,
        &local,
        expired(true),
        true,
    )
    .await;
    assert!(
        read(&store, &verifier, &raw, &native, deadline(), false)
            .await
            .is_ok()
    );
    c.execute("UPDATE public.local_users SET enabled=1,revision=1 WHERE username='alice'")
        .await
        .unwrap();
    // A corresponding stored OIDC token is revoked and SQL identity access is
    // removed. The signed Native proof retains only its verified until-exp window.
    c.execute("INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('approved-client','Fixture','[\"https://client.example.test/callback\"]','[\"presence-sdk\"]','web',0)").await.unwrap();
    let digest = support::digester()
        .token(TokenKind::OidcStoredAccess, JTI.as_bytes())
        .unwrap();
    let stored=json!({"issuer":"local","subject":"alice-subject","username":"alice","auth_method":"oidc","local_user_revision":1,"name":"Alice","email":null,"organization":"org","teams":["dev"],"scopes":["presence-sdk"],"roles":[],"roles_from_claim":false,"role_claim_selector":""}).to_string();
    sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,'oidc_access','alice-subject','broker-subject',$3,'approved-client','presence-api','https://broker.example.test/v1','[\"presence-sdk\"]',1,'',0,9223372036854775807,0)").bind(digest.to_sql_hex()).bind(JTI).bind(stored).execute(&mut c).await.unwrap();
    assert!(
        read(&store, &verifier, &raw, &native, deadline(), false)
            .await
            .is_ok()
    );
    c.execute("UPDATE public.local_tokens SET revoked_at=1,expires_at=0,principal_json='{}' WHERE token_kind='oidc_access'; DELETE FROM public.oauth_dynamic_clients; UPDATE public.local_users SET enabled=0,revision=2 WHERE username='alice'; REVOKE SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients FROM now_channel_owner").await.unwrap();
    for table in ["local_users", "local_tokens", "oauth_dynamic_clients"] {
        assert!(
            !sqlx_core::query_scalar::query_scalar::<_, bool>(
                "SELECT has_table_privilege('now_channel_owner',$1,'SELECT')"
            )
            .bind(format!("public.{table}"))
            .fetch_one(&mut c)
            .await
            .unwrap()
        );
    }
    assert!(
        read(&store, &verifier, &raw, &native, deadline(), false)
            .await
            .is_ok()
    );
    c.execute("GRANT SELECT ON public.local_users,public.local_tokens,public.oauth_dynamic_clients TO now_channel_owner; UPDATE public.local_users SET enabled=1,revision=1 WHERE username='alice'").await.unwrap();
    // Withdrawal through the real Native registrar and current exact version checks.
    let version = channel("native", A, "branch/ação");
    assert!(
        read(&store, &verifier, &raw, &version, deadline(), false)
            .await
            .is_ok()
    );
    store
        .broker_instance_registrar(&verifier, n(65536))
        .unwrap()
        .register(
            &raw,
            &scopes(),
            &InstanceInventory::new(
                "native".into(),
                vec![InstanceProjectVersions::new(A.into(), vec!["main".into()]).unwrap()],
            )
            .unwrap(),
            deadline(),
        )
        .await
        .unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        &version,
        Error::NotRegistered,
        false,
    )
    .await;
    // Errors preserve whether the failing producer is grants or inventory.
    for local_mode in [false, true] {
        let token = if local_mode { LOCAL_RAW } else { &raw };
        let ch = if local_mode { &local } else { &native };
        let small = if local_mode {
            store
                .local_now_channel_authorizer("explicit-audience", n(16384), n(1), n(65536))
                .unwrap()
        } else {
            store
                .broker_now_channel_authorizer(&verifier, n(1), n(65536))
                .unwrap()
        };
        let expected = if local_mode {
            Error::Local(Local::Grants(ResourceGrantReadError::ReadLimitExceeded))
        } else {
            Error::Native(Native::Grants(ResourceGrantReadError::ReadLimitExceeded))
        };
        assert_eq!(
            small
                .authorize_read(token, &scopes(), ch, deadline())
                .await
                .unwrap_err(),
            expected
        );
        let small = if local_mode {
            store
                .local_now_channel_authorizer("explicit-audience", n(16384), n(65536), n(1))
                .unwrap()
        } else {
            store
                .broker_now_channel_authorizer(&verifier, n(65536), n(1))
                .unwrap()
        };
        assert_eq!(
            small
                .authorize_read(token, &scopes(), ch, deadline())
                .await
                .unwrap_err(),
            Error::Inventory(InstanceReadError::ReadLimitExceeded)
        );
        for inventory in [false, true] {
            c.execute(if inventory {
                "REVOKE SELECT ON public.broker_instances FROM now_channel_owner"
            } else {
                "REVOKE SELECT ON public.resource_grants FROM now_channel_owner"
            })
            .await
            .unwrap();
            let expected = if inventory {
                Error::Inventory(InstanceReadError::Control(ControlError::Storage))
            } else if local_mode {
                Error::Local(Local::Control(ControlError::Storage))
            } else {
                Error::Native(Native::Control(ControlError::Storage))
            };
            denied(&mut c, &store, &verifier, token, ch, expected, local_mode).await;
            c.execute(if inventory {
                "GRANT SELECT ON public.broker_instances TO now_channel_owner"
            } else {
                "GRANT SELECT ON public.resource_grants TO now_channel_owner"
            })
            .await
            .unwrap();
        }
    }
    c.execute("UPDATE public.broker_instance_project_versions SET position=position+3 WHERE instance_id='native'").await.unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        &native,
        Error::Inventory(InstanceReadError::MalformedStored),
        false,
    )
    .await;
    c.execute("UPDATE public.broker_instance_project_versions SET position=position-3 WHERE instance_id='native'").await.unwrap();
    let mut blocker = f.connection().await;
    // Expiry after an observed wait must beat allowed/denied/missing decisions.
    for (local_mode, inventory, missing, permitted) in [
        (false, false, false, true),
        (false, false, false, false),
        (false, true, true, true),
        (true, false, false, true),
        (true, false, false, false),
        (true, true, true, true),
    ] {
        clear(&mut c).await;
        grant(
            &mut c,
            "wait",
            "subject",
            if permitted { "*" } else { "foreign" },
            &["presence:read"],
            &["*"],
        )
        .await;
        let expiry = seconds() + 4;
        let mut claims = signer.claims();
        claims["exp"] = json!(expiry);
        let token = if local_mode {
            LOCAL_RAW.to_owned()
        } else {
            signer.sign(&claims)
        };
        if local_mode {
            sqlx_core::query::query(
                "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='now-access'",
            )
            .bind(i64::try_from(expiry).unwrap() * 1_000_000)
            .execute(&mut c)
            .await
            .unwrap();
        }
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
        let ch = channel(
            if missing {
                "missing"
            } else if local_mode {
                "local"
            } else {
                "native"
            },
            A,
            "main",
        );
        let pending = tokio::spawn(async move {
            read(&worker, &trust, &token, &ch, deadline(), local_mode)
                .await
                .map(|_| ())
        });
        observe_lock(&mut c, inventory).await;
        assert!(!pending.is_finished());
        assert!(seconds() < expiry);
        let remaining = (UNIX_EPOCH + Duration::from_secs(expiry))
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        tokio::time::sleep(remaining + Duration::from_millis(30)).await;
        blocker.execute("COMMIT").await.unwrap();
        assert_eq!(pending.await.unwrap().unwrap_err(), expired(local_mode));
        c.execute("UPDATE public.local_tokens SET expires_at=9223372036854775807 WHERE token_id='now-access'").await.unwrap();
    }
    clear(&mut c).await;
    grant(
        &mut c,
        "all",
        "authenticated",
        "",
        &["presence:*", "*:read"],
        &["*"],
    )
    .await;
    for local_mode in [false, true] {
        for inventory in [false, true] {
            for abort in [false, true] {
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
                let token = if local_mode {
                    LOCAL_RAW.to_owned()
                } else {
                    raw.clone()
                };
                let ch = if local_mode {
                    local.clone()
                } else {
                    native.clone()
                };
                let pending = tokio::spawn(async move {
                    read(
                        &worker,
                        &trust,
                        &token,
                        &ch,
                        Instant::now() + Duration::from_secs(2),
                        local_mode,
                    )
                    .await
                    .map(|_| ())
                });
                observe_lock(&mut c, inventory).await;
                if abort {
                    pending.abort();
                    assert!(pending.await.unwrap_err().is_cancelled());
                } else {
                    let expected = if inventory {
                        Error::Inventory(InstanceReadError::Control(ControlError::Deadline))
                    } else if local_mode {
                        Error::Local(Local::Control(ControlError::Deadline))
                    } else {
                        Error::Native(Native::Control(ControlError::Deadline))
                    };
                    assert_eq!(pending.await.unwrap().unwrap_err(), expected);
                }
                blocker.execute("COMMIT").await.unwrap();
                assert_eq!(oracle(&mut c).await, before);
                assert!(
                    read(
                        &store,
                        &verifier,
                        if local_mode { LOCAL_RAW } else { &raw },
                        if local_mode { &local } else { &native },
                        deadline(),
                        local_mode
                    )
                    .await
                    .is_ok()
                );
            }
        }
    }
    let stale = read(
        &store,
        &verifier,
        &raw,
        &native,
        Instant::now() + Duration::from_millis(100),
        false,
    )
    .await
    .unwrap();
    let (utc, mono) = stale.authentication_expiry();
    assert!(utc > SystemTime::now() + Duration::from_secs(1));
    assert!(mono > Instant::now() + Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(
        stale.check().unwrap_err(),
        Error::Native(Native::Control(ControlError::Deadline))
    );
    assert_eq!(
        stale.filter_snapshot(data(A)).unwrap_err(),
        Error::Native(Native::Control(ControlError::Deadline))
    );
    let before = oracle(&mut c).await;
    store.shutdown(deadline()).await.unwrap();
    denied(
        &mut c,
        &store,
        &verifier,
        &raw,
        &native,
        Error::Native(Native::Control(ControlError::Closed)),
        false,
    )
    .await;
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    assert!(
        read(&reopened, &verifier, &raw, &native, deadline(), false)
            .await
            .is_ok()
    );
    assert_eq!(oracle(&mut c).await, before);
    reopened.shutdown(deadline()).await.unwrap();
    blocker.close().await.unwrap();
    c.close().await.unwrap();
}
