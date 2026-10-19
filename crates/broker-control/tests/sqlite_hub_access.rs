#[allow(
    dead_code,
    reason = "shared SQLite fixture also serves administrative tests"
)]
#[path = "support/sqlite_admin_fixture.rs"]
mod fixture;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessVerifier, ControlError, FlowLimits, HubAccessError as Error, HubAccessResolution,
    ResourceGrantReadError, SqliteControlConfig, SqliteControlStore,
};
use broker_security::{CredentialDigester, DigestLimits};
use fixture::{Fixture, end, n};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const ISSUER: &str = "https://broker.example.test";
const RESOURCE: &str = "https://broker.example.test/v1";
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

fn clear(db: &Connection) {
    db.execute_batch(
        "DELETE FROM resource_grants; UPDATE resource_acl_state SET revision=revision+1 WHERE id=1",
    )
    .unwrap();
}
fn grant(db: &Connection, id: &str, kind: &str, principal: &str, caps: &[&str], projects: &[&str]) {
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES(?1,'fixture',?2,?3,'',0,0)", params![id,kind,principal]).unwrap();
    for c in caps {
        db.execute(
            "INSERT INTO grant_capabilities(grant_id,value) VALUES(?1,?2)",
            params![id, c],
        )
        .unwrap();
    }
    for p in projects {
        db.execute(
            "INSERT INTO grant_projects(grant_id,value) VALUES(?1,?2)",
            params![id, p],
        )
        .unwrap();
    }
}
fn wire(mut r: HubAccessResolution<'_>) -> Value {
    r.check().unwrap();
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 4);
    assert_eq!(v["v"], 1);
    v
}
async fn native(
    store: &SqliteControlStore,
    verifier: &BrokerAccessVerifier,
    raw: Option<&str>,
    deadline: Instant,
) -> Result<Value, Error> {
    Ok(wire(
        store
            .broker_hub_access_resolver(verifier, n(65536))?
            .resolve(raw, deadline)
            .await?,
    ))
}
async fn local(f: &Fixture, raw: Option<&str>) -> Result<Value, Error> {
    Ok(wire(
        f.store
            .local_hub_access_resolver("admin-api", n(8192), n(65536))?
            .resolve(raw, end())
            .await?,
    ))
}
#[tokio::test]
#[ignore = "real private SQLite, Ed25519 and current opaque authority"]
async fn sqlite_hub_current_policy_and_identity() {
    let f = Fixture::new().await;
    let db = f.db();
    let signer = Signer::new();
    let v = signer.verifier(Some(RESOURCE));
    let token = signer.sign(&signer.claims());
    clear(&db);
    for (kind, principal, matched) in [
        ("user", "alice", true),
        ("user", "ali*", false),
        ("user", "Alice", false),
        ("team", "dev", true),
        ("organization", "engineering", true),
        ("subject", "hub-subject", true),
        ("subject", "https://broker.example.test|hub-subject", true),
        ("user", "anonymous", false),
    ] {
        clear(&db);
        grant(&db, "literal", kind, principal, &["hub"], &[A]);
        assert_eq!(
            native(&f.store, &v, Some(&token), end()).await.unwrap()["selectors"],
            if matched {
                json!([{"id":A}])
            } else {
                json!([])
            }
        );
        assert_eq!(
            native(&f.store, &v, None, end()).await.unwrap()["selectors"],
            json!([])
        );
    }
    clear(&db);
    grant(&db, "a", "anonymous", "", &["hub"], &[A]);
    grant(&db, "b", "global", "", &["hub"], &[A, B]);
    grant(&db, "c", "authenticated", "", &["hub"], &[]);
    grant(&db, "d", "global", "", &["ast.read"], &["*"]);
    let anon = native(&f.store, &v, None, end()).await.unwrap();
    assert_eq!(anon["selectors"], json!([{"id":A},{"id":B}]));
    assert_eq!(anon["subject"], "anonymous|anonymous");
    let auth = native(&f.store, &v, Some(&token), end()).await.unwrap();
    assert_eq!(auth["selectors"], json!([{"id":A},{"id":B},{"all":true}]));
    assert!(native(&f.store, &v, Some("invalid"), end()).await.is_err());
    assert!(native(&f.store, &v, Some(&f.access), end()).await.is_err());
    assert!(local(&f, Some(&token)).await.is_err());
    clear(&db);
    grant(&db, "alice", "user", "alice", &["hub"], &[A]);
    grant(&db, "bot", "user", "bot", &["hub"], &[B]);
    assert_eq!(
        local(&f, Some(&f.access)).await.unwrap()["selectors"],
        json!([{"id":A}])
    );
    assert_eq!(
        local(&f, Some(&f.service)).await.unwrap()["selectors"],
        json!([{"id":B}])
    );
    let mut retained = f
        .store
        .local_hub_access_resolver("admin-api", n(8192), n(65536))
        .unwrap()
        .resolve(Some(&f.access), end())
        .await
        .unwrap();
    db.execute(
        "UPDATE local_users SET revision=revision+1 WHERE username='alice'",
        [],
    )
    .unwrap();
    assert!(local(&f, Some(&f.access)).await.is_err());
    retained.check().unwrap(); // retained proof is not a retroactive SQL lease
    drop(retained);
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test]
#[ignore = "real SQLite reopen, ACL revision and finite failure paths"]
async fn sqlite_hub_reopen_caps_corruption_deadline_and_closed() {
    let f = Fixture::new().await;
    let db = f.db();
    let signer = Signer::new();
    let v = signer.verifier(None);
    clear(&db);
    grant(&db, "a", "global", "", &["hub"], &[A]);
    let before = native(&f.store, &v, None, end()).await.unwrap();
    db.execute_batch(
        "DELETE FROM resource_grants; UPDATE resource_acl_state SET revision=revision+1 WHERE id=1",
    )
    .unwrap();
    let after = native(&f.store, &v, None, end()).await.unwrap();
    assert_ne!(
        before["authorization_revision"],
        after["authorization_revision"]
    );
    assert_eq!(after["selectors"], json!([]));
    grant(&db, "a", "global", "", &["hub"], &[B]);
    assert!(matches!(
        f.store
            .broker_hub_access_resolver(&v, n(1))
            .unwrap()
            .resolve(None, end())
            .await,
        Err(Error::Grants(ResourceGrantReadError::ReadLimitExceeded))
    ));
    db.execute("UPDATE resource_grants SET access_kind='invalid'", [])
        .unwrap();
    assert!(matches!(
        native(&f.store, &v, None, end()).await,
        Err(Error::InvalidPolicy)
    ));
    db.execute("UPDATE resource_grants SET access_kind='global'", [])
        .unwrap();
    assert!(matches!(
        native(&f.store, &v, None, Instant::now()).await,
        Err(Error::Control(ControlError::Deadline))
    ));
    db.execute("DELETE FROM resource_acl_state", []).unwrap();
    assert!(native(&f.store, &v, None, end()).await.is_err());
    db.execute(
        "INSERT INTO resource_acl_state(id,revision,updated_at) VALUES(1,99,0)",
        [],
    )
    .unwrap();
    f.store.shutdown(end()).await.unwrap();
    assert!(matches!(
        native(&f.store, &v, None, end()).await,
        Err(Error::Grants(ResourceGrantReadError::Control(
            ControlError::Closed
        )))
    ));
    let reopened = SqliteControlStore::open(
        SqliteControlConfig::new(
            f.path.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            FlowLimits {
                provider_bytes: n(128),
                request_bytes: n(256),
                continuation_bytes: n(1024),
            },
        )
        .unwrap(),
        CredentialDigester::new(
            zeroize::Zeroizing::new(vec![93; 32].into_boxed_slice()),
            DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
        )
        .unwrap(),
        end(),
    )
    .await
    .unwrap();
    assert_eq!(
        native(&reopened, &v, None, end()).await.unwrap()["selectors"],
        json!([{"id":B}])
    );
    reopened.shutdown(end()).await.unwrap();
}

// Withhold delivery at the real executor's post-COMMIT event. This observes an
// actual SQLite transaction; it does not inject a result or simulate network loss.
struct CommitDelivery {
    armed: std::sync::atomic::AtomicBool,
    seen: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
impl tracing::Subscriber for CommitDelivery {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "broker_control::sqlite::commit_confirmed"
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {
        if self.armed.swap(false, std::sync::atomic::Ordering::AcqRel) {
            self.seen.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real SQLite COMMIT with retained owner and withheld caller acknowledgement"]
async fn sqlite_hub_commit_without_ack_never_emits_resolution() {
    let (seen, committed) = std::sync::mpsc::sync_channel(1);
    let (release, withheld) = std::sync::mpsc::sync_channel(1);
    let subscriber = std::sync::Arc::new(CommitDelivery {
        armed: std::sync::atomic::AtomicBool::new(false),
        seen,
        release: std::sync::Mutex::new(withheld),
    });
    tracing::subscriber::set_global_default(subscriber.clone()).unwrap();
    let f = Fixture::new().await;
    let db = f.db();
    clear(&db);
    grant(&db, "a", "global", "", &["hub"], &[A]);
    let verifier = Signer::new().verifier(None);
    subscriber
        .armed
        .store(true, std::sync::atomic::Ordering::Release);
    let store = f.store.clone();
    let task = tokio::spawn(async move {
        store
            .broker_hub_access_resolver(&verifier, n(65536))
            .unwrap()
            .resolve(None, Instant::now() + Duration::from_millis(500))
            .await
            .map(|_| ())
    });
    tokio::task::spawn_blocking(move || committed.recv_timeout(Duration::from_secs(2)).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(Error::Grants(ResourceGrantReadError::Control(
            ControlError::OutcomeUncertain
        )))
    ));
    release.send(()).unwrap();
    f.store.shutdown(end()).await.unwrap();
}
