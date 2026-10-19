//! Private test inputs. Persisted opaque possession is not a bearer emitter.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    AuthorizedStorageGrant, BrokerAccessVerifier, FlowLimits, LocalBearerKind, SqliteControlConfig,
    SqliteControlStore, StorageAdmissionError, StorageModule, StorageOperation, StorageScope,
};
use broker_security::{CredentialDigester, DigestLimits};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
pub const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
pub const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
pub const ISSUER: &str = "https://broker.example.test";
pub const AUDIENCE: &str = "storage-api";
pub const RESOURCE: &str = "https://broker.example.test/v1";
pub fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
pub fn end() -> Instant {
    Instant::now() + Duration::from_secs(12)
}
pub fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
pub fn micros() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
pub fn config(path: &Path) -> SqliteControlConfig {
    SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        FlowLimits {
            provider_bytes: n(128),
            request_bytes: n(256),
            continuation_bytes: n(1024),
        },
    )
    .unwrap()
}
pub fn digester(key: &[u8]) -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(key.to_vec().into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
pub struct Signer {
    key: EncodingKey,
    keys: jsonwebtoken::jwk::JwkSet,
}
impl Signer {
    pub fn new() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self {key:EncodingKey::from_ed_der(&pair.serialize_der()),keys:serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"storage-key","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())}]})).unwrap()}
    }
    pub fn verifier(&self) -> BrokerAccessVerifier {
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), &self.keys, n(8192)).unwrap()
    }
    pub fn claims(&self) -> Value {
        json!({"iss":ISSUER,"sub":"native-subject","aud":[AUDIENCE,RESOURCE],"iat":seconds()-1,"exp":seconds()+600,"token_use":"access","client_id":"configured-client","jti":"native-storage","scope":"storage","preferred_username":"alice","organization":"current-org","groups":["current-team"],"roles":["user"]})
    }
    pub fn sign(&self, claims: &Value) -> Zeroizing<String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("storage-key".into());
        Zeroizing::new(encode(&header, claims, &self.key).unwrap())
    }
}
pub struct Fixture {
    pub db: Connection,
    pub store: Arc<SqliteControlStore>,
    pub path: PathBuf,
    pub key: Zeroizing<[u8; 32]>,
    pub access: Zeroizing<String>,
    pub service: Zeroizing<String>,
    pub signer: Signer,
    _root: tempfile::TempDir,
}
fn raw(prefix: &str) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0; 32]);
    getrandom::fill(bytes.as_mut()).unwrap();
    Zeroizing::new(format!(
        "{prefix}{}",
        URL_SAFE_NO_PAD.encode(bytes.as_ref())
    ))
}
impl Fixture {
    pub async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private/broker.db");
        let mut key = Zeroizing::new([0; 32]);
        getrandom::fill(key.as_mut()).unwrap();
        let store = Arc::new(
            SqliteControlStore::open(config(&path), digester(key.as_ref()), end())
                .await
                .unwrap(),
        );
        let db = Connection::open(&path).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        for (username, subject, kind) in [
            ("alice", "alice-subject", "human"),
            ("bot", "bot-subject", "service"),
        ] {
            db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at)VALUES(?1,?2,?3,'unused-private-fixture','Current','current@example.test','current-org','[\"current-team\"]',1,0,1,0,0)",params![username,subject,kind]).unwrap();
        }
        let f = Self {
            db,
            store,
            path,
            key,
            access: raw("gb_at_"),
            service: raw("gb_sc_"),
            signer: Signer::new(),
            _root: root,
        };
        for (raw, kind, subject, id) in [
            (
                f.access.as_str(),
                LocalBearerKind::Access,
                "alice-subject",
                "fixture-access",
            ),
            (
                f.service.as_str(),
                LocalBearerKind::ServiceCredential,
                "bot-subject",
                "fixture-service",
            ),
        ] {
            let principal=json!({"issuer":"local","subject":subject,"username":"stale-name","auth_method":"stale-method","name":"stale-name","organization":"stale-org","teams":["stale-team"],"roles":["admin"],"local_user_revision":1}).to_string();
            f.db.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at)VALUES(?1,?2,?3,?4,'pseudonymous-other',?5,'configured-client',?6,'','[\"storage\"]',1,'',0,?7,0)",params![f.hash(raw,kind),id,kind.as_str(),subject,principal,AUDIENCE,micros()+600_000_000]).unwrap();
        }
        f
    }
    pub fn hash(&self, raw: &str, kind: LocalBearerKind) -> String {
        digester(self.key.as_ref())
            .token(kind.token_kind(), raw.as_bytes())
            .unwrap()
            .to_sql_hex()
    }
    pub async fn reopen(&self) -> SqliteControlStore {
        SqliteControlStore::open(config(&self.path), digester(self.key.as_ref()), end())
            .await
            .unwrap()
    }
    pub async fn close(&self) {
        self.store.shutdown(end()).await.unwrap();
    }
    pub fn revision(&self) -> i64 {
        self.db
            .query_row(
                "SELECT revision FROM resource_acl_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }
    pub fn clear(&self) {
        self.db.execute_batch("DELETE FROM resource_grants;UPDATE resource_acl_state SET revision=revision+1,updated_at=0 WHERE id=1").unwrap();
    }
    pub fn grant(&self, id: &str, rule: &Rule<'_>) {
        self.db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at)VALUES(?1,'fixture',?2,?3,?4,0,0)",params![id,rule.kind,rule.principal,rule.route]).unwrap();
        for (query, values) in [
            (
                "INSERT INTO grant_capabilities(grant_id,value)VALUES(?1,?2)",
                rule.caps,
            ),
            (
                "INSERT INTO grant_projects(grant_id,value)VALUES(?1,?2)",
                rule.projects,
            ),
            (
                "INSERT INTO grant_s3_operations(grant_id,value)VALUES(?1,?2)",
                rule.operations,
            ),
            (
                "INSERT INTO grant_s3_prefixes(grant_id,value)VALUES(?1,?2)",
                rule.prefixes,
            ),
        ] {
            for value in values {
                self.db.execute(query, params![id, value]).unwrap();
            }
        }
    }
}
pub struct Rule<'a> {
    pub kind: &'a str,
    pub principal: &'a str,
    pub caps: &'a [&'a str],
    pub projects: &'a [&'a str],
    pub operations: &'a [&'a str],
    pub prefixes: &'a [&'a str],
    pub route: &'a str,
}
impl Rule<'static> {
    pub fn all() -> Self {
        Self {
            kind: "authenticated",
            principal: "",
            caps: &["hub", "s3"],
            projects: &[],
            operations: &[],
            prefixes: &[],
            route: "",
        }
    }
}
pub fn scopes() -> Vec<StorageScope> {
    [
        StorageModule::Hub,
        StorageModule::Task,
        StorageModule::Memory,
        StorageModule::Knowledge,
        StorageModule::Ast,
    ]
    .into_iter()
    .map(|module| StorageScope::project(A, module).unwrap())
    .chain([
        StorageScope::user_memory("Install-A").unwrap(),
        StorageScope::global_hub(),
    ])
    .collect()
}
#[derive(Debug)]
pub struct Observation {
    pub route: String,
    pub revision: i64,
    pub subject: String,
    pub access: [Vec<String>; 4],
    pub original: Instant,
}
pub fn observe(grant: &AuthorizedStorageGrant<'_>) -> Observation {
    grant.check().unwrap();
    assert_eq!(format!("{grant:?}"), "AuthorizedStorageGrant([REDACTED])");
    Observation {
        route: grant.route().into(),
        revision: grant.revision(),
        subject: grant.canonical_subject(),
        access: [
            StorageOperation::Read,
            StorageOperation::Write,
            StorageOperation::Publish,
            StorageOperation::Delete,
        ]
        .map(|op| grant.prefixes(op).to_vec()),
        original: grant.request_deadline(),
    }
}
pub async fn native(
    f: &Fixture,
    raw: &str,
    scope: &StorageScope,
) -> Result<Observation, StorageAdmissionError> {
    let verifier = f.signer.verifier();
    let factory = f
        .store
        .broker_storage_authorizer(&verifier, n(65536), "configured")
        .unwrap();
    Ok(observe(
        &factory
            .authorize(raw, &["storage".into()], scope, end())
            .await?,
    ))
}
pub async fn opaque(
    f: &Fixture,
    raw: &str,
    scope: &StorageScope,
) -> Result<Observation, StorageAdmissionError> {
    let factory = f
        .store
        .local_storage_authorizer(AUDIENCE, n(8192), n(65536), "configured")
        .unwrap();
    Ok(observe(
        &factory
            .authorize(raw, &["storage".into()], scope, end())
            .await?,
    ))
}
