use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    AdminBrokerSessionLimits, FlowLimits, IdentityReadLimits, SqliteControlConfig,
    SqliteControlStore,
};
use broker_security::{CredentialDigester, DigestLimits, TokenKind};
use rusqlite::{Connection, params};
use serde_json::json;
use std::{
    num::NonZeroUsize,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
pub fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
pub fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
        .try_into()
        .unwrap()
}
pub fn limits() -> AdminBrokerSessionLimits {
    AdminBrokerSessionLimits {
        identity: IdentityReadLimits {
            username_bytes: n(128),
            subject_bytes: n(512),
            role_bytes: n(128),
            roles: n(16),
            rows: n(128),
        },
        profile_json_bytes: n(8192),
    }
}
pub struct Fixture {
    _root: tempfile::TempDir,
    pub path: PathBuf,
    pub store: Arc<SqliteControlStore>,
    pub access: String,
    pub service: String,
}
impl Fixture {
    pub async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private/broker.db");
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        let digester = CredentialDigester::new(
            Zeroizing::new(key.to_vec().into_boxed_slice()),
            DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
        )
        .unwrap();
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).unwrap();
        let access = format!("gb_at_{}", URL_SAFE_NO_PAD.encode(bytes));
        getrandom::fill(&mut bytes).unwrap();
        let service = format!("gb_sc_{}", URL_SAFE_NO_PAD.encode(bytes));
        let ah = digester
            .token(TokenKind::LocalAccess, access.as_bytes())
            .unwrap()
            .to_sql_hex();
        let sh = digester
            .token(TokenKind::ServiceCredential, service.as_bytes())
            .unwrap()
            .to_sql_hex();
        let store = Arc::new(
            SqliteControlStore::open(
                SqliteControlConfig::new(
                    path.clone(),
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
                digester,
                end(),
            )
            .await
            .unwrap(),
        );
        let f = Self {
            _root: root,
            path,
            store,
            access,
            service,
        };
        let db = f.db();
        for (username, subject, kind, hash) in [
            ("alice", "alice-subject", "human", ah),
            ("bot", "bot-subject", "service", sh),
        ] {
            db.execute(r#"INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES(?1,?2,?3,'not-selected','Current','current@example.invalid','org','[" z ","a","z"]',1,1,1,0,0)"#,params![username,subject,kind]).unwrap();
            let principal=json!({"issuer":"local","subject":subject,"username":"stale-user","name":"stale-name","auth_method":"stale-method","roles":["admin"],"teams":["stale"],"local_user_revision":1}).to_string();
            db.execute(r#"INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES(?1,?2,?3,?4,'different-pseudonym',?5,'client','admin-api','','["admin:session"]',1,'',0,?6,0)"#,params![hash,username,if kind=="human"{"access"}else{"service"},subject,principal,now()+60_000_000]).unwrap();
        }
        f
    }
    pub fn db(&self) -> Connection {
        let db = Connection::open(&self.path).unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db
    }
}
