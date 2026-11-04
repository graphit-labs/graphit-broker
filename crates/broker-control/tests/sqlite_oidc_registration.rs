use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    ControlError, FlowLimits, OIDC_REGISTRATION_BODY_BYTES, OidcAuthorizationConfiguration,
    OidcAuthorizationLimits, OidcAuthorizationPolicy, OidcRegistrationError as Error,
    SqliteControlConfig, SqliteControlStore,
};
use broker_security::{CredentialDigester, DigestLimits};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn utc() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(vec![41; 32].into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
fn config(path: &Path, operation: Duration) -> SqliteControlConfig {
    SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(5),
        operation,
        Duration::from_secs(5),
        FlowLimits {
            provider_bytes: n(128),
            request_bytes: n(1024),
            continuation_bytes: n(4096),
        },
    )
    .unwrap()
}
fn policy(enabled: bool, json_bytes: usize, parameter: usize) -> OidcAuthorizationPolicy {
    OidcAuthorizationPolicy::new(
        OidcAuthorizationConfiguration {
            cli_client_id: "graphit-cli".into(),
            cli_redirect_path: "/oauth/callback".into(),
            api_audience: "graphit-broker".into(),
            accepted_resources: vec![],
            dynamic_registration: enabled,
            authorization_ttl: Duration::from_secs(60),
        },
        OidcAuthorizationLimits::new(n(json_bytes), n(parameter)).unwrap(),
    )
    .unwrap()
}
fn metadata() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"redirect_uris":["http://127.0.0.1:43210/callback"],"client_name":"Public client"}),
    )
    .unwrap()
}
struct Fixture {
    store: Arc<SqliteControlStore>,
    db: Connection,
    path: PathBuf,
    _temp: tempfile::TempDir,
}
impl Fixture {
    async fn new(operation: Duration) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private").join("broker.db");
        let store = Arc::new(
            SqliteControlStore::open(config(&path, operation), digester(), end())
                .await
                .unwrap(),
        );
        let db = Connection::open(&path).unwrap();
        Self {
            store,
            db,
            path,
            _temp: temp,
        }
    }
    fn count(&self) -> i64 {
        count(&self.db)
    }
    fn seed(&self) {
        self.db.execute("INSERT INTO oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES(?1,?2,?3,?4,?5,?6)", params!["existing-client","untouched","[\"https://existing.example/cb\"]","[\"openid\"]","web",1]).unwrap();
    }
}
fn count(db: &Connection) -> i64 {
    db.query_row("SELECT count(*) FROM oauth_dynamic_clients", [], |row| {
        row.get(0)
    })
    .unwrap()
}
fn body(value: &broker_control::RegisteredOidcClient) -> Value {
    serde_json::to_value(value).unwrap()
}
fn id(value: &Value) -> &str {
    value["client_id"].as_str().unwrap()
}
fn assert_public(value: &Value) {
    let client = id(value);
    assert_eq!(client.len(), 43);
    let bytes = URL_SAFE_NO_PAD.decode(client).unwrap();
    assert_eq!(bytes.len(), 32);
    assert_eq!(URL_SAFE_NO_PAD.encode(bytes), client);
    assert_ne!(client, "graphit-cli");
    assert_eq!(value["token_endpoint_auth_method"], "none");
    assert_eq!(
        value["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(value["response_types"], json!(["code"]));
    for key in [
        "client_secret",
        "client_secret_expires_at",
        "registration_access_token",
        "registration_client_uri",
    ] {
        assert!(
            value.get(key).is_none(),
            "unexpected public response field {key}"
        );
    }
}

#[tokio::test]
async fn disabled_and_invalid_metadata_leave_catalog_untouched() {
    let f = Fixture::new(Duration::from_secs(2)).await;
    let disabled = policy(false, 8192, 4096);
    assert!(!f.store.oidc_registration_service(&disabled).enabled());
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        f.store
            .oidc_registration_service(&disabled)
            .register(b"not JSON", Instant::now())
            .await,
        Err(Error::Disabled)
    ));
    f.db.execute_batch("ROLLBACK").unwrap();
    let enabled = policy(true, 8192, 4096);
    let service = f.store.oidc_registration_service(&enabled);
    assert!(service.enabled());
    assert_eq!(
        format!("{service:?}"),
        "SqliteOidcRegistrationService([REDACTED])"
    );
    let mut invalid = vec![
        br#"{}"#.to_vec(),
        br#"{"redirect_uris":"https://client.example/cb"}"#.to_vec(),
        br#"{"redirect_uris":["https://client.example/cb"],"redirect_uris":["https://other.example/cb"]}"#.to_vec(),
        br#"{"redirect_uris":["https://client.example/cb"],"scope":42}"#.to_vec(),
        br#"{"redirect_uris":["https://client.example/cb"],"scope":"openid","scope":"profile"}"#.to_vec(),
        br#"{"redirect_uris":["http://remote.example/cb"]}"#.to_vec(),
        br#"{"redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}"#.to_vec(),
        br#"{"redirect_uris":["https://client.example/cb"],"grant_types":["client_credentials"]}"#.to_vec(),
        br#"{"redirect_uris":["https://client.example/cb"],"response_types":["token"]}"#.to_vec(),
        br#"{"redirect_uris":["https://client.example/cb"],"scope":"custom"}"#.to_vec(),
        vec![b' '; OIDC_REGISTRATION_BODY_BYTES + 1],
    ];
    let mut trailing = metadata();
    trailing.extend_from_slice(b" {}");
    invalid.push(trailing);
    invalid.push(
        serde_json::to_vec(
            &json!({"redirect_uris":["https://client.example/cb"],"client_name":"🦀".repeat(257)}),
        )
        .unwrap(),
    );
    for raw in invalid {
        assert!(matches!(
            service.register(&raw, end()).await,
            Err(Error::InvalidMetadata)
        ));
        assert_eq!(f.count(), 0);
    }
    for limited in [policy(true, 4, 4096), policy(true, 8192, 32)] {
        let raw = serde_json::to_vec(
            &json!({"redirect_uris":["https://client.example/cb"],"client_name":"a".repeat(33)}),
        )
        .unwrap();
        assert!(matches!(
            f.store
                .oidc_registration_service(&limited)
                .register(&raw, end())
                .await,
            Err(Error::InvalidMetadata)
        ));
        assert_eq!(f.count(), 0);
    }
    assert!(matches!(
        service.register(&metadata(), Instant::now()).await,
        Err(Error::Control(ControlError::Deadline))
    ));
    assert_eq!(f.count(), 0);
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test]
async fn sdk_response_six_columns_and_reopen_preserve_public_client() {
    let f = Fixture::new(Duration::from_secs(2)).await;
    f.seed();
    let policy = policy(true, 8192, 4096);
    let raw = serde_json::to_vec(&json!({
        "client_name":"  Mixed client  ", "client_id":"caller-selected-id",
        "redirect_uris":[" HTTPS://Client.example:443/cb?q=%2F ","http://localhost:8123/cb","http://localhost:8123/cb"],
        "application_type":"native", "scope":" profile openid profile ",
        "extension":{"do_not_fetch":"https://unreachable.invalid/metadata"}
    })).unwrap();
    let before = utc();
    let response = f
        .store
        .oidc_registration_service(&policy)
        .register(&raw, end())
        .await
        .unwrap();
    let after = utc();
    assert_eq!(format!("{response:?}"), "RegisteredOidcClient([REDACTED])");
    let public = body(&response);
    assert_public(&public);
    assert_ne!(id(&public), "caller-selected-id");
    assert_eq!(public["scope"], "profile openid");
    assert_eq!(public["application_type"], "web");
    assert_eq!(public["client_name"], "Mixed client");
    let redirects = json!([
        "HTTPS://Client.example:443/cb?q=%2F",
        "http://localhost:8123/cb"
    ]);
    assert_eq!(public["redirect_uris"], redirects);
    let row = f.db.query_row("SELECT client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at FROM oauth_dynamic_clients WHERE client_id=?1", [id(&public)], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,i64>(5)?))).unwrap();
    assert_eq!(row.0, id(&public));
    assert_eq!(row.1, "Mixed client");
    assert_eq!(serde_json::from_str::<Value>(&row.2).unwrap(), redirects);
    assert_eq!(row.3, r#"["profile","openid"]"#);
    assert_eq!(row.4, "web");
    assert!((before..=after).contains(&row.5));
    assert_eq!(
        public["client_id_issued_at"].as_i64(),
        Some(row.5 / 1_000_000)
    );
    assert_eq!(f.count(), 2);
    assert_eq!(
        f.db.query_row(
            "SELECT client_name FROM oauth_dynamic_clients WHERE client_id='existing-client'",
            [],
            |row| row.get::<_, String>(0)
        )
        .unwrap(),
        "untouched"
    );
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM oauth_dynamic_clients WHERE client_id='graphit-cli'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    f.store.shutdown(end()).await.unwrap();
    let reopened =
        SqliteControlStore::open(config(&f.path, Duration::from_secs(2)), digester(), end())
            .await
            .unwrap();
    let fresh = Connection::open(&f.path).unwrap();
    assert_eq!(count(&fresh), 2);
    assert_eq!(
        fresh
            .query_row(
                "SELECT created_at FROM oauth_dynamic_clients WHERE client_id=?1",
                [id(&public)],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        row.5
    );
    reopened.shutdown(end()).await.unwrap();
}

#[tokio::test]
async fn default_scopes_and_exact_input_limits_use_existing_admission() {
    let f = Fixture::new(Duration::from_secs(2)).await;
    let policy = policy(true, 8192, 4096);
    for scope in [None, Some(""), Some("  ")] {
        let mut input = json!({"redirect_uris":["http://127.0.0.1:43210/callback"]});
        if let Some(scope) = scope {
            input["scope"] = scope.into();
        }
        let response = f
            .store
            .oidc_registration_service(&policy)
            .register(&serde_json::to_vec(&input).unwrap(), end())
            .await
            .unwrap();
        let public = body(&response);
        assert_public(&public);
        assert_eq!(public["scope"], "openid profile email offline_access");
        assert_eq!(public["application_type"], "native");
        let scopes: String =
            f.db.query_row(
                "SELECT scopes_json FROM oauth_dynamic_clients WHERE client_id=?1",
                [id(&public)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(scopes, r#"["openid","profile","email","offline_access"]"#);
    }
    let mut exact = json!({"redirect_uris":["https://client.example/cb"],"client_name":"🦀".repeat(256),"extension":""});
    let base = serde_json::to_vec(&exact).unwrap().len();
    exact["extension"] = "x".repeat(OIDC_REGISTRATION_BODY_BYTES - base).into();
    let raw = serde_json::to_vec(&exact).unwrap();
    assert_eq!(raw.len(), OIDC_REGISTRATION_BODY_BYTES);
    let response = f
        .store
        .oidc_registration_service(&policy)
        .register(&raw, end())
        .await
        .unwrap();
    assert_eq!(body(&response)["client_name"], "🦀".repeat(256));
    assert_eq!(f.count(), 4);
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_owners_insert_once_without_overwriting_existing_rows() {
    let f = Fixture::new(Duration::from_secs(2)).await;
    f.seed();
    let other =
        SqliteControlStore::open(config(&f.path, Duration::from_secs(2)), digester(), end())
            .await
            .unwrap();
    let policy = policy(true, 8192, 4096);
    let raw = metadata();
    let first = f.store.oidc_registration_service(&policy);
    let second = other.oidc_registration_service(&policy);
    let (a, b) = tokio::join!(first.register(&raw, end()), second.register(&raw, end()));
    let a = body(&a.unwrap());
    let b = body(&b.unwrap());
    assert_public(&a);
    assert_public(&b);
    assert_ne!(id(&a), id(&b));
    assert_eq!(f.count(), 3);
    assert_eq!(
        f.db.query_row(
            "SELECT created_at FROM oauth_dynamic_clients WHERE client_id='existing-client'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    other.shutdown(end()).await.unwrap();
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_lock_deadlines_cancel_and_close_recover_without_response_or_replay() {
    let normal_budget = Duration::from_secs(2);
    let short_budget = Duration::from_millis(80);
    for caller in [short_budget, normal_budget] {
        let f = Fixture::new(normal_budget).await;
        let short = if caller == normal_budget {
            Some(
                SqliteControlStore::open(config(&f.path, short_budget), digester(), end())
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let policy = policy(true, 8192, 4096);
        let raw = metadata();
        f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let store = short.as_ref().unwrap_or(f.store.as_ref());
        let service = store.oidc_registration_service(&policy);
        let mut pending = Box::pin(service.register(&raw, Instant::now() + caller));
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        assert_eq!(f.count(), 0);
        assert!(matches!(
            pending.await,
            Err(Error::Control(ControlError::Deadline))
        ));
        assert_eq!(f.count(), 0);
        f.db.execute_batch("ROLLBACK").unwrap();
        // A timed-out call may leave SQLite releasing its transaction. Drain the
        // short-budget owner before testing a new registration on the same database.
        if let Some(short) = short {
            short.shutdown(end()).await.unwrap();
            assert_eq!(f.count(), 0);
        }
        let recovered = f
            .store
            .oidc_registration_service(&policy)
            .register(&raw, end())
            .await
            .unwrap();
        assert_public(&body(&recovered));
        assert_eq!(f.count(), 1);
        f.store.shutdown(end()).await.unwrap();
    }
    let f = Fixture::new(Duration::from_secs(2)).await;
    let policy = policy(true, 8192, 4096);
    let raw = metadata();
    let service = f.store.oidc_registration_service(&policy);
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut pending = Box::pin(service.register(&raw, end()));
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    drop(pending);
    f.db.execute_batch("ROLLBACK").unwrap();
    let recovered = service.register(&raw, end()).await.unwrap();
    assert_public(&body(&recovered));
    assert_eq!(f.count(), 1);
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut pending = Box::pin(service.register(&raw, end()));
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    let closing = f.store.shutdown(end());
    assert!(matches!(
        pending.await,
        Err(Error::Control(ControlError::Closed))
    ));
    f.db.execute_batch("ROLLBACK").unwrap();
    closing.await.unwrap();
    assert_eq!(f.count(), 1);
    assert!(matches!(
        service.register(&raw, end()).await,
        Err(Error::Control(ControlError::Closed))
    ));
    let reopened =
        SqliteControlStore::open(config(&f.path, Duration::from_secs(2)), digester(), end())
            .await
            .unwrap();
    assert_eq!(f.count(), 1);
    reopened.shutdown(end()).await.unwrap();
}
