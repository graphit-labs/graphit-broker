#[allow(
    dead_code,
    reason = "shared SQLite fixture serves multiple identity journeys"
)]
#[path = "../../broker-control/tests/support/sqlite_admin_fixture.rs"]
mod fixture;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::BrokerAccessVerifier;
use broker_presence::{
    HubAccessHttpConfig, LocalHubAccessHttpConfig, sqlite_broker_hub_access_router,
    sqlite_local_hub_access_router,
};
use fixture::{Fixture, end, n};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::{TcpListener, TcpStream};
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const PATH: &str = "/v1/hub/access/resolve";
const ISSUER: &str = "https://broker.example.test";
const RESOURCE: &str = "https://broker.example.test/v1";
struct Signer {
    key: EncodingKey,
    keys: jsonwebtoken::jwk::JwkSet,
}
impl Signer {
    fn new() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self{key:EncodingKey::from_ed_der(&pair.serialize_der()),keys:serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"hub-key","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())}]})).unwrap()}
    }
    fn verifier(&self) -> BrokerAccessVerifier {
        BrokerAccessVerifier::new(ISSUER, "hub-api", Some(RESOURCE), &self.keys, n(8192)).unwrap()
    }
    fn claims(&self) -> Value {
        let now = seconds();
        json!({"iss":ISSUER,"sub":"http-subject","aud":["hub-api",RESOURCE],"iat":now-1,"exp":now+600,"token_use":"access","client_id":"explicit-client","jti":"hub-http-token","scope":"","preferred_username":"alice","organization":"engineering","groups":["dev"]})
    }
    fn sign(&self, v: &Value) -> String {
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("hub-key".into());
        encode(&h, v, &self.key).unwrap()
    }
}
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
struct Server {
    address: std::net::SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn start(app: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        Self {
            address,
            stop,
            task,
        }
    }
    async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(6), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}
// A canceled exchange must not detach its client-side connection driver.
struct Driver(Option<tokio::task::JoinHandle<Result<(), hyper::Error>>>);
impl Drop for Driver {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
#[derive(Debug)]
struct Reply {
    status: StatusCode,
    json: Value,
    challenge: bool,
    no_store: bool,
}
async fn exchange(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    auth: &[&str],
    body: Option<&str>,
) -> Reply {
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let mut worker = Driver(Some(tokio::spawn(connection)));
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("x-subject", "untrusted|admin");
    for a in auth {
        request = request.header(header::AUTHORIZATION, *a);
    }
    let reply = tokio::time::timeout(
        Duration::from_secs(8),
        sender.send_request(
            request
                .body(
                    body.map(|b| Body::from(b.to_owned()))
                        .unwrap_or_else(Body::empty),
                )
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let status = reply.status();
    let challenge = reply
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .is_some_and(|v| v == "Bearer");
    let no_store = reply
        .headers()
        .get(header::CACHE_CONTROL)
        .is_some_and(|v| v == "no-store");
    assert_eq!(
        reply.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let bytes = reply.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    drop(sender);
    tokio::time::timeout(Duration::from_secs(3), worker.0.take().unwrap())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    Reply {
        status,
        json,
        challenge,
        no_store,
    }
}
fn config() -> HubAccessHttpConfig {
    HubAccessHttpConfig {
        grants_json_bytes: n(65536),
        request_timeout: Duration::from_secs(2),
    }
}
fn local_config() -> LocalHubAccessHttpConfig {
    LocalHubAccessHttpConfig {
        audience: "admin-api".into(),
        identity_json_bytes: n(8192),
        grants_json_bytes: n(65536),
        request_timeout: Duration::from_secs(2),
    }
}
fn clear(db: &Connection) {
    db.execute_batch(
        "DELETE FROM resource_grants; UPDATE resource_acl_state SET revision=revision+1 WHERE id=1",
    )
    .unwrap();
}
fn grant(db: &Connection, id: &str, kind: &str, principal: &str, project: &str, route: &str) {
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES(?1,'fixture',?2,?3,?4,0,0)",params![id,kind,principal,route]).unwrap();
    db.execute(
        "INSERT INTO grant_capabilities(grant_id,value) VALUES(?1,'hub')",
        params![id],
    )
    .unwrap();
    db.execute(
        "INSERT INTO grant_projects(grant_id,value) VALUES(?1,?2)",
        params![id, project],
    )
    .unwrap();
}
fn error(r: &Reply, status: StatusCode, code: &str) {
    assert_eq!(r.status, status, "{r:?}");
    assert_eq!(r.json, json!({"error":{"code":code}}));
    assert!(!r.no_store);
}
#[tokio::test]
#[ignore = "real TCP, SQLite, Ed25519 and opaque Hub ingress"]
async fn sqlite_hub_resolve_http_current_authority() {
    let f = Fixture::new().await;
    let db = f.db();
    let signer = Signer::new();
    let token = format!("Bearer {}", signer.sign(&signer.claims()));
    let opaque = format!("Bearer {}", f.access);
    let native = Server::start(
        sqlite_broker_hub_access_router(f.store.clone(), Arc::new(signer.verifier()), config())
            .unwrap(),
    )
    .await;
    let local =
        Server::start(sqlite_local_hub_access_router(f.store.clone(), local_config()).unwrap())
            .await;
    clear(&db);
    grant(&db, "a", "anonymous", "", A, "");
    grant(&db, "b", "authenticated", "", B, "");
    for auth in [vec![], vec!["   "]] {
        let r = exchange(
            native.address,
            "POST",
            PATH,
            &auth,
            Some("{bad body, ignored"),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(r.no_store);
        assert_eq!(r.json.as_object().unwrap().len(), 4);
        assert_eq!(r.json["selectors"], json!([{"id":A}]));
        assert_eq!(r.json["subject"], "anonymous|anonymous");
    }
    for auth in [
        vec!["", ""],
        vec!["Bearer invalid"],
        vec!["Basic invalid"],
        vec![opaque.as_str()],
    ] {
        let r = exchange(native.address, "POST", PATH, &auth, None).await;
        error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
        assert!(r.challenge);
    }
    let r = exchange(native.address, "POST", PATH, &[&token], Some("ignored")).await;
    assert_eq!(r.json["selectors"], json!([{"id":B}]));
    assert_eq!(r.json["subject"], format!("{ISSUER}|http-subject"));
    let r = exchange(local.address, "POST", PATH, &[&opaque], None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["subject"], "local|alice-subject");
    error(
        &exchange(local.address, "POST", PATH, &[&token], None).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    let revision = r.json["authorization_revision"].clone();
    clear(&db);
    let r = exchange(local.address, "POST", PATH, &[&opaque], None).await;
    assert_eq!(r.json["selectors"], json!([]));
    assert_ne!(r.json["authorization_revision"], revision);
    db.execute(
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
        [],
    )
    .unwrap();
    error(
        &exchange(local.address, "POST", PATH, &[&opaque], None).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    grant(&db, "bad", "invalid", "", A, "");
    error(
        &exchange(native.address, "POST", PATH, &[], None).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    error(
        &exchange(native.address, "GET", PATH, &[], None).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    );
    error(
        &exchange(native.address, "POST", "/unknown", &[], None).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    clear(&db);
    let timed = Server::start(
        sqlite_broker_hub_access_router(
            f.store.clone(),
            Arc::new(signer.verifier()),
            HubAccessHttpConfig {
                grants_json_bytes: n(65536),
                request_timeout: Duration::from_nanos(1),
            },
        )
        .unwrap(),
    )
    .await;
    error(
        &exchange(timed.address, "POST", PATH, &[], None).await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    timed.stop().await;
    f.store.shutdown(end()).await.unwrap();
    error(
        &exchange(native.address, "POST", PATH, &[], None).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "closed",
    );
    native.stop().await;
    local.stop().await;
}

// Seed physical metadata documents, not credentials or storage authorization.
// Publication/STS is a separate journey; this target exercises the real confined reader.
fn metadata(root: &std::path::Path, route: &str, id: &str, bytes: &[u8]) {
    let file = root.join(route).join(format!(
        "data/hub-root/v1/projects/{id}/hub/metadata/project.json"
    ));
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, bytes).unwrap();
}
fn catalog_config() -> broker_presence::HubCatalogHttpConfig {
    broker_presence::HubCatalogHttpConfig {
        audience: "admin-api".into(),
        identity_json_bytes: n(8192),
        grants_json_bytes: n(65536),
        default_route: "first".into(),
        query_bytes: n(8192),
        request_timeout: Duration::from_secs(2),
    }
}
#[tokio::test]
#[ignore = "real TCP, SQLite authority and confined filesystem metadata catalog"]
async fn sqlite_hub_catalog_pages_bound_authority_routes_and_metadata() {
    use broker_storage::{
        FilesystemStorageIssuer, FilesystemStorageRoute, FilesystemStorageRouteConfig,
        FilesystemStore, FilesystemStoreConfig, HubCatalogReader, StorageCredentialsService,
        StorageIssuer,
    };
    let f = Fixture::new().await;
    let db = f.db();
    clear(&db);
    grant(&db, "a", "authenticated", "", A, "first");
    grant(&db, "b", "authenticated", "", B, "second");
    let root = tempfile::tempdir().unwrap();
    let mut stores = Vec::new();
    let mut routes = Vec::new();
    for name in ["first", "second"] {
        stores.push(Arc::new(
            FilesystemStore::open(FilesystemStoreConfig {
                directory: root.path().join(name),
                bucket: format!("bucket-{name}"),
                max_object_bytes: std::num::NonZeroU64::new(65536).unwrap(),
                metadata_bytes: n(8192),
            })
            .unwrap(),
        ));
        routes.push(
            FilesystemStorageRoute::new(FilesystemStorageRouteConfig {
                name: name.into(),
                bucket: format!("bucket-{name}"),
                region: "local".into(),
                base_prefix: "hub-root".into(),
                endpoint: "https://storage.example.test".into(),
                session_duration: Duration::from_secs(900),
                token_bytes: n(8192),
            })
            .unwrap(),
        );
    }
    let a = json!({"v":1,"project":{"id":A,"name":"alpha-project","status":"active"}}).to_string();
    let b = json!({"v":1,"project":{"id":B,"name":"beta-project","status":"active"}}).to_string();
    metadata(root.path(), "first", A, a.as_bytes());
    metadata(root.path(), "second", B, b.as_bytes());
    let storage = Arc::new(
        StorageCredentialsService::new(vec![StorageIssuer::Filesystem(
            FilesystemStorageIssuer::new(routes, zeroize::Zeroizing::new(vec![7; 32])).unwrap(),
        )])
        .unwrap(),
    );
    let reader = Arc::new(HubCatalogReader::new(storage, stores, n(8192)));
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let jwt = format!("Bearer {}", signer.sign(&signer.claims()));
    let opaque = format!("Bearer {}", f.access);
    let server = Server::start(
        broker_presence::sqlite_hub_catalog_router(
            f.store.clone(),
            verifier.clone(),
            reader.clone(),
            catalog_config(),
        )
        .unwrap(),
    )
    .await;
    let path = "/v1/hub/catalog/projects";
    let first = exchange(
        server.address,
        "GET",
        &format!("{path}?limit=1"),
        &[&jwt],
        None,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(first.no_store);
    assert_eq!(first.json.as_object().unwrap().len(), 5);
    assert_eq!(
        first.json["projects"],
        json!([{"id":A,"name":"alpha-project"}])
    );
    let cursor = first.json["next_cursor"].as_str().unwrap();
    let next = exchange(
        server.address,
        "GET",
        &format!("{path}?limit=1&cursor={cursor}"),
        &[&jwt],
        None,
    )
    .await;
    assert_eq!(next.status, StatusCode::OK);
    assert_eq!(
        next.json["projects"],
        json!([{"id":B,"name":"beta-project"}])
    );
    assert!(next.json["next_cursor"].is_null());
    let head = exchange(server.address, "HEAD", path, &[&jwt], None).await;
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.no_store);
    assert!(head.json.is_null());
    let local = exchange(
        server.address,
        "GET",
        &format!("{path}?id={B}"),
        &[&opaque],
        None,
    )
    .await;
    assert_eq!(local.json["projects"], next.json["projects"]);
    let prefix = exchange(
        server.address,
        "GET",
        &format!("{path}?name_prefix=alpha"),
        &[&jwt],
        None,
    )
    .await;
    assert_eq!(prefix.json["projects"], first.json["projects"]);
    let anon = exchange(server.address, "GET", path, &[], None).await;
    assert_eq!(anon.status, StatusCode::OK);
    assert_eq!(anon.json["projects"], json!([]));
    for query in [
        "limit=0",
        "limit=1001",
        "limit=bad",
        "id=x",
        "unknown=x",
        "limit=1&limit=1",
        "id=01D39ZY06FGSCTVN4T2V9PKHFZ&name_prefix=alpha",
        "name_prefix=",
    ] {
        error(
            &exchange(
                server.address,
                "GET",
                &format!("{path}?{query}"),
                &[&jwt],
                None,
            )
            .await,
            StatusCode::BAD_REQUEST,
            "invalid_query",
        );
    }
    error(
        &exchange(
            server.address,
            "GET",
            &format!("{path}?cursor=invalid"),
            &[&jwt],
            None,
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_cursor",
    );
    for (query, auth) in [
        (format!("{path}?limit=2&cursor={cursor}"), jwt.as_str()),
        (format!("{path}?limit=1&cursor={cursor}"), opaque.as_str()),
    ] {
        error(
            &exchange(server.address, "GET", &query, &[auth], None).await,
            StatusCode::CONFLICT,
            "catalog_restart_required",
        );
    }
    db.execute(
        "UPDATE resource_grants SET s3_route='first' WHERE id='b'",
        [],
    )
    .unwrap();
    error(
        &exchange(
            server.address,
            "GET",
            &format!("{path}?limit=1&cursor={cursor}"),
            &[&jwt],
            None,
        )
        .await,
        StatusCode::CONFLICT,
        "catalog_restart_required",
    );
    db.execute(
        "UPDATE resource_grants SET s3_route='second' WHERE id='b'",
        [],
    )
    .unwrap();
    db.execute("UPDATE resource_acl_state SET revision=revision+1", [])
        .unwrap();
    error(
        &exchange(
            server.address,
            "GET",
            &format!("{path}?limit=1&cursor={cursor}"),
            &[&jwt],
            None,
        )
        .await,
        StatusCode::CONFLICT,
        "catalog_restart_required",
    );
    grant(&db, "conflict", "authenticated", "", A, "second");
    error(
        &exchange(
            server.address,
            "GET",
            &format!("{path}?id={A}"),
            &[&jwt],
            None,
        )
        .await,
        StatusCode::FORBIDDEN,
        "conflicting_routes",
    );
    db.execute("DELETE FROM resource_grants WHERE id='conflict'", [])
        .unwrap();
    metadata(root.path(), "second", B, b"invalid metadata");
    error(
        &exchange(
            server.address,
            "GET",
            &format!("{path}?id={B}"),
            &[&jwt],
            None,
        )
        .await,
        StatusCode::BAD_GATEWAY,
        "invalid_project_metadata",
    );
    std::fs::remove_file(root.path().join("second").join(format!(
        "data/hub-root/v1/projects/{B}/hub/metadata/project.json"
    )))
    .unwrap();
    assert_eq!(
        exchange(
            server.address,
            "GET",
            &format!("{path}?id={B}"),
            &[&jwt],
            None
        )
        .await
        .json["projects"],
        json!([])
    );
    db.execute(
        "UPDATE resource_grants SET s3_route='unconfigured' WHERE id='b'",
        [],
    )
    .unwrap();
    error(
        &exchange(
            server.address,
            "GET",
            &format!("{path}?id={B}"),
            &[&jwt],
            None,
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "catalog_unavailable",
    );
    let mut cfg = catalog_config();
    cfg.request_timeout = Duration::from_nanos(1);
    let timed = Server::start(
        broker_presence::sqlite_hub_catalog_router(f.store.clone(), verifier, reader, cfg).unwrap(),
    )
    .await;
    error(
        &exchange(timed.address, "GET", path, &[&jwt], None).await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    timed.stop().await;
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
}
