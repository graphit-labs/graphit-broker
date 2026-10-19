use axum::{
    Router,
    body::Bytes,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessVerifier, BrokerInstanceRegistrationError, BrokerPresenceAuthorizationError,
    ControlError, FlowLimits, InstanceInventory, InstanceProjectVersions, SqliteControlConfig,
    SqliteControlStore,
};
use broker_now_wire::NowSnapshotData;
use broker_presence::{
    BrokerOwnReadHttpConfig, BrokerPublishHttpConfig, RealtimeHttpConfig, RealtimeServerRuntime,
    sqlite_broker_instance_inventory_router, sqlite_broker_realtime_router,
};
use broker_security::{CredentialDigester, DigestLimits};
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rusqlite::{Connection, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Error as WsError, Message, client::IntoClientRequest},
};
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const ISSUER: &str = "https://broker.example.test";
const RESOURCE: &str = "https://broker.example.test/v1";
const SUBJECT: &str = "broker-subject";
const JTI: &str = "jwt-native-token";
fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(
            b"presence-fixture-pepper-32-bytes"
                .to_vec()
                .into_boxed_slice(),
        ),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
struct Signer {
    key: EncodingKey,
    keys: jsonwebtoken::jwk::JwkSet,
}
impl Signer {
    fn new() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self { key:EncodingKey::from_ed_der(&pair.serialize_der()),
            keys:serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"project-key","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())}]})).unwrap() }
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
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("project-key".into());
        encode(&header, claims, &self.key).unwrap()
    }
}
struct Fixture {
    store: Arc<SqliteControlStore>,
    path: PathBuf,
    _temp: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private").join("broker.db");
        let store = Arc::new(open(&path).await);
        Self {
            store,
            path,
            _temp: temp,
        }
    }
    fn db(&self) -> Connection {
        let db = Connection::open(&self.path).unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db
    }
}
async fn open(path: &Path) -> SqliteControlStore {
    let config = SqliteControlConfig::new(
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
    .unwrap();
    SqliteControlStore::open(config, digester(), end())
        .await
        .unwrap()
}
fn clear(db: &Connection) {
    db.execute_batch("DELETE FROM resource_grants; UPDATE resource_acl_state SET revision=revision+1,updated_at=0 WHERE id=1").unwrap();
}
fn grant(db: &Connection, id: &str, kind: &str, principal: &str, caps: &[&str], projects: &[&str]) {
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES(?1,'fixture',?2,?3,'',0,0)",params![id,kind,principal]).unwrap();
    for cap in caps {
        db.execute(
            "INSERT INTO grant_capabilities(grant_id,value) VALUES(?1,?2)",
            params![id, cap],
        )
        .unwrap();
    }
    for project in projects {
        db.execute(
            "INSERT INTO grant_projects(grant_id,value) VALUES(?1,?2)",
            params![id, project],
        )
        .unwrap();
    }
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

struct Server {
    address: std::net::SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
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
            stop: Some(stop),
            task: Some(task),
        }
    }
    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(5), self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap();
        self.task.take();
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn serve(
    f: &Fixture,
    signer: &Signer,
    heartbeat: Duration,
    timeout: Duration,
    grants: usize,
    inventory: usize,
) -> (Server, RealtimeServerRuntime) {
    let verifier = Arc::new(signer.verifier());
    let runtime = RealtimeServerRuntime::new(heartbeat, n(32)).unwrap();
    let app = sqlite_broker_instance_inventory_router(
        f.store.clone(),
        verifier.clone(),
        BrokerPublishHttpConfig {
            required_scopes: vec!["presence-sdk".into()],
            grants_json_bytes: n(grants),
            body_bytes: n(65536),
            request_timeout: timeout,
        },
        BrokerOwnReadHttpConfig {
            required_scopes: vec!["presence-sdk".into()],
            grants_json_bytes: n(grants),
            inventory_json_bytes: n(inventory),
            request_timeout: timeout,
        },
    )
    .unwrap()
    .merge(
        sqlite_broker_realtime_router(
            f.store.clone(),
            verifier,
            RealtimeHttpConfig {
                required_scopes: vec!["presence-sdk".into()],
                grants_json_bytes: n(grants),
                inventory_json_bytes: n(inventory),
                command_bytes: n(131072),
                outbound_bytes: n(131072),
                operation_timeout: timeout,
            },
            &runtime,
        )
        .unwrap(),
    );
    (Server::start(app).await, runtime)
}
async fn http(
    server: &Server,
    method: &str,
    id: &str,
    raw: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let stream = TcpStream::connect(server.address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let mut request = Request::builder()
        .method(method)
        .uri(format!(
            "http://{}/v1/instances/{id}/inventory",
            server.address
        ))
        .header(header::HOST, server.address.to_string())
        .header(header::CONNECTION, "close")
        .header(header::AUTHORIZATION, format!("Bearer {raw}"));
    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let bytes = body
        .map(|v| serde_json::to_vec(&v).unwrap())
        .unwrap_or_default();
    let response = sender
        .send_request(request.body(Full::new(Bytes::from(bytes))).unwrap())
        .await
        .unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap();
    drop(sender);
    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    (status, value)
}
fn input(projects: &[&str], versions: &[&str]) -> Value {
    json!({"projects":projects.iter().map(|p|json!({"project_id":p,"versions":versions})).collect::<Vec<_>>()})
}
fn oracle(db: &Connection) -> String {
    db.query_row("SELECT json_object('instances',json((SELECT json_group_array(json_array(instance_id,owner_issuer,owner_subject,created_at,updated_at)) FROM (SELECT * FROM broker_instances ORDER BY instance_id))),'versions',json((SELECT json_group_array(json_array(instance_id,project_id,position,version)) FROM (SELECT * FROM broker_instance_project_versions ORDER BY instance_id,project_id,position))))", [], |r| r.get(0)).unwrap()
}
fn policy(db: &Connection, bits: u8) {
    clear(db);
    let mut caps = vec!["presence:publish", "presence:read"];
    for (bit, cap) in [(1, "task:read"), (2, "memory:read"), (4, "knowledge:read")] {
        if bits & bit != 0 {
            caps.push(cap);
        }
    }
    grant(db, "live", "authenticated", "", &caps, &[A, B]);
}
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
async fn connection(server: &Server, raw: &str) -> Result<Socket, WsError> {
    let mut request = format!("ws://{}/v1/realtime", server.address)
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {raw}").parse().unwrap(),
    );
    let (socket, response) = tokio::time::timeout(Duration::from_secs(5), connect_async(request))
        .await
        .unwrap()?;
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    Ok(socket)
}
async fn send(socket: &mut Socket, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}
async fn receive(socket: &mut Socket) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap()
        {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("expected JSON text, got {other:?}"),
        }
    }
}
async fn closed(socket: &mut Socket, code: &str, close: u16) {
    loop {
        let value = receive(socket).await;
        if value["type"] == "snapshot" {
            continue;
        }
        assert_eq!(value, json!({"type":"error","code":code}));
        break;
    }
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap()
        {
            Some(Ok(Message::Close(Some(frame)))) => {
                assert_eq!(u16::from(frame.code), close);
                break;
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("expected close, got {other:?}"),
        }
    }
}
async fn publish(socket: &mut Socket, project: &str, version: &str, marker: &str) {
    let mut snapshot = serde_json::to_value(data(project)).unwrap();
    snapshot["generated_at"] = json!(marker);
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    NowSnapshotData::decode(&bytes, n(bytes.len())).unwrap();
    send(socket,json!({"op":"publish","instance_id":"station","project_id":project,"version":version,"snapshot":snapshot})).await;
}
async fn publisher(server: &Server, raw: &str) -> Socket {
    let mut socket = connection(server, raw).await.unwrap();
    publish(&mut socket, A, "main", "1000000").await;
    let welcome = receive(&mut socket).await;
    assert_eq!(welcome["type"], "welcome");
    assert_eq!(welcome.as_object().unwrap().len(), 2);
    socket
}
async fn subscriber(server: &Server, raw: &str) -> (Socket, Value) {
    let mut socket = connection(server, raw).await.unwrap();
    send(&mut socket, json!({"op":"subscribe","project_id":A})).await;
    let welcome = receive(&mut socket).await;
    assert_eq!(welcome["type"], "welcome");
    let view = receive(&mut socket).await;
    assert_eq!(view["type"], "snapshot");
    assert_eq!(view["project_id"], A);
    assert_eq!(view.as_object().unwrap().len(), 3);
    (socket, view)
}
async fn nonempty(socket: &mut Socket) -> Value {
    loop {
        let view = receive(socket).await;
        assert_eq!(view["type"], "snapshot");
        if !view["instances"].as_array().unwrap().is_empty() {
            return view;
        }
    }
}
async fn empty(socket: &mut Socket) {
    loop {
        let view = receive(socket).await;
        assert_eq!(view["type"], "snapshot");
        if view["instances"].as_array().unwrap().is_empty() {
            break;
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_registration_and_own_reads_require_whole_current_policy_and_literal_owner() {
    let f = Fixture::new().await;
    let db = f.db();
    let signer = Signer::new();
    let token = signer.sign(&signer.claims());
    clear(&db);
    let (server, runtime) = serve(
        &f,
        &signer,
        Duration::from_secs(30),
        Duration::from_secs(3),
        65536,
        65536,
    )
    .await;
    let empty_before = oracle(&db);
    assert_eq!(
        http(
            &server,
            "PUT",
            "station",
            &token,
            Some(input(&[A], &["main"]))
        )
        .await,
        (StatusCode::FORBIDDEN, json!({"error":{"code":"forbidden"}}))
    );
    assert_eq!(oracle(&db), empty_before);
    grant(
        &db,
        "a",
        "authenticated",
        "",
        &["presence:publish", "presence:read"],
        &[A],
    );
    let (status, created) = http(
        &server,
        "PUT",
        "station",
        &token,
        Some(input(&[A], &["main"])),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["change"], "created");
    assert_eq!(created.as_object().unwrap().len(), 4);
    let before = oracle(&db);
    let (status, unchanged) = http(
        &server,
        "PUT",
        "station",
        &token,
        Some(input(&[A], &["main"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(unchanged["change"], "unchanged");
    assert_eq!(unchanged["created_at"], created["created_at"]);
    assert_eq!(oracle(&db), before);
    assert_eq!(
        http(
            &server,
            "PUT",
            "station",
            &token,
            Some(input(&[A, B], &["main"]))
        )
        .await,
        (StatusCode::FORBIDDEN, json!({"error":{"code":"forbidden"}}))
    );
    assert_eq!(oracle(&db), before);
    grant(
        &db,
        "b",
        "authenticated",
        "",
        &["presence:publish", "presence:read"],
        &[B],
    );
    let (status, updated) = http(
        &server,
        "PUT",
        "station",
        &token,
        Some(input(&[B, A], &["main", "branch/ação"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["change"], "updated");
    assert_eq!(updated["created_at"], created["created_at"]);
    let (status, read) = http(&server, "GET", "station", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["projects"].as_array().unwrap().len(), 2);
    assert_eq!(read["projects"][0]["project_id"], A);
    assert!(read.get("owner").is_none());
    let full = oracle(&db);
    db.execute("DELETE FROM resource_grants WHERE id='b'", [])
        .unwrap();
    assert_eq!(
        http(&server, "GET", "station", &token, None).await,
        (StatusCode::FORBIDDEN, json!({"error":{"code":"forbidden"}}))
    );
    assert_eq!(oracle(&db), full);
    let mut foreign = signer.claims();
    foreign["sub"] = json!(SUBJECT.to_uppercase());
    let foreign = signer.sign(&foreign);
    assert_eq!(
        http(&server, "GET", "station", &foreign, None).await,
        (
            StatusCode::CONFLICT,
            json!({"error":{"code":"owner_conflict"}})
        )
    );
    assert_eq!(
        http(
            &server,
            "PUT",
            "station",
            &foreign,
            Some(input(&[A], &["main"]))
        )
        .await,
        (
            StatusCode::CONFLICT,
            json!({"error":{"code":"owner_conflict"}})
        )
    );
    assert_eq!(oracle(&db), full);
    assert_eq!(
        http(&server, "PUT", "station", &token, Some(input(&[], &[])))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(oracle(&db), full);
    grant(
        &db,
        "any",
        "authenticated",
        "",
        &["presence:publish", "presence:read"],
        &["*"],
    );
    assert_eq!(
        http(&server, "PUT", "station", &token, Some(input(&[], &[])))
            .await
            .0,
        StatusCode::OK
    );
    let (status, read) = http(&server, "GET", "station", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["projects"], json!([]));
    db.execute(
        "DELETE FROM grant_capabilities WHERE grant_id='any' AND value='presence:read'",
        [],
    )
    .unwrap();
    assert_eq!(
        http(&server, "GET", "station", &token, None).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        http(&server, "GET", "absent", &token, None).await,
        (StatusCode::NOT_FOUND, json!({"error":{"code":"not_found"}}))
    );
    runtime.shutdown().await.unwrap();
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
    let reopened = open(&f.path).await;
    assert!(
        reopened
            .instance_inventories(n(65536))
            .unwrap()
            .read("station", end())
            .await
            .unwrap()
            .unwrap()
            .inventory()
            .projects()
            .is_empty()
    );
    reopened.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_uses_registered_channels_genuine_proofs_and_fresh_domain_masks() {
    let f = Fixture::new().await;
    let db = f.db();
    let signer = Signer::new();
    let token = signer.sign(&signer.claims());
    policy(&db, 7);
    let (server, runtime) = serve(
        &f,
        &signer,
        Duration::from_secs(30),
        Duration::from_secs(3),
        65536,
        65536,
    )
    .await;
    assert_eq!(
        http(
            &server,
            "PUT",
            "station",
            &token,
            Some(input(&[A], &["main", "branch/ação"]))
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let mut viewer = signer.claims();
    viewer["sub"] = json!("viewer");
    viewer["preferred_username"] = json!("bob");
    let viewer = signer.sign(&viewer);
    let (mut reader, initial) = subscriber(&server, &viewer).await;
    assert_eq!(initial["instances"], json!([]));
    let mut writer = publisher(&server, &token).await;
    let view = nonempty(&mut reader).await;
    assert_mask(&view["instances"][0]["now"], 7);
    assert_eq!(view["instances"][0].as_object().unwrap().len(), 3);
    assert_eq!(view["instances"][0]["instance_id"], "station");
    // Both publisher filtering and current subscriber filtering restrict DATA.
    clear(&db);
    grant(
        &db,
        "pub",
        "user",
        "alice",
        &["presence:publish", "task:read", "memory:read"],
        &[A, B],
    );
    grant(
        &db,
        "read",
        "user",
        "bob",
        &["presence:read", "task:read", "knowledge:read"],
        &[A, B],
    );
    publish(&mut writer, A, "main", "1000001").await;
    let view = nonempty(&mut reader).await;
    assert_eq!(view["instances"][0]["now"]["generated_at"], "1000001");
    assert_mask(&view["instances"][0]["now"], 1);
    policy(&db, 2);
    publish(&mut writer, A, "main", "1000002").await;
    let view = nonempty(&mut reader).await;
    assert_mask(&view["instances"][0]["now"], 2);
    for (project, version) in [(B, "main"), (A, "not-registered")] {
        let mut denied = connection(&server, &token).await.unwrap();
        publish(&mut denied, project, version, "1000003").await;
        closed(&mut denied, "not_registered", 1008).await;
    }
    // The real registered owner is required even when Publish policy matches.
    let mut denied = connection(&server, &viewer).await.unwrap();
    publish(&mut denied, A, "main", "1000003").await;
    closed(&mut denied, "owner_conflict", 1008).await;
    writer.close(None).await.unwrap();
    empty(&mut reader).await;
    reader.close(None).await.unwrap();
    runtime.shutdown().await.unwrap();
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn heartbeat_and_new_publications_revalidate_committed_acl_and_registration() {
    let f = Fixture::new().await;
    let db = f.db();
    let signer = Signer::new();
    let token = signer.sign(&signer.claims());
    policy(&db, 7);
    let (server, runtime) = serve(
        &f,
        &signer,
        Duration::from_secs(30),
        Duration::from_secs(3),
        65536,
        65536,
    )
    .await;
    assert_eq!(
        http(
            &server,
            "PUT",
            "station",
            &token,
            Some(input(&[A], &["main"]))
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let mut writer = publisher(&server, &token).await;
    let (mut reader, view) = subscriber(&server, &token).await;
    assert_eq!(view["instances"].as_array().unwrap().len(), 1);
    clear(&db);
    grant(&db, "pub", "authenticated", "", &["presence:publish"], &[A]);
    send(&mut reader, json!({"op":"heartbeat"})).await;
    closed(&mut reader, "forbidden", 1008).await;
    clear(&db);
    grant(&db, "read", "authenticated", "", &["presence:read"], &[A]);
    publish(&mut writer, A, "main", "1000001").await;
    closed(&mut writer, "forbidden", 1008).await;
    let (mut reader, view) = subscriber(&server, &token).await;
    assert_eq!(view["instances"], json!([]));
    reader.close(None).await.unwrap();
    policy(&db, 7);
    let mut writer = publisher(&server, &token).await;
    let (mut reader, view) = subscriber(&server, &token).await;
    assert_eq!(view["instances"].as_array().unwrap().len(), 1);
    db.execute(
        "DELETE FROM broker_instance_project_versions WHERE instance_id='station'",
        [],
    )
    .unwrap();
    send(&mut reader, json!({"op":"heartbeat"})).await;
    closed(&mut reader, "not_registered", 1008).await;
    publish(&mut writer, A, "main", "1000002").await;
    closed(&mut writer, "not_registered", 1008).await;
    let (mut reader, view) = subscriber(&server, &token).await;
    assert_eq!(view["instances"], json!([]));
    reader.close(None).await.unwrap();
    let persisted = f
        .store
        .instance_inventories(n(65536))
        .unwrap()
        .read("station", end())
        .await
        .unwrap()
        .unwrap();
    assert!(persisted.inventory().projects().is_empty());
    runtime.shutdown().await.unwrap();
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ping_pong_does_not_keep_data_alive_and_shutdown_joins_active_connections() {
    let f = Fixture::new().await;
    let db = f.db();
    let signer = Signer::new();
    let token = signer.sign(&signer.claims());
    policy(&db, 7);
    let heartbeat = Duration::from_millis(900);
    let (server, runtime) =
        serve(&f, &signer, heartbeat, Duration::from_secs(3), 65536, 65536).await;
    assert_eq!(
        http(
            &server,
            "PUT",
            "station",
            &token,
            Some(input(&[A], &["main"]))
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let mut writer = publisher(&server, &token).await;
    let (mut reader, initial) = subscriber(&server, &token).await;
    assert_eq!(initial["instances"].as_array().unwrap().len(), 1);
    tokio::time::sleep(heartbeat * 2 / 3).await;
    publish(&mut writer, A, "main", "1000001").await;
    let renewed = nonempty(&mut reader).await;
    assert_eq!(renewed["instances"][0]["now"]["generated_at"], "1000001");
    // Beyond the initial heartbeat, the accepted full replacement remains live.
    tokio::time::sleep(heartbeat * 2 / 3).await;
    send(&mut reader, json!({"op":"heartbeat"})).await;
    let renewed = nonempty(&mut reader).await;
    assert_eq!(renewed["instances"][0]["now"]["generated_at"], "1000001");
    let mut timer = tokio::time::interval(Duration::from_millis(50));
    let deadline = tokio::time::Instant::now() + heartbeat * 3;
    let mut pong = false;
    loop {
        tokio::select! {
            _=tokio::time::sleep_until(deadline)=>panic!("transport Ping/Pong renewed live DATA"),
            _=timer.tick()=>writer.send(Message::Ping(Bytes::from_static(b"transport"))).await.unwrap(),
            frame=writer.next()=>match frame {
                Some(Ok(Message::Pong(_)))=>pong=true,
                Some(Ok(Message::Text(text)))=>{assert_eq!(serde_json::from_str::<Value>(&text).unwrap(),json!({"type":"error","code":"closed"}));break;},
                other=>panic!("unexpected ping lifecycle frame {other:?}"),
            }
        }
    }
    assert!(pong);
    empty(&mut reader).await;
    runtime.shutdown().await.unwrap();
    assert!(!matches!(
        tokio::time::timeout(Duration::from_secs(3), reader.next())
            .await
            .unwrap(),
        Some(Ok(Message::Text(_)))
    ));
    assert!(
        f.store
            .instance_inventories(n(65536))
            .unwrap()
            .read("station", end())
            .await
            .unwrap()
            .is_some()
    );
    match connection(&server, &token).await {
        Err(WsError::Http(response)) => {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE)
        }
        _ => panic!("closed runtime admitted a socket"),
    }
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scopes_limits_original_and_closed_storage_keep_finite_consumer_outcomes() {
    let f = Fixture::new().await;
    let mut db = f.db();
    let signer = Signer::new();
    let verifier = signer.verifier();
    let token = signer.sign(&signer.claims());
    policy(&db, 7);
    let (server, runtime) = serve(
        &f,
        &signer,
        Duration::from_secs(30),
        Duration::from_secs(3),
        65536,
        65536,
    )
    .await;
    assert_eq!(
        http(
            &server,
            "PUT",
            "station",
            &token,
            Some(input(&[A], &["main"]))
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let before = oracle(&db);
    let (short, short_runtime) = serve(
        &f,
        &signer,
        Duration::from_secs(30),
        Duration::from_millis(60),
        65536,
        65536,
    )
    .await;
    let mut short_publisher = publisher(&short, &token).await;
    let writer = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let mut claims = signer.claims();
    claims["scope"] = json!("other");
    let scope = signer.sign(&claims);
    assert_eq!(
        http(
            &server,
            "PUT",
            "station",
            &scope,
            Some(input(&[A], &["main"]))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        http(&server, "GET", "station", "invalid", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    match connection(&server, &scope).await {
        Err(WsError::Http(response)) => assert_eq!(response.status(), StatusCode::FORBIDDEN),
        _ => panic!("wrong scope upgraded"),
    }
    // SELECT-only admission can read the committed WAL snapshot while an
    // external writer is pending. Contend on the actual shared owner instead.
    assert_eq!(
        http(&short, "GET", "station", &token, None).await.0,
        StatusCode::OK
    );
    let inventory = InstanceInventory::new(
        "station".into(),
        vec![InstanceProjectVersions::new(A.into(), vec!["main".into()]).unwrap()],
    )
    .unwrap();
    let owner = broker_control::InstanceOwner::new(ISSUER, SUBJECT).unwrap();
    let mut held = Box::pin(
        f.store
            .replace_instance_inventory(&owner, &inventory, end()),
    );
    assert!(futures_util::poll!(held.as_mut()).is_pending());
    assert_eq!(
        http(&short, "GET", "station", &token, None).await,
        (
            StatusCode::GATEWAY_TIMEOUT,
            json!({"error":{"code":"deadline"}})
        )
    );
    publish(&mut short_publisher, A, "main", "1000001").await;
    closed(&mut short_publisher, "deadline", 1011).await;
    writer.rollback().unwrap();
    held.await.unwrap();
    short_runtime.shutdown().await.unwrap();
    short.stop().await;
    assert_eq!(oracle(&db), before);
    let expired = f
        .store
        .broker_instance_registrar(&verifier, n(65536))
        .unwrap()
        .register(
            &token,
            &["presence-sdk".into()],
            &inventory,
            Instant::now() - Duration::from_millis(1),
        )
        .await;
    assert_eq!(
        expired.err(),
        Some(BrokerInstanceRegistrationError::Authorization(
            BrokerPresenceAuthorizationError::Control(ControlError::Deadline)
        ))
    );
    assert_eq!(
        http(&server, "GET", "station", &token, None).await.0,
        StatusCode::OK
    );
    let (small, small_runtime) = serve(
        &f,
        &signer,
        Duration::from_secs(30),
        Duration::from_secs(3),
        65536,
        1,
    )
    .await;
    assert_eq!(
        http(&small, "GET", "station", &token, None).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":{"code":"inventory_unavailable"}})
        )
    );
    let mut ws = connection(&small, &token).await.unwrap();
    publish(&mut ws, A, "main", "1000001").await;
    closed(&mut ws, "authorization_unavailable", 1011).await;
    small_runtime.shutdown().await.unwrap();
    small.stop().await;
    grant(
        &db,
        "invalid",
        "authenticated",
        "",
        &["unrelated"],
        &["[bad"],
    );
    assert_eq!(
        http(&server, "GET", "station", &token, None).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":{"code":"invalid_policy"}})
        )
    );
    db.execute("DELETE FROM resource_grants WHERE id='invalid'", [])
        .unwrap();
    f.store.shutdown(end()).await.unwrap();
    assert_eq!(
        http(&server, "GET", "station", &token, None).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":{"code":"closed"}})
        )
    );
    let mut ws = connection(&server, &token).await.unwrap();
    send(&mut ws, json!({"op":"subscribe","project_id":A})).await;
    closed(&mut ws, "closed", 1000).await;
    runtime.shutdown().await.unwrap();
    server.stop().await;
}
