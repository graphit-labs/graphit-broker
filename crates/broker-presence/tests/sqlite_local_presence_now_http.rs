#[allow(
    dead_code,
    reason = "shared SQLite opaque fixture serves additional administrative targets"
)]
#[path = "../../broker-control/tests/support/sqlite_admin_fixture.rs"]
mod fixture;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use broker_control::{InstanceInventory, InstanceProjectVersions};
use broker_now_wire::NowSnapshotData;
use broker_presence::{
    InstanceInventoryListHttpConfig, InstanceInventoryReadHttpConfig, InstanceRegistryHttpConfig,
    LocalRealtimeHttpConfig, RealtimeHttpConfig, RealtimeServerRuntime,
    sqlite_instance_inventory_router, sqlite_local_realtime_router,
};
use fixture::{Fixture, end, n, now};
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Error as WsError, Message, client::IntoClientRequest},
};
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
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
    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
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
    }
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

fn prepare(f: &Fixture) {
    f.db().execute_batch("UPDATE local_tokens SET audience='presence-api',scopes_json='[\"presence-sdk\"]'; DELETE FROM resource_grants; UPDATE resource_acl_state SET revision=revision+1").unwrap();
}
fn grant(db: &Connection, id: &str, user: &str, caps: &[&str], projects: &[&str]) {
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES(?1,'fixture','user',?2,'',0,0)",params![id,user]).unwrap();
    for cap in caps {
        db.execute(
            "INSERT INTO grant_capabilities(grant_id,value) VALUES(?1,?2)",
            params![id, cap],
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
fn scopes() -> Vec<String> {
    vec!["presence-sdk".into()]
}
fn registration_config() -> InstanceRegistryHttpConfig {
    InstanceRegistryHttpConfig {
        audience: "presence-api".into(),
        required_scopes: scopes(),
        identity_json_bytes: n(8192),
        grants_json_bytes: n(65536),
        body_bytes: n(8192),
        request_timeout: Duration::from_secs(2),
    }
}
fn read_config() -> InstanceInventoryReadHttpConfig {
    InstanceInventoryReadHttpConfig {
        audience: "presence-api".into(),
        required_scopes: scopes(),
        identity_json_bytes: n(8192),
        grants_json_bytes: n(65536),
        inventory_json_bytes: n(65536),
        request_timeout: Duration::from_secs(2),
    }
}
fn list_config() -> InstanceInventoryListHttpConfig {
    InstanceInventoryListHttpConfig {
        audience: "presence-api".into(),
        required_scopes: scopes(),
        identity_json_bytes: n(8192),
        grants_json_bytes: n(65536),
        inventory_json_bytes: n(65536),
        query_bytes: n(8192),
        request_timeout: Duration::from_secs(2),
    }
}
fn realtime_config() -> LocalRealtimeHttpConfig {
    LocalRealtimeHttpConfig {
        audience: "presence-api".into(),
        identity_json_bytes: n(8192),
        realtime: RealtimeHttpConfig {
            required_scopes: scopes(),
            grants_json_bytes: n(65536),
            inventory_json_bytes: n(65536),
            command_bytes: n(65536),
            outbound_bytes: n(65536),
            operation_timeout: Duration::from_secs(2),
        },
    }
}
async fn serve(f: &Fixture, heartbeat: Duration) -> (Server, RealtimeServerRuntime) {
    let runtime = RealtimeServerRuntime::new(heartbeat, n(32)).unwrap();
    let app = sqlite_instance_inventory_router(
        f.store.clone(),
        registration_config(),
        read_config(),
        list_config(),
    )
    .unwrap()
    .merge(sqlite_local_realtime_router(f.store.clone(), realtime_config(), &runtime).unwrap());
    (Server::start(app).await, runtime)
}
fn input(projects: &[&str]) -> String {
    json!({"projects":projects.iter().map(|p|json!({"project_id":p,"versions":["main","release.1"]})).collect::<Vec<_>>()}).to_string()
}
async fn register(f: &Fixture, id: &str, projects: &[&str]) {
    let inventory = InstanceInventory::new(
        id.into(),
        projects
            .iter()
            .map(|p| {
                InstanceProjectVersions::new((*p).into(), vec!["main".into(), "release.1".into()])
                    .unwrap()
            })
            .collect(),
    )
    .unwrap();
    f.store
        .local_instance_registrar("presence-api", n(8192), n(65536))
        .unwrap()
        .register(&f.access, &scopes(), &inventory, end())
        .await
        .unwrap();
}
fn assert_error(r: &Reply, status: StatusCode, code: &str) {
    assert_eq!(r.status, status, "{r:?}");
    assert_eq!(r.json, json!({"error":{"code":code}}));
}
#[tokio::test]
#[ignore = "real SQLite current opaque and Axum/Hyper PUT/GET/HEAD/LIST"]
async fn sqlite_local_presence_http_inventory_and_current_authority() {
    let f = Fixture::new().await;
    prepare(&f);
    let db = f.db();
    grant(
        &db,
        "alice",
        "alice",
        &["presence:publish", "presence:read"],
        &[A, B],
    );
    grant(&db, "bot", "bot", &["presence:read"], &[A]);
    let (server, runtime) = serve(&f, Duration::from_secs(10)).await;
    let alice = format!("Bearer {}", f.access);
    let bot = format!("Bearer {}", f.service);
    let path = "/v1/instances/station/inventory";
    for headers in [vec![], vec!["invalid header"]] {
        let denied = exchange(server.address, "PUT", path, &headers, Some("invalid body")).await;
        assert_error(&denied, StatusCode::UNAUTHORIZED, "unauthenticated");
        assert!(denied.challenge);
    }
    let invalid_json = exchange(
        server.address,
        "PUT",
        path,
        &["Bearer invalid"],
        Some("invalid body"),
    )
    .await;
    assert_error(&invalid_json, StatusCode::BAD_REQUEST, "invalid_json");
    let denied = exchange(
        server.address,
        "PUT",
        path,
        &["Bearer invalid"],
        Some(&input(&[A])),
    )
    .await;
    assert_error(&denied, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert!(denied.challenge);
    assert!(
        f.store
            .instance_inventories(n(65536))
            .unwrap()
            .read("station", end())
            .await
            .unwrap()
            .is_none()
    );
    let created = exchange(
        server.address,
        "PUT",
        path,
        &[&alice],
        Some(&input(&[A, B])),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.json["change"], "created");
    assert_eq!(created.json.as_object().unwrap().len(), 4);
    assert_eq!(
        exchange(
            server.address,
            "PUT",
            path,
            &[&alice],
            Some(&input(&[A, B]))
        )
        .await
        .json["change"],
        "unchanged"
    );
    let read = exchange(server.address, "GET", path, &[&alice], None).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.json["projects"].as_array().unwrap().len(), 2);
    assert_eq!(read.json.as_object().unwrap().len(), 4);
    let head = exchange(server.address, "HEAD", path, &[&alice], None).await;
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.json.is_null());
    assert_error(
        &exchange(server.address, "GET", path, &[&bot], None).await,
        StatusCode::CONFLICT,
        "owner_conflict",
    );
    assert_error(
        &exchange(
            server.address,
            "GET",
            "/v1/instances/missing/inventory",
            &[&alice],
            None,
        )
        .await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    exchange(
        server.address,
        "PUT",
        "/v1/instances/z/inventory",
        &[&alice],
        Some(&input(&[A])),
    )
    .await;
    let first = exchange(
        server.address,
        "GET",
        "/v1/instances?limit=1",
        &[&bot],
        None,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.json["next_after"], "station");
    assert_eq!(
        first.json["items"][0]["projects"],
        json!([{"project_id":A,"versions":["main","release.1"]}])
    );
    let next = exchange(
        server.address,
        "GET",
        "/v1/instances?limit=1&after=station",
        &[&bot],
        None,
    )
    .await;
    assert_eq!(next.json["items"][0]["instance_id"], "z");
    assert!(next.json["next_after"].is_null());
    for query in [
        "limit=0",
        "limit=101",
        "limit=1&limit=1",
        "unknown=x",
        "after=%FF",
        "after=%ZZ",
    ] {
        assert_error(
            &exchange(
                server.address,
                "GET",
                &format!("/v1/instances?{query}"),
                &[&alice],
                None,
            )
            .await,
            StatusCode::BAD_REQUEST,
            "INVALID_QUERY",
        );
    }
    assert_error(
        &exchange(
            server.address,
            "PUT",
            path,
            &[&alice],
            Some("{\"projects\":[],\"owner\":\"forged\"}"),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_json",
    );
    assert_error(
        &exchange(
            server.address,
            "PUT",
            path,
            &[&alice],
            Some(&"x".repeat(9000)),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "body_too_large",
    );
    db.execute(
        "UPDATE local_users SET revision=revision+1 WHERE username='alice'",
        [],
    )
    .unwrap();
    assert_error(
        &exchange(server.address, "GET", path, &[&alice], None).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    runtime.shutdown().await.unwrap();
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
async fn connection(server: &Server, raw: Option<&str>) -> Result<Socket, WsError> {
    let mut request = format!("ws://{}/v1/realtime", server.address)
        .into_client_request()
        .unwrap();
    if let Some(raw) = raw {
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {raw}").parse().unwrap(),
        );
    }
    connect_async(request).await.map(|(socket, _)| socket)
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
            other => panic!("expected JSON, got {other:?}"),
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
            other => panic!("expected Close {close} after policy {code}, got {other:?}"),
        }
    }
}
async fn publish(socket: &mut Socket, project: &str, version: &str, marker: &str) {
    let mut snapshot = serde_json::to_value(data(project)).unwrap();
    snapshot["generated_at"] = json!(marker);
    send(socket,json!({"op":"publish","instance_id":"station","project_id":project,"version":version,"snapshot":snapshot})).await;
}
async fn publisher(server: &Server, raw: &str) -> Socket {
    let mut s = connection(server, Some(raw)).await.unwrap();
    publish(&mut s, A, "main", "1000000").await;
    assert_eq!(receive(&mut s).await["type"], "welcome");
    s
}
async fn subscriber(server: &Server, raw: &str) -> (Socket, Value) {
    let mut s = connection(server, Some(raw)).await.unwrap();
    send(&mut s, json!({"op":"subscribe","project_id":A})).await;
    assert_eq!(receive(&mut s).await["type"], "welcome");
    let view = receive(&mut s).await;
    assert_eq!(view["type"], "snapshot");
    (s, view)
}
async fn nonempty(socket: &mut Socket) -> Value {
    loop {
        let v = receive(socket).await;
        assert_eq!(v["type"], "snapshot");
        if !v["instances"].as_array().unwrap().is_empty() {
            return v;
        }
    }
}
async fn empty(socket: &mut Socket) {
    loop {
        let v = receive(socket).await;
        assert_eq!(v["type"], "snapshot");
        if v["instances"].as_array().unwrap().is_empty() {
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real LOCAL WebSocket admission, masks, supersession and current SQL registration"]
async fn sqlite_local_now_masks_supersession_and_invalidation() {
    let f = Fixture::new().await;
    prepare(&f);
    let db = f.db();
    grant(
        &db,
        "alice",
        "alice",
        &[
            "presence:publish",
            "presence:read",
            "task:read",
            "memory:read",
        ],
        &[A, B],
    );
    grant(
        &db,
        "bot",
        "bot",
        &["presence:read", "task:read", "knowledge:read"],
        &[A, B],
    );
    register(&f, "station", &[A]).await;
    let (server, runtime) = serve(&f, Duration::from_secs(5)).await;
    for raw in [None, Some("invalid")] {
        match connection(&server, raw).await {
            Err(WsError::Http(r)) => assert_eq!(r.status(), StatusCode::UNAUTHORIZED),
            _ => panic!("invalid LOCAL credential upgraded"),
        }
    }
    let (mut reader, view) = subscriber(&server, &f.service).await;
    assert_eq!(view["instances"], json!([]));
    let mut writer = publisher(&server, &f.access).await;
    let initial = nonempty(&mut reader).await;
    assert_mask(&initial["instances"][0]["now"], 1);
    for (project, version) in [(B, "main"), (A, "wrong")] {
        let mut denied = connection(&server, Some(&f.access)).await.unwrap();
        publish(&mut denied, project, version, "1000001").await;
        closed(&mut denied, "not_registered", 1008).await;
    }
    grant(&db, "bot-pub", "bot", &["presence:publish"], &[A]);
    let mut denied = connection(&server, Some(&f.service)).await.unwrap();
    publish(&mut denied, A, "main", "1000001").await;
    closed(&mut denied, "owner_conflict", 1008).await;
    db.execute(
        "DELETE FROM grant_capabilities WHERE grant_id='bot' AND value='task:read'",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO grant_capabilities(grant_id,value) VALUES('bot','memory:read')",
        [],
    )
    .unwrap();
    db.execute("UPDATE resource_acl_state SET revision=revision+1", [])
        .unwrap();
    send(&mut reader, json!({"op":"heartbeat"})).await;
    assert_mask(&nonempty(&mut reader).await["instances"][0]["now"], 2);
    let mut replacement = publisher(&server, &f.access).await;
    closed(&mut writer, "superseded", 1008).await;
    db.execute(
        "DELETE FROM broker_instance_project_versions WHERE instance_id='station'",
        [],
    )
    .unwrap();
    send(&mut reader, json!({"op":"heartbeat"})).await;
    closed(&mut reader, "not_registered", 1008).await;
    publish(&mut replacement, A, "main", "1000002").await;
    closed(&mut replacement, "not_registered", 1008).await;
    let (mut empty_reader, view) = subscriber(&server, &f.service).await;
    assert_eq!(view["instances"], json!([]));
    empty_reader.close(None).await.unwrap();
    runtime.shutdown().await.unwrap();
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real LOCAL full publication renewal, transport ping expiry and owned shutdown"]
async fn sqlite_local_now_full_publish_renews_data_ping_does_not() {
    let f = Fixture::new().await;
    prepare(&f);
    let db = f.db();
    grant(
        &db,
        "alice",
        "alice",
        &[
            "presence:publish",
            "presence:read",
            "task:read",
            "memory:read",
            "knowledge:read",
        ],
        &[A],
    );
    grant(
        &db,
        "bot",
        "bot",
        &[
            "presence:read",
            "task:read",
            "memory:read",
            "knowledge:read",
        ],
        &[A],
    );
    register(&f, "station", &[A]).await;
    let heartbeat = Duration::from_millis(900);
    let (server, runtime) = serve(&f, heartbeat).await;
    let mut writer = publisher(&server, &f.access).await;
    let (mut reader, initial) = subscriber(&server, &f.service).await;
    assert_eq!(initial["instances"].as_array().unwrap().len(), 1);
    tokio::time::sleep(heartbeat * 2 / 3).await;
    publish(&mut writer, A, "main", "1000001").await;
    assert_eq!(
        nonempty(&mut reader).await["instances"][0]["now"]["generated_at"],
        "1000001"
    );
    tokio::time::sleep(heartbeat * 2 / 3).await;
    send(&mut reader, json!({"op":"heartbeat"})).await;
    assert_eq!(
        nonempty(&mut reader).await["instances"][0]["now"]["generated_at"],
        "1000001"
    );
    let mut timer = tokio::time::interval(Duration::from_millis(50));
    let deadline = tokio::time::Instant::now() + heartbeat * 3;
    let mut pong = false;
    loop {
        tokio::select! {
         _=tokio::time::sleep_until(deadline)=>panic!("Ping/Pong kept DATA alive"),
         _=timer.tick()=>writer.send(Message::Ping(b"transport".as_slice().into())).await.unwrap(),
         frame=writer.next()=>match frame{Some(Ok(Message::Pong(_)))=>pong=true,Some(Ok(Message::Text(text)))=>{assert_eq!(serde_json::from_str::<Value>(&text).unwrap(),json!({"type":"error","code":"closed"}));break;},other=>panic!("unexpected lifecycle frame {other:?}")}
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
    match connection(&server, Some(&f.access)).await {
        Err(WsError::Http(r)) => assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE),
        _ => panic!("closed runtime admitted socket"),
    }
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real opaque authentication cutoff and closed SQL preserve finite WS outcomes"]
async fn sqlite_local_now_expiry_and_closed_store_end_live_state() {
    let f = Fixture::new().await;
    prepare(&f);
    let db = f.db();
    grant(
        &db,
        "alice",
        "alice",
        &["presence:publish", "presence:read", "task:read"],
        &[A],
    );
    grant(&db, "bot", "bot", &["presence:read", "task:read"], &[A]);
    register(&f, "station", &[A]).await;
    db.execute(
        "UPDATE local_tokens SET expires_at=?1 WHERE token_kind='service'",
        params![now() + 900_000],
    )
    .unwrap();
    let (server, runtime) = serve(&f, Duration::from_secs(5)).await;
    let mut writer = publisher(&server, &f.access).await;
    let (mut reader, view) = subscriber(&server, &f.service).await;
    assert_eq!(view["instances"].as_array().unwrap().len(), 1);
    // Quiet subscriber expiry has no competing publisher inactivity branch.
    closed(&mut reader, "unauthenticated", 1008).await;
    let (mut live_reader, view) = subscriber(&server, &f.access).await;
    assert_eq!(view["instances"].as_array().unwrap().len(), 1);
    f.store.shutdown(end()).await.unwrap();
    send(&mut live_reader, json!({"op":"heartbeat"})).await;
    closed(&mut live_reader, "closed", 1000).await;
    publish(&mut writer, A, "main", "1000001").await;
    closed(&mut writer, "closed", 1000).await;
    runtime.shutdown().await.unwrap();
    server.stop().await;
}
