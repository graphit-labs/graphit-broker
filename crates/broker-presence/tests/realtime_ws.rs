#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessVerifier, ConnectionLimits, InstanceInventory, InstanceProjectVersions,
    PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use broker_now_wire::NowSnapshotData;
use broker_presence::{
    BrokerOwnReadHttpConfig, BrokerPublishHttpConfig, LocalRealtimeHttpConfig, RealtimeHttpConfig,
    RealtimeServerRuntime, broker_instance_inventory_router, broker_realtime_router,
    local_realtime_router,
};
use broker_security::TokenKind;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
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
        tokio::time::timeout(Duration::from_secs(3), self.task.as_mut().unwrap())
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
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
fn cfg(timeout: Duration, command: usize, outbound: usize) -> RealtimeHttpConfig {
    RealtimeHttpConfig {
        required_scopes: scopes(),
        grants_json_bytes: n(65536),
        inventory_json_bytes: n(65536),
        command_bytes: n(command),
        outbound_bytes: n(outbound),
        operation_timeout: timeout,
    }
}
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
    let (socket, response) = tokio::time::timeout(Duration::from_secs(10), connect_async(request))
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
        match tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await
            .unwrap()
        {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(Message::Close(frame))) => panic!("unexpected close {frame:?}"),
            other => panic!("unexpected frame {other:?}"),
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
        match tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await
            .unwrap()
        {
            Some(Ok(Message::Close(Some(frame)))) => {
                assert_eq!(u16::from(frame.code), close);
                return;
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("expected close, got {other:?}"),
        }
    }
}
async fn publisher(server: &Server, raw: &str, id: &str, project: &str, version: &str) -> Socket {
    let mut socket = connection(server, Some(raw)).await.unwrap();
    publish(&mut socket, id, project, version, "1000000").await;
    let welcome = receive(&mut socket).await;
    assert_eq!(welcome["type"], "welcome");
    assert_eq!(welcome.as_object().unwrap().len(), 2);
    socket
}
async fn publish(socket: &mut Socket, id: &str, project: &str, version: &str, marker: &str) {
    let mut snapshot = serde_json::to_value(data(project)).unwrap();
    snapshot["generated_at"] = json!(marker);
    send(socket, json!({"op":"publish","instance_id":id,"project_id":project,"version":version,"snapshot":snapshot})).await;
}
async fn subscriber(server: &Server, raw: &str, command: Value) -> (Socket, Value) {
    let mut socket = connection(server, Some(raw)).await.unwrap();
    // This client sends the command first; the server must not wait for a welcome ACK.
    send(&mut socket, command).await;
    let welcome = receive(&mut socket).await;
    assert_eq!(welcome["type"], "welcome");
    assert!(
        welcome["heartbeat_timeout_ns"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > 0
    );
    let snapshot = receive(&mut socket).await;
    assert_eq!(snapshot["type"], "snapshot");
    (socket, snapshot)
}
fn ids(frame: &Value) -> Vec<(String, String)> {
    assert_eq!(frame.as_object().unwrap().len(), 3);
    frame["instances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            assert_eq!(v.as_object().unwrap().len(), 3);
            assert_eq!(v["now"]["project_id"], frame["project_id"]);
            (
                v["instance_id"].as_str().unwrap().into(),
                v["version"].as_str().unwrap().into(),
            )
        })
        .collect()
}
async fn http_inventory(
    server: &Server,
    raw: &str,
    id: &str,
    method: &str,
    body: Value,
) -> (StatusCode, Value) {
    let stream = TcpStream::connect(server.address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let task = tokio::spawn(connection);
    let request = Request::builder()
        .method(method)
        .uri(format!("/v1/instances/{id}/inventory"))
        .header(header::AUTHORIZATION, format!("Bearer {raw}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let json =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    drop(sender);
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    (status, json)
}
async fn observe_lock(c: &mut PgConnection, query: &str) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='now_channel_owner' AND wait_event_type='Lock' AND query LIKE $1)")
            .bind(query).fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(Instant::now() < end, "actual SQL lock was not observed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn disconnected(socket: &mut Socket) {
    let end = Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(end.into(), socket.next())
            .await
            .unwrap()
        {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
            _ => {}
        }
    }
}
#[tokio::test]
#[ignore = "actual TCP WebSocket SDK, PostgreSQL TLS NOSUPERUSER, EdDSA and current opaque access/service"]
async fn realtime_ws_postgres_contract() {
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
    policy(&mut c, 7).await;
    let runtime = RealtimeServerRuntime::new(Duration::from_secs(60), n(1)).unwrap();
    let native_app = broker_realtime_router(
        store.clone(),
        verifier.clone(),
        cfg(Duration::from_secs(8), 65536, 65536),
        &runtime,
    )
    .unwrap();
    let inventory = broker_instance_inventory_router(
        store.clone(),
        verifier.clone(),
        BrokerPublishHttpConfig {
            required_scopes: scopes(),
            grants_json_bytes: n(65536),
            body_bytes: n(65536),
            request_timeout: Duration::from_secs(8),
        },
        BrokerOwnReadHttpConfig {
            required_scopes: scopes(),
            grants_json_bytes: n(65536),
            inventory_json_bytes: n(65536),
            request_timeout: Duration::from_secs(8),
        },
    )
    .unwrap();
    let native_server = Server::start(native_app.merge(inventory)).await;
    let local_server = Server::start(
        local_realtime_router(
            store.clone(),
            LocalRealtimeHttpConfig {
                audience: "explicit-audience".into(),
                identity_json_bytes: n(16384),
                realtime: cfg(Duration::from_secs(8), 65536, 65536),
            },
            &runtime,
        )
        .unwrap(),
    )
    .await;
    for id in ["native", "native-2"] {
        let body = json!({"projects":[{"project_id":A,"versions":["main","branch/ação"]},{"project_id":B,"versions":["main"]}]});
        assert_eq!(
            http_inventory(&native_server, &raw, id, "PUT", body)
                .await
                .0,
            StatusCode::CREATED
        );
        let (status, get) = http_inventory(&native_server, &raw, id, "GET", Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(get["instance_id"], id);
    }
    for (token, id) in [(LOCAL_RAW, "local"), (SERVICE_RAW, "service")] {
        store
            .local_instance_registrar("explicit-audience", n(16384), n(65536))
            .unwrap()
            .register(token, &scopes(), &super_inventory(id, &[A]), deadline())
            .await
            .unwrap();
    }
    let initial_sql = oracle(&mut c).await;
    for (server, token, status) in [
        (&native_server, None, StatusCode::UNAUTHORIZED),
        (&native_server, Some(LOCAL_RAW), StatusCode::UNAUTHORIZED),
        (&local_server, Some(raw.as_str()), StatusCode::UNAUTHORIZED),
    ] {
        let Err(WsError::Http(response)) = connection(server, token).await else {
            panic!("expected pre101 denial")
        };
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }
    let mut missing_scope = signer.claims();
    missing_scope["scope"] = json!("");
    let denied_raw = signer.sign(&missing_scope);
    let Err(WsError::Http(response)) = connection(&native_server, Some(&denied_raw)).await else {
        panic!()
    };
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Bearer error=\"insufficient_scope\""
    );
    let mut p1 = publisher(&native_server, &raw, "native", A, "main").await;
    let mut p2 = publisher(&native_server, &raw, "native-2", A, "main").await;
    let mut branch = publisher(&native_server, &raw, "native", A, "branch/ação").await;
    let mut other = publisher(&native_server, &raw, "native", B, "main").await;
    let lp = publisher(&local_server, LOCAL_RAW, "local", A, "main").await;
    let service = publisher(&local_server, SERVICE_RAW, "service", A, "main").await;
    let expected: Vec<_> = [
        ("local", "main"),
        ("native", "branch/ação"),
        ("native", "main"),
        ("native-2", "main"),
        ("service", "main"),
    ]
    .into_iter()
    .map(|(a, b)| (a.into(), b.into()))
    .collect();
    let (mut sub, frame) = subscriber(
        &native_server,
        &raw,
        json!({"op":"subscribe","project_id":A}),
    )
    .await;
    assert_eq!(ids(&frame), expected);
    for item in frame["instances"].as_array().unwrap() {
        assert_mask(&item["now"], 7);
    }
    for (filter, count) in [
        (json!({"instance_id":"native"}), 2),
        (json!({"version":"branch/ação"}), 1),
        (json!({"instance_id":"native","version":"main"}), 1),
        (json!({"instance_id":"absent"}), 0),
    ] {
        let mut command = json!({"op":"subscribe","project_id":A});
        for (k, v) in filter.as_object().unwrap() {
            command[k] = v.clone();
        }
        let (socket, view) = subscriber(&native_server, &raw, command).await;
        assert_eq!(ids(&view).len(), count);
        drop(socket);
    }
    let (mut bsub, bview) = subscriber(
        &native_server,
        &raw,
        json!({"op":"subscribe","project_id":B}),
    )
    .await;
    assert_eq!(ids(&bview), vec![("native".into(), "main".into())]);
    for bits in 0..8 {
        policy(&mut c, bits).await;
        send(&mut sub, json!({"op":"heartbeat"})).await;
        let view = receive(&mut sub).await;
        assert_eq!(ids(&view), expected);
        for item in view["instances"].as_array().unwrap() {
            assert_mask(&item["now"], bits);
        }
    }
    policy(&mut c, 7).await;
    drop(sub);
    let (mut sub, reconnected) = subscriber(
        &native_server,
        &raw,
        json!({"op":"subscribe","project_id":A}),
    )
    .await;
    assert_eq!(ids(&reconnected), expected);
    publish(&mut p1, "native", A, "main", "1000001").await;
    let view = receive(&mut sub).await;
    assert_eq!(view["instances"][2]["now"]["generated_at"], "1000001");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), bsub.next())
            .await
            .is_err(),
        "project A signal must not reach B"
    );
    // Every subsequent publication has the whole immutable context.
    let mut replacement = publisher(&native_server, &raw, "native", A, "main").await;
    closed(&mut p1, "superseded", 1008).await;
    drop(p1);
    send(&mut replacement,json!({"op":"publish","instance_id":"native","project_id":B,"version":"main","snapshot":serde_json::to_value(data(B)).unwrap()})).await;
    closed(&mut replacement, "invalid_data", 1008).await;
    drop(replacement);
    drop(sub);
    drop(bsub);
    // Malformed role/shape never receives welcome.
    for command in [
        json!({"op":"heartbeat"}),
        json!({"op":"subscribe","project_id":A,"version":null}),
        json!({"op":"subscribe","project_id":A,"instance_id":""}),
        json!(["heartbeat"]),
    ] {
        let mut invalid = connection(&native_server, Some(&raw)).await.unwrap();
        send(&mut invalid, command).await;
        closed(&mut invalid, "invalid_data", 1008).await;
    }
    let mut foreign = signer.claims();
    foreign["sub"] = json!("another-subject");
    foreign["jti"] = json!("other-token");
    let foreign = signer.sign(&foreign);
    let mut invalid = connection(&native_server, Some(&foreign)).await.unwrap();
    publish(&mut invalid, "native-2", A, "main", "1000000").await;
    closed(&mut invalid, "owner_conflict", 1008).await;
    assert_eq!(oracle(&mut c).await, initial_sql);
    // Removing current registrations is a failure, never an authorized empty snapshot.
    let (mut withdrawal, _) = subscriber(
        &native_server,
        &raw,
        json!({"op":"subscribe","project_id":A,"instance_id":"native-2"}),
    )
    .await;
    store
        .broker_instance_registrar(&verifier, n(65536))
        .unwrap()
        .register(
            &raw,
            &scopes(),
            &super_inventory("native-2", &[B]),
            deadline(),
        )
        .await
        .unwrap();
    send(&mut withdrawal, json!({"op":"heartbeat"})).await;
    closed(&mut withdrawal, "not_registered", 1008).await;
    store
        .broker_instance_registrar(&verifier, n(65536))
        .unwrap()
        .register(
            &raw,
            &scopes(),
            &super_inventory("native-2", &[A, B]),
            deadline(),
        )
        .await
        .unwrap();
    let final_sql = oracle(&mut c).await;
    // Current ACL corruption and revocation remain errors after 101.
    let (mut revoked, _) = subscriber(
        &native_server,
        &raw,
        json!({"op":"subscribe","project_id":A}),
    )
    .await;
    clear(&mut c).await;
    send(&mut revoked, json!({"op":"heartbeat"})).await;
    closed(&mut revoked, "forbidden", 1008).await;
    policy(&mut c, 7).await;
    let (mut corrupt, _) = subscriber(
        &native_server,
        &raw,
        json!({"op":"subscribe","project_id":A}),
    )
    .await;
    c.execute("UPDATE public.resource_grants SET access_kind='invalid'")
        .await
        .unwrap();
    send(&mut corrupt, json!({"op":"heartbeat"})).await;
    closed(&mut corrupt, "authorization_unavailable", 1011).await;
    policy(&mut c, 7).await;
    let (mut revoked_local, _) = subscriber(
        &local_server,
        LOCAL_RAW,
        json!({"op":"subscribe","project_id":A}),
    )
    .await;
    c.execute("DELETE FROM public.local_tokens WHERE token_id='now-access'")
        .await
        .unwrap();
    send(&mut revoked_local, json!({"op":"heartbeat"})).await;
    closed(&mut revoked_local, "unauthenticated", 1008).await;
    drop(lp);
    drop(service);
    c.execute("DELETE FROM public.local_tokens;DELETE FROM public.local_users")
        .await
        .unwrap();
    local_tokens(&mut c).await;
    // Original is owned by the SQL producer; lock cancellation recovers the actual pool.
    let short_native = Server::start(
        broker_realtime_router(
            store.clone(),
            verifier.clone(),
            cfg(Duration::from_millis(500), 65536, 65536),
            &runtime,
        )
        .unwrap(),
    )
    .await;
    let (mut locked, _) = subscriber(
        &short_native,
        &raw,
        json!({"op":"subscribe","project_id":A}),
    )
    .await;
    let mut blocker = f.connection().await;
    blocker
        .execute("BEGIN;LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    send(&mut locked, json!({"op":"heartbeat"})).await;
    observe_lock(&mut c, "%resource_acl_state%").await;
    closed(&mut locked, "deadline", 1011).await;
    blocker.execute("ROLLBACK").await.unwrap();
    let (recovery, _) = subscriber(
        &short_native,
        &raw,
        json!({"op":"subscribe","project_id":A}),
    )
    .await;
    drop(recovery);
    // Actual Lagged: opaque replay is SQL-blocked while Native publications invalidate its capacity-one queue.
    let (mut lagged, _) = subscriber(
        &local_server,
        LOCAL_RAW,
        json!({"op":"subscribe","project_id":A}),
    )
    .await;
    blocker
        .execute("BEGIN;LOCK TABLE public.local_tokens IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    publish(&mut p2, "native-2", A, "main", "1000002").await;
    observe_lock(&mut c, "%local_tokens%").await;
    for marker in ["1000003", "1000004", "1000005"] {
        publish(&mut p2, "native-2", A, "main", marker).await;
        let end = deadline();
        loop {
            let (reader, view) = subscriber(
                &native_server,
                &raw,
                json!({"op":"subscribe","project_id":A,"instance_id":"native-2"}),
            )
            .await;
            drop(reader);
            if view["instances"][0]["now"]["generated_at"] == marker {
                break;
            }
            assert!(Instant::now() < end);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    blocker.execute("COMMIT").await.unwrap();
    closed(&mut lagged, "backpressure", 1013).await;
    drop(lagged);
    short_native.stop().await;
    // Whole output cap fails without truncated protected DATA; SDK oversized input yields1009.
    let small = Server::start(
        broker_realtime_router(
            store.clone(),
            verifier.clone(),
            cfg(Duration::from_secs(8), 128, 128),
            &runtime,
        )
        .unwrap(),
    )
    .await;
    let mut oversize = connection(&small, Some(&raw)).await.unwrap();
    oversize
        .send(Message::Text("x".repeat(1024).into()))
        .await
        .unwrap();
    closed(&mut oversize, "too_large", 1009).await;
    let mut output = connection(&small, Some(&raw)).await.unwrap();
    send(&mut output, json!({"op":"subscribe","project_id":A})).await;
    assert_eq!(receive(&mut output).await["type"], "welcome");
    closed(&mut output, "too_large", 1009).await;
    small.stop().await;
    // Native JWT retains its signed local window; opaque uses current SQL, and quiet expiry is scheduled.
    let mut claims = signer.claims();
    claims["exp"] = json!(seconds() + 2);
    let expiring = signer.sign(&claims);
    let (mut expiry, _) = subscriber(
        &native_server,
        &expiring,
        json!({"op":"subscribe","project_id":B}),
    )
    .await;
    closed(&mut expiry, "unauthenticated", 1008).await;
    // A delayed real opaque pre101 authentication still returns a valid original producer pair.
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='now-access'",
    )
    .bind(now() + 4_000_000)
    .execute(&mut c)
    .await
    .unwrap();
    blocker
        .execute("BEGIN;LOCK TABLE public.local_tokens IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let mut delayed = {
        let connecting = connection(&local_server, Some(LOCAL_RAW));
        tokio::pin!(connecting);
        tokio::select! {
            _ = &mut connecting => panic!("SQL-blocked pre101 must not finish"),
            _ = observe_lock(&mut c,"%local_tokens%") => {}
        }
        tokio::time::sleep(Duration::from_millis(2250)).await;
        blocker.execute("COMMIT").await.unwrap();
        connecting.await.unwrap()
    };
    send(&mut delayed, json!({"op":"subscribe","project_id":A})).await;
    assert_eq!(receive(&mut delayed).await["type"], "welcome");
    assert_eq!(receive(&mut delayed).await["type"], "snapshot");
    closed(&mut delayed, "unauthenticated", 1008).await;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='now-access'",
    )
    .bind(now() + 600_000_000)
    .execute(&mut c)
    .await
    .unwrap();
    // Runtime Drop aborts actual active and pre-role sockets without touching the shared SQL store.
    let drop_runtime = RealtimeServerRuntime::new(Duration::from_secs(60), n(4)).unwrap();
    let drop_server = Server::start(
        broker_realtime_router(
            store.clone(),
            verifier.clone(),
            cfg(Duration::from_secs(8), 65536, 65536),
            &drop_runtime,
        )
        .unwrap(),
    )
    .await;
    let mut dropped_pub = publisher(&drop_server, &raw, "native", A, "main").await;
    let mut dropped_idle = connection(&drop_server, Some(&raw)).await.unwrap();
    drop(drop_runtime);
    disconnected(&mut dropped_pub).await;
    disconnected(&mut dropped_idle).await;
    let Err(WsError::Http(response)) = connection(&drop_server, Some(&raw)).await else {
        panic!()
    };
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop_server.stop().await;
    // Heartbeat maintenance runs without another publication; Ping is not presence renewal.
    let short_runtime = RealtimeServerRuntime::new(Duration::from_millis(600), n(4)).unwrap();
    let short_server = Server::start(
        broker_realtime_router(
            store.clone(),
            verifier.clone(),
            cfg(Duration::from_secs(8), 65536, 65536),
            &short_runtime,
        )
        .unwrap(),
    )
    .await;
    let mut timed = publisher(&short_server, &raw, "native", A, "main").await;
    let (mut timed_view, _) = subscriber(
        &short_server,
        &raw,
        json!({"op":"subscribe","project_id":A}),
    )
    .await;
    timed
        .send(Message::Ping(vec![1, 2, 3].into()))
        .await
        .unwrap();
    closed(&mut timed, "closed", 1000).await;
    assert!(ids(&receive(&mut timed_view).await).is_empty());
    let abandoned = publisher(&short_server, &raw, "native", A, "main").await;
    assert_eq!(ids(&receive(&mut timed_view).await).len(), 1);
    drop(abandoned);
    assert!(ids(&receive(&mut timed_view).await).is_empty());
    let mut renewed = publisher(&short_server, &raw, "native", A, "main").await;
    let _ = receive(&mut timed_view).await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    publish(&mut renewed, "native", A, "main", "1000001").await;
    let update = receive(&mut timed_view).await;
    assert_eq!(update["instances"][0]["now"]["generated_at"], "1000001");
    assert!(
        tokio::time::timeout(Duration::from_millis(350), timed_view.next())
            .await
            .is_err()
    );
    drop(timed_view);
    drop(renewed);
    // Receiving DATA cannot renew an expired publication while real admission
    // waits for SQL. Release that admission only after the heartbeat has elapsed.
    let mut pending = publisher(&short_server, &raw, "native", A, "main").await;
    blocker
        .execute("BEGIN;LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    publish(&mut pending, "native", A, "main", "1000002").await;
    observe_lock(&mut c, "%resource_acl_state%").await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    blocker.execute("ROLLBACK").await.unwrap();
    closed(&mut pending, "closed", 1000).await;
    let (mut recovered_view, empty) = subscriber(
        &short_server,
        &raw,
        json!({"op":"subscribe","project_id":A}),
    )
    .await;
    assert!(ids(&empty).is_empty());
    let mut recovered = connection(&short_server, Some(&raw)).await.unwrap();
    publish(&mut recovered, "native", A, "main", "1000003").await;
    assert_eq!(receive(&mut recovered).await["type"], "welcome");
    let fresh = receive(&mut recovered_view).await;
    assert_eq!(fresh["instances"][0]["now"]["generated_at"], "1000003");
    short_runtime.shutdown().await.unwrap();
    disconnected(&mut recovered).await;
    short_server.stop().await;
    // Actual slow TCP peer: a whole large DATA frame cannot finish within Original.
    // On cancellation, drop the socket instead of flushing its pending DATA during error cleanup.
    let pressure_runtime = RealtimeServerRuntime::new(Duration::from_secs(60), n(4)).unwrap();
    let pressure_server = Server::start(
        broker_realtime_router(
            store.clone(),
            verifier.clone(),
            cfg(Duration::from_secs(1), 16 * 1024 * 1024, 16 * 1024 * 1024),
            &pressure_runtime,
        )
        .unwrap(),
    )
    .await;
    let mut pressure_publisher = connection(&pressure_server, Some(&raw)).await.unwrap();
    let mut large = serde_json::to_value(data(A)).unwrap();
    large["sections"]["memories"]["items"][0]["title"] = json!("x".repeat(8 * 1024 * 1024));
    send(&mut pressure_publisher, json!({"op":"publish","instance_id":"native","project_id":A,"version":"main","snapshot":large})).await;
    assert_eq!(receive(&mut pressure_publisher).await["type"], "welcome");
    let mut slow = connection(&pressure_server, Some(&raw)).await.unwrap();
    send(&mut slow, json!({"op":"subscribe","project_id":A})).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(receive(&mut slow).await["type"], "welcome");
    let terminal = tokio::time::timeout(Duration::from_secs(3), slow.next())
        .await
        .unwrap();
    assert!(
        matches!(terminal, None | Some(Err(_)) | Some(Ok(Message::Close(_)))),
        "expired incomplete send must not flush a complete DATA frame"
    );
    pressure_runtime.shutdown().await.unwrap();
    disconnected(&mut pressure_publisher).await;
    pressure_server.stop().await;
    let pending = connection(&native_server, Some(&raw)).await.unwrap();
    let (mut pending_sub, _) = subscriber(
        &native_server,
        &raw,
        json!({"op":"subscribe","project_id":B}),
    )
    .await;
    // Explicit runtime shutdown cancels/joins socket tasks independently of HTTP graceful shutdown.
    runtime.shutdown().await.unwrap();
    disconnected(&mut pending_sub).await;
    let mut pending = pending;
    disconnected(&mut pending).await;
    disconnected(&mut p2).await;
    disconnected(&mut branch).await;
    disconnected(&mut other).await;
    native_server.stop().await;
    local_server.stop().await;
    assert_eq!(
        oracle(&mut c).await,
        final_sql,
        "socket activity must not erase SQL registrations"
    );
    blocker.close().await.unwrap();
    c.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    drop(store);
    drop(f);
}
