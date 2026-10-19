#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
#[allow(
    dead_code,
    reason = "shared SQL producer fixture also serves contracts with a fixed issuer"
)]
mod oidc;
#[allow(
    dead_code,
    reason = "shared TLS PostgreSQL fixture serves other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use broker_control::BrokerAccessVerifier;
use broker_now_wire::NowSnapshotData;
use broker_security::TokenKind;
use futures_util::{SinkExt, StreamExt};
use oidc::{AUDIENCE, OidcFixture, PEPPER, RESOURCE, VERIFIER};
use rcgen::KeyPair;
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{deadline, n};
use tokio::{
    net::{TcpListener, TcpStream},
    process::{Child, Command},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Error as WsError, Message, client::IntoClientRequest},
};
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const ACCESS: &str = "gb_at_server-presence-access";
const SERVICE: &str = "gb_sc_server-presence-service";
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
fn blocks(doc: &str) -> Vec<&str> {
    doc.split("```yaml\n")
        .skip(1)
        .map(|s| s.split_once("```").unwrap().0)
        .collect()
}
fn base(address: SocketAddr, port: u16) -> String {
    let config = blocks(include_str!("../../../docs/rust-broker-server.md"))[0]
        .replace("127.0.0.1:8080", &address.to_string())
        .replace(
            "  public_url: https://broker.example.test",
            &format!("  public_url: http://{address}"),
        )
        .replace("  host: postgres.example.test", "  host: 127.0.0.1")
        .replace("  port: 5432", &format!("  port: {port}"))
        .replace("  database: graphit", "  database: postgres")
        .replace("  username: graphit_owner", "  username: exchange_owner")
        .replace(
            "\"${BROKER_DATABASE_PASSWORD:?required}\"",
            "ephemeral-owner",
        )
        .replace("postgres-ca.pem", "ca.pem")
        .replace(
            "  issuer: https://broker.example.test",
            &format!("  issuer: http://{address}"),
        )
        .replace(
            "  audience: storage-api",
            &format!("  audience: {AUDIENCE}"),
        )
        .replace(
            "  resource: https://broker.example.test/v1",
            &format!("  resource: {RESOURCE}"),
        )
        .replace("\"${BROKER_PEPPER:?required}\"", PEPPER);
    format!(
        "{config}{}{}{}",
        blocks(include_str!("../../../docs/rust-oidc-token-exchange.md"))[0].replace(
            "accepted_resources: [https://broker.example.test/v1]",
            &format!("accepted_resources: [{RESOURCE}]")
        ),
        blocks(include_str!("../../../docs/rust-admin-session-http.md"))[0],
        blocks(include_str!("../../../docs/rust-project-access-http.md"))[0]
    )
}
fn presence(opaque: bool) -> String {
    let yaml = blocks(include_str!("../../../docs/rust-presence-server.md"));
    if opaque {
        yaml[0]
            .replace("  authentication:\n    type: broker_jwt\n", yaml[1])
            .replace("required_scopes: []", "required_scopes: [presence-sdk]")
    } else {
        yaml[0].replace("required_scopes: []", "required_scopes: [openid]")
    }
}
fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn files(root: &Path, ca: &[u8]) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let der = Zeroizing::new(key.serialize_der());
    std::fs::write(root.join("signing.pk8"), &der).unwrap();
    std::fs::write(root.join("ca.pem"), ca).unwrap();
}
fn write(root: &Path, yaml: &str) -> PathBuf {
    let path = root.join("config.yaml");
    std::fs::write(&path, yaml).unwrap();
    path
}
fn command() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphit-broker"));
    c.kill_on_drop(true);
    c
}
async fn start(path: &Path, addr: SocketAddr) -> Child {
    let mut child = command()
        .args(["--config", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let end = deadline();
    loop {
        if reqwest::get(format!("http://{addr}/readyz"))
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return child;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "native Broker exited before readiness"
        );
        assert!(Instant::now() < end, "native Broker readiness deadline");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn stop(mut child: Child) {
    #[cfg(unix)]
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().unwrap().to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    #[cfg(not(unix))]
    child.kill().await.unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .unwrap()
        .unwrap();
    #[cfg(unix)]
    assert!(exit.success());
    #[cfg(not(unix))]
    let _ = exit;
}
async fn value(response: reqwest::Response) -> Value {
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}
async fn register(addr: SocketAddr, token: &str, id: &str, projects: &[&str]) -> reqwest::Response {
    reqwest::Client::new().put(format!("http://{addr}/v1/instances/{id}/inventory"))
        .bearer_auth(token).header("content-type", "application/json")
        .body(json!({"projects":projects.iter().map(|p|json!({"project_id":p,"versions":["main","branch/ação"]})).collect::<Vec<_>>()} ).to_string())
        .send().await.unwrap()
}
async fn own(addr: SocketAddr, token: &str, id: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("http://{addr}/v1/instances/{id}/inventory"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}
async fn socket(addr: SocketAddr, token: &str) -> Result<Socket, WsError> {
    let mut request = format!("ws://{addr}/v1/realtime")
        .into_client_request()
        .unwrap();
    let mut header = format!("Bearer {token}")
        .parse::<tokio_tungstenite::tungstenite::http::HeaderValue>()
        .unwrap();
    header.set_sensitive(true);
    request.headers_mut().insert("authorization", header);
    connect_async(request).await.map(|(s, _)| s)
}
async fn send(socket: &mut Socket, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}
async fn receive(socket: &mut Socket) -> Value {
    let end = deadline();
    loop {
        let message = tokio::time::timeout_at(end.into(), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match message {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected non-text server frame: {other:?}"),
        }
    }
}
async fn closed(socket: &mut Socket) {
    let end = deadline();
    loop {
        match tokio::time::timeout_at(end.into(), socket.next())
            .await
            .unwrap()
        {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
            Some(Ok(_)) => {}
        }
    }
}
async fn denied(socket: &mut Socket, code: &str, context: &str) {
    loop {
        let value = receive(socket).await;
        if value["type"] == "snapshot" {
            continue;
        }
        assert_eq!(value, json!({"type":"error","code":code}), "{context}");
        break;
    }
    policy_closed(socket, context).await;
}
async fn policy_closed(socket: &mut Socket, context: &str) {
    let end = deadline();
    loop {
        match tokio::time::timeout_at(end.into(), socket.next())
            .await
            .unwrap()
        {
            Some(Ok(Message::Close(Some(frame)))) => {
                assert_eq!(
                    frame.code,
                    tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy
                );
                return;
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("{context}: policy denial expected SDK Close1008, got {other:?}"),
        }
    }
}
fn snapshot() -> NowSnapshotData {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        * 1_000_000;
    let available = |items: Value| json!({"availability":"available","total":1,"items":items,"has_more":false,"error":null});
    let actor = "a".repeat(64);
    let data = json!({"project_id":A,"generated_at":now.to_string(),"sections":{
        "tasks":available(json!([{"id":A,"session_id":B,"title":"Task","owner":actor,"lease_expires_at":(now+5_000_000_000).to_string(),"updated_at":now.to_string()}])),
        "sessions":available(json!([{"id":B,"title":"Session","owner":actor,"lease_expires_at":(now+5_000_000_000).to_string(),"updated_at":now.to_string(),"completed_tasks":1,"total_tasks":2}])),
        "memories":available(json!([{"id":A,"title":"Memory","updated_by":actor,"updated_at":now.to_string()}])),
        "knowledge":available(json!([{"slug":"known","title":"Knowledge","updated_at":null}]))}});
    NowSnapshotData::decode(&serde_json::to_vec(&data).unwrap(), n(65536)).unwrap()
}
async fn publisher(addr: SocketAddr, token: &str, id: &str) -> Socket {
    let mut s = socket(addr, token).await.unwrap();
    send(&mut s,json!({"op":"publish","instance_id":id,"project_id":A,"version":"main","snapshot":snapshot()})).await;
    assert_eq!(
        receive(&mut s).await,
        json!({"type":"welcome","heartbeat_timeout_ns":"30000000000"})
    );
    s
}
async fn subscriber(addr: SocketAddr, token: &str, id: &str) -> (Socket, Value) {
    let mut s = socket(addr, token).await.unwrap();
    send(
        &mut s,
        json!({"op":"subscribe","project_id":A,"instance_id":id}),
    )
    .await;
    assert_eq!(
        receive(&mut s).await,
        json!({"type":"welcome","heartbeat_timeout_ns":"30000000000"})
    );
    let v = receive(&mut s).await;
    (s, v)
}
fn assert_view(view: &Value, id: &str) {
    assert_mask(view, id, 7);
}
fn assert_mask(view: &Value, id: &str, bits: u8) {
    assert_eq!(view["type"], "snapshot");
    assert_eq!(view["project_id"], A);
    assert_eq!(view["instances"].as_array().unwrap().len(), 1);
    assert_eq!(view["instances"][0]["instance_id"], id);
    let data = &view["instances"][0]["now"];
    NowSnapshotData::decode(&serde_json::to_vec(data).unwrap(), n(65536)).unwrap();
    for (section, bit) in [
        ("tasks", 1),
        ("sessions", 1),
        ("memories", 2),
        ("knowledge", 4),
    ] {
        if bits & bit != 0 {
            assert_eq!(
                data["sections"][section]["items"].as_array().unwrap().len(),
                1
            );
        } else {
            assert_eq!(
                data["sections"][section],
                json!({"availability":"failed","items":[],"total":null,"has_more":null,"error":"forbidden"})
            );
        }
    }
    assert!(!view.to_string().contains("token"));
    assert!(!view.to_string().contains("issuer"));
}
async fn clear(f: &mut OidcFixture) {
    f.admin.execute("DELETE FROM public.resource_grants; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
}
async fn grant(f: &mut OidcFixture, id: &str, caps: &[&str], projects: &[&str]) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture','authenticated','','',0,0)").bind(id).execute(&mut f.admin).await.unwrap();
    for cap in caps {
        sqlx_core::query::query(
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
        )
        .bind(id)
        .bind(*cap)
        .execute(&mut f.admin)
        .await
        .unwrap();
    }
    for p in projects {
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(*p)
            .execute(&mut f.admin)
            .await
            .unwrap();
    }
    f.admin
        .execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
        .await
        .unwrap();
}
async fn policy(f: &mut OidcFixture) {
    mask_policy(f, 7).await;
}
async fn mask_policy(f: &mut OidcFixture, bits: u8) {
    clear(f).await;
    let mut caps = vec!["presence:publish", "presence:read"];
    for (cap, bit) in [("task:read", 1), ("memory:read", 2), ("knowledge:read", 4)] {
        if bits & bit != 0 {
            caps.push(cap);
        }
    }
    grant(f, "live", &caps, &[A, B]).await;
}
async fn opaque_tokens(f: &mut OidcFixture) {
    f.admin.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('bot','bot-subject','service','','Bot','','org','[]',1,0,1,0,0)").await.unwrap();
    for (raw, kind, id, name, subject) in [
        (
            ACCESS,
            TokenKind::LocalAccess,
            "server-access",
            "access",
            "alice-subject",
        ),
        (
            SERVICE,
            TokenKind::ServiceCredential,
            "server-service",
            "service",
            "bot-subject",
        ),
    ] {
        let digest = oidc::digester().token(kind, raw.as_bytes()).unwrap();
        let principal=json!({"issuer":"local","subject":subject,"username":"stale","auth_method":"old","local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'envelope',$5,'client','opaque-presence','','[\"presence-sdk\"]',1,'',0,$6,0)")
            .bind(digest.to_sql_hex()).bind(id).bind(name).bind(subject).bind(principal).bind(oidc::micros()+600_000_000).execute(&mut f.admin).await.unwrap();
    }
}
#[tokio::test]
#[ignore = "actual native binary, Native P3 and opaque access/service, PostgreSQL TLS and WebSocket SDK"]
async fn broker_presence_server_http_ws_contract() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    files(root.path(), &f.fixture.ca);
    let base = base(addr, f.fixture.port);
    let native = presence(false);
    let opaque = presence(true);
    let path = write(root.path(), &format!("{base}{native}"));
    for section in [&native, &opaque] {
        write(root.path(), &format!("{base}{section}"));
        assert!(
            command()
                .args(["--config", path.to_str().unwrap(), "--check-config"])
                .output()
                .await
                .unwrap()
                .status
                .success()
        );
    }
    for (case, bad) in [
        native.replace("    type: broker_jwt\n", ""),
        native.replace("    type: broker_jwt", "    type: guessed"),
        native.replace(
            "    type: broker_jwt",
            "    type: broker_jwt\n    audience: invented",
        ),
        native.replace("  heartbeat_timeout: 30s\n", ""),
        native.replace("  heartbeat_timeout: 30s", "  heartbeat_timeout: 0s"),
        native.replace(
            "  broadcast_capacity: 32",
            &format!("  broadcast_capacity: {}", usize::MAX),
        ),
        native.replace(
            "grants_json_bytes: 65536",
            &format!("grants_json_bytes: {}", usize::MAX),
        ),
        native.replace("command_bytes: 65536", "command_bytes: 0"),
        native.replace("required_scopes: [openid]", "required_scopes: ['a b']"),
        opaque.replace("    audience: opaque-presence\n", ""),
        opaque.replace("    identity_json_bytes: 8192\n", ""),
        opaque.replace("      query_bytes: 4096\n", ""),
    ]
    .into_iter()
    .enumerate()
    {
        write(root.path(), &format!("{base}{bad}"));
        let out = command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap();
        assert!(!out.status.success(), "invalid config case {case} accepted");
        assert!(!String::from_utf8_lossy(&out.stderr).contains(PEPPER));
        assert!(TcpStream::connect(addr).await.is_err());
        assert!(!root.path().join("volumes").exists());
    }
    write(root.path(), &format!("{base}{native}"));
    let mut native_child = Some(start(&path, addr).await);
    let client = reqwest::Client::new();
    let code = f.code(true, true).await;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", "web-client")
        .append_pair("code", code.code())
        .append_pair("redirect_uri", "https://client.example/cb")
        .append_pair("code_verifier", VERIFIER)
        .append_pair("resource", RESOURCE)
        .finish();
    let response = client
        .post(format!("http://{addr}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let tokens = value(response).await;
    let jwt = Zeroizing::new(tokens["access_token"].as_str().unwrap().to_owned());
    let keys = serde_json::from_value(
        value(
            client
                .get(format!("http://{addr}/v1/oidc/keys"))
                .send()
                .await
                .unwrap(),
        )
        .await,
    )
    .unwrap();
    let verifier = BrokerAccessVerifier::new(
        &format!("http://{addr}"),
        AUDIENCE,
        Some(RESOURCE),
        &keys,
        n(8192),
    )
    .unwrap();
    verifier
        .verify(&jwt, &["openid".into()], deadline())
        .unwrap()
        .check()
        .unwrap();
    opaque_tokens(&mut f).await;
    policy(&mut f).await;
    let ledger = f.token_count().await;
    for (opaque_mode, section, token, id, foreign) in [
        (false, &native, jwt.as_str(), "native-station", ACCESS),
        (true, &opaque, ACCESS, "opaque-station", jwt.as_str()),
    ] {
        let child = if opaque_mode {
            write(root.path(), &format!("{base}{section}"));
            start(&path, addr).await
        } else {
            native_child.take().unwrap()
        };
        clear(&mut f).await;
        grant(
            &mut f,
            "one-project",
            &["presence:publish", "presence:read"],
            &[A],
        )
        .await;
        assert_eq!(
            register(addr, token, "missing-project", &[A, B])
                .await
                .status(),
            403
        );
        assert_eq!(own(addr, token, "missing-project").await.status(), 404);
        policy(&mut f).await;
        assert_eq!(register(addr, token, id, &[A, B]).await.status(), 201);
        let response = own(addr, token, id).await;
        assert_eq!(response.status(), 200);
        let data = value(response).await;
        assert_eq!(data["instance_id"], id);
        assert_eq!(data["projects"].as_array().unwrap().len(), 2);
        assert!(data.get("owner").is_none());
        assert_eq!(
            client
                .head(format!("http://{addr}/v1/instances/{id}/inventory"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            register(addr, foreign, "cross-format", &[A]).await.status(),
            401
        );
        let Err(WsError::Http(reply)) = socket(addr, foreign).await else {
            panic!("cross-format must deny before upgrade")
        };
        assert_eq!(reply.status(), 401);
        if opaque_mode {
            assert_eq!(own(addr, token, "native-station").await.status(), 409);
            assert_eq!(
                register(addr, SERVICE, "service-station", &[A])
                    .await
                    .status(),
                201
            );
            assert_eq!(own(addr, token, "service-station").await.status(), 409);
            assert_eq!(own(addr, SERVICE, "service-station").await.status(), 200);
            let list = client
                .get(format!("http://{addr}/v1/instances?project_id={A}"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap();
            assert_eq!(list.status(), 200);
            let list = value(list).await;
            for station in ["opaque-station", "service-station"] {
                assert!(
                    list["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|item| item["instance_id"] == station)
                );
            }
        }
        let mut publication = publisher(addr, token, id).await;
        let (mut subscription, view) = subscriber(addr, token, id).await;
        assert_view(&view, id);
        send(&mut publication,json!({"op":"publish","instance_id":id,"project_id":A,"version":"main","snapshot":snapshot()})).await;
        assert_view(&receive(&mut subscription).await, id);
        for bits in [5, 0, 7] {
            mask_policy(&mut f, bits).await;
            send(&mut subscription, json!({"op":"heartbeat"})).await;
            assert_mask(&receive(&mut subscription).await, id, bits);
        }
        publication.close(None).await.unwrap();
        closed(&mut publication).await;
        let removal = receive(&mut subscription).await;
        assert_eq!(removal["type"], "snapshot");
        assert_eq!(removal["instances"], json!([]));
        publication = publisher(addr, token, id).await;
        assert_view(&receive(&mut subscription).await, id);
        let withdrawn=client.put(format!("http://{addr}/v1/instances/{id}/inventory"))
            .bearer_auth(token).header("content-type","application/json")
            .body(json!({"projects":[{"project_id":A,"versions":["branch/ação"]},{"project_id":B,"versions":["main"]}]}).to_string()).send().await.unwrap();
        assert_eq!(withdrawn.status(), 200);
        send(&mut publication,json!({"op":"publish","instance_id":id,"project_id":A,"version":"main","snapshot":snapshot()})).await;
        assert_eq!(
            receive(&mut publication).await,
            json!({"type":"error","code":"not_registered"})
        );
        policy_closed(
            &mut publication,
            &format!("version withdrawal opaque={opaque_mode}"),
        )
        .await;
        subscription.close(None).await.unwrap();
        closed(&mut subscription).await;
        assert_eq!(register(addr, token, id, &[A, B]).await.status(), 200);
        publication = publisher(addr, token, id).await;
        let (new_subscription, restored_view) = subscriber(addr, token, id).await;
        subscription = new_subscription;
        assert_view(&restored_view, id);
        clear(&mut f).await;
        assert_eq!(own(addr, token, id).await.status(), 403);
        send(&mut subscription, json!({"op":"heartbeat"})).await;
        denied(
            &mut subscription,
            "forbidden",
            &format!("grant revoke opaque={opaque_mode}"),
        )
        .await;
        publication.close(None).await.unwrap();
        policy(&mut f).await;
        let mut live = publisher(addr, token, id).await;
        let (mut reader, view) = subscriber(addr, token, id).await;
        assert_view(&view, id);
        if opaque_mode {
            f.admin
                .execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
                .await
                .unwrap();
            assert_eq!(own(addr, token, id).await.status(), 401);
            send(&mut live,json!({"op":"publish","instance_id":id,"project_id":A,"version":"main","snapshot":snapshot()})).await;
            denied(&mut live, "unauthenticated", "disabled opaque publisher").await;
            // Publisher removal signals a current-SQL replay; do not send DATA
            // after the subscriber may already have started its close handshake.
            denied(
                &mut reader,
                "unauthenticated",
                "disabled opaque subscriber replay",
            )
            .await;
            f.admin
                .execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'")
                .await
                .unwrap();
            live = publisher(addr, token, id).await;
            let (fresh_reader, fresh_view) = subscriber(addr, token, id).await;
            reader = fresh_reader;
            assert_view(&fresh_view, id);
            let mut service = publisher(addr, SERVICE, "service-station").await;
            f.admin
                .execute("DELETE FROM public.local_tokens WHERE token_id='server-service'")
                .await
                .unwrap();
            assert_eq!(own(addr, SERVICE, "service-station").await.status(), 401);
            send(&mut service,json!({"op":"publish","instance_id":"service-station","project_id":A,"version":"main","snapshot":snapshot()})).await;
            denied(&mut service, "unauthenticated", "revoked opaque service").await;
        }
        // The real binary receives SIGTERM while upgraded sockets remain live.
        stop(child).await;
        closed(&mut live).await;
        closed(&mut reader).await;
        let rebound = TcpListener::bind(addr).await.unwrap();
        drop(rebound);
        let restarted = start(&path, addr).await;
        assert_eq!(own(addr, token, id).await.status(), 200);
        let (mut empty, view) = subscriber(addr, token, id).await;
        assert_eq!(view["instances"], json!([]));
        empty.close(None).await.unwrap();
        stop(restarted).await;
    }
    // All projects are required; an empty inventory needs an explicit Any grant.
    policy(&mut f).await;
    write(root.path(), &format!("{base}{opaque}"));
    let child = start(&path, addr).await;
    assert_eq!(register(addr, ACCESS, "empty", &[]).await.status(), 403);
    grant(&mut f, "any", &["presence:publish", "presence:read"], &[]).await;
    assert_eq!(register(addr, ACCESS, "empty", &[]).await.status(), 201);
    assert_eq!(own(addr, ACCESS, "empty").await.status(), 200);
    assert_eq!(
        client
            .get(format!("http://{addr}/admin/api/v1/session"))
            .bearer_auth(&*jwt)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .post(format!("http://{addr}/v1/project/access/authorize"))
            .bearer_auth(&*jwt)
            .header("content-type", "application/json")
            .body(json!({"project_id":A,"module":"memory","action":"read"}).to_string())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    stop(child).await;
    // A bind failure must exit after cleaning the newly created realtime owner.
    let held = TcpListener::bind(addr).await.unwrap();
    let out = tokio::time::timeout(
        Duration::from_secs(20),
        command()
            .args(["--config", path.to_str().unwrap()])
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!out.status.success());
    drop(held);
    for section in ["", "presence:\n  enabled: false\n"] {
        write(root.path(), &format!("{base}{section}"));
        let child = start(&path, addr).await;
        assert_eq!(own(addr, ACCESS, "empty").await.status(), 404);
        let Err(WsError::Http(reply)) = socket(addr, ACCESS).await else {
            panic!("disabled WS route must be absent")
        };
        assert_eq!(reply.status(), 404);
        stop(child).await;
    }
    assert_eq!(f.token_count().await, ledger - 1);
    f.close().await;
}
