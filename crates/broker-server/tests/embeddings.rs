#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "reuse the existing native PostgreSQL TLS lifecycle fixture"
)]
mod support;
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post as post_route};
use broker_control::{BrokerAccessIssuer, BrokerAccessTokenInput};
use rcgen::KeyPair;
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::process::{Child, Command};
use zeroize::Zeroizing;

const ISSUER: &str = "https://broker.example.test";
const AUDIENCE: &str = "storage-api";
const KEY: &str = "ephemeral-embedding-provider-key";
fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn private(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(bytes).unwrap();
}
fn config(
    root: &Path,
    address: SocketAddr,
    pg: &support::Fixture,
    endpoint: &str,
) -> (PathBuf, BrokerAccessIssuer) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let der = Zeroizing::new(key.serialize_der());
    private(&root.join("signing.pk8"), &der);
    private(&root.join("ca.pem"), &pg.ca);
    let issuer = BrokerAccessIssuer::new(ISSUER, AUDIENCE, "startup-key", &der).unwrap();
    let example = include_str!("../../../docs/rust-broker-server.md")
        .split_once("```yaml\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0;
    let text = example
        .replace("127.0.0.1:8080", &address.to_string())
        .replace(
            "  public_url: https://broker.example.test",
            &format!("  public_url: http://{address}"),
        )
        .replace("  host: postgres.example.test", "  host: 127.0.0.1")
        .replace("  port: 5432", &format!("  port: {}", pg.port))
        .replace("  database: graphit", "  database: postgres")
        .replace(
            "  username: graphit_owner",
            "  username: embedding_server_owner",
        )
        .replace(
            "\"${BROKER_DATABASE_PASSWORD:?required}\"",
            "ephemeral-owner",
        )
        .replace("postgres-ca.pem", "ca.pem")
        .replace(
            "\"${BROKER_PEPPER:?required}\"",
            "ephemeral-embedding-fixture-pepper-32bytes",
        );
    let mut value: Value = serde_saphyr::from_str(&text).unwrap();
    value["auth"]["kid"] = json!("startup-key");
    value["auth"]["issuer"] = json!(ISSUER);
    value["auth"]["audience"] = json!(AUDIENCE);
    value["services"] = json!({"embeddings":{
        "enabled":true,"revision":"server-fixture-v1","dimensions":2,"max_batch":8,"max_input_bytes":64,"request_timeout":"2s","required_scopes":[],"request_body_bytes":4096,"response_body_bytes":16384,"identity_json_bytes":8192,"grants_json_bytes":16384,"vector_json_bytes":256,"metadata_bytes":2048,
        "upstream":{"protocol":"openai-compatible","model":"fixture-model","model_revision":"fixture-model-r1","recipe":"retrieval-v1","url":endpoint,"api_key":KEY,"send_dimensions":true,"transport":{"request_body_bytes":4096,"response_body_bytes":16384,"url_bytes":2048,"header_bytes":4096,"header_count":32,"max_in_flight":2,"max_idle_per_host":2,"idle_timeout":"1s","max_certificates":1,"max_certificate_bytes":4096,"allow_loopback_http":true}}
    }});
    let path = root.join("broker.json");
    private(&path, &serde_json::to_vec(&value).unwrap());
    (path, issuer)
}
fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_graphit-broker"));
    command.kill_on_drop(true);
    command
}
async fn start(path: &Path, address: SocketAddr) -> Child {
    let mut child = command()
        .args(["--config", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "native Broker exited before readiness"
        );
        if reqwest::get(format!("http://{address}/readyz"))
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return child;
        }
        assert!(Instant::now() < end, "native Broker did not become ready");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn stop(mut child: Child) {
    #[cfg(unix)]
    {
        assert!(
            Command::new("kill")
                .args(["-TERM", &child.id().unwrap().to_string()])
                .status()
                .await
                .unwrap()
                .success()
        );
    }
    #[cfg(not(unix))]
    child.kill().await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .unwrap()
        .unwrap();
    #[cfg(unix)]
    assert!(status.success(), "native Broker failed to drain and close");
    #[cfg(not(unix))]
    let _ = status;
}
fn jwt(issuer: &BrokerAccessIssuer, subject: &str) -> Zeroizing<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    issuer
        .sign_access(
            BrokerAccessTokenInput {
                subject,
                client_id: "native-embedding-client",
                resource: Some("https://broker.example.test/v1"),
                scope: "",
                jti: subject,
                issued_at: now,
                expires_at: now + 600,
                preferred_username: Some(subject),
                name: None,
                email: None,
                organization: None,
                groups: &[],
                roles: &[],
            },
            support::deadline(),
        )
        .unwrap()
        .into()
}
struct Peer {
    calls: AtomicUsize,
    partial: AtomicBool,
}
async fn upstream(
    State(peer): State<Arc<Peer>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_eq!(headers["authorization"], format!("Bearer {KEY}"));
    assert_eq!(body["dimensions"], 2);
    let input = body["input"].as_array().unwrap();
    let call = peer.calls.fetch_add(1, Ordering::SeqCst);
    let partial = peer.partial.swap(false, Ordering::SeqCst);
    if call == 0 {
        assert_eq!(input, &vec![json!("a"), json!("b")]);
    } else {
        assert_eq!(input, &vec![json!("b")]);
    }
    Json(
        json!({"data":input.iter().enumerate().map(|(index,_)|json!({"index":index,"embedding":if partial && index==1 { vec![0.5] } else { vec![0.25,0.75] }})).collect::<Vec<_>>(),"usage":{"tokens":input.len()}}),
    )
}
async fn post(
    client: &reqwest::Client,
    address: SocketAddr,
    token: &str,
    body: Value,
) -> reqwest::Response {
    client
        .post(format!("http://{address}/v1/embeddings"))
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .send()
        .await
        .unwrap()
}

async fn read_json(response: reqwest::Response) -> Value {
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native executable with actual PostgreSQL TLS NOSUPERUSER owner and HTTP provider"]
async fn compiled_server_embeddings_authorizes_batches_persists_and_reopens() {
    let pg = support::Fixture::new(true).await;
    let mut sql = pg.connection().await;
    sql.execute("CREATE ROLE embedding_server_owner LOGIN PASSWORD 'ephemeral-owner' NOSUPERUSER NOCREATEDB NOCREATEROLE; GRANT CONNECT,CREATE ON DATABASE postgres TO embedding_server_owner; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION embedding_server_owner").await.unwrap();
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='embedding_server_owner'",
    )
    .fetch_one(&mut sql)
    .await
    .unwrap();
    assert!(!superuser);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/embeddings", listener.local_addr().unwrap());
    let peer = Arc::new(Peer {
        calls: AtomicUsize::new(0),
        partial: AtomicBool::new(true),
    });
    let router = Router::new()
        .route("/embeddings", post_route(upstream))
        .with_state(peer.clone());
    let (signal, stopped) = tokio::sync::oneshot::channel();
    let peer_job = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let address = address();
    let (path, issuer) = config(root.path(), address, &pg, &endpoint);
    let checked = command()
        .args(["--config", path.to_str().unwrap(), "--check-config"])
        .output()
        .await
        .unwrap();
    assert!(
        checked.status.success(),
        "native --check-config rejected captured embedding settings"
    );
    for bytes in [&checked.stdout, &checked.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains(KEY));
    }
    let child = start(&path, address).await;
    let client = reqwest::Client::new();
    let first = jwt(&issuer, "subject-a");
    let second = jwt(&issuer, "subject-b");
    let body = json!({"input":["a","b","a"]});
    assert_eq!(
        post(&client, address, &first, body.clone())
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 0);
    sql.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at)VALUES('embeddings','fixture','authenticated','','',0,0);INSERT INTO grant_capabilities(grant_id,value)VALUES('embeddings','embeddings');INSERT INTO grant_projects(grant_id,value)VALUES('embeddings','01KSH1CRFFG8Z74B5ZS78WW808');INSERT INTO resource_acl_state(id,revision,updated_at)VALUES(1,1,0)ON CONFLICT(id)DO UPDATE SET revision=resource_acl_state.revision+1").await.unwrap();
    assert_eq!(
        post(&client, address, "invalid", body.clone())
            .await
            .status()
            .as_u16(),
        401
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 0);
    let failed = post(&client, address, &first, body.clone()).await;
    assert_eq!(failed.status().as_u16(), 502);
    let error = read_json(failed).await;
    assert_eq!(error["error"]["code"], "upstream_failed");
    assert!(error.get("data").is_none());
    let count: i64 = sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM embedding_cache")
        .fetch_one(&mut sql)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let mixed = post(&client, address, &second, body.clone()).await;
    assert_eq!(mixed.status().as_u16(), 200);
    assert_eq!(mixed.headers()["x-graphit-cache"], "MISS");
    let mixed = read_json(mixed).await;
    assert_eq!(mixed["data"].as_array().unwrap().len(), 3);
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
    let hit = post(&client, address, &first, body.clone()).await;
    assert_eq!(hit.headers()["x-graphit-cache"], "HIT");
    let hit = read_json(hit).await;
    assert!(hit.get("usage").is_none());
    let discovery = read_json(
        client
            .get(format!("http://{address}/.well-known/graphit-broker"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        discovery["services"]["embeddings"],
        json!({"protocol":"graphit-embeddings-v1","path":"/v1/embeddings","revision":"server-fixture-v1","model":"fixture-model","model_revision":"fixture-model-r1","recipe":"retrieval-v1","dimensions":2,"max_batch":8,"max_input_bytes":64})
    );
    assert!(!discovery.to_string().contains(KEY));
    assert_eq!(
        discovery["services"]["embeddings"]["model"],
        "fixture-model"
    );
    stop(child).await;
    let reopened = start(&path, address).await;
    let hit = post(&client, address, &second, body.clone()).await;
    assert_eq!(hit.status().as_u16(), 200);
    assert_eq!(hit.headers()["x-graphit-cache"], "HIT");
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
    sql.execute("DELETE FROM grant_projects;DELETE FROM grant_capabilities;DELETE FROM resource_grants;UPDATE resource_acl_state SET revision=revision+1").await.unwrap();
    assert_eq!(
        post(&client, address, &second, body)
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
    stop(reopened).await;
    signal.send(()).unwrap();
    peer_job.await.unwrap();
    sql.close().await.unwrap();
    pg.shutdown().unwrap();
}
