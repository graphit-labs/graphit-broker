#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "reuse genuine PostgreSQL TLS owner and lifecycle fixture"
)]
mod support;
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post as post_route};
use broker_control::{BrokerAccessIssuer, BrokerAccessTokenInput};
use graphit_ai::{
    context::InferenceContext, graphit_rerank::GraphitReranker, native_rerank::NativeRerankLimits,
};
use graphit_auth::broker::{BrokerModelIdentity, BrokerRerankService};
use graphit_core::file_lock::Cancellation;
use graphit_http::client::{BoundedClient, ClientPolicy, Limits};
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
const KEY: &str = "ephemeral-rerank-provider-key";
fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn loopback_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
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
    pg: Option<&support::Fixture>,
    endpoint: &str,
) -> (PathBuf, BrokerAccessIssuer) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let der = Zeroizing::new(key.serialize_der());
    private(&root.join("signing.pk8"), &der);
    if let Some(pg) = pg {
        private(&root.join("ca.pem"), &pg.ca);
    }
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
        .replace(
            "  port: 5432",
            &format!("  port: {}", pg.map(|pg| pg.port).unwrap_or(5432)),
        )
        .replace("  database: graphit", "  database: postgres")
        .replace(
            "  username: graphit_owner",
            "  username: rerank_server_owner",
        )
        .replace(
            "\"${BROKER_DATABASE_PASSWORD:?required}\"",
            "ephemeral-owner",
        )
        .replace("postgres-ca.pem", "ca.pem")
        .replace(
            "\"${BROKER_PEPPER:?required}\"",
            "ephemeral-rerank-fixture-pepper-32bytes",
        );
    let mut value: Value = serde_saphyr::from_str(&text).unwrap();
    value["auth"]["kid"] = json!("startup-key");
    value["auth"]["issuer"] = json!(ISSUER);
    value["auth"]["audience"] = json!(AUDIENCE);
    if pg.is_none() {
        let example = include_str!("../../../docs/rust-broker-server.md")
            .split_once("## Select private SQLite")
            .unwrap()
            .1
            .split_once("~~~yaml\n")
            .unwrap()
            .1
            .split_once("~~~")
            .unwrap()
            .0;
        let sqlite: Value = serde_saphyr::from_str(example).unwrap();
        value["database"] = sqlite["database"].clone();
        value["database"]["path"] = json!(root.join("private/broker.db"));
        value.as_object_mut().unwrap().remove("oidc");
    }
    value["storage"]["routes"] = json!({"native-fs":{"driver":"filesystem","bucket":"native-storage","base_prefix":"graphit","directory":"volume"}});
    value["storage"]["default_route"] = json!("native-fs");
    value["services"] = json!({"rerank":{
      "enabled":true,"revision":"server-rerank-v1","max_documents":8,"max_document_bytes":64,"max_batch":8,"request_timeout":"3s","required_scopes":[],"request_body_bytes":4096,"response_body_bytes":16384,"identity_json_bytes":8192,"grants_json_bytes":16384,
      "upstream":{"protocol":"graphit-rerank-v1","service_revision":"upstream-service-v7","max_documents":8,"model":"fixture-reranker","model_revision":"fixture-r1","recipe":"native-rerank-v1","url":endpoint,"api_key":KEY,"transport":{"request_body_bytes":4096,"response_body_bytes":16384,"url_bytes":2048,"header_bytes":4096,"header_count":32,"max_in_flight":2,"max_idle_per_host":2,"idle_timeout":"1s","max_certificates":1,"max_certificate_bytes":4096,"allow_loopback_http":true}}
    }});
    let path = root.join("broker.json");
    private(&path, &serde_json::to_vec(&value).unwrap());
    (path, issuer)
}
fn command(path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_graphit-broker"));
    command.kill_on_drop(true);
    command.env("GRAPHIT_GLOBAL_DIR", path.parent().unwrap().join("global"));
    command
}
async fn start(path: &Path, address: SocketAddr) -> Child {
    let mut child = command(path)
        .args(["--config", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let configuration: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let startup = humantime::parse_duration(
        configuration["database"]["startup_timeout"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    // The service declaration and private staging parent are prepared before readiness.
    let end = Instant::now() + startup + Duration::from_secs(5);
    let client = loopback_client();
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "native Broker exited before readiness"
        );
        if client
            .get(format!("http://{address}/readyz"))
            .send()
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
                client_id: "native-rerank-client",
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
    hold: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
async fn upstream(
    State(peer): State<Arc<Peer>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_eq!(headers["authorization"], format!("Bearer {KEY}"));
    assert!(body.get("model").is_none());
    let count = body["documents"].as_array().unwrap().len();
    peer.calls.fetch_add(1, Ordering::SeqCst);
    if peer.hold.load(Ordering::SeqCst) {
        peer.entered.notify_one();
        peer.release.notified().await;
    }
    Json(
        json!({"graphit":{"revision":"upstream-service-v7","model":"fixture-reranker","model_revision":"fixture-r1","recipe":"native-rerank-v1"},"results":(0..count).rev().map(|index|json!({"index":index,"relevance_score":if index==2{0.9}else{0.4}})).collect::<Vec<_>>()}),
    )
}
async fn peer() -> (
    Arc<Peer>,
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/rerank", listener.local_addr().unwrap());
    let state = Arc::new(Peer {
        calls: AtomicUsize::new(0),
        hold: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let router = Router::new()
        .route("/rerank", post_route(upstream))
        .with_state(state.clone());
    let (signal, stopped) = tokio::sync::oneshot::channel();
    let job = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    (state, endpoint, signal, job)
}
async fn post(
    client: &reqwest::Client,
    address: SocketAddr,
    token: &str,
    body: Value,
) -> reqwest::Response {
    client
        .post(format!("http://{address}/v1/rerank"))
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
async fn consumer_scores(
    address: SocketAddr,
    token: &str,
    query: &str,
    documents: &[&str],
) -> Vec<f64> {
    let origin = format!("http://{address}");
    let endpoint = format!("{origin}/v1/rerank");
    let client = BoundedClient::new(
        ClientPolicy {
            origin: &origin,
            allow_loopback_http: true,
            proxy: None,
            additional_roots: &[],
        },
        Limits {
            request_body_bytes: 4096,
            response_body_bytes: 16384,
            url_bytes: 2048,
            header_bytes: 8192,
            header_count: 32,
            max_in_flight: 2,
            max_idle_per_host: 2,
            idle_timeout: Duration::from_secs(1),
            max_certificates: 1,
            max_certificate_bytes: 4096,
        },
    )
    .unwrap();
    let discovery = metadata(&loopback_client(), address).await;
    let advertised = &discovery["services"]["rerank"];
    let descriptor = BrokerRerankService {
        endpoint,
        identity: BrokerModelIdentity {
            model: advertised["model"].as_str().unwrap().into(),
            model_revision: advertised["model_revision"].as_str().unwrap().into(),
            recipe: advertised["recipe"].as_str().unwrap().into(),
            service_revision: advertised["revision"].as_str().unwrap().into(),
        },
        max_documents: advertised["max_documents"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let sdk = GraphitReranker::new(
        &client,
        &descriptor,
        NativeRerankLimits::new(8, 8, 4096, 4096, 16384).unwrap(),
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    let mut value = axum::http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    value.set_sensitive(true);
    headers.insert("authorization", value);
    let cancel = Cancellation::default();
    sdk.score_guarded(
        query,
        documents,
        &headers,
        InferenceContext::new(&cancel, Instant::now() + Duration::from_secs(5)),
        &mut || Ok::<(), std::convert::Infallible>(()),
    )
    .await
    .unwrap()
}
fn both_services(value: &mut Value, endpoint: &str) {
    value["services"]["embeddings"] = json!({"enabled":true,"revision":"unused-embedding-v1","dimensions":2,"max_batch":8,"max_input_bytes":64,"request_timeout":"3s","required_scopes":[],"request_body_bytes":4096,"response_body_bytes":16384,"identity_json_bytes":8192,"grants_json_bytes":16384,"vector_json_bytes":256,"metadata_bytes":2048,
 "upstream":{"protocol":"openai-compatible","model":"fixture-model","model_revision":"fixture-model-r1","recipe":"retrieval-v1","url":endpoint,"transport":{"request_body_bytes":4096,"response_body_bytes":16384,"url_bytes":2048,"header_bytes":4096,"header_count":32,"max_in_flight":2,"max_idle_per_host":2,"idle_timeout":"1s","max_certificates":1,"max_certificate_bytes":4096,"allow_loopback_http":true}}});
}
async fn metadata(client: &reqwest::Client, address: SocketAddr) -> Value {
    read_json(
        client
            .get(format!("http://{address}/.well-known/graphit-broker"))
            .send()
            .await
            .unwrap(),
    )
    .await
}
fn assert_metadata(doc: &Value, both: bool) {
    assert_eq!(
        doc["services"]["rerank"],
        json!({"protocol":"graphit-rerank-v1","path":"/v1/rerank","revision":"server-rerank-v1","model":"fixture-reranker","model_revision":"fixture-r1","recipe":"native-rerank-v1","max_documents":8})
    );
    assert_eq!(doc["services"]["embeddings"].is_object(), both);
    assert!(!doc.to_string().contains(KEY));
    assert_eq!(doc["services"]["rerank"]["model"], "fixture-reranker");
}
async fn pg_grants(sql: &mut sqlx_postgres::PgConnection, capability: &str) {
    sql.execute("DELETE FROM grant_capabilities;DELETE FROM grant_projects;DELETE FROM grant_s3_operations;DELETE FROM grant_s3_prefixes;DELETE FROM resource_grants;INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at)VALUES('rerank','fixture','authenticated','','',0,0);INSERT INTO resource_acl_state(id,revision,updated_at)VALUES(1,1,0)ON CONFLICT(id)DO UPDATE SET revision=resource_acl_state.revision+1").await.unwrap();
    sqlx_core::query::query("INSERT INTO grant_capabilities(grant_id,value)VALUES('rerank',$1)")
        .bind(capability)
        .execute(sql)
        .await
        .unwrap();
}
fn sqlite_grants(sql: &rusqlite::Connection, capability: &str) {
    sql.execute_batch("DELETE FROM grant_capabilities;DELETE FROM grant_projects;DELETE FROM grant_s3_operations;DELETE FROM grant_s3_prefixes;DELETE FROM resource_grants;INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at)VALUES('rerank','fixture','authenticated','','',0,0);INSERT INTO resource_acl_state(id,revision,updated_at)VALUES(1,1,0)ON CONFLICT(id)DO UPDATE SET revision=revision+1").unwrap();
    sql.execute(
        "INSERT INTO grant_capabilities(grant_id,value)VALUES('rerank',?1)",
        [capability],
    )
    .unwrap();
}
fn sqlite_connection(root: &Path, path: &Path) -> rusqlite::Connection {
    let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let db = root.join(value["database"]["path"].as_str().unwrap());
    let db = rusqlite::Connection::open(db).unwrap();
    db.busy_timeout(Duration::from_secs(5)).unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    db
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real executable, PostgreSQL TLS NOSUPERUSER owner and Code Graphit SDK consumer"]
async fn compiled_rerank_postgres_discovery_private_cache_sdk_and_shutdown() {
    let pg = support::Fixture::new(true).await;
    let mut sql = pg.connection().await;
    sql.execute("CREATE ROLE rerank_server_owner LOGIN PASSWORD 'ephemeral-owner' NOSUPERUSER NOCREATEDB NOCREATEROLE;GRANT CONNECT,CREATE ON DATABASE postgres TO rerank_server_owner;DROP SCHEMA public CASCADE;CREATE SCHEMA public AUTHORIZATION rerank_server_owner").await.unwrap();
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='rerank_server_owner'",
    )
    .fetch_one(&mut sql)
    .await
    .unwrap();
    assert!(!superuser);
    let (peer, endpoint, signal, job) = peer().await;
    let root = tempfile::tempdir().unwrap();
    let address = address();
    let (path, issuer) = config(root.path(), address, Some(&pg), &endpoint);
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    both_services(&mut value, &endpoint);
    private(&path, &serde_json::to_vec(&value).unwrap());
    let checked = command(&path)
        .args(["--config", path.to_str().unwrap(), "--check-config"])
        .output()
        .await
        .unwrap();
    assert!(checked.status.success());
    assert!(!String::from_utf8_lossy(&checked.stdout).contains(KEY));
    assert!(!String::from_utf8_lossy(&checked.stderr).contains(KEY));
    let child = start(&path, address).await;
    let client = reqwest::Client::new();
    let first = jwt(&issuer, "subject-a");
    let second = jwt(&issuer, "subject-b");
    let body = json!({"query":"query","documents":["a","b","c"],"top_n":2});
    assert_eq!(
        post(&client, address, &first, body.clone())
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 0);
    pg_grants(&mut sql, "embeddings").await;
    assert_eq!(
        post(&client, address, &first, body.clone())
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 0);
    pg_grants(&mut sql, "rerank").await;
    assert_eq!(
        post(&client, address, "invalid", body.clone())
            .await
            .status()
            .as_u16(),
        401
    );
    let miss = post(&client, address, &first, body.clone()).await;
    assert_eq!(miss.status().as_u16(), 200);
    assert_eq!(miss.headers()["x-graphit-cache"], "MISS");
    let results = read_json(miss).await;
    assert_eq!(results["results"][0]["index"], 2);
    assert_eq!(results["results"][1]["index"], 0);
    assert_eq!(results["graphit"]["revision"], "server-rerank-v1");
    assert_eq!(
        post(&client, address, &first, body.clone()).await.headers()["x-graphit-cache"],
        "HIT"
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        post(&client, address, &second, body.clone())
            .await
            .headers()["x-graphit-cache"],
        "MISS"
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
    assert_metadata(&metadata(&client, address).await, true);
    assert_eq!(
        consumer_scores(address, &first, "sdk", &["a", "b", "c"]).await,
        [0.4, 0.4, 0.9]
    );
    assert_eq!(
        consumer_scores(address, &first, "sdk", &["a", "b", "c"]).await,
        [0.4, 0.4, 0.9]
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 3);
    pg_grants(&mut sql, "embeddings").await;
    assert_eq!(
        post(&client, address, &first, body.clone())
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 3);
    pg_grants(&mut sql, "rerank").await;
    stop(child).await;
    let reopened = start(&path, address).await;
    let miss = post(&client, address, &first, body.clone()).await;
    assert_eq!(miss.status().as_u16(), 200);
    assert_eq!(miss.headers()["x-graphit-cache"], "MISS");
    assert_eq!(peer.calls.load(Ordering::SeqCst), 4);
    peer.hold.store(true, Ordering::SeqCst);
    let c = client.clone();
    let token = first.clone();
    let pending = tokio::spawn(async move {
        c.post(format!("http://{address}/v1/rerank"))
            .bearer_auth(token.as_str())
            .header("content-type", "application/json")
            .body(json!({"query":"shutdown","documents":["a","b","c"]}).to_string())
            .send()
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), peer.entered.notified())
        .await
        .unwrap();
    stop(reopened).await;
    if let Ok(response) = tokio::time::timeout(Duration::from_secs(3), pending)
        .await
        .unwrap()
        .unwrap()
    {
        assert_ne!(response.status().as_u16(), 200);
    }
    peer.release.notify_one();
    signal.send(()).unwrap();
    job.await.unwrap();
    sql.close().await.unwrap();
    pg.shutdown().unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compiled_rerank_sqlite_standalone_dual_disabled_and_cache_authority() {
    let (peer, endpoint, signal, job) = peer().await;
    let root = tempfile::tempdir().unwrap();
    let address = address();
    let (path, issuer) = config(root.path(), address, None, &endpoint);
    let child = start(&path, address).await;
    let db = sqlite_connection(root.path(), &path);
    let client = loopback_client();
    let first = jwt(&issuer, "sqlite-a");
    let second = jwt(&issuer, "sqlite-b");
    let body = json!({"query":"query","documents":["a","b","c"]});
    assert_metadata(&metadata(&client, address).await, false);
    sqlite_grants(&db, "rerank");
    assert_eq!(
        consumer_scores(address, &first, "query", &["a", "b", "c"]).await,
        [0.4, 0.4, 0.9]
    );
    assert_eq!(
        post(&client, address, &first, body.clone()).await.headers()["x-graphit-cache"],
        "HIT"
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        post(&client, address, &second, body.clone())
            .await
            .headers()["x-graphit-cache"],
        "MISS"
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
    sqlite_grants(&db, "embeddings");
    assert_eq!(
        post(&client, address, &first, body.clone())
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(peer.calls.load(Ordering::SeqCst), 2);
    stop(child).await;
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    both_services(&mut value, &endpoint);
    private(&path, &serde_json::to_vec(&value).unwrap());
    let dual = start(&path, address).await;
    assert_metadata(&metadata(&client, address).await, true);
    stop(dual).await;
    value["services"]["rerank"]["enabled"] = json!(false);
    value["services"]["rerank"]["upstream"] = json!({"protocol":"gguf-bge-reranker-v2-m3","model":"unused","manifest_file":"missing-model.json"});
    private(&path, &serde_json::to_vec(&value).unwrap());
    let disabled = start(&path, address).await;
    assert_eq!(
        post(&client, address, &first, body).await.status().as_u16(),
        404
    );
    let doc = metadata(&client, address).await;
    assert!(doc["services"].get("rerank").is_none());
    assert!(doc["services"]["embeddings"].is_object());
    stop(disabled).await;
    drop(db);
    signal.send(()).unwrap();
    job.await.unwrap();
}

fn private_model_bundle(root: &std::path::Path, source: &std::path::Path) -> std::path::PathBuf {
    let bundle = root.join("model-bundle");
    std::fs::create_dir(&bundle).unwrap();
    let manifest = std::fs::read(source.join("model.json")).unwrap();
    std::fs::write(bundle.join("model.json"), &manifest).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest).unwrap();
    for artifact in manifest["artifacts"].as_array().unwrap() {
        let path = artifact["path"].as_str().unwrap();
        let target = bundle.join(path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(source.join(path), target).unwrap();
    }
    bundle
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real SQLite executable and explicit verified GRAPHIT_TEST_RERANK_BUNDLE GGUF weights"]
async fn compiled_rerank_gguf_cpu_manifest_sdk_and_load_on_first_request() {
    let source_bundle = std::fs::canonicalize(
        std::env::var_os("GRAPHIT_TEST_RERANK_BUNDLE").expect("explicit verified BGE GGUF bundle"),
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let bundle = private_model_bundle(root.path(), &source_bundle);
    let manifest_path = bundle.join("model.json");
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["runtime"], "gguf-bge-reranker-v2-m3");
    assert_eq!(manifest["id"], "bge-reranker-v2-m3");
    let address = address();
    let (path, issuer) = config(root.path(), address, None, "http://127.0.0.1:1/unused");
    let mut prepared: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    prepared["services"]["rerank"]["request_timeout"] = json!("30s");
    prepared["database"]["startup_timeout"] = json!("60s");
    prepared["services"]["rerank"]["upstream"] = json!({"protocol":"gguf-bge-reranker-v2-m3","model":"bge-reranker-v2-m3","directory":bundle,"manifest_file":manifest_path,"max_artifact_bytes":1200000000u64,"threads":2,"queue_capacity":2,"device":"cpu","device_id":0,
        "manifest_limits":{"max_manifest_bytes":8192,"max_artifacts":8,"max_role_bytes":64,"max_relative_path_bytes":256,"max_id_bytes":128,"max_revision_bytes":128,"max_dimension":768,"max_tokens":8192}});
    prepared["services"]["rerank"]["upstream"]["idle_timeout_seconds"] = json!(1);
    // Invalid declarations fail before loading weights or opening the listener.
    for field in ["max_artifact_bytes", "manifest_file"] {
        let mut bad = prepared.clone();
        bad["services"]["rerank"]["upstream"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        private(&path, &serde_json::to_vec(&bad).unwrap());
        assert!(
            !command(&path)
                .args(["--config", path.to_str().unwrap(), "--check-config"])
                .status()
                .await
                .unwrap()
                .success()
        );
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }
    let mut invalid = manifest.clone();
    invalid["artifacts"][0]["digest"] = json!(vec![0u8; 32]);
    let invalid_path = root.path().join("invalid-model.json");
    private(&invalid_path, &serde_json::to_vec(&invalid).unwrap());
    let mut bad = prepared.clone();
    bad["services"]["rerank"]["upstream"]["manifest_file"] = json!(invalid_path);
    private(&path, &serde_json::to_vec(&bad).unwrap());
    assert!(
        command(&path)
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .status()
            .await
            .unwrap()
            .success()
    );
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    // An announced service keeps only its declaration until an uncached request.
    // The corrupt digest is therefore rejected at first use, without loading a model at boot.
    let invalid_child = start(&path, address).await;
    let invalid_db = sqlite_connection(root.path(), &path);
    sqlite_grants(&invalid_db, "rerank");
    let client = reqwest::Client::new();
    let token = jwt(&issuer, "native-model-caller");
    let query = "What is the capital of France?";
    let documents = [
        "Paris is the capital of France.",
        "Bananas grow in tropical climates.",
    ];
    let body = json!({"query":query,"documents":documents});
    assert!(metadata(&client, address).await["services"]["rerank"].is_object());
    assert_eq!(
        post(&client, address, &token, body.clone())
            .await
            .status()
            .as_u16(),
        502
    );
    stop(invalid_child).await;
    drop(invalid_db);
    private(&path, &serde_json::to_vec(&prepared).unwrap());
    let child = start(&path, address).await;
    let db = sqlite_connection(root.path(), &path);
    sqlite_grants(&db, "rerank");
    let reply = post(&client, address, &token, body.clone()).await;
    assert_eq!(reply.status().as_u16(), 200);
    assert_eq!(reply.headers()["x-graphit-cache"], "MISS");
    let revision = reply.headers()["x-graphit-rerank-revision"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(revision.starts_with("server-rerank-v1@sha256:"));
    let reply = read_json(reply).await;
    assert_eq!(reply["results"][0]["index"], 0);
    assert_eq!(reply["graphit"]["model"], "bge-reranker-v2-m3");
    assert_eq!(reply["graphit"]["model_revision"], manifest["revision"]);
    assert!(
        reply["graphit"]["recipe"]
            .as_str()
            .unwrap()
            .starts_with("gguf-config-v1:")
    );
    assert_eq!(
        post(&client, address, &token, body.clone()).await.headers()["x-graphit-cache"],
        "HIT"
    );
    let scores = consumer_scores(address, &token, query, &documents).await;
    assert!(scores.iter().all(|score| score.is_finite()));
    assert!(scores[0] > scores[1]);
    let discovery = metadata(&client, address).await;
    for field in ["model", "model_revision", "recipe", "revision"] {
        assert_eq!(
            reply["graphit"][field],
            discovery["services"]["rerank"][field]
        );
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let artifact = manifest["artifacts"][0]["path"].as_str().unwrap();
    let inactive_artifact = root.path().join("inactive-model.gguf");
    std::fs::rename(bundle.join(artifact), &inactive_artifact).unwrap();
    let cached = post(&client, address, &token, body.clone()).await;
    assert_eq!(cached.status().as_u16(), 200);
    assert_eq!(cached.headers()["x-graphit-cache"], "HIT");
    let reload = json!({"query":"Which city is the capital of France?","documents":documents});
    assert_eq!(
        post(&client, address, &token, reload.clone())
            .await
            .status()
            .as_u16(),
        502
    );
    std::fs::rename(&inactive_artifact, bundle.join(artifact)).unwrap();
    let reloaded = post(&client, address, &token, reload).await;
    assert_eq!(reloaded.status().as_u16(), 200);
    assert_eq!(reloaded.headers()["x-graphit-rerank-revision"], revision);
    sqlite_grants(&db, "embeddings");
    assert_eq!(
        post(&client, address, &token, body).await.status().as_u16(),
        403
    );
    stop(child).await;
    drop(db);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real SQLite executable and explicit verified GRAPHIT_TEST_GEMMA_BUNDLE GGUF weights"]
async fn compiled_embeddings_gguf_cpu_sdk_cache_and_authority() {
    use graphit_ai::{
        embedding::EmbeddingLimits,
        graphit_embedding::{GraphitEmbeddingInput, GraphitEmbeddings},
    };
    use graphit_auth::broker::BrokerEmbeddingService;
    let source_bundle = std::fs::canonicalize(
        std::env::var_os("GRAPHIT_TEST_GEMMA_BUNDLE").expect("explicit verified Gemma GGUF bundle"),
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let bundle = private_model_bundle(root.path(), &source_bundle);
    let local_manifest: Value =
        serde_json::from_slice(&std::fs::read(bundle.join("model.json")).unwrap()).unwrap();
    let address = address();
    let (path, issuer) = config(root.path(), address, None, "http://127.0.0.1:1/unused");
    let mut prepared: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    both_services(&mut prepared, "http://127.0.0.1:1/unused");
    prepared["services"]["rerank"] = json!({"enabled":false});
    prepared["database"]["startup_timeout"] = json!("60s");
    let embedding = &mut prepared["services"]["embeddings"];
    embedding["request_timeout"] = json!("30s");
    embedding["dimensions"] = json!(768);
    embedding["max_input_bytes"] = json!(65536);
    embedding["request_body_bytes"] = json!(131072);
    embedding["response_body_bytes"] = json!(65536);
    embedding["vector_json_bytes"] = json!(65536);
    embedding["upstream"] = json!({"protocol":"gguf-embeddinggemma2","model":"embeddinggemma2","directory":bundle,"manifest_file":bundle.join("model.json"),"max_artifact_bytes":600000000u64,"threads":2,"queue_capacity":2,"device":"cpu",
        "manifest_limits":{"max_manifest_bytes":8192,"max_artifacts":8,"max_role_bytes":64,"max_relative_path_bytes":256,"max_id_bytes":128,"max_revision_bytes":128,"max_dimension":768,"max_tokens":8192}});
    prepared["services"]["embeddings"]["upstream"]["idle_timeout_seconds"] = json!(1);
    private(&path, &serde_json::to_vec(&prepared).unwrap());
    let child = start(&path, address).await;
    let db = sqlite_connection(root.path(), &path);
    sqlite_grants(&db, "embeddings");
    let token = jwt(&issuer, "native-embedding-caller");
    let http = reqwest::Client::new();
    let discovery = metadata(&http, address).await;
    let advertised = &discovery["services"]["embeddings"];
    assert_eq!(advertised["model"], "embeddinggemma2");
    assert!(discovery["services"].get("rerank").is_none());
    let origin = format!("http://{address}");
    let endpoint = format!("{origin}/v1/embeddings");
    let client = BoundedClient::new(
        ClientPolicy {
            origin: &origin,
            allow_loopback_http: true,
            proxy: None,
            additional_roots: &[],
        },
        Limits {
            request_body_bytes: 4096,
            response_body_bytes: 65536,
            url_bytes: 2048,
            header_bytes: 8192,
            header_count: 32,
            max_in_flight: 1,
            max_idle_per_host: 1,
            idle_timeout: Duration::from_secs(1),
            max_certificates: 1,
            max_certificate_bytes: 4096,
        },
    )
    .unwrap();
    let service = BrokerEmbeddingService {
        endpoint: endpoint.clone(),
        identity: BrokerModelIdentity {
            model: advertised["model"].as_str().unwrap().into(),
            model_revision: advertised["model_revision"].as_str().unwrap().into(),
            recipe: advertised["recipe"].as_str().unwrap().into(),
            service_revision: advertised["revision"].as_str().unwrap().into(),
        },
        dimensions: 768,
        max_batch: advertised["max_batch"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        max_input_bytes: advertised["max_input_bytes"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let sdk = GraphitEmbeddings::new(
        &client,
        &service,
        EmbeddingLimits::new(8, 4096, 768, 6144, 8, 4096, 65536).unwrap(),
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    let mut auth =
        axum::http::HeaderValue::from_str(&format!("Bearer {}", token.as_str())).unwrap();
    auth.set_sensitive(true);
    headers.insert("authorization", auth);
    let cancel = Cancellation::default();
    let vectors = sdk
        .embed_guarded(
            &["Paris is the capital of France."],
            GraphitEmbeddingInput::Document,
            &headers,
            InferenceContext::new(&cancel, Instant::now() + Duration::from_secs(30)),
            &mut || Ok::<(), std::convert::Infallible>(()),
        )
        .await
        .unwrap()
        .into_vectors();
    assert_eq!(vectors.len(), 1);
    assert_eq!(vectors[0].len(), 768);
    assert!(vectors[0].iter().all(|value| value.is_finite()));
    let body = json!({"input":["Paris is the capital of France."]});
    let hit = http
        .post(&endpoint)
        .bearer_auth(token.as_str())
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(hit.status().as_u16(), 200);
    assert_eq!(hit.headers()["x-graphit-cache"], "HIT");
    let query = http
        .post(&endpoint)
        .bearer_auth(token.as_str())
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(
                &json!({"input":["Paris is the capital of France."],"input_type":"query"}),
            )
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(query.status().as_u16(), 200);
    assert_eq!(query.headers()["x-graphit-cache"], "MISS");
    let query = read_json(query).await;
    assert_ne!(query["data"][0]["embedding"], json!(vectors[0]));
    let completed = "A new sentence retained before a later token-limit failure.";
    let partial = http
        .post(&endpoint)
        .bearer_auth(token.as_str())
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(
                &json!({"input":[completed,"word ".repeat(9000)],"input_type":"query"}),
            )
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let partial_status = partial.status().as_u16();
    let partial_body = read_json(partial).await;
    assert_eq!(partial_status, 502, "{partial_body}");
    let retained = http
        .post(&endpoint)
        .bearer_auth(token.as_str())
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"input":[completed],"input_type":"query"})).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(retained.status().as_u16(), 200);
    assert_eq!(retained.headers()["x-graphit-cache"], "HIT");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let artifact = local_manifest["artifacts"][0]["path"].as_str().unwrap();
    let inactive_artifact = root.path().join("inactive-model.gguf");
    std::fs::rename(bundle.join(artifact), &inactive_artifact).unwrap();
    let request = |text: &str| {
        http.post(&endpoint)
            .bearer_auth(token.as_str())
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&json!({"input":[text],"input_type":"query"})).unwrap())
    };
    let cached = request(completed).send().await.unwrap();
    assert_eq!(cached.status().as_u16(), 200);
    assert_eq!(cached.headers()["x-graphit-cache"], "HIT");
    let reload = "A new query after the native embedding model became idle.";
    assert_eq!(request(reload).send().await.unwrap().status().as_u16(), 502);
    std::fs::rename(&inactive_artifact, bundle.join(artifact)).unwrap();
    let reloaded = request(reload).send().await.unwrap();
    assert_eq!(reloaded.status().as_u16(), 200);
    let reloaded = read_json(reloaded).await;
    assert_eq!(reloaded["graphit"]["recipe"], advertised["recipe"]);

    sqlite_grants(&db, "rerank");
    assert_eq!(
        http.post(&endpoint)
            .bearer_auth(token.as_str())
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    stop(child).await;
    drop(db);
}
