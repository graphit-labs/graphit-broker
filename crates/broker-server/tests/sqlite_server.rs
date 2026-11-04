use broker_control::{FlowLimits, LocalPasswordEngine, SqliteControlConfig, SqliteControlStore};
use broker_security::{CredentialDigester, DigestLimits, LocalPasswordHasher};
use broker_server::{ServerError, load_config};
use futures_util::{SinkExt, StreamExt};
use object_store::{ClientOptions, ObjectStoreExt, aws::AmazonS3Builder, path::Path as ObjectPath};
use rcgen::KeyPair;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{
    net::TcpStream,
    process::{Child, Command},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use zeroize::Zeroizing;
fn signed_stall(keys: &Value, url: &str) -> String {
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
        UriPathNormalizationMode, sign,
    };
    let field = |name: &str| keys[name].as_str().unwrap();
    let identity = aws_credential_types::Credentials::new(
        field("access_key_id"),
        field("secret_access_key"),
        Some(field("session_token").into()),
        None,
        "startup-fixture",
    )
    .into();
    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    let params = aws_sigv4::sign::v4::SigningParams::builder()
        .identity(&identity)
        .region(field("region"))
        .name("s3")
        .time(std::time::SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let host = url::Url::parse(url).unwrap().authority().to_string();
    let request = SignableRequest::new(
        "PUT",
        url,
        [("host", host.as_str())].into_iter(),
        SignableBody::UnsignedPayload,
    )
    .unwrap();
    let (instructions, _) = sign(request, &params).unwrap().into_parts();
    let parsed = url::Url::parse(url).unwrap();
    let mut wire = format!(
        "PUT {} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10000\r\n",
        parsed.path()
    );
    for (name, value) in instructions.headers() {
        wire.push_str(&format!("{name}: {value}\r\n"));
    }
    wire.push_str("\r\na");
    wire
}
const PEPPER: &str = "ephemeral-sqlite-server-pepper-32bytes";
fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn block(doc: &str) -> &str {
    doc.split_once("\x60\x60\x60yaml\n")
        .or_else(|| doc.split_once("\x60\x60\x60yaml\r\n"))
        .unwrap()
        .1
        .split_once("\x60\x60\x60")
        .unwrap()
        .0
}
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
fn config(root: &Path, addr: SocketAddr) -> Value {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    private(
        &root.join("signing.pk8"),
        &Zeroizing::new(key.serialize_der()),
    );
    let guide = include_str!("../../../docs/rust-broker-server.md");
    let mut value: Value = serde_saphyr::from_str(block(guide)).unwrap();
    value["server"]["address"] = json!(addr.to_string());
    value["server"]["public_url"] = json!(format!("http://{addr}"));
    value["server"]["shutdown_timeout"] = json!("3s");
    let sqlite_section = guide.split_once("## Select private SQLite").unwrap().1;
    let sqlite_example = sqlite_section
        .split_once("~~~yaml\n")
        .or_else(|| sqlite_section.split_once("~~~yaml\r\n"))
        .unwrap()
        .1
        .split_once("~~~")
        .unwrap()
        .0;
    let sqlite: Value = serde_saphyr::from_str(sqlite_example).unwrap();
    value["database"] = sqlite["database"].clone();
    value["auth"]["issuer"] = json!(format!("http://{addr}"));
    value["auth"]["pepper"] = json!(PEPPER);
    value["auth"].as_object_mut().unwrap().remove("resource");
    value["storage"]["routes"] = json!({"native-fs":{"driver":"filesystem","bucket":"native-storage","base_prefix":"graphit","directory":"volume"}});
    value["storage"]["default_route"] = json!("native-fs");
    value
}
fn write(root: &Path, value: &Value) -> PathBuf {
    let path = root.join("broker.json");
    private(&path, &serde_json::to_vec(value).unwrap());
    path
}
fn command() -> Command {
    let binary = std::env::var_os("GRAPHIT_TEST_BROKER_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_graphit-broker")));
    let mut c = Command::new(binary);
    c.kill_on_drop(true);
    c
}
async fn checked(path: &Path) -> std::process::Output {
    command()
        .args(["--config", path.to_str().unwrap(), "--check-config"])
        .output()
        .await
        .unwrap()
}
async fn start(path: &Path, addr: SocketAddr) -> Child {
    let mut child = command()
        .args(["--config", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let original = end();
    loop {
        if reqwest::get(format!("http://{addr}/readyz"))
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return child;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().await.unwrap();
            assert!(!String::from_utf8_lossy(&output.stderr).contains(PEPPER));
            panic!(
                "native SQLite Broker exited before ready: {status}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            Instant::now() < original,
            "native SQLite readiness deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn stop(mut child: Child, success: bool) {
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
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .unwrap()
        .unwrap();
    #[cfg(unix)]
    assert_eq!(status.success(), success, "native process close outcome");
    #[cfg(not(unix))]
    let _ = (status, success);
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(PEPPER.as_bytes().to_vec().into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
async fn reopened(path: &Path) {
    let config = SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(5),
        Duration::from_secs(4),
        Duration::from_secs(3),
        FlowLimits {
            provider_bytes: n(128),
            request_bytes: n(1024),
            continuation_bytes: n(4096),
        },
    )
    .unwrap();
    let store = SqliteControlStore::open(config, digester(), end())
        .await
        .unwrap();
    store.shutdown(end()).await.unwrap();
}

const PASSWORD: &str = "synthetic SQLite binary password";
const PROJECT: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const PKCE: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}
async fn post_form(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    pairs: &[(&str, &str)],
) -> reqwest::Response {
    client
        .post(format!("{base}{path}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(pairs))
        .send()
        .await
        .unwrap()
}
async fn stalled_put(root: &Path, addr: SocketAddr, keys: &Value) -> TcpStream {
    let prefix = keys["prefixes"][0].as_str().unwrap();
    let wire = signed_stall(
        keys,
        &format!(
            "http://{addr}/native-storage/{prefix}/v1/projects/{PROJECT}/registry/stalled.bin"
        ),
    );
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(wire.as_bytes()).await.unwrap();
    let original = end();
    loop {
        if std::fs::read_dir(root.join("volume/tmp"))
            .unwrap()
            .next()
            .is_some()
        {
            return stream;
        }
        assert!(
            Instant::now() < original,
            "signed PUT must hold real temporary IO"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn joined_io(mut stream: TcpStream, root: &Path) {
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(
        result.is_ok()
            || result.is_err_and(|e| matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ))
    );
    assert_eq!(
        std::fs::read_dir(root.join("volume/tmp")).unwrap().count(),
        0
    );
}
fn input(html: &str, name: &str) -> Zeroizing<String> {
    let prefix = format!("name=\"{name}\" value=\"");
    Zeroizing::new(
        html.split_once(&prefix)
            .unwrap()
            .1
            .split_once('"')
            .unwrap()
            .0
            .to_owned(),
    )
}
#[tokio::test]
#[ignore = "real SQLite binary OP browser/PKCE/refresh/Device, signed filesystem S3 and Native inventory/WS"]
async fn sqlite_binary_op_storage_and_native_presence() {
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let base = format!("http://{addr}");
    let mut value = config(root.path(), addr);
    local_admin(&mut value);
    value["auth"]["local"]["mfa"]["required"] = json!(false);
    let oidc: Value = serde_saphyr::from_str(block(include_str!(
        "../../../docs/rust-oidc-token-exchange.md"
    )))
    .unwrap();
    value["oidc"] = oidc["oidc"].clone();
    value["oidc"]["device_poll_interval"] = json!("1s");
    let presence: Value =
        serde_saphyr::from_str(block(include_str!("../../../docs/rust-presence-server.md")))
            .unwrap();
    value["presence"] = presence["presence"].clone();
    let project: Value = serde_saphyr::from_str(block(include_str!(
        "../../../docs/rust-project-access-http.md"
    )))
    .unwrap();
    value["project_access"] = project["project_access"].clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/embeddings", listener.local_addr().unwrap());
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peer_calls = calls.clone();
    let peer = axum::Router::new().route(
        "/embeddings",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<Value>| {
                let calls = peer_calls.clone();
                async move {
                    assert_eq!(
                        headers["authorization"],
                        "Bearer synthetic-sqlite-provider-key"
                    );
                    assert_eq!(body["input"], json!(["sqlite-cache"]));
                    assert_eq!(body["dimensions"], 2);
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    axum::Json(json!({"data":[{"index":0,"embedding":[0.25,0.75]}]}))
                }
            },
        ),
    );
    let (stop_peer, peer_stopped) = tokio::sync::oneshot::channel();
    let peer_job = tokio::spawn(async move {
        axum::serve(listener, peer)
            .with_graceful_shutdown(async {
                let _ = peer_stopped.await;
            })
            .await
            .unwrap();
    });
    value["services"] = json!({"embeddings":{"enabled":true,"revision":"sqlite-server-cache-v1","dimensions":2,"max_batch":8,"max_input_bytes":64,"request_timeout":"2s","required_scopes":[],"request_body_bytes":4096,"response_body_bytes":16384,"identity_json_bytes":8192,"grants_json_bytes":16384,"vector_json_bytes":256,"metadata_bytes":2048,"upstream":{"protocol":"openai-compatible","model":"fixture-model","model_revision":"fixture-model-r1","recipe":"retrieval-v1","url":endpoint,"api_key":"synthetic-sqlite-provider-key","send_dimensions":true,"transport":{"request_body_bytes":4096,"response_body_bytes":16384,"url_bytes":2048,"header_bytes":4096,"header_count":32,"max_in_flight":2,"max_idle_per_host":2,"idle_timeout":"1s","max_certificates":1,"max_certificate_bytes":4096,"allow_loopback_http":true}}}});
    let path = write(root.path(), &value);
    assert!(checked(&path).await.status.success());
    let dbpath = root.path().join("private/broker.db");
    provision_fixture_user(&dbpath).await;
    let child = start(&path, addr).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(25))
        .build()
        .unwrap();
    let redirect = "https://client.example.invalid/cb";
    let registered=data(client.post(format!("{base}/oauth/register")).body(json!({"redirect_uris":[redirect],"scope":"openid profile email offline_access","client_name":"SQLite native Server"}).to_string()).send().await.unwrap(),201).await;
    let client_id = registered["client_id"].as_str().unwrap();
    let query = form(&[
        ("client_id", client_id),
        ("redirect_uri", redirect),
        ("response_type", "code"),
        ("scope", "openid profile email offline_access"),
        ("state", "sqlite-server-state"),
        ("nonce", "sqlite-server-nonce"),
        (
            "code_challenge",
            "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
        ),
        ("code_challenge_method", "S256"),
        ("resource", "https://broker.example.test/v1"),
    ]);
    let response = client
        .get(format!("{base}/oauth/authorize?{query}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    let login = response.headers()["location"].to_str().unwrap().to_owned();
    assert!(login.starts_with("/oauth/login?id="));
    let response = post_form(
        &client,
        &base,
        &login,
        &[("username", "alice"), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(response.status(), 303);
    let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(
        location
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1,
        "sqlite-server-state"
    );
    let code = Zeroizing::new(
        location
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned(),
    );
    let fields = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("redirect_uri", redirect),
        ("code", code.as_str()),
        ("code_verifier", PKCE),
        ("resource", "https://broker.example.test/v1"),
    ];
    let tokens = data(
        post_form(&client, &base, "/oauth/token", &fields).await,
        200,
    )
    .await;
    assert_eq!(
        data(
            post_form(&client, &base, "/oauth/token", &fields).await,
            400
        )
        .await["error"],
        "invalid_grant"
    );
    let raw = Zeroizing::new(tokens["access_token"].as_str().unwrap().to_owned());
    let refresh = Zeroizing::new(tokens["refresh_token"].as_str().unwrap().to_owned());
    let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(
        data(
            client
                .get(format!("{base}/v1/oidc/keys"))
                .send()
                .await
                .unwrap(),
            200,
        )
        .await,
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&[base.as_str()]);
    validation.set_audience(&["storage-api"]);
    let claims = jsonwebtoken::decode::<Value>(
        &raw,
        &jsonwebtoken::DecodingKey::from_jwk(&jwks.keys[0]).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    let subject = claims["sub"].as_str().unwrap();
    assert_eq!(
        data(
            client
                .get(format!("{base}/oauth/userinfo"))
                .bearer_auth(raw.as_str())
                .send()
                .await
                .unwrap(),
            200
        )
        .await["sub"],
        subject
    );
    let rotated = data(
        post_form(
            &client,
            &base,
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", refresh.as_str()),
                ("resource", "https://broker.example.test/v1"),
            ],
        )
        .await,
        200,
    )
    .await;
    assert_ne!(rotated["refresh_token"], tokens["refresh_token"]);

    let embedding_body = json!({"input":["sqlite-cache"]}).to_string();
    assert_eq!(
        client
            .post(format!("{base}/v1/embeddings"))
            .bearer_auth(raw.as_str())
            .header("content-type", "application/json")
            .body(embedding_body.clone())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    // A real current subject receives fixture ACL rows; the Server must consume them fresh.
    let db = Connection::open(&dbpath).unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at)VALUES('server-grant','fixture','subject',?1,'native-fs',0,0)",[subject]).unwrap();
    for (table, values) in [
        (
            "grant_capabilities",
            vec![
                "s3",
                "presence:publish",
                "presence:read",
                "embeddings",
                "hub",
                "task:read",
            ],
        ),
        ("grant_projects", vec![PROJECT]),
        ("grant_s3_operations", vec!["read", "write"]),
        ("grant_s3_prefixes", vec!["v1"]),
    ] {
        for v in values {
            db.execute(
                &format!("INSERT INTO {table}(grant_id,value)VALUES('server-grant',?1)"),
                [v],
            )
            .unwrap();
        }
    }

    for expected in ["MISS", "HIT"] {
        let response = client
            .post(format!("{base}/v1/embeddings"))
            .bearer_auth(raw.as_str())
            .header("content-type", "application/json")
            .body(embedding_body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["x-graphit-cache"], expected);
        let _ = response.bytes().await.unwrap();
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let project_body = json!({"project_id":PROJECT,"module":"task","action":"read"}).to_string();
    assert_eq!(
        client
            .post(format!("{base}/v1/project/access/authorize"))
            .bearer_auth(raw.as_str())
            .header("content-type", "application/json")
            .body(project_body.clone())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(format!("{base}/v1/hub/catalog/projects"))
            .bearer_auth(raw.as_str())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let storage_body = json!({"scope":"project","project_id":PROJECT,"module":"hub"}).to_string();
    let keys = data(
        client
            .post(format!("{base}/v1/s3/credentials"))
            .bearer_auth(raw.as_str())
            .header("content-type", "application/json")
            .body(storage_body.clone())
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    let field = |name: &str| keys[name].as_str().unwrap().to_owned();
    let objects = AmazonS3Builder::new()
        .with_bucket_name(field("bucket"))
        .with_region(field("region"))
        .with_endpoint(field("endpoint"))
        .with_access_key_id(field("access_key_id"))
        .with_secret_access_key(field("secret_access_key"))
        .with_token(field("session_token"))
        .with_virtual_hosted_style_request(false)
        .with_client_options(
            ClientOptions::new()
                .with_allow_http(true)
                .with_timeout(Duration::from_secs(5)),
        )
        .build()
        .unwrap();
    let prefix = keys["prefixes"][0].as_str().unwrap();
    let object = ObjectPath::from(format!(
        "{prefix}/v1/projects/{PROJECT}/registry/server.bin"
    ));
    objects
        .put(&object, b"native SQLite signed storage".to_vec().into())
        .await
        .unwrap();
    assert_eq!(
        &objects.get(&object).await.unwrap().bytes().await.unwrap()[..],
        b"native SQLite signed storage"
    );
    let inventory = format!("{base}/v1/instances/sqlite-station/inventory");
    assert_eq!(
        client
            .put(&inventory)
            .bearer_auth(raw.as_str())
            .header("content-type", "application/json")
            .body(json!({"projects":[{"project_id":PROJECT,"versions":["main"]}]}).to_string())
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    assert_eq!(
        data(
            client
                .get(&inventory)
                .bearer_auth(raw.as_str())
                .send()
                .await
                .unwrap(),
            200
        )
        .await["projects"][0]["project_id"],
        PROJECT
    );
    let mut request = format!("ws://{addr}/v1/realtime")
        .into_client_request()
        .unwrap();
    let mut header = format!("Bearer {}", raw.as_str())
        .parse::<tokio_tungstenite::tungstenite::http::HeaderValue>()
        .unwrap();
    header.set_sensitive(true);
    request.headers_mut().insert("authorization", header);
    let (mut socket, _) = connect_async(request).await.unwrap();
    socket
        .send(Message::Text(
            json!({"op":"subscribe","project_id":PROJECT,"instance_id":"sqlite-station"})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let welcome = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Text(welcome) = welcome else {
        panic!("expected WS welcome")
    };
    assert_eq!(
        serde_json::from_str::<Value>(&welcome).unwrap()["type"],
        "welcome"
    );
    // A fresh ACL snapshot must deny a new issuance and own read after revocation.
    db.execute("DELETE FROM grant_capabilities WHERE grant_id='server-grant' AND value IN ('s3','presence:read','embeddings','task:read')",[]).unwrap();
    assert_eq!(
        client
            .post(format!("{base}/v1/s3/credentials"))
            .bearer_auth(raw.as_str())
            .header("content-type", "application/json")
            .body(storage_body)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .get(&inventory)
            .bearer_auth(raw.as_str())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    db.execute(
        "INSERT INTO grant_capabilities(grant_id,value)VALUES('server-grant','presence:read')",
        [],
    )
    .unwrap();

    assert_eq!(
        client
            .post(format!("{base}/v1/embeddings"))
            .bearer_auth(raw.as_str())
            .header("content-type", "application/json")
            .body(embedding_body.clone())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    db.execute(
        "INSERT INTO grant_capabilities(grant_id,value)VALUES('server-grant','embeddings')",
        [],
    )
    .unwrap();
    assert_eq!(
        client
            .post(format!("{base}/v1/project/access/authorize"))
            .bearer_auth(raw.as_str())
            .header("content-type", "application/json")
            .body(project_body)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    // Device performs a second real password purpose and explicit consent.
    let device = data(
        post_form(
            &client,
            &base,
            "/oauth/device/authorize",
            &[("client_id", "graphit-cli")],
        )
        .await,
        200,
    )
    .await;
    let device_path = format!(
        "/oauth/device?{}",
        form(&[("user_code", device["user_code"].as_str().unwrap())])
    );
    let consent = post_form(
        &client,
        &base,
        &device_path,
        &[("username", "alice"), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(consent.status(), 200);
    let html = Zeroizing::new(consent.text().await.unwrap());
    let consent_secret = input(&html, "consent_secret");
    assert_eq!(
        post_form(
            &client,
            &base,
            &device_path,
            &[
                ("client_id", "graphit-cli"),
                ("consent_secret", consent_secret.as_str()),
                ("decision", "allow")
            ]
        )
        .await
        .status(),
        200
    );
    let device_tokens = data(
        post_form(
            &client,
            &base,
            "/oauth/token",
            &[
                ("grant_type", broker_control::DEVICE_GRANT_TYPE),
                ("client_id", "graphit-cli"),
                ("device_code", device["device_code"].as_str().unwrap()),
            ],
        )
        .await,
        200,
    )
    .await;
    assert!(
        device_tokens.get("id_token").is_none() && device_tokens.get("refresh_token").is_none()
    );
    let device_claims = jsonwebtoken::decode::<Value>(
        device_tokens["access_token"].as_str().unwrap(),
        &jsonwebtoken::DecodingKey::from_jwk(&jwks.keys[0]).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(device_claims["scope"], "");
    drop(db);
    // Fresh socket after the causal ACL denial; it stays owned during signal shutdown.
    drop(socket);
    let mut request = format!("ws://{addr}/v1/realtime")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", raw.as_str()).parse().unwrap(),
    );
    let (mut socket, _) = connect_async(request).await.unwrap();
    socket
        .send(Message::Text(
            json!({"op":"subscribe","project_id":PROJECT,"instance_id":"sqlite-station"})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap(),
        Some(Ok(Message::Text(_)))
    ));
    // A credential issued before ACL removal retains its captured FS authority to expiry.
    let stalled = stalled_put(root.path(), addr, &keys).await;
    stop(child, true).await;
    drop(socket);
    joined_io(stalled, root.path()).await;
    reopened(&dbpath).await;
    let restarted = start(&path, addr).await;

    let response = client
        .post(format!("{base}/v1/embeddings"))
        .bearer_auth(raw.as_str())
        .header("content-type", "application/json")
        .body(embedding_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-graphit-cache"], "HIT");
    let _ = response.bytes().await.unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        data(
            client
                .get(&inventory)
                .bearer_auth(raw.as_str())
                .send()
                .await
                .unwrap(),
            200
        )
        .await["projects"][0]["project_id"],
        PROJECT
    );
    stop(restarted, true).await;
    value["server"]["shutdown_timeout"] = json!("1ns");
    let path = write(root.path(), &value);
    let impatient = start(&path, addr).await;
    let stalled = stalled_put(root.path(), addr, &keys).await;
    stop(impatient, false).await;
    joined_io(stalled, root.path()).await;
    assert!(TcpStream::connect(addr).await.is_err());
    reopened(&dbpath).await;
    let _ = stop_peer.send(());
    peer_job.await.unwrap();
}
async fn provision_fixture_user(path: &Path) {
    // Offline test provisioning supplies a real PHC and explicit role assignment;
    // it is neither a product bootstrap command nor a pre-authenticated session.
    reopened(path).await;
    let engine = LocalPasswordEngine::new(
        LocalPasswordHasher::new(Zeroizing::new(
            PEPPER.as_bytes().to_vec().into_boxed_slice(),
        ))
        .unwrap(),
        n(1),
        end(),
    )
    .await
    .unwrap();
    let hash = engine.hash(PASSWORD, end()).await.unwrap();
    let db = Connection::open(path).unwrap();
    db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',?1,'Alice','alice@example.invalid','org','[]',1,0,1,0,0)", [hash.as_str()]).unwrap();
    db.execute("INSERT INTO role_assignments(subject,role,created_at)VALUES('local|alice-subject','admin',0)", []).unwrap();
    drop(db);
    engine.close().await;
}
fn local_admin(value: &mut Value) {
    let local: Value = serde_saphyr::from_str(block(include_str!(
        "../../../docs/rust-admin-local-login.md"
    )))
    .unwrap();
    value["auth"]["local"] = local["auth"]["local"].clone();
    let admin: Value = serde_saphyr::from_str(block(include_str!(
        "../../../docs/rust-admin-cookie-session.md"
    )))
    .unwrap();
    value["administration"] = admin["administration"].clone();
    value["administration"]["cookie_secure"] = json!(false);
    value["administration"]["request_timeout"] = json!("20s");
    value["database"]["operation_timeout"] = json!("20s");
}
async fn data(response: reqwest::Response, status: u16) -> Value {
    assert_eq!(response.status(), status, "{}", response.url().path());
    let bytes = Zeroizing::new(response.bytes().await.unwrap().to_vec());
    serde_json::from_slice(&bytes).unwrap()
}
fn cookie(response: &reqwest::Response) -> Zeroizing<String> {
    let value = response.headers()["set-cookie"].to_str().unwrap();
    assert!(value.contains("HttpOnly") && value.contains("SameSite=Lax"));
    assert!(!value.contains("; Secure"));
    Zeroizing::new(value.split(';').next().unwrap().to_owned())
}
#[tokio::test]
#[ignore = "real native SQLite LOCAL MFA, admin cookie and current SQL authorization"]
async fn sqlite_binary_local_mfa_admin_current_authority_and_redacted_config() {
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let mut value = config(root.path(), addr);
    local_admin(&mut value);
    let path = write(root.path(), &value);
    assert!(checked(&path).await.status.success());
    assert!(!root.path().join("private").exists());
    let dbpath = root.path().join("private/broker.db");
    provision_fixture_user(&dbpath).await;
    let child = start(&path, addr).await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let response = client
        .post(format!("{base}/admin/auth/local"))
        .header("content-type", "application/json")
        .body(json!({"username":"alice","password":PASSWORD}).to_string())
        .send()
        .await
        .unwrap();
    assert!(!response.headers().contains_key("set-cookie"));
    let pending = data(response, 200).await;
    assert_eq!(pending["status"], "mfa-enrollment");
    let uri = Zeroizing::new(pending["otpauth_uri"].as_str().unwrap().to_owned());
    let sdk = totp_rs::Totp::from_url(&uri).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let factor = Zeroizing::new(sdk.generate(now).to_string());
    let response = client
        .post(format!("{base}/admin/auth/local/continue"))
        .header("content-type", "application/json")
        .body(
            json!({"challenge_token":pending["challenge_token"],"code":factor.as_str()})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    let session_cookie = cookie(&response);
    let complete = data(response, 200).await;
    assert_eq!(complete["status"], "complete");
    assert_eq!(complete["recovery_codes"].as_array().unwrap().len(), 10);
    let session = data(
        client
            .get(format!("{base}/admin/api/v1/session"))
            .header("cookie", session_cookie.as_str())
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(session["username"], "alice");
    let csrf = Zeroizing::new(session["csrf_token"].as_str().unwrap().to_owned());
    let dump = data(
        client
            .get(format!("{base}/admin/api/v1/config"))
            .header("cookie", session_cookie.as_str())
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    let yaml = dump["yaml"].as_str().unwrap();
    assert!(!yaml.contains(PEPPER));
    let projection: Value = serde_saphyr::from_str(yaml).unwrap();
    let database = projection["database"].as_object().unwrap();
    assert_eq!(database.len(), 6);
    assert_eq!(database["backend"], "sqlite");
    assert_eq!(database["path"], dbpath.to_string_lossy().as_ref());
    for absent in ["password", "host", "pool", "ca_file"] {
        assert!(!database.contains_key(absent));
    }
    let admin_request = |method, route: &str| {
        client
            .request(method, format!("{base}/admin/api/v1/{route}"))
            .header("cookie", session_cookie.as_str())
            .header("x-csrf-token", csrf.as_str())
            .header("content-type", "application/json")
    };
    assert_eq!(
        admin_request(reqwest::Method::POST, "local-users")
            .body(
                json!({"username":"server-bot","subject":"server-bot-subject","kind":"service"})
                    .to_string()
            )
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    assert_eq!(admin_request(reqwest::Method::PUT,"local-users/server-bot").body(json!({"username":"server-bot","subject":"server-bot-subject","kind":"service","name":"Updated through native SQLite HTTP"}).to_string()).send().await.unwrap().status(),204);
    assert_eq!(
        admin_request(reqwest::Method::PUT, "roles/server-reader")
            .body(json!({"permissions":["session.read"]}).to_string())
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    let assignment =
        json!({"subject":"local|server-bot-subject","role":"server-reader"}).to_string();
    assert_eq!(
        admin_request(reqwest::Method::POST, "role-assignments")
            .body(assignment.clone())
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    let issued = data(
        admin_request(reqwest::Method::POST, "local-users/server-bot/credentials")
            .body(json!({"scopes":["presence-sdk"],"expires_in":3600}).to_string())
            .send()
            .await
            .unwrap(),
        201,
    )
    .await;
    let opaque = Zeroizing::new(issued["token"].as_str().unwrap().to_owned());
    assert!(opaque.starts_with("gb_sc_"));
    // URL-safe base64 can start with a dash. Make the listing cover that
    // valid random outcome on every run, while leaving the bearer intact.
    let credential_id = "-AAAAAAAAAAAAAAA";
    Connection::open(&dbpath)
        .unwrap()
        .execute(
            "UPDATE local_tokens SET token_id=?1 WHERE token_id=?2",
            [credential_id, issued["id"].as_str().unwrap()],
        )
        .unwrap();

    let credentials = data(
        admin_request(reqwest::Method::GET, "local-users/server-bot/credentials")
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(credentials["credentials"][0]["id"], credential_id);
    assert!(!credentials.to_string().contains(opaque.as_str()));
    let db = Connection::open(&dbpath).unwrap();
    #[cfg(target_os = "linux")]
    let before_close_sidecars: Vec<_> = ["broker.db-wal", "broker.db-shm"]
        .iter()
        .map(|name| {
            use std::os::unix::fs::MetadataExt;
            let p = root.path().join("private").join(name);
            (p.clone(), std::fs::symlink_metadata(p).unwrap().ino())
        })
        .collect();
    let revision: i64 = db
        .query_row(
            "SELECT revision FROM resource_acl_state WHERE id=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    drop(db);
    #[cfg(target_os = "linux")]
    for (path, inode) in before_close_sidecars {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::symlink_metadata(path).ok().map(|m| m.ino()),
            Some(inode),
            "closing peer SQLite must preserve live Server WAL/SHM inodes"
        );
    }
    let grant = json!({"id":"server-bot-presence","name":"Native service presence","access":"subject","principal":"local|server-bot-subject","capabilities":["presence:publish","presence:read"],"projects":[PROJECT],"s3_operations":[],"s3_prefixes":[],"s3_route":""});
    assert_eq!(
        admin_request(reqwest::Method::POST, "grants")
            .header("if-match", revision.to_string())
            .body(grant.to_string())
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    assert_eq!(
        admin_request(reqwest::Method::POST, "grants")
            .header("if-match", revision.to_string())
            .body(grant.to_string())
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        admin_request(reqwest::Method::DELETE, "role-assignments")
            .body(assignment)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        admin_request(reqwest::Method::DELETE, "roles/server-reader")
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    // Cookie possession without CSRF cannot log out the session.
    assert_eq!(
        client
            .post(format!("{base}/admin/auth/logout"))
            .header("cookie", session_cookie.as_str())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .get(format!("{base}/admin/api/v1/session"))
            .header("cookie", session_cookie.as_str())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // Authority is read again for an already issued cookie.
    let db = Connection::open(&dbpath).unwrap();
    assert_eq!(
        db.execute(
            "DELETE FROM role_assignments WHERE subject='local|alice-subject'",
            []
        )
        .unwrap(),
        1,
        "fixture revoked exactly Alice explicit admin assignment"
    );
    assert_eq!(
        db.query_row(
            "SELECT subject FROM local_users WHERE username='alice'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "alice-subject"
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM role_assignments WHERE subject='local|alice-subject'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let observed = data(
        client
            .get(format!("{base}/admin/api/v1/session"))
            .header("cookie", session_cookie.as_str())
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(
        observed["role_source"], "database",
        "cookie role source after native writes"
    );
    assert!(
        !observed["roles"]
            .as_array()
            .unwrap()
            .contains(&json!("admin")),
        "current roles after native writes: {}",
        observed["roles"]
    );
    assert_eq!(
        client
            .get(format!("{base}/admin/api/v1/config"))
            .header("cookie", session_cookie.as_str())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    db.execute("INSERT INTO role_assignments(subject,role,created_at)VALUES('local|alice-subject','admin',0)", []).unwrap();
    assert_eq!(
        client
            .post(format!("{base}/admin/auth/logout"))
            .header("cookie", session_cookie.as_str())
            .header("x-csrf-token", csrf.as_str())
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        client
            .get(format!("{base}/admin/api/v1/session"))
            .header("cookie", session_cookie.as_str())
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    drop(db);
    stop(child, true).await;
    reopened(&dbpath).await;
    let db = Connection::open(&dbpath).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM local_mfa WHERE subject='alice-subject'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    drop(db);
    // Select the explicit LOCAL composition on the same durable database.
    let presence: Value =
        serde_saphyr::from_str(block(include_str!("../../../docs/rust-presence-server.md")))
            .unwrap();
    value["presence"] = presence["presence"].clone();
    value["presence"]["authentication"] = json!({"type":"local_opaque","audience":"storage-api","identity_json_bytes":8192,"list":{"required_scopes":["presence-sdk"],"grants_json_bytes":65536,"inventory_json_bytes":65536,"query_bytes":4096,"request_timeout":"3s"}});
    value["presence"]["publish"]["required_scopes"] = json!(["presence-sdk"]);
    value["presence"]["read"]["required_scopes"] = json!(["presence-sdk"]);
    value["presence"]["realtime"]["required_scopes"] = json!(["presence-sdk"]);
    let path = write(root.path(), &value);
    let child = start(&path, addr).await;
    let inventory = format!("{base}/v1/instances/sqlite-service/inventory");
    assert_eq!(
        client
            .put(&inventory)
            .bearer_auth(opaque.as_str())
            .header("content-type", "application/json")
            .body(json!({"projects":[{"project_id":PROJECT,"versions":["main"]}]}).to_string())
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    assert_eq!(
        data(
            client
                .get(&inventory)
                .bearer_auth(opaque.as_str())
                .send()
                .await
                .unwrap(),
            200
        )
        .await["instance_id"],
        "sqlite-service"
    );
    let list = data(
        client
            .get(format!("{base}/v1/instances?limit=1"))
            .bearer_auth(opaque.as_str())
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(list["items"][0]["instance_id"], "sqlite-service");
    let mut request = format!("ws://{addr}/v1/realtime")
        .into_client_request()
        .unwrap();
    let mut header = format!("Bearer {}", opaque.as_str())
        .parse::<tokio_tungstenite::tungstenite::http::HeaderValue>()
        .unwrap();
    header.set_sensitive(true);
    request.headers_mut().insert("authorization", header);
    let (mut socket, _) = connect_async(request).await.unwrap();
    socket
        .send(Message::Text(
            json!({"op":"subscribe","project_id":PROJECT,"instance_id":"sqlite-service"})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let Message::Text(welcome) = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    else {
        panic!("expected LOCAL WS welcome")
    };
    assert_eq!(
        serde_json::from_str::<Value>(&welcome).unwrap()["type"],
        "welcome"
    );
    let db = Connection::open(&dbpath).unwrap();
    db.execute(
        "UPDATE local_users SET enabled=0 WHERE username='server-bot'",
        [],
    )
    .unwrap();
    assert_eq!(
        client
            .get(&inventory)
            .bearer_auth(opaque.as_str())
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    drop(db);
    stop(child, true).await;
    drop(socket);
    reopened(&dbpath).await;
}
#[tokio::test]
async fn sqlite_cli_validates_explicit_backend_without_side_effects() {
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let good = config(root.path(), addr);
    let path = write(root.path(), &good);
    assert!(load_config(&path).await.is_ok());
    assert!(checked(&path).await.status.success());
    assert!(!root.path().join("private").exists());
    assert!(!root.path().join("volume").exists());
    assert!(TcpStream::connect(addr).await.is_err());
    let mut invalid = vec![];
    for field in [
        "path",
        "startup_timeout",
        "operation_timeout",
        "shutdown_timeout",
        "flows",
    ] {
        let mut v = good.clone();
        v["database"].as_object_mut().unwrap().remove(field);
        invalid.push(v);
    }
    for field in ["host", "pool", "password", "ca_file"] {
        let mut v = good.clone();
        v["database"][field] = json!("foreign-field");
        invalid.push(v);
    }
    for spelling in ["", ":memory:", "file:broker.db"] {
        let mut v = good.clone();
        v["database"]["path"] = json!(spelling);
        invalid.push(v);
    }
    for field in ["startup_timeout", "operation_timeout", "shutdown_timeout"] {
        let mut v = good.clone();
        v["database"][field] = json!("0s");
        invalid.push(v);
    }
    for v in invalid {
        let path = write(root.path(), &v);
        assert_eq!(
            load_config(&path).await.err(),
            Some(ServerError::Configuration)
        );
        let result = checked(&path).await;
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains(PEPPER));
    }
    assert!(!root.path().join("private").exists());
    assert!(!root.path().join("volume").exists());
    assert!(TcpStream::connect(addr).await.is_err());
}
#[tokio::test]
#[ignore = "real native binary, private SQLite birth/reopen and signal-owned close"]
async fn sqlite_binary_birth_reopen_and_partial_startup_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let good = config(root.path(), addr);
    let path = write(root.path(), &good);
    let child = start(&path, addr).await;
    let dbpath = root.path().join("private/broker.db");
    assert!(dbpath.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&dbpath).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    let db = Connection::open(&dbpath).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        25
    );
    drop(db);
    stop(child, true).await;
    reopened(&dbpath).await;
    stop(start(&path, addr).await, true).await;
    reopened(&dbpath).await;
    // Bind fails after SQL and volume owners have started; their ownership is released.
    let held = tokio::net::TcpListener::bind(addr).await.unwrap();
    let output = command()
        .args(["--config", path.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("listener bind failed"));
    drop(held);
    reopened(&dbpath).await;
    stop(start(&path, addr).await, true).await;
    // The second volume cannot open after the first one has succeeded.
    let mut bad = good.clone();
    private(&root.path().join("occupied"), b"occupied");
    bad["storage"]["routes"]["z-bad"] = json!({"driver":"filesystem","bucket":"blocked-storage","base_prefix":"graphit","directory":"occupied"});
    let badpath = write(root.path(), &bad);
    let output = command()
        .args(["--config", badpath.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("storage startup failed"));
    assert!(TcpStream::connect(addr).await.is_err());
    reopened(&dbpath).await;
    let path = write(root.path(), &good);
    stop(start(&path, addr).await, true).await;
}
