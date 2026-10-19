use axum::{
    Router,
    http::{HeaderMap, StatusCode},
};
use broker_control::{
    FlowLimits, OIDC_REGISTRATION_BODY_BYTES, OidcAuthorizationConfiguration,
    OidcAuthorizationLimits, OidcAuthorizationPolicy, SqliteControlConfig, SqliteControlStore,
};
use broker_presence::{OidcRegistrationHttpConfig, sqlite_oidc_registration_router};
use broker_security::{CredentialDigester, DigestLimits};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::{
    Request,
    body::{Body, Bytes, Frame},
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    net::SocketAddr,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
use zeroize::Zeroizing;

fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(vec![43; 32].into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
fn policy(enabled: bool) -> OidcAuthorizationPolicy {
    OidcAuthorizationPolicy::new(
        OidcAuthorizationConfiguration {
            cli_client_id: "graphit-cli".into(),
            cli_redirect_path: "/oauth/callback".into(),
            api_audience: "graphit-broker".into(),
            accepted_resources: vec![],
            dynamic_registration: enabled,
            authorization_ttl: Duration::from_secs(60),
        },
        OidcAuthorizationLimits::new(n(8192), n(4096)).unwrap(),
    )
    .unwrap()
}
struct Fixture {
    store: Arc<SqliteControlStore>,
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    server: JoinHandle<std::io::Result<()>>,
    _temp: tempfile::TempDir,
}
impl Fixture {
    async fn new(enabled: bool, request_timeout: Duration) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let config = SqliteControlConfig::new(
            temp.path().join("private").join("broker.db"),
            Duration::from_secs(5),
            Duration::from_secs(3),
            Duration::from_secs(5),
            FlowLimits {
                provider_bytes: n(128),
                request_bytes: n(1024),
                continuation_bytes: n(4096),
            },
        )
        .unwrap();
        let store = Arc::new(
            SqliteControlStore::open(config, digester(), end())
                .await
                .unwrap(),
        );
        let router: Router = sqlite_oidc_registration_router(
            store.clone(),
            Arc::new(policy(enabled)),
            OidcRegistrationHttpConfig::new(request_timeout).unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        Self {
            store,
            address,
            stop: Some(stop),
            server,
            _temp: temp,
        }
    }
    async fn send<B>(&self, body: B) -> (StatusCode, HeaderMap, Bytes)
    where
        B: Body<Data = Bytes, Error = Infallible> + Unpin + Send + 'static,
    {
        let stream = TcpStream::connect(self.address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let driver = tokio::spawn(connection);
        let request = Request::builder()
            .method("POST")
            .uri("/oauth/register")
            .header("host", self.address.to_string())
            .header("content-type", "application/json")
            .header("connection", "close")
            .body(body)
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
            .await
            .unwrap()
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = tokio::time::timeout(Duration::from_secs(5), body.collect())
            .await
            .unwrap()
            .unwrap()
            .to_bytes();
        drop(sender);
        let completion = tokio::time::timeout(Duration::from_secs(5), driver)
            .await
            .unwrap()
            .unwrap();
        // A timeout response may close the client's unfinished body. Always join it.
        assert!(completion.is_ok() || parts.status == StatusCode::GATEWAY_TIMEOUT);
        (parts.status, parts.headers, bytes)
    }
    async fn post(&self, raw: Vec<u8>) -> (StatusCode, HeaderMap, Bytes) {
        self.send(Full::new(Bytes::from(raw))).await
    }
    async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut self.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.store.shutdown(end()).await.unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.server.abort();
    }
}
fn no_store(headers: &HeaderMap) {
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["pragma"], "no-cache");
}
fn valid_metadata() -> Vec<u8> {
    serde_json::to_vec(&json!({"redirect_uris":["http://127.0.0.1:43210/callback"],"client_name":"HTTP SQLite public client"})).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_dcr_http_uses_committed_sdk_response_and_public_headers() {
    let f = Fixture::new(true, Duration::from_secs(2)).await;
    let (status, headers, bytes) = f.post(valid_metadata()).await;
    assert_eq!(status, StatusCode::CREATED);
    no_store(&headers);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["client_name"], "HTTP SQLite public client");
    assert_eq!(value["token_endpoint_auth_method"], "none");
    assert_eq!(
        value["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(value["response_types"], json!(["code"]));
    assert_eq!(value["scope"], "openid profile email offline_access");
    assert_eq!(
        value["redirect_uris"],
        json!(["http://127.0.0.1:43210/callback"])
    );
    let id = value["client_id"].as_str().unwrap();
    assert_eq!(id.len(), 43);
    assert_ne!(id, "graphit-cli");
    assert!(value["client_id_issued_at"].as_i64().unwrap() > 0);
    for field in [
        "client_secret",
        "client_secret_expires_at",
        "registration_access_token",
        "registration_client_uri",
    ] {
        assert!(value.get(field).is_none());
    }
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_dcr_http_rejects_bad_metadata_and_oversized_body() {
    let f = Fixture::new(true, Duration::from_secs(2)).await;
    for raw in [
        b"not JSON".to_vec(),
        vec![b' '; OIDC_REGISTRATION_BODY_BYTES + 1],
    ] {
        let (status, headers, bytes) = f.post(raw).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        no_store(&headers);
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"error":"invalid_client_metadata"})
        );
    }
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_dcr_http_disabled_route_and_closed_store_remain_distinct() {
    let disabled = Fixture::new(false, Duration::from_secs(2)).await;
    assert_eq!(
        disabled.post(valid_metadata()).await.0,
        StatusCode::NOT_FOUND
    );
    disabled.close().await;
    let closed = Fixture::new(true, Duration::from_secs(2)).await;
    closed.store.shutdown(end()).await.unwrap();
    let (status, headers, bytes) = closed.post(valid_metadata()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    no_store(&headers);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({"error":"temporarily_unavailable"})
    );
    closed.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_dcr_http_body_deadline_is_finite_and_joins_peer() {
    let f = Fixture::new(true, Duration::from_millis(80)).await;
    let body = StreamBody::new(futures_util::stream::pending::<
        Result<Frame<Bytes>, Infallible>,
    >());
    let (status, headers, bytes) = f.send(body).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    no_store(&headers);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({"error":"temporarily_unavailable"})
    );
    let mut incomplete = TcpStream::connect(f.address).await.unwrap();
    incomplete.write_all(b"POST /oauth/register HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{").await.unwrap();
    drop(incomplete);
    f.close().await;
}
