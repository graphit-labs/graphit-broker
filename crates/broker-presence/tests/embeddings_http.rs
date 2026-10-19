#[path = "../../broker-control/tests/support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    unused_imports,
    reason = "shared genuine JWT and HTTPS F1 fixtures serve several protocol consumers"
)]
mod ingress;
#[path = "../../broker-control/tests/support/sqlite_admin_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared persisted human/service fixtures also serve administration tests"
)]
mod opaque;
#[path = "support/sqlite_oidc_fixture.rs"]
#[allow(
    dead_code,
    unused_imports,
    reason = "reuse the established native TCP client rather than a new transport harness"
)]
mod transport;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::Response,
    routing::post,
};
use broker_control::{EmbeddingAdmissionLimits, EmbeddingCacheLimits};
use broker_presence::{
    EmbeddingBackend, EmbeddingsHttpConfig, RemoteEmbeddingsConfig, disabled_embeddings_router,
    sqlite_embeddings_router,
};
use graphit_ai::{embedding::EmbeddingLimits, google_embedding::GoogleFamily};
use graphit_http::client::{BoundedClient, ClientPolicy, Limits};
use opaque::{Fixture, end, n};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use transport::{Reply, Server};

const PATH: &str = "/v1/embeddings";
fn config() -> EmbeddingsHttpConfig {
    EmbeddingsHttpConfig {
        revision: "fixture-v1".into(),
        model: "fixture-model".into(),
        model_revision: "fixture-model-r1".into(),
        recipe: "retrieval-v1".into(),
        dimensions: n(2),
        max_batch: n(8),
        max_input_bytes: n(64),
        request_body_bytes: n(4096),
        response_body_bytes: n(16384),
        request_timeout: Duration::from_secs(2),
        local_audience: "admin-api".into(),
        required_scopes: vec![],
        admission_limits: EmbeddingAdmissionLimits {
            identity_json_bytes: n(8192),
            grants_json_bytes: n(16384),
        },
        cache_limits: EmbeddingCacheLimits {
            dimensions: n(2),
            max_entries: n(8),
            vector_json_bytes: n(256),
            metadata_bytes: n(2048),
        },
    }
}
fn grants(f: &Fixture, kind: &str, principal: &str) {
    let db = f.db();
    db.execute_batch("DELETE FROM grant_capabilities;DELETE FROM grant_projects;DELETE FROM grant_s3_operations;DELETE FROM grant_s3_prefixes;DELETE FROM resource_grants;").unwrap();
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at)VALUES('embedding-fixture','fixture',?1,?2,'',0,0)",rusqlite::params![kind,principal]).unwrap();
    db.execute(
        "INSERT INTO grant_capabilities(grant_id,value)VALUES('embedding-fixture','embedding*')",
        [],
    )
    .unwrap();
    // A PROJECT selector must not restrict this capability-only endpoint.
    db.execute("INSERT INTO grant_projects(grant_id,value)VALUES('embedding-fixture','01KSH1CRFFG8Z74B5ZS78WW808')",[]).unwrap();
    db.execute("INSERT INTO resource_acl_state(id,revision,updated_at)VALUES(1,1,0) ON CONFLICT(id) DO UPDATE SET revision=revision+1",[]).unwrap();
}
struct PeerState {
    family: &'static str,
    partial: AtomicBool,
    width: AtomicUsize,
    delay_ms: AtomicU64,
    delay_after: AtomicUsize,
    seen: Mutex<Vec<(HeaderMap, Value)>>,
}
struct Peer {
    origin: String,
    state: Arc<PeerState>,
    stop: tokio::sync::oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}
async fn upstream(
    State(state): State<Arc<PeerState>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let count = if state.family == "google" {
        body.get("requests")
            .and_then(Value::as_array)
            .map_or(1, Vec::len)
    } else {
        body.get("input")
            .or_else(|| body.get("texts"))
            .unwrap()
            .as_array()
            .unwrap()
            .len()
    };
    let partial = state.partial.swap(false, Ordering::SeqCst);
    let call = {
        let mut seen = state.seen.lock().unwrap();
        seen.push((headers, body));
        seen.len()
    };
    if call >= state.delay_after.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(state.delay_ms.load(Ordering::SeqCst))).await;
    }
    let vectors: Vec<_> = (0..count)
        .map(|index| {
            if partial && index == 1 {
                json!([0.5])
            } else {
                json!(
                    (0..state.width.load(Ordering::SeqCst))
                        .map(|index| if index == 0 { 0.25 } else { 0.75 })
                        .collect::<Vec<_>>()
                )
            }
        })
        .collect();
    let body = match state.family {
        "cohere" => {
            json!({"embeddings":{"float":vectors},"meta":{"billed_units":{"input_tokens":count}}})
        }
        "google" if count == 1 => {
            json!({"embedding":{"values":vectors[0]},"usageMetadata":{"promptTokenCount":count}})
        }
        "google" => {
            json!({"embeddings":vectors.into_iter().map(|vector|json!({"values":vector})).collect::<Vec<_>>(),"usageMetadata":{"promptTokenCount":count}})
        }
        _ => {
            json!({"data":vectors.into_iter().enumerate().rev().map(|(index,vector)|json!({"index":index,"embedding":vector})).collect::<Vec<_>>(),"usage":{"tokens":count}})
        }
    };
    let mut response = Response::new(Body::from(body.to_string()));
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    response
}
impl Peer {
    async fn new(family: &'static str, partial: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(PeerState {
            family,
            partial: AtomicBool::new(partial),
            width: AtomicUsize::new(2),
            delay_ms: AtomicU64::new(0),
            delay_after: AtomicUsize::new(1),
            seen: Mutex::new(Vec::new()),
        });
        let router = Router::new()
            .route("/embeddings", post(upstream))
            .route("/alternative", post(upstream))
            .route("/other/models/fixture:batchEmbedContents", post(upstream))
            .route("/models/fixture:embedContent", post(upstream))
            .route("/models/fixture:batchEmbedContents", post(upstream))
            .with_state(state.clone());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let join = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            origin,
            state,
            stop,
            join,
        }
    }
    fn configuration(&self, protocol: &str, headers: HeaderMap) -> RemoteEmbeddingsConfig {
        let client = BoundedClient::new(
            ClientPolicy {
                origin: &self.origin,
                allow_loopback_http: true,
                proxy: None,
                additional_roots: &[],
            },
            Limits {
                request_body_bytes: 4096,
                response_body_bytes: 16384,
                url_bytes: 2048,
                header_bytes: 4096,
                header_count: 32,
                max_in_flight: 2,
                max_idle_per_host: 2,
                idle_timeout: Duration::from_secs(1),
                max_certificates: 1,
                max_certificate_bytes: 4096,
            },
        )
        .unwrap();
        let google = self.state.family == "google";
        RemoteEmbeddingsConfig {
            client,
            protocol: protocol.into(),
            endpoint: format!(
                "{}{}",
                self.origin,
                if google {
                    "/models/fixture:embedContent"
                } else {
                    "/embeddings"
                }
            ),
            batch_endpoint: google
                .then(|| format!("{}/models/fixture:batchEmbedContents", self.origin)),
            model: if google {
                "models/fixture"
            } else {
                "fixture-model"
            }
            .into(),
            dimensions: 2,
            request_dimensions: (protocol == "openai-compatible").then_some(2),
            google_family: google.then_some(GoogleFamily::Gemini2),
            headers,
            limits: EmbeddingLimits::new(
                8,
                64 + 8 * GoogleFamily::Gemini2.max_input_prefix_bytes(),
                2,
                16,
                2,
                4096,
                16384,
            )
            .unwrap(),
        }
    }
    fn backend(&self, protocol: &str, headers: HeaderMap) -> Arc<EmbeddingBackend> {
        Arc::new(EmbeddingBackend::remote(self.configuration(protocol, headers)).unwrap())
    }
    fn hits(&self) -> usize {
        self.state.seen.lock().unwrap().len()
    }
    async fn close(self) {
        self.stop.send(()).unwrap();
        self.join.await.unwrap();
    }
}
async fn send(server: &Server, auth: &[(&str, &str)], body: &str) -> Reply {
    server
        .send_headers("POST", PATH, body.as_bytes(), auth)
        .await
}
fn error(reply: &Reply, status: u16, code: &str) {
    assert_eq!(reply.status.as_u16(), status, "{}", reply.json());
    assert_eq!(reply.json()["error"]["code"], code);
    assert!(reply.json()["request_id"].is_string());
    assert!(reply.json().get("data").is_none());
    let text = String::from_utf8_lossy(&reply.body);
    for canary in [
        "gb_at_",
        "gb_sc_",
        "fixture-secret",
        "private/broker.db",
        "SELECT",
    ] {
        assert!(!text.contains(canary));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn namespace_components_credentials_and_observed_multibatch_usage() {
    let f = Fixture::new().await;
    let issuer = ingress::fixture::Fixture::new().await;
    grants(&f, "global", "");
    let peer = Peer::new("openai", false).await;
    for variant in 0..11 {
        peer.state.width.store(2, Ordering::SeqCst);
        let mut remote = peer.configuration("openai-compatible", HeaderMap::new());
        let mut http = config();
        match variant {
            1 => {
                let mut value = HeaderValue::from_static("header-key-canary-170b");
                value.set_sensitive(true);
                remote.headers.insert("x-api-key", value);
            }
            2 => remote.protocol = "openai-embeddings-v1".into(),
            3 => remote.endpoint = format!("{}/alternative", peer.origin),
            4 => remote.model = "another-fixture-model".into(),
            5 => http.revision = "fixture-v2".into(),
            6 => remote.request_dimensions = None,
            9 => http.model_revision = "fixture-model-r2".into(),
            10 => http.recipe = "retrieval-v2".into(),
            7 => {
                remote.dimensions = 3;
                remote.request_dimensions = Some(3);
                remote.limits = EmbeddingLimits::new(8, 64, 3, 24, 2, 4096, 16384).unwrap();
                http.dimensions = n(3);
                http.cache_limits.dimensions = n(3);
                peer.state.width.store(3, Ordering::SeqCst);
            }
            _ => {}
        }
        let backend = Arc::new(EmbeddingBackend::remote(remote).unwrap());
        let server = Server::router(
            sqlite_embeddings_router(
                f.store.clone(),
                issuer.verifier(),
                None,
                http,
                backend.clone(),
            )
            .unwrap(),
        )
        .await;
        let before = peer.hits();
        let body = if variant == 8 {
            r#"{"input":"reuse","input_type":"query"}"#
        } else {
            r#"{"input":"reuse"}"#
        };
        let reply = send(&server, &[], body).await;
        assert_eq!(reply.status.as_u16(), 200, "variant={variant}");
        assert_eq!(
            reply.headers["x-graphit-cache"],
            if variant == 1 { "HIT" } else { "MISS" }
        );
        assert_eq!(peer.hits() - before, usize::from(variant != 1));
        let hit = send(&server, &[], body).await;
        assert_eq!(hit.headers["x-graphit-cache"], "HIT");
        server.close().await;
        backend.stop();
    }
    peer.state.width.store(2, Ordering::SeqCst);
    assert_eq!(peer.hits(), 10);
    assert_eq!(
        f.db()
            .query_row("SELECT count(*) FROM embedding_cache", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        10
    );
    let backend = peer.backend("openai-compatible", HeaderMap::new());
    let server = Server::router(
        sqlite_embeddings_router(
            f.store.clone(),
            issuer.verifier(),
            None,
            config(),
            backend.clone(),
        )
        .unwrap(),
    )
    .await;
    let body = r#"{"input":["m1","m2","m3","m4","m5"]}"#;
    let before = peer.hits();
    let reply = send(&server, &[], body).await;
    assert_eq!(reply.status.as_u16(), 200);
    assert_eq!(
        reply.json()["usage"],
        json!([{"tokens":2},{"tokens":2},{"tokens":1}])
    );
    assert_eq!(peer.hits() - before, 3);
    let hit = send(&server, &[], body).await;
    assert_eq!(hit.headers["x-graphit-cache"], "HIT");
    assert!(hit.json().get("usage").is_none());
    f.db()
        .execute("UPDATE embedding_cache SET embedding_json='corrupt'", [])
        .unwrap();
    error(&send(&server, &[], body).await, 502, "upstream_failed");
    assert_eq!(peer.hits() - before, 3);
    server.close().await;
    backend.stop();
    peer.close().await;
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn google_configured_dimensions_family_and_batch_route_change_namespace() {
    let f = Fixture::new().await;
    let issuer = ingress::fixture::Fixture::new().await;
    grants(&f, "global", "");
    let peer = Peer::new("google", false).await;
    for variant in 0..4 {
        let mut remote = peer.configuration("google", HeaderMap::new());
        if variant == 1 {
            remote.request_dimensions = Some(2);
        }
        if variant == 2 {
            remote.google_family = Some(GoogleFamily::Gemini1);
        }
        if variant == 3 {
            remote.batch_endpoint = Some(format!(
                "{}/other/models/fixture:batchEmbedContents",
                peer.origin
            ));
        }
        let backend = Arc::new(EmbeddingBackend::remote(remote).unwrap());
        let server = Server::router(
            sqlite_embeddings_router(
                f.store.clone(),
                issuer.verifier(),
                None,
                config(),
                backend.clone(),
            )
            .unwrap(),
        )
        .await;
        let reply = send(&server, &[], r#"{"input":["google","batch"]}"#).await;
        assert_eq!(reply.status.as_u16(), 200);
        assert_eq!(reply.headers["x-graphit-cache"], "MISS");
        {
            let observed = peer.state.seen.lock().unwrap();
            let body = &observed.last().unwrap().1;
            assert_eq!(
                body["requests"][0]["embedContentConfig"]
                    .get("outputDimensionality")
                    .and_then(Value::as_u64),
                if variant == 1 { Some(2) } else { None }
            );
            assert!(observed.last().unwrap().0.get("x-goog-api-key").is_none());
        }
        server.close().await;
        backend.stop();
    }
    assert_eq!(peer.hits(), 4);
    peer.close().await;
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_opaque_proof_expiry_during_later_batch_cannot_publish_earlier_vectors() {
    let f = Fixture::new().await;
    let issuer = ingress::fixture::Fixture::new().await;
    grants(&f, "authenticated", "");
    let peer = Peer::new("openai", false).await;
    peer.state.delay_after.store(2, Ordering::SeqCst);
    peer.state.delay_ms.store(1500, Ordering::SeqCst);
    let backend = peer.backend("openai", HeaderMap::new());
    let server = Server::router(
        sqlite_embeddings_router(
            f.store.clone(),
            issuer.verifier(),
            None,
            config(),
            backend.clone(),
        )
        .unwrap(),
    )
    .await;
    f.db()
        .execute(
            "UPDATE local_tokens SET expires_at=?1 WHERE token_id='alice'",
            [opaque::now() + 1_000_000],
        )
        .unwrap();
    let auth = format!("Bearer {}", f.access);
    let started = Instant::now();
    let reply = send(
        &server,
        &[("authorization", &auth)],
        r#"{"input":["a","b","c"]}"#,
    )
    .await;
    error(&reply, 401, "unauthorized");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(peer.hits(), 2);
    assert_eq!(
        f.db()
            .query_row("SELECT count(*) FROM embedding_cache", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    peer.state.delay_ms.store(0, Ordering::SeqCst);
    f.db()
        .execute(
            "UPDATE local_tokens SET expires_at=?1 WHERE token_id='alice'",
            [opaque::now() + 60_000_000],
        )
        .unwrap();
    let reply = send(&server, &[("authorization", &auth)], r#"{"input":"a"}"#).await;
    assert_eq!(reply.status.as_u16(), 200);
    assert_eq!(reply.headers["x-graphit-cache"], "MISS");
    assert_eq!(peer.hits(), 3);
    server.close().await;
    backend.stop();
    peer.close().await;
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_families_cache_only_valid_complete_items_and_retry_only_unique_misses() {
    for (family, protocol) in [
        ("openai", "openai-compatible"),
        ("cohere", "cohere"),
        ("voyage", "voyage"),
        ("google", "google"),
    ] {
        let f = Fixture::new().await;
        let issuer = ingress::fixture::Fixture::new().await;
        grants(&f, "global", "");
        let peer = Peer::new(family, true).await;
        let mut headers = HeaderMap::new();
        let mut value = HeaderValue::from_static("Custom fixture-secret");
        value.set_sensitive(true);
        headers.insert("x-fixture-auth", value);
        let backend = peer.backend(protocol, headers);
        let router = sqlite_embeddings_router(
            f.store.clone(),
            issuer.verifier(),
            None,
            config(),
            backend.clone(),
        )
        .unwrap();
        let server = Server::router(router).await;
        let body = r#"{"input":["a","b","a","c"],"input_type":" QUERY "}"#;
        error(&send(&server, &[], body).await, 502, "upstream_failed");
        assert_eq!(peer.hits(), 1, "family={family}");
        assert_eq!(
            f.db()
                .query_row("SELECT count(*) FROM embedding_cache", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let reply = send(&server, &[], body).await;
        assert_eq!(reply.status.as_u16(), 200, "{}", reply.json());
        assert_eq!(reply.headers["x-graphit-cache"], "MISS");
        assert_eq!(reply.headers["x-graphit-embedding-revision"], "fixture-v1");
        assert_eq!(reply.headers["x-graphit-embedding-dimensions"], "2");
        let json = reply.json();
        assert_eq!(json["object"], "list");
        assert_eq!(
            json["graphit"],
            json!({"revision":"fixture-v1","model":"fixture-model","model_revision":"fixture-model-r1","recipe":"retrieval-v1","dimensions":2})
        );
        assert_eq!(json["data"].as_array().unwrap().len(), 4);
        assert!(json.get("model").is_none());
        assert!(json.get("usage").is_some());
        for (index, row) in json["data"].as_array().unwrap().iter().enumerate() {
            assert_eq!(row["index"], index);
            assert_eq!(row["embedding"], json!([0.25, 0.75]));
        }
        assert_eq!(peer.hits(), 2);
        let hit = send(&server, &[], body).await;
        assert_eq!(hit.status.as_u16(), 200);
        assert_eq!(hit.headers["x-graphit-cache"], "HIT");
        assert!(hit.json().get("usage").is_none());
        assert_eq!(peer.hits(), 2);
        {
            let seen = peer.state.seen.lock().unwrap();
            for (headers, body) in seen.iter() {
                assert_eq!(headers["x-fixture-auth"], "Custom fixture-secret");
                assert!(headers.get("authorization").is_none());
                if protocol == "openai-compatible" {
                    assert_eq!(body["dimensions"], 2);
                }
            }
            let second = &seen[1].1;
            if family == "google" {
                assert_eq!(second["requests"].as_array().unwrap().len(), 2);
            } else {
                assert_eq!(
                    second[if family == "cohere" { "texts" } else { "input" }],
                    json!(["b", "c"])
                );
            }
        }
        server.close().await;
        backend.stop();
        peer.close().await;
        f.store.shutdown(end()).await.unwrap();
        issuer.store.shutdown(end()).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn genuine_ingresses_reauthorize_hits_and_reject_invalid_credentials_before_decode() {
    let f = Fixture::new().await;
    let issuer = ingress::fixture::Fixture::new().await;
    let jwt = ingress::jwt(&issuer).await;
    let mut external = ingress::upstream::UpstreamFixture::new().await;
    let trust = ingress::trust(vec![ingress::config(
        &external.issuer,
        &external.ca,
        false,
        None,
    )]);
    let upstream = external.sign(&external.claims(), "upstream-key", "at+jwt");
    let peer = Peer::new("openai", false).await;
    let backend = peer.backend("openai", HeaderMap::new());
    let server = Server::router(
        sqlite_embeddings_router(
            f.store.clone(),
            issuer.verifier(),
            Some(trust),
            config(),
            backend.clone(),
        )
        .unwrap(),
    )
    .await;
    grants(&f, "global", "");
    let first = send(&server, &[], r#"{"input":"cache-me"}"#).await;
    assert_eq!(first.status.as_u16(), 200, "{}", first.json());
    let human = format!("Bearer {}", f.access);
    let service = format!("Bearer {}", f.service);
    let native = format!("Bearer {}", jwt.as_str());
    let federated = format!("Bearer {}", upstream.as_str());
    for raw in [&human, &service, &native, &federated] {
        grants(&f, "authenticated", "");
        let reply = send(
            &server,
            &[("authorization", raw)],
            r#"{"input":"cache-me"}"#,
        )
        .await;
        assert_eq!(reply.status.as_u16(), 200, "{}", reply.json());
        assert_eq!(reply.headers["x-graphit-cache"], "HIT");
    }
    for (kind, principal) in [
        ("user", " alice "),
        ("organization", "org"),
        ("team", "z"),
        ("subject", "local|alice-subject"),
        ("subject", "alice-subject"),
    ] {
        grants(&f, kind, principal);
        assert_eq!(
            send(
                &server,
                &[("authorization", &human)],
                r#"{"input":"cache-me"}"#
            )
            .await
            .status
            .as_u16(),
            200
        );
    }
    grants(&f, "user", "ali*");
    error(
        &send(&server, &[("authorization", &human)], "malformed").await,
        403,
        "forbidden",
    );
    grants(&f, "anonymous", "");
    for headers in [
        vec![("authorization", "Bearer invalid")],
        vec![("authorization", "Basic invalid")],
        vec![
            ("authorization", human.as_str()),
            ("authorization", human.as_str()),
        ],
    ] {
        let reply = send(&server, &headers, "malformed").await;
        error(&reply, 401, "unauthorized");
        assert_eq!(reply.headers["www-authenticate"], "Bearer");
    }
    error(
        &send(&server, &[("authorization", &human)], "malformed").await,
        403,
        "forbidden",
    );
    assert_eq!(peer.hits(), 1);
    grants(&f, "global", "");
    f.db()
        .execute("DELETE FROM local_tokens WHERE token_id='alice'", [])
        .unwrap();
    error(
        &send(
            &server,
            &[("authorization", &human)],
            r#"{"input":"cache-me"}"#,
        )
        .await,
        401,
        "unauthorized",
    );
    assert_eq!(peer.hits(), 1);
    server.close().await;
    backend.stop();
    peer.close().await;
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(end()).await.unwrap();
    external.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_input_and_closed_disabled_errors_do_not_infer() {
    let f = Fixture::new().await;
    let issuer = ingress::fixture::Fixture::new().await;
    grants(&f, "global", "");
    let peer = Peer::new("openai", false).await;
    let backend = peer.backend("openai", HeaderMap::new());
    let server = Server::router(
        sqlite_embeddings_router(
            f.store.clone(),
            issuer.verifier(),
            None,
            config(),
            backend.clone(),
        )
        .unwrap(),
    )
    .await;
    for body in [
        "{}",
        r#"{"input":null}"#,
        r#"{"input":[]}"#,
        r#"{"input":7}"#,
        r#"{"input":["a",7]}"#,
        r#"{"input":" \t"}"#,
        r#"{"input":"a","input_type":3}"#,
        r#"{"input":"a","input_type":"invalid"}"#,
        r#"{"input":["1","2","3","4","5","6","7","8","9"]}"#,
    ] {
        error(&send(&server, &[], body).await, 400, "invalid_request");
    }
    for body in [
        "malformed",
        r#"{"input":"a","model":"x"}"#,
        r#"{"input":"a","route":"x"}"#,
        r#"{"input":"a","input":"b"}"#,
        r#"{"input":null,"input":null}"#,
        r#"{"input":"a","input_type":null,"input_type":null}"#,
        r#"{"input":"a"} {}"#,
    ] {
        error(&send(&server, &[], body).await, 400, "invalid_json");
    }
    error(
        &send(&server, &[], &json!({"input":"x".repeat(65)}).to_string()).await,
        413,
        "request_too_large",
    );
    assert_eq!(peer.hits(), 0);
    backend.stop();
    error(
        &send(&server, &[], r#"{"input":"a"}"#).await,
        502,
        "upstream_failed",
    );
    assert_eq!(peer.hits(), 0);
    server.close().await;
    peer.close().await;
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(end()).await.unwrap();
    let disabled = Server::router(disabled_embeddings_router()).await;
    error(
        &send(&disabled, &[], "malformed").await,
        404,
        "capability_disabled",
    );
    disabled.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_jwt_expiry_cuts_off_locked_acl_and_keeps_earliest_cause() {
    let f = Fixture::new().await;
    let mut issuer = ingress::fixture::Fixture::new().await;
    // Preserve the productive exchange's genuine minimum TTL; use its real cutoff.
    issuer.policy = Arc::new(
        broker_control::OidcTokenExchangePolicy::new(
            Duration::from_secs(60),
            Duration::from_secs(86400),
        )
        .unwrap(),
    );
    let jwt = ingress::jwt(&issuer).await;
    let original = Instant::now() + Duration::from_secs(62);
    let native = issuer.verifier();
    let peer = Peer::new("openai", false).await;
    let backend = peer.backend("openai", HeaderMap::new());
    let mut http = config();
    http.request_timeout = Duration::from_secs(3);
    let server = Server::router(
        sqlite_embeddings_router(f.store.clone(), native.clone(), None, http, backend.clone())
            .unwrap(),
    )
    .await;
    grants(&f, "authenticated", "");
    let bearer = format!("Bearer {}", jwt.as_str());
    let headers = [("Authorization", bearer.as_str())];
    let body = r#"{"input":"acl-lock"}"#;
    assert_eq!(send(&server, &headers, body).await.status.as_u16(), 200);
    assert_eq!(peer.hits(), 1);
    {
        let prepared = config();
        let admissions = f
            .store
            .embedding_admissions(
                native.as_ref(),
                None,
                &prepared.local_audience,
                &prepared.required_scopes,
                prepared.admission_limits,
            )
            .unwrap();
        let mut retained = admissions.authorize(Some(&jwt), original).await.unwrap();
        let expiry = retained.deadline();
        assert!(expiry < original);
        tokio::time::sleep_until((expiry - Duration::from_secs(1)).into()).await;
        retained.check().unwrap();
        let mut db = f.db();
        let writer = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let started = Instant::now();
        let reply = send(&server, &headers, body).await;
        assert_eq!(reply.status.as_u16(), 401);
        assert_eq!(reply.json()["error"]["code"], "unauthorized");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "proof cutoff must precede the request Original"
        );
        assert_eq!(
            peer.hits(),
            1,
            "a hit still requires the physically blocked current ACL"
        );
        writer.rollback().unwrap();
        tokio::time::sleep_until((original + Duration::from_millis(10)).into()).await;
        assert!(
            matches!(
                retained.check(),
                Err(broker_control::EmbeddingAdmissionError::Authentication(
                    broker_control::BrokerAccessError::Expired
                ))
            ),
            "proof expiry remains the earliest cause after both real cutoffs"
        );
    }
    server.close().await;
    backend.stop();
    peer.close().await;
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(end()).await.unwrap();
}
