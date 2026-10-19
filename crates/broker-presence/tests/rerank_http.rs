#[path = "../../broker-control/tests/support/sqlite_admin_ingress_fixture.rs"]
#[allow(dead_code, unused_imports, reason = "shared genuine issuer fixture")]
mod ingress;
#[path = "../../broker-control/tests/support/sqlite_admin_fixture.rs"]
#[allow(dead_code, reason = "shared persisted identity fixture")]
mod opaque;
#[path = "support/sqlite_oidc_fixture.rs"]
#[allow(dead_code, unused_imports, reason = "established native TCP transport")]
mod transport;
use axum::{Json, Router, extract::State, routing::post};
use broker_control::RerankAdmissionLimits;
use broker_presence::{
    RerankBackend, RerankHttpConfig, disabled_rerank_router, sqlite_rerank_router,
};
use graphit_ai::{native_rerank::NativeRerankLimits, ranking::RankingLimits};
use graphit_auth::broker::{BrokerModelIdentity, BrokerRerankService};
use graphit_http::client::{BoundedClient, ClientPolicy, Limits};
use opaque::{Fixture, end, n};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use transport::{Reply, Server};
const BODY: &str = r#"{"query":"q","documents":["a","b"]}"#;
fn config() -> RerankHttpConfig {
    RerankHttpConfig {
        revision: "rerank-v1".into(),
        model: "fixture-model".into(),
        model_revision: "fixture-model-r1".into(),
        recipe: "retrieval-v1".into(),
        max_documents: n(3),
        max_document_bytes: n(8),
        request_body_bytes: n(512),
        response_body_bytes: n(4096),
        request_timeout: Duration::from_secs(3),
        local_audience: "admin-api".into(),
        required_scopes: vec![],
        admission_limits: RerankAdmissionLimits {
            identity_json_bytes: n(8192),
            grants_json_bytes: n(16384),
        },
        cache_ttl: Duration::from_secs(60),
        cache_entries: 2,
    }
}
fn grants(f: &Fixture, capability: &str, kind: &str) {
    let db = f.db();
    db.execute_batch("DELETE FROM grant_capabilities;DELETE FROM grant_projects;DELETE FROM grant_s3_operations;DELETE FROM grant_s3_prefixes;DELETE FROM resource_grants;").unwrap();
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at)VALUES('rerank','fixture',?1,'','',0,0)",[kind]).unwrap();
    db.execute(
        "INSERT INTO grant_capabilities(grant_id,value)VALUES('rerank',?1)",
        [capability],
    )
    .unwrap();
    db.execute("INSERT INTO resource_acl_state(id,revision,updated_at)VALUES(1,1,0) ON CONFLICT(id) DO UPDATE SET revision=revision+1",[]).unwrap();
}
struct PeerState {
    hits: AtomicUsize,
    hold: AtomicBool,
    malformed: AtomicBool,
    entered: Notify,
    release: Notify,
}
struct Peer {
    origin: String,
    state: Arc<PeerState>,
    stop: tokio::sync::oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}
async fn upstream(State(s): State<Arc<PeerState>>, Json(body): Json<Value>) -> Json<Value> {
    assert!(body.get("model").is_none());
    s.hits.fetch_add(1, Ordering::SeqCst);
    if s.hold.load(Ordering::SeqCst) {
        s.entered.notify_one();
        s.release.notified().await;
    }
    if s.malformed.swap(false, Ordering::SeqCst) {
        return Json(
            json!({"graphit":{"revision":"upstream-service-v7","model":"fixture-model","model_revision":"fixture-model-r1","recipe":"retrieval-v1"},"results":[{"index":0,"relevance_score":1.0},{"index":0,"relevance_score":0.2}]}),
        );
    }
    let count = body["documents"].as_array().unwrap().len();
    Json(
        json!({"graphit":{"revision":"upstream-service-v7","model":"fixture-model","model_revision":"fixture-model-r1","recipe":"retrieval-v1"},"results":(0..count).map(|index|json!({"index":index,"relevance_score":1.0-index as f64*0.1})).collect::<Vec<_>>()}),
    )
}
impl Peer {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(PeerState {
            hits: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            malformed: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let router = Router::new()
            .route("/rerank", post(upstream))
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
    fn backend(&self) -> Arc<RerankBackend> {
        let client = BoundedClient::new(
            ClientPolicy {
                origin: &self.origin,
                allow_loopback_http: true,
                proxy: None,
                additional_roots: &[],
            },
            Limits {
                request_body_bytes: 4096,
                response_body_bytes: 4096,
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
        Arc::new(
            RerankBackend::graphit(
                client,
                BrokerRerankService {
                    endpoint: format!("{}/rerank", self.origin),
                    identity: BrokerModelIdentity {
                        model: "fixture-model".into(),
                        model_revision: "fixture-model-r1".into(),
                        recipe: "retrieval-v1".into(),
                        service_revision: "upstream-service-v7".into(),
                    },
                    max_documents: 3,
                },
                axum::http::HeaderMap::new(),
                NativeRerankLimits::new(3, 3, 512, 4096, 4096).unwrap(),
                RankingLimits::new(3, 2, 8).unwrap(),
            )
            .unwrap(),
        )
    }
    fn hits(&self) -> usize {
        self.state.hits.load(Ordering::SeqCst)
    }
    async fn close(self) {
        self.stop.send(()).unwrap();
        self.join.await.unwrap();
    }
}
async fn send(s: &Server, auth: Option<&str>, body: &str) -> Reply {
    let headers = auth.map(|a| vec![("authorization", a)]).unwrap_or_default();
    s.send_headers("POST", "/v1/rerank", body.as_bytes(), &headers)
        .await
}
fn error(r: &Reply, status: u16, code: &str) {
    assert_eq!(r.status.as_u16(), status, "{}", r.json());
    assert_eq!(r.json()["error"]["code"], code);
    assert!(r.json().get("results").is_none());
    let text = String::from_utf8_lossy(&r.body);
    for private in ["gb_at_", "gb_sc_", "SELECT", "broker.db"] {
        assert!(!text.contains(private));
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_sql_private_cache_and_strict_http_boundaries() {
    let f = Fixture::new().await;
    let issuer = ingress::fixture::Fixture::new().await;
    let p = Peer::new().await;
    let backend = p.backend();
    let s = Server::router(
        sqlite_rerank_router(
            f.store.clone(),
            issuer.verifier(),
            None,
            config(),
            backend.clone(),
        )
        .unwrap(),
    )
    .await;
    grants(&f, "embeddings", "global");
    error(&send(&s, None, BODY).await, 403, "forbidden");
    assert_eq!(p.hits(), 0);
    grants(&f, "rerank", "authenticated");
    error(&send(&s, None, BODY).await, 403, "forbidden");
    error(
        &send(&s, Some("Basic invalid"), BODY).await,
        401,
        "unauthorized",
    );
    let human = format!("Bearer {}", f.access);
    let service = format!("Bearer {}", f.service);
    let first = send(&s, Some(&human), BODY).await;
    assert_eq!(first.status.as_u16(), 200, "{}", first.json());
    assert_eq!(first.headers["x-graphit-cache"], "MISS");
    assert_eq!(first.headers["x-graphit-rerank-revision"], "rerank-v1");
    assert_eq!(
        first.json()["graphit"],
        json!({"revision":"rerank-v1","model":"fixture-model","model_revision":"fixture-model-r1","recipe":"retrieval-v1"})
    );
    assert_eq!(first.json()["results"].as_array().unwrap().len(), 2);
    assert_eq!(
        send(&s, Some(&human), BODY).await.headers["x-graphit-cache"],
        "HIT"
    );
    assert_eq!(p.hits(), 1);
    assert_eq!(
        send(&s, Some(&service), BODY).await.headers["x-graphit-cache"],
        "MISS"
    );
    assert_eq!(p.hits(), 2);
    grants(&f, "embeddings", "authenticated");
    error(&send(&s, Some(&human), BODY).await, 403, "forbidden");
    assert_eq!(p.hits(), 2);
    grants(&f, "rerank", "authenticated");
    for (body, code) in [
        (
            r#"{"query":"q","documents":["a"],"model":"x"}"#,
            "invalid_json",
        ),
        (
            r#"{"query":"q","query":"x","documents":["a"]}"#,
            "invalid_json",
        ),
        (r#"{"query":1,"documents":["a"]}"#, "invalid_json"),
        (r#"{"query":" ","documents":["a"]}"#, "invalid_request"),
        (r#"{"query":"q","documents":[]}"#, "invalid_request"),
        (r#"{"query":"q","documents":[null]}"#, "invalid_request"),
        (
            r#"{"query":"q","documents":["123456789"]}"#,
            "invalid_request",
        ),
        (
            r#"{"query":"q","documents":["a","b","c","d"]}"#,
            "invalid_request",
        ),
        (
            r#"{"query":"q","documents":["a"],"top_n":-1}"#,
            "invalid_request",
        ),
        (
            r#"{"query":"q","documents":["a"],"top_n":2}"#,
            "invalid_request",
        ),
        (
            r#"{"query":"q","documents":["a"],"top_n":0.5}"#,
            "invalid_json",
        ),
        (r#"{"query":"q","documents":["a"]}{}"#, "invalid_json"),
    ] {
        error(&send(&s, Some(&human), body).await, 400, code);
    }
    error(
        &send(&s, Some(&human), &"x".repeat(513)).await,
        413,
        "request_too_large",
    );
    f.db()
        .execute_batch("DROP TABLE grant_capabilities")
        .unwrap();
    error(
        &send(&s, Some(&human), BODY).await,
        503,
        "authorization_unavailable",
    );
    assert_eq!(p.hits(), 2);
    s.close().await;
    backend.stop();
    p.close().await;
    let disabled = Server::router(disabled_rerank_router()).await;
    error(
        &send(&disabled, None, BODY).await,
        404,
        "capability_disabled",
    );
    disabled.close().await;
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_remote_revocation_prevents_result_and_cache() {
    let f = Fixture::new().await;
    let issuer = ingress::fixture::Fixture::new().await;
    grants(&f, "rerank", "authenticated");
    let p = Peer::new().await;
    let backend = p.backend();
    let server = Arc::new(
        Server::router(
            sqlite_rerank_router(
                f.store.clone(),
                issuer.verifier(),
                None,
                config(),
                backend.clone(),
            )
            .unwrap(),
        )
        .await,
    );
    let auth = format!("Bearer {}", f.access);
    for identity in [false, true] {
        let body = if identity {
            r#"{"query":"r","documents":["a","b"]}"#
        } else {
            BODY
        };
        p.state.hold.store(true, Ordering::SeqCst);
        let s = server.clone();
        let a = auth.clone();
        let before = p.hits();
        let request = tokio::spawn(async move { send(&s, Some(&a), body).await });
        tokio::time::timeout(Duration::from_secs(2), p.state.entered.notified())
            .await
            .unwrap();
        assert!(!request.is_finished());
        if identity {
            f.db()
                .execute(
                    "UPDATE local_users SET enabled=0 WHERE username='alice'",
                    [],
                )
                .unwrap();
        } else {
            grants(&f, "embeddings", "authenticated");
        }
        p.state.release.notify_one();
        let reply = request.await.unwrap();
        error(
            &reply,
            if identity { 401 } else { 403 },
            if identity {
                "unauthorized"
            } else {
                "forbidden"
            },
        );
        p.state.hold.store(false, Ordering::SeqCst);
        if identity {
            f.db()
                .execute(
                    "UPDATE local_users SET enabled=1 WHERE username='alice'",
                    [],
                )
                .unwrap();
        } else {
            grants(&f, "rerank", "authenticated");
        }
        let recovered = send(&server, Some(&auth), body).await;
        assert_eq!(recovered.status.as_u16(), 200, "{}", recovered.json());
        assert_eq!(recovered.headers["x-graphit-cache"], "MISS");
        assert_eq!(p.hits(), before + 2);
    }
    Arc::try_unwrap(server).ok().unwrap().close().await;
    backend.stop();
    p.close().await;
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_upstream_is_not_cached_and_top_n_null_zero_are_preserved() {
    let f = Fixture::new().await;
    let issuer = ingress::fixture::Fixture::new().await;
    grants(&f, "rerank", "global");
    let p = Peer::new().await;
    let backend = p.backend();
    let mut cfg = config();
    cfg.cache_ttl = Duration::from_millis(20);
    let s = Server::router(
        sqlite_rerank_router(
            f.store.clone(),
            issuer.verifier(),
            None,
            cfg,
            backend.clone(),
        )
        .unwrap(),
    )
    .await;
    p.state.malformed.store(true, Ordering::SeqCst);
    error(&send(&s, None, BODY).await, 502, "upstream_failed");
    assert_eq!(
        send(&s, None, BODY).await.headers["x-graphit-cache"],
        "MISS"
    );
    assert_eq!(p.hits(), 2);
    assert_eq!(send(&s, None, BODY).await.headers["x-graphit-cache"], "HIT");
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        send(&s, None, BODY).await.headers["x-graphit-cache"],
        "MISS"
    );
    assert_eq!(p.hits(), 3);
    for top in ["null", "0", "1"] {
        let body = format!(r#"{{"query":"q","documents":["a","b"],"top_n":{top}}}"#);
        let reply = send(&s, None, &body).await;
        assert_eq!(reply.status.as_u16(), 200, "{}", reply.json());
        assert_eq!(
            reply.json()["results"].as_array().unwrap().len(),
            if top == "1" { 1 } else { 2 }
        );
    }
    s.close().await;
    backend.stop();
    p.close().await;
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initial_authentication_expiry_http_drop_and_backend_stop_do_not_publish_cache() {
    let f = Fixture::new().await;
    let issuer = ingress::fixture::Fixture::new().await;
    grants(&f, "rerank", "authenticated");
    let p = Peer::new().await;
    let backend = p.backend();
    let router = sqlite_rerank_router(
        f.store.clone(),
        issuer.verifier(),
        None,
        config(),
        backend.clone(),
    )
    .unwrap();
    let service = hyper_util::service::TowerToHyperService::new(router.clone());
    let server = Arc::new(Server::router(router).await);
    let auth = format!("Bearer {}", f.access);
    f.db()
        .execute(
            "UPDATE local_tokens SET expires_at=?1 WHERE token_id='alice'",
            [opaque::now() + 300_000],
        )
        .unwrap();
    p.state.hold.store(true, Ordering::SeqCst);
    let s = server.clone();
    let a = auth.clone();
    let pending = tokio::spawn(async move { send(&s, Some(&a), BODY).await });
    tokio::time::timeout(Duration::from_secs(2), p.state.entered.notified())
        .await
        .unwrap();
    let expired = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    error(&expired, 401, "unauthorized");
    p.state.hold.store(false, Ordering::SeqCst);
    p.state.release.notify_one();
    f.db()
        .execute(
            "UPDATE local_tokens SET expires_at=?1 WHERE token_id='alice'",
            [opaque::now() + 60_000_000],
        )
        .unwrap();
    let reply = send(&server, Some(&auth), BODY).await;
    assert_eq!(reply.status.as_u16(), 200, "{}", reply.json());
    assert_eq!(reply.headers["x-graphit-cache"], "MISS");
    assert_eq!(p.hits(), 2);
    let dropped_body = r#"{"query":"drop","documents":["a","b"]}"#;
    p.state.hold.store(true, Ordering::SeqCst);
    {
        let request = hyper::Request::builder()
            .method("POST")
            .uri("/v1/rerank")
            .header("authorization", &auth)
            .body(axum::body::Body::from(dropped_body))
            .unwrap();
        let future = hyper::service::Service::call(&service, request);
        tokio::pin!(future);
        tokio::select! {biased;_=p.state.entered.notified()=>{},r=&mut future=>panic!("completed before held peer: {:?}",r.map(|v|v.status()))}
        // The actual HTTP service future is dropped here; its request cancellation guard runs.
    }
    p.state.hold.store(false, Ordering::SeqCst);
    p.state.release.notify_one();
    let reply = send(&server, Some(&auth), dropped_body).await;
    assert_eq!(reply.status.as_u16(), 200, "{}", reply.json());
    assert_eq!(reply.headers["x-graphit-cache"], "MISS");
    assert_eq!(p.hits(), 4);
    p.state.hold.store(true, Ordering::SeqCst);
    let s = server.clone();
    let a = auth.clone();
    let pending =
        tokio::spawn(
            async move { send(&s, Some(&a), r#"{"query":"stop","documents":["a"]}"#).await },
        );
    tokio::time::timeout(Duration::from_secs(2), p.state.entered.notified())
        .await
        .unwrap();
    backend.stop();
    error(&pending.await.unwrap(), 502, "upstream_failed");
    p.state.release.notify_one();
    assert_eq!(p.hits(), 5);
    drop(service);
    Arc::try_unwrap(server).ok().unwrap().close().await;
    p.close().await;
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(end()).await.unwrap();
}
