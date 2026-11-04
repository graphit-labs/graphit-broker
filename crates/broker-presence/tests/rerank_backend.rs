use axum::http::HeaderMap;
use broker_presence::{
    RemoteEmbeddingsConfig, RemoteRerankConfig, RerankBackend, RerankBackendError,
};
use graphit_ai::{
    context::{ContextError, InferenceContext},
    embedding::{EmbeddingError, EmbeddingLimits},
    google_embedding::GoogleFamily,
    native_rerank::NativeRerankLimits,
    ranking::RankingLimits,
};
use graphit_auth::broker::{BrokerModelIdentity, BrokerRerankService};
use graphit_core::file_lock::Cancellation;
use graphit_http::client::{BoundedClient, ClientPolicy, Limits, NetworkEffect};
use serde_json::json;
use std::{
    convert::Infallible,
    sync::Arc,
    time::{Duration, Instant},
};
#[path = "support/model_http.rs"]
mod wire;
use wire::{fixture, reply};

fn client(origin: &str) -> BoundedClient {
    BoundedClient::new(
        ClientPolicy {
            origin,
            allow_loopback_http: true,
            proxy: None,
            additional_roots: &[],
        },
        Limits {
            request_body_bytes: 10000,
            response_body_bytes: 10000,
            url_bytes: 2048,
            header_bytes: 4096,
            header_count: 32,
            max_in_flight: 1,
            max_idle_per_host: 1,
            idle_timeout: Duration::from_secs(1),
            max_certificates: 1,
            max_certificate_bytes: 4096,
        },
    )
    .unwrap()
}
fn ranking() -> RankingLimits {
    RankingLimits::new(100, 2, 202).unwrap()
}
fn descriptor(origin: &str) -> BrokerRerankService {
    BrokerRerankService {
        endpoint: origin.into(),
        identity: BrokerModelIdentity {
            model: "fixture-model".into(),
            model_revision: "fixture-r1".into(),
            recipe: "native-rerank-v1".into(),
            service_revision: "upstream-service-v7".into(),
        },
        max_documents: 2,
    }
}
fn native(origin: &str, protocol: &str) -> RerankBackend {
    if protocol == "graphit-rerank-v1" {
        return RerankBackend::graphit(
            client(origin),
            descriptor(origin),
            HeaderMap::new(),
            NativeRerankLimits::new(100, 2, 10000, 10000, 10000).unwrap(),
            ranking(),
        )
        .unwrap();
    }
    RerankBackend::remote(
        RemoteRerankConfig {
            client: client(origin),
            protocol: protocol.into(),
            endpoint: origin.into(),
            model: "fixture-model".into(),
            headers: HeaderMap::new(),
            limits: NativeRerankLimits::new(100, 2, 10000, 10000, 10000).unwrap(),
        },
        ranking(),
    )
    .unwrap()
}
fn embedding(origin: &str, protocol: &str) -> RerankBackend {
    let google = matches!(protocol, "google" | "gemini");
    RerankBackend::embedding(
        RemoteEmbeddingsConfig {
            client: client(origin),
            protocol: protocol.into(),
            endpoint: if google {
                format!("{origin}/v1beta/models/fixture-model:embedContent")
            } else {
                origin.into()
            },
            batch_endpoint: google
                .then(|| format!("{origin}/v1beta/models/fixture-model:batchEmbedContents")),
            model: if google {
                "models/fixture-model".into()
            } else {
                "fixture-model".into()
            },
            dimensions: 2,
            request_dimensions: None,
            google_family: google.then_some(GoogleFamily::Gemini2),
            headers: HeaderMap::new(),
            limits: EmbeddingLimits::new(100, 10000, 2, 202, 2, 10000, 10000).unwrap(),
        },
        ranking(),
    )
    .unwrap()
}
fn context(cancel: &Cancellation) -> InferenceContext<'_> {
    InferenceContext::new(cancel, Instant::now() + Duration::from_secs(5))
}
fn docs() -> Vec<String> {
    vec!["a".into(), "b".into(), "c".into()]
}

#[tokio::test]
async fn remote_families_remap_batches_then_rank_global_top_n_and_ties() {
    for protocol in [
        "cohere",
        "cohere-v2",
        "voyage",
        "voyage-v1",
        "jina",
        "jina-v1",
        "graphit-rerank-v1",
    ] {
        let envelope = if protocol.starts_with("voyage") {
            "data"
        } else {
            "results"
        };
        let mut first =
            json!({envelope:[{"index":1,"relevance_score":0.4},{"index":0,"relevance_score":0.4}]});
        let mut second = json!({envelope:[{"index":0,"relevance_score":0.9}]});
        if protocol == "graphit-rerank-v1" {
            for response in [&mut first, &mut second] {
                response["graphit"] = json!({"revision":"upstream-service-v7","model":"fixture-model","model_revision":"fixture-r1","recipe":"native-rerank-v1"});
            }
        }
        let tcp = fixture(vec![reply(first), reply(second)]).await;
        let backend = native(&tcp.origin, protocol);
        let cancel = Cancellation::default();
        let result = backend
            .infer_guarded("query".into(), docs(), 2, context(&cancel), &mut || {
                Ok::<(), Infallible>(())
            })
            .await
            .unwrap();
        assert_eq!(result.iter().map(|r| r.index).collect::<Vec<_>>(), [2, 0]);
        assert_eq!(
            result.iter().map(|r| r.relevance_score).collect::<Vec<_>>(),
            [0.9, 0.4]
        );
        assert_eq!(backend.protocol(), protocol);
        assert_eq!(backend.effective_identity().len(), 64);
        assert!(backend.local_identity().is_none());
        let requests = tcp.server.await.unwrap();
        assert_eq!(requests.len(), 2);
        if protocol == "graphit-rerank-v1" {
            assert!(
                requests
                    .iter()
                    .all(|request| request.body.get("model").is_none())
            );
        }
        assert!(
            requests
                .iter()
                .all(|request| !request.head.to_ascii_lowercase().contains("authorization:"))
        );
    }
}

#[tokio::test]
async fn graphit_upstream_identity_must_match_each_pinned_field() {
    for field in ["revision", "model", "model_revision", "recipe"] {
        let mut body = json!({"graphit":{"revision":"upstream-service-v7","model":"fixture-model","model_revision":"fixture-r1","recipe":"native-rerank-v1"},"results":[{"index":0,"relevance_score":0.8}]});
        body["graphit"][field] = json!("different-upstream");
        let tcp = fixture(vec![reply(body)]).await;
        let backend = native(&tcp.origin, "graphit-rerank-v1");
        let cancel = Cancellation::default();
        let result = backend
            .infer_guarded(
                "query".into(),
                vec!["a".into()],
                1,
                context(&cancel),
                &mut || Ok::<(), Infallible>(()),
            )
            .await;
        assert!(
            matches!(
                result,
                Err(RerankBackendError::Native {
                    effect: NetworkEffect::MayHaveApplied,
                    ..
                })
            ),
            "{field}"
        );
        assert_eq!(tcp.server.await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn graphit_upstream_batch_limit_and_descriptor_identity_are_preserved() {
    let body = json!({"graphit":{"revision":"upstream-service-v7","model":"fixture-model","model_revision":"fixture-r1","recipe":"native-rerank-v1"},"results":[{"index":0,"relevance_score":0.8}]});
    let tcp = fixture(vec![reply(body.clone()), reply(body)]).await;
    let mut service = descriptor(&tcp.origin);
    service.max_documents = 1;
    let backend = RerankBackend::graphit(
        client(&tcp.origin),
        service.clone(),
        HeaderMap::new(),
        NativeRerankLimits::new(100, 2, 10000, 10000, 10000).unwrap(),
        ranking(),
    )
    .unwrap();
    let original_identity = backend.effective_identity().to_owned();
    for variant in 0..5 {
        let mut changed = service.clone();
        match variant {
            0 => changed.identity.model.push_str("-changed"),
            1 => changed.identity.model_revision.push_str("-changed"),
            2 => changed.identity.recipe.push_str("-changed"),
            3 => changed.identity.service_revision.push_str("-changed"),
            _ => changed.max_documents = 2,
        }
        let changed = RerankBackend::graphit(
            client(&tcp.origin),
            changed,
            HeaderMap::new(),
            NativeRerankLimits::new(100, 2, 10000, 10000, 10000).unwrap(),
            ranking(),
        )
        .unwrap();
        assert_ne!(changed.effective_identity(), original_identity);
    }
    let cancel = Cancellation::default();
    let result = backend
        .infer_guarded(
            "query".into(),
            vec!["a".into(), "b".into()],
            2,
            context(&cancel),
            &mut || Ok::<(), Infallible>(()),
        )
        .await
        .unwrap();
    assert_eq!(result.len(), 2);
    let requests = tcp.server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.body["documents"].as_array().unwrap().len() == 1)
    );
}

#[tokio::test]
async fn embedding_families_use_query_document_modes_and_existing_cosine() {
    for protocol in [
        "openai",
        "openai-compatible",
        "openai-embeddings-v1",
        "cohere-embed-v2",
        "voyage-embeddings-v1",
        "google",
        "gemini",
    ] {
        let (q, d) = match protocol {
            "cohere-embed-v2" => (
                json!({"embeddings":{"float":[[1.0,0.0]]}}),
                json!({"embeddings":{"float":[[1.0,0.0],[0.0,1.0]]}}),
            ),
            "google" | "gemini" => (
                json!({"embedding":{"values":[1.0,0.0]}}),
                json!({"embeddings":[{"values":[1.0,0.0]},{"values":[0.0,1.0]}]}),
            ),
            _ => (
                json!({"data":[{"index":0,"embedding":[1.0,0.0]}]}),
                json!({"data":[{"index":1,"embedding":[0.0,1.0]},{"index":0,"embedding":[1.0,0.0]}]}),
            ),
        };
        let tcp = fixture(vec![reply(q), reply(d)]).await;
        let backend = embedding(&tcp.origin, protocol);
        let cancel = Cancellation::default();
        let result = backend
            .infer_guarded(
                "query".into(),
                vec!["a".into(), "b".into()],
                2,
                context(&cancel),
                &mut || Ok::<(), Infallible>(()),
            )
            .await
            .unwrap();
        assert_eq!(result.iter().map(|r| r.index).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(
            result.iter().map(|r| r.relevance_score).collect::<Vec<_>>(),
            [1.0, 0.0]
        );
        let requests = tcp.server.await.unwrap();
        assert_eq!(requests.len(), 2);
        if protocol == "cohere-embed-v2" {
            assert_eq!(requests[0].body["input_type"], "search_query");
            assert_eq!(requests[1].body["input_type"], "search_document");
        }
        if protocol == "voyage-embeddings-v1" {
            assert_eq!(requests[0].body["input_type"], "query");
            assert_eq!(requests[1].body["input_type"], "document");
        }
    }
}

#[tokio::test]
async fn later_document_failure_keeps_query_network_effect_and_no_partial_result() {
    let tcp = fixture(vec![
        reply(json!({"data":[{"index":0,"embedding":[1.0,0.0]}]})),
        reply(
            json!({"data":[{"index":0,"embedding":[1.0,0.0]},{"index":0,"embedding":[0.0,1.0]}]}),
        ),
    ])
    .await;
    let backend = embedding(&tcp.origin, "openai");
    let cancel = Cancellation::default();
    let error = backend
        .infer_guarded(
            "query".into(),
            vec!["a".into(), "b".into()],
            1,
            context(&cancel),
            &mut || Ok::<(), Infallible>(()),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RerankBackendError::Embedding {
            source: EmbeddingError::Shape,
            effect: NetworkEffect::MayHaveApplied
        }
    ));
    assert!(!error.temporal());
    assert_eq!(tcp.server.await.unwrap().len(), 2);
}

#[tokio::test]
async fn stop_cancels_original_request_then_reuse_is_closed() {
    let mut response = reply(json!({"results":[{"index":0,"relevance_score":1.0}]}));
    response.delay = Duration::from_millis(100);
    let tcp = fixture(vec![response]).await;
    let backend = Arc::new(native(&tcp.origin, "graphit-rerank-v1"));
    let cancel = Cancellation::default();
    let mut gate = || Ok::<(), Infallible>(());
    let operation = backend.infer_guarded(
        "query".into(),
        vec!["a".into()],
        1,
        context(&cancel),
        &mut gate,
    );
    tokio::pin!(operation);
    tokio::select! { biased; _=tcp.observed.notified()=>{}, result=&mut operation=>panic!("ended before observed request: {result:?}") }
    backend.stop();
    let error = operation.await.unwrap_err();
    assert!(error.temporal());
    assert!(cancel.is_cancelled());
    assert!(backend.closed());
    let fresh = Cancellation::default();
    assert!(matches!(
        backend
            .infer_guarded(
                "query".into(),
                vec!["a".into()],
                1,
                context(&fresh),
                &mut || Ok::<(), Infallible>(())
            )
            .await,
        Err(RerankBackendError::Closed)
    ));
    assert_eq!(tcp.server.await.unwrap().len(), 1);
}

#[tokio::test]
async fn original_deadline_and_guard_failure_precede_socket_effects() {
    let tcp = fixture(vec![]).await;
    let backend = native(&tcp.origin, "cohere");
    let cancel = Cancellation::default();
    let error = backend
        .infer_guarded("query".into(), docs(), 2, context(&cancel), &mut || {
            Err("private-guard-canary")
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RerankBackendError::Admission {
            source: "private-guard-canary",
            effect: NetworkEffect::NotSent
        }
    ));
    assert!(!format!("{error:?} {error}").contains("private-guard-canary"));
    let expired = InferenceContext::new(&cancel, Instant::now());
    assert!(matches!(
        backend
            .infer_guarded("query".into(), docs(), 2, expired, &mut || Ok::<
                (),
                Infallible,
            >(()))
            .await,
        Err(RerankBackendError::Native {
            source: graphit_ai::native_rerank::NativeRerankError::Context(ContextError::Deadline),
            effect: NetworkEffect::NotSent
        })
    ));
    assert!(tcp.server.await.unwrap().is_empty());
}
