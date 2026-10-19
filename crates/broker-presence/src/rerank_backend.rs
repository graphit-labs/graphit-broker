//! Reranking composition over the existing Code clients; no HTTP, SQL or grant creation.
use crate::RemoteEmbeddingsConfig;
use crate::local_model::{LocalError, LocalModel, LocalRerankConfig};
use axum::http::HeaderMap;
use graphit_ai::{
    cohere_embedding::{CohereEmbeddings, CohereInput},
    cohere_rerank::CohereReranker,
    context::InferenceContext,
    embedding::{EmbeddingError, GuardedEmbeddingError},
    google_embedding::{GoogleEmbeddings, GoogleEndpoints, GoogleFamily, GoogleInput},
    graphit_rerank::GraphitReranker,
    jina_rerank::JinaReranker,
    native_embedding::worker::{NativeWorkerError, NativeWorkerErrorKind},
    native_rerank::{GuardedRerankError, NativeRerankError, NativeRerankLimits},
    openai::OpenAiEmbeddings,
    ranking::{RankingError, RankingLimits, rank_order, similarity_scores},
    voyage_embedding::{VoyageEmbeddings, VoyageInput},
    voyage_rerank::VoyageReranker,
};
use graphit_auth::broker::BrokerRerankService;
use graphit_core::file_lock::Cancellation;
use graphit_http::client::{BoundedClient, NetworkEffect, NetworkError};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub struct RemoteRerankConfig {
    pub client: BoundedClient,
    pub protocol: String,
    pub endpoint: String,
    pub model: String,
    pub headers: HeaderMap,
    pub limits: NativeRerankLimits,
}
struct GraphitRerankConfig {
    client: BoundedClient,
    service: BrokerRerankService,
    headers: HeaderMap,
    limits: NativeRerankLimits,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RerankResult {
    pub index: usize,
    pub relevance_score: f64,
}

pub enum RerankBackendError<E> {
    Native {
        source: NativeRerankError,
        effect: NetworkEffect,
    },
    Embedding {
        source: EmbeddingError,
        effect: NetworkEffect,
    },
    Admission {
        source: E,
        effect: NetworkEffect,
    },
    Local(NativeWorkerError),
    Ranking {
        source: RankingError,
        effect: NetworkEffect,
    },
    Closed,
}
impl<E> RerankBackendError<E> {
    pub fn effect(&self) -> NetworkEffect {
        match self {
            Self::Native { effect, .. }
            | Self::Embedding { effect, .. }
            | Self::Admission { effect, .. }
            | Self::Ranking { effect, .. } => *effect,
            Self::Local(_) | Self::Closed => NetworkEffect::NotSent,
        }
    }
    pub fn temporal(&self) -> bool {
        match self {
            Self::Native {
                source:
                    NativeRerankError::Context(_)
                    | NativeRerankError::Network(NetworkError::Cancelled | NetworkError::Deadline),
                ..
            }
            | Self::Embedding {
                source:
                    EmbeddingError::Context(_)
                    | EmbeddingError::Network(NetworkError::Cancelled | NetworkError::Deadline),
                ..
            }
            | Self::Ranking {
                source: RankingError::Context(_),
                ..
            } => true,
            Self::Local(error) => matches!(error.kind(), NativeWorkerErrorKind::Context(_)),
            _ => false,
        }
    }
}
impl<E> fmt::Debug for RerankBackendError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Native { .. } => "Native",
            Self::Embedding { .. } => "Embedding",
            Self::Admission { .. } => "Admission",
            Self::Local(_) => "Local",
            Self::Ranking { .. } => "Ranking",
            Self::Closed => "Closed",
        };
        f.debug_struct(kind)
            .field("effect", &self.effect())
            .finish_non_exhaustive()
    }
}
impl<E> fmt::Display for RerankBackendError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reranking failed")
    }
}
impl<E: std::error::Error + 'static> std::error::Error for RerankBackendError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native { source, .. } => Some(source),
            Self::Embedding { source, .. } => Some(source),
            Self::Admission { source, .. } => Some(source),
            Self::Local(source) => Some(source),
            Self::Ranking { source, .. } => Some(source),
            Self::Closed => None,
        }
    }
}
impl<E> From<GuardedRerankError<E>> for RerankBackendError<E> {
    fn from(error: GuardedRerankError<E>) -> Self {
        match error {
            GuardedRerankError::Rerank { source, effect } => Self::Native { source, effect },
            GuardedRerankError::Admission { source, effect } => Self::Admission { source, effect },
        }
    }
}
enum Backend {
    Remote(Box<RemoteRerankConfig>),
    Graphit(Box<GraphitRerankConfig>),
    Embedding(Box<RemoteEmbeddingsConfig>),
    Local(Arc<LocalModel>),
}
pub struct RerankBackend {
    inner: Backend,
    protocol: String,
    model: String,
    identity: String,
    ranking_limits: RankingLimits,
    closed: AtomicBool,
    stopped: tokio::sync::Notify,
}
fn identity(parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    hex(&digest.finalize())
}
fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("digest formatting");
    }
    result
}
impl RerankBackend {
    pub fn remote(
        mut config: RemoteRerankConfig,
        ranking_limits: RankingLimits,
    ) -> Result<Self, NativeRerankError> {
        config.protocol = config.protocol.trim().to_ascii_lowercase();
        match config.protocol.as_str() {
            "cohere" | "cohere-v2" => CohereReranker::new(
                &config.client,
                &config.endpoint,
                &config.model,
                config.limits,
            )
            .map(|_| ()),
            "voyage" | "voyage-v1" => VoyageReranker::new(
                &config.client,
                &config.endpoint,
                &config.model,
                config.limits,
            )
            .map(|_| ()),
            "jina" | "jina-v1" => JinaReranker::new(
                &config.client,
                &config.endpoint,
                &config.model,
                config.limits,
            )
            .map(|_| ()),
            _ => Err(NativeRerankError::Policy),
        }?;
        if config
            .headers
            .contains_key(axum::http::header::CONTENT_TYPE)
        {
            return Err(NativeRerankError::Policy);
        }
        let identity = identity(&[
            config.protocol.as_bytes(),
            config.endpoint.as_bytes(),
            config.model.as_bytes(),
        ]);
        Ok(Self::new(
            Backend::Remote(Box::new(config)),
            identity,
            ranking_limits,
        ))
    }
    pub fn graphit(
        client: BoundedClient,
        service: BrokerRerankService,
        headers: HeaderMap,
        limits: NativeRerankLimits,
        ranking_limits: RankingLimits,
    ) -> Result<Self, NativeRerankError> {
        GraphitReranker::new(&client, &service, limits)?;
        if headers.contains_key(axum::http::header::CONTENT_TYPE) {
            return Err(NativeRerankError::Policy);
        }
        let identity = identity(&[
            b"graphit-rerank-v1",
            service.endpoint.as_bytes(),
            service.identity.model.as_bytes(),
            service.identity.model_revision.as_bytes(),
            service.identity.recipe.as_bytes(),
            service.identity.service_revision.as_bytes(),
            &service.max_documents.to_le_bytes(),
        ]);
        Ok(Self::new(
            Backend::Graphit(Box::new(GraphitRerankConfig {
                client,
                service,
                headers,
                limits,
            })),
            identity,
            ranking_limits,
        ))
    }
    pub fn embedding(
        mut config: RemoteEmbeddingsConfig,
        ranking_limits: RankingLimits,
    ) -> Result<Self, EmbeddingError> {
        config.protocol = config.protocol.trim().to_ascii_lowercase();
        validate_embedding(&config)?;
        let family = match config.google_family {
            Some(GoogleFamily::Gemini1) => "gemini1",
            Some(GoogleFamily::Gemini2) => "gemini2",
            None => "",
        };
        let dimensions = config.dimensions.to_le_bytes();
        let request_dimensions = config
            .request_dimensions
            .map(|n| n.to_string())
            .unwrap_or_default();
        let identity = identity(&[
            config.protocol.as_bytes(),
            config.endpoint.as_bytes(),
            config.model.as_bytes(),
            config
                .batch_endpoint
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            family.as_bytes(),
            &dimensions,
            request_dimensions.as_bytes(),
        ]);
        Ok(Self::new(
            Backend::Embedding(Box::new(config)),
            identity,
            ranking_limits,
        ))
    }
    /// Retain declarations only; weights reside only while the model is in use.
    pub fn local(
        config: LocalRerankConfig,
        effective_identity: &[u8],
        ranking_limits: RankingLimits,
    ) -> Result<Self, NativeWorkerError> {
        let model = config.source.model.clone();
        Ok(Self {
            inner: Backend::Local(LocalModel::rerank(config)?),
            protocol: "gguf-bge-reranker-v2-m3".into(),
            model,
            identity: hex(&Sha256::digest(effective_identity)),
            ranking_limits,
            closed: AtomicBool::new(false),
            stopped: tokio::sync::Notify::new(),
        })
    }
    fn new(inner: Backend, identity: String, ranking_limits: RankingLimits) -> Self {
        let (protocol, model) = match &inner {
            Backend::Remote(c) => (c.protocol.clone(), c.model.clone()),
            Backend::Graphit(c) => ("graphit-rerank-v1".into(), c.service.identity.model.clone()),
            Backend::Embedding(c) => (c.protocol.clone(), c.model.clone()),
            Backend::Local(_) => unreachable!("local constructor supplies its runtime metadata"),
        };
        Self {
            inner,
            protocol,
            model,
            identity,
            ranking_limits,
            closed: AtomicBool::new(false),
            stopped: tokio::sync::Notify::new(),
        }
    }
    pub async fn shutdown(&self, context: InferenceContext<'_>) -> Result<(), NativeWorkerError> {
        self.stop();
        if let Backend::Local(worker) = &self.inner {
            worker.shutdown(context).await?;
        }
        Ok(())
    }
    pub fn protocol(&self) -> &str {
        &self.protocol
    }
    pub fn model(&self) -> &str {
        &self.model
    }
    pub fn effective_identity(&self) -> &str {
        &self.identity
    }
    pub fn local_identity(&self) -> Option<&str> {
        matches!(self.inner, Backend::Local(_)).then_some(self.identity.as_str())
    }
    pub fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub fn stop(&self) {
        self.closed.store(true, Ordering::Release);
        if let Backend::Local(model) = &self.inner {
            model.stop();
        }
        self.stopped.notify_waiters();
    }

    pub async fn infer_guarded<G, E>(
        &self,
        query: String,
        documents: Vec<String>,
        top_n: usize,
        context: InferenceContext<'_>,
        gate: &mut G,
    ) -> Result<Vec<RerankResult>, RerankBackendError<E>>
    where
        G: FnMut() -> Result<(), E>,
    {
        check(gate, context, NetworkEffect::NotSent)?;
        if self.closed() {
            return Err(RerankBackendError::Closed);
        }
        if top_n == 0 || top_n > documents.len() {
            return Err(RerankBackendError::Native {
                source: NativeRerankError::Policy,
                effect: NetworkEffect::NotSent,
            });
        }
        // Stop remains observable at synchronous SDK/final gate boundaries too.
        let mut guarded = || admit_with_stop(&self.closed, context.cancellation(), gate);
        let gate = &mut guarded;
        let count = documents.len();
        let stopped = self.stopped.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if self.closed() {
            context.cancellation().cancel();
        }
        let operation = async {
            let (scores, effect) = match &self.inner {
                Backend::Remote(config) => {
                    let refs: Vec<_> = documents.iter().map(String::as_str).collect();
                    (
                        remote_scores(config, &query, &refs, context, gate).await?,
                        NetworkEffect::MayHaveApplied,
                    )
                }
                Backend::Graphit(config) => {
                    let refs: Vec<_> = documents.iter().map(String::as_str).collect();
                    let scores =
                        GraphitReranker::new(&config.client, &config.service, config.limits)
                            .map_err(|source| RerankBackendError::Native {
                                source,
                                effect: NetworkEffect::NotSent,
                            })?
                            .score_guarded(&query, &refs, &config.headers, context, gate)
                            .await?;
                    (scores, NetworkEffect::MayHaveApplied)
                }
                Backend::Embedding(config) => {
                    let query_vectors = embeddings(
                        config,
                        &[query.as_str()],
                        true,
                        context,
                        gate,
                        NetworkEffect::NotSent,
                    )
                    .await?;
                    let refs: Vec<_> = documents.iter().map(String::as_str).collect();
                    let vectors = embeddings(
                        config,
                        &refs,
                        false,
                        context,
                        gate,
                        NetworkEffect::MayHaveApplied,
                    )
                    .await?;
                    check(gate, context, NetworkEffect::MayHaveApplied)?;
                    let scores = similarity_scores(
                        &query_vectors[0],
                        &vectors,
                        config.dimensions,
                        self.ranking_limits,
                        context,
                    )
                    .map_err(|source| RerankBackendError::Ranking {
                        source,
                        effect: NetworkEffect::MayHaveApplied,
                    })?;
                    (scores, NetworkEffect::MayHaveApplied)
                }
                Backend::Local(client) => (
                    client
                        .score(query, documents, context)
                        .await
                        .map_err(|error| match error {
                            LocalError::Worker(error) => RerankBackendError::Local(error),
                            LocalError::Closed => RerankBackendError::Closed,
                        })?,
                    NetworkEffect::NotSent,
                ),
            };
            check(gate, context, effect)?;
            let indices: Vec<_> = (0..count).collect();
            let order = rank_order(&indices, &scores, self.ranking_limits, context)
                .map_err(|source| RerankBackendError::Ranking { source, effect })?;
            let result = order
                .into_iter()
                .take(top_n)
                .map(|index| RerankResult {
                    index,
                    relevance_score: scores[index],
                })
                .collect();
            check(gate, context, effect)?;
            Ok(result)
        };
        tokio::pin!(operation);
        tokio::select! {
            result = &mut operation => result,
            _ = &mut stopped => { context.cancellation().cancel(); operation.await }
        }
    }
}
fn admit_with_stop<G, E>(closed: &AtomicBool, cancel: &Cancellation, gate: &mut G) -> Result<(), E>
where
    G: FnMut() -> Result<(), E>,
{
    if closed.load(Ordering::Acquire) {
        cancel.cancel();
    }
    let admitted = gate();
    // A shutdown during the finite callback must be seen at the same output boundary.
    if closed.load(Ordering::Acquire) {
        cancel.cancel();
    }
    admitted
}

fn check<G, E>(
    gate: &mut G,
    context: InferenceContext<'_>,
    effect: NetworkEffect,
) -> Result<(), RerankBackendError<E>>
where
    G: FnMut() -> Result<(), E>,
{
    let temporal = |source| RerankBackendError::Native {
        source: NativeRerankError::Context(source),
        effect,
    };
    context.check().map_err(temporal)?;
    let admitted = gate();
    context.check().map_err(temporal)?;
    admitted.map_err(|source| RerankBackendError::Admission { source, effect })
}
async fn remote_scores<G, E>(
    c: &RemoteRerankConfig,
    query: &str,
    documents: &[&str],
    context: InferenceContext<'_>,
    gate: &mut G,
) -> Result<Vec<f64>, RerankBackendError<E>>
where
    G: FnMut() -> Result<(), E>,
{
    macro_rules! native {
        ($adapter:ident) => {
            $adapter::new(&c.client, &c.endpoint, &c.model, c.limits)
                .map_err(|source| RerankBackendError::Native {
                    source,
                    effect: NetworkEffect::NotSent,
                })?
                .score_guarded(query, documents, &c.headers, context, gate)
                .await
                .map_err(Into::into)
        };
    }
    match c.protocol.as_str() {
        "cohere" | "cohere-v2" => native!(CohereReranker),
        "voyage" | "voyage-v1" => native!(VoyageReranker),
        "jina" | "jina-v1" => native!(JinaReranker),
        _ => unreachable!("validated rerank protocol"),
    }
}
fn validate_embedding(c: &RemoteEmbeddingsConfig) -> Result<(), EmbeddingError> {
    if c.headers.contains_key(axum::http::header::CONTENT_TYPE) {
        return Err(EmbeddingError::InvalidPolicy);
    }
    let google = matches!(
        c.protocol.as_str(),
        "google" | "google-embed-content-v1beta" | "gemini" | "gemini-embed-content-v1beta"
    );
    if !google && (c.google_family.is_some() || c.batch_endpoint.is_some()) {
        return Err(EmbeddingError::InvalidPolicy);
    }
    if !google
        && !matches!(
            c.protocol.as_str(),
            "openai" | "openai-compatible" | "openai-embeddings-v1"
        )
        && c.request_dimensions.is_some()
    {
        return Err(EmbeddingError::InvalidPolicy);
    }
    match c.protocol.as_str() {
        "openai" | "openai-compatible" | "openai-embeddings-v1" => OpenAiEmbeddings::new(
            &c.client,
            &c.endpoint,
            &c.model,
            c.dimensions,
            c.request_dimensions,
            c.limits,
        )
        .map(|_| ()),
        "cohere-embed-v2" => {
            CohereEmbeddings::new(&c.client, &c.endpoint, &c.model, c.dimensions, c.limits)
                .map(|_| ())
        }
        "voyage-embeddings-v1" => {
            VoyageEmbeddings::new(&c.client, &c.endpoint, &c.model, c.dimensions, c.limits)
                .map(|_| ())
        }
        _ if google => GoogleEmbeddings::new(
            &c.client,
            GoogleEndpoints {
                single: &c.endpoint,
                batch: c
                    .batch_endpoint
                    .as_deref()
                    .ok_or(EmbeddingError::InvalidPolicy)?,
            },
            &c.model,
            c.dimensions,
            c.request_dimensions,
            c.google_family.ok_or(EmbeddingError::InvalidPolicy)?,
            c.limits,
        )
        .map(|_| ()),
        _ => Err(EmbeddingError::InvalidPolicy),
    }
}
async fn embeddings<G, E>(
    c: &RemoteEmbeddingsConfig,
    texts: &[&str],
    query: bool,
    context: InferenceContext<'_>,
    gate: &mut G,
    previous: NetworkEffect,
) -> Result<Vec<Vec<f32>>, RerankBackendError<E>>
where
    G: FnMut() -> Result<(), E>,
{
    macro_rules! setup {
        ($value:expr) => {
            $value.map_err(|source| RerankBackendError::Embedding {
                source,
                effect: previous,
            })?
        };
    }
    let result = match c.protocol.as_str() {
        "openai" | "openai-compatible" | "openai-embeddings-v1" => {
            setup!(OpenAiEmbeddings::new(
                &c.client,
                &c.endpoint,
                &c.model,
                c.dimensions,
                c.request_dimensions,
                c.limits
            ))
            .embed_guarded(texts, &c.headers, context, gate)
            .await
        }
        "cohere-embed-v2" => {
            setup!(CohereEmbeddings::new(
                &c.client,
                &c.endpoint,
                &c.model,
                c.dimensions,
                c.limits
            ))
            .embed_guarded(
                texts,
                if query {
                    CohereInput::Query
                } else {
                    CohereInput::Document
                },
                &c.headers,
                context,
                gate,
            )
            .await
        }
        "voyage-embeddings-v1" => {
            setup!(VoyageEmbeddings::new(
                &c.client,
                &c.endpoint,
                &c.model,
                c.dimensions,
                c.limits
            ))
            .embed_guarded(
                texts,
                if query {
                    VoyageInput::Query
                } else {
                    VoyageInput::Document
                },
                &c.headers,
                context,
                gate,
            )
            .await
        }
        _ => {
            setup!(GoogleEmbeddings::new(
                &c.client,
                GoogleEndpoints {
                    single: &c.endpoint,
                    batch: c
                        .batch_endpoint
                        .as_deref()
                        .expect("validated batch endpoint")
                },
                &c.model,
                c.dimensions,
                c.request_dimensions,
                c.google_family.expect("validated Google family"),
                c.limits
            ))
            .embed_guarded(
                texts,
                if query {
                    GoogleInput::Query
                } else {
                    GoogleInput::Document
                },
                &c.headers,
                context,
                gate,
            )
            .await
        }
    };
    result.map(|batch| batch.into_vectors()).map_err(|error| {
        let effect = if previous == NetworkEffect::MayHaveApplied {
            previous
        } else {
            error.effect()
        };
        match error {
            GuardedEmbeddingError::Embedding { source, .. } => {
                RerankBackendError::Embedding { source, effect }
            }
            GuardedEmbeddingError::Admission { source, .. } => {
                RerankBackendError::Admission { source, effect }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stop_during_admission_cancels_the_original_at_the_same_boundary() {
        let closed = AtomicBool::new(false);
        let cancel = Cancellation::default();
        let context = InferenceContext::new(
            &cancel,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        let mut gate = || {
            closed.store(true, Ordering::Release);
            Ok::<(), std::convert::Infallible>(())
        };
        let mut guarded = || admit_with_stop(&closed, &cancel, &mut gate);
        let result = check(&mut guarded, context, NetworkEffect::MayHaveApplied);
        assert!(matches!(
            result,
            Err(RerankBackendError::Native {
                source: NativeRerankError::Context(graphit_ai::context::ContextError::Cancelled),
                effect: NetworkEffect::MayHaveApplied,
            })
        ));
        assert!(cancel.is_cancelled());
    }
}
