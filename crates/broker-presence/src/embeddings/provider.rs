use crate::local_model::{LocalEmbeddingConfig, LocalError, LocalModel};
use axum::http::{HeaderMap, header};
use broker_control::{EmbeddingAdmission, EmbeddingAdmissionError};
use graphit_ai::{
    cohere_embedding::{CohereEmbeddings, CohereInput},
    context::InferenceContext,
    embedding::{EmbeddingBatch, EmbeddingError, EmbeddingLimits, GuardedEmbeddingError},
    google_embedding::{GoogleEmbeddings, GoogleEndpoints, GoogleFamily, GoogleInput},
    native_embedding::{
        NativeEmbeddingInput,
        worker::{NativeWorkerError, NativeWorkerErrorKind},
    },
    openai::OpenAiEmbeddings,
    voyage_embedding::{VoyageEmbeddings, VoyageInput},
};
use graphit_core::file_lock::Cancellation;
use graphit_http::client::{BoundedClient, NetworkEffect};
use serde_json::value::RawValue;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Captured remote settings. This data is neither a caller identity nor a grant.
pub struct RemoteEmbeddingsConfig {
    pub client: BoundedClient,
    pub protocol: String,
    pub endpoint: String,
    pub batch_endpoint: Option<String>,
    pub model: String,
    pub dimensions: usize,
    pub request_dimensions: Option<usize>,
    pub google_family: Option<GoogleFamily>,
    pub headers: HeaderMap,
    pub limits: EmbeddingLimits,
}
enum Protocol {
    OpenAi,
    Cohere,
    Voyage,
    Google(GoogleFamily),
}
struct Remote {
    config: RemoteEmbeddingsConfig,
    protocol: Protocol,
}
enum Backend {
    Remote(Box<Remote>),
    Local(Arc<LocalModel>),
}
pub struct EmbeddingBackend {
    inner: Backend,
    protocol: String,
    model: String,
    source_identity: String,
    send_dimensions: bool,
    dimensions: usize,
    closed: AtomicBool,
    stopped: tokio::sync::Notify,
}
pub(super) enum Failure {
    Remote(EmbeddingError, NetworkEffect),
    Admission(EmbeddingAdmissionError, NetworkEffect),
    Local(NativeWorkerError),
    Closed,
}
impl Failure {
    pub(super) fn temporal(&self) -> bool {
        match self {
            Self::Remote(
                EmbeddingError::Context(_)
                | EmbeddingError::Network(
                    graphit_http::client::NetworkError::Cancelled
                    | graphit_http::client::NetworkError::Deadline,
                ),
                _,
            ) => true,
            Self::Local(error) => matches!(error.kind(), NativeWorkerErrorKind::Context(_)),
            _ => false,
        }
    }
}
impl std::fmt::Debug for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Remote(source, effect) => f
                .debug_struct("Remote")
                .field("source", source)
                .field("effect", effect)
                .finish(),
            Self::Admission(source, effect) => f
                .debug_struct("Admission")
                .field("source", source)
                .field("effect", effect)
                .finish(),
            Self::Local(source) => f.debug_tuple("Local").field(source).finish(),
            Self::Closed => f.write_str("Closed"),
        }
    }
}
pub(super) struct Outcome {
    pub entries: Vec<(usize, Vec<f32>)>,
    pub usage: Vec<Box<RawValue>>,
    pub failure: Option<Failure>,
}
impl EmbeddingBackend {
    pub fn remote(mut config: RemoteEmbeddingsConfig) -> Result<Self, super::EmbeddingsError> {
        config.protocol = config.protocol.trim().to_ascii_lowercase();
        let protocol = match config.protocol.as_str() {
            "openai" | "openai-embeddings-v1" => Protocol::OpenAi,
            "openai-compatible" => Protocol::OpenAi,
            "cohere" | "cohere-embed-v2" => Protocol::Cohere,
            "voyage" | "voyage-embeddings-v1" => Protocol::Voyage,
            "google" | "google-embed-content-v1beta" | "gemini" | "gemini-embed-content-v1beta" => {
                Protocol::Google(
                    config
                        .google_family
                        .ok_or(super::EmbeddingsError::Configuration)?,
                )
            }
            _ => return Err(super::EmbeddingsError::Configuration),
        };
        if config.headers.contains_key(header::CONTENT_TYPE)
            || (!matches!(protocol, Protocol::Google(_))
                && (config.google_family.is_some() || config.batch_endpoint.is_some()))
            || (!matches!(protocol, Protocol::OpenAi | Protocol::Google(_))
                && config.request_dimensions.is_some())
        {
            return Err(super::EmbeddingsError::Configuration);
        }
        match protocol {
            Protocol::OpenAi => OpenAiEmbeddings::new(
                &config.client,
                &config.endpoint,
                &config.model,
                config.dimensions,
                config.request_dimensions,
                config.limits,
            )
            .map(|_| ()),
            Protocol::Cohere => CohereEmbeddings::new(
                &config.client,
                &config.endpoint,
                &config.model,
                config.dimensions,
                config.limits,
            )
            .map(|_| ()),
            Protocol::Voyage => VoyageEmbeddings::new(
                &config.client,
                &config.endpoint,
                &config.model,
                config.dimensions,
                config.limits,
            )
            .map(|_| ()),
            Protocol::Google(family) => GoogleEmbeddings::new(
                &config.client,
                GoogleEndpoints {
                    single: &config.endpoint,
                    batch: config
                        .batch_endpoint
                        .as_deref()
                        .ok_or(super::EmbeddingsError::Configuration)?,
                },
                &config.model,
                config.dimensions,
                config.request_dimensions,
                family,
                config.limits,
            )
            .map(|_| ()),
        }
        .map_err(|_| super::EmbeddingsError::Configuration)?;
        let mut source_identity = config.endpoint.clone();
        if let Protocol::Google(family) = protocol {
            source_identity.push('\0');
            source_identity.push_str(
                config
                    .batch_endpoint
                    .as_deref()
                    .expect("validated batch endpoint"),
            );
            source_identity.push('\0');
            source_identity.push_str(match family {
                GoogleFamily::Gemini1 => "gemini1",
                GoogleFamily::Gemini2 => "gemini2",
            });
        }
        Ok(Self {
            protocol: config.protocol.clone(),
            model: config.model.clone(),
            source_identity,
            send_dimensions: config.request_dimensions.is_some(),
            dimensions: config.dimensions,
            inner: Backend::Remote(Box::new(Remote { config, protocol })),
            closed: AtomicBool::new(false),
            stopped: tokio::sync::Notify::new(),
        })
    }
    /// Retain bounded declarations; load weights on demand and release idle residency.
    pub fn local(config: LocalEmbeddingConfig, identity: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let identity: [u8; 32] = Sha256::digest(identity).into();
        let dimensions = config.options.dimensions;
        let model = config.source.model.clone();
        let mut source_identity = String::with_capacity(64);
        use std::fmt::Write;
        for byte in identity {
            write!(&mut source_identity, "{byte:02x}").expect("writing a digest to String");
        }
        Self {
            inner: Backend::Local(LocalModel::embedding(config)),
            protocol: "gguf-embeddinggemma2".into(),
            model,
            source_identity,
            send_dimensions: false,
            dimensions,
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
    pub fn dimensions(&self) -> usize {
        self.dimensions
    }
    pub fn local_identity(&self) -> Option<&str> {
        matches!(&self.inner, Backend::Local(_)).then_some(self.source_identity.as_str())
    }
    pub fn stop(&self) {
        self.closed.store(true, Ordering::Release);
        if let Backend::Local(model) = &self.inner {
            model.stop();
        }
        self.stopped.notify_waiters();
    }
    pub(super) fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub(super) fn protocol(&self) -> &str {
        &self.protocol
    }
    pub fn model(&self) -> &str {
        &self.model
    }
    pub(super) fn source_identity(&self) -> &str {
        &self.source_identity
    }
    pub(super) fn send_dimensions(&self) -> bool {
        self.send_dimensions
    }
    pub(super) async fn infer(
        &self,
        texts: Vec<String>,
        input: super::InputType,
        admission: &mut EmbeddingAdmission<'_>,
        cancel: &Cancellation,
    ) -> Outcome {
        if let Err(error) = admission.check() {
            return Outcome {
                entries: Vec::new(),
                usage: Vec::new(),
                failure: Some(Failure::Admission(error, NetworkEffect::NotSent)),
            };
        }
        if self.closed() {
            return Outcome {
                entries: Vec::new(),
                usage: Vec::new(),
                failure: Some(Failure::Closed),
            };
        }
        let context = InferenceContext::new(cancel, admission.deadline());
        let stopped = self.stopped.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if self.closed() {
            cancel.cancel();
        }
        let operation = async {
            match &self.inner {
                Backend::Remote(remote) => {
                    remote.infer(&texts, input, context, admission, self).await
                }
                Backend::Local(local) => local_infer(local, texts, input, admission, context).await,
            }
        };
        tokio::pin!(operation);
        tokio::select! {
            result=&mut operation=>result,
            _=stopped=>{ cancel.cancel();operation.await },
        }
    }
}
impl Remote {
    async fn infer(
        &self,
        texts: &[String],
        input: super::InputType,
        context: InferenceContext<'_>,
        admission: &mut EmbeddingAdmission<'_>,
        owner: &EmbeddingBackend,
    ) -> Outcome {
        let texts: Vec<_> = texts.iter().map(String::as_str).collect();
        let mut gate = || {
            admission.check()?;
            if owner.closed() {
                Err(EmbeddingAdmissionError::Control(
                    broker_control::ControlError::Closed,
                ))
            } else {
                Ok(())
            }
        };
        let c = &self.config;
        let result = match self.protocol {
            Protocol::OpenAi => match OpenAiEmbeddings::new(
                &c.client,
                &c.endpoint,
                &c.model,
                c.dimensions,
                c.request_dimensions,
                c.limits,
            ) {
                Ok(sdk) => {
                    sdk.embed_guarded(&texts, &c.headers, context, &mut gate)
                        .await
                }
                Err(error) => return failed(error),
            },
            Protocol::Cohere => match CohereEmbeddings::new(
                &c.client,
                &c.endpoint,
                &c.model,
                c.dimensions,
                c.limits,
            ) {
                Ok(sdk) => {
                    sdk.embed_guarded(
                        &texts,
                        if input == super::InputType::Query {
                            CohereInput::Query
                        } else {
                            CohereInput::Document
                        },
                        &c.headers,
                        context,
                        &mut gate,
                    )
                    .await
                }
                Err(error) => return failed(error),
            },
            Protocol::Voyage => match VoyageEmbeddings::new(
                &c.client,
                &c.endpoint,
                &c.model,
                c.dimensions,
                c.limits,
            ) {
                Ok(sdk) => {
                    sdk.embed_guarded(
                        &texts,
                        if input == super::InputType::Query {
                            VoyageInput::Query
                        } else {
                            VoyageInput::Document
                        },
                        &c.headers,
                        context,
                        &mut gate,
                    )
                    .await
                }
                Err(error) => return failed(error),
            },
            Protocol::Google(family) => match GoogleEmbeddings::new(
                &c.client,
                GoogleEndpoints {
                    single: &c.endpoint,
                    batch: c
                        .batch_endpoint
                        .as_deref()
                        .expect("validated Google endpoint"),
                },
                &c.model,
                c.dimensions,
                c.request_dimensions,
                family,
                c.limits,
            ) {
                Ok(sdk) => {
                    sdk.embed_guarded(
                        &texts,
                        if input == super::InputType::Query {
                            GoogleInput::Query
                        } else {
                            GoogleInput::Document
                        },
                        &c.headers,
                        context,
                        &mut gate,
                    )
                    .await
                }
                Err(error) => return failed(error),
            },
        };
        remote_outcome(result)
    }
}
fn failed(error: EmbeddingError) -> Outcome {
    Outcome {
        entries: Vec::new(),
        usage: Vec::new(),
        failure: Some(Failure::Remote(error, NetworkEffect::NotSent)),
    }
}
fn remote_outcome(
    result: Result<EmbeddingBatch<'_>, GuardedEmbeddingError<EmbeddingAdmissionError>>,
) -> Outcome {
    match result {
        Ok(mut batch) => {
            let usage = batch.take_usage();
            Outcome {
                entries: batch.into_vectors().into_iter().enumerate().collect(),
                usage,
                failure: None,
            }
        }
        Err(mut error) => {
            let entries = error.take_completed();
            let usage = error.take_usage();
            let failure = match error {
                GuardedEmbeddingError::Embedding { source, effect, .. } => {
                    Failure::Remote(source, effect)
                }
                GuardedEmbeddingError::Admission { source, effect } => {
                    Failure::Admission(source, effect)
                }
            };
            Outcome {
                entries,
                usage,
                failure: Some(failure),
            }
        }
    }
}

async fn local_infer(
    worker: &Arc<LocalModel>,
    texts: Vec<String>,
    input: super::InputType,
    admission: &mut EmbeddingAdmission<'_>,
    context: InferenceContext<'_>,
) -> Outcome {
    let input = if input == super::InputType::Query {
        NativeEmbeddingInput::Query
    } else {
        NativeEmbeddingInput::Document
    };
    let mut outcome = Outcome {
        entries: Vec::new(),
        usage: Vec::new(),
        failure: None,
    };
    // GGUF processes texts independently. Separate worker requests retain
    // completed vectors when tokenization/inference of a later item fails.
    for (offset, text) in texts.into_iter().enumerate() {
        if let Err(error) = admission.check() {
            outcome.failure = Some(Failure::Admission(error, NetworkEffect::NotSent));
            break;
        }
        match worker.embed(vec![text], input, context).await {
            Ok(batch) => outcome.entries.extend(
                batch
                    .into_iter()
                    .enumerate()
                    .map(|(index, vector)| (offset + index, vector)),
            ),
            Err(error) => {
                outcome.failure = Some(match error {
                    LocalError::Worker(error) => Failure::Local(error),
                    LocalError::Closed => Failure::Closed,
                });
                break;
            }
        }
    }
    if let Err(error) = admission.check() {
        outcome
            .failure
            .get_or_insert(Failure::Admission(error, NetworkEffect::NotSent));
    }
    outcome
}
