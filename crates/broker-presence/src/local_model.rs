//! Residency for the two local model backends; native work stays in the existing workers.
use graphit_ai::{
    context::{ContextError, InferenceContext},
    embedding::EmbeddingLimits,
    gguf_rerank::{GgufRerankClient, GgufRerankOptions},
    model_artifact::GgufModelSource,
    native_embedding::{
        NativeEmbeddingClient, NativeEmbeddingInput, NativeEmbeddingOptions,
        worker::{GgufRerankWorker, NativeEmbeddingWorker, NativeWorkerError},
    },
    native_rerank::NativeRerankLimits,
};
use graphit_core::{file_lock::Cancellation, native_document_file::CapturedDocumentDirectory};
use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex as AsyncMutex, Notify, oneshot},
    task::JoinHandle,
};

pub struct LocalEmbeddingConfig {
    pub snapshot_parent: Arc<CapturedDocumentDirectory>,
    pub source: GgufModelSource,
    pub options: NativeEmbeddingOptions,
    pub limits: EmbeddingLimits,
    pub capacity: NonZeroUsize,
    pub idle_timeout: Duration,
    pub shutdown_timeout: Duration,
}
pub struct LocalRerankConfig {
    pub snapshot_parent: Arc<CapturedDocumentDirectory>,
    pub source: GgufModelSource,
    pub options: GgufRerankOptions,
    pub limits: NativeRerankLimits,
    pub capacity: NonZeroUsize,
    pub idle_timeout: Duration,
    pub shutdown_timeout: Duration,
}
enum Configuration {
    Embedding(NativeEmbeddingOptions, EmbeddingLimits),
    Rerank(GgufRerankOptions, NativeRerankLimits),
}
enum Worker {
    Embedding(NativeEmbeddingWorker),
    Rerank(GgufRerankWorker),
}
enum Request {
    Embed(Vec<String>, NativeEmbeddingInput),
    Score(String, Vec<String>),
}
enum Output {
    Embedding(Vec<Vec<f32>>),
    Rerank(Vec<f64>),
}
#[derive(Debug)]
pub(crate) enum LocalError {
    Worker(NativeWorkerError),
    Closed,
}
impl From<NativeWorkerError> for LocalError {
    fn from(error: NativeWorkerError) -> Self {
        Self::Worker(error)
    }
}
impl From<ContextError> for LocalError {
    fn from(error: ContextError) -> Self {
        Self::Worker(error.into())
    }
}
#[derive(Default)]
struct Resident {
    worker: Option<Worker>,
    completed: Option<tokio::time::Instant>,
}
pub(crate) struct LocalModel {
    snapshot_parent: Arc<CapturedDocumentDirectory>,
    source: GgufModelSource,
    configuration: Configuration,
    capacity: NonZeroUsize,
    idle_timeout: Duration,
    shutdown_timeout: Duration,
    state: Arc<AsyncMutex<Resident>>,
    changed: Arc<Notify>,
    stop: Cancellation,
    timer: Mutex<Option<JoinHandle<()>>>,
    #[cfg(test)]
    startup_gate: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    #[cfg(test)]
    ready_gate: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}
impl Worker {
    async fn shutdown(self, context: InferenceContext<'_>) -> Result<(), NativeWorkerError> {
        match self {
            Self::Embedding(worker) => worker.shutdown_retained(context).await,
            Self::Rerank(worker) => worker.shutdown_retained(context).await,
        }
    }
}
impl LocalModel {
    pub(crate) fn embedding(config: LocalEmbeddingConfig) -> Arc<Self> {
        Self::new(
            config.snapshot_parent,
            config.source,
            Configuration::Embedding(config.options, config.limits),
            config.capacity,
            config.idle_timeout,
            config.shutdown_timeout,
        )
    }
    pub(crate) fn rerank(config: LocalRerankConfig) -> Result<Arc<Self>, NativeWorkerError> {
        GgufRerankClient::validate_options(config.options)?;
        Ok(Self::new(
            config.snapshot_parent,
            config.source,
            Configuration::Rerank(config.options, config.limits),
            config.capacity,
            config.idle_timeout,
            config.shutdown_timeout,
        ))
    }
    fn new(
        snapshot_parent: Arc<CapturedDocumentDirectory>,
        source: GgufModelSource,
        configuration: Configuration,
        capacity: NonZeroUsize,
        idle_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshot_parent,
            source,
            configuration,
            capacity,
            idle_timeout,
            shutdown_timeout,
            state: Arc::new(AsyncMutex::new(Resident::default())),
            changed: Arc::new(Notify::new()),
            stop: Cancellation::default(),
            timer: Mutex::new(None),
            #[cfg(test)]
            startup_gate: Mutex::new(None),
            #[cfg(test)]
            ready_gate: Mutex::new(None),
        })
    }
    fn start_idle_timer(&self) {
        let mut timer = self.timer.lock().unwrap();
        if timer.is_some() {
            return;
        }
        let state = self.state.clone();
        let changed = self.changed.clone();
        let stop = self.stop.clone();
        let idle = self.idle_timeout;
        let model = self.source.model.clone();
        let shutdown_timeout = self.shutdown_timeout;
        *timer = Some(tokio::spawn(async move {
            loop {
                let deadline = {
                    let resident = state.lock().await;
                    resident.completed.map(|finished| finished + idle)
                };
                match deadline {
                    Some(deadline) => tokio::select! {
                        biased;
                        _ = stop.cancelled() => break,
                        _ = changed.notified() => continue,
                        _ = tokio::time::sleep_until(deadline) => {}
                    },
                    None => {
                        tokio::select! { biased; _ = stop.cancelled() => break, _ = changed.notified() => {} }
                        continue;
                    }
                }
                let mut resident = state.lock().await;
                if resident
                    .completed
                    .is_some_and(|finished| tokio::time::Instant::now() >= finished + idle)
                {
                    if let Some(worker) = resident.worker.take() {
                        let cancel = Cancellation::default();
                        let context =
                            InferenceContext::new(&cancel, Instant::now() + shutdown_timeout);
                        if let Err(error) = worker.shutdown(context).await {
                            eprintln!("local model idle shutdown failed: {:?}", error.kind());
                        }
                    }
                    resident.completed = None;
                    eprintln!("local model unloaded after inactivity: model={model}");
                }
            }
        }));
    }
    async fn load(&self, context: InferenceContext<'_>) -> Result<Worker, NativeWorkerError> {
        #[cfg(test)]
        {
            let gate = self.startup_gate.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                let _ = entered.send(());
                let _ = release.await;
            }
        }
        let source = GgufModelSource {
            model: self.source.model.clone(),
            revision: self.source.revision.clone(),
            root: self.source.root.clone(),
            path: self.source.path.clone(),
            minimum_bytes: self.source.minimum_bytes,
            maximum_bytes: self.source.maximum_bytes,
            sha256: self.source.sha256,
        };
        let (worker, device) = match self.configuration {
            Configuration::Embedding(options, limits) => {
                let worker = NativeEmbeddingWorker::start(
                    self.snapshot_parent.clone(),
                    source,
                    options,
                    limits,
                    self.capacity,
                    context,
                )
                .await?;
                let device = worker.registered_device();
                (Worker::Embedding(worker), device)
            }
            Configuration::Rerank(options, limits) => {
                let worker = GgufRerankWorker::start(
                    self.snapshot_parent.clone(),
                    source,
                    options,
                    limits,
                    self.capacity,
                    context,
                )
                .await?;
                let device = worker.registered_device();
                (Worker::Rerank(worker), device)
            }
        };
        #[cfg(test)]
        {
            let gate = self.ready_gate.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                let _ = entered.send(());
                let _ = release.await;
            }
        }
        if let Some(device) = device {
            eprintln!(
                "local model loaded: model={} requested={:?} provider={:?} device_id={} fallback={:?}",
                self.source.model,
                device.requested_provider,
                device.provider,
                device.device_id,
                device.fallback_reason
            );
        }
        Ok(worker)
    }
    async fn execute(
        self: &Arc<Self>,
        request: Request,
        context: InferenceContext<'_>,
    ) -> Result<Output, LocalError> {
        context.check()?;
        if self.stop.is_cancelled() {
            return Err(LocalError::Closed);
        }
        match (&self.configuration, &request) {
            (Configuration::Embedding(options, limits), Request::Embed(texts, input)) => {
                let refs: Vec<_> = texts.iter().map(String::as_str).collect();
                NativeEmbeddingClient::validate_request(*options, *limits, &refs, *input, context)
                    .map_err(NativeWorkerError::from)?;
            }
            (Configuration::Rerank(options, limits), Request::Score(query, documents)) => {
                let refs: Vec<_> = documents.iter().map(String::as_str).collect();
                GgufRerankClient::validate_request(*options, *limits, query, &refs, context)
                    .map_err(NativeWorkerError::from)?;
            }
            _ => return Err(LocalError::Closed),
        }
        let mut resident = tokio::select! {
            biased;
            _ = context.cancellation().cancelled() => return Err(ContextError::Cancelled.into()),
            _ = tokio::time::sleep_until(context.deadline().into()) => return Err(ContextError::Deadline.into()),
            _ = self.stop.cancelled() => return Err(LocalError::Closed),
            resident = self.state.clone().lock_owned() => resident,
        };
        context.check()?;
        if self.stop.is_cancelled() {
            return Err(LocalError::Closed);
        }
        self.start_idle_timer();
        let owner = self.clone();
        let cancel = context.cancellation().clone();
        let deadline = context.deadline();
        let (mut reply, response) = oneshot::channel();
        tokio::spawn(async move {
            let context = InferenceContext::new(&cancel, deadline);
            let operation = async {
                if resident.worker.is_none() {
                    resident.worker = Some(owner.load(context).await?);
                }
                let result = match (resident.worker.as_ref(), request) {
                    (Some(Worker::Embedding(worker)), Request::Embed(texts, input)) => worker
                        .embed_retained(texts, input, context)
                        .await
                        .map(|batch| Output::Embedding(batch.into_vectors())),
                    (Some(Worker::Rerank(worker)), Request::Score(query, documents)) => worker
                        .score_retained(query, documents, context)
                        .await
                        .map(Output::Rerank),
                    _ => return Err(LocalError::Closed),
                };
                // Retained calls return after native acknowledgement, including cancellation.
                resident.completed = Some(tokio::time::Instant::now());
                owner.changed.notify_one();
                result.map_err(LocalError::Worker)
            };
            tokio::pin!(operation);
            let result = tokio::select! {
                result = &mut operation => result,
                _ = reply.closed() => { cancel.cancel(); operation.await },
                _ = owner.stop.cancelled() => { cancel.cancel(); operation.await },
            };
            let _ = reply.send(result);
            // resident (and any startup join) is retained through the complete operation.
        });
        tokio::select! {
            biased;
            _ = context.cancellation().cancelled() => Err(ContextError::Cancelled.into()),
            _ = tokio::time::sleep_until(context.deadline().into()) => Err(ContextError::Deadline.into()),
            result = response => result.map_err(|_| LocalError::Closed)?,
        }
    }
    pub(crate) async fn embed(
        self: &Arc<Self>,
        texts: Vec<String>,
        input: NativeEmbeddingInput,
        context: InferenceContext<'_>,
    ) -> Result<Vec<Vec<f32>>, LocalError> {
        match self.execute(Request::Embed(texts, input), context).await? {
            Output::Embedding(vectors) => Ok(vectors),
            _ => Err(LocalError::Closed),
        }
    }
    pub(crate) async fn score(
        self: &Arc<Self>,
        query: String,
        documents: Vec<String>,
        context: InferenceContext<'_>,
    ) -> Result<Vec<f64>, LocalError> {
        match self
            .execute(Request::Score(query, documents), context)
            .await?
        {
            Output::Rerank(scores) => Ok(scores),
            _ => Err(LocalError::Closed),
        }
    }
    pub(crate) fn stop(&self) {
        self.stop.cancel();
    }
    pub(crate) async fn shutdown(
        &self,
        context: InferenceContext<'_>,
    ) -> Result<(), NativeWorkerError> {
        self.stop.cancel();
        // Drain owned startup/inference even when the public shutdown deadline has elapsed.
        let mut resident = self.state.lock().await;
        let result = match resident.worker.take() {
            Some(worker) => worker.shutdown(context).await,
            None => context.check().map_err(NativeWorkerError::from),
        };
        resident.completed = None;
        drop(resident);
        let timer = self.timer.lock().unwrap().take();
        if let Some(timer) = timer {
            let _ = timer.await;
        }
        result
    }
}
impl Drop for LocalModel {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphit_ai::{
        local_execution::LocalProvider,
        model_manifest::{RerankPrecision, RerankScoreTransform},
    };
    use std::num::NonZeroU32;
    fn config(root: &std::path::Path) -> LocalRerankConfig {
        let snapshot_path = root.join("tmp");
        let birth = graphit_fs::create_private_directory(&snapshot_path).unwrap();
        let original = graphit_core::artifact_store::SnapshotContext::new(
            Instant::now() + Duration::from_secs(30),
            Cancellation::default(),
        );
        let snapshot_parent = Arc::new(
            CapturedDocumentDirectory::capture(
                &snapshot_path,
                graphit_core::native_document_file::NativeDocumentFileLimits::new(1, 65536, 256)
                    .unwrap(),
                &original,
            )
            .unwrap(),
        );
        snapshot_parent
            .verify_private_handle(&birth, &original)
            .unwrap();
        LocalRerankConfig {
            snapshot_parent,
            source: GgufModelSource {
                model: "bge-reranker-v2-m3".into(),
                revision: "fixture".into(),
                root: root.to_owned(),
                path: "missing.gguf".into(),
                minimum_bytes: 1,
                maximum_bytes: 1200000000,
                sha256: [0; 32],
            },
            options: GgufRerankOptions {
                threads: NonZeroU32::new(1).unwrap(),
                max_tokens: NonZeroU32::new(8192).unwrap(),
                provider: LocalProvider::CPU,
                device_id: 0,
                precision: RerankPrecision::F16,
                score: RerankScoreTransform::RawLogit,
            },
            limits: NativeRerankLimits::new(2, 2, 4096, 4096, 4096).unwrap(),
            capacity: NonZeroUsize::new(1).unwrap(),
            idle_timeout: Duration::from_secs(300),
            shutdown_timeout: Duration::from_secs(3),
        }
    }
    #[tokio::test]
    async fn unused_models_and_invalid_or_cancelled_requests_never_open_weights() {
        let root = tempfile::tempdir().unwrap();
        let model = LocalModel::rerank(config(root.path())).unwrap();
        let cancel = Cancellation::default();
        let context = InferenceContext::new(&cancel, Instant::now() + Duration::from_secs(3));
        assert!(
            model
                .score("x".repeat(4097), vec!["document".into()], context)
                .await
                .is_err()
        );
        cancel.cancel();
        assert!(
            model
                .score("query".into(), vec!["document".into()], context)
                .await
                .is_err()
        );
        assert!(model.state.lock().await.worker.is_none());
        assert!(model.timer.lock().unwrap().is_none());
        let cleanup = Cancellation::default();
        model
            .shutdown(InferenceContext::new(
                &cleanup,
                Instant::now() + Duration::from_secs(3),
            ))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn missing_weights_fail_on_use_and_leave_no_resident_model() {
        let root = tempfile::tempdir().unwrap();
        let model = LocalModel::rerank(config(root.path())).unwrap();
        let cancel = Cancellation::default();
        let context = InferenceContext::new(&cancel, Instant::now() + Duration::from_secs(3));
        assert!(matches!(
            model
                .score("query".into(), vec!["document".into()], context)
                .await,
            Err(LocalError::Worker(_))
        ));
        assert!(model.state.lock().await.worker.is_none());
        model.shutdown(context).await.unwrap();
    }
    async fn drop_waiter_and_drain(
        model: Arc<LocalModel>,
        entered: oneshot::Receiver<()>,
        release: oneshot::Sender<()>,
    ) {
        let original = Cancellation::default();
        let mut waiter = {
            let model = model.clone();
            let original = original.clone();
            tokio::spawn(async move {
                model
                    .score(
                        "query".into(),
                        vec!["document".into()],
                        InferenceContext::new(&original, Instant::now() + Duration::from_secs(60)),
                    )
                    .await
            })
        };
        tokio::select! {
            result = entered => result.expect("expected startup gate remained available"),
            result = &mut waiter => panic!("request completed before the expected startup gate: {result:?}"),
        }
        waiter.abort();
        let _ = waiter.await;
        original.cancelled().await;
        let cleanup = Cancellation::default();
        let shutdown = model.shutdown(InferenceContext::new(
            &cleanup,
            Instant::now() + Duration::from_secs(5),
        ));
        tokio::pin!(shutdown);
        assert!(
            std::future::poll_fn(|cx| {
                use std::future::Future;
                std::task::Poll::Ready(shutdown.as_mut().poll(cx).is_pending())
            })
            .await,
            "shutdown cannot pass a retained startup merely because residency is empty"
        );
        release.send(()).unwrap();
        shutdown.await.unwrap();
        assert!(model.state.lock().await.worker.is_none());
    }
    #[tokio::test]
    async fn dropped_startup_waiter_is_drained_before_shutdown_completes() {
        let root = tempfile::tempdir().unwrap();
        let model = LocalModel::rerank(config(root.path())).unwrap();
        let (entered, waiting) = oneshot::channel();
        let (release, released) = oneshot::channel();
        *model.startup_gate.lock().unwrap() = Some((entered, released));
        drop_waiter_and_drain(model, waiting, release).await;
    }
    #[tokio::test]
    #[ignore = "explicit verified GRAPHIT_TEST_RERANK_BUNDLE GGUF weights"]
    async fn ready_worker_is_joined_after_first_waiter_drops_before_publication() {
        let _sdk = graphit_ai::native_embedding::NativeSdkRoot::new().unwrap();
        let bundle =
            std::path::PathBuf::from(std::env::var_os("GRAPHIT_TEST_RERANK_BUNDLE").unwrap())
                .canonicalize()
                .unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(bundle.join("model.json")).unwrap()).unwrap();
        let fixture = tempfile::tempdir().unwrap();
        let global = fixture.path().join("global");
        let _birth = graphit_fs::create_private_directory(&global).unwrap();
        let mut config = config(&global);
        assert_eq!(
            config.snapshot_parent.canonical_path(),
            global.join("tmp").canonicalize().unwrap()
        );
        config.source.root = bundle.clone();
        let artifact = &manifest["artifacts"][0];
        config.source.model = manifest["id"].as_str().unwrap().into();
        config.source.revision = manifest["revision"].as_str().unwrap().into();
        config.source.path = artifact["path"].as_str().unwrap().into();
        config.source.minimum_bytes = artifact["minimum_bytes"].as_u64().unwrap();
        config.source.sha256 = serde_json::from_value(artifact["digest"].clone()).unwrap();
        let model = LocalModel::rerank(config).unwrap();
        let (entered, waiting) = oneshot::channel();
        let (release, released) = oneshot::channel();
        *model.ready_gate.lock().unwrap() = Some((entered, released));
        drop_waiter_and_drain(model, waiting, release).await;
    }
}
