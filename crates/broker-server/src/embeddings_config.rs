//! Captured native embeddings configuration and verified provider preparation.
use super::*;
use broker_control::{EmbeddingAdmissionLimits, EmbeddingCacheLimits};
use broker_presence::{
    EmbeddingBackend, EmbeddingsHttpConfig, LocalEmbeddingConfig, RemoteEmbeddingsConfig,
};
use graphit_ai::{
    context::InferenceContext,
    embedding::EmbeddingLimits,
    google_embedding::GoogleFamily,
    local_execution::LocalProvider,
    model_artifact::GgufModelSource,
    model_manifest::{
        ArtifactFormat, GemmaPrecision, ManifestLimits, ModelBackend, ModelManifest,
        decode_manifest,
    },
    native_embedding::{NativeEmbeddingOptions, NativeWeightPrecision},
};
use graphit_core::{file_lock::Cancellation, native_document_file::CapturedDocumentDirectory};
use graphit_http::client::{BoundedClient, ClientPolicy, Limits};
use serde::Serialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Services {
    embeddings: Option<Embeddings>,
    rerank: Option<super::rerank_config::Rerank>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Embeddings {
    enabled: bool,
    #[serde(default)]
    revision: String,
    #[serde(default)]
    dimensions: usize,
    #[serde(default)]
    max_batch: usize,
    #[serde(default)]
    max_input_bytes: usize,
    request_timeout: Option<Budget>,
    required_scopes: Option<Vec<String>>,
    request_body_bytes: Option<NonZeroUsize>,
    response_body_bytes: Option<NonZeroUsize>,
    identity_json_bytes: Option<NonZeroUsize>,
    grants_json_bytes: Option<NonZeroUsize>,
    vector_json_bytes: Option<NonZeroUsize>,
    metadata_bytes: Option<NonZeroUsize>,
    upstream: Option<Upstream>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    protocol: String,
    #[serde(default)]
    model: String,
    model_revision: Option<String>,
    recipe: Option<String>,
    url: Option<String>,
    api_key: Option<Secret>,
    api_key_header: Option<String>,
    api_key_scheme: Option<String>,
    #[serde(default)]
    send_dimensions: bool,
    transport: Option<Transport>,
    directory: Option<PathBuf>,
    manifest_file: Option<PathBuf>,
    max_artifact_bytes: Option<NonZeroU64>,
    threads: Option<NonZeroU32>,
    queue_capacity: Option<NonZeroUsize>,
    idle_timeout_seconds: Option<NonZeroU64>,
    device: Option<String>,
    #[serde(default)]
    device_id: i32,
    manifest_limits: Option<ManifestBounds>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Transport {
    pub(super) request_body_bytes: NonZeroUsize,
    pub(super) response_body_bytes: NonZeroUsize,
    pub(super) url_bytes: NonZeroUsize,
    pub(super) header_bytes: NonZeroUsize,
    pub(super) header_count: NonZeroUsize,
    pub(super) max_in_flight: NonZeroUsize,
    pub(super) max_idle_per_host: NonZeroUsize,
    pub(super) idle_timeout: Budget,
    pub(super) max_certificates: NonZeroUsize,
    pub(super) max_certificate_bytes: NonZeroUsize,
    #[serde(default)]
    pub(super) allow_loopback_http: bool,
    pub(super) ca_file: Option<PathBuf>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestBounds {
    pub(super) max_manifest_bytes: NonZeroUsize,
    pub(super) max_artifacts: NonZeroUsize,
    pub(super) max_role_bytes: NonZeroUsize,
    pub(super) max_relative_path_bytes: NonZeroUsize,
    pub(super) max_id_bytes: NonZeroUsize,
    pub(super) max_revision_bytes: NonZeroUsize,
    pub(super) max_dimension: NonZeroU64,
    pub(super) max_tokens: NonZeroU64,
}
impl ManifestBounds {
    pub(super) fn limits(&self) -> ManifestLimits {
        ManifestLimits {
            max_manifest_bytes: self.max_manifest_bytes.get(),
            max_artifacts: self.max_artifacts.get(),
            max_role_bytes: self.max_role_bytes.get(),
            max_relative_path_bytes: self.max_relative_path_bytes.get(),
            max_id_bytes: self.max_id_bytes.get(),
            max_revision_bytes: self.max_revision_bytes.get(),
            max_dimension: self.max_dimension.get(),
            max_tokens: self.max_tokens.get(),
        }
    }
}
#[derive(Clone, Serialize)]
pub(super) struct ServicesView {
    #[serde(skip_serializing_if = "Option::is_none")]
    embeddings: Option<EmbeddingsView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rerank: Option<serde_json::Value>,
}
#[derive(Clone, Serialize)]
struct EmbeddingsView {
    enabled: bool,
    revision: String,
    model: String,
    model_revision: String,
    recipe: String,
    dimensions: NonZeroUsize,
    max_batch: NonZeroUsize,
    max_input_bytes: NonZeroUsize,
    request_timeout: admin_config_view::Time,
    required_scopes: Vec<String>,
    request_body_bytes: NonZeroUsize,
    response_body_bytes: NonZeroUsize,
    identity_json_bytes: NonZeroUsize,
    grants_json_bytes: NonZeroUsize,
    vector_json_bytes: NonZeroUsize,
    metadata_bytes: NonZeroUsize,
    upstream: UpstreamView,
}
#[derive(Clone, Serialize)]
struct UpstreamView {
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<TransportView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_limits: Option<ManifestBounds>,
    protocol: String,
    model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    api_key: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key_scheme: Option<String>,
    send_dimensions: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    directory: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_artifact_bytes: Option<NonZeroU64>,
    threads: Option<NonZeroU32>,
    queue_capacity: Option<NonZeroUsize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idle_timeout_seconds: Option<NonZeroU64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<i32>,
}
pub(crate) struct PreparedEmbeddings {
    pub http: EmbeddingsHttpConfig,
    pub backend: Arc<EmbeddingBackend>,
    pub(super) view: ServicesView,
}
fn required<T>(value: Option<T>) -> Result<T, ServerError> {
    value.ok_or(ServerError::Configuration)
}
fn nz(value: usize) -> Result<NonZeroUsize, ServerError> {
    let value = NonZeroUsize::new(value).ok_or(ServerError::Configuration)?;
    presence_sql_cap(value)?;
    Ok(value)
}
fn sdk_limits(
    batch: NonZeroUsize,
    input: NonZeroUsize,
    dimensions: usize,
    request: usize,
    response: usize,
) -> Result<EmbeddingLimits, ServerError> {
    EmbeddingLimits::new(
        batch.get(),
        input.get(),
        dimensions,
        batch
            .get()
            .checked_mul(dimensions)
            .ok_or(ServerError::Configuration)?,
        batch.get(),
        request,
        response,
    )
    .map_err(|_| ServerError::Configuration)
}
fn safe_model(model: &str) -> bool {
    !model.is_empty()
        && model != "."
        && model != ".."
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn google(protocol: &str) -> bool {
    matches!(
        protocol,
        "google" | "google-embed-content-v1beta" | "gemini" | "gemini-embed-content-v1beta"
    )
}
pub(super) fn google_endpoints(
    endpoint: &str,
    model: &str,
) -> Result<(String, String, String, GoogleFamily), ServerError> {
    let model = model.strip_prefix("models/").unwrap_or(model);
    if !safe_model(model) {
        return Err(ServerError::Configuration);
    }
    let resource = format!("models/{model}");
    let mut batch = Url::parse(endpoint).map_err(|_| ServerError::Configuration)?;
    if !batch.path().ends_with(":batchEmbedContents") {
        let path = format!(
            "{}/{resource}:batchEmbedContents",
            batch.path().trim_end_matches('/')
        );
        batch.set_path(&path);
    }
    let mut single = batch.clone();
    let path = single
        .path()
        .strip_suffix(":batchEmbedContents")
        .ok_or(ServerError::Configuration)?;
    single.set_path(&format!("{path}:embedContent"));
    let family = if model.to_ascii_lowercase().starts_with("gemini-embedding-2") {
        GoogleFamily::Gemini2
    } else {
        GoogleFamily::Gemini1
    };
    Ok((single.into(), batch.into(), resource, family))
}
pub(super) fn local_provider(value: Option<&str>) -> Result<LocalProvider, ServerError> {
    match value.unwrap_or("cpu") {
        "cpu" => Ok(LocalProvider::CPU),
        "cuda" => Ok(LocalProvider::CUDA),
        "metal" => Ok(LocalProvider::Metal),
        "auto" => Ok(LocalProvider::Auto),
        _ => Err(ServerError::Configuration),
    }
}
pub(super) fn local_threads(value: Option<NonZeroU32>) -> Result<NonZeroU32, ServerError> {
    match value {
        Some(value) => Ok(value),
        None => NonZeroU32::new(
            u32::try_from(
                std::thread::available_parallelism()
                    .map_err(|_| ServerError::Configuration)?
                    .get()
                    .div_ceil(2),
            )
            .map_err(|_| ServerError::Configuration)?,
        )
        .ok_or(ServerError::Configuration),
    }
}
pub(super) fn local_idle_timeout(value: Option<NonZeroU64>) -> Result<Duration, ServerError> {
    let timeout = Duration::from_secs(value.map_or(300, NonZeroU64::get));
    Instant::now()
        .checked_add(timeout)
        .ok_or(ServerError::Configuration)?;
    Ok(timeout)
}
pub(super) fn gguf_source(
    manifest: &ModelManifest,
    role: &str,
    root: PathBuf,
    maximum_bytes: u64,
) -> Result<GgufModelSource, ServerError> {
    let artifact = manifest
        .artifacts
        .iter()
        .find(|a| a.role == role && a.required && a.format == ArtifactFormat::Gguf)
        .ok_or(ServerError::Configuration)?;
    if artifact.minimum_bytes > maximum_bytes {
        return Err(ServerError::Configuration);
    }
    Ok(GgufModelSource {
        model: manifest.id.clone(),
        revision: manifest.revision.clone(),
        root,
        path: artifact.path.clone(),
        minimum_bytes: artifact.minimum_bytes,
        maximum_bytes,
        sha256: artifact.digest,
    })
}
pub(super) fn local_identity(manifest: &[u8]) -> Result<Vec<u8>, ServerError> {
    let manifest: serde_json::Value =
        serde_json::from_slice(manifest).map_err(|_| ServerError::Configuration)?;
    serde_json::to_vec(&manifest).map_err(|_| ServerError::Configuration)
}
/// A named recipe is a deployment contract, not an execution-device choice.
/// Otherwise derive it from the verified manifest, including weights/precision
/// and the actual query/document recipe, without operational settings.
pub(super) fn local_recipe(
    manifest: &[u8],
    declared: Option<String>,
) -> Result<String, ServerError> {
    use sha2::{Digest, Sha256};
    if let Some(recipe) = declared {
        return declared_metadata(recipe);
    }
    let bytes = local_identity(manifest)?;
    use std::fmt::Write;
    let mut recipe = String::with_capacity(81);
    recipe.push_str("gguf-manifest-v1:");
    for byte in Sha256::digest(bytes) {
        write!(&mut recipe, "{byte:02x}").expect("writing a digest to String");
    }
    Ok(recipe)
}
impl ServicesView {
    pub(super) fn combined(
        embeddings: Option<&PreparedEmbeddings>,
        rerank: Option<&super::rerank_config::PreparedRerank>,
    ) -> Option<Self> {
        if embeddings.is_none() && rerank.is_none() {
            return None;
        }
        Some(Self {
            embeddings: embeddings.and_then(|e| e.view.embeddings.clone()),
            rerank: rerank.map(|r| r.view.clone()),
        })
    }
}
impl Services {
    pub(super) fn needs_native_sdk(&self) -> bool {
        self.embeddings.as_ref().is_some_and(|c| {
            c.enabled
                && c.upstream.as_ref().is_some_and(|u| {
                    u.protocol
                        .trim()
                        .eq_ignore_ascii_case("gguf-embeddinggemma2")
                })
        }) || self.rerank.as_ref().is_some_and(|c| c.needs_native_sdk())
    }
    pub(super) async fn prepare_all(
        self,
        snapshot_parent: Option<Arc<CapturedDocumentDirectory>>,
        base: &Path,
        audience: &str,
        startup_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> Result<
        (
            Option<PreparedEmbeddings>,
            Option<super::rerank_config::PreparedRerank>,
        ),
        ServerError,
    > {
        Instant::now()
            .checked_add(shutdown_timeout)
            .ok_or(ServerError::Configuration)?;
        let embeddings = match self.embeddings.filter(|c| c.enabled) {
            Some(c) => Some(
                c.prepare(
                    snapshot_parent.clone(),
                    base,
                    audience,
                    startup_timeout,
                    shutdown_timeout,
                )
                .await?,
            ),
            None => None,
        };
        let rerank = match self.rerank.filter(|c| c.enabled) {
            Some(c) => match c
                .prepare(
                    snapshot_parent,
                    base,
                    audience,
                    startup_timeout,
                    shutdown_timeout,
                )
                .await
            {
                Ok(prepared) => Some(prepared),
                Err(error) => {
                    if let Some(embedding) = &embeddings {
                        let cancel = Cancellation::default();
                        let end = Instant::now()
                            .checked_add(startup_timeout)
                            .ok_or(ServerError::Configuration)?;
                        let _ = embedding
                            .backend
                            .shutdown(InferenceContext::new(&cancel, end))
                            .await;
                    }
                    return Err(error);
                }
            },
            None => None,
        };
        Ok((embeddings, rerank))
    }
}
impl Embeddings {
    async fn prepare(
        self,
        snapshot_parent: Option<Arc<CapturedDocumentDirectory>>,
        base: &Path,
        audience: &str,
        startup_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> Result<PreparedEmbeddings, ServerError> {
        let scopes = required(self.required_scopes)?;
        presence_scopes(&scopes, true)?;
        let max_batch = nz(if self.max_batch == 0 {
            256
        } else {
            self.max_batch
        })?;
        let max_input = nz(if self.max_input_bytes == 0 {
            1024 * 1024
        } else {
            self.max_input_bytes
        })?;
        let request_timeout = self
            .request_timeout
            .map(|v| v.0)
            .unwrap_or(Duration::from_secs(45));
        let request = required(self.request_body_bytes)?;
        let response = required(self.response_body_bytes)?;
        let identity = required(self.identity_json_bytes)?;
        let grants = required(self.grants_json_bytes)?;
        let vector = required(self.vector_json_bytes)?;
        let metadata = required(self.metadata_bytes)?;
        for cap in [request, response, identity, grants, vector, metadata] {
            presence_sql_cap(cap)?;
        }
        let mut upstream = required(self.upstream)?;
        upstream.protocol = upstream.protocol.trim().to_ascii_lowercase();
        let local = upstream.protocol == "gguf-embeddinggemma2";
        let mut view = UpstreamView {
            transport: upstream
                .transport
                .as_ref()
                .map(|t| t.view(base))
                .transpose()?,
            manifest_limits: upstream.manifest_limits.clone(),
            protocol: upstream.protocol.clone(),
            model: upstream.model.clone(),
            url: upstream.url.clone(),
            api_key: upstream
                .api_key
                .as_ref()
                .map(admin_config_view::secret_marker)
                .unwrap_or(""),
            api_key_header: upstream.api_key_header.clone(),
            api_key_scheme: upstream.api_key_scheme.clone(),
            send_dimensions: upstream.send_dimensions,
            directory: None,
            manifest_file: None,
            max_artifact_bytes: upstream.max_artifact_bytes,
            threads: upstream.threads,
            queue_capacity: upstream.queue_capacity,
            idle_timeout_seconds: upstream.idle_timeout_seconds,
            device: None,
            device_id: None,
        };
        let (backend, revision, model_revision, recipe) = if local {
            if upstream.model_revision.is_some() {
                return Err(ServerError::Configuration);
            }
            if upstream.url.is_some()
                || upstream.api_key.is_some()
                || upstream.api_key_header.is_some()
                || upstream.api_key_scheme.is_some()
                || upstream.send_dimensions
                || upstream.transport.is_some()
            {
                return Err(ServerError::Configuration);
            }
            let model = declared_metadata(upstream.model.clone())?;
            let bundle = resolve(base, required(upstream.directory)?)?
                .canonicalize()
                .map_err(|_| ServerError::ConfigurationIo)?;
            let manifest_path = resolve(base, required(upstream.manifest_file)?)?;
            let bounds = required(upstream.manifest_limits)?;
            let maximum_bytes = required(upstream.max_artifact_bytes)?.get();
            let threads = local_threads(upstream.threads)?;
            let capacity = upstream
                .queue_capacity
                .unwrap_or(NonZeroUsize::new(8).unwrap());
            let end = Instant::now()
                .checked_add(startup_timeout)
                .ok_or(ServerError::Configuration)?;
            let cancel = Cancellation::default();
            let context = InferenceContext::new(&cancel, end);
            let bytes = read_bounded(
                &manifest_path,
                bounds.max_manifest_bytes.get(),
                ServerError::ConfigurationIo,
            )?;
            let manifest = decode_manifest(&bytes, &bounds.limits(), &mut || {
                context.check().map_err(std::io::Error::other)
            })
            .map_err(|_| ServerError::Configuration)?;
            if manifest.id != model {
                return Err(ServerError::Configuration);
            }
            let ModelBackend::EmbeddingGemma2 {
                ref model_role,
                ref recipe,
            } = manifest.backend
            else {
                return Err(ServerError::Configuration);
            };
            let dimensions =
                usize::try_from(recipe.dimensions).map_err(|_| ServerError::Configuration)?;
            if self.dimensions != 0 && self.dimensions != dimensions {
                return Err(ServerError::Configuration);
            }
            let prefix = graphit_ai::model_manifest::GemmaEmbeddingRecipe::QUERY_PREFIX
                .len()
                .max(graphit_ai::model_manifest::GemmaEmbeddingRecipe::DOCUMENT_PREFIX.len());
            let sdk_input = nz(max_batch
                .get()
                .checked_mul(prefix)
                .and_then(|n| max_input.get().checked_add(n))
                .ok_or(ServerError::Configuration)?)?;
            let limits = sdk_limits(
                max_batch,
                sdk_input,
                dimensions,
                request.get(),
                response.get(),
            )?;
            let source = gguf_source(&manifest, model_role, bundle.clone(), maximum_bytes)?;
            let options = NativeEmbeddingOptions {
                provider: local_provider(upstream.device.as_deref())?,
                device_id: upstream.device_id,
                threads,
                max_tokens: NonZeroU32::new(
                    u32::try_from(recipe.max_tokens).map_err(|_| ServerError::Configuration)?,
                )
                .ok_or(ServerError::Configuration)?,
                dimensions,
                precision: match recipe.precision {
                    GemmaPrecision::Bf16 => NativeWeightPrecision::Bf16,
                    GemmaPrecision::F32 => NativeWeightPrecision::F32,
                },
            };
            let idle_timeout = local_idle_timeout(upstream.idle_timeout_seconds)?;
            let identity = local_identity(&bytes)?;
            view.device = Some(upstream.device.clone().unwrap_or_else(|| "cpu".into()));
            view.device_id = Some(options.device_id);
            view.threads = Some(threads);
            view.queue_capacity = Some(capacity);
            view.idle_timeout_seconds = NonZeroU64::new(idle_timeout.as_secs());
            view.model = source.model.clone();
            view.directory = Some(bundle);
            view.manifest_file = Some(manifest_path);
            let model_revision = source.revision.clone();
            let backend = EmbeddingBackend::local(
                LocalEmbeddingConfig {
                    snapshot_parent: snapshot_parent.ok_or(ServerError::Configuration)?,
                    source,
                    options,
                    limits,
                    capacity,
                    idle_timeout,
                    shutdown_timeout,
                },
                &identity,
            );
            let prefix = if self.revision.trim().is_empty() {
                view.model.as_str()
            } else {
                self.revision.trim()
            };
            let revision = format!(
                "{prefix}@sha256:{}",
                backend.local_identity().ok_or(ServerError::Configuration)?
            );
            let recipe = local_recipe(&bytes, upstream.recipe)?;
            (backend, revision, model_revision, recipe)
        } else {
            if upstream.directory.is_some()
                || upstream.manifest_file.is_some()
                || upstream.max_artifact_bytes.is_some()
                || upstream.threads.is_some()
                || upstream.queue_capacity.is_some()
                || upstream.idle_timeout_seconds.is_some()
                || upstream.device.is_some()
                || upstream.device_id != 0
                || upstream.manifest_limits.is_some()
                || self.revision.trim().is_empty()
            {
                return Err(ServerError::Configuration);
            }
            let model_revision = declared_metadata(required(upstream.model_revision)?)?;
            let recipe = declared_metadata(required(upstream.recipe)?)?;
            let dimensions = nz(self.dimensions)?;
            let transport = required(upstream.transport)?;
            let endpoint = required(upstream.url)?;
            let url = Url::parse(&endpoint).map_err(|_| ServerError::Configuration)?;
            let origin = url.origin().ascii_serialization();
            let mut roots = Vec::new();
            if let Some(path) = transport.ca_file {
                let bytes = read_bounded(
                    &resolve(base, path)?,
                    transport.max_certificate_bytes.get(),
                    ServerError::Certificate,
                )?;
                for cert in CertificateDer::pem_slice_iter(&bytes) {
                    roots.push(
                        cert.map_err(|_| ServerError::Certificate)?
                            .as_ref()
                            .to_vec(),
                    );
                }
                if roots.is_empty() {
                    return Err(ServerError::Certificate);
                }
            }
            let root_refs = roots.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let limits = Limits {
                request_body_bytes: transport.request_body_bytes.get(),
                response_body_bytes: transport.response_body_bytes.get(),
                url_bytes: transport.url_bytes.get(),
                header_bytes: transport.header_bytes.get(),
                header_count: transport.header_count.get(),
                max_in_flight: transport.max_in_flight.get(),
                max_idle_per_host: transport.max_idle_per_host.get(),
                idle_timeout: transport.idle_timeout.0,
                max_certificates: transport.max_certificates.get(),
                max_certificate_bytes: transport.max_certificate_bytes.get(),
            };
            let is_google = google(&upstream.protocol);
            let (endpoint, batch_endpoint, model, family) = if is_google {
                let (one, batch, model, family) = google_endpoints(&endpoint, &upstream.model)?;
                (one, Some(batch), model, Some(family))
            } else {
                (endpoint, None, upstream.model, None)
            };
            let prefix = family.map(|f| f.max_input_prefix_bytes()).unwrap_or(0);
            let sdk_input = nz(max_batch
                .get()
                .checked_mul(prefix)
                .and_then(|extra| max_input.get().checked_add(extra))
                .ok_or(ServerError::Configuration)?)?;
            let embedding_limits = sdk_limits(
                max_batch,
                sdk_input,
                dimensions.get(),
                limits.request_body_bytes,
                limits.response_body_bytes,
            )?;
            let client = BoundedClient::new(
                ClientPolicy {
                    origin: &origin,
                    allow_loopback_http: transport.allow_loopback_http,
                    proxy: None,
                    additional_roots: &root_refs,
                },
                limits,
            )
            .map_err(|_| ServerError::Configuration)?;
            let mut headers = axum::http::HeaderMap::new();
            if let Some(key) = upstream.api_key.filter(|v| !v.0.is_empty()) {
                let name = upstream
                    .api_key_header
                    .as_deref()
                    .filter(|v| !v.is_empty())
                    .unwrap_or(if is_google {
                        "x-goog-api-key"
                    } else {
                        "Authorization"
                    });
                let name = axum::http::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| ServerError::Configuration)?;
                if matches!(
                    name.as_str(),
                    "host"
                        | "content-type"
                        | "content-length"
                        | "transfer-encoding"
                        | "connection"
                        | "trailer"
                        | "upgrade"
                ) {
                    return Err(ServerError::Configuration);
                }
                let scheme = upstream
                    .api_key_scheme
                    .as_deref()
                    .filter(|v| !v.is_empty())
                    .unwrap_or(if is_google { "" } else { "Bearer" })
                    .trim();
                let value = Zeroizing::new(if scheme.is_empty() {
                    key.0.to_string()
                } else {
                    format!("{scheme} {}", key.0.as_str())
                });
                let mut value = axum::http::HeaderValue::from_str(&value)
                    .map_err(|_| ServerError::Configuration)?;
                value.set_sensitive(true);
                headers.insert(name, value);
            }
            let backend = EmbeddingBackend::remote(RemoteEmbeddingsConfig {
                client,
                protocol: upstream.protocol,
                endpoint,
                batch_endpoint,
                model,
                dimensions: dimensions.get(),
                request_dimensions: upstream.send_dimensions.then_some(dimensions.get()),
                google_family: family,
                headers,
                limits: embedding_limits,
            })
            .map_err(|_| ServerError::Configuration)?;
            (backend, self.revision, model_revision, recipe)
        };
        let dimensions = nz(backend.dimensions())?;
        let model = declared_metadata(backend.model().to_owned())?;
        let http = EmbeddingsHttpConfig {
            revision: revision.clone(),
            model: model.clone(),
            model_revision: model_revision.clone(),
            recipe: recipe.clone(),
            dimensions,
            max_batch,
            max_input_bytes: max_input,
            request_body_bytes: request,
            response_body_bytes: response,
            request_timeout,
            local_audience: audience.to_owned(),
            required_scopes: scopes.clone(),
            admission_limits: EmbeddingAdmissionLimits {
                identity_json_bytes: identity,
                grants_json_bytes: grants,
            },
            cache_limits: EmbeddingCacheLimits {
                dimensions,
                max_entries: max_batch,
                vector_json_bytes: vector,
                metadata_bytes: metadata,
            },
        };
        let view = ServicesView {
            embeddings: Some(EmbeddingsView {
                enabled: true,
                revision,
                model,
                model_revision,
                recipe,
                dimensions,
                max_batch,
                max_input_bytes: max_input,
                request_timeout: admin_config_view::Time(request_timeout),
                required_scopes: scopes,
                request_body_bytes: request,
                response_body_bytes: response,
                identity_json_bytes: identity,
                grants_json_bytes: grants,
                vector_json_bytes: vector,
                metadata_bytes: metadata,
                upstream: view,
            }),
            rerank: None,
        };
        Ok(PreparedEmbeddings {
            http,
            backend: Arc::new(backend),
            view,
        })
    }
}

#[derive(Clone, Serialize)]
pub(super) struct TransportView {
    request_body_bytes: NonZeroUsize,
    response_body_bytes: NonZeroUsize,
    url_bytes: NonZeroUsize,
    header_bytes: NonZeroUsize,
    header_count: NonZeroUsize,
    max_in_flight: NonZeroUsize,
    max_idle_per_host: NonZeroUsize,
    idle_timeout: admin_config_view::Time,
    max_certificates: NonZeroUsize,
    max_certificate_bytes: NonZeroUsize,
    allow_loopback_http: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_file: Option<PathBuf>,
}
impl Transport {
    pub(super) fn view(&self, base: &Path) -> Result<TransportView, ServerError> {
        Ok(TransportView {
            request_body_bytes: self.request_body_bytes,
            response_body_bytes: self.response_body_bytes,
            url_bytes: self.url_bytes,
            header_bytes: self.header_bytes,
            header_count: self.header_count,
            max_in_flight: self.max_in_flight,
            max_idle_per_host: self.max_idle_per_host,
            idle_timeout: admin_config_view::Time(self.idle_timeout.0),
            max_certificates: self.max_certificates,
            max_certificate_bytes: self.max_certificate_bytes,
            allow_loopback_http: self.allow_loopback_http,
            ca_file: self
                .ca_file
                .as_ref()
                .map(|p| resolve(base, p.clone()))
                .transpose()?,
        })
    }
}

/// Public provenance is declared exactly; normalization must not invent a revision.
pub(super) fn declared_metadata(value: String) -> Result<String, ServerError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(ServerError::Configuration);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_recipe_tracks_verified_manifest_and_explicit_semantics() {
        let manifest = br#"{"model":"fixture","weights":"sha256:a","recipe":{"precision":"F16","dimensions":768,"query":"query:","document":"document:"}}"#;
        let semantic = local_recipe(manifest, None).unwrap();
        let pretty = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(manifest).unwrap(),
        )
        .unwrap();
        assert_eq!(
            local_identity(manifest).unwrap(),
            local_identity(&pretty).unwrap()
        );
        assert_eq!(semantic, local_recipe(&pretty, None).unwrap());
        let mut changed: serde_json::Value = serde_json::from_slice(manifest).unwrap();
        for field in ["precision", "query", "document", "dimensions"] {
            let previous = changed["recipe"][field].clone();
            changed["recipe"][field] = serde_json::json!("changed");
            assert_ne!(
                semantic,
                local_recipe(&serde_json::to_vec(&changed).unwrap(), None).unwrap()
            );
            changed["recipe"][field] = previous;
        }
        changed["weights"] = serde_json::json!("sha256:b");
        assert_ne!(
            semantic,
            local_recipe(&serde_json::to_vec(&changed).unwrap(), None).unwrap()
        );
        assert_eq!(
            local_recipe(manifest, Some("deployment-retrieval-v1".into())).unwrap(),
            "deployment-retrieval-v1"
        );
        for invalid in ["", " padded ", "line\nbreak"] {
            assert!(local_recipe(manifest, Some(invalid.into())).is_err());
        }
    }
    fn remote() -> serde_json::Value {
        serde_json::json!({"embeddings":{
            "enabled":true,"revision":"space-v1","dimensions":2,"required_scopes":[],
            "request_body_bytes":4096,"response_body_bytes":16384,"identity_json_bytes":8192,
            "grants_json_bytes":16384,"vector_json_bytes":256,"metadata_bytes":4096,
            "upstream":{"protocol":" OpenAI-compatible ","model":"fixture","model_revision":"fixture-model-r1","recipe":"retrieval-v1","url":"http://127.0.0.1:19091/embeddings",
                "api_key":"synthetic-private-config-key","transport":{
                    "request_body_bytes":65536,"response_body_bytes":65536,"url_bytes":2048,
                    "header_bytes":4096,"header_count":32,"max_in_flight":2,"max_idle_per_host":2,
                    "idle_timeout":"30s","max_certificates":8,"max_certificate_bytes":65536,"allow_loopback_http":true}}
        }})
    }
    async fn parse(value: serde_json::Value) -> Result<Option<PreparedEmbeddings>, ServerError> {
        let config: Services =
            serde_json::from_value(value).map_err(|_| ServerError::Configuration)?;
        config
            .prepare_all(
                None,
                Path::new("."),
                "native-api",
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .await
            .map(|(embeddings, _)| embeddings)
    }
    #[test]
    fn local_idle_policy_is_positive_and_defaults_to_five_minutes() {
        assert_eq!(local_idle_timeout(None).unwrap(), Duration::from_secs(300));
        assert_eq!(
            local_idle_timeout(NonZeroU64::new(1)).unwrap(),
            Duration::from_secs(1)
        );
        assert!(
            serde_json::from_value::<Upstream>(
                serde_json::json!({"protocol":"gguf-embeddinggemma2","idle_timeout_seconds":0})
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn captured_embeddings_defaults_redaction_and_strict_boundaries() {
        let prepared = parse(remote()).await.unwrap().unwrap();
        assert_eq!(prepared.http.max_batch.get(), 256);
        assert_eq!(prepared.http.max_input_bytes.get(), 1024 * 1024);
        assert_eq!(prepared.http.request_timeout, Duration::from_secs(45));
        assert_eq!(prepared.http.local_audience, "native-api");
        let view = serde_json::to_string(&prepared.view).unwrap();
        assert!(!view.contains("synthetic-private-config-key"));
        assert!(view.contains("[configured-secret]"));
        assert!(view.contains("request_body_bytes"));
        assert!(view.contains("allow_loopback_http"));
        let document = include_str!("../../../docs/rust-broker-server.md");
        let section = document.split_once("## Native embeddings").unwrap().1;
        let example = section
            .split_once("```yaml\n")
            .unwrap()
            .1
            .split_once("\n```")
            .unwrap()
            .0;
        let example: serde_json::Value = serde_saphyr::from_str(example).unwrap();
        let documented = parse(example["services"].clone()).await.unwrap().unwrap();
        assert_eq!(documented.http.dimensions.get(), 1536);
        assert_eq!(documented.http.revision, "embedding-space-v1");
        documented.backend.stop();
        let mut padded = remote();
        padded["embeddings"]["revision"] = serde_json::json!(" space-v1 ");
        let padded = parse(padded).await.unwrap().unwrap();
        assert_eq!(padded.http.revision, " space-v1 ");
        padded.backend.stop();
        let mut unknown = remote();
        unknown["embeddings"]["route"] = serde_json::json!("not-supported");
        assert!(matches!(
            parse(unknown).await,
            Err(ServerError::Configuration)
        ));
        let mut inert = remote();
        inert["embeddings"]["upstream"]["timeout"] = serde_json::json!("45s");
        assert!(matches!(
            parse(inert).await,
            Err(ServerError::Configuration)
        ));
        let mut local = remote();
        local["embeddings"]["upstream"]["device"] = serde_json::json!("cpu");
        assert!(matches!(
            parse(local).await,
            Err(ServerError::Configuration)
        ));
        let mut overflow = remote();
        overflow["embeddings"]["max_batch"] = serde_json::json!(usize::MAX);
        assert!(matches!(
            parse(overflow).await,
            Err(ServerError::Configuration)
        ));
        let mut injection = remote();
        injection["embeddings"]["upstream"]["api_key_header"] = serde_json::json!("Content-Length");
        assert!(matches!(
            parse(injection).await,
            Err(ServerError::Configuration)
        ));
        prepared.backend.stop();
    }
    #[tokio::test]
    async fn disabled_embeddings_and_gguf_require_explicit_captured_artifacts() {
        assert!(
            parse(serde_json::json!({"embeddings":{"enabled":false}}))
                .await
                .unwrap()
                .is_none()
        );
        let mut gguf = remote();
        gguf["embeddings"]["upstream"] =
            serde_json::json!({"protocol":"gguf-embeddinggemma2","directory":"relative/model"});
        assert!(matches!(parse(gguf).await, Err(ServerError::Configuration)));
        let (single, batch, model, family) =
            google_endpoints("https://example.test/v1beta", "gemini-embedding-2-preview").unwrap();
        assert_eq!(
            single,
            "https://example.test/v1beta/models/gemini-embedding-2-preview:embedContent"
        );
        assert_eq!(
            batch,
            "https://example.test/v1beta/models/gemini-embedding-2-preview:batchEmbedContents"
        );
        assert_eq!(model, "models/gemini-embedding-2-preview");
        assert!(matches!(family, GoogleFamily::Gemini2));
        assert!(google_endpoints("https://example.test/v1beta", "../escape").is_err());
    }
    #[tokio::test]
    async fn remote_model_provenance_is_required_and_cannot_be_normalized_or_invented() {
        for field in ["model_revision", "recipe"] {
            for value in [
                serde_json::Value::Null,
                serde_json::json!(""),
                serde_json::json!(" padded "),
                serde_json::json!("invalid\nvalue"),
            ] {
                let mut document = remote();
                document["embeddings"]["upstream"][field] = value;
                assert!(matches!(
                    parse(document).await,
                    Err(ServerError::Configuration)
                ));
            }
        }
        let prepared = parse(remote()).await.unwrap().unwrap();
        assert_ne!(prepared.http.revision, prepared.http.model_revision);
        assert!(!prepared.http.model.is_empty());
        assert!(!prepared.http.recipe.is_empty());
        prepared.backend.stop();
    }
}
