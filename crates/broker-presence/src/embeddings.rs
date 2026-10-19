//! Authenticated embeddings over the existing SQL owners and Code inference SDK.
mod provider;
mod request;
pub use provider::{EmbeddingBackend, RemoteEmbeddingsConfig};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::post,
};
use broker_control::{
    BrokerAccessVerifier, ControlError, EmbeddingAdmission, EmbeddingAdmissionError,
    EmbeddingAdmissionLimits, EmbeddingCacheEntry, EmbeddingCacheError, EmbeddingCacheKey,
    EmbeddingCacheLimits, EmbeddingCacheProvenance, PostgresControlStore, SqliteControlStore,
    UpstreamBearerVerifier, new_admin_request_id,
};
use graphit_core::file_lock::Cancellation;
use headers::{Authorization, Header, authorization::Bearer};
use serde::Serialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt,
    io::{self, Write},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddingsError {
    Configuration,
}
impl fmt::Display for EmbeddingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid embeddings configuration")
    }
}
impl std::error::Error for EmbeddingsError {}

#[derive(Clone)]
pub struct EmbeddingsHttpConfig {
    /// Revision of the service configuration, separate from model provenance.
    pub revision: String,
    pub model: String,
    pub model_revision: String,
    pub recipe: String,
    pub dimensions: NonZeroUsize,
    pub max_batch: NonZeroUsize,
    pub max_input_bytes: NonZeroUsize,
    pub request_body_bytes: NonZeroUsize,
    pub response_body_bytes: NonZeroUsize,
    pub request_timeout: Duration,
    pub local_audience: String,
    pub required_scopes: Vec<String>,
    pub admission_limits: EmbeddingAdmissionLimits,
    pub cache_limits: EmbeddingCacheLimits,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum InputType {
    Query,
    Document,
}
impl InputType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Document => "document",
        }
    }
}
enum Store {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
struct EmbeddingsState {
    store: Store,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: EmbeddingsHttpConfig,
    backend: Arc<EmbeddingBackend>,
    revision_header: HeaderValue,
    dimensions_header: HeaderValue,
}
pub fn postgres_embeddings_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: EmbeddingsHttpConfig,
    backend: Arc<EmbeddingBackend>,
) -> Result<Router, EmbeddingsError> {
    router(Store::Postgres(store), verifier, upstream, config, backend)
}
pub fn sqlite_embeddings_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: EmbeddingsHttpConfig,
    backend: Arc<EmbeddingBackend>,
) -> Result<Router, EmbeddingsError> {
    router(Store::Sqlite(store), verifier, upstream, config, backend)
}
fn router(
    store: Store,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: EmbeddingsHttpConfig,
    backend: Arc<EmbeddingBackend>,
) -> Result<Router, EmbeddingsError> {
    if [&config.model, &config.model_revision, &config.recipe]
        .iter()
        .any(|value| {
            value.is_empty()
                || value.trim() != value.as_str()
                || value.chars().any(char::is_control)
        })
        || config.revision.trim().is_empty()
        || config.request_timeout.is_zero()
        || Instant::now().checked_add(config.request_timeout).is_none()
        || config.dimensions != config.cache_limits.dimensions
        || config.dimensions.get() != backend.dimensions()
        || config.max_batch.get() > config.cache_limits.max_entries.get()
        || config.local_audience.trim().is_empty()
        || config
            .required_scopes
            .iter()
            .any(|scope| scope.trim().is_empty())
    {
        return Err(EmbeddingsError::Configuration);
    }
    for bytes in [
        config.request_body_bytes.get(),
        config.response_body_bytes.get(),
        config.max_input_bytes.get(),
    ] {
        if bytes > isize::MAX as usize {
            return Err(EmbeddingsError::Configuration);
        }
    }
    let metadata = backend
        .protocol()
        .len()
        .checked_add(backend.model().len())
        .and_then(|n| n.checked_add(config.revision.len()))
        .and_then(|n| n.checked_add("document".len()))
        .ok_or(EmbeddingsError::Configuration)?;
    if metadata > config.cache_limits.metadata_bytes.get() {
        return Err(EmbeddingsError::Configuration);
    }
    let revision_header =
        HeaderValue::from_str(&config.revision).map_err(|_| EmbeddingsError::Configuration)?;
    let dimensions_header = HeaderValue::from_str(&config.dimensions.to_string())
        .map_err(|_| EmbeddingsError::Configuration)?;
    let state = EmbeddingsState {
        store,
        verifier,
        upstream,
        config,
        backend,
        revision_header,
        dimensions_header,
    };
    // Validate borrowed views without touching SQL or initializing another provider.
    match &state.store {
        Store::Postgres(store) => {
            store
                .embedding_cache(state.config.cache_limits)
                .map_err(|_| EmbeddingsError::Configuration)?;
            store
                .embedding_admissions(
                    &state.verifier,
                    state.upstream.as_deref(),
                    &state.config.local_audience,
                    &state.config.required_scopes,
                    state.config.admission_limits,
                )
                .map_err(|_| EmbeddingsError::Configuration)?;
        }
        Store::Sqlite(store) => {
            store
                .embedding_cache(state.config.cache_limits)
                .map_err(|_| EmbeddingsError::Configuration)?;
            store
                .embedding_admissions(
                    &state.verifier,
                    state.upstream.as_deref(),
                    &state.config.local_audience,
                    &state.config.required_scopes,
                    state.config.admission_limits,
                )
                .map_err(|_| EmbeddingsError::Configuration)?;
        }
    }
    Ok(Router::new()
        .route("/v1/embeddings", post(handle))
        .with_state(Arc::new(state)))
}
pub fn disabled_embeddings_router() -> Router {
    Router::new().route("/v1/embeddings", post(disabled))
}
async fn disabled() -> Response {
    error_response(WireError::Disabled, new_admin_request_id().ok().as_deref())
}

#[derive(Clone, Copy)]
enum WireError {
    Disabled,
    Authentication,
    Forbidden,
    AuthorizationUnavailable,
    InvalidJson,
    InvalidRequest,
    TooLarge,
    Upstream,
}
impl WireError {
    fn fields(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::Disabled => (
                StatusCode::NOT_FOUND,
                "capability_disabled",
                "Embeddings are disabled",
            ),
            Self::Authentication => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication failed",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "Embeddings are forbidden",
            ),
            Self::AuthorizationUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization_unavailable",
                "Authorization is unavailable",
            ),
            Self::InvalidJson => (
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "Invalid JSON request",
            ),
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid embeddings request",
            ),
            Self::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "Embeddings request exceeds the input limit",
            ),
            Self::Upstream => (
                StatusCode::BAD_GATEWAY,
                "upstream_failed",
                "Embeddings failed",
            ),
        }
    }
}
#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorFields,
    request_id: Option<&'a str>,
}
#[derive(Serialize)]
struct ErrorFields {
    code: &'static str,
    message: &'static str,
}
fn error_response(error: WireError, request_id: Option<&str>) -> Response {
    let (status, code, message) = error.fields();
    let body = serde_json::to_vec(&ErrorBody {
        error: ErrorFields { code, message },
        request_id,
    })
    .expect("static error envelope serializes");
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}
fn admission_error(error: EmbeddingAdmissionError) -> WireError {
    use broker_control::{AdminBrokerSessionError, LocalBearerVerificationError};
    match error {
        EmbeddingAdmissionError::Forbidden => WireError::Forbidden,
        EmbeddingAdmissionError::Control(_)
        | EmbeddingAdmissionError::Grants(_)
        | EmbeddingAdmissionError::InvalidPolicy => WireError::AuthorizationUnavailable,
        EmbeddingAdmissionError::LocalAuthentication(LocalBearerVerificationError::Control(_)) => {
            WireError::AuthorizationUnavailable
        }
        EmbeddingAdmissionError::Upstream(AdminBrokerSessionError::Control(_)) => {
            WireError::AuthorizationUnavailable
        }
        _ => WireError::Authentication,
    }
}
fn bearer(headers: &HeaderMap) -> Result<Option<Authorization<Bearer>>, WireError> {
    let count = headers.get_all(header::AUTHORIZATION).iter().count();
    if count > 1 {
        return Err(WireError::Authentication);
    }
    if count == 0 {
        return Ok(None);
    }
    Authorization::<Bearer>::decode(&mut headers.get_all(header::AUTHORIZATION).iter())
        .map(Some)
        .map_err(|_| WireError::Authentication)
}
struct RequestCancellation(Cancellation);
impl Drop for RequestCancellation {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
async fn handle(State(state): State<Arc<EmbeddingsState>>, request: Request) -> Response {
    let request_id = match new_admin_request_id() {
        Ok(id) => id,
        Err(_) => return error_response(WireError::Upstream, None),
    };
    let original = Instant::now() + state.config.request_timeout;
    let cancel = RequestCancellation(Cancellation::default());
    let result = serve(&state, request, original, &cancel.0).await;
    result.unwrap_or_else(|error| error_response(error, Some(&request_id)))
}
async fn serve(
    state: &EmbeddingsState,
    request: Request,
    original: Instant,
    cancel: &Cancellation,
) -> Result<Response, WireError> {
    let authorization = bearer(request.headers())?;
    let raw = authorization.as_ref().map(|value| value.token());
    let mut proof = match &state.store {
        Store::Postgres(store) => store
            .embedding_admissions(
                &state.verifier,
                state.upstream.as_deref(),
                &state.config.local_audience,
                &state.config.required_scopes,
                state.config.admission_limits,
            )
            .map_err(admission_error)?
            .authorize(raw, original)
            .await
            .map_err(admission_error)?,
        Store::Sqlite(store) => store
            .embedding_admissions(
                &state.verifier,
                state.upstream.as_deref(),
                &state.config.local_audience,
                &state.config.required_scopes,
                state.config.admission_limits,
            )
            .map_err(admission_error)?
            .authorize(raw, original)
            .await
            .map_err(admission_error)?,
    };
    check_owner(&state.backend, &mut proof, cancel)?;
    if state.backend.closed() {
        return Err(WireError::Upstream);
    }
    let read = tokio::time::timeout_at(
        proof.deadline().into(),
        axum::body::to_bytes(request.into_body(), state.config.request_body_bytes.get()),
    )
    .await;
    check_owner(&state.backend, &mut proof, cancel)?;
    let bytes = read
        .map_err(|_| WireError::Upstream)?
        .map_err(|_| WireError::TooLarge)?;
    let request = request::decode(&bytes, &state.config, &mut proof, cancel)?;
    pipeline(state, request, proof, cancel).await
}
fn check(proof: &mut EmbeddingAdmission<'_>, cancel: &Cancellation) -> Result<(), WireError> {
    proof.check().map_err(admission_error)?;
    if cancel.is_cancelled() {
        return Err(WireError::Upstream);
    }
    Ok(())
}
fn check_owner(
    backend: &EmbeddingBackend,
    proof: &mut EmbeddingAdmission<'_>,
    cancel: &Cancellation,
) -> Result<(), WireError> {
    check(proof, cancel)?;
    if backend.closed() {
        return Err(WireError::Upstream);
    }
    Ok(())
}
fn namespace(state: &EmbeddingsState, input: InputType) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in [
        "graphit-embedding-cache-v1",
        state.backend.protocol(),
        state.backend.source_identity(),
        state.backend.model(),
        &state.config.revision,
        &state.config.model,
        &state.config.model_revision,
        &state.config.recipe,
        &state.config.dimensions.to_string(),
        if state.backend.send_dimensions() {
            "true"
        } else {
            "false"
        },
        input.as_str(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.finalize().into()
}
async fn pipeline(
    state: &EmbeddingsState,
    request: request::Decoded,
    mut proof: EmbeddingAdmission<'_>,
    cancel: &Cancellation,
) -> Result<Response, WireError> {
    let mut unique = Vec::new();
    let mut positions = HashMap::new();
    let mut order = Vec::new();
    let mut keys = Vec::new();
    let compatibility = namespace(state, request.input_type);
    for text in request.inputs {
        check_owner(&state.backend, &mut proof, cancel)?;
        let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        let index = match positions.entry(digest) {
            std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let index = unique.len();
                entry.insert(index);
                unique.push(Some(text));
                keys.push(EmbeddingCacheKey::new(compatibility, digest));
                index
            }
        };
        order.push(index);
    }
    let cached = match &state.store {
        Store::Postgres(store) => {
            store
                .embedding_cache(state.config.cache_limits)
                .map_err(|_| WireError::Upstream)?
                .read(&keys, proof.deadline())
                .await
        }
        Store::Sqlite(store) => {
            store
                .embedding_cache(state.config.cache_limits)
                .map_err(|_| WireError::Upstream)?
                .read(&keys, proof.deadline())
                .await
        }
    };
    // Preserve a non-temporal SQL/COMMIT failure before checking later proof expiry.
    let mut vectors = cache_result(cached, &mut proof, cancel)?;
    let mut misses = Vec::new();
    let mut texts = Vec::new();
    for (index, vector) in vectors.iter().enumerate() {
        if vector.is_none() {
            misses.push(index);
            texts.push(unique[index].take().expect("unique input retained"));
        }
    }
    let hit = misses.is_empty();
    let mut usage = Vec::new();
    let mut first_failure = None;
    if !hit {
        check_owner(&state.backend, &mut proof, cancel)?;
        let outcome = state
            .backend
            .infer(texts, request.input_type, &mut proof, cancel)
            .await;
        usage = outcome.usage;
        first_failure = outcome.failure;
        // An already-observed non-temporal upstream error remains first, but the
        // authority boundary still prevents persisting any later completion.
        if let Err(error) = check_owner(&state.backend, &mut proof, cancel) {
            return Err(first_failure
                .as_ref()
                .filter(|failure| !failure.temporal())
                .map_or(error, failure_wire));
        }
        let mut inserted = Vec::new();
        for (index, vector) in outcome.entries {
            let Some(&position) = misses.get(index) else {
                return Err(WireError::Upstream);
            };
            if vectors[position].is_some()
                || vector.len() != state.config.dimensions.get()
                || vector.iter().any(|v| !v.is_finite())
            {
                return Err(WireError::Upstream);
            }
            vectors[position] = Some(vector);
            inserted.push(position);
        }
        if !inserted.is_empty() {
            if let Err(error) = check_owner(&state.backend, &mut proof, cancel) {
                return Err(first_failure.as_ref().map_or(error, failure_wire));
            }
            let provenance = EmbeddingCacheProvenance {
                provider: state.backend.protocol(),
                revision: &state.config.revision,
                model: state.backend.model(),
                input_type: request.input_type.as_str(),
            };
            let entries: Vec<_> = inserted
                .into_iter()
                .map(|index| EmbeddingCacheEntry {
                    key: keys[index],
                    provenance,
                    vector: vectors[index]
                        .as_deref()
                        .expect("validated vector retained"),
                })
                .collect();
            let written = match &state.store {
                Store::Postgres(store) => {
                    store
                        .embedding_cache(state.config.cache_limits)
                        .map_err(|_| WireError::Upstream)?
                        .insert(&entries, proof.deadline())
                        .await
                }
                Store::Sqlite(store) => {
                    store
                        .embedding_cache(state.config.cache_limits)
                        .map_err(|_| WireError::Upstream)?
                        .insert(&entries, proof.deadline())
                        .await
                }
            };
            if let Err(error) = cache_result(written, &mut proof, cancel) {
                return Err(first_failure.as_ref().map_or(error, failure_wire));
            }
        }
    }
    if let Some(failure) = first_failure {
        return Err(failure_wire(&failure));
    }
    if vectors.iter().any(Option::is_none) {
        return Err(WireError::Upstream);
    }
    check_owner(&state.backend, &mut proof, cancel)?;
    let data: Vec<_> = order
        .into_iter()
        .enumerate()
        .map(|(index, position)| EmbeddingRow {
            object: "embedding",
            embedding: vectors[position].as_deref().expect("complete batch"),
            index,
        })
        .collect();
    let response = Success {
        object: "list",
        data,
        graphit: Metadata {
            revision: &state.config.revision,
            model: &state.config.model,
            model_revision: &state.config.model_revision,
            recipe: &state.config.recipe,
            dimensions: state.config.dimensions.get(),
        },
        usage: match usage.as_slice() {
            [] => None,
            [one] => Some(ObservedUsage::Single(one)),
            many => Some(ObservedUsage::Batches(many)),
        },
    };
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        maximum: state.config.response_body_bytes.get(),
        proof: &mut proof,
        cancel,
        backend: &state.backend,
        failure: None,
    };
    if serde_json::to_writer(&mut writer, &response).is_err() {
        return Err(writer.failure.unwrap_or(WireError::Upstream));
    }
    let bytes = writer.bytes;
    check_owner(&state.backend, &mut proof, cancel)?;
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        "x-graphit-embedding-revision",
        state.revision_header.clone(),
    );
    response.headers_mut().insert(
        "x-graphit-embedding-dimensions",
        state.dimensions_header.clone(),
    );
    response.headers_mut().insert(
        "x-graphit-cache",
        HeaderValue::from_static(if hit { "HIT" } else { "MISS" }),
    );
    Ok(response)
}
fn failure_wire(failure: &provider::Failure) -> WireError {
    match failure {
        provider::Failure::Admission(error, _) => admission_error(*error),
        _ => WireError::Upstream,
    }
}
fn cache_result<T>(
    result: Result<T, EmbeddingCacheError>,
    proof: &mut EmbeddingAdmission<'_>,
    cancel: &Cancellation,
) -> Result<T, WireError> {
    match result {
        Ok(value) => {
            check(proof, cancel)?;
            Ok(value)
        }
        Err(EmbeddingCacheError::Control(ControlError::Deadline)) => {
            check(proof, cancel)?;
            Err(WireError::Upstream)
        }
        Err(_) => Err(WireError::Upstream),
    }
}
#[derive(Serialize)]
struct Success<'a> {
    object: &'static str,
    data: Vec<EmbeddingRow<'a>>,
    graphit: Metadata<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<ObservedUsage<'a>>,
}
#[derive(Serialize)]
#[serde(untagged)]
enum ObservedUsage<'a> {
    Single(&'a RawValue),
    Batches(&'a [Box<RawValue>]),
}
#[derive(Serialize)]
struct EmbeddingRow<'a> {
    object: &'static str,
    embedding: &'a [f32],
    index: usize,
}
#[derive(Serialize)]
struct Metadata<'a> {
    revision: &'a str,
    model: &'a str,
    model_revision: &'a str,
    recipe: &'a str,
    dimensions: usize,
}
struct BoundedWriter<'a, 'p> {
    bytes: Vec<u8>,
    maximum: usize,
    proof: &'a mut EmbeddingAdmission<'p>,
    cancel: &'a Cancellation,
    backend: &'a EmbeddingBackend,
    failure: Option<WireError>,
}
impl Write for BoundedWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Err(error) = check_owner(self.backend, self.proof, self.cancel) {
            self.failure.get_or_insert(error);
            return Err(io::Error::other("embedding operation expired"));
        }
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|end| *end <= self.maximum)
            .ok_or_else(|| io::Error::other("embedding response exceeds its bound"))?;
        self.bytes
            .try_reserve(end - self.bytes.len())
            .map_err(|_| io::Error::other("embedding response allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
