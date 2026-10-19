//! Rerank HTTP over current SQL capability admission and the existing inference owner.
mod cache;
mod request;

use crate::{RerankBackend, RerankBackendError, RerankResult};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::post,
};
use broker_control::{
    AdminBrokerSessionError, BrokerAccessVerifier, LocalBearerVerificationError,
    PostgresControlStore, RerankAdmission, RerankAdmissionError, RerankAdmissionLimits,
    SqliteControlStore, UpstreamBearerVerifier, new_admin_request_id,
};
use graphit_ai::context::InferenceContext;
use graphit_core::file_lock::Cancellation;
use headers::{Authorization, Header, authorization::Bearer};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct RerankHttpConfig {
    /// Revision of the service configuration, separate from model provenance.
    pub revision: String,
    pub model: String,
    pub model_revision: String,
    pub recipe: String,
    pub max_documents: NonZeroUsize,
    pub max_document_bytes: NonZeroUsize,
    pub request_body_bytes: NonZeroUsize,
    pub response_body_bytes: NonZeroUsize,
    pub request_timeout: Duration,
    pub local_audience: String,
    pub required_scopes: Vec<String>,
    pub admission_limits: RerankAdmissionLimits,
    pub cache_ttl: Duration,
    pub cache_entries: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RerankConfigurationError;
impl std::fmt::Display for RerankConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid rerank configuration")
    }
}
impl std::error::Error for RerankConfigurationError {}

enum Store {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
struct RerankState {
    store: Store,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: RerankHttpConfig,
    backend: Arc<RerankBackend>,
    revision_header: HeaderValue,
    cache: Mutex<cache::Cache>,
}
pub fn postgres_rerank_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: RerankHttpConfig,
    backend: Arc<RerankBackend>,
) -> Result<Router, RerankConfigurationError> {
    router(Store::Postgres(store), verifier, upstream, config, backend)
}
pub fn sqlite_rerank_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: RerankHttpConfig,
    backend: Arc<RerankBackend>,
) -> Result<Router, RerankConfigurationError> {
    router(Store::Sqlite(store), verifier, upstream, config, backend)
}
fn router(
    store: Store,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: RerankHttpConfig,
    backend: Arc<RerankBackend>,
) -> Result<Router, RerankConfigurationError> {
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
        || Instant::now().checked_add(config.cache_ttl).is_none()
        || config.local_audience.trim().is_empty()
        || config.required_scopes.iter().any(|s| s.trim().is_empty())
    {
        return Err(RerankConfigurationError);
    }
    for bytes in [
        config.request_body_bytes,
        config.response_body_bytes,
        config.max_document_bytes,
    ] {
        if bytes.get() > isize::MAX as usize {
            return Err(RerankConfigurationError);
        }
    }
    let revision_header =
        HeaderValue::from_str(&config.revision).map_err(|_| RerankConfigurationError)?;
    match &store {
        Store::Postgres(store) => {
            store
                .rerank_admissions(
                    &verifier,
                    upstream.as_deref(),
                    &config.local_audience,
                    &config.required_scopes,
                    config.admission_limits,
                )
                .map_err(|_| RerankConfigurationError)?;
        }
        Store::Sqlite(store) => {
            store
                .rerank_admissions(
                    &verifier,
                    upstream.as_deref(),
                    &config.local_audience,
                    &config.required_scopes,
                    config.admission_limits,
                )
                .map_err(|_| RerankConfigurationError)?;
        }
    }
    let state = RerankState {
        store,
        verifier,
        upstream,
        config,
        backend,
        revision_header,
        cache: Mutex::new(cache::Cache::new()),
    };
    Ok(Router::new()
        .route("/v1/rerank", post(handle))
        .with_state(Arc::new(state)))
}
pub fn disabled_rerank_router() -> Router {
    Router::new().route(
        "/v1/rerank",
        post(|| async {
            error_response(WireError::Disabled, new_admin_request_id().ok().as_deref())
        }),
    )
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
                "Rerank is disabled",
            ),
            Self::Authentication => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication failed",
            ),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "Rerank is forbidden"),
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
                "Invalid rerank request",
            ),
            Self::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "Request body exceeds its limit",
            ),
            Self::Upstream => (
                StatusCode::BAD_GATEWAY,
                "upstream_failed",
                "Rerank upstream request failed",
            ),
        }
    }
}
#[derive(Serialize)]
struct ErrorFields {
    code: &'static str,
    message: &'static str,
}
#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorFields,
    request_id: Option<&'a str>,
}
fn error_response(error: WireError, request_id: Option<&str>) -> Response {
    let (status, code, message) = error.fields();
    let bytes = serde_json::to_vec(&ErrorBody {
        error: ErrorFields { code, message },
        request_id,
    })
    .expect("static error serializes");
    let mut response = Response::new(Body::from(bytes));
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
fn admission_error(error: RerankAdmissionError) -> WireError {
    match error {
        RerankAdmissionError::Forbidden => WireError::Forbidden,
        RerankAdmissionError::Control(_)
        | RerankAdmissionError::Grants(_)
        | RerankAdmissionError::InvalidPolicy => WireError::AuthorizationUnavailable,
        RerankAdmissionError::LocalAuthentication(LocalBearerVerificationError::Control(_))
        | RerankAdmissionError::Upstream(AdminBrokerSessionError::Control(_)) => {
            WireError::AuthorizationUnavailable
        }
        _ => WireError::Authentication,
    }
}
fn bearer(headers: &HeaderMap) -> Result<Option<Authorization<Bearer>>, WireError> {
    match headers.get_all(header::AUTHORIZATION).iter().count() {
        0 => Ok(None),
        1 => Authorization::<Bearer>::decode(&mut headers.get_all(header::AUTHORIZATION).iter())
            .map(Some)
            .map_err(|_| WireError::Authentication),
        _ => Err(WireError::Authentication),
    }
}
fn check(proof: &mut RerankAdmission<'_>, cancel: &Cancellation) -> Result<(), WireError> {
    proof.check().map_err(admission_error)?;
    if cancel.is_cancelled() {
        return Err(WireError::Upstream);
    }
    Ok(())
}
fn check_owner(
    backend: &RerankBackend,
    proof: &mut RerankAdmission<'_>,
    cancel: &Cancellation,
) -> Result<(), WireError> {
    check(proof, cancel)?;
    if backend.closed() {
        return Err(WireError::Upstream);
    }
    Ok(())
}
struct RequestCancellation(Cancellation);
impl Drop for RequestCancellation {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
async fn handle(State(state): State<Arc<RerankState>>, request: Request) -> Response {
    let id = match new_admin_request_id() {
        Ok(id) => id,
        Err(_) => return error_response(WireError::Upstream, None),
    };
    let original = Instant::now() + state.config.request_timeout;
    let cancel = RequestCancellation(Cancellation::default());
    serve(&state, request, original, &cancel.0)
        .await
        .unwrap_or_else(|e| error_response(e, Some(&id)))
}
async fn serve(
    state: &RerankState,
    request: Request,
    original: Instant,
    cancel: &Cancellation,
) -> Result<Response, WireError> {
    let authorization = bearer(request.headers())?;
    let raw = authorization.as_ref().map(|v| v.token());
    let mut proof = authorize(state, raw, original)
        .await
        .map_err(admission_error)?;
    check_owner(&state.backend, &mut proof, cancel)?;
    let read = tokio::time::timeout_at(
        proof.deadline().into(),
        axum::body::to_bytes(request.into_body(), state.config.request_body_bytes.get()),
    )
    .await;
    check_owner(&state.backend, &mut proof, cancel)?;
    let bytes = read
        .map_err(|_| WireError::Upstream)?
        .map_err(|_| WireError::TooLarge)?;
    let input = request::decode(&bytes, &state.config, &mut proof, cancel)?;
    let key = cache_key(state, &input, &mut proof, cancel)?;
    let hit = state
        .cache
        .lock()
        .map_err(|_| WireError::Upstream)?
        .get(&key, Instant::now());
    check_owner(&state.backend, &mut proof, cancel)?;
    let (results, was_hit) = match hit {
        Some(results) => (results, true),
        None => {
            let context = InferenceContext::new(cancel, proof.deadline());
            let result = state
                .backend
                .infer_guarded(
                    input.query,
                    input.documents,
                    input.top_n,
                    context,
                    &mut || proof.check(),
                )
                .await;
            let results = match result {
                Ok(results) => results,
                Err(RerankBackendError::Admission { source, .. }) => {
                    return Err(admission_error(source));
                }
                Err(error) => {
                    if error.temporal() {
                        proof.check().map_err(admission_error)?;
                    }
                    return Err(WireError::Upstream);
                }
            };
            check_owner(&state.backend, &mut proof, cancel)?;
            (Arc::new(results), false)
        }
    };
    // Refresh SQL after computation/HIT; retain the first genuine authentication cutoff.
    check_owner(&state.backend, &mut proof, cancel)?;
    let captured_cutoff = proof.deadline();
    let mut fresh = match authorize(state, raw, captured_cutoff).await {
        Ok(fresh) => fresh,
        Err(error) => {
            if admission_temporal(error) {
                proof.check().map_err(admission_error)?;
            }
            return Err(admission_error(error));
        }
    };
    check_current(state, &mut proof, &mut fresh, cancel)?;
    if fresh.cache_scope() != proof.cache_scope() {
        return Err(WireError::Authentication);
    }
    let bytes = encode(state, &results, &mut proof, &mut fresh, cancel)?;
    if !was_hit && !state.config.cache_ttl.is_zero() && state.config.cache_entries > 0 {
        let mut cache = state.cache.lock().map_err(|_| WireError::Upstream)?;
        check_current(state, &mut proof, &mut fresh, cancel)?;
        cache.put(
            key,
            results,
            Instant::now(),
            state.config.cache_ttl,
            state.config.cache_entries,
            &mut || check_current(state, &mut proof, &mut fresh, cancel),
        )?;
    }
    check_current(state, &mut proof, &mut fresh, cancel)?;
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert("x-graphit-rerank-revision", state.revision_header.clone());
    response.headers_mut().insert(
        "x-graphit-cache",
        HeaderValue::from_static(if was_hit { "HIT" } else { "MISS" }),
    );
    Ok(response)
}
fn cache_key(
    state: &RerankState,
    input: &request::Decoded,
    proof: &mut RerankAdmission<'_>,
    cancel: &Cancellation,
) -> Result<[u8; 32], WireError> {
    let mut hash = Sha256::new();
    hash.update(b"graphit-rerank-response-v1");
    hash.update(proof.cache_scope());
    for part in [
        state.backend.protocol(),
        state.backend.effective_identity(),
        state.backend.model(),
        &state.config.revision,
        &state.config.model,
        &state.config.model_revision,
        &state.config.recipe,
        &input.query,
    ] {
        check_owner(&state.backend, proof, cancel)?;
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part.as_bytes());
    }
    hash.update((input.top_n as u64).to_le_bytes());
    hash.update((input.documents.len() as u64).to_le_bytes());
    for doc in &input.documents {
        check_owner(&state.backend, proof, cancel)?;
        hash.update((doc.len() as u64).to_le_bytes());
        hash.update(doc.as_bytes());
    }
    check_owner(&state.backend, proof, cancel)?;
    Ok(hash.finalize().into())
}
#[derive(Serialize)]
struct Metadata<'a> {
    revision: &'a str,
    model: &'a str,
    model_revision: &'a str,
    recipe: &'a str,
}
#[derive(Serialize)]
struct Success<'a> {
    results: &'a [RerankResult],
    graphit: Metadata<'a>,
}
struct Output<'a, 'v> {
    bytes: Vec<u8>,
    maximum: usize,
    proof: &'a mut RerankAdmission<'v>,
    fresh: &'a mut RerankAdmission<'v>,
    cancel: &'a Cancellation,
    backend: &'a RerankBackend,
    error: Option<WireError>,
}
impl Write for Output<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = check_owner(self.backend, self.proof, self.cancel)
            .and_then(|()| self.fresh.check().map_err(admission_error))
            .and_then(|()| {
                if self
                    .bytes
                    .len()
                    .checked_add(buf.len())
                    .is_none_or(|n| n > self.maximum)
                {
                    return Err(WireError::Upstream);
                }
                self.bytes
                    .try_reserve(buf.len())
                    .map_err(|_| WireError::Upstream)?;
                self.bytes.extend_from_slice(buf);
                Ok(())
            });
        if let Err(error) = result {
            self.error = Some(error);
            return Err(io::Error::other("rerank response rejected"));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode<'v>(
    state: &RerankState,
    results: &[RerankResult],
    proof: &mut RerankAdmission<'v>,
    fresh: &mut RerankAdmission<'v>,
    cancel: &Cancellation,
) -> Result<Vec<u8>, WireError> {
    let mut output = Output {
        bytes: Vec::new(),
        maximum: state.config.response_body_bytes.get(),
        proof,
        fresh,
        cancel,
        backend: &state.backend,
        error: None,
    };
    let response = Success {
        results,
        graphit: Metadata {
            revision: &state.config.revision,
            model: &state.config.model,
            model_revision: &state.config.model_revision,
            recipe: &state.config.recipe,
        },
    };
    serde_json::to_writer(&mut output, &response)
        .map_err(|_| output.error.unwrap_or(WireError::Upstream))?;
    check_owner(output.backend, output.proof, output.cancel)?;
    output.fresh.check().map_err(admission_error)?;
    Ok(output.bytes)
}

async fn authorize<'a>(
    state: &'a RerankState,
    raw: Option<&str>,
    original: Instant,
) -> Result<RerankAdmission<'a>, RerankAdmissionError> {
    match &state.store {
        Store::Postgres(store) => {
            store
                .rerank_admissions(
                    &state.verifier,
                    state.upstream.as_deref(),
                    &state.config.local_audience,
                    &state.config.required_scopes,
                    state.config.admission_limits,
                )?
                .authorize(raw, original)
                .await
        }
        Store::Sqlite(store) => {
            store
                .rerank_admissions(
                    &state.verifier,
                    state.upstream.as_deref(),
                    &state.config.local_audience,
                    &state.config.required_scopes,
                    state.config.admission_limits,
                )?
                .authorize(raw, original)
                .await
        }
    }
}

fn admission_temporal(error: RerankAdmissionError) -> bool {
    use broker_control::{ControlError, ResourceGrantReadError};
    matches!(
        error,
        RerankAdmissionError::Control(ControlError::Deadline)
            | RerankAdmissionError::Grants(ResourceGrantReadError::Control(ControlError::Deadline))
            | RerankAdmissionError::LocalAuthentication(LocalBearerVerificationError::Control(
                ControlError::Deadline
            ))
            | RerankAdmissionError::Upstream(AdminBrokerSessionError::Control(
                ControlError::Deadline
            ))
    )
}
fn check_current(
    state: &RerankState,
    proof: &mut RerankAdmission<'_>,
    fresh: &mut RerankAdmission<'_>,
    cancel: &Cancellation,
) -> Result<(), WireError> {
    check_owner(&state.backend, proof, cancel)?;
    fresh.check().map_err(admission_error)
}
