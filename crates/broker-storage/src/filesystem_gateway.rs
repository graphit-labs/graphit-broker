//! Request-scoped MAC admission and mature S3/SigV4 protocol over native storage.
use crate::*;
use broker_control::StorageOperation;
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use http::{HeaderMap, StatusCode};
use http_body::{Body as HttpBody, Frame, SizeHint};
use parking_lot::Mutex;
use s3s::access::{S3Access, S3AccessContext};
use s3s::auth::{S3Auth, SecretKey};
use s3s::config::{S3Config, StaticConfigProvider};
use s3s::crypto::Checksum as _;
use s3s::dto::*;
use s3s::service::S3ServiceBuilder;
use s3s::{
    Body, HttpError, HttpRequest, HttpResponse, S3, S3Error, S3ErrorCode, S3Request, S3Response,
    S3Result,
};
use std::{
    collections::BTreeMap,
    error::Error as StdError,
    fmt,
    io::{self, Read},
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio_util::{
    io::{StreamReader, SyncIoBridge},
    sync::{CancellationToken, DropGuard},
    task::TaskTracker,
};
use zeroize::Zeroizing;

pub struct FilesystemGatewayConfig {
    pub request_timeout: Duration,
    pub request_head_bytes: NonZeroUsize,
}
#[derive(Debug)]
pub enum FilesystemGatewayError {
    InvalidConfiguration,
    ShutdownTimeout,
}
impl fmt::Display for FilesystemGatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid filesystem gateway configuration",
            Self::ShutdownTimeout => "filesystem gateway shutdown deadline",
        })
    }
}
impl StdError for FilesystemGatewayError {}
struct Route {
    name: String,
    region: s3s::region::Region,
    token_bytes: usize,
    store: Arc<FilesystemStore>,
}
struct Runtime {
    admission: Mutex<bool>,
    tracker: TaskTracker,
    cancellation: CancellationToken,
}
impl Runtime {
    fn spawn<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> S3Result<T> + Send + 'static,
    ) -> S3Result<tokio::task::JoinHandle<S3Result<T>>> {
        let closed = self.admission.lock();
        if *closed {
            return Err(S3Error::new(S3ErrorCode::ServiceUnavailable));
        }
        Ok(self.tracker.spawn_blocking(work))
    }
}
pub struct FilesystemGateway {
    issuer: Arc<FilesystemStorageIssuer>,
    routes: BTreeMap<String, Arc<Route>>,
    config: FilesystemGatewayConfig,
    runtime: Arc<Runtime>,
}
impl FilesystemGateway {
    /// Configured path-style bucket names, for HTTP registration only.
    pub fn buckets(&self) -> impl Iterator<Item = &str> {
        self.routes.keys().map(String::as_str)
    }

    pub fn new(
        issuer: Arc<FilesystemStorageIssuer>,
        stores: Vec<Arc<FilesystemStore>>,
        config: FilesystemGatewayConfig,
    ) -> Result<Self, FilesystemGatewayError> {
        if config.request_timeout.is_zero()
            || Instant::now().checked_add(config.request_timeout).is_none()
        {
            return Err(FilesystemGatewayError::InvalidConfiguration);
        }
        let count = stores.len();
        let mut stores: BTreeMap<_, _> = stores
            .into_iter()
            .map(|s| (s.config.bucket.clone(), s))
            .collect();
        if count != stores.len() || count == 0 {
            return Err(FilesystemGatewayError::InvalidConfiguration);
        }
        let mut routes = BTreeMap::new();
        for cfg in issuer.gateway_routes() {
            let store = stores
                .remove(&cfg.bucket)
                .ok_or(FilesystemGatewayError::InvalidConfiguration)?;
            if cfg.token_bytes.get() > config.request_head_bytes.get() {
                return Err(FilesystemGatewayError::InvalidConfiguration);
            }
            routes.insert(
                cfg.bucket.clone(),
                Arc::new(Route {
                    name: cfg.name.clone(),
                    region: cfg
                        .region
                        .parse()
                        .map_err(|_| FilesystemGatewayError::InvalidConfiguration)?,
                    token_bytes: cfg.token_bytes.get(),
                    store,
                }),
            );
        }
        if !stores.is_empty() {
            return Err(FilesystemGatewayError::InvalidConfiguration);
        }
        Ok(Self {
            issuer,
            routes,
            config,
            runtime: Arc::new(Runtime {
                admission: Mutex::new(false),
                tracker: TaskTracker::new(),
                cancellation: CancellationToken::new(),
            }),
        })
    }
    pub async fn handle(
        &self,
        request: HttpRequest,
        original: Instant,
    ) -> Result<HttpResponse, HttpError> {
        let admitted = self.prepare(&request, original);
        let (scope, guard) = match admitted {
            Ok(v) => v,
            Err(e) => {
                return e
                    .to_http_response()
                    .map_err(|e| HttpError::from_std_error(Box::new(e)));
            }
        };
        let mut config = S3Config::default();
        config.enable_sig_v2 = false;
        config.allow_presigned_url = false;
        config.allow_post_signature = false;
        config.normalize_forward_slash_path = false;
        config.expected_region = Some(scope.route.region.clone());
        config.sig_v4_allowed_services = vec!["s3".into()];
        config.xml_max_body_size = 1024 * 1024;
        config.put_object_max_size = Some(scope.route.store.config.max_object_bytes.get());
        config.aws_chunked_stream_max_chunk_size = config.aws_chunked_stream_max_chunk_size.min(
            usize::try_from(scope.route.store.config.max_object_bytes.get()).unwrap_or(usize::MAX),
        );
        let mut builder = S3ServiceBuilder::new(Backend {
            scope: scope.clone(),
        });
        builder.set_auth(Auth {
            scope: scope.clone(),
        });
        builder.set_access(Access {
            scope: scope.clone(),
        });
        builder.set_config(Arc::new(StaticConfigProvider::new(Arc::new(config))));
        let service = builder.build();
        if request.method() == http::Method::POST
            && (request
                .headers()
                .get("content-encoding")
                .is_some_and(|v| v == "aws-chunked")
                || request
                    .headers()
                    .get("x-amz-content-sha256")
                    .is_some_and(|v| v.as_bytes().starts_with(b"STREAMING-")))
        {
            return S3Error::new(S3ErrorCode::NotImplemented)
                .to_http_response()
                .map_err(|e| HttpError::from_std_error(Box::new(e)));
        }
        let xml_integrity = if request.method() == http::Method::POST
            && request
                .headers()
                .keys()
                .any(|k| k.as_str() == "content-md5" || k.as_str().starts_with("x-amz-checksum-"))
        {
            let result = Arc::new(Mutex::new(XmlValidation::Pending));
            let reader = match DigestReader::new(
                io::empty(),
                request.headers(),
                None,
                None,
                Arc::new(Mutex::new(None)),
            ) {
                Ok(v) => v,
                Err(e) => {
                    return e
                        .to_http_response()
                        .map_err(|e| HttpError::from_std_error(Box::new(e)));
                }
            };
            scope.xml_validation.set(result.clone()).map_err(|_| {
                HttpError::from_std_error(Box::new(S3Error::new(S3ErrorCode::InternalError)))
            })?;
            Some(XmlIntegrity { reader, result })
        } else {
            None
        };
        let (parts, body) = request.into_parts();
        let mut input = GuardedBody::new(body, scope.clone(), None);
        input.integrity = xml_integrity;
        let request = HttpRequest::from_parts(parts, Body::http_body_unsync(input));
        // Input frames carry deadlines; retain the actual mutator result and its joined IO.
        let response = service.call(request).await;
        match response {
            Ok(response) => {
                if response.status().is_success() {
                    if scope.cancellation.is_cancelled() || Instant::now() >= scope.deadline {
                        return Err(HttpError::from_std_error(Box::new(S3Error::new(
                            S3ErrorCode::RequestTimeout,
                        ))));
                    }
                    if let Some(proof) = scope.session.get() {
                        proof
                            .check(scope.deadline)
                            .map_err(|e| HttpError::from_std_error(Box::new(e)))?;
                    }
                }
                let (parts, body) = response.into_parts();
                Ok(HttpResponse::from_parts(
                    parts,
                    Body::http_body_unsync(GuardedBody::new(body, scope.clone(), Some(guard))),
                ))
            }
            Err(e) => Err(e),
        }
    }
    fn prepare(
        &self,
        request: &HttpRequest,
        original: Instant,
    ) -> S3Result<(Arc<Scope>, DropGuard)> {
        if *self.runtime.admission.lock() {
            return Err(S3Error::new(S3ErrorCode::ServiceUnavailable));
        }
        let size = request
            .headers()
            .iter()
            .try_fold(request.uri().to_string().len(), |n, (k, v)| {
                n.checked_add(k.as_str().len())?
                    .checked_add(v.as_bytes().len())?
                    .checked_add(4)
            })
            .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidRequest))?;
        if size > self.config.request_head_bytes.get() {
            return Err(S3Error::new(S3ErrorCode::InvalidRequest));
        }
        for (name, _) in
            url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
        {
            if [
                "X-Amz-Algorithm",
                "X-Amz-Credential",
                "X-Amz-Signature",
                "X-Amz-Security-Token",
                "AWSAccessKeyId",
                "Signature",
            ]
            .contains(&name.as_ref())
            {
                return Err(S3Error::new(S3ErrorCode::InvalidRequest));
            }
        }
        let path = s3s::path::parse_path_style(request.uri().path())
            .map_err(|e| S3Error::with_source(S3ErrorCode::InvalidURI, Box::new(e)))?;
        let route = path
            .get_bucket_name()
            .and_then(|b| self.routes.get(b))
            .cloned()
            .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchBucket))?;
        let mut tokens = request.headers().get_all("x-amz-security-token").iter();
        let token = tokens
            .next()
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty() && v.len() <= route.token_bytes)
            .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidToken))?;
        if tokens.next().is_some() {
            return Err(S3Error::new(S3ErrorCode::InvalidToken));
        }
        // Credentials stay in the mandatory header; S3s rejects presigned query authorization.
        for name in [
            "authorization",
            "x-amz-content-sha256",
            "x-amz-date",
            "host",
        ] {
            if request.headers().get_all(name).iter().count() != 1 {
                return Err(S3Error::new(S3ErrorCode::InvalidRequest));
            }
        }
        let deadline = original.min(
            Instant::now()
                .checked_add(self.config.request_timeout)
                .ok_or_else(|| S3Error::new(S3ErrorCode::InternalError))?,
        );
        if deadline <= Instant::now() {
            return Err(S3Error::new(S3ErrorCode::RequestTimeout));
        }
        let cancellation = self.runtime.cancellation.child_token();
        let guard = cancellation.clone().drop_guard();
        Ok((
            Arc::new(Scope {
                route,
                issuer: self.issuer.clone(),
                token: Zeroizing::new(token.to_owned()),
                session: OnceLock::new(),
                xml_validation: OnceLock::new(),
                runtime: self.runtime.clone(),
                deadline,
                cancellation,
            }),
            guard,
        ))
    }
    pub async fn shutdown(&self, original: Instant) -> Result<(), FilesystemGatewayError> {
        {
            let mut closed = self.runtime.admission.lock();
            *closed = true;
            self.runtime.cancellation.cancel();
            self.runtime.tracker.close();
        }
        tokio::time::timeout_at(original.into(), self.runtime.tracker.wait())
            .await
            .map_err(|_| FilesystemGatewayError::ShutdownTimeout)
    }

    /// Join retained IO after shutdown closed admission, even when its Original expired.
    /// This does not renew a deadline or change the causal shutdown result.
    pub async fn join_closed(&self) -> Result<(), FilesystemGatewayError> {
        if !*self.runtime.admission.lock() {
            return Err(FilesystemGatewayError::InvalidConfiguration);
        }
        self.runtime.tracker.wait().await;
        Ok(())
    }
}
struct GuardedBody {
    inner: Body,
    scope: Arc<Scope>,
    timer: Pin<Box<tokio::time::Sleep>>,
    _guard: Option<DropGuard>,
    ended: bool,
    integrity: Option<XmlIntegrity>,
    cancelled: Pin<Box<tokio_util::sync::WaitForCancellationFutureOwned>>,
}
impl GuardedBody {
    fn new(inner: Body, scope: Arc<Scope>, guard: Option<DropGuard>) -> Self {
        let timer = Box::pin(tokio::time::sleep_until(scope.deadline.into()));
        let cancelled = Box::pin(scope.cancellation.clone().cancelled_owned());
        Self {
            inner,
            scope,
            timer,
            cancelled,
            _guard: guard,
            ended: false,
            integrity: None,
        }
    }
    fn check(&self) -> S3Result<()> {
        if self.scope.cancellation.is_cancelled() || Instant::now() >= self.scope.deadline {
            return Err(S3Error::new(S3ErrorCode::RequestTimeout));
        }
        if let Some(proof) = self.scope.session.get() {
            proof
                .check(self.scope.deadline)
                .map_err(|e| S3Error::with_source(S3ErrorCode::RequestTimeout, Box::new(e)))?;
        }
        Ok(())
    }
}
impl HttpBody for GuardedBody {
    type Data = Bytes;
    type Error = s3s::StdError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        let deadline = self.scope.session.get().map_or(self.scope.deadline, |p| {
            p.bounded_deadline(self.scope.deadline)
        });
        self.timer.as_mut().reset(deadline.into());
        let _ = std::future::Future::poll(self.timer.as_mut(), cx);
        // Poll the mature cancellation future so shutdown also wakes a stalled HTTP body.
        let _ = std::future::Future::poll(self.cancelled.as_mut(), cx);
        if let Err(e) = self.check() {
            self.ended = true;
            return Poll::Ready(Some(Err(Box::new(e))));
        }
        let frame = Pin::new(&mut self.inner).poll_frame(cx);
        if let Err(e) = self.check() {
            self.ended = true;
            return Poll::Ready(Some(Err(Box::new(e))));
        }
        if let Some(integrity) = self.integrity.as_mut() {
            if let Poll::Ready(Some(Ok(frame))) = &frame
                && let Some(data) = frame.data_ref()
            {
                integrity.reader.read = integrity.reader.read.saturating_add(data.len() as u64);
                if integrity.reader.read > 1024 * 1024 {
                    self.ended = true;
                    return Poll::Ready(Some(Err(Box::new(S3Error::new(
                        S3ErrorCode::EntityTooLarge,
                    )))));
                }
                if let Some(hash) = integrity.reader.hasher.as_mut() {
                    hash.update(data);
                }
            }
            if matches!(&frame, Poll::Ready(None)) {
                let result = match integrity.reader.read(&mut [0]) {
                    Ok(_) => XmlValidation::Passed,
                    Err(e) => XmlValidation::Failed(
                        e.get_ref()
                            .and_then(|e| e.downcast_ref::<S3Error>())
                            .map(|e| e.code().clone())
                            .unwrap_or(S3ErrorCode::InternalError),
                    ),
                };
                *integrity.result.lock() = result;
                self.integrity = None;
            }
        }
        if matches!(&frame, Poll::Ready(None)) {
            self.ended = true;
        }
        frame
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.ended || (self.integrity.is_none() && self.inner.is_end_stream())
    }
}
enum XmlValidation {
    Pending,
    Passed,
    Failed(S3ErrorCode),
}
struct XmlIntegrity {
    reader: DigestReader<io::Empty>,
    result: Arc<Mutex<XmlValidation>>,
}
struct Scope {
    route: Arc<Route>,
    issuer: Arc<FilesystemStorageIssuer>,
    token: Zeroizing<String>,
    session: OnceLock<Arc<VerifiedFilesystemSession>>,
    xml_validation: OnceLock<Arc<Mutex<XmlValidation>>>,
    runtime: Arc<Runtime>,
    deadline: Instant,
    cancellation: CancellationToken,
}
impl Scope {
    fn proof(&self) -> S3Result<&Arc<VerifiedFilesystemSession>> {
        self.session
            .get()
            .ok_or_else(|| S3Error::new(S3ErrorCode::AccessDenied))
    }
    fn request(&self) -> S3Result<FilesystemRequest> {
        let proof = self.proof()?;
        let r = FilesystemRequest {
            deadline: proof.bounded_deadline(self.deadline),
            cancellation: self.cancellation.clone(),
        };
        r.check(proof).map_err(store_error)?;
        Ok(r)
    }
}
struct Auth {
    scope: Arc<Scope>,
}
#[async_trait::async_trait]
impl S3Auth for Auth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        let session = Arc::new(
            self.scope
                .issuer
                .verify_session(&self.scope.route.name, access_key, &self.scope.token)
                .map_err(|e| S3Error::with_source(S3ErrorCode::InvalidToken, Box::new(e)))?,
        );
        session
            .check(self.scope.deadline)
            .map_err(|e| S3Error::with_source(S3ErrorCode::RequestTimeout, Box::new(e)))?;
        let secret = SecretKey::from(session.secret_access_key());
        self.scope
            .session
            .set(session)
            .map_err(|_| S3Error::new(S3ErrorCode::AccessDenied))?;
        Ok(secret)
    }
}
#[derive(Clone)]
struct Checked(Arc<Scope>);
struct Access {
    scope: Arc<Scope>,
}
#[async_trait::async_trait]
impl S3Access for Access {
    async fn check(&self, ctx: &mut S3AccessContext<'_>) -> S3Result<()> {
        let proof = self.scope.proof()?;
        self.scope.request()?;
        let credential = ctx
            .credentials()
            .ok_or_else(|| S3Error::new(S3ErrorCode::AccessDenied))?;
        if credential.access_key != proof.access_key_id()
            || ctx.s3_path().get_bucket_name() != Some(proof.bucket())
        {
            return Err(S3Error::new(S3ErrorCode::AccessDenied));
        }
        let op = match ctx.s3_op().name() {
            "GetObject" | "HeadObject" => Some(StorageOperation::Read),
            "PutObject" | "CopyObject" => Some(StorageOperation::Write),
            "DeleteObject" => Some(StorageOperation::Delete),
            "CreateMultipartUpload"
            | "UploadPart"
            | "ListParts"
            | "CompleteMultipartUpload"
            | "AbortMultipartUpload" => Some(StorageOperation::Write),
            _ => None,
        };
        if let Some(op) = op
            && !ctx
                .s3_path()
                .get_object_key()
                .is_some_and(|k| proof.allows(op, k))
        {
            return Err(S3Error::new(S3ErrorCode::AccessDenied));
        }
        ctx.extensions_mut().insert(Checked(self.scope.clone()));
        Ok(())
    }
}
struct Backend {
    scope: Arc<Scope>,
}
impl Backend {
    fn checked<T>(&self, r: &S3Request<T>, bucket: &str) -> S3Result<()> {
        if !r
            .extensions
            .get::<Checked>()
            .is_some_and(|c| Arc::ptr_eq(&c.0, &self.scope))
            || bucket != self.scope.proof()?.bucket()
            || r.credentials.as_ref().map(|c| c.access_key.as_str())
                != Some(self.scope.proof()?.access_key_id())
        {
            return Err(S3Error::new(S3ErrorCode::AccessDenied));
        }
        self.scope.request()?;
        if let Some(result) = self.scope.xml_validation.get() {
            match &*result.lock() {
                XmlValidation::Passed => {}
                XmlValidation::Pending => return Err(S3Error::new(S3ErrorCode::InvalidRequest)),
                XmlValidation::Failed(code) => return Err(S3Error::new(code.clone())),
            }
        }
        for (name, value) in
            url::form_urlencoded::parse(r.uri.query().unwrap_or_default().as_bytes())
        {
            if name.starts_with("response-") || (name == "fetch-owner" && value == "true") {
                return Err(S3Error::new(S3ErrorCode::NotImplemented));
            }
        }
        unsupported_headers(&r.headers, &r.method)
    }
    async fn io<T: Send + 'static>(
        &self,
        work: impl FnOnce(Arc<Scope>, FilesystemRequest) -> S3Result<T> + Send + 'static,
    ) -> S3Result<T> {
        let scope = self.scope.clone();
        let request = scope.request()?;
        let handle = scope.runtime.spawn({
            let scope = scope.clone();
            move || {
                request.check(scope.proof()?).map_err(store_error)?;
                work(scope, request)
            }
        })?;
        handle.await.map_err(S3Error::internal_error)?
    }
}
fn unsupported_headers(h: &HeaderMap, method: &http::Method) -> S3Result<()> {
    if method == http::Method::PUT || method == http::Method::POST {
        if [
            "cache-control",
            "content-disposition",
            "content-language",
            "expires",
        ]
        .iter()
        .any(|n| h.contains_key(*n))
        {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        }
        if let Some(encoding) = h.get("content-encoding") {
            let streaming = h.get("x-amz-content-sha256").is_some_and(|value| {
                [
                    "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
                    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
                ]
                .iter()
                .any(|v| value == *v)
            });
            if encoding != "aws-chunked" || !streaming {
                return Err(S3Error::new(S3ErrorCode::NotImplemented));
            }
        }
    }
    for (name, _) in h {
        let n = name.as_str();
        if n.starts_with("x-amz-server-side-encryption")
            || n.starts_with("x-amz-object-lock")
            || n.starts_with("x-amz-grant-")
            || n.starts_with("x-amz-meta-")
            || [
                "x-amz-expected-bucket-owner",
                "x-amz-expected-source-bucket-owner",
                "x-amz-request-payer",
                "x-amz-checksum-mode",
                "x-amz-copy-source-range",
                "x-amz-acl",
                "x-amz-tagging",
                "x-amz-storage-class",
                "x-amz-write-offset-bytes",
                "x-amz-metadata-directive",
                "x-amz-tagging-directive",
            ]
            .contains(&n)
        {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        }
    }
    Ok(())
}
fn store_error(e: FilesystemStoreError) -> S3Error {
    let code = match &e {
        FilesystemStoreError::Forbidden => S3ErrorCode::AccessDenied,
        FilesystemStoreError::NotFound => S3ErrorCode::NoSuchKey,
        FilesystemStoreError::InvalidKey | FilesystemStoreError::InvalidArgument => {
            S3ErrorCode::InvalidArgument
        }
        FilesystemStoreError::InvalidRange => S3ErrorCode::InvalidRange,
        FilesystemStoreError::Precondition => S3ErrorCode::PreconditionFailed,
        FilesystemStoreError::BadDigest => S3ErrorCode::BadDigest,
        FilesystemStoreError::TooLarge => S3ErrorCode::EntityTooLarge,
        FilesystemStoreError::NoSuchUpload => S3ErrorCode::NoSuchUpload,
        FilesystemStoreError::InvalidPart => S3ErrorCode::InvalidPart,
        FilesystemStoreError::InvalidPartOrder => S3ErrorCode::InvalidPartOrder,
        FilesystemStoreError::Cancelled
        | FilesystemStoreError::Session(
            FilesystemSessionError::Expired | FilesystemSessionError::Deadline,
        ) => S3ErrorCode::RequestTimeout,
        FilesystemStoreError::Session(_) => S3ErrorCode::InvalidToken,
        FilesystemStoreError::Io(io) => io
            .get_ref()
            .and_then(|e| e.downcast_ref::<S3Error>())
            .map(|e| e.code().clone())
            .unwrap_or(S3ErrorCode::InternalError),
        _ => S3ErrorCode::InternalError,
    };
    S3Error::with_source(code, Box::new(e))
}
fn etag(info: &FilesystemObjectInfo) -> S3Result<ETag> {
    ETag::parse_http_header(info.etag.as_bytes()).map_err(S3Error::internal_error)
}
fn conditions(
    a: Option<ETagCondition>,
    b: Option<ETagCondition>,
) -> S3Result<FilesystemConditions> {
    fn encode(v: ETagCondition) -> S3Result<String> {
        let h = v.to_http_header().map_err(S3Error::internal_error)?;
        Ok(h.to_str().map_err(S3Error::internal_error)?.to_owned())
    }
    Ok(FilesystemConditions {
        if_match: a.map(encode).transpose()?,
        if_none_match: b.map(encode).transpose()?,
    })
}
fn read_conditions(
    info: &FilesystemObjectInfo,
    a: Option<&ETagCondition>,
    b: Option<&ETagCondition>,
    modified: Option<&Timestamp>,
    unmodified: Option<&Timestamp>,
) -> S3Result<()> {
    let tag = etag(info)?;
    if a.is_some_and(|v| match v {
        ETagCondition::Any => false,
        ETagCondition::ETag(e) => !e.strong_cmp(&tag),
    }) {
        return Err(S3Error::new(S3ErrorCode::PreconditionFailed));
    }
    if b.is_some_and(|v| match v {
        ETagCondition::Any => true,
        ETagCondition::ETag(e) => e.weak_cmp(&tag),
    }) {
        return Err(S3Error::new(S3ErrorCode::NotModified));
    }
    let rounded = match info.modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => std::time::UNIX_EPOCH.checked_add(Duration::from_secs(duration.as_secs())),
        Err(error) => {
            let duration = error.duration();
            let seconds = duration
                .as_secs()
                .checked_add(u64::from(duration.subsec_nanos() != 0))
                .ok_or_else(|| S3Error::new(S3ErrorCode::InternalError))?;
            std::time::UNIX_EPOCH.checked_sub(Duration::from_secs(seconds))
        }
    }
    .ok_or_else(|| S3Error::new(S3ErrorCode::InternalError))?;
    let timestamp = Timestamp::from(rounded);
    if a.is_none() && unmodified.is_some_and(|v| timestamp > *v) {
        return Err(S3Error::new(S3ErrorCode::PreconditionFailed));
    }
    if b.is_none() && modified.is_some_and(|v| timestamp <= *v) {
        return Err(S3Error::new(S3ErrorCode::NotModified));
    }
    Ok(())
}
fn signed_payload(
    body: Option<StreamingBlob>,
    scope: Arc<Scope>,
) -> impl tokio::io::AsyncRead + Unpin + Send {
    let body = body.unwrap_or_else(|| StreamingBlob::from_bytes(Bytes::new()));
    let s = stream::try_unfold((body, scope), |(mut body, scope)| async move {
        let request = scope.request().map_err(io::Error::other)?;
        let item = tokio::select! { biased; _=request.cancellation.cancelled()=>return Err(io::Error::other(S3Error::new(S3ErrorCode::RequestTimeout))), r=tokio::time::timeout_at(request.deadline.into(),body.next())=>r.map_err(|_|io::Error::other(S3Error::new(S3ErrorCode::RequestTimeout)))? };
        match item {
            None => Ok(None),
            Some(Ok(b)) => Ok(Some((b, (body, scope)))),
            Some(Err(e)) => Err(protocol_io(e)),
        }
    });
    StreamReader::new(Box::pin(s))
}
fn protocol_io(e: s3s::StdError) -> io::Error {
    let code = if let Some(v) = e.downcast_ref::<s3s::stream::upload_stream::UploadStreamError>() {
        Some(v.to_s3_error_code())
    } else {
        e.downcast_ref::<s3s::stream::aws_chunked_stream::AwsChunkedStreamError>()
            .map(|v| v.to_s3_error_code())
    };
    match code {
        Some(code) => io::Error::other(S3Error::with_source(code, e)),
        None => io::Error::other(e),
    }
}
const CHECKSUMS: [&str; 10] = [
    "crc32",
    "crc32c",
    "crc64nvme",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "xxhash64",
    "xxhash3",
    "xxhash128",
];
fn checksum_value<'a>(c: &'a Checksum, n: &str) -> Option<&'a str> {
    match n {
        "crc32" => c.checksum_crc32.as_deref(),
        "crc32c" => c.checksum_crc32c.as_deref(),
        "crc64nvme" => c.checksum_crc64nvme.as_deref(),
        "md5" => c.checksum_md5.as_deref(),
        "sha1" => c.checksum_sha1.as_deref(),
        "sha256" => c.checksum_sha256.as_deref(),
        "sha512" => c.checksum_sha512.as_deref(),
        "xxhash64" => c.checksum_xxhash64.as_deref(),
        "xxhash3" => c.checksum_xxhash3.as_deref(),
        "xxhash128" => c.checksum_xxhash128.as_deref(),
        _ => None,
    }
}
struct DigestReader<R> {
    inner: R,
    expected: BTreeMap<String, String>,
    trailers: Option<s3s::TrailingHeaders>,
    declared: Vec<String>,
    hasher: Option<s3s::checksum::ChecksumHasher>,
    length: Option<u64>,
    read: u64,
    result: Arc<Mutex<Option<Checksum>>>,
}
impl<R: Read> DigestReader<R> {
    fn new(
        inner: R,
        headers: &HeaderMap,
        trailers: Option<s3s::TrailingHeaders>,
        length: Option<i64>,
        result: Arc<Mutex<Option<Checksum>>>,
    ) -> S3Result<Self> {
        let mut expected = BTreeMap::new();
        let mut declared = Vec::new();
        for name in CHECKSUMS {
            let h = format!("x-amz-checksum-{name}");
            let mut v = headers.get_all(&h).iter();
            if let Some(value) = v.next() {
                if v.next().is_some() {
                    return Err(S3Error::new(S3ErrorCode::InvalidRequest));
                }
                expected.insert(
                    name.to_owned(),
                    value
                        .to_str()
                        .map_err(|e| {
                            S3Error::with_source(S3ErrorCode::InvalidRequest, Box::new(e))
                        })?
                        .to_owned(),
                );
            }
        }
        for name in ["content-md5", "x-amz-trailer"] {
            if headers.get_all(name).iter().count() > 1 {
                return Err(S3Error::new(S3ErrorCode::InvalidRequest));
            }
        }
        if let Some(v) = headers.get("content-md5") {
            expected.insert(
                "content-md5".into(),
                v.to_str()
                    .map_err(|e| S3Error::with_source(S3ErrorCode::InvalidRequest, Box::new(e)))?
                    .to_owned(),
            );
        }
        if let Some(v) = headers.get("x-amz-trailer") {
            for h in v
                .to_str()
                .map_err(|e| S3Error::with_source(S3ErrorCode::InvalidRequest, Box::new(e)))?
                .split(',')
                .map(str::trim)
            {
                let n = h
                    .strip_prefix("x-amz-checksum-")
                    .filter(|n| CHECKSUMS.contains(n))
                    .ok_or_else(|| S3Error::new(S3ErrorCode::NotImplemented))?;
                if expected.contains_key(n) || declared.iter().any(|s| s == n) {
                    return Err(S3Error::new(S3ErrorCode::InvalidRequest));
                }
                declared.push(n.to_owned());
            }
        }
        let mut hasher = s3s::checksum::ChecksumHasher::default();
        for n in expected.keys().chain(declared.iter()) {
            match n.as_str() {
                "crc32" => hasher.crc32 = Some(s3s::crypto::Crc32::new()),
                "crc32c" => hasher.crc32c = Some(s3s::crypto::Crc32c::new()),
                "crc64nvme" => hasher.crc64nvme = Some(s3s::crypto::Crc64Nvme::new()),
                "md5" | "content-md5" => hasher.md5 = Some(s3s::crypto::Md5::new()),
                "sha1" => hasher.sha1 = Some(s3s::crypto::Sha1::new()),
                "sha256" => hasher.sha256 = Some(s3s::crypto::Sha256::new()),
                "sha512" => hasher.sha512 = Some(s3s::crypto::Sha512::new()),
                "xxhash64" => hasher.xxhash64 = Some(s3s::crypto::XxHash64::new()),
                "xxhash3" => hasher.xxhash3 = Some(s3s::crypto::XxHash3::new()),
                "xxhash128" => hasher.xxhash128 = Some(s3s::crypto::XxHash128::new()),
                _ => return Err(S3Error::new(S3ErrorCode::InvalidRequest)),
            }
        }
        Ok(Self {
            inner,
            expected,
            trailers,
            declared,
            hasher: Some(hasher),
            length: length
                .map(u64::try_from)
                .transpose()
                .map_err(|e| S3Error::with_source(S3ErrorCode::InvalidArgument, Box::new(e)))?,
            read: 0,
            result,
        })
    }
}
impl<R: Read> Read for DigestReader<R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        let n = self.inner.read(b)?;
        if n > 0 {
            self.read = self
                .read
                .checked_add(n as u64)
                .ok_or_else(|| io::Error::other(S3Error::new(S3ErrorCode::EntityTooLarge)))?;
            if let Some(h) = self.hasher.as_mut() {
                h.update(&b[..n]);
            }
            return Ok(n);
        }
        if let Some(h) = self.hasher.take() {
            if self.length.is_some_and(|n| n != self.read) {
                return Err(io::Error::other(S3Error::new(S3ErrorCode::IncompleteBody)));
            }
            if !self.declared.is_empty() {
                let headers = self
                    .trailers
                    .as_ref()
                    .and_then(|h| h.take())
                    .ok_or_else(|| io::Error::other(S3Error::new(S3ErrorCode::InvalidRequest)))?;
                for n in &self.declared {
                    let mut values = headers.get_all(format!("x-amz-checksum-{n}")).iter();
                    let value = values
                        .next()
                        .and_then(|v| v.to_str().ok())
                        .filter(|_| values.next().is_none())
                        .ok_or_else(|| {
                            io::Error::other(S3Error::new(S3ErrorCode::InvalidRequest))
                        })?;
                    self.expected.insert(n.clone(), value.to_owned());
                }
            }
            let mut actual = h.finalize();
            for (n, v) in &self.expected {
                if checksum_value(&actual, if n == "content-md5" { "md5" } else { n })
                    != Some(v.as_str())
                {
                    return Err(io::Error::other(S3Error::new(S3ErrorCode::BadDigest)));
                }
            }
            if !self.expected.contains_key("md5") {
                actual.checksum_md5 = None;
            }
            *self.result.lock() = Some(actual);
        }
        Ok(0)
    }
}
macro_rules! output_checksums {
    ($out:expr,$c:expr) => {{
        let c = $c;
        $out.checksum_crc32 = c.checksum_crc32;
        $out.checksum_crc32c = c.checksum_crc32c;
        $out.checksum_crc64nvme = c.checksum_crc64nvme;
        $out.checksum_md5 = c.checksum_md5;
        $out.checksum_sha1 = c.checksum_sha1;
        $out.checksum_sha256 = c.checksum_sha256;
        $out.checksum_sha512 = c.checksum_sha512;
        $out.checksum_xxhash64 = c.checksum_xxhash64;
        $out.checksum_xxhash3 = c.checksum_xxhash3;
        $out.checksum_xxhash128 = c.checksum_xxhash128;
    }};
}
#[async_trait::async_trait]
impl S3 for Backend {
    async fn get_object(
        &self,
        r: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        self.checked(&r, &r.input.bucket)?;
        let i = r.input;
        if i.version_id.is_some() || i.part_number.is_some() {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        }
        let requested_range = i.range.is_some();
        let (object, start, end) = self
            .io(move |scope, request| {
                let mut object = scope
                    .route
                    .store
                    .open_range(scope.proof()?, &i.key, None, &request)
                    .map_err(store_error)?;
                read_conditions(
                    &object.info,
                    i.if_match.as_ref(),
                    i.if_none_match.as_ref(),
                    i.if_modified_since.as_ref(),
                    i.if_unmodified_since.as_ref(),
                )?;
                let range = i
                    .range
                    .as_ref()
                    .map(|range| range.check(object.info.size))
                    .transpose()
                    .map_err(|e| S3Error::with_source(S3ErrorCode::InvalidRange, Box::new(e)))?
                    .unwrap_or(0..object.info.size);
                if i.range.is_some() && range.is_empty() {
                    return Err(S3Error::new(S3ErrorCode::InvalidRange));
                }
                std::io::Seek::seek(&mut object.file, std::io::SeekFrom::Start(range.start))
                    .map_err(S3Error::internal_error)?;
                Ok((object, range.start, range.end))
            })
            .await?;
        let info = object.info;
        let length = end - start;
        let partial = requested_range;
        let content_range = partial.then(|| format!("bytes {start}-{}/{}", end - 1, info.size));
        let scope = self.scope.clone();
        let stream = stream::try_unfold(
            (object.file, length, scope),
            |(mut file, left, scope)| async move {
                if left == 0 {
                    return Ok::<_, S3Error>(None);
                }
                let request = scope.request()?;
                let worker_scope = scope.clone();
                let result = scope
                    .runtime
                    .spawn(move || {
                        request.check(worker_scope.proof()?).map_err(store_error)?;
                        let mut buffer = vec![
                            0;
                            usize::try_from(left.min(16384))
                                .map_err(S3Error::internal_error)?
                        ];
                        let n = file.read(&mut buffer).map_err(S3Error::internal_error)?;
                        if n == 0 {
                            return Err(S3Error::new(S3ErrorCode::IncompleteBody));
                        }
                        request.check(worker_scope.proof()?).map_err(store_error)?;
                        buffer.truncate(n);
                        Ok((file, Bytes::from(buffer), left - n as u64))
                    })?
                    .await
                    .map_err(S3Error::internal_error)??;
                Ok(Some((result.1, (result.0, result.2, scope))))
            },
        );
        let out = GetObjectOutput {
            body: Some(StreamingBlob::wrap(stream)),
            accept_ranges: Some("bytes".into()),
            content_length: Some(i64::try_from(length).map_err(S3Error::internal_error)?),
            content_range,
            content_type: Some(info.content_type.clone()),
            e_tag: Some(etag(&info)?),
            last_modified: Some(info.modified.into()),
            ..Default::default()
        };
        let mut response = S3Response::new(out);
        if partial {
            response.status = Some(StatusCode::PARTIAL_CONTENT);
        }
        Ok(response)
    }
    async fn head_object(
        &self,
        r: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        self.checked(&r, &r.input.bucket)?;
        let i = r.input;
        if i.version_id.is_some() || i.part_number.is_some() {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        }
        let (info, range) = self
            .io(move |scope, request| {
                let info = scope
                    .route
                    .store
                    .head(scope.proof()?, &i.key, &request)
                    .map_err(store_error)?;
                read_conditions(
                    &info,
                    i.if_match.as_ref(),
                    i.if_none_match.as_ref(),
                    i.if_modified_since.as_ref(),
                    i.if_unmodified_since.as_ref(),
                )?;
                let range = i
                    .range
                    .as_ref()
                    .map(|r| r.check(info.size))
                    .transpose()
                    .map_err(|e| S3Error::with_source(S3ErrorCode::InvalidRange, Box::new(e)))?;
                if range.as_ref().is_some_and(|r| r.is_empty()) {
                    return Err(S3Error::new(S3ErrorCode::InvalidRange));
                }
                Ok((info, range))
            })
            .await?;
        let out = HeadObjectOutput {
            accept_ranges: Some("bytes".into()),
            content_length: Some(
                i64::try_from(range.as_ref().map_or(info.size, |r| r.end - r.start))
                    .map_err(S3Error::internal_error)?,
            ),
            content_range: range
                .as_ref()
                .map(|r| format!("bytes {}-{}/{}", r.start, r.end - 1, info.size)),
            content_type: Some(info.content_type.clone()),
            e_tag: Some(etag(&info)?),
            last_modified: Some(info.modified.into()),
            ..Default::default()
        };
        let mut response = S3Response::new(out);
        if range.is_some() {
            response.status = Some(StatusCode::PARTIAL_CONTENT);
        }
        Ok(response)
    }
    async fn put_object(
        &self,
        r: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        self.checked(&r, &r.input.bucket)?;
        let i = r.input;
        let conditions = conditions(i.if_match, i.if_none_match)?;
        let result = Arc::new(Mutex::new(None));
        let stream = signed_payload(i.body, self.scope.clone());
        let mut body = DigestReader::new(
            SyncIoBridge::new(stream),
            &r.headers,
            r.trailing_headers,
            i.content_length,
            result.clone(),
        )?;
        let info = self
            .io(move |scope, request| {
                scope
                    .route
                    .store
                    .put(
                        scope.proof()?,
                        &i.key,
                        &mut body,
                        FilesystemPutOptions {
                            content_type: i.content_type.as_deref(),
                            expected_digest: None,
                            conditions: &conditions,
                        },
                        &request,
                    )
                    .map_err(store_error)
            })
            .await?;
        let mut out = PutObjectOutput {
            e_tag: Some(etag(&info)?),
            size: Some(i64::try_from(info.size).map_err(S3Error::internal_error)?),
            ..Default::default()
        };
        if let Some(c) = result.lock().take() {
            output_checksums!(out, c);
        }
        Ok(S3Response::new(out))
    }
    async fn delete_object(
        &self,
        r: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        self.checked(&r, &r.input.bucket)?;
        if r.input.version_id.is_some()
            || r.input.if_match_size.is_some()
            || r.input.if_match_last_modified_time.is_some()
        {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        }
        let condition = conditions(r.input.if_match, None)?;
        self.io(move |scope, request| {
            match condition.if_match.as_deref() {
                Some(if_match) => scope.route.store.delete_if_match(
                    scope.proof()?,
                    &r.input.key,
                    if_match,
                    &request,
                ),
                None => scope
                    .route
                    .store
                    .delete(scope.proof()?, &r.input.key, &request),
            }
            .map_err(store_error)
        })
        .await?;
        Ok(S3Response::new(DeleteObjectOutput::default()))
    }
    async fn copy_object(
        &self,
        r: S3Request<CopyObjectInput>,
    ) -> S3Result<S3Response<CopyObjectOutput>> {
        self.checked(&r, &r.input.bucket)?;
        let i = r.input;
        let CopySource::Bucket {
            bucket,
            key: source,
            version_id: None,
        } = i.copy_source
        else {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        };
        if bucket.as_ref() != i.bucket
            || i.copy_source_if_modified_since.is_some()
            || i.copy_source_if_unmodified_since.is_some()
            || i.content_type.is_some()
            || i.checksum_algorithm.is_some()
        {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        }
        let source_conditions = conditions(i.copy_source_if_match, i.copy_source_if_none_match)?;
        let target_conditions = conditions(i.if_match, i.if_none_match)?;
        let info = self
            .io(move |scope, request| {
                scope
                    .route
                    .store
                    .copy(
                        scope.proof()?,
                        &source,
                        &i.key,
                        FilesystemCopyOptions {
                            source_conditions: &source_conditions,
                            target_conditions: &target_conditions,
                        },
                        &request,
                    )
                    .map_err(store_error)
            })
            .await?;
        Ok(S3Response::new(CopyObjectOutput {
            copy_object_result: Some(CopyObjectResult {
                e_tag: Some(etag(&info)?),
                last_modified: Some(info.modified.into()),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }
    async fn list_objects_v2(
        &self,
        r: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        self.checked(&r, &r.input.bucket)?;
        let i = r.input;
        let encoding = match i.encoding_type.as_ref().map(|v| v.as_str()) {
            None => FilesystemListEncoding::Plain,
            Some("url") => FilesystemListEncoding::Url,
            Some(_) => return Err(S3Error::new(S3ErrorCode::InvalidArgument)),
        };
        let native_input = i.clone();
        let page = self
            .io(move |scope, request| {
                let native = FilesystemListRequest {
                    prefix: native_input.prefix.as_deref().unwrap_or(""),
                    delimiter: native_input.delimiter.as_deref(),
                    start_after: native_input.start_after.as_deref(),
                    continuation_token: native_input.continuation_token.as_deref(),
                    max_keys: native_input.max_keys,
                    encoding,
                };
                scope
                    .route
                    .store
                    .list(scope.proof()?, native, &request)
                    .map_err(store_error)
            })
            .await?;
        let contents = page
            .objects
            .into_iter()
            .map(|o| {
                Ok(Object {
                    key: Some(o.key),
                    size: Some(i64::try_from(o.info.size).map_err(S3Error::internal_error)?),
                    e_tag: Some(etag(&o.info)?),
                    last_modified: Some(o.info.modified.into()),
                    ..Default::default()
                })
            })
            .collect::<S3Result<Vec<_>>>()?;
        Ok(S3Response::new(ListObjectsV2Output {
            name: Some(i.bucket),
            prefix: i.prefix,
            delimiter: i.delimiter,
            start_after: i.start_after,
            continuation_token: i.continuation_token,
            max_keys: Some(i.max_keys.filter(|n| *n != 0).unwrap_or(1000)),
            key_count: Some(i32::try_from(page.key_count).map_err(S3Error::internal_error)?),
            is_truncated: Some(page.is_truncated),
            next_continuation_token: page.next_token,
            encoding_type: i.encoding_type,
            contents: Some(contents),
            common_prefixes: Some(
                page.common_prefixes
                    .into_iter()
                    .map(|prefix| CommonPrefix {
                        prefix: Some(prefix),
                    })
                    .collect(),
            ),
            ..Default::default()
        }))
    }
    async fn delete_objects(
        &self,
        r: S3Request<DeleteObjectsInput>,
    ) -> S3Result<S3Response<DeleteObjectsOutput>> {
        self.checked(&r, &r.input.bucket)?;
        if r.input
            .delete
            .objects
            .iter()
            .any(|o| o.version_id.is_some())
        {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        }
        let keys = r
            .input
            .delete
            .objects
            .into_iter()
            .map(|o| o.key)
            .collect::<Vec<_>>();
        let quiet = r.input.delete.quiet.unwrap_or(false);
        let results = self
            .io(move |scope, request| {
                scope
                    .route
                    .store
                    .delete_batch(scope.proof()?, &keys, quiet, &request)
                    .map_err(store_error)
            })
            .await?;
        let mut out = DeleteObjectsOutput::default();
        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        for item in results {
            match item.result {
                Ok(()) => deleted.push(DeletedObject {
                    key: Some(item.key),
                    ..Default::default()
                }),
                Err(e) => {
                    let e = store_error(e);
                    errors.push(s3s::dto::Error {
                        key: Some(item.key),
                        code: Some(e.code().as_str().to_owned()),
                        message: Some(e.code().as_str().to_owned()),
                        ..Default::default()
                    });
                }
            }
        }
        out.deleted = Some(deleted);
        out.errors = Some(errors);
        Ok(S3Response::new(out))
    }
    async fn create_multipart_upload(
        &self,
        r: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        self.checked(&r, &r.input.bucket)?;
        let i = r.input;
        if i.checksum_algorithm.is_some() || i.checksum_type.is_some() {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        }
        let bucket = i.bucket.clone();
        let key = i.key.clone();
        let id = self
            .io(move |scope, request| {
                scope
                    .route
                    .store
                    .create_upload(scope.proof()?, &i.key, i.content_type.as_deref(), &request)
                    .map_err(store_error)
            })
            .await?;
        Ok(S3Response::new(CreateMultipartUploadOutput {
            bucket: Some(bucket),
            key: Some(key),
            upload_id: Some(id),
            ..Default::default()
        }))
    }
    async fn upload_part(
        &self,
        r: S3Request<UploadPartInput>,
    ) -> S3Result<S3Response<UploadPartOutput>> {
        self.checked(&r, &r.input.bucket)?;
        let i = r.input;
        let result = Arc::new(Mutex::new(None));
        let stream = signed_payload(i.body, self.scope.clone());
        let mut body = DigestReader::new(
            SyncIoBridge::new(stream),
            &r.headers,
            r.trailing_headers,
            i.content_length,
            result.clone(),
        )?;
        let info = self
            .io(move |scope, request| {
                scope
                    .route
                    .store
                    .upload_part(
                        scope.proof()?,
                        &i.key,
                        &i.upload_id,
                        i.part_number,
                        &mut body,
                        &request,
                    )
                    .map_err(store_error)
            })
            .await?;
        let mut out = UploadPartOutput {
            e_tag: Some(
                ETag::parse_http_header(info.etag.as_bytes()).map_err(S3Error::internal_error)?,
            ),
            ..Default::default()
        };
        if let Some(c) = result.lock().take() {
            output_checksums!(out, c);
        }
        Ok(S3Response::new(out))
    }
    async fn list_parts(
        &self,
        r: S3Request<ListPartsInput>,
    ) -> S3Result<S3Response<ListPartsOutput>> {
        self.checked(&r, &r.input.bucket)?;
        let i = r.input;
        let bucket = i.bucket.clone();
        let key = i.key.clone();
        let id = i.upload_id.clone();
        let marker = i.part_number_marker;
        let max = i.max_parts;
        let page = self
            .io(move |scope, request| {
                scope
                    .route
                    .store
                    .list_parts(
                        scope.proof()?,
                        &i.key,
                        FilesystemPartsRequest {
                            upload_id: &i.upload_id,
                            marker: i.part_number_marker,
                            max_parts: i.max_parts,
                        },
                        &request,
                    )
                    .map_err(store_error)
            })
            .await?;
        let parts = page
            .parts
            .into_iter()
            .map(|p| {
                Ok(Part {
                    part_number: Some(p.number),
                    e_tag: Some(
                        ETag::parse_http_header(p.etag.as_bytes())
                            .map_err(S3Error::internal_error)?,
                    ),
                    size: Some(i64::try_from(p.size).map_err(S3Error::internal_error)?),
                    last_modified: Some(p.modified.into()),
                    ..Default::default()
                })
            })
            .collect::<S3Result<Vec<_>>>()?;
        Ok(S3Response::new(ListPartsOutput {
            bucket: Some(bucket),
            key: Some(key),
            upload_id: Some(id),
            part_number_marker: marker,
            max_parts: Some(max.filter(|n| *n != 0).unwrap_or(1000)),
            is_truncated: Some(page.is_truncated),
            next_part_number_marker: page.next_marker,
            parts: Some(parts),
            ..Default::default()
        }))
    }
    async fn complete_multipart_upload(
        &self,
        r: S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<CompleteMultipartUploadOutput>> {
        self.checked(&r, &r.input.bucket)?;
        let i = r.input;
        if CHECKSUMS
            .iter()
            .any(|n| r.headers.contains_key(format!("x-amz-checksum-{n}")))
            || i.mpu_object_size.is_some()
        {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        }
        let parts = i
            .multipart_upload
            .and_then(|u| u.parts)
            .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidPart))?
            .into_iter()
            .map(|p| {
                if p.checksum_crc32.is_some()
                    || p.checksum_crc32c.is_some()
                    || p.checksum_crc64nvme.is_some()
                    || p.checksum_md5.is_some()
                    || p.checksum_sha1.is_some()
                    || p.checksum_sha256.is_some()
                    || p.checksum_sha512.is_some()
                    || p.checksum_xxhash64.is_some()
                    || p.checksum_xxhash3.is_some()
                    || p.checksum_xxhash128.is_some()
                {
                    return Err(S3Error::new(S3ErrorCode::NotImplemented));
                }
                Ok(FilesystemCompletedPart {
                    number: p
                        .part_number
                        .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidPart))?,
                    etag: p
                        .e_tag
                        .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidPart))?
                        .to_http_header()
                        .map_err(S3Error::internal_error)?
                        .to_str()
                        .map_err(S3Error::internal_error)?
                        .to_owned(),
                })
            })
            .collect::<S3Result<Vec<_>>>()?;
        let conditions = conditions(i.if_match, i.if_none_match)?;
        let bucket = i.bucket.clone();
        let key = i.key.clone();
        let info = self
            .io(move |scope, request| {
                scope
                    .route
                    .store
                    .complete_upload(
                        scope.proof()?,
                        &i.key,
                        FilesystemCompleteUpload {
                            upload_id: &i.upload_id,
                            parts: &parts,
                            conditions: &conditions,
                        },
                        &request,
                    )
                    .map_err(store_error)
            })
            .await?;
        Ok(S3Response::new(CompleteMultipartUploadOutput {
            bucket: Some(bucket),
            key: Some(key),
            e_tag: Some(etag(&info)?),
            ..Default::default()
        }))
    }
    async fn abort_multipart_upload(
        &self,
        r: S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        self.checked(&r, &r.input.bucket)?;
        if r.input.if_match_initiated_time.is_some() {
            return Err(S3Error::new(S3ErrorCode::NotImplemented));
        }
        self.io(move |scope, request| {
            scope
                .route
                .store
                .abort_upload(scope.proof()?, &r.input.key, &r.input.upload_id, &request)
                .map_err(store_error)
        })
        .await?;
        Ok(S3Response::new(AbortMultipartUploadOutput::default()))
    }
    async fn get_bucket_location(
        &self,
        r: S3Request<GetBucketLocationInput>,
    ) -> S3Result<S3Response<GetBucketLocationOutput>> {
        self.checked(&r, &r.input.bucket)?;
        let region = self.scope.proof()?.region();
        Ok(S3Response::new(GetBucketLocationOutput {
            location_constraint: (region != "us-east-1").then(|| region.to_owned().into()),
        }))
    }
}
