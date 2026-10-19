//! Configured Axum ingress for the mature filesystem S3 gateway.
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    response::Response,
    routing::any,
};
use broker_storage::{FilesystemGateway, FilesystemGatewayError};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

struct Ingress {
    gateways: Vec<Arc<FilesystemGateway>>,
    timeout: Duration,
    closed: AtomicBool,
}

/// The enclosing server owns listeners and joins connections before releasing volumes.
pub struct FilesystemStorageHttp {
    ingress: Arc<Ingress>,
    buckets: BTreeMap<String, usize>,
}

impl FilesystemStorageHttp {
    pub fn new(
        gateways: Vec<Arc<FilesystemGateway>>,
        request_timeout: Duration,
    ) -> Result<Self, FilesystemGatewayError> {
        if request_timeout.is_zero() || Instant::now().checked_add(request_timeout).is_none() {
            return Err(FilesystemGatewayError::InvalidConfiguration);
        }
        let mut buckets = BTreeMap::new();
        for (index, gateway) in gateways.iter().enumerate() {
            for bucket in gateway.buckets() {
                if buckets.insert(bucket.to_owned(), index).is_some() {
                    return Err(FilesystemGatewayError::InvalidConfiguration);
                }
            }
        }
        Ok(Self {
            ingress: Arc::new(Ingress {
                gateways,
                timeout: request_timeout,
                closed: AtomicBool::new(false),
            }),
            buckets,
        })
    }

    /// Register only configured buckets; no wildcard fallback consumes other APIs.
    pub fn router(&self) -> Router {
        let mut router = Router::new();
        for (bucket, index) in &self.buckets {
            let state = (self.ingress.clone(), *index);
            router = router
                .route(&format!("/{bucket}"), any(handle).with_state(state.clone()))
                .route(
                    &format!("/{bucket}/"),
                    any(handle).with_state(state.clone()),
                )
                .route(
                    &format!("/{bucket}/{{*key}}"),
                    any(handle).with_state(state),
                );
        }
        router
    }

    /// Close admission and await every gateway's IO using the same Original.
    pub async fn shutdown(&self, original: Instant) -> Result<(), FilesystemGatewayError> {
        self.ingress.closed.store(true, Ordering::Release);
        let results = futures_util::future::join_all(
            self.ingress
                .gateways
                .iter()
                .map(|gateway| gateway.shutdown(original)),
        )
        .await;
        for result in results {
            result?;
        }
        Ok(())
    }

    /// After closing and joining HTTP connections, retain volumes until all owned IO finishes.
    pub async fn join_closed(&self) -> Result<(), FilesystemGatewayError> {
        let results = futures_util::future::join_all(
            self.ingress
                .gateways
                .iter()
                .map(|gateway| gateway.join_closed()),
        )
        .await;
        for result in results {
            result?;
        }
        Ok(())
    }
}

async fn handle(
    State((ingress, index)): State<(Arc<Ingress>, usize)>,
    request: Request,
) -> Response {
    if ingress.closed.load(Ordering::Acquire) {
        let response = s3s::S3Error::new(s3s::S3ErrorCode::ServiceUnavailable).to_http_response();
        return match response {
            Ok(response) => response.map(Body::new),
            Err(_) => Response::builder()
                .status(503)
                .body(Body::empty())
                .expect("constant status"),
        };
    }
    let Some(original) = Instant::now().checked_add(ingress.timeout) else {
        return Response::builder()
            .status(503)
            .body(Body::empty())
            .expect("constant status");
    };
    match ingress.gateways[index]
        .handle(request.map(s3s::Body::http_body_unsync), original)
        .await
    {
        Ok(response) => response.map(Body::new),
        Err(_) => Response::builder()
            .status(502)
            .body(Body::empty())
            .expect("constant status"),
    }
}
