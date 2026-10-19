//! Native rerank settings; secrets and runtime owners never enter the administrative view.
use super::embeddings_config::{
    ManifestBounds, Transport, declared_metadata, gguf_source, google_endpoints, local_identity,
    local_idle_timeout, local_provider, local_recipe, local_threads,
};
use super::*;
use broker_control::RerankAdmissionLimits;
use broker_presence::{
    LocalRerankConfig, RemoteEmbeddingsConfig, RemoteRerankConfig, RerankBackend, RerankHttpConfig,
};
use graphit_ai::{
    context::InferenceContext,
    embedding::EmbeddingLimits,
    gguf_rerank::GgufRerankOptions,
    model_manifest::{ModelBackend, decode_manifest},
    native_rerank::NativeRerankLimits,
    ranking::RankingLimits,
};
use graphit_auth::broker::{BrokerModelIdentity, BrokerRerankService};
use graphit_core::{file_lock::Cancellation, native_document_file::CapturedDocumentDirectory};
use graphit_http::client::{BoundedClient, ClientPolicy, Limits};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rerank {
    pub(super) enabled: bool,
    #[serde(default)]
    revision: String,
    #[serde(default)]
    max_documents: usize,
    #[serde(default)]
    max_document_bytes: usize,
    request_timeout: Option<Budget>,
    required_scopes: Option<Vec<String>>,
    request_body_bytes: Option<NonZeroUsize>,
    response_body_bytes: Option<NonZeroUsize>,
    identity_json_bytes: Option<NonZeroUsize>,
    grants_json_bytes: Option<NonZeroUsize>,
    max_batch: Option<NonZeroUsize>,
    dimensions: Option<NonZeroUsize>,
    cache: Option<Cache>,
    upstream: Option<Upstream>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cache {
    ttl: Budget,
    max_entries: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    protocol: String,
    #[serde(default)]
    model: String,
    model_revision: Option<String>,
    recipe: Option<String>,
    service_revision: Option<String>,
    max_documents: Option<NonZeroUsize>,
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
pub(crate) struct PreparedRerank {
    pub http: RerankHttpConfig,
    pub backend: Arc<RerankBackend>,
    pub(super) view: serde_json::Value,
}
fn required<T>(v: Option<T>) -> Result<T, ServerError> {
    v.ok_or(ServerError::Configuration)
}
fn nz(v: usize) -> Result<NonZeroUsize, ServerError> {
    let v = NonZeroUsize::new(v).ok_or(ServerError::Configuration)?;
    presence_sql_cap(v)?;
    Ok(v)
}
fn embedding(protocol: &str) -> bool {
    matches!(
        protocol,
        "openai"
            | "openai-compatible"
            | "openai-embeddings-v1"
            | "cohere-embed-v2"
            | "voyage-embeddings-v1"
            | "google"
            | "google-embed-content-v1beta"
            | "gemini"
            | "gemini-embed-content-v1beta"
    )
}
fn google(protocol: &str) -> bool {
    matches!(
        protocol,
        "google" | "google-embed-content-v1beta" | "gemini" | "gemini-embed-content-v1beta"
    )
}
fn client(t: Transport, base: &Path, endpoint: &str) -> Result<BoundedClient, ServerError> {
    let url = Url::parse(endpoint).map_err(|_| ServerError::Configuration)?;
    let origin = url.origin().ascii_serialization();
    let mut roots = Vec::new();
    if let Some(path) = t.ca_file {
        let bytes = read_bounded(
            &resolve(base, path)?,
            t.max_certificate_bytes.get(),
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
    let refs = roots.iter().map(Vec::as_slice).collect::<Vec<_>>();
    BoundedClient::new(
        ClientPolicy {
            origin: &origin,
            allow_loopback_http: t.allow_loopback_http,
            proxy: None,
            additional_roots: &refs,
        },
        Limits {
            request_body_bytes: t.request_body_bytes.get(),
            response_body_bytes: t.response_body_bytes.get(),
            url_bytes: t.url_bytes.get(),
            header_bytes: t.header_bytes.get(),
            header_count: t.header_count.get(),
            max_in_flight: t.max_in_flight.get(),
            max_idle_per_host: t.max_idle_per_host.get(),
            idle_timeout: t.idle_timeout.0,
            max_certificates: t.max_certificates.get(),
            max_certificate_bytes: t.max_certificate_bytes.get(),
        },
    )
    .map_err(|_| ServerError::Configuration)
}
fn headers(u: &Upstream) -> Result<axum::http::HeaderMap, ServerError> {
    let mut result = axum::http::HeaderMap::new();
    let is_google = google(&u.protocol);
    if let Some(key) = u.api_key.as_ref().filter(|k| !k.0.is_empty()) {
        let name = u
            .api_key_header
            .as_deref()
            .filter(|s| !s.is_empty())
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
        let scheme = u
            .api_key_scheme
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(if is_google { "" } else { "Bearer" })
            .trim();
        let value = Zeroizing::new(if scheme.is_empty() {
            key.0.to_string()
        } else {
            format!("{scheme} {}", key.0.as_str())
        });
        let mut value =
            axum::http::HeaderValue::from_str(&value).map_err(|_| ServerError::Configuration)?;
        value.set_sensitive(true);
        result.insert(name, value);
    }
    Ok(result)
}
impl Rerank {
    pub(super) fn needs_native_sdk(&self) -> bool {
        self.enabled
            && self.upstream.as_ref().is_some_and(|u| {
                u.protocol
                    .trim()
                    .eq_ignore_ascii_case("gguf-bge-reranker-v2-m3")
            })
    }
    pub(super) async fn prepare(
        self,
        snapshot_parent: Option<Arc<CapturedDocumentDirectory>>,
        base: &Path,
        audience: &str,
        startup_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> Result<PreparedRerank, ServerError> {
        let scopes = required(self.required_scopes)?;
        presence_scopes(&scopes, true)?;
        let docs = nz(if self.max_documents == 0 {
            1000
        } else {
            self.max_documents
        })?;
        let docbytes = nz(if self.max_document_bytes == 0 {
            1024 * 1024
        } else {
            self.max_document_bytes
        })?;
        let batch = required(self.max_batch)?;
        presence_sql_cap(batch)?;
        let request = required(self.request_body_bytes)?;
        let response = required(self.response_body_bytes)?;
        let identity = required(self.identity_json_bytes)?;
        let grants = required(self.grants_json_bytes)?;
        for cap in [request, response, identity, grants] {
            presence_sql_cap(cap)?;
        }
        let timeout = self
            .request_timeout
            .map(|v| v.0)
            .unwrap_or(Duration::from_secs(45));
        let (cache_ttl, cache_entries) = self
            .cache
            .map(|c| (c.ttl.0, c.max_entries))
            .unwrap_or((Duration::from_secs(300), 1000));
        let mut u = required(self.upstream)?;
        u.protocol = u.protocol.trim().to_ascii_lowercase();
        if u.protocol != "graphit-rerank-v1"
            && (u.service_revision.is_some() || u.max_documents.is_some())
        {
            return Err(ServerError::Configuration);
        }
        let cosine = embedding(&u.protocol);
        let dimensions = if cosine {
            required(self.dimensions)?.get()
        } else {
            if self.dimensions.is_some() || u.send_dimensions {
                return Err(ServerError::Configuration);
            }
            1
        };
        let ranking = RankingLimits::new(
            docs.get(),
            dimensions,
            docs.get()
                .checked_add(1)
                .and_then(|n| n.checked_mul(dimensions))
                .ok_or(ServerError::Configuration)?,
        )
        .map_err(|_| ServerError::Configuration)?;
        let mut view = serde_json::json!({"protocol":u.protocol,"model":u.model,"url":u.url,
 "api_key":u.api_key.as_ref().map(admin_config_view::secret_marker).unwrap_or(""),
 "api_key_header":u.api_key_header,"api_key_scheme":u.api_key_scheme,"send_dimensions":u.send_dimensions,
 "transport":u.transport.as_ref().map(|t|t.view(base)).transpose()?,"manifest_limits":u.manifest_limits});
        if u.protocol == "graphit-rerank-v1" {
            view["service_revision"] = serde_json::json!(u.service_revision);
            view["max_documents"] = serde_json::json!(u.max_documents);
        }
        let (backend, revision, model, model_revision, recipe) = if u.protocol
            == "gguf-bge-reranker-v2-m3"
        {
            if u.model_revision.is_some() {
                return Err(ServerError::Configuration);
            }
            if u.url.is_some()
                || u.api_key.is_some()
                || u.api_key_header.is_some()
                || u.api_key_scheme.is_some()
                || u.transport.is_some()
                || u.send_dimensions
                || u.model.trim().is_empty()
            {
                return Err(ServerError::Configuration);
            }
            let bundle = resolve(base, required(u.directory)?)?
                .canonicalize()
                .map_err(|_| ServerError::ConfigurationIo)?;
            let manifest_path = resolve(base, required(u.manifest_file)?)?;
            let bounds = required(u.manifest_limits)?;
            let maximum_bytes = required(u.max_artifact_bytes)?.get();
            let threads = local_threads(u.threads)?;
            let capacity = u.queue_capacity.unwrap_or(NonZeroUsize::new(8).unwrap());
            let cancel = Cancellation::default();
            let end = Instant::now()
                .checked_add(startup_timeout)
                .ok_or(ServerError::Configuration)?;
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
            if manifest.id != u.model {
                return Err(ServerError::Configuration);
            }
            let ModelBackend::BgeRerankerV2M3 {
                ref model_role,
                ref recipe,
            } = manifest.backend
            else {
                return Err(ServerError::Configuration);
            };
            let source = gguf_source(&manifest, model_role, bundle.clone(), maximum_bytes)?;
            let limits = NativeRerankLimits::new(
                docs.get(),
                batch.get(),
                request.get(),
                request.get(),
                response.get(),
            )
            .map_err(|_| ServerError::Configuration)?;
            let options = GgufRerankOptions {
                threads,
                max_tokens: NonZeroU32::new(
                    u32::try_from(recipe.max_tokens).map_err(|_| ServerError::Configuration)?,
                )
                .ok_or(ServerError::Configuration)?,
                provider: local_provider(u.device.as_deref())?,
                device_id: u.device_id,
                precision: recipe.precision,
                score: recipe.score,
            };
            let idle_timeout = local_idle_timeout(u.idle_timeout_seconds)?;
            let identity = local_identity(&bytes)?;
            view["directory"] = serde_json::json!(bundle);
            view["manifest_file"] = serde_json::json!(manifest_path);
            view["max_artifact_bytes"] = serde_json::json!(maximum_bytes);
            view["threads"] = serde_json::json!(threads);
            view["queue_capacity"] = serde_json::json!(capacity);
            view["idle_timeout_seconds"] = serde_json::json!(idle_timeout.as_secs());
            view["device"] = serde_json::json!(u.device.as_deref().unwrap_or("cpu"));
            view["device_id"] = serde_json::json!(options.device_id);
            let model = source.model.clone();
            let model_revision = source.revision.clone();
            let backend = RerankBackend::local(
                LocalRerankConfig {
                    snapshot_parent: snapshot_parent.ok_or(ServerError::Configuration)?,
                    source,
                    options,
                    limits,
                    capacity,
                    idle_timeout,
                    shutdown_timeout,
                },
                &identity,
                ranking,
            )
            .map_err(|_| ServerError::Configuration)?;
            let prefix = if self.revision.trim().is_empty() {
                model.as_str()
            } else {
                self.revision.trim()
            };
            let revision = format!(
                "{prefix}@sha256:{}",
                backend.local_identity().ok_or(ServerError::Configuration)?
            );
            let recipe = local_recipe(&bytes, u.recipe)?;
            (backend, revision, model, model_revision, recipe)
        } else {
            if u.directory.is_some()
                || u.manifest_file.is_some()
                || u.max_artifact_bytes.is_some()
                || u.threads.is_some()
                || u.queue_capacity.is_some()
                || u.idle_timeout_seconds.is_some()
                || u.device.is_some()
                || u.device_id != 0
                || u.manifest_limits.is_some()
                || self.revision.trim().is_empty()
            {
                return Err(ServerError::Configuration);
            }
            let model = declared_metadata(u.model.clone())?;
            let model_revision = declared_metadata(required(u.model_revision.clone())?)?;
            let recipe = declared_metadata(required(u.recipe.clone())?)?;
            let headers = headers(&u)?;
            let endpoint = required(u.url)?;
            let transport = required(u.transport)?;
            let req = transport.request_body_bytes.get();
            let res = transport.response_body_bytes.get();
            let client = client(transport, base, &endpoint)?;
            let backend = if cosine {
                let (endpoint, batch_endpoint, model, family) = if google(&u.protocol) {
                    let (one, many, model, family) = google_endpoints(&endpoint, &u.model)?;
                    (one, Some(many), model, Some(family))
                } else {
                    (endpoint, None, u.model, None)
                };
                let input = request
                    .get()
                    .checked_add(
                        docs.get()
                            .checked_mul(family.map(|f| f.max_input_prefix_bytes()).unwrap_or(0))
                            .ok_or(ServerError::Configuration)?,
                    )
                    .ok_or(ServerError::Configuration)?;
                let limits = EmbeddingLimits::new(
                    docs.get()
                        .checked_add(1)
                        .ok_or(ServerError::Configuration)?,
                    input,
                    dimensions,
                    docs.get()
                        .checked_add(1)
                        .and_then(|n| n.checked_mul(dimensions))
                        .ok_or(ServerError::Configuration)?,
                    batch.get(),
                    req,
                    res,
                )
                .map_err(|_| ServerError::Configuration)?;
                RerankBackend::embedding(
                    RemoteEmbeddingsConfig {
                        client,
                        protocol: u.protocol,
                        endpoint,
                        batch_endpoint,
                        model,
                        dimensions,
                        request_dimensions: u.send_dimensions.then_some(dimensions),
                        google_family: family,
                        headers,
                        limits,
                    },
                    ranking,
                )
                .map_err(|_| ServerError::Configuration)?
            } else if u.protocol == "graphit-rerank-v1" {
                let limits =
                    NativeRerankLimits::new(docs.get(), batch.get(), request.get(), req, res)
                        .map_err(|_| ServerError::Configuration)?;
                let service_revision = declared_metadata(required(u.service_revision)?)?;
                let max_documents = required(u.max_documents)?;
                presence_sql_cap(max_documents)?;
                RerankBackend::graphit(
                    client,
                    BrokerRerankService {
                        endpoint,
                        identity: BrokerModelIdentity {
                            model: model.clone(),
                            model_revision: model_revision.clone(),
                            recipe: recipe.clone(),
                            service_revision,
                        },
                        max_documents: max_documents.get(),
                    },
                    headers,
                    limits,
                    ranking,
                )
                .map_err(|_| ServerError::Configuration)?
            } else {
                let limits =
                    NativeRerankLimits::new(docs.get(), batch.get(), request.get(), req, res)
                        .map_err(|_| ServerError::Configuration)?;
                RerankBackend::remote(
                    RemoteRerankConfig {
                        client,
                        protocol: u.protocol.clone(),
                        endpoint,
                        model: u.model,
                        headers,
                        limits,
                    },
                    ranking,
                )
                .map_err(|_| ServerError::Configuration)?
            };
            let model = if cosine {
                backend.model().to_owned()
            } else {
                model
            };
            (backend, self.revision, model, model_revision, recipe)
        };
        if timeout.is_zero()
            || Instant::now().checked_add(timeout).is_none()
            || Instant::now().checked_add(cache_ttl).is_none()
            || axum::http::HeaderValue::from_str(&revision).is_err()
        {
            backend.stop();
            return Err(ServerError::Configuration);
        }
        let http = RerankHttpConfig {
            revision: revision.clone(),
            model: model.clone(),
            model_revision: model_revision.clone(),
            recipe: recipe.clone(),
            max_documents: docs,
            max_document_bytes: docbytes,
            request_body_bytes: request,
            response_body_bytes: response,
            request_timeout: timeout,
            local_audience: audience.to_owned(),
            required_scopes: scopes.clone(),
            admission_limits: RerankAdmissionLimits {
                identity_json_bytes: identity,
                grants_json_bytes: grants,
            },
            cache_ttl,
            cache_entries,
        };
        let view = serde_json::json!({"enabled":true,"revision":revision,"model":model,"model_revision":model_revision,"recipe":recipe,"max_documents":docs,"max_document_bytes":docbytes,"max_batch":batch,"dimensions":self.dimensions,"request_timeout":admin_config_view::Time(timeout),"required_scopes":scopes,"request_body_bytes":request,"response_body_bytes":response,"identity_json_bytes":identity,"grants_json_bytes":grants,"cache":{"ttl":admin_config_view::Time(cache_ttl),"max_entries":cache_entries},"upstream":view});
        Ok(PreparedRerank {
            http,
            backend: Arc::new(backend),
            view,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn remote() -> Value {
        json!({
        "enabled":true,"revision":"rerank-route-v1","max_batch":2,"required_scopes":[],
        "request_body_bytes":8192,"response_body_bytes":8192,"identity_json_bytes":8192,"grants_json_bytes":16384,
        "upstream":{"protocol":"graphit-rerank-v1","service_revision":"upstream-service-v7","max_documents":8,"model":"fixture-reranker","model_revision":"fixture-r1","recipe":"native-rerank-v1","url":"http://127.0.0.1:19091/rerank","api_key":"private-config-canary",
        "transport":{"request_body_bytes":8192,"response_body_bytes":8192,"url_bytes":2048,"header_bytes":4096,"header_count":32,"max_in_flight":2,"max_idle_per_host":2,"idle_timeout":"30s","max_certificates":8,"max_certificate_bytes":65536,"allow_loopback_http":true}}
        })
    }
    async fn parse(value: Value) -> Result<PreparedRerank, ServerError> {
        let config: Rerank =
            serde_json::from_value(value).map_err(|_| ServerError::Configuration)?;
        config
            .prepare(
                None,
                Path::new("."),
                "native-api",
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .await
    }
    #[tokio::test]
    async fn rerank_captured_defaults_redaction_protocols_and_explicit_bounds() {
        let prepared = parse(remote()).await.unwrap();
        assert_eq!(prepared.http.max_documents.get(), 1000);
        assert_eq!(prepared.http.max_document_bytes.get(), 1024 * 1024);
        assert_eq!(prepared.http.request_timeout, Duration::from_secs(45));
        assert_eq!(prepared.http.cache_ttl, Duration::from_secs(300));
        assert_eq!(prepared.http.cache_entries, 1000);
        assert_eq!(prepared.http.local_audience, "native-api");
        let view = serde_json::to_string(&prepared.view).unwrap();
        assert!(!view.contains("private-config-canary"));
        assert!(view.contains("[configured-secret]"));
        assert!(view.contains("allow_loopback_http"));
        prepared.backend.stop();
        let doc = include_str!("../../../docs/rust-broker-server.md");
        let section = doc.split_once("## Native rerank").unwrap().1;
        let example = section
            .split_once("```yaml\n")
            .unwrap()
            .1
            .split_once("\n```")
            .unwrap()
            .0;
        let example: Value = serde_saphyr::from_str(example).unwrap();
        let documented = parse(example["services"]["rerank"].clone()).await.unwrap();
        assert_eq!(documented.http.revision, "rerank-route-v1");
        assert_eq!(documented.http.max_documents.get(), 1000);
        documented.backend.stop();
        for protocol in [
            "cohere",
            "cohere-v2",
            "jina",
            "jina-v1",
            "voyage",
            "voyage-v1",
            "graphit-rerank-v1",
        ] {
            let mut v = remote();
            v["upstream"]["protocol"] = json!(protocol);
            if v["upstream"]["protocol"] != "graphit-rerank-v1" {
                let upstream = v["upstream"].as_object_mut().unwrap();
                upstream.remove("service_revision");
                upstream.remove("max_documents");
            }
            v["upstream"]["model"] = json!("fixture-model");
            let prepared = parse(v)
                .await
                .unwrap_or_else(|_| panic!("protocol {protocol} rejected"));
            assert_eq!(prepared.backend.protocol(), protocol);
            prepared.backend.stop();
        }
        for protocol in [
            "openai",
            "openai-compatible",
            "openai-embeddings-v1",
            "cohere-embed-v2",
            "voyage-embeddings-v1",
            "google",
            "google-embed-content-v1beta",
            "gemini",
            "gemini-embed-content-v1beta",
        ] {
            let mut v = remote();
            v["upstream"]["protocol"] = json!(protocol);
            if v["upstream"]["protocol"] != "graphit-rerank-v1" {
                let upstream = v["upstream"].as_object_mut().unwrap();
                upstream.remove("service_revision");
                upstream.remove("max_documents");
            }
            v["upstream"]["model"] = json!("fixture-model");
            v["dimensions"] = json!(2);
            let prepared = parse(v)
                .await
                .unwrap_or_else(|_| panic!("protocol {protocol} rejected"));
            assert_eq!(prepared.backend.protocol(), protocol);
            prepared.backend.stop();
        }
        for field in [
            "max_batch",
            "required_scopes",
            "request_body_bytes",
            "response_body_bytes",
            "identity_json_bytes",
            "grants_json_bytes",
            "upstream",
        ] {
            let mut v = remote();
            v.as_object_mut().unwrap().remove(field);
            assert!(
                matches!(parse(v).await, Err(ServerError::Configuration)),
                "{field}"
            );
        }
        for variant in 0..8 {
            let mut v = remote();
            match variant {
                0 => v["upstream"]["protocol"] = json!("unsupported"),
                1 => v["upstream"]["device"] = json!("cpu"),
                2 => v["upstream"]["api_key_header"] = json!("Content-Length"),
                3 => v["revision"] = json!(" "),
                4 => v["request_timeout"] = json!("0s"),
                5 => v["dimensions"] = json!(2),
                6 => v["upstream"]["protocol"] = json!("openai"),
                _ => v["upstream"]["send_dimensions"] = json!(true),
            };
            assert!(
                matches!(parse(v).await, Err(ServerError::Configuration)),
                "variant {variant}"
            );
        }
        let mut v = remote();
        v["upstream"]["model"] = json!("");
        assert!(matches!(parse(v).await, Err(ServerError::Configuration)));
        let mut v = remote();
        v["model"] = json!("caller-selection");
        assert!(matches!(parse(v).await, Err(ServerError::Configuration)));
        let mut v = remote();
        v["upstream"] = json!({"protocol":"gguf-bge-reranker-v2-m3","model":"bge-reranker-v2-m3"});
        assert!(matches!(parse(v).await, Err(ServerError::Configuration)));
        let services: embeddings_config::Services =
            serde_json::from_value(json!({"rerank":{"enabled":false}})).unwrap();
        let (a, b) = services
            .prepare_all(
                None,
                Path::new("."),
                "native-api",
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert!(a.is_none() && b.is_none());
    }

    #[tokio::test]
    async fn graphit_upstream_descriptor_is_explicit_and_separate_from_outer_service() {
        for field in ["service_revision", "max_documents"] {
            let mut document = remote();
            document["upstream"].as_object_mut().unwrap().remove(field);
            assert!(
                matches!(parse(document).await, Err(ServerError::Configuration)),
                "{field}"
            );
        }
        for value in [json!(""), json!(" padded "), json!("invalid\nvalue")] {
            let mut document = remote();
            document["upstream"]["service_revision"] = value;
            assert!(matches!(
                parse(document).await,
                Err(ServerError::Configuration)
            ));
        }
        let mut document = remote();
        document["upstream"]["max_documents"] = json!(0);
        assert!(matches!(
            parse(document).await,
            Err(ServerError::Configuration)
        ));
        let mut document = remote();
        document["upstream"]["protocol"] = json!("cohere");
        assert!(matches!(
            parse(document).await,
            Err(ServerError::Configuration)
        ));
        let prepared = parse(remote()).await.unwrap();
        assert_eq!(prepared.http.revision, "rerank-route-v1");
        assert_eq!(prepared.http.max_documents.get(), 1000);
        assert_eq!(
            prepared.view["upstream"]["service_revision"],
            "upstream-service-v7"
        );
        assert_eq!(prepared.view["upstream"]["max_documents"], 8);
        prepared.backend.stop();
    }

    #[tokio::test]
    async fn rerank_google_prefix_budget_covers_all_documents_before_chunks() {
        use axum::{Json, Router, extract::State, routing::post};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1beta", listener.local_addr().unwrap());
        let router = Router::new()
            .route(
                "/v1beta/models/gemini-embedding-2-preview:embedContent",
                post(
                    |State(calls): State<Arc<AtomicUsize>>, Json(body): Json<Value>| async move {
                        let index = calls.fetch_add(1, Ordering::SeqCst);
                        assert!(body.to_string().contains(if index == 0 {
                            "task: search result | query: "
                        } else {
                            "title: none | text: "
                        }));
                        Json(json!({"embedding":{"values":[1.0,0.0]}}))
                    },
                ),
            )
            .with_state(calls.clone());
        let (signal, stopped) = tokio::sync::oneshot::channel();
        let job = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let mut value = remote();
        value["max_documents"] = json!(8);
        value["max_batch"] = json!(1);
        value["request_body_bytes"] = json!(256);
        value["dimensions"] = json!(2);
        value["upstream"]["protocol"] = json!("gemini");
        let upstream = value["upstream"].as_object_mut().unwrap();
        upstream.remove("service_revision");
        upstream.remove("max_documents");
        value["upstream"]["model"] = json!("gemini-embedding-2-preview");
        value["upstream"]["url"] = json!(endpoint);
        let prepared = parse(value).await.unwrap();
        let documents = vec!["a".repeat(24); 8];
        assert!(
            serde_json::to_vec(&json!({"query":"q","documents":documents}))
                .unwrap()
                .len()
                <= 256
        );
        let cancel = Cancellation::default();
        let results = prepared
            .backend
            .infer_guarded(
                "q".into(),
                documents,
                8,
                InferenceContext::new(&cancel, Instant::now() + Duration::from_secs(5)),
                &mut || Ok::<(), std::convert::Infallible>(()),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 8);
        assert_eq!(calls.load(Ordering::SeqCst), 9);
        assert!(results.iter().all(|r| r.relevance_score == 1.0));
        prepared.backend.stop();
        signal.send(()).unwrap();
        job.await.unwrap();
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
                document["upstream"][field] = value;
                assert!(matches!(
                    parse(document).await,
                    Err(ServerError::Configuration)
                ));
            }
        }
        let prepared = parse(remote()).await.unwrap();
        assert_ne!(prepared.http.revision, prepared.http.model_revision);
        assert!(!prepared.http.model.is_empty());
        assert!(!prepared.http.recipe.is_empty());
        prepared.backend.stop();
    }
}
