use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

/// Public configuration only. No signing owner, private key, SQL handle or request input is retained.
pub(crate) struct Discovery {
    graphit: Value,
    openid: Value,
    pub device_authorization_endpoint: Option<String>,
}

impl Discovery {
    pub fn new(
        issuer: &str,
        audience: &str,
        client_id: &str,
        redirect_path: &str,
        resources: &[String],
        dynamic_registration: bool,
    ) -> Self {
        let base = issuer.trim_end_matches('/');
        let scopes = ["openid", "profile", "email", "offline_access"];
        let graphit = json!({
            "version": "1",
            "issuer": issuer,
            "authentication": {
                "type": "oidc",
                "issuer": issuer,
                "client_id": client_id,
                "scopes": scopes,
                "audiences": [audience],
                "access_token_audience": audience,
                "redirect_uri_path": redirect_path,
                "mcp_resources": resources,
            },
        });
        let mut openid = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base}/oauth/authorize"),
            "token_endpoint": format!("{base}/oauth/token"),
            "introspection_endpoint": format!("{base}/oauth/introspect"),
            "introspection_endpoint_auth_methods_supported": ["Bearer"],
            "userinfo_endpoint": format!("{base}/oauth/userinfo"),
            "end_session_endpoint": format!("{base}/oauth/end-session"),
            "revocation_endpoint": format!("{base}/oauth/revoke"),
            "revocation_endpoint_auth_methods_supported": ["none"],
            "jwks_uri": format!("{base}/v1/oidc/keys"),
            "scopes_supported": scopes,
            "response_types_supported": ["code"],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["EdDSA"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
        });
        if dynamic_registration {
            openid["registration_endpoint"] = json!(format!("{base}/oauth/register"));
        }
        Self {
            graphit,
            openid,
            device_authorization_endpoint: None,
        }
    }

    pub(crate) fn embeddings(&mut self, config: &broker_presence::EmbeddingsHttpConfig) {
        self.graphit["services"]["embeddings"] = embeddings_metadata(config);
    }

    pub(crate) fn rerank(&mut self, config: &broker_presence::RerankHttpConfig) {
        self.graphit["services"]["rerank"] = rerank_metadata(config);
    }

    pub(crate) fn storage(&mut self, enabled: bool) {
        if enabled {
            self.graphit["services"]["s3_credentials"] = storage_metadata();
        }
    }

    pub fn router(mut self) -> Router {
        if let Some(uri) = self.device_authorization_endpoint {
            self.openid["device_authorization_endpoint"] = json!(uri);
            self.openid["grant_types_supported"]
                .as_array_mut()
                .expect("constant grant list")
                .push(json!(broker_control::DEVICE_GRANT_TYPE));
        }
        Router::new()
            .route(
                "/.well-known/graphit-broker",
                get(move || {
                    let document = self.graphit.clone();
                    async move { Json(document) }
                }),
            )
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let document = self.openid.clone();
                    async move { Json(document) }
                }),
            )
    }
}

fn storage_metadata() -> Value {
    json!({"protocol":"graphit-s3-credentials-v3", "path":"/v1/s3/credentials"})
}

fn embeddings_metadata(config: &broker_presence::EmbeddingsHttpConfig) -> Value {
    json!({"protocol":"graphit-embeddings-v1", "path":"/v1/embeddings",
        "revision":config.revision,"model":config.model,"model_revision":config.model_revision,"recipe":config.recipe,"dimensions":config.dimensions.get(),
        "max_batch":config.max_batch.get(),"max_input_bytes":config.max_input_bytes.get()})
}
fn rerank_metadata(config: &broker_presence::RerankHttpConfig) -> Value {
    json!({"protocol":"graphit-rerank-v1","path":"/v1/rerank","revision":config.revision,"model":config.model,"model_revision":config.model_revision,"recipe":config.recipe,"max_documents":config.max_documents.get()})
}
pub(crate) fn services_discovery_router(
    issuer: &str,
    embeddings: Option<&broker_presence::EmbeddingsHttpConfig>,
    rerank: Option<&broker_presence::RerankHttpConfig>,
    storage_enabled: bool,
) -> Router {
    if embeddings.is_none() && rerank.is_none() && !storage_enabled {
        return Router::new();
    }
    let mut document = json!({"version":"1","issuer":issuer,"services":{}});
    if storage_enabled {
        document["services"]["s3_credentials"] = storage_metadata();
    }
    if let Some(config) = embeddings {
        document["services"]["embeddings"] = embeddings_metadata(config);
    }
    if let Some(config) = rerank {
        document["services"]["rerank"] = rerank_metadata(config);
    }
    Router::new().route(
        "/.well-known/graphit-broker",
        get(move || {
            let document = document.clone();
            async move { Json(document) }
        }),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) async fn http_document(router: Router) -> (reqwest::StatusCode, Option<Value>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let response = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap()
            .get(format!("http://{address}/.well-known/graphit-broker"))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let document = if status.is_success() {
            Some(serde_json::from_slice::<Value>(&response.bytes().await.unwrap()).unwrap())
        } else {
            None
        };
        stop.send(()).unwrap();
        server.await.unwrap();
        (status, document)
    }

    #[tokio::test]
    async fn oidc_discovery_http_preserves_authentication_and_storage_selection() {
        for enabled in [false, true] {
            let mut discovery = Discovery::new(
                "https://broker.example",
                "broker-api",
                "graphit-cli",
                "/oauth/callback",
                &[],
                false,
            );
            discovery.storage(enabled);
            let (status, document) = http_document(discovery.router()).await;
            assert_eq!(status, reqwest::StatusCode::OK);
            let document = document.unwrap();
            assert_eq!(document["authentication"]["type"], "oidc");
            assert_eq!(
                document.pointer("/services/s3_credentials").is_some(),
                enabled
            );
            if enabled {
                assert_eq!(document["services"]["s3_credentials"], storage_metadata());
            }
        }
    }

    #[test]
    fn storage_is_advertised_only_when_the_server_enables_its_credential_route() {
        let make = || {
            Discovery::new(
                "https://broker.example",
                "broker-api",
                "graphit-cli",
                "/oauth/callback",
                &[],
                false,
            )
        };
        let mut disabled = make();
        disabled.storage(false);
        assert!(
            disabled
                .graphit
                .pointer("/services/s3_credentials")
                .is_none()
        );
        let mut enabled = make();
        enabled.storage(true);
        assert_eq!(
            enabled.graphit["services"]["s3_credentials"],
            storage_metadata()
        );
        assert!(
            enabled.graphit["services"]["s3_credentials"]
                .get("authorization_revision")
                .is_none()
        );
    }
}
