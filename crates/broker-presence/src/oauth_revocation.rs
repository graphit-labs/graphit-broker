//! Explicit RFC7009 route using the same native store and verifier as the server.
use crate::oauth_token::{OidcTokenHttpConfigurationError, failure, no_store};
use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use broker_control::{
    BrokerAccessVerifier, OidcAuthorizationPolicy, OidcRevocationInput,
    OidcTokenExchangeError as Error, PostgresControlStore, SqliteControlStore,
};
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct OidcRevocationHttpConfig {
    pub request_timeout: Duration,
    pub body_bytes: NonZeroUsize,
}
struct RevocationState {
    store: Store,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    config: OidcRevocationHttpConfig,
}
pub fn oidc_revocation_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    config: OidcRevocationHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    router(Store::Postgres(store), verifier, authorization, config)
}
pub fn sqlite_oidc_revocation_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    config: OidcRevocationHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    router(Store::Sqlite(store), verifier, authorization, config)
}
fn router(
    store: Store,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    config: OidcRevocationHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    if config.request_timeout.is_zero()
        || Instant::now().checked_add(config.request_timeout).is_none()
        || isize::try_from(config.body_bytes.get()).is_err()
    {
        return Err(OidcTokenHttpConfigurationError);
    }
    store
        .validate(&authorization, &verifier)
        .map_err(|_| OidcTokenHttpConfigurationError)?;
    Ok(Router::new()
        .route("/oauth/revoke", post(revoke))
        .with_state(Arc::new(RevocationState {
            store,
            verifier,
            authorization,
            config,
        }))
        .layer(middleware::map_response(private_response)))
}
const PARAMETERS: &[&str] = &[
    "token",
    "token_type_hint",
    "client_id",
    "client_secret",
    "client_assertion",
    "client_assertion_type",
];
async fn revoke(State(state): State<Arc<RevocationState>>, request: Request) -> Response {
    let Some(end) = Instant::now().checked_add(state.config.request_timeout) else {
        return failure(Error::InvalidConfiguration);
    };
    let result = async {
        let parsed =
            crate::oauth_form::read(request, PARAMETERS, end, state.config.body_bytes.get())
                .await?;
        if parsed.fields.contains_key("client_secret") {
            return Err(Error::InvalidClient);
        }
        let get = |name: &str| parsed.fields.get(name).map(|v| v.as_str());
        state
            .store
            .revoke(
                &state.authorization,
                &state.verifier,
                OidcRevocationInput {
                    token: get("token"),
                    client_id: get("client_id"),
                    token_type_hint: get("token_type_hint"),
                    authorization: parsed
                        .authorization
                        .as_ref()
                        .map(|(u, p)| (u.as_str(), p.as_bytes())),
                },
                end,
            )
            .await?;
        Ok(no_store(StatusCode::OK.into_response()))
    }
    .await;
    result.unwrap_or_else(failure)
}

enum Store {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
impl Store {
    fn validate(
        &self,
        policy: &Arc<OidcAuthorizationPolicy>,
        verifier: &Arc<BrokerAccessVerifier>,
    ) -> Result<(), broker_control::OidcTokenExchangeError> {
        match self {
            Self::Postgres(s) => s.oidc_revocation(policy, verifier).map(|_| ()),
            Self::Sqlite(s) => s
                .oidc_revocation(policy.clone(), verifier.clone())
                .map(|_| ()),
        }
    }
    async fn revoke(
        &self,
        policy: &Arc<OidcAuthorizationPolicy>,
        verifier: &Arc<BrokerAccessVerifier>,
        input: OidcRevocationInput<'_>,
        end: Instant,
    ) -> Result<(), broker_control::OidcTokenExchangeError> {
        match self {
            Self::Postgres(s) => {
                s.oidc_revocation(policy, verifier)?
                    .revoke(input, end)
                    .await
            }
            Self::Sqlite(s) => {
                s.oidc_revocation(policy.clone(), verifier.clone())?
                    .revoke(input, end)
                    .await
            }
        }
    }
}

async fn private_response(response: Response) -> Response {
    no_store(response)
}
