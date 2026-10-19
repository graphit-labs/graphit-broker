//! RP-initiated disposal using a signed Broker ID hint; no redirect or alternate authority.
use crate::oauth_token::{OidcTokenHttpConfigurationError, failure, no_store};
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::any,
};
use broker_control::{
    BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy, OidcEndSessionInput,
    OidcTokenExchangeError as Error, PostgresControlStore, SqliteControlStore,
};
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct OidcEndSessionHttpConfig {
    pub request_timeout: Duration,
    pub body_bytes: NonZeroUsize,
}
struct EndSessionState {
    store: Store,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    parameter_bytes: usize,
    config: OidcEndSessionHttpConfig,
}
pub fn oidc_end_session_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    config: OidcEndSessionHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    router(Store::Postgres(store), verifier, authorization, config)
}
pub fn sqlite_oidc_end_session_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    config: OidcEndSessionHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    router(Store::Sqlite(store), verifier, authorization, config)
}
fn router(
    store: Store,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    config: OidcEndSessionHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    if config.request_timeout.is_zero()
        || Instant::now().checked_add(config.request_timeout).is_none()
        || isize::try_from(config.body_bytes.get()).is_err()
    {
        return Err(OidcTokenHttpConfigurationError);
    }
    let parameter_bytes = store
        .validate(&authorization, &verifier)
        .map_err(|_| OidcTokenHttpConfigurationError)?;
    Ok(Router::new()
        .route("/oauth/end-session", any(end_session))
        .with_state(Arc::new(EndSessionState {
            store,
            verifier,
            authorization,
            parameter_bytes,
            config,
        }))
        .layer(middleware::map_response(private_response)))
}
async fn private_response(response: Response) -> Response {
    no_store(response)
}
const PARAMETERS: &[&str] = &[
    "id_token_hint",
    "client_id",
    "post_logout_redirect_uri",
    "state",
    "ui_locales",
    "logout_hint",
];
async fn end_session(State(state): State<Arc<EndSessionState>>, mut request: Request) -> Response {
    let Some(end) = Instant::now().checked_add(state.config.request_timeout) else {
        return failure(Error::InvalidConfiguration);
    };
    if request.method() != Method::GET && request.method() != Method::POST {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET, POST")],
        )
            .into_response();
    }
    // These credentials never select or enlarge the signed disposal authority.
    request.headers_mut().remove(header::AUTHORIZATION);
    request.headers_mut().remove(header::COOKIE);
    let result = async {
        let query = request.uri().query().unwrap_or("");
        if query.len() > state.parameter_bytes {
            return Err(Error::InvalidRequest);
        }
        let query_fields = crate::oauth_form::form(query.as_bytes(), PARAMETERS)?;
        let fields = if request.method() == Method::GET {
            let body = tokio::time::timeout_at(
                end.into(),
                to_bytes(request.into_body(), state.config.body_bytes.get()),
            )
            .await
            .map_err(|_| Error::Control(ControlError::Deadline))?
            .map_err(|_| Error::InvalidRequest)?;
            if !body.is_empty() {
                return Err(Error::InvalidRequest);
            }
            query_fields
        } else {
            crate::oauth_form::read(request, PARAMETERS, end, state.config.body_bytes.get())
                .await?
                .fields
        };
        if fields.contains_key("post_logout_redirect_uri") {
            return Err(Error::InvalidRequest);
        }
        let size = fields
            .values()
            .try_fold(0usize, |n, v| n.checked_add(v.len()))
            .ok_or(Error::InvalidRequest)?;
        if size > state.parameter_bytes {
            return Err(Error::InvalidRequest);
        }
        let get = |name: &str| fields.get(name).map(|v| v.as_str());
        state
            .store
            .end_session(
                &state.authorization,
                &state.verifier,
                OidcEndSessionInput {
                    id_token_hint: get("id_token_hint"),
                    client_id: get("client_id"),
                },
                end,
            )
            .await?;
        Ok(StatusCode::NO_CONTENT.into_response())
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
    ) -> Result<usize, broker_control::OidcTokenExchangeError> {
        match self {
            Self::Postgres(s) => s
                .oidc_end_session(policy, verifier)
                .map(|v| v.parameter_bytes()),
            Self::Sqlite(s) => s
                .oidc_end_session(policy.clone(), verifier.clone())
                .map(|v| v.parameter_bytes()),
        }
    }
    async fn end_session(
        &self,
        policy: &Arc<OidcAuthorizationPolicy>,
        verifier: &Arc<BrokerAccessVerifier>,
        input: OidcEndSessionInput<'_>,
        end: Instant,
    ) -> Result<(), broker_control::OidcTokenExchangeError> {
        match self {
            Self::Postgres(s) => {
                s.oidc_end_session(policy, verifier)?
                    .end_session(input, end)
                    .await
            }
            Self::Sqlite(s) => {
                s.oidc_end_session(policy.clone(), verifier.clone())?
                    .end_session(input, end)
                    .await
            }
        }
    }
}
