//! RFC7662 inspection authorized by a Broker access Bearer, never a public client identifier.
use crate::oauth_token::{OidcTokenHttpConfigurationError, no_store};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use broker_control::{
    BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy, OidcIntrospectionError as Error,
    PostgresControlStore, SqliteControlStore,
};
use headers::{Authorization, Header, authorization::Bearer};
use serde::Serialize;
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub struct OidcIntrospectionHttpConfig {
    pub request_timeout: Duration,
    pub body_bytes: NonZeroUsize,
}
struct IntrospectionState {
    store: Store,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    parameter_bytes: usize,
    config: OidcIntrospectionHttpConfig,
}
pub fn oidc_introspection_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    config: OidcIntrospectionHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    router(Store::Postgres(store), verifier, authorization, config)
}
pub fn sqlite_oidc_introspection_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    config: OidcIntrospectionHttpConfig,
) -> Result<Router, OidcTokenHttpConfigurationError> {
    router(Store::Sqlite(store), verifier, authorization, config)
}
fn router(
    store: Store,
    verifier: Arc<BrokerAccessVerifier>,
    authorization: Arc<OidcAuthorizationPolicy>,
    config: OidcIntrospectionHttpConfig,
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
        .route("/oauth/introspect", post(introspect))
        .with_state(Arc::new(IntrospectionState {
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
#[derive(Serialize)]
struct ErrorWire {
    error: &'static str,
}
fn failure(error: Error) -> Response {
    let (status, code) = match error {
        Error::InvalidAuthority => (StatusCode::UNAUTHORIZED, "invalid_token"),
        Error::Control(ControlError::Deadline) => {
            (StatusCode::GATEWAY_TIMEOUT, "temporarily_unavailable")
        }
        Error::Control(ControlError::Closed | ControlError::OutcomeUncertain) => {
            (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    let mut response = (status, Json(ErrorWire { error: code })).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Bearer realm="graphit-broker", error="invalid_token""#),
        );
    }
    response
}
fn invalid_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorWire {
            error: "invalid_request",
        }),
    )
        .into_response()
}
fn authority(request: &mut Request) -> Result<Zeroizing<String>, Error> {
    for (name, value) in request.headers_mut().iter_mut() {
        if name == header::AUTHORIZATION {
            value.set_sensitive(true);
        }
    }
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let first = values.next().ok_or(Error::InvalidAuthority)?;
    if values.next().is_some() {
        return Err(Error::InvalidAuthority);
    }
    let token = Authorization::<Bearer>::decode(&mut std::iter::once(first))
        .map_err(|_| Error::InvalidAuthority)?;
    let token = Zeroizing::new(token.token().to_owned());
    // The shared form parser handles client credentials elsewhere; this route accepts only Bearer.
    request.headers_mut().remove(header::AUTHORIZATION);
    Ok(token)
}
async fn introspect(
    State(state): State<Arc<IntrospectionState>>,
    mut request: Request,
) -> Response {
    let Some(end) = Instant::now().checked_add(state.config.request_timeout) else {
        return failure(Error::InvalidConfiguration);
    };
    let authority = match authority(&mut request) {
        Ok(token) => token,
        Err(error) => return failure(error),
    };
    let parsed = match crate::oauth_form::read(
        request,
        &["token", "token_type_hint"],
        end,
        state.config.body_bytes.get(),
    )
    .await
    {
        Ok(parsed) => parsed,
        Err(broker_control::OidcTokenExchangeError::Control(error)) => {
            return failure(error.into());
        }
        Err(_) => return invalid_request(),
    };
    if parsed
        .fields
        .values()
        .any(|value| value.len() > state.parameter_bytes)
    {
        return invalid_request();
    }
    match state
        .store
        .introspect(
            &state.authorization,
            &state.verifier,
            &authority,
            parsed.fields.get("token").map(|value| value.as_str()),
            end,
        )
        .await
    {
        Ok(result) => Json(result).into_response(),
        Err(error) => failure(error),
    }
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
    ) -> Result<usize, broker_control::OidcIntrospectionError> {
        match self {
            Self::Postgres(s) => s
                .oidc_introspection(policy, verifier)
                .map(|v| v.parameter_bytes()),
            Self::Sqlite(s) => s
                .oidc_introspection(policy.clone(), verifier.clone())
                .map(|v| v.parameter_bytes()),
        }
    }
    async fn introspect(
        &self,
        policy: &Arc<OidcAuthorizationPolicy>,
        verifier: &Arc<BrokerAccessVerifier>,
        authority: &str,
        token: Option<&str>,
        end: Instant,
    ) -> Result<broker_control::OidcIntrospection, broker_control::OidcIntrospectionError> {
        match self {
            Self::Postgres(s) => {
                s.oidc_introspection(policy, verifier)?
                    .introspect(authority, token, end)
                    .await
            }
            Self::Sqlite(s) => {
                s.oidc_introspection(policy.clone(), verifier.clone())?
                    .introspect(authority, token, end)
                    .await
            }
        }
    }
}
