//! Broker-wide instruction drafts and the authenticated sync projection.
use crate::{HttpFailure, authentication_failure, bearer, hub_access};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use broker_control::{
    BrokerAccessError, BrokerAccessVerifier, PostgresControlStore, SqliteControlStore,
    SystemAction, SystemPermission, UpstreamBearerVerifier,
};
use graphit_core::{
    file_lock::{Cancellation, FileLock},
    local_files::{atomic_replace, read_regular},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

const MAX_BYTES: usize = 512 * 1024;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    revision: u64,
    templates: BTreeMap<String, Draft>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    markdown: String,
    enabled: bool,
}

fn valid_name(name: &str) -> bool {
    name.ends_with(".md")
        && !name.starts_with("defaults/")
        && !name.contains(['\\', ':'])
        && !name.chars().any(char::is_control)
        && name.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn validate(document: &Document) -> Result<(), HttpFailure> {
    let mut syntax = minijinja::Environment::new();
    for (name, draft) in &document.templates {
        if !valid_name(name) || draft.markdown.contains('\0') {
            return Err(HttpFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_instruction_template",
            ));
        }
        if draft.enabled && syntax.add_template(name, &draft.markdown).is_err() {
            return Err(HttpFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_instruction_syntax",
            ));
        }
    }
    Ok(())
}

fn unavailable() -> HttpFailure {
    HttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "instructions_unavailable")
}

fn load(path: &Path) -> Result<Document, HttpFailure> {
    let document = read_regular(path, MAX_BYTES)
        .map_err(|_| unavailable())?
        .map(|(bytes, _)| serde_json::from_slice(&bytes).map_err(|_| unavailable()))
        .transpose()
        .map(Option::unwrap_or_default)?;
    validate(&document).map_err(|_| unavailable())?;
    Ok(document)
}

fn save(path: &Path, mut next: Document) -> Result<Document, HttpFailure> {
    validate(&next)?;
    let conflict = || HttpFailure::new(StatusCode::CONFLICT, "instruction_revision_conflict");
    let _lock =
        FileLock::try_acquire(path.with_extension("instructions.lock")).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                conflict()
            } else {
                unavailable()
            }
        })?;
    if load(path)?.revision != next.revision {
        return Err(conflict());
    }
    next.revision = next.revision.checked_add(1).ok_or_else(unavailable)?;
    let bytes = serde_json::to_vec(&next).map_err(|_| unavailable())?;
    if bytes.len() > MAX_BYTES {
        return Err(HttpFailure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "instruction_document_too_large",
        ));
    }
    atomic_replace(path, &bytes, None, &Cancellation::default()).map_err(|_| unavailable())?;
    Ok(next)
}

#[derive(Clone)]
pub enum InstructionStore {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
pub struct InstructionHttpConfig {
    pub file: PathBuf,
    pub timeout: Duration,
    pub audience: String,
    pub identity_json_bytes: NonZeroUsize,
    pub cookie: crate::AdminCookieHttpConfig,
}
struct Shared {
    store: InstructionStore,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: InstructionHttpConfig,
}

pub fn instruction_overrides_router(
    store: InstructionStore,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    config: InstructionHttpConfig,
) -> Router {
    Router::new()
        .route("/v1/agent-instructions", get(sync))
        .route(
            "/admin/api/v1/agent-instructions",
            get(admin_read).put(admin_write),
        )
        .layer(DefaultBodyLimit::max(MAX_BYTES))
        .layer(axum::middleware::map_response(
            |mut response: Response| async move {
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    "no-store".parse().expect("static header"),
                );
                response
            },
        ))
        .with_state(Arc::new(Shared {
            store,
            verifier,
            upstream,
            config,
        }))
}

async fn read_document(state: &Shared, end: std::time::Instant) -> Result<Document, HttpFailure> {
    let file = state.config.file.clone();
    tokio::time::timeout_at(end.into(), tokio::task::spawn_blocking(move || load(&file)))
        .await
        .map_err(|_| HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"))?
        .map_err(|_| unavailable())?
}

async fn sync(
    State(state): State<Arc<Shared>>,
    headers: HeaderMap,
) -> Result<Response, HttpFailure> {
    let bearer = bearer(&headers).map_err(|_| HttpFailure::unauthenticated())?;
    let raw = bearer.token();
    let end = hub_access::deadline(state.config.timeout)?;
    let config = &state.config;
    if raw.starts_with("gb_at_") || raw.starts_with("gb_sc_") {
        let result = match &state.store {
            InstructionStore::Postgres(store) => {
                store
                    .local_bearer_verifier(&config.audience, config.identity_json_bytes)
                    .map_err(authentication_failure)?
                    .verify(raw, &[], end)
                    .await
            }
            InstructionStore::Sqlite(store) => {
                store
                    .local_bearer_verifier(&config.audience, config.identity_json_bytes)
                    .map_err(authentication_failure)?
                    .verify(raw, &[], end)
                    .await
            }
        };
        result.map_err(authentication_failure)?;
    } else {
        state
            .verifier
            .verify(raw, &[], end)
            .map_err(|error| match error {
                BrokerAccessError::InvalidToken | BrokerAccessError::Expired => {
                    HttpFailure::unauthenticated()
                }
                BrokerAccessError::InsufficientScope => {
                    HttpFailure::new(StatusCode::FORBIDDEN, "insufficient_scope")
                }
                BrokerAccessError::InvalidConfiguration => unavailable(),
                BrokerAccessError::Deadline => {
                    HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline")
                }
            })?;
    }
    let document = read_document(&state, end).await?;
    let templates = document
        .templates
        .into_iter()
        .filter_map(|(name, draft)| draft.enabled.then_some((name, draft.markdown)))
        .collect::<BTreeMap<_, _>>();
    Ok(Json(serde_json::json!({"version":1,"templates":templates})).into_response())
}

async fn admin_session(
    state: &Shared,
    headers: &HeaderMap,
    write: bool,
) -> Result<(broker_control::AdminCookieReadSession, std::time::Instant), HttpFailure> {
    let raw = crate::admin_session::cookie_credential(headers)
        .map_err(|_| HttpFailure::unauthenticated())?
        .ok_or_else(HttpFailure::unauthenticated)?;
    let end = hub_access::deadline(state.config.timeout)?;
    let cookie = state.config.cookie;
    let session = match &state.store {
        InstructionStore::Postgres(store) => {
            store
                .admin_cookie_sessions(cookie.limits, cookie.policy, state.upstream.as_deref())
                .map_err(|_| unavailable())?
                .read(&raw, end)
                .await
        }
        InstructionStore::Sqlite(store) => {
            store
                .admin_cookie_sessions(cookie.limits, cookie.policy, state.upstream.clone())
                .map_err(|_| unavailable())?
                .read(&raw, end)
                .await
        }
    }
    .map_err(|error| match error {
        broker_control::AdminCookieSessionError::Control(
            broker_control::ControlError::Deadline,
        ) => HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"),
        broker_control::AdminCookieSessionError::MalformedCookie
        | broker_control::AdminCookieSessionError::Unauthorized
        | broker_control::AdminCookieSessionError::Control(
            broker_control::ControlError::SessionExpired,
        ) => HttpFailure::unauthenticated(),
        broker_control::AdminCookieSessionError::Forbidden => {
            HttpFailure::new(StatusCode::FORBIDDEN, "instructions_forbidden")
        }
        _ => unavailable(),
    })?;
    let all = session.permissions().contains(&SystemPermission::All);
    let admin = all || session.roles().iter().any(|role| role == "admin");
    let allowed = if write {
        admin
    } else {
        admin
            || session
                .permissions()
                .contains(&SystemPermission::Action(SystemAction::ConfigurationRead))
    };
    if !allowed {
        return Err(HttpFailure::new(
            StatusCode::FORBIDDEN,
            "instructions_forbidden",
        ));
    }
    if write {
        let mut values = headers.get_all("x-csrf-token").iter();
        let value = values.next().and_then(|v| v.to_str().ok());
        if values.next().is_some() || !session.csrf_matches(value) {
            return Err(HttpFailure::new(StatusCode::FORBIDDEN, "csrf_failed"));
        }
    }
    Ok((session, end))
}

async fn admin_read(
    State(state): State<Arc<Shared>>,
    headers: HeaderMap,
) -> Result<Json<Document>, HttpFailure> {
    let (session, end) = admin_session(&state, &headers, false).await?;
    let document = read_document(&state, end).await?;
    session
        .check()
        .map_err(|_| HttpFailure::unauthenticated())?;
    Ok(Json(document))
}
async fn admin_write(
    State(state): State<Arc<Shared>>,
    mut request: Request,
) -> Result<Json<Document>, HttpFailure> {
    let (session, end) = admin_session(&state, request.headers(), true).await?;
    DefaultBodyLimit::max(MAX_BYTES).apply(&mut request);
    let Json(input) =
        tokio::time::timeout_at(end.into(), Json::<Document>::from_request(request, &state))
            .await
            .map_err(|_| HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"))?
            .map_err(|error| HttpFailure::new(error.status(), "invalid_instruction_document"))?;
    let file = state.config.file.clone();
    tokio::task::spawn_blocking(move || {
        if std::time::Instant::now() >= end || session.check().is_err() {
            return Err(HttpFailure::new(StatusCode::GATEWAY_TIMEOUT, "deadline"));
        }
        save(&file, input).map(Json)
    })
    .await
    .map_err(|_| unavailable())?
}
