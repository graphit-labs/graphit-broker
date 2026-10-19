//! Authenticated WSv1 Now channels with explicitly owned connection tasks.
use super::{
    HttpFailure, RealtimeHub, RealtimeHubError, RealtimeHubMaintenance, RealtimeHubReplay,
    RealtimeHubSignalError, RealtimeProjectSubscription, RealtimePublisherHandle, bearer,
};
use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::get,
};
use broker_control::{
    AuthorizedNowProjectSubscriber, AuthorizedNowPublisher, AuthorizedNowSubscriber,
    BrokerAccessVerifier, BrokerPresenceAuthorizationError, InstanceInventory,
    InstanceProjectVersions, InstanceReadError, NowChannelAuthorizationError, PostgresControlStore,
    PostgresNowChannelAuthorizer, PresenceChannel, SqliteControlStore, SqliteNowChannelAuthorizer,
};
use broker_now_wire::NowSnapshotData;
use futures_util::StreamExt;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{
    fmt,
    io::{self, Write},
    num::NonZeroUsize,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    sync::{Notify, mpsc},
    task::{JoinHandle, JoinSet},
};
use tokio_tungstenite::tungstenite::Error as SocketError;
use zeroize::Zeroizing;

/// Every cap, scope and operation budget is supplied by the serving application.
pub struct RealtimeHttpConfig {
    pub required_scopes: Vec<String>,
    pub grants_json_bytes: NonZeroUsize,
    pub inventory_json_bytes: NonZeroUsize,
    pub command_bytes: NonZeroUsize,
    pub outbound_bytes: NonZeroUsize,
    pub operation_timeout: Duration,
}
/// Opaque authentication is selected explicitly, with its actual audience.
pub struct LocalRealtimeHttpConfig {
    pub audience: String,
    pub identity_json_bytes: NonZeroUsize,
    pub realtime: RealtimeHttpConfig,
}
impl fmt::Debug for RealtimeHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealtimeHttpConfig([REDACTED])")
    }
}
impl fmt::Debug for LocalRealtimeHttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalRealtimeHttpConfig([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealtimeServerError {
    InvalidConfiguration,
    Unavailable,
    Hub(RealtimeHubError),
}
impl fmt::Display for RealtimeServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid realtime server configuration",
            Self::Unavailable => "realtime server unavailable",
            Self::Hub(_) => "realtime Hub unavailable",
        })
    }
}
impl std::error::Error for RealtimeServerError {}
impl From<RealtimeHubError> for RealtimeServerError {
    fn from(e: RealtimeHubError) -> Self {
        Self::Hub(e)
    }
}
struct RuntimeState {
    hub: Arc<RealtimeHub>,
    heartbeat: Duration,
    closed: AtomicBool,
    stop: Notify,
    input: mpsc::UnboundedSender<Connection>,
}
impl RuntimeState {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.stop.notify_one();
    }
}
/// Keep this owner alive while serving its routers. Explicit shutdown joins its
/// connection tasks and Hub maintenance; Drop aborts them.
/// ~~~no_run
/// # async fn example() -> Result<(), broker_presence::RealtimeServerError> {
/// let runtime = broker_presence::RealtimeServerRuntime::new(
///     std::time::Duration::from_secs(30), std::num::NonZeroUsize::new(32).unwrap())?;
/// runtime.shutdown().await?;
/// # Ok(()) }
/// ~~~
/// ~~~compile_fail
/// fn clone<T: Clone>() {} clone::<broker_presence::RealtimeServerRuntime>();
/// ~~~
/// ~~~compile_fail
/// fn default<T: Default>() {} default::<broker_presence::RealtimeServerRuntime>();
/// ~~~
pub struct RealtimeServerRuntime {
    state: Arc<RuntimeState>,
    supervisor: Option<JoinHandle<()>>,
    maintenance: Option<RealtimeHubMaintenance>,
}
impl RealtimeServerRuntime {
    pub fn new(
        heartbeat_timeout: Duration,
        broadcast_capacity: NonZeroUsize,
    ) -> Result<Self, RealtimeServerError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| RealtimeServerError::InvalidConfiguration)?;
        let hub = RealtimeHub::new(heartbeat_timeout, broadcast_capacity)?;
        let maintenance = hub.run_maintenance()?;
        let (input, receiver) = mpsc::unbounded_channel();
        let state = Arc::new(RuntimeState {
            hub,
            heartbeat: heartbeat_timeout,
            closed: AtomicBool::new(false),
            stop: Notify::new(),
            input,
        });
        let supervisor = runtime.spawn(supervise(state.clone(), receiver));
        Ok(Self {
            state,
            supervisor: Some(supervisor),
            maintenance: Some(maintenance),
        })
    }
    pub async fn shutdown(mut self) -> Result<(), RealtimeServerError> {
        self.state.close();
        let connections = if let Some(task) = self.supervisor.as_mut() {
            task.await.map_err(|_| RealtimeServerError::Unavailable)
        } else {
            Ok(())
        };
        self.supervisor.take();
        let maintenance = if let Some(owner) = self.maintenance.take() {
            owner.shutdown().await.map_err(RealtimeServerError::from)
        } else {
            Ok(())
        };
        connections.and(maintenance)
    }
}
impl Drop for RealtimeServerRuntime {
    fn drop(&mut self) {
        self.state.close();
        if let Some(task) = self.supervisor.take() {
            task.abort();
        }
        self.maintenance.take();
    }
}
struct SupervisorExit(Arc<RuntimeState>);
impl Drop for SupervisorExit {
    fn drop(&mut self) {
        self.0.close();
    }
}
async fn supervise(state: Arc<RuntimeState>, mut receiver: mpsc::UnboundedReceiver<Connection>) {
    let _exit = SupervisorExit(state.clone());
    let mut tasks = JoinSet::new();
    loop {
        if state.closed.load(Ordering::Acquire) {
            break;
        }
        tokio::select! {
            biased;
            _ = state.stop.notified() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            input = receiver.recv() => match input {
                Some(connection) if !state.closed.load(Ordering::Acquire) => {
                    tasks.spawn(connection.run(state.clone()));
                }
                _ => break,
            }
        }
    }
    receiver.close();
    while receiver.try_recv().is_ok() {}
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
enum ControlBackend {
    Postgres(Arc<PostgresControlStore>),
    Sqlite(Arc<SqliteControlStore>),
}
enum Authentication {
    Native {
        backend: ControlBackend,
        verifier: Arc<BrokerAccessVerifier>,
    },
    Local {
        backend: ControlBackend,
        audience: String,
        identity_json_bytes: NonZeroUsize,
    },
}
enum NowAuthorizer<'a> {
    Postgres(PostgresNowChannelAuthorizer<'a>),
    Sqlite(SqliteNowChannelAuthorizer<'a>),
}
impl<'a> NowAuthorizer<'a> {
    async fn authorize_publish(
        &self,
        raw: &str,
        scopes: &[String],
        channel: &PresenceChannel,
        end: Instant,
    ) -> Result<AuthorizedNowPublisher<'a>, NowChannelAuthorizationError> {
        match self {
            Self::Postgres(authorizer) => {
                authorizer
                    .authorize_publish(raw, scopes, channel, end)
                    .await
            }
            Self::Sqlite(authorizer) => {
                authorizer
                    .authorize_publish(raw, scopes, channel, end)
                    .await
            }
        }
    }
    async fn authorize_read(
        &self,
        raw: &str,
        scopes: &[String],
        channel: &PresenceChannel,
        end: Instant,
    ) -> Result<AuthorizedNowSubscriber<'a>, NowChannelAuthorizationError> {
        match self {
            Self::Postgres(authorizer) => {
                authorizer.authorize_read(raw, scopes, channel, end).await
            }
            Self::Sqlite(authorizer) => authorizer.authorize_read(raw, scopes, channel, end).await,
        }
    }
    async fn authorize_subscriber_project(
        &self,
        raw: &str,
        scopes: &[String],
        project: &str,
        end: Instant,
    ) -> Result<AuthorizedNowProjectSubscriber<'a>, NowChannelAuthorizationError> {
        match self {
            Self::Postgres(authorizer) => {
                authorizer
                    .authorize_subscriber_project(raw, scopes, project, end)
                    .await
            }
            Self::Sqlite(authorizer) => {
                authorizer
                    .authorize_subscriber_project(raw, scopes, project, end)
                    .await
            }
        }
    }
}
struct RouteState {
    authentication: Authentication,
    config: RealtimeHttpConfig,
    runtime: Weak<RuntimeState>,
}
impl RouteState {
    fn authorizer(&self) -> Result<NowAuthorizer<'_>, Failure> {
        let c = &self.config;
        match &self.authentication {
            Authentication::Native { backend, verifier } => match backend {
                ControlBackend::Postgres(store) => store
                    .broker_now_channel_authorizer(
                        verifier,
                        c.grants_json_bytes,
                        c.inventory_json_bytes,
                    )
                    .map(NowAuthorizer::Postgres),
                ControlBackend::Sqlite(store) => store
                    .broker_now_channel_authorizer(
                        verifier,
                        c.grants_json_bytes,
                        c.inventory_json_bytes,
                    )
                    .map(NowAuthorizer::Sqlite),
            },
            Authentication::Local {
                backend,
                audience,
                identity_json_bytes,
            } => match backend {
                ControlBackend::Postgres(store) => store
                    .local_now_channel_authorizer(
                        audience,
                        *identity_json_bytes,
                        c.grants_json_bytes,
                        c.inventory_json_bytes,
                    )
                    .map(NowAuthorizer::Postgres),
                ControlBackend::Sqlite(store) => store
                    .local_now_channel_authorizer(
                        audience,
                        *identity_json_bytes,
                        c.grants_json_bytes,
                        c.inventory_json_bytes,
                    )
                    .map(NowAuthorizer::Sqlite),
            },
        }
        .map_err(Failure::from)
    }
    async fn authenticate(&self, raw: &str, end: Instant) -> Result<Window, HttpFailure> {
        let pair = match &self.authentication {
            Authentication::Native { verifier, .. } => verifier
                .verify(raw, &self.config.required_scopes, end)
                .map_err(|e| HttpFailure::from(BrokerPresenceAuthorizationError::from(e)))?
                .authentication_expiry(),
            Authentication::Local {
                backend,
                audience,
                identity_json_bytes,
            } => match backend {
                ControlBackend::Postgres(store) => {
                    store
                        .local_bearer_verifier(audience, *identity_json_bytes)
                        .map_err(super::authentication_failure)?
                        .verify(raw, &self.config.required_scopes, end)
                        .await
                }
                ControlBackend::Sqlite(store) => {
                    store
                        .local_bearer_verifier(audience, *identity_json_bytes)
                        .map_err(super::authentication_failure)?
                        .verify(raw, &self.config.required_scopes, end)
                        .await
                }
            }
            .map_err(super::authentication_failure)?
            .authentication_expiry(),
        };
        let window = Window::from_pair(pair);
        window.check(end).map_err(|e| e.http())?;
        Ok(window)
    }
    fn original(&self) -> Result<Instant, Failure> {
        Instant::now()
            .checked_add(self.config.operation_timeout)
            .ok_or(Failure::UNAVAILABLE)
    }
}
/// Select Native JWT authentication explicitly and retain the runtime owner.
/// ~~~no_run
/// fn routes(store: std::sync::Arc<broker_control::PostgresControlStore>,
///     verifier: std::sync::Arc<broker_control::BrokerAccessVerifier>,
///     config: broker_presence::RealtimeHttpConfig, runtime: &broker_presence::RealtimeServerRuntime)
///     -> Result<axum::Router, broker_presence::RealtimeServerError> {
///     broker_presence::broker_realtime_router(store, verifier, config, runtime)
/// }
/// ~~~
pub fn broker_realtime_router(
    store: Arc<PostgresControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: RealtimeHttpConfig,
    runtime: &RealtimeServerRuntime,
) -> Result<Router, RealtimeServerError> {
    routes(
        Authentication::Native {
            backend: ControlBackend::Postgres(store),
            verifier,
        },
        config,
        runtime,
    )
}
/// Explicit SQLite Native JWT realtime with the existing owned runtime and proofs.
pub fn sqlite_broker_realtime_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: RealtimeHttpConfig,
    runtime: &RealtimeServerRuntime,
) -> Result<Router, RealtimeServerError> {
    routes(
        Authentication::Native {
            backend: ControlBackend::Sqlite(store),
            verifier,
        },
        config,
        runtime,
    )
}
/// Select current opaque access/service authentication explicitly.
pub fn local_realtime_router(
    store: Arc<PostgresControlStore>,
    config: LocalRealtimeHttpConfig,
    runtime: &RealtimeServerRuntime,
) -> Result<Router, RealtimeServerError> {
    routes(
        Authentication::Local {
            backend: ControlBackend::Postgres(store),
            audience: config.audience,
            identity_json_bytes: config.identity_json_bytes,
        },
        config.realtime,
        runtime,
    )
}
/// Explicit SQLite opaque ingress using the existing owned WS runtime.
pub fn sqlite_local_realtime_router(
    store: Arc<SqliteControlStore>,
    config: LocalRealtimeHttpConfig,
    runtime: &RealtimeServerRuntime,
) -> Result<Router, RealtimeServerError> {
    routes(
        Authentication::Local {
            backend: ControlBackend::Sqlite(store),
            audience: config.audience,
            identity_json_bytes: config.identity_json_bytes,
        },
        config.realtime,
        runtime,
    )
}

fn routes(
    authentication: Authentication,
    config: RealtimeHttpConfig,
    runtime: &RealtimeServerRuntime,
) -> Result<Router, RealtimeServerError> {
    if runtime.state.closed.load(Ordering::Acquire)
        || config.operation_timeout.is_zero()
        || Instant::now()
            .checked_add(config.operation_timeout)
            .is_none()
        || config.required_scopes.iter().any(|s| s.trim().is_empty())
        || config.command_bytes.get() > isize::MAX as usize
        || config.outbound_bytes.get() > isize::MAX as usize
    {
        return Err(RealtimeServerError::InvalidConfiguration);
    }
    let state = Arc::new(RouteState {
        authentication,
        config,
        runtime: Arc::downgrade(&runtime.state),
    });
    state
        .authorizer()
        .map_err(|_| RealtimeServerError::InvalidConfiguration)?;
    Ok(Router::new()
        .route("/v1/realtime", get(upgrade))
        .with_state(state))
}
async fn upgrade(
    State(route): State<Arc<RouteState>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, HttpFailure> {
    let end = route.original().map_err(|e| e.http())?;
    let runtime = route
        .runtime
        .upgrade()
        .filter(|s| !s.closed.load(Ordering::Acquire))
        .ok_or_else(|| Failure::CLOSED.http())?;
    let credential = bearer(&headers)?;
    let raw = Zeroizing::new(credential.token().to_owned());
    let window = route.authenticate(&raw, end).await?;
    window.check(end).map_err(|e| e.http())?;
    if runtime.closed.load(Ordering::Acquire) {
        return Err(Failure::CLOSED.http());
    }
    let weak = Arc::downgrade(&runtime);
    let cap = route.config.command_bytes.get();
    Ok(upgrade
        .max_frame_size(cap)
        .max_message_size(cap)
        .on_upgrade(move |socket| async move {
            if let Some(state) = weak.upgrade()
                && !state.closed.load(Ordering::Acquire)
                && window.check(end).is_ok()
            {
                // No connection task is detached from the explicit runtime owner.
                let _ = state.input.send(Connection {
                    socket,
                    route,
                    raw,
                    window,
                    write_incomplete: false,
                });
            }
        }))
}
#[derive(Clone, Copy)]
struct Window {
    utc: SystemTime,
    mono: Instant,
}
impl Window {
    fn from_pair((utc, mono): (SystemTime, Instant)) -> Self {
        Self { utc, mono }
    }
    fn intersect(&mut self, pair: (SystemTime, Instant)) {
        self.utc = self.utc.min(pair.0);
        self.mono = self.mono.min(pair.1);
    }
    fn check(self, end: Instant) -> Result<(), Failure> {
        self.check_auth()?;
        if Instant::now() >= end {
            return Err(Failure::DEADLINE);
        }
        Ok(())
    }
    fn check_auth(self) -> Result<(), Failure> {
        if SystemTime::now() >= self.utc || Instant::now() >= self.mono {
            return Err(Failure::UNAUTHENTICATED);
        }
        Ok(())
    }
    fn limit(self, end: Instant) -> Instant {
        let now = Instant::now();
        let utc_end = self
            .utc
            .duration_since(SystemTime::now())
            .ok()
            .and_then(|d| now.checked_add(d))
            .unwrap_or(now);
        end.min(self.mono).min(utc_end)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Failure {
    code: &'static str,
    close: u16,
}
impl Failure {
    const INVALID: Self = Self {
        code: "invalid_data",
        close: 1008,
    };
    const TOO_LARGE: Self = Self {
        code: "too_large",
        close: 1009,
    };
    const UNAUTHENTICATED: Self = Self {
        code: "unauthenticated",
        close: 1008,
    };
    const FORBIDDEN: Self = Self {
        code: "forbidden",
        close: 1008,
    };
    const DEADLINE: Self = Self {
        code: "deadline",
        close: 1011,
    };
    const UNAVAILABLE: Self = Self {
        code: "authorization_unavailable",
        close: 1011,
    };
    const CLOSED: Self = Self {
        code: "closed",
        close: 1000,
    };
    const SUPERSEDED: Self = Self {
        code: "superseded",
        close: 1008,
    };
    const BACKPRESSURE: Self = Self {
        code: "backpressure",
        close: 1013,
    };
    fn http(self) -> HttpFailure {
        let status = match self.code {
            "unauthenticated" => StatusCode::UNAUTHORIZED,
            "forbidden" => StatusCode::FORBIDDEN,
            "invalid_data" => StatusCode::BAD_REQUEST,
            "deadline" => StatusCode::GATEWAY_TIMEOUT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        HttpFailure::new(status, self.code)
    }
    fn socket(e: axum::Error) -> Self {
        match e.into_inner().downcast::<SocketError>() {
            Ok(e) => match *e {
                SocketError::Capacity(_) => Self::TOO_LARGE,
                SocketError::ConnectionClosed | SocketError::AlreadyClosed | SocketError::Io(_) => {
                    Self::CLOSED
                }
                _ => Self::INVALID,
            },
            Err(_) => Self::UNAVAILABLE,
        }
    }
}
impl From<HttpFailure> for Failure {
    fn from(e: HttpFailure) -> Self {
        match e.code {
            "unauthenticated" => Self::UNAUTHENTICATED,
            "forbidden" | "insufficient_scope" => Self::FORBIDDEN,
            "deadline" => Self::DEADLINE,
            "closed" => Self::CLOSED,
            "outcome_uncertain" => Self {
                code: "outcome_uncertain",
                close: 1011,
            },
            _ => Self::UNAVAILABLE,
        }
    }
}
impl From<NowChannelAuthorizationError> for Failure {
    fn from(e: NowChannelAuthorizationError) -> Self {
        use NowChannelAuthorizationError as E;
        match e {
            E::Native(e) => HttpFailure::from(e).into(),
            E::Local(e) => super::authorization_failure(e).into(),
            E::Inventory(InstanceReadError::Control(e)) => {
                super::control_failure(e, "authorization_unavailable").into()
            }
            E::Inventory(_) => Self::UNAVAILABLE,
            E::InvalidChannel | E::InvalidProject | E::SnapshotProjectMismatch => Self::INVALID,
            E::NotRegistered => Self {
                code: "not_registered",
                close: 1008,
            },
            E::OwnerConflict => Self {
                code: "owner_conflict",
                close: 1008,
            },
        }
    }
}
impl From<RealtimeHubError> for Failure {
    fn from(e: RealtimeHubError) -> Self {
        match e {
            RealtimeHubError::Authorization(e) => e.into(),
            RealtimeHubError::InvalidContext => Self::INVALID,
            RealtimeHubError::OwnerConflict => Self {
                code: "owner_conflict",
                close: 1008,
            },
            RealtimeHubError::AuthenticationExpired => Self::UNAUTHENTICATED,
            RealtimeHubError::Superseded => Self::SUPERSEDED,
            RealtimeHubError::Closed => Self::CLOSED,
            RealtimeHubError::InvalidConfiguration | RealtimeHubError::Unavailable => {
                Self::UNAVAILABLE
            }
        }
    }
}
fn optional_literal<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Publish {
        instance_id: String,
        project_id: String,
        version: String,
        snapshot: Box<NowSnapshotData>,
    },
    Subscribe {
        project_id: String,
        #[serde(default, deserialize_with = "optional_literal")]
        instance_id: Option<String>,
        #[serde(default, deserialize_with = "optional_literal")]
        version: Option<String>,
    },
    Heartbeat {},
}
// Require a JSON object while delegating keys, duplicates and enum decoding to Serde.
struct MapOnly<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Object<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
            type Value = MapOnly<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a realtime command object")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(MapOnly)
            }
        }
        d.deserialize_map(Object(std::marker::PhantomData))
    }
}
struct Filter {
    project: String,
    instance: Option<String>,
    version: Option<String>,
}
impl Filter {
    fn validate(
        project: String,
        instance: Option<String>,
        version: Option<String>,
    ) -> Result<Self, Failure> {
        if let Some(id) = &instance {
            InstanceInventory::new(id.clone(), vec![]).map_err(|_| Failure::INVALID)?;
        }
        if let Some(v) = &version {
            InstanceProjectVersions::new(project.clone(), vec![v.clone()])
                .map_err(|_| Failure::INVALID)?;
        }
        // The real project authorizer validates the project, including no-filter subscriptions.
        Ok(Self {
            project,
            instance,
            version,
        })
    }
    fn includes(&self, channel: &PresenceChannel) -> bool {
        self.instance
            .as_deref()
            .is_none_or(|s| s == channel.instance_id())
            && self
                .version
                .as_deref()
                .is_none_or(|s| s == channel.version())
    }
}
struct BoundedFrame {
    bytes: Vec<u8>,
    cap: usize,
    exceeded: bool,
}
impl Write for BoundedFrame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.cap)
        {
            self.exceeded = true;
            return Err(io::Error::other("realtime frame too large"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T, cap: usize) -> Result<String, Failure> {
    let mut writer = BoundedFrame {
        bytes: Vec::new(),
        cap,
        exceeded: false,
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        return Err(if writer.exceeded {
            Failure::TOO_LARGE
        } else {
            Failure::INVALID
        });
    }
    String::from_utf8(writer.bytes).map_err(|_| Failure::INVALID)
}
#[derive(Serialize)]
struct Welcome {
    r#type: &'static str,
    heartbeat_timeout_ns: String,
}
#[derive(Serialize)]
struct Snapshot<'a, 'v> {
    r#type: &'static str,
    #[serde(flatten)]
    replay: &'a RealtimeHubReplay<'v>,
}
#[derive(Serialize)]
struct Notice {
    r#type: &'static str,
    code: &'static str,
}
struct Connection {
    socket: WebSocket,
    route: Arc<RouteState>,
    raw: Zeroizing<String>,
    window: Window,
    write_incomplete: bool,
}
enum Role {
    Publisher {
        channel: PresenceChannel,
        handle: RealtimePublisherHandle,
    },
    Subscriber {
        filter: Filter,
        subscription: RealtimeProjectSubscription,
    },
}
impl Connection {
    async fn run(mut self, state: Arc<RuntimeState>) {
        let result = self.serve(&state).await;
        if let Err(failure) = result
            && !self.write_incomplete
        {
            // Only finite public control data; this cleanup budget never extends a
            // protected DATA operation or its authorization window.
            if let Ok(end) = self.route.original() {
                let cap = self.route.config.outbound_bytes.get();
                if let Ok(text) = encode(
                    &Notice {
                        r#type: "error",
                        code: failure.code,
                    },
                    cap,
                ) && !matches!(
                    tokio::time::timeout_at(
                        end.into(),
                        self.socket.send(Message::Text(text.into())),
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    return;
                }
                if !matches!(
                    tokio::time::timeout_at(
                        end.into(),
                        self.socket.send(Message::Close(Some(CloseFrame {
                            code: failure.close,
                            reason: failure.code.into(),
                        }))),
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    return;
                }
                // Drive the peer's closing handshake before dropping TCP. Incoming
                // application data is discarded; cleanup cannot authorize new DATA.
                while Instant::now() < end {
                    match tokio::time::timeout_at(end.into(), self.socket.next()).await {
                        Ok(Some(Ok(Message::Close(_))) | None) | Ok(Some(Err(_))) | Err(_) => break,
                        Ok(Some(Ok(_))) => {}
                    }
                }
            }
        }
    }
    async fn next(
        &mut self,
        original: Option<Instant>,
    ) -> Result<Option<(Command, Instant)>, Failure> {
        loop {
            self.window.check_auth()?;
            let end = original.unwrap_or(self.window.mono);
            if original.is_some() {
                self.window.check(end)?;
            }
            let message =
                tokio::time::timeout_at(self.window.limit(end).into(), self.socket.next())
                    .await
                    .map_err(|_| self.window.check_auth().err().unwrap_or(Failure::DEADLINE))?;
            match message {
                Some(Ok(Message::Text(text))) => {
                    self.window.check_auth()?;
                    if original.is_some() {
                        self.window.check(end)?;
                    }
                    if text.len() > self.route.config.command_bytes.get() {
                        return Err(Failure::TOO_LARGE);
                    }
                    let operation = match original {
                        Some(end) => end,
                        None => self.route.original()?,
                    };
                    let result = serde_json::from_str::<MapOnly<Command>>(&text)
                        .map(|v| Some((v.0, operation)));
                    self.window.check(operation)?;
                    return result.map_err(|_| Failure::INVALID);
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Ok(Message::Binary(_))) => return Err(Failure::INVALID),
                Some(Err(e)) => return Err(Failure::socket(e)),
            }
        }
    }
    async fn send<T: Serialize>(&mut self, value: &T, end: Instant) -> Result<(), Failure> {
        self.window.check(end)?;
        let text = encode(value, self.route.config.outbound_bytes.get())?;
        self.window.check(end)?;
        self.write_incomplete = true;
        tokio::time::timeout_at(
            self.window.limit(end).into(),
            self.socket.send(Message::Text(text.into())),
        )
        .await
        .map_err(|_| self.window.check(end).err().unwrap_or(Failure::DEADLINE))?
        .map_err(Failure::socket)?;
        self.write_incomplete = false;
        self.window.check(end)
    }
    async fn replay(
        &mut self,
        state: &RuntimeState,
        filter: &Filter,
        end: Instant,
        subscribe: bool,
    ) -> Result<Option<RealtimeProjectSubscription>, Failure> {
        self.window.check(end)?;
        let route = self.route.clone();
        let authorizer = route.authorizer()?;
        let project = authorizer
            .authorize_subscriber_project(
                &self.raw,
                &route.config.required_scopes,
                &filter.project,
                end,
            )
            .await?;
        self.window.intersect(project.authentication_expiry());
        self.window.check(end)?;
        let subscription = if subscribe {
            Some(state.hub.subscribe(&project)?)
        } else {
            None
        };
        let candidates = state.hub.candidates(&project)?;
        let mut channels = Vec::new();
        for candidate in candidates {
            if filter.includes(candidate.channel()) {
                self.window.check(end)?;
                let proof = authorizer
                    .authorize_read(
                        &self.raw,
                        &route.config.required_scopes,
                        candidate.channel(),
                        end,
                    )
                    .await?;
                self.window.intersect(proof.authentication_expiry());
                channels.push(proof);
            }
        }
        let replay = state.hub.replay(project, channels)?;
        replay.check()?;
        self.window.check(end)?;
        if subscribe {
            self.send(
                &Welcome {
                    r#type: "welcome",
                    heartbeat_timeout_ns: state.heartbeat.as_nanos().to_string(),
                },
                end,
            )
            .await?;
        }
        let frame = Snapshot {
            r#type: "snapshot",
            replay: &replay,
        };
        let encoded = encode(&frame, route.config.outbound_bytes.get());
        // Preserve the real temporal error if encoding crossed a proof window.
        replay.check()?;
        self.window.check(end)?;
        let text = encoded?;
        self.write_incomplete = true;
        tokio::time::timeout_at(
            self.window.limit(end).into(),
            self.socket.send(Message::Text(text.into())),
        )
        .await
        .map_err(|_| self.window.check(end).err().unwrap_or(Failure::DEADLINE))?
        .map_err(Failure::socket)?;
        self.write_incomplete = false;
        replay.check()?;
        self.window.check(end)?;
        Ok(subscription)
    }
    async fn publish(
        &mut self,
        state: &RuntimeState,
        channel: &PresenceChannel,
        snapshot: NowSnapshotData,
        handle: Option<&RealtimePublisherHandle>,
        end: Instant,
    ) -> Result<Option<RealtimePublisherHandle>, Failure> {
        self.window.check(end)?;
        let route = self.route.clone();
        let authorizer = route.authorizer()?;
        let proof = authorizer
            .authorize_publish(&self.raw, &route.config.required_scopes, channel, end)
            .await?;
        self.window.intersect(proof.authentication_expiry());
        self.window.check(end)?;
        if let Some(handle) = handle {
            handle.publish(proof, snapshot)?;
            Ok(None)
        } else {
            Ok(Some(state.hub.open_publisher(proof, snapshot)?))
        }
    }
    async fn serve(&mut self, state: &RuntimeState) -> Result<(), Failure> {
        let first_end = self.route.original()?;
        let Some((command, first_end)) = self.next(Some(first_end)).await? else {
            return Ok(());
        };
        let mut role = match command {
            Command::Publish {
                instance_id,
                project_id,
                version,
                snapshot,
            } => {
                let channel = PresenceChannel::new(&instance_id, &project_id, &version)?;
                let handle = self
                    .publish(state, &channel, *snapshot, None, first_end)
                    .await?
                    .ok_or(Failure::UNAVAILABLE)?;
                self.send(
                    &Welcome {
                        r#type: "welcome",
                        heartbeat_timeout_ns: state.heartbeat.as_nanos().to_string(),
                    },
                    first_end,
                )
                .await?;
                Role::Publisher { channel, handle }
            }
            Command::Subscribe {
                project_id,
                instance_id,
                version,
            } => {
                let filter = Filter::validate(project_id, instance_id, version)?;
                let subscription = self
                    .replay(state, &filter, first_end, true)
                    .await?
                    .ok_or(Failure::UNAVAILABLE)?;
                Role::Subscriber {
                    filter,
                    subscription,
                }
            }
            Command::Heartbeat {} => return Err(Failure::INVALID),
        };
        loop {
            self.window.check_auth()?;
            enum Event {
                Command(Option<(Command, Instant)>),
                Signal(Result<(), RealtimeHubSignalError>),
                Inactive(RealtimeHubError),
            }
            let event = match &mut role {
                Role::Publisher { handle, .. } => tokio::select! {
                    command = self.next(None) => Event::Command(command?),
                    reason = handle.wait_inactive() => Event::Inactive(reason),
                },
                Role::Subscriber { subscription, .. } => tokio::select! {
                    command = self.next(None) => Event::Command(command?),
                    signal = subscription.recv() => Event::Signal(signal),
                },
            };
            let end = match &event {
                Event::Command(Some((_, end))) => *end,
                _ => self.route.original()?,
            };
            match (&role, event) {
                (_, Event::Command(None)) => return Ok(()),
                (_, Event::Inactive(reason)) => return Err(reason.into()),
                (_, Event::Signal(Err(RealtimeHubSignalError::Lagged))) => {
                    return Err(Failure::BACKPRESSURE);
                }
                (_, Event::Signal(Err(RealtimeHubSignalError::Closed))) => {
                    return Err(Failure::CLOSED);
                }
                (
                    Role::Subscriber { filter, .. },
                    Event::Command(Some((Command::Heartbeat {}, _))) | Event::Signal(Ok(())),
                ) => {
                    self.replay(state, filter, end, false).await?;
                }
                (
                    Role::Publisher { channel, handle },
                    Event::Command(Some((
                        Command::Publish {
                            instance_id,
                            project_id,
                            version,
                            snapshot,
                        },
                        _,
                    ))),
                ) => {
                    if channel != &PresenceChannel::new(&instance_id, &project_id, &version)? {
                        return Err(Failure::INVALID);
                    }
                    self.publish(state, channel, *snapshot, Some(handle), end)
                        .await?;
                }
                _ => return Err(Failure::INVALID),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn window_check_prioritizes_authentication_expiry() {
        let now = Instant::now();
        let future = now + Duration::from_secs(60);
        let past = now - Duration::from_secs(1);
        let utc_future = SystemTime::now() + Duration::from_secs(60);
        for (name, utc, mono, end, expected) in [
            (
                "UTC authentication and operation expired",
                SystemTime::UNIX_EPOCH,
                future,
                past,
                Err(Failure::UNAUTHENTICATED),
            ),
            (
                "monotonic authentication and operation expired",
                utc_future,
                past,
                past,
                Err(Failure::UNAUTHENTICATED),
            ),
            (
                "both authentication bounds and operation expired",
                SystemTime::UNIX_EPOCH,
                past,
                past,
                Err(Failure::UNAUTHENTICATED),
            ),
            (
                "authentication expired during a live operation",
                SystemTime::UNIX_EPOCH,
                past,
                future,
                Err(Failure::UNAUTHENTICATED),
            ),
            (
                "only operation expired",
                utc_future,
                future,
                past,
                Err(Failure::DEADLINE),
            ),
            (
                "authentication and operation valid",
                utc_future,
                future,
                future,
                Ok(()),
            ),
        ] {
            assert_eq!(Window { utc, mono }.check(end), expected, "{name}");
        }
    }
    #[test]
    fn codec_optional_filters_are_independent_and_null_is_not_absence() {
        let a = "01D39ZY06FGSCTVN4T2V9PKHFZ";
        for suffix in [
            "",
            ",\"instance_id\":\"station\"",
            ",\"version\":\"branch/ação\"",
            ",\"instance_id\":\"station\",\"version\":\"main\"",
        ] {
            let text = format!("{{\"op\":\"subscribe\",\"project_id\":\"{a}\"{suffix}}}");
            let Command::Subscribe {
                project_id,
                instance_id,
                version,
            } = serde_json::from_str::<MapOnly<Command>>(&text).unwrap().0
            else {
                panic!()
            };
            assert!(Filter::validate(project_id, instance_id, version).is_ok());
        }
        for raw in [
            r#"{"op":"heartbeat","extra":1}"#,
            r#"{"op":"heartbeat","op":"heartbeat"}"#,
            r#"{"op":"subscribe","project_id":"a","instance_id":null}"#,
            r#"{"op":"subscribe","project_id":"a","version":null}"#,
            r#"{"op":"subscribe","project_id":"a","project_id":"a"}"#,
            r#"{"op":"publish","instance_id":"s","project_id":"a","version":"main"}"#,
        ] {
            assert!(
                serde_json::from_str::<MapOnly<Command>>(raw).is_err(),
                "{raw}"
            );
        }
        for raw in [
            r#"["heartbeat"]"#,
            r#"["subscribe","01D39ZY06FGSCTVN4T2V9PKHFZ",null,null]"#,
            r#"["publish","s","01D39ZY06FGSCTVN4T2V9PKHFZ","main",{}]"#,
        ] {
            assert!(serde_json::from_str::<MapOnly<Command>>(raw).is_err());
        }
        assert!(Filter::validate(a.into(), Some("".into()), None).is_err());
        assert!(Filter::validate(a.into(), None, Some("".into())).is_err());
        assert!(Filter::validate(a.into(), None, Some(" main".into())).is_err());
    }
    #[test]
    fn bounded_whole_frame_and_finite_errors() {
        let value = Notice {
            r#type: "error",
            code: "forbidden",
        };
        let text = encode(&value, 1024).unwrap();
        assert_eq!(encode(&value, text.len()).unwrap(), text);
        assert_eq!(
            encode(&value, text.len() - 1).unwrap_err(),
            Failure::TOO_LARGE
        );
        for failure in [
            Failure::INVALID,
            Failure::TOO_LARGE,
            Failure::BACKPRESSURE,
            Failure::UNAUTHENTICATED,
        ] {
            let bytes = encode(
                &Notice {
                    r#type: "error",
                    code: failure.code,
                },
                1024,
            )
            .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&bytes)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .len(),
                2
            );
        }
    }
}
