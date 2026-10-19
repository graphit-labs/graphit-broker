//! Warm Native verification fixture; login/refresh/OP are outside this tool.
#[allow(
    dead_code,
    reason = "shared native PostgreSQL support serves other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use axum::{
    Json,
    body::Body,
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use broker_control::{
    BrokerAccessIssuer, BrokerAccessTokenInput, BrokerAccessVerifier, InstanceInventory,
    InstanceProjectVersions, PostgresControlStore,
};
use broker_presence::{
    BrokerOwnReadHttpConfig, BrokerPublishHttpConfig, RealtimeHttpConfig, RealtimeHub,
    RealtimeServerRuntime, broker_instance_inventory_router, broker_realtime_router,
};
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    io::{BufRead, Write},
    num::NonZeroUsize,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

struct Object<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an IPC object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                m: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(m)).map(Object)
            }
        }
        d.deserialize_map(Visitor(std::marker::PhantomData))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectFields {
    project_id: String,
    versions: Vec<String>,
}
struct Project(ProjectFields);
impl<'de> Deserialize<'de> for Project {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Object::<ProjectFields>::deserialize(d).map(|Object(p)| Self(p))
    }
}
fn optional_realtime<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Object<RealtimeSettings>>, D::Error> {
    Object::<RealtimeSettings>::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealtimeSettings {
    heartbeat_timeout_ms: u64,
    broadcast_capacity: usize,
    required_scopes: Vec<String>,
    command_bytes: usize,
    outbound_bytes: usize,
    operation_timeout_ms: u64,
    task_read: bool,
}
impl RealtimeSettings {
    fn validate(&self) -> Result<(), Failure> {
        if self.operation_timeout_ms == 0
            || std::time::Instant::now()
                .checked_add(Duration::from_millis(self.operation_timeout_ms))
                .is_none()
            || self
                .required_scopes
                .iter()
                .any(|s| s.trim().is_empty() || s.contains(' '))
            || [self.command_bytes, self.outbound_bytes]
                .iter()
                .any(|v| *v == 0 || *v > isize::MAX as usize)
        {
            return Err(Failure::InvalidCommand);
        }
        RealtimeHub::new(
            Duration::from_millis(self.heartbeat_timeout_ms),
            std::num::NonZeroUsize::new(self.broadcast_capacity).ok_or(Failure::InvalidCommand)?,
        )
        .map(|_| ())
        .map_err(|_| Failure::InvalidCommand)
    }
    fn prepare(&self) -> Result<RealtimeServerRuntime, Failure> {
        self.validate()?;
        RealtimeServerRuntime::new(
            Duration::from_millis(self.heartbeat_timeout_ms),
            std::num::NonZeroUsize::new(self.broadcast_capacity).ok_or(Failure::InvalidCommand)?,
        )
        .map_err(|_| Failure::InvalidCommand)
    }
    fn http(
        &self,
        grants_json_bytes: std::num::NonZeroUsize,
        inventory_json_bytes: std::num::NonZeroUsize,
    ) -> RealtimeHttpConfig {
        RealtimeHttpConfig {
            required_scopes: self.required_scopes.clone(),
            grants_json_bytes,
            inventory_json_bytes,
            command_bytes: std::num::NonZeroUsize::new(self.command_bytes)
                .expect("validated realtime cap"),
            outbound_bytes: std::num::NonZeroUsize::new(self.outbound_bytes)
                .expect("validated realtime cap"),
            operation_timeout: Duration::from_millis(self.operation_timeout_ms),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    api_audience: String,
    resource: String,
    client_id: String,
    subject: String,
    scope: String,
    redirect_uri_path: String,
    access_ttl_seconds: u64,
    instance_id: String,
    projects: Vec<Project>,
    seed_inventory: bool,
    grant_project_ids: Vec<String>,
    read_required_scopes: Vec<String>,
    publish_required_scopes: Vec<String>,
    token_bytes: usize,
    grants_json_bytes: usize,
    inventory_json_bytes: usize,
    body_bytes: usize,
    request_timeout_ms: u64,
    #[serde(default, deserialize_with = "optional_realtime")]
    realtime: Option<Object<RealtimeSettings>>,
}
impl Setup {
    fn inventory(&self) -> Result<InstanceInventory, Failure> {
        let projects = self
            .projects
            .iter()
            .map(|p| {
                InstanceProjectVersions::new(p.0.project_id.clone(), p.0.versions.clone())
                    .map_err(|_| Failure::InvalidCommand)
            })
            .collect::<Result<Vec<_>, _>>()?;
        InstanceInventory::new(self.instance_id.clone(), projects)
            .map_err(|_| Failure::InvalidCommand)
    }
    fn validate(&self) -> Result<(), Failure> {
        self.inventory()?;
        if [
            &self.api_audience,
            &self.resource,
            &self.client_id,
            &self.subject,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
            || self.access_ttl_seconds == 0
            || self.request_timeout_ms == 0
            || !self.scope.split(' ').any(|s| s == "openid")
            || !self.redirect_uri_path.starts_with('/')
            || self.redirect_uri_path.contains(['?', '#'])
            || self.redirect_uri_path.chars().any(char::is_control)
            || self
                .read_required_scopes
                .iter()
                .chain(&self.publish_required_scopes)
                .any(|s| s.trim().is_empty())
        {
            return Err(Failure::InvalidCommand);
        }
        for cap in [
            self.token_bytes,
            self.grants_json_bytes,
            self.inventory_json_bytes,
            self.body_bytes,
        ] {
            let cap = positive(cap)?;
            if cap.get() > isize::MAX as usize || i64::try_from(cap.get()).is_err() {
                return Err(Failure::InvalidCommand);
            }
        }
        if Instant::now()
            .checked_add(Duration::from_millis(self.request_timeout_ms))
            .is_none()
        {
            return Err(Failure::InvalidCommand);
        }
        i64::try_from(
            seconds()?
                .checked_add(self.access_ttl_seconds)
                .ok_or(Failure::InvalidCommand)?,
        )
        .map_err(|_| Failure::InvalidCommand)?;
        for (i, p) in self.grant_project_ids.iter().enumerate() {
            if self.grant_project_ids[..i].contains(p) {
                return Err(Failure::InvalidCommand);
            }
            if p != "*" {
                // Reuse the public DATA validator; this lexical probe is never
                // stored as an installed version or used as permission.
                InstanceProjectVersions::new(p.clone(), vec!["validation".into()])
                    .map_err(|_| Failure::InvalidCommand)?;
            }
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Start {
        #[serde(flatten)]
        setup: Box<Setup>,
    },
    DenyRead {},
    AllowRead {},
    DenyPublish {},
    AllowPublish {},
    DeleteInventory {},
    ReplaceWithForeignOwner {
        subject: String,
    },
    LoseNextSuccessfulPutResponse {},
    Stats {},
    Shutdown {},
}
impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Start { .. } => "start",
            Self::DenyRead {} => "deny_read",
            Self::AllowRead {} => "allow_read",
            Self::DenyPublish {} => "deny_publish",
            Self::AllowPublish {} => "allow_publish",
            Self::DeleteInventory {} => "delete_inventory",
            Self::ReplaceWithForeignOwner { .. } => "replace_with_foreign_owner",
            Self::LoseNextSuccessfulPutResponse {} => "lose_next_successful_put_response",
            Self::Stats {} => "stats",
            Self::Shutdown {} => "shutdown",
        }
    }
}
#[derive(Debug)]
enum Failure {
    InvalidCommand,
    Input,
    Output,
    Setup,
    Storage,
    Server,
    Shutdown,
}
impl Failure {
    fn message(&self) -> &'static str {
        match self {
            Self::InvalidCommand => "invalid Native inventory fixture command",
            Self::Input => "Native inventory fixture input failed",
            Self::Output => "Native inventory fixture output failed",
            Self::Setup => "Native inventory fixture setup failed",
            Self::Storage => "Native inventory fixture storage failed",
            Self::Server => "Native inventory fixture server failed",
            Self::Shutdown => "Native inventory fixture shutdown failed",
        }
    }
}
fn read_command(input: &mut impl BufRead) -> Result<Option<Command>, Failure> {
    let mut line = String::new();
    if input.read_line(&mut line).map_err(|_| Failure::Input)? == 0 {
        return Ok(None);
    }
    serde_json::from_str::<Object<Command>>(&line)
        .map(|Object(c)| Some(c))
        .map_err(|_| Failure::InvalidCommand)
}
fn emit(output: &mut impl Write, event: &impl Serialize) -> Result<(), Failure> {
    serde_json::to_writer(&mut *output, event).map_err(|_| Failure::Output)?;
    output.write_all(b"\n").map_err(|_| Failure::Output)?;
    output.flush().map_err(|_| Failure::Output)
}
fn positive(v: usize) -> Result<NonZeroUsize, Failure> {
    NonZeroUsize::new(v).ok_or(Failure::InvalidCommand)
}
fn seconds() -> Result<u64, Failure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Failure::Setup)
}
fn literal(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        if "\\*?[]{}".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
fn signed(
    issuer: &BrokerAccessIssuer,
    setup: &Setup,
    subject: &str,
) -> Result<(String, u64), Failure> {
    let now = seconds()?;
    let exp = now
        .checked_add(setup.access_ttl_seconds)
        .ok_or(Failure::InvalidCommand)?;
    i64::try_from(exp).map_err(|_| Failure::InvalidCommand)?;
    let bearer = issuer
        .sign_access(
            BrokerAccessTokenInput {
                subject,
                client_id: &setup.client_id,
                resource: Some(&setup.resource),
                scope: &setup.scope,
                jti: "native-inventory-fixture-access",
                issued_at: now,
                expires_at: exp,
                preferred_username: None,
                name: None,
                email: None,
                organization: None,
                groups: &[],
                roles: &[],
            },
            deadline(),
        )
        .map_err(|_| Failure::InvalidCommand)?;
    Ok((bearer, exp))
}
fn config(f: &Fixture) -> Result<broker_control::PostgresConfig, Failure> {
    broker_control::PostgresConfig::new(
        broker_control::PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: std::num::NonZeroU16::new(f.port).ok_or(Failure::Setup)?,
            database: "postgres".into(),
        },
        broker_control::PostgresCredentials::new(
            "native_inventory_owner".into(),
            zeroize::Zeroizing::new("fixture-owner".into()),
        ),
        f.ca.clone(),
        broker_control::ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .map_err(|_| Failure::Setup)
}
#[derive(Default)]
struct Counters {
    broker: AtomicU64,
    oidc: AtomicU64,
    jwks: AtomicU64,
    token: AtomicU64,
    userinfo: AtomicU64,
    put: AtomicU64,
    loss: AtomicU64,
    armed: AtomicBool,
}
#[derive(Serialize)]
struct Stats {
    event: &'static str,
    broker_metadata_requests: u64,
    oidc_metadata_requests: u64,
    jwks_requests: u64,
    token_requests: u64,
    userinfo_requests: u64,
    put_success_responses: u64,
    put_response_losses: u64,
}
impl Counters {
    fn stats(&self) -> Stats {
        Stats {
            event: "stats",
            broker_metadata_requests: self.broker.load(Ordering::SeqCst),
            oidc_metadata_requests: self.oidc.load(Ordering::SeqCst),
            jwks_requests: self.jwks.load(Ordering::SeqCst),
            token_requests: self.token.load(Ordering::SeqCst),
            userinfo_requests: self.userinfo.load(Ordering::SeqCst),
            put_success_responses: self.put.load(Ordering::SeqCst),
            put_response_losses: self.loss.load(Ordering::SeqCst),
        }
    }
}
async fn observe(c: Arc<Counters>, request: Request, next: Next) -> Response {
    let put = request.method() == Method::PUT
        && request.uri().path().starts_with("/v1/instances/")
        && request.uri().path().ends_with("/inventory");
    let counter = match request.uri().path() {
        "/.well-known/graphit-broker" => Some(&c.broker),
        "/.well-known/openid-configuration" => Some(&c.oidc),
        "/jwks" => Some(&c.jwks),
        "/token" => Some(&c.token),
        "/userinfo" => Some(&c.userinfo),
        _ => None,
    };
    if let Some(counter) = counter {
        counter.fetch_add(1, Ordering::SeqCst);
    }
    let mut response = next.run(request).await;
    if put && matches!(response.status(), StatusCode::OK | StatusCode::CREATED) {
        c.put.fetch_add(1, Ordering::SeqCst);
        // The actual registrar returned a confirmed result before the route
        // constructed 200/201. Lose delivery only, not SQL or its acknowledgment.
        if c.armed.swap(false, Ordering::SeqCst) {
            c.loss.fetch_add(1, Ordering::SeqCst);
            *response.body_mut() = Body::from_stream(futures_util::stream::once(async {
                Err::<axum::body::Bytes, _>(std::io::Error::other(
                    "fixture response delivery failed",
                ))
            }));
        }
    }
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
#[derive(Serialize)]
struct Ready<'a> {
    event: &'static str,
    endpoint: &'a str,
    issuer: &'a str,
    inventory_endpoint: &'a str,
    instance_id: &'a str,
    api_audience: &'a str,
    resource: &'a str,
    client_id: &'a str,
    subject: &'a str,
    scope: &'a str,
    redirect_uri_path: &'a str,
    expires_at: u64,
    access_bearer: &'a str,
    read_required_scopes: &'a [String],
    publish_required_scopes: &'a [String],
}
#[derive(Serialize)]
struct Ack {
    event: &'static str,
    command: &'static str,
    ok: bool,
}
struct LiveFixture {
    postgres: Fixture,
    control: PgConnection,
    store: Arc<PostgresControlStore>,
    issuer: BrokerAccessIssuer,
    verifier: Arc<BrokerAccessVerifier>,
    setup: Setup,
    origin: String,
    bearer: zeroize::Zeroizing<String>,
    expires_at: u64,
    counters: Arc<Counters>,
    realtime: Option<RealtimeServerRuntime>,
    stop: oneshot::Sender<()>,
    server: JoinHandle<Result<(), std::io::Error>>,
}
impl LiveFixture {
    async fn start(setup: Setup) -> Result<Self, Failure> {
        setup.validate()?;
        if let Some(Object(settings)) = &setup.realtime {
            settings.validate()?;
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| Failure::Server)?;
        let origin = format!(
            "http://{}",
            listener.local_addr().map_err(|_| Failure::Server)?
        );
        let pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|_| Failure::Setup)?;
        let key = zeroize::Zeroizing::new(pair.serialize_der());
        let issuer = BrokerAccessIssuer::new(
            &origin,
            &setup.api_audience,
            "native-inventory-fixture",
            &key,
        )
        .map_err(|_| Failure::InvalidCommand)?;
        let verifier = Arc::new(
            BrokerAccessVerifier::new(
                &origin,
                &setup.api_audience,
                Some(&setup.resource),
                issuer.jwks(),
                positive(setup.token_bytes)?,
            )
            .map_err(|_| Failure::InvalidCommand)?,
        );
        let (bearer, expires_at) = signed(&issuer, &setup, &setup.subject)?;
        verifier
            .verify(&bearer, &[], deadline())
            .map_err(|_| Failure::InvalidCommand)?;
        let postgres = Fixture::new(true).await;
        let mut control = postgres.connection().await;
        control.execute("CREATE ROLE native_inventory_owner LOGIN NOSUPERUSER PASSWORD 'fixture-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION native_inventory_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO native_inventory_owner").await.map_err(|_|Failure::Setup)?;
        let store = Arc::new(
            PostgresControlStore::open(config(&postgres)?, support::digester(), deadline())
                .await
                .map_err(|_| Failure::Setup)?,
        );
        set_grant(
            &mut control,
            &setup,
            &origin,
            "fixture-read",
            &setup.subject,
            "presence:read",
            true,
        )
        .await?;
        set_grant(
            &mut control,
            &setup,
            &origin,
            "fixture-publish",
            &setup.subject,
            "presence:publish",
            true,
        )
        .await?;
        if setup.realtime.as_ref().is_some_and(|Object(s)| s.task_read) {
            set_grant(
                &mut control,
                &setup,
                &origin,
                "fixture-task-read",
                &setup.subject,
                "task:read",
                true,
            )
            .await?;
        }
        if setup.seed_inventory {
            store
                .broker_instance_registrar(&verifier, positive(setup.grants_json_bytes)?)
                .map_err(|_| Failure::Setup)?
                .register(
                    &bearer,
                    &setup.publish_required_scopes,
                    &setup.inventory()?,
                    deadline(),
                )
                .await
                .map_err(|_| Failure::Setup)?;
        }
        let timeout = Duration::from_millis(setup.request_timeout_ms);
        let router = broker_instance_inventory_router(
            store.clone(),
            verifier.clone(),
            BrokerPublishHttpConfig {
                required_scopes: setup.publish_required_scopes.clone(),
                grants_json_bytes: positive(setup.grants_json_bytes)?,
                body_bytes: positive(setup.body_bytes)?,
                request_timeout: timeout,
            },
            BrokerOwnReadHttpConfig {
                required_scopes: setup.read_required_scopes.clone(),
                grants_json_bytes: positive(setup.grants_json_bytes)?,
                inventory_json_bytes: positive(setup.inventory_json_bytes)?,
                request_timeout: timeout,
            },
        )
        .map_err(|_| Failure::InvalidCommand)?;
        let broker = json!({"version":"1","issuer":origin,"authentication":{"type":"oidc","issuer":origin,"client_id":setup.client_id,
            "scopes":setup.scope.split(' ').filter(|s|!s.is_empty()).collect::<Vec<_>>(),"audiences":[setup.api_audience],"mcp_resources":[setup.resource],
            "access_token_audience":setup.api_audience,"redirect_uri_path":setup.redirect_uri_path}});
        // Shape required for warm verification, not an implementation or
        // qualification of login/refresh or a production OpenID Provider.
        let oidc = json!({"issuer":origin,"authorization_endpoint":format!("{origin}/authorize"),"token_endpoint":format!("{origin}/token"),
            "jwks_uri":format!("{origin}/jwks"),"grant_types_supported":["authorization_code","refresh_token"],
            "code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"id_token_signing_alg_values_supported":["EdDSA"]});
        let keys = serde_json::to_value(issuer.jwks()).map_err(|_| Failure::Setup)?;
        let counters = Arc::new(Counters::default());
        let observed = counters.clone();
        let mut router = router
            .route(
                "/.well-known/graphit-broker",
                get(move || {
                    let data = broker.clone();
                    async move { Json(data) }
                }),
            )
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let data = oidc.clone();
                    async move { Json(data) }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    let data = keys.clone();
                    async move { Json(data) }
                }),
            )
            .layer(middleware::from_fn(move |request, next| {
                observe(observed.clone(), request, next)
            }));
        let mut realtime = setup
            .realtime
            .as_ref()
            .map(|Object(s)| s.prepare())
            .transpose()?;
        if let (Some(Object(settings)), Some(runtime)) = (&setup.realtime, &realtime) {
            match broker_realtime_router(
                store.clone(),
                verifier.clone(),
                settings.http(n(setup.grants_json_bytes), n(setup.inventory_json_bytes)),
                runtime,
            ) {
                Ok(ws) => router = router.reset_fallback().merge(ws),
                Err(_) => {
                    if let Some(runtime) = realtime.take() {
                        let _ = runtime.shutdown().await;
                    }
                    return Err(Failure::InvalidCommand);
                }
            }
        }
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        Ok(Self {
            postgres,
            control,
            store,
            issuer,
            verifier,
            setup,
            origin,
            bearer: zeroize::Zeroizing::new(bearer),
            expires_at,
            counters,
            realtime,
            stop,
            server,
        })
    }
    fn ready(&self) -> Ready<'_> {
        Ready {
            event: "ready",
            endpoint: &self.origin,
            issuer: &self.origin,
            inventory_endpoint: &self.origin,
            instance_id: &self.setup.instance_id,
            api_audience: &self.setup.api_audience,
            resource: &self.setup.resource,
            client_id: &self.setup.client_id,
            subject: &self.setup.subject,
            scope: &self.setup.scope,
            redirect_uri_path: &self.setup.redirect_uri_path,
            expires_at: self.expires_at,
            access_bearer: &self.bearer,
            read_required_scopes: &self.setup.read_required_scopes,
            publish_required_scopes: &self.setup.publish_required_scopes,
        }
    }
    fn emit_ready(&self, output: &mut impl Write) -> Result<(), Failure> {
        // Startup may outlive an explicitly short TTL. Never emit a Ready
        // whose access token already fails the actual Native verifier.
        self.verifier
            .verify(&self.bearer, &[], deadline())
            .map_err(|_| Failure::Setup)?;
        emit(output, &self.ready())
    }
    async fn command(&mut self, c: &Command) -> Result<(), Failure> {
        match c {
            Command::Start { .. } => return Err(Failure::InvalidCommand),
            Command::DenyRead {} | Command::AllowRead {} => {
                set_grant(
                    &mut self.control,
                    &self.setup,
                    &self.origin,
                    "fixture-read",
                    &self.setup.subject,
                    "presence:read",
                    matches!(c, Command::AllowRead {}),
                )
                .await?
            }
            Command::DenyPublish {} | Command::AllowPublish {} => {
                set_grant(
                    &mut self.control,
                    &self.setup,
                    &self.origin,
                    "fixture-publish",
                    &self.setup.subject,
                    "presence:publish",
                    matches!(c, Command::AllowPublish {}),
                )
                .await?
            }
            Command::DeleteInventory {} => {
                delete_inventory(&mut self.control, &self.setup.instance_id).await?
            }
            Command::ReplaceWithForeignOwner { subject } => {
                if subject.trim().is_empty() || subject == &self.setup.subject {
                    return Err(Failure::InvalidCommand);
                }
                // Fixture operator reads DATA, never fabricates an authenticated
                // owner. The replacement uses a real signed principal/registrar.
                let stored = self
                    .store
                    .instance_inventories(positive(self.setup.inventory_json_bytes)?)
                    .map_err(|_| Failure::Storage)?
                    .read(&self.setup.instance_id, deadline())
                    .await
                    .map_err(|_| Failure::Storage)?
                    .ok_or(Failure::Storage)?;
                let replacement = InstanceInventory::new(
                    stored.inventory().instance_id().into(),
                    stored
                        .inventory()
                        .projects()
                        .iter()
                        .map(|p| {
                            InstanceProjectVersions::new(
                                p.project_id().into(),
                                p.versions().to_vec(),
                            )
                            .map_err(|_| Failure::Storage)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                )
                .map_err(|_| Failure::Storage)?;
                let (foreign, _) = signed(&self.issuer, &self.setup, subject)?;
                let foreign = zeroize::Zeroizing::new(foreign);
                set_grant(
                    &mut self.control,
                    &self.setup,
                    &self.origin,
                    "fixture-foreign",
                    subject,
                    "presence:publish",
                    true,
                )
                .await?;
                delete_inventory(&mut self.control, &self.setup.instance_id).await?;
                let result = self
                    .store
                    .broker_instance_registrar(
                        &self.verifier,
                        positive(self.setup.grants_json_bytes)?,
                    )
                    .map_err(|_| Failure::Storage)?
                    .register(
                        &foreign,
                        &self.setup.publish_required_scopes,
                        &replacement,
                        deadline(),
                    )
                    .await
                    .map_err(|_| Failure::Storage);
                let removed = set_grant(
                    &mut self.control,
                    &self.setup,
                    &self.origin,
                    "fixture-foreign",
                    subject,
                    "presence:publish",
                    false,
                )
                .await;
                result?;
                removed?;
            }
            Command::LoseNextSuccessfulPutResponse {} => {
                self.counters.armed.store(true, Ordering::SeqCst);
            }
            Command::Stats {} | Command::Shutdown {} => {}
        }
        Ok(())
    }
    async fn shutdown(self) -> Result<(), Failure> {
        let Self {
            postgres,
            control,
            store,
            stop,
            mut server,
            realtime,
            ..
        } = self;
        let _ = stop.send(());
        let realtime_closed = match realtime {
            Some(runtime) => runtime.shutdown().await.map_err(|_| Failure::Shutdown),
            None => Ok(()),
        };
        let served = match tokio::time::timeout(Duration::from_secs(3), &mut server).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(_) => Err(Failure::Shutdown),
            Err(_) => {
                server.abort();
                let _ = server.await;
                Err(Failure::Shutdown)
            }
        };
        let closed = store
            .shutdown(deadline())
            .await
            .map_err(|_| Failure::Shutdown);
        let control_closed = control.close().await.map_err(|_| Failure::Shutdown);
        drop(store);
        let removed = postgres.shutdown().map_err(|_| Failure::Shutdown);
        served
            .and(realtime_closed)
            .and(closed)
            .and(control_closed)
            .and(removed)
    }
}
async fn set_grant(
    c: &mut PgConnection,
    setup: &Setup,
    origin: &str,
    id: &str,
    subject: &str,
    cap: &str,
    allowed: bool,
) -> Result<(), Failure> {
    let mut tx = c.begin().await.map_err(|_| Failure::Storage)?;
    sqlx_core::query::query("DELETE FROM public.resource_grants WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::Storage)?;
    if allowed {
        sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'native fixture','subject',$2,'',0,0)")
            .bind(id).bind(literal(&format!("{origin}|{subject}"))).execute(&mut *tx).await.map_err(|_|Failure::Storage)?;
        sqlx_core::query::query(
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
        )
        .bind(id)
        .bind(cap)
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::Storage)?;
        for project in &setup.grant_project_ids {
            sqlx_core::query::query(
                "INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)",
            )
            .bind(id)
            .bind(project)
            .execute(&mut *tx)
            .await
            .map_err(|_| Failure::Storage)?;
        }
    }
    sqlx_core::query::query(
        "UPDATE public.resource_acl_state SET revision=revision+1,updated_at=0 WHERE id=1",
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| Failure::Storage)?;
    tx.commit().await.map_err(|_| Failure::Storage)
}
async fn delete_inventory(c: &mut PgConnection, id: &str) -> Result<(), Failure> {
    let mut tx = c.begin().await.map_err(|_| Failure::Storage)?;
    sqlx_core::query::query(
        "DELETE FROM public.broker_instance_project_versions WHERE instance_id=$1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|_| Failure::Storage)?;
    sqlx_core::query::query("DELETE FROM public.broker_instances WHERE instance_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::Storage)?;
    tx.commit().await.map_err(|_| Failure::Storage)
}
async fn run(input: &mut impl BufRead, output: &mut impl Write) -> Result<(), Failure> {
    let Some(start) = read_command(input)? else {
        return Ok(());
    };
    let Command::Start { setup } = start else {
        return Err(Failure::InvalidCommand);
    };
    let mut fixture = LiveFixture::start(*setup).await?;
    let mut shutdown = false;
    let result = async {
        fixture.emit_ready(output)?;
        while let Some(command) = read_command(input)? {
            fixture.command(&command).await?;
            if matches!(command, Command::Shutdown {}) {
                shutdown = true;
                break;
            }
            if matches!(command, Command::Stats {}) {
                emit(output, &fixture.counters.stats())?;
            } else {
                emit(
                    output,
                    &Ack {
                        event: "ack",
                        command: command.name(),
                        ok: true,
                    },
                )?;
            }
        }
        Ok(())
    }
    .await;
    let stopped = fixture.shutdown().await;
    result.and(stopped)?;
    if shutdown {
        emit(
            output,
            &Ack {
                event: "ack",
                command: "shutdown",
                ok: true,
            },
        )?;
    }
    Ok(())
}
#[tokio::main(worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    // The binary's finite failure surface must not expose panic payloads from
    // dependency/setup code. The catch below owns the single stderr message.
    std::panic::set_hook(Box::new(|_| {}));
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    match AssertUnwindSafe(run(&mut input, &mut output))
        .catch_unwind()
        .await
    {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        Ok(Err(e)) => {
            eprintln!("{}", e.message());
            std::process::ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("Native inventory fixture failed");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use serde_json::Value;
    use std::io::Cursor;
    use tokio::net::TcpStream;
    const PROJECT: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
    fn setup_json() -> Value {
        json!({"command":"start","api_audience":"broker-api","resource":"https://resource.example.test/v1","client_id":"native-client",
            "subject":"native-subject","scope":"openid fixture","redirect_uri_path":"/auth/callback","access_ttl_seconds":600,
            "instance_id":"Station._-1","projects":[{"project_id":PROJECT,"versions":["main"]}],"seed_inventory":false,
            "grant_project_ids":[PROJECT],"read_required_scopes":["fixture"],"publish_required_scopes":["fixture"],
            "token_bytes":8192,"grants_json_bytes":65536,"inventory_json_bytes":65536,"body_bytes":65536,"request_timeout_ms":3000})
    }
    fn setup() -> Setup {
        let Object(Command::Start { setup }) =
            serde_json::from_value::<Object<Command>>(setup_json()).unwrap()
        else {
            panic!("start")
        };
        *setup
    }

    type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;
    fn realtime_json(scope: &str) -> serde_json::Value {
        serde_json::json!({"heartbeat_timeout_ms":60000,"broadcast_capacity":32,
            "required_scopes":[scope],"command_bytes":65536,"outbound_bytes":65536,
            "operation_timeout_ms":30000,"task_read":true})
    }
    async fn socket(origin: &str, raw: &str) -> Socket {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut request = format!(
            "ws://{}/v1/realtime",
            origin.strip_prefix("http://").unwrap()
        )
        .into_client_request()
        .unwrap();
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {raw}").parse().unwrap(),
        );
        tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::connect_async(request),
        )
        .await
        .unwrap()
        .unwrap()
        .0
    }
    async fn send_ws(socket: &mut Socket, value: serde_json::Value) {
        use futures_util::SinkExt;
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                value.to_string().into(),
            ))
            .await
            .unwrap();
    }
    async fn receive_ws(socket: &mut Socket) -> serde_json::Value {
        use futures_util::StreamExt;
        loop {
            match tokio::time::timeout(Duration::from_secs(10), socket.next())
                .await
                .unwrap()
            {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                    return serde_json::from_str(&text).unwrap();
                }
                Some(Ok(
                    tokio_tungstenite::tungstenite::Message::Ping(_)
                    | tokio_tungstenite::tungstenite::Message::Pong(_),
                )) => {}
                _ => panic!("expected realtime DATA"),
            }
        }
    }
    fn snapshot() -> serde_json::Value {
        let section = serde_json::json!({"availability":"available","total":0,
            "items":[],"has_more":false,"error":null});
        let value = serde_json::json!({"project_id":PROJECT,"generated_at":"1000000",
            "sections":{"tasks":section,"sessions":section,"memories":section,"knowledge":section}});
        let bytes = serde_json::to_vec(&value).unwrap();
        let _ = broker_now_wire::NowSnapshotData::decode(&bytes, n(bytes.len())).unwrap();
        value
    }
    async fn publish_ws(origin: &str, raw: &str, id: &str) -> Socket {
        let mut socket = socket(origin, raw).await;
        send_ws(
            &mut socket,
            serde_json::json!({"op":"publish","instance_id":id,
            "project_id":PROJECT,"version":"main","snapshot":snapshot()}),
        )
        .await;
        assert_eq!(receive_ws(&mut socket).await["type"], "welcome");
        socket
    }
    async fn assert_socket_closed(socket: &mut Socket) {
        use futures_util::StreamExt;
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(frame) = socket.next().await {
                if frame.is_err()
                    || matches!(frame, Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
                {
                    return;
                }
            }
        })
        .await
        .unwrap();
    }
    #[test]
    fn strict_ipc_and_explicit_configuration() {
        let wire = serde_json::to_string(&setup_json()).unwrap();
        for bad in [
            "[]".to_owned(),
            "{\"command\":\"stats\",\"unknown\":1}".into(),
            wire.replace(
                "\"client_id\":\"native-client\"",
                "\"client_id\":\"native-client\",\"client_id\":\"duplicate\"",
            ),
            format!("{wire} {{}}"),
            wire.replace(
                "\"versions\":[\"main\"]",
                "\"versions\":[\"main\"],\"extra\":true",
            ),
        ] {
            assert!(read_command(&mut Cursor::new(bad)).is_err());
        }
        let fields = setup_json()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for field in fields {
            let mut missing = setup_json();
            missing.as_object_mut().unwrap().remove(&field);
            assert!(
                serde_json::from_value::<Object<Command>>(missing).is_err(),
                "missing {field}"
            );
        }
        for (field, value) in [
            ("access_ttl_seconds", json!(0)),
            ("token_bytes", json!(0)),
            ("body_bytes", json!(0)),
            ("request_timeout_ms", json!(0)),
            ("scope", json!("fixture")),
            ("redirect_uri_path", json!("/bad?x")),
            ("instance_id", json!("bad/id")),
            ("grant_project_ids", json!([PROJECT, PROJECT])),
        ] {
            let mut bad = setup_json();
            bad[field] = value;
            let Object(Command::Start { setup }) =
                serde_json::from_value::<Object<Command>>(bad).unwrap()
            else {
                panic!("start")
            };
            assert!(setup.validate().is_err(), "invalid {field}");
        }
        setup().validate().unwrap();
        let ack = serde_json::to_value(Ack {
            event: "ack",
            command: "shutdown",
            ok: true,
        })
        .unwrap();
        assert_eq!(ack, json!({"event":"ack","command":"shutdown","ok":true}));
    }
    #[tokio::test]
    async fn initial_eof_and_non_start_have_no_resources_or_output() {
        let mut output = Vec::new();
        run(&mut Cursor::new(Vec::<u8>::new()), &mut output)
            .await
            .unwrap();
        assert!(output.is_empty());
        assert!(matches!(
            run(
                &mut Cursor::new(b"{\"command\":\"shutdown\"}\n"),
                &mut output
            )
            .await,
            Err(Failure::InvalidCommand)
        ));
        assert!(output.is_empty());
    }
    async fn request(
        live: &LiveFixture,
        method: Method,
        path: &str,
        body: Value,
        bearer: bool,
    ) -> Result<(StatusCode, Value), &'static str> {
        let address = live
            .origin
            .strip_prefix("http://")
            .unwrap()
            .parse::<std::net::SocketAddr>()
            .unwrap();
        let io = TokioIo::new(TcpStream::connect(address).await.map_err(|_| "connect")?);
        let (mut sender, connection) = http1::handshake(io).await.map_err(|_| "handshake")?;
        let mut task = tokio::spawn(connection);
        let bytes = if method == Method::PUT {
            serde_json::to_vec(&body).unwrap()
        } else {
            vec![]
        };
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(format!("{}{path}", live.origin))
            .header(header::CONTENT_TYPE, "application/json");
        if bearer {
            builder = builder.header(
                header::AUTHORIZATION,
                format!("Bearer {}", live.bearer.as_str()),
            );
        }
        let result = async {
            let response = sender
                .send_request(builder.body(Full::new(Bytes::from(bytes))).unwrap())
                .await
                .map_err(|_| "delivery")?;
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            let status = response.status();
            let bytes = response
                .into_body()
                .collect()
                .await
                .map_err(|_| "delivery")?
                .to_bytes();
            let value = serde_json::from_slice(&bytes).map_err(|_| "json")?;
            Ok((status, value))
        }
        .await;
        drop(sender);
        match tokio::time::timeout(Duration::from_secs(3), &mut task).await {
            Ok(joined) => {
                let connected = joined.map_err(|_| "connection join")?;
                if result.is_ok() {
                    connected.map_err(|_| "connection")?;
                }
            }
            Err(_) => {
                task.abort();
                let _ = task.await;
                return Err("connection shutdown");
            }
        }
        result
    }
    fn inventory(version: &str) -> Value {
        json!({"projects":[{"project_id":PROJECT,"versions":[version]}]})
    }
    #[tokio::test]
    #[ignore = "real PostgreSQL TLS, Native issuer/JWK/discovery/router and causal TCP response loss"]
    async fn native_inventory_fixture_postgres_contract() {
        let mut live = LiveFixture::start(setup()).await.unwrap();
        assert!(
            !sqlx_core::query_scalar::query_scalar::<_, bool>(
                "SELECT rolsuper FROM pg_roles WHERE rolname='native_inventory_owner'"
            )
            .fetch_one(&mut live.control)
            .await
            .unwrap()
        );
        let mut ready_bytes = Vec::new();
        live.emit_ready(&mut ready_bytes).unwrap();
        let ready: Value = serde_json::from_slice(&ready_bytes).unwrap();
        assert_eq!(ready.as_object().unwrap().len(), 15);
        for key in ["endpoint", "issuer", "inventory_endpoint"] {
            assert_eq!(ready[key], live.origin);
        }
        assert_eq!(ready["expires_at"], live.expires_at);
        assert!(live.expires_at > seconds().unwrap());
        let (status, broker) = request(
            &live,
            Method::GET,
            "/.well-known/graphit-broker",
            Value::Null,
            false,
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(broker["version"], "1");
        assert_eq!(broker["issuer"], live.origin);
        assert_eq!(broker["authentication"]["client_id"], live.setup.client_id);
        assert_eq!(
            broker["authentication"]["mcp_resources"],
            json!([live.setup.resource])
        );
        let (_, oidc) = request(
            &live,
            Method::GET,
            "/.well-known/openid-configuration",
            Value::Null,
            false,
        )
        .await
        .unwrap();
        for (field, value) in [
            (
                "grant_types_supported",
                json!(["authorization_code", "refresh_token"]),
            ),
            ("code_challenge_methods_supported", json!(["S256"])),
            ("token_endpoint_auth_methods_supported", json!(["none"])),
            ("id_token_signing_alg_values_supported", json!(["EdDSA"])),
        ] {
            assert_eq!(oidc[field], value);
        }
        assert_eq!(oidc["jwks_uri"], format!("{}/jwks", live.origin));
        let (_, keys) = request(&live, Method::GET, "/jwks", Value::Null, false)
            .await
            .unwrap();
        let keys = serde_json::from_value(keys).unwrap();
        let trusted = BrokerAccessVerifier::new(
            &live.origin,
            &live.setup.api_audience,
            Some(&live.setup.resource),
            &keys,
            n(8192),
        )
        .unwrap();
        let principal = trusted
            .verify(&live.bearer, &live.setup.read_required_scopes, deadline())
            .unwrap();
        assert_eq!(principal.subject(), live.setup.subject);
        let path = format!("/v1/instances/{}/inventory", live.setup.instance_id);
        assert_eq!(
            request(&live, Method::GET, &path, Value::Null, true)
                .await
                .unwrap()
                .0,
            StatusCode::NOT_FOUND
        );
        let created = request(&live, Method::PUT, &path, inventory("main"), true)
            .await
            .unwrap();
        assert_eq!(created.0, StatusCode::CREATED);
        assert_eq!(created.1["change"], "created");
        assert!(created.1["created_at"].as_i64().unwrap() > 0);
        assert_eq!(created.1["created_at"], created.1["updated_at"]);
        let read = request(&live, Method::GET, &path, Value::Null, true)
            .await
            .unwrap();
        assert_eq!(read.0, StatusCode::OK);
        assert_eq!(read.1["projects"], inventory("main")["projects"]);
        let update = request(&live, Method::PUT, &path, inventory("branch"), true)
            .await
            .unwrap();
        assert_eq!(update.0, StatusCode::OK);
        assert_eq!(update.1["change"], "updated");
        let unchanged = request(&live, Method::PUT, &path, inventory("branch"), true)
            .await
            .unwrap();
        assert_eq!(unchanged.1["change"], "unchanged");
        assert_eq!(unchanged.1["created_at"], update.1["created_at"]);
        assert_eq!(unchanged.1["updated_at"], update.1["updated_at"]);
        live.command(&Command::DenyRead {}).await.unwrap();
        assert_eq!(
            request(&live, Method::GET, &path, Value::Null, true)
                .await
                .unwrap()
                .0,
            StatusCode::FORBIDDEN
        );
        live.command(&Command::AllowRead {}).await.unwrap();
        assert_eq!(
            request(&live, Method::GET, &path, Value::Null, true)
                .await
                .unwrap()
                .0,
            StatusCode::OK
        );
        live.command(&Command::DenyPublish {}).await.unwrap();
        assert_eq!(
            request(&live, Method::PUT, &path, inventory("denied"), true)
                .await
                .unwrap()
                .0,
            StatusCode::FORBIDDEN
        );
        live.command(&Command::AllowPublish {}).await.unwrap();
        live.command(&Command::LoseNextSuccessfulPutResponse {})
            .await
            .unwrap();
        assert!(
            request(
                &live,
                Method::PUT,
                &path,
                inventory("committed-before-loss"),
                true
            )
            .await
            .is_err()
        );
        let recovered = request(&live, Method::GET, &path, Value::Null, true)
            .await
            .unwrap();
        assert_eq!(
            recovered.1["projects"],
            inventory("committed-before-loss")["projects"]
        );
        assert_eq!(live.counters.stats().put_response_losses, 1);
        assert_eq!(
            request(
                &live,
                Method::PUT,
                &path,
                inventory("normal-after-loss"),
                true
            )
            .await
            .unwrap()
            .0,
            StatusCode::OK
        );
        live.command(&Command::ReplaceWithForeignOwner {
            subject: "foreign-subject".into(),
        })
        .await
        .unwrap();
        assert_eq!(
            request(&live, Method::PUT, &path, inventory("foreign"), true)
                .await
                .unwrap()
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(&live, Method::GET, &path, Value::Null, true)
                .await
                .unwrap()
                .0,
            StatusCode::CONFLICT
        );
        live.command(&Command::DeleteInventory {}).await.unwrap();
        assert_eq!(
            request(&live, Method::GET, &path, Value::Null, true)
                .await
                .unwrap()
                .0,
            StatusCode::NOT_FOUND
        );
        let stats = live.counters.stats();
        assert_eq!(
            (
                stats.broker_metadata_requests,
                stats.oidc_metadata_requests,
                stats.jwks_requests
            ),
            (1, 1, 1)
        );
        assert_eq!((stats.token_requests, stats.userinfo_requests), (0, 0));
        // Reproduce post-setup expiry with a real short-lived token from the
        // same issuer. Ready's real verifier rejects it without writing bytes.
        live.setup.access_ttl_seconds = 1;
        let (short, exp) = signed(&live.issuer, &live.setup, &live.setup.subject).unwrap();
        live.bearer = zeroize::Zeroizing::new(short);
        live.expires_at = exp;
        tokio::time::timeout(Duration::from_secs(3), async {
            while seconds().unwrap() < exp {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let mut rejected_ready = Vec::new();
        assert!(matches!(
            live.emit_ready(&mut rejected_ready),
            Err(Failure::Setup)
        ));
        assert!(rejected_ready.is_empty());
        let address = live
            .origin
            .strip_prefix("http://")
            .unwrap()
            .parse::<std::net::SocketAddr>()
            .unwrap();
        live.shutdown().await.unwrap();
        assert!(TcpStream::connect(address).await.is_err());
        // Exercise the actual JSON-lines driver: Ack exists only after cleanup.
        let mut input = Cursor::new(format!(
            "{}\n{{\"command\":\"stats\"}}\n{{\"command\":\"shutdown\"}}\n",
            setup_json()
        ));
        let mut output = Vec::new();
        run(&mut input, &mut output).await.unwrap();
        let lines = output
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice::<Value>(l).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[2],
            json!({"event":"ack","command":"shutdown","ok":true})
        );
        let address = lines[0]["endpoint"]
            .as_str()
            .unwrap()
            .strip_prefix("http://")
            .unwrap()
            .parse::<std::net::SocketAddr>()
            .unwrap();
        assert!(TcpStream::connect(address).await.is_err());
        // EOF and malformed control after Ready clean up the actual resources.
        for (tail, invalid) in [("", false), ("{\"command\":\"unknown\"}\n", true)] {
            let mut input = Cursor::new(format!("{}\n{tail}", setup_json()));
            let mut output = Vec::new();
            let result = run(&mut input, &mut output).await;
            if invalid {
                assert!(matches!(result, Err(Failure::InvalidCommand)));
            } else {
                result.unwrap();
            }
            let lines = output
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_slice::<Value>(l).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0]["event"], "ready");
            let address = lines[0]["endpoint"]
                .as_str()
                .unwrap()
                .strip_prefix("http://")
                .unwrap()
                .parse::<std::net::SocketAddr>()
                .unwrap();
            assert!(TcpStream::connect(address).await.is_err());
        }
    }
    #[tokio::test]
    #[ignore = "real PostgreSQL TLS, Native Inventory and realtime sockets"]
    async fn realtime_fixture_postgres_tcp_contract() {
        let mut config = setup();
        config.realtime = Some(
            serde_json::from_value::<Object<RealtimeSettings>>(realtime_json("fixture")).unwrap(),
        );
        let live = LiveFixture::start(config).await.unwrap();
        let pg = live.postgres.port;
        let body = serde_json::json!({"projects":[{"project_id":PROJECT,"versions":["main"]}]});
        for id in ["Station._-1", "runtime-second"] {
            assert_eq!(
                request(
                    &live,
                    Method::PUT,
                    &format!("/v1/instances/{id}/inventory"),
                    body.clone(),
                    true
                )
                .await
                .unwrap()
                .0,
                StatusCode::CREATED
            );
        }
        let mut first = publish_ws(&live.origin, &live.bearer, "Station._-1").await;
        let mut second = publish_ws(&live.origin, &live.bearer, "runtime-second").await;
        let mut sub = socket(&live.origin, &live.bearer).await;
        send_ws(
            &mut sub,
            serde_json::json!({"op":"subscribe","project_id":PROJECT}),
        )
        .await;
        assert_eq!(receive_ws(&mut sub).await["type"], "welcome");
        let view = receive_ws(&mut sub).await;
        assert_eq!(view["instances"].as_array().unwrap().len(), 2);
        for instance in view["instances"].as_array().unwrap() {
            assert_eq!(
                instance["now"]["sections"]["tasks"]["availability"],
                "available"
            );
            assert_ne!(
                instance["now"]["sections"]["knowledge"]["availability"],
                "available"
            );
        }
        let address = live
            .origin
            .strip_prefix("http://")
            .unwrap()
            .parse::<std::net::SocketAddr>()
            .unwrap();
        live.shutdown().await.unwrap();
        assert_socket_closed(&mut sub).await;
        assert_socket_closed(&mut first).await;
        assert_socket_closed(&mut second).await;
        assert!(TcpStream::connect(address).await.is_err());
        assert!(TcpStream::connect(("127.0.0.1", pg)).await.is_err());
    }

    #[tokio::test]
    async fn realtime_configuration_rejects_invalid_before_setup() {
        let mut value = setup_json();
        value["realtime"] = realtime_json("presence:read");
        for field in [
            "heartbeat_timeout_ms",
            "broadcast_capacity",
            "required_scopes",
            "command_bytes",
            "outbound_bytes",
            "operation_timeout_ms",
            "task_read",
        ] {
            let mut missing = value.clone();
            missing["realtime"].as_object_mut().unwrap().remove(field);
            assert!(read_command(&mut Cursor::new(missing.to_string())).is_err());
        }
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            let mut bad = value.clone();
            bad["realtime"] = invalid;
            assert!(read_command(&mut Cursor::new(bad.to_string())).is_err());
        }
        for (field, invalid) in [
            ("heartbeat_timeout_ms", serde_json::json!(0)),
            ("broadcast_capacity", serde_json::json!(0)),
            ("broadcast_capacity", serde_json::json!(usize::MAX)),
            ("command_bytes", serde_json::json!(0)),
            ("outbound_bytes", serde_json::json!(usize::MAX)),
            ("operation_timeout_ms", serde_json::json!(0)),
            ("required_scopes", serde_json::json!(["bad scope"])),
        ] {
            let mut bad = value.clone();
            bad["realtime"][field] = invalid;
            let mut output = Vec::new();
            assert!(matches!(
                run(&mut Cursor::new(bad.to_string()), &mut output).await,
                Err(Failure::InvalidCommand)
            ));
            assert!(output.is_empty());
        }
        let mut unknown = value;
        unknown["realtime"]["unknown"] = serde_json::json!(true);
        assert!(read_command(&mut Cursor::new(unknown.to_string())).is_err());
    }
}
