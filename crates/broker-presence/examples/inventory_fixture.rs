//! Public, synthetic Inventory fixture for the real Runtime HTTP consumer.
#[allow(
    dead_code,
    reason = "Shared test support also serves other active PostgreSQL suites."
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;

use broker_control::{
    ConnectionLimits, InstanceInventory, InstanceOwner, InstanceProjectVersions, PostgresConfig,
    PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use broker_presence::{
    InstanceInventoryListHttpConfig, InstanceInventoryReadHttpConfig, InstanceRegistryHttpConfig,
    LocalRealtimeHttpConfig, RealtimeHttpConfig, RealtimeHub, RealtimeServerRuntime,
    instance_inventory_router, local_realtime_router,
};
use broker_security::TokenKind;
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    io::{BufRead, Write},
    net::SocketAddr,
    num::NonZeroU16,
    panic::AssertUnwindSafe,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

const AUDIENCE: &str = "inventory-fixture";
const READ_SCOPE: &str = "presence:read";
const PUBLISH_SCOPE: &str = "presence:publish";
const USERNAME: &str = "inventory-reader";
const SUBJECT: &str = "inventory-human";
const SERVICE_USERNAME: &str = "inventory-service";
const SERVICE_SUBJECT: &str = "inventory-service-subject";
const ACCESS: &str = "gb_at_inventory-fixture";
const SERVICE: &str = "gb_sc_inventory-fixture";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Serialize)]
struct Project {
    project_id: String,
    versions: Vec<String>,
}

/// Accept JSON objects through the Serde SDK; positional sequences cannot substitute for IPC maps.
struct Object<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an IPC object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<Self::Value, A::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectFields {
    project_id: String,
    versions: Vec<String>,
}
impl<'de> Deserialize<'de> for Project {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let Object(fields) = Object::<ProjectFields>::deserialize(deserializer)?;
        Ok(Self {
            project_id: fields.project_id,
            versions: fields.versions,
        })
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
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Start {
        instance_id: String,
        projects: Vec<Project>,
        #[serde(default, deserialize_with = "optional_realtime")]
        realtime: Option<Object<RealtimeSettings>>,
    },
    DenyRead {},
    AllowRead {},
    RevokeAccess {},
    RestoreAccess {},
    DeleteInventory {},
    Shutdown {},
}
impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Start { .. } => "start",
            Self::DenyRead {} => "deny_read",
            Self::AllowRead {} => "allow_read",
            Self::RevokeAccess {} => "revoke_access",
            Self::RestoreAccess {} => "restore_access",
            Self::DeleteInventory {} => "delete_inventory",
            Self::Shutdown {} => "shutdown",
        }
    }
    fn into_inventory(self) -> Result<InstanceInventory, Failure> {
        let Self::Start {
            instance_id,
            projects,
            ..
        } = self
        else {
            return Err(Failure::InvalidCommand);
        };
        let projects = projects
            .into_iter()
            .map(|p| {
                InstanceProjectVersions::new(p.project_id, p.versions)
                    .map_err(|_| Failure::InvalidCommand)
            })
            .collect::<Result<Vec<_>, _>>()?;
        InstanceInventory::new(instance_id, projects).map_err(|_| Failure::InvalidCommand)
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
    Shutdown {},
}
impl Failure {
    fn message(&self) -> &'static str {
        match self {
            Self::InvalidCommand => "invalid inventory fixture command",
            Self::Input => "inventory fixture input failed",
            Self::Output => "inventory fixture output failed",
            Self::Setup => "inventory fixture setup failed",
            Self::Storage => "inventory fixture SQL operation failed",
            Self::Server => "inventory fixture HTTP server failed",
            Self::Shutdown {} => "inventory fixture shutdown failed",
        }
    }
}
fn read_command(input: &mut impl BufRead) -> Result<Option<Command>, Failure> {
    let mut line = String::new();
    if input.read_line(&mut line).map_err(|_| Failure::Input)? == 0 {
        return Ok(None);
    }
    serde_json::from_str::<Object<Command>>(&line)
        .map(|Object(command)| Some(command))
        .map_err(|_| Failure::InvalidCommand)
}
fn emit(output: &mut impl Write, event: &impl Serialize) -> Result<(), Failure> {
    serde_json::to_writer(&mut *output, event).map_err(|_| Failure::Output)?;
    output.write_all(b"\n").map_err(|_| Failure::Output)?;
    output.flush().map_err(|_| Failure::Output)
}
fn now() -> Result<i64, Failure> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::Setup)?
        .as_micros();
    i64::try_from(micros).map_err(|_| Failure::Setup)
}
fn config(f: &Fixture) -> Result<PostgresConfig, Failure> {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).ok_or(Failure::Setup)?,
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "inventory_owner".into(),
            zeroize::Zeroizing::new("fixture-owner".into()),
        ),
        f.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .map_err(|_| Failure::Setup)
}
fn router(store: Arc<PostgresControlStore>) -> Result<axum::Router, Failure> {
    instance_inventory_router(
        store,
        InstanceRegistryHttpConfig {
            audience: AUDIENCE.into(),
            required_scopes: vec![PUBLISH_SCOPE.into()],
            identity_json_bytes: n(4096),
            grants_json_bytes: n(16384),
            body_bytes: n(16384),
            request_timeout: REQUEST_TIMEOUT,
        },
        InstanceInventoryReadHttpConfig {
            audience: AUDIENCE.into(),
            required_scopes: vec![READ_SCOPE.into()],
            identity_json_bytes: n(4096),
            grants_json_bytes: n(16384),
            inventory_json_bytes: n(16384),
            request_timeout: REQUEST_TIMEOUT,
        },
        InstanceInventoryListHttpConfig {
            audience: AUDIENCE.into(),
            required_scopes: vec![READ_SCOPE.into()],
            identity_json_bytes: n(4096),
            grants_json_bytes: n(16384),
            inventory_json_bytes: n(16384),
            query_bytes: n(1024),
            request_timeout: REQUEST_TIMEOUT,
        },
    )
    .map_err(|_| Failure::Setup)
}
#[derive(Serialize)]
struct Ready<'a> {
    event: &'static str,
    endpoint: String,
    instance_id: &'a str,
    projects: Vec<Project>,
    audience: &'static str,
    read_scopes: [&'static str; 1],
    publish_scopes: [&'static str; 1],
    access_bearer: &'static str,
    service_bearer: &'static str,
    subject: &'static str,
    username: &'static str,
    service_subject: &'static str,
    service_username: &'static str,
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
    inventory: InstanceInventory,
    realtime: Option<RealtimeServerRuntime>,
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    server: JoinHandle<Result<(), std::io::Error>>,
}
impl LiveFixture {
    async fn start(
        inventory: InstanceInventory,
        settings: Option<RealtimeSettings>,
    ) -> Result<Self, Failure> {
        if let Some(settings) = &settings {
            settings.validate()?;
        }
        let postgres = Fixture::new(true).await;
        let mut control = postgres.connection().await;
        control.execute("CREATE ROLE inventory_owner LOGIN NOSUPERUSER PASSWORD 'fixture-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION inventory_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO inventory_owner")
            .await.map_err(|_| Failure::Setup)?;
        let store = Arc::new(
            PostgresControlStore::open(config(&postgres)?, support::digester(), deadline())
                .await
                .map_err(|_| Failure::Setup)?,
        );
        let superuser: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT rolsuper FROM pg_roles WHERE rolname='inventory_owner'",
        )
        .fetch_one(&mut control)
        .await
        .map_err(|_| Failure::Setup)?;
        if superuser {
            return Err(Failure::Setup);
        }
        control.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('inventory-reader','inventory-human','human','','Fixture human','','','[]',1,0,1,0,0),('inventory-service','inventory-service-subject','service','','Fixture service','','','[]',1,0,1,0,0)")
            .await.map_err(|_| Failure::Setup)?;
        let expiry = now()?.checked_add(3_600_000_000).ok_or(Failure::Setup)?;
        let scopes =
            serde_json::to_string(&[READ_SCOPE, PUBLISH_SCOPE]).map_err(|_| Failure::Setup)?;
        for (raw, kind, token_id, sql_kind, subject, username) in [
            (
                ACCESS,
                TokenKind::LocalAccess,
                "fixture-access",
                "access",
                SUBJECT,
                USERNAME,
            ),
            (
                SERVICE,
                TokenKind::ServiceCredential,
                "fixture-service",
                "service",
                SERVICE_SUBJECT,
                SERVICE_USERNAME,
            ),
        ] {
            let digest = support::digester()
                .token(kind, raw.as_bytes())
                .map_err(|_| Failure::Setup)?;
            let principal = serde_json::json!({
                "issuer":"local", "subject":subject, "username":username,
                "auth_method": if sql_kind == "access" { "local-token" } else { "service-credential" },
                "local_user_revision":1,
            }).to_string();
            sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'fixture-envelope',$5,'fixture-client',$6,'',$7,1,'',0,$8,0)")
                .bind(digest.to_sql_hex()).bind(token_id).bind(sql_kind).bind(subject)
                .bind(principal).bind(AUDIENCE).bind(&scopes).bind(expiry)
                .execute(&mut control).await.map_err(|_| Failure::Setup)?;
        }
        for (id, username) in [
            ("fixture-human", USERNAME),
            ("fixture-service", SERVICE_USERNAME),
        ] {
            sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'Inventory fixture','user',$2,'',0,0)")
                .bind(id).bind(username).execute(&mut control).await.map_err(|_| Failure::Setup)?;
            for cap in [READ_SCOPE, PUBLISH_SCOPE] {
                sqlx_core::query::query(
                    "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
                )
                .bind(id)
                .bind(cap)
                .execute(&mut control)
                .await
                .map_err(|_| Failure::Setup)?;
            }
        }
        if settings.as_ref().is_some_and(|s| s.task_read) && !inventory.projects().is_empty() {
            for (id, username) in [
                ("fixture-task-human", USERNAME),
                ("fixture-task-service", SERVICE_USERNAME),
            ] {
                sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'Task fixture','user',$2,'',0,0)")
                    .bind(id).bind(username).execute(&mut control).await.map_err(|_| Failure::Setup)?;
                sqlx_core::query::query(
                    "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,'task:read')",
                )
                .bind(id)
                .execute(&mut control)
                .await
                .map_err(|_| Failure::Setup)?;
                for project in inventory.projects() {
                    sqlx_core::query::query(
                        "INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)",
                    )
                    .bind(id)
                    .bind(project.project_id())
                    .execute(&mut control)
                    .await
                    .map_err(|_| Failure::Setup)?;
                }
            }
        }
        let owner = InstanceOwner::new("local", SUBJECT).map_err(|_| Failure::Setup)?;
        store
            .replace_instance_inventory(&owner, &inventory, deadline())
            .await
            .map_err(|_| Failure::Setup)?;
        let mut app = router(store.clone())?;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| Failure::Server)?;
        let address = listener.local_addr().map_err(|_| Failure::Server)?;
        let mut realtime = settings
            .as_ref()
            .map(RealtimeSettings::prepare)
            .transpose()?;
        if let (Some(settings), Some(runtime)) = (&settings, &realtime) {
            match local_realtime_router(
                store.clone(),
                LocalRealtimeHttpConfig {
                    audience: AUDIENCE.into(),
                    identity_json_bytes: n(4096),
                    realtime: settings.http(n(16384), n(16384)),
                },
                runtime,
            ) {
                Ok(ws) => app = app.reset_fallback().merge(ws),
                Err(_) => {
                    if let Some(runtime) = realtime.take() {
                        let _ = runtime.shutdown().await;
                    }
                    return Err(Failure::InvalidCommand);
                }
            }
        }
        let (stop, rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
        });
        Ok(Self {
            postgres,
            control,
            store,
            inventory,
            realtime,
            address,
            stop,
            server,
        })
    }
    fn ready(&self) -> Ready<'_> {
        Ready {
            event: "ready",
            endpoint: format!("http://{}", self.address),
            instance_id: self.inventory.instance_id(),
            projects: self
                .inventory
                .projects()
                .iter()
                .map(|p| Project {
                    project_id: p.project_id().into(),
                    versions: p.versions().to_vec(),
                })
                .collect(),
            audience: AUDIENCE,
            read_scopes: [READ_SCOPE],
            publish_scopes: [PUBLISH_SCOPE],
            access_bearer: ACCESS,
            service_bearer: SERVICE,
            subject: SUBJECT,
            username: USERNAME,
            service_subject: SERVICE_SUBJECT,
            service_username: SERVICE_USERNAME,
        }
    }
    async fn command(&mut self, command: &Command) -> Result<(), Failure> {
        match command {
            Command::Start { .. } => return Err(Failure::InvalidCommand),
            Command::DenyRead {} | Command::AllowRead {} => {
                let mut tx = self.control.begin().await.map_err(|_| Failure::Storage)?;
                sqlx_core::query::query("DELETE FROM public.grant_capabilities WHERE grant_id IN ('fixture-human','fixture-service') AND value=$1")
                    .bind(READ_SCOPE).execute(&mut *tx).await.map_err(|_| Failure::Storage)?;
                if matches!(command, Command::AllowRead {}) {
                    sqlx_core::query::query("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('fixture-human',$1),('fixture-service',$1)")
                        .bind(READ_SCOPE).execute(&mut *tx).await.map_err(|_| Failure::Storage)?;
                }
                sqlx_core::query::query("UPDATE public.resource_acl_state SET revision=revision+1,updated_at=$1 WHERE id=1")
                    .bind(now()?).execute(&mut *tx).await.map_err(|_| Failure::Storage)?;
                tx.commit().await.map_err(|_| Failure::Storage)?;
            }
            Command::RevokeAccess {} | Command::RestoreAccess {} => {
                let revoked = if matches!(command, Command::RevokeAccess {}) {
                    Some(now()?)
                } else {
                    None
                };
                sqlx_core::query::query(
                    "UPDATE public.local_tokens SET revoked_at=$1 WHERE token_id='fixture-access'",
                )
                .bind(revoked)
                .execute(&mut self.control)
                .await
                .map_err(|_| Failure::Storage)?;
            }
            Command::DeleteInventory {} => {
                let mut tx = self.control.begin().await.map_err(|_| Failure::Storage)?;
                sqlx_core::query::query(
                    "DELETE FROM public.broker_instance_project_versions WHERE instance_id=$1",
                )
                .bind(self.inventory.instance_id())
                .execute(&mut *tx)
                .await
                .map_err(|_| Failure::Storage)?;
                sqlx_core::query::query("DELETE FROM public.broker_instances WHERE instance_id=$1")
                    .bind(self.inventory.instance_id())
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| Failure::Storage)?;
                tx.commit().await.map_err(|_| Failure::Storage)?;
            }
            Command::Shutdown {} => {}
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
        let realtime_result = match realtime {
            Some(runtime) => runtime.shutdown().await.map_err(|_| Failure::Shutdown {}),
            None => Ok(()),
        };
        let server_result = match tokio::time::timeout(Duration::from_secs(3), &mut server).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(_) => Err(Failure::Shutdown {}),
            Err(_) => {
                server.abort();
                let _ = server.await;
                Err(Failure::Shutdown {})
            }
        };
        let store_result = store
            .shutdown(deadline())
            .await
            .map_err(|_| Failure::Shutdown {});
        let control_result = control.close().await.map_err(|_| Failure::Shutdown {});
        drop(store);
        let postgres_result = postgres.shutdown().map_err(|_| Failure::Shutdown {});
        server_result
            .and(realtime_result)
            .and(store_result)
            .and(control_result)
            .and(postgres_result)
    }
}
async fn run(input: &mut impl BufRead, output: &mut impl Write) -> Result<(), Failure> {
    let Some(mut start) = read_command(input)? else {
        return Ok(());
    };
    let settings = match &mut start {
        Command::Start { realtime, .. } => realtime.take().map(|Object(s)| s),
        _ => return Err(Failure::InvalidCommand),
    };
    let mut fixture = LiveFixture::start(start.into_inventory()?, settings).await?;
    let mut requested_shutdown = false;
    let result = async {
        emit(output, &fixture.ready())?;
        while let Some(command) = read_command(input)? {
            fixture.command(&command).await?;
            if matches!(command, Command::Shutdown {}) {
                requested_shutdown = true;
                break;
            }
            emit(
                output,
                &Ack {
                    event: "ack",
                    command: command.name(),
                    ok: true,
                },
            )?;
        }
        Ok(())
    }
    .await;
    let stopped = fixture.shutdown().await;
    result.and(stopped)?;
    if requested_shutdown {
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
    // Shared fixture helpers can panic on Docker/startup faults. Never expose their debug data.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("inventory fixture internal failure")
    }));
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    match AssertUnwindSafe(run(&mut input, &mut output))
        .catch_unwind()
        .await
    {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        Ok(Err(error)) => {
            eprintln!("{}", error.message());
            std::process::ExitCode::FAILURE
        }
        Err(_) => std::process::ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use hyper_util::rt::TokioIo;
    use std::io::Cursor;
    use tokio::net::TcpStream;

    const PROJECT: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
    fn start() -> Command {
        Command::Start {
            instance_id: "runtime-captured".into(),
            realtime: None,
            projects: vec![Project {
                project_id: PROJECT.into(),
                versions: vec!["release".into(), "main".into()],
            }],
        }
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
    fn snapshot(project: &str) -> serde_json::Value {
        let section = serde_json::json!({"availability":"available","total":0,
            "items":[],"has_more":false,"error":null});
        let value = serde_json::json!({"project_id":project,"generated_at":"1000000",
            "sections":{"tasks":section,"sessions":section,"memories":section,"knowledge":section}});
        let bytes = serde_json::to_vec(&value).unwrap();
        let _ = broker_now_wire::NowSnapshotData::decode(&bytes, n(bytes.len())).unwrap();
        value
    }
    async fn publish_ws(origin: &str, raw: &str, id: &str, project: &str) -> Socket {
        let mut socket = socket(origin, raw).await;
        send_ws(
            &mut socket,
            serde_json::json!({"op":"publish","instance_id":id,
            "project_id":project,"version":"main","snapshot":snapshot(project)}),
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
    fn start_codec_validates_native_inventory_and_exact_fields() {
        let valid = format!(
            r#"{{"command":"start","instance_id":"captured","projects":[{{"project_id":"{PROJECT}","versions":["release","main"]}}]}}"#
        );
        let inventory = read_command(&mut Cursor::new(valid))
            .unwrap()
            .unwrap()
            .into_inventory()
            .unwrap();
        assert_eq!(inventory.instance_id(), "captured");
        assert_eq!(inventory.projects()[0].versions(), ["main", "release"]);
        let empty = r#"{"command":"start","instance_id":"empty","projects":[]}"#;
        assert!(
            read_command(&mut Cursor::new(empty))
                .unwrap()
                .unwrap()
                .into_inventory()
                .unwrap()
                .projects()
                .is_empty()
        );
        for invalid in [
            r#"{"command":"start","instance_id":"a","instance_id":"b","projects":[]}"#,
            r#"{"command":"start","command":"start","instance_id":"a","projects":[]}"#,
            r#"{"command":"start","instance_id":"a","projects":[],"extra":1}"#,
            r#"{"command":"start","projects":[]}"#,
            r#"{"command":"start","instance_id":"a","projects":null}"#,
            r#"{"command":"start","instance_id":"a","projects":[["01D39ZY06FGSCTVN4T2V9PKHFZ",["main"]]]}"#,
            r#"{"command":"start","instance_id":1,"projects":[]}"#,
            r#"{"command":"start","instance_id":"a","projects":[]} {}"#,
            r#"{"command":"start","instance_id":"a","projects":[{"project_id":"x","versions":[],"extra":1}]}"#,
            r#"{"command":"start","instance_id":"a","projects":[{"project_id":"x","versions":["a"],"versions":["b"]}]}"#,
            r#"{"command":"start","instance_id":"a","projects":[{"project_id":"x","versions":[1]}]}"#,
        ] {
            assert!(
                read_command(&mut Cursor::new(invalid)).is_err(),
                "invalid Start accepted"
            );
        }
        for invalid in [
            r#"{"command":"start","instance_id":"bad/id","projects":[]}"#,
            r#"{"command":"start","instance_id":"a","projects":[{"project_id":"bad","versions":["main"]}]}"#,
        ] {
            assert!(
                read_command(&mut Cursor::new(invalid))
                    .unwrap()
                    .unwrap()
                    .into_inventory()
                    .is_err()
            );
        }
    }
    #[test]
    fn finite_commands_reject_extra_and_duplicate_fields() {
        for name in [
            "deny_read",
            "allow_read",
            "revoke_access",
            "restore_access",
            "delete_inventory",
            "shutdown",
        ] {
            let value = format!(r#"{{"command":"{name}"}}"#);
            assert_eq!(
                read_command(&mut Cursor::new(value))
                    .unwrap()
                    .unwrap()
                    .name(),
                name
            );
            let extra = format!(r#"{{"command":"{name}","extra":true}}"#);
            assert!(
                read_command(&mut Cursor::new(extra)).is_err(),
                "extra command field accepted"
            );
        }
        for invalid in [
            r#"{"command":"unknown"}"#,
            r#"{"command":"shutdown","command":"deny_read"}"#,
            r#"[]"#,
            r#"["shutdown"]"#,
            r#"["start","id",[]]"#,
            "null",
            "",
        ] {
            let result = read_command(&mut Cursor::new(invalid));
            if invalid.is_empty() {
                assert!(result.unwrap().is_none());
            } else {
                assert!(result.is_err());
            }
        }
    }
    #[tokio::test]
    async fn eof_before_start_has_no_output_or_fixture() {
        let mut output = Vec::new();
        run(&mut Cursor::new(""), &mut output).await.unwrap();
        assert!(output.is_empty());
        assert!(
            run(&mut Cursor::new(r#"{"command":"shutdown"}"#), &mut output)
                .await
                .is_err()
        );
        assert!(output.is_empty());
    }
    async fn exchange(
        address: SocketAddr,
        method: &str,
        path: &str,
        bearer: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value, bool) {
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let worker = tokio::spawn(connection);
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::from(body.to_owned()))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(6), sender.send_request(request))
            .await
            .unwrap()
            .unwrap();
        let status = response.status();
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .is_some_and(|v| v == "Bearer");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap();
        drop(sender);
        worker.await.unwrap().unwrap();
        (status, json, challenge)
    }
    async fn own(f: &LiveFixture, bearer: &str) -> (StatusCode, serde_json::Value, bool) {
        exchange(
            f.address,
            "GET",
            "/v1/instances/runtime-captured/inventory",
            bearer,
            "",
        )
        .await
    }
    #[tokio::test]
    #[ignore = "real PostgreSQL TLS and native Inventory HTTP fixture"]
    async fn inventory_fixture_postgres_tcp_contract() {
        let mut f = LiveFixture::start(start().into_inventory().unwrap(), None)
            .await
            .unwrap();
        let address = f.address;
        let postgres_port = f.postgres.port;
        let ready = f.ready();
        assert_eq!(ready.instance_id, "runtime-captured");
        assert_eq!(ready.projects[0].project_id, PROJECT);
        assert_eq!(ready.projects[0].versions, ["main", "release"]);
        let (status, value, _) = own(&f, ACCESS).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["instance_id"], "runtime-captured");
        assert_eq!(value["projects"][0]["project_id"], PROJECT);
        assert_eq!(
            value["projects"][0]["versions"],
            serde_json::json!(["main", "release"])
        );
        for key in ["created_at", "updated_at"] {
            assert!(value[key].as_i64().unwrap() >= 0);
        }
        assert_eq!(own(&f, SERVICE).await.0, StatusCode::CONFLICT);
        let list = exchange(address, "GET", "/v1/instances", SERVICE, "").await;
        assert_eq!(list.0, StatusCode::OK);
        assert_eq!(list.1["items"][0]["instance_id"], "runtime-captured");
        let body = format!(r#"{{"projects":[{{"project_id":"{PROJECT}","versions":["next"]}}]}}"#);
        assert_eq!(
            exchange(
                address,
                "PUT",
                "/v1/instances/runtime-captured/inventory",
                ACCESS,
                &body
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            own(&f, ACCESS).await.1["projects"][0]["versions"],
            serde_json::json!(["next"])
        );
        assert_eq!(
            exchange(
                address,
                "PUT",
                "/v1/instances/runtime-captured/inventory",
                SERVICE,
                &body
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        f.command(&Command::DenyRead {}).await.unwrap();
        assert_eq!(own(&f, ACCESS).await.0, StatusCode::FORBIDDEN);
        let revision: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT revision FROM public.resource_acl_state WHERE id=1",
        )
        .fetch_one(&mut f.control)
        .await
        .unwrap();
        f.command(&Command::AllowRead {}).await.unwrap();
        let restored: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT revision FROM public.resource_acl_state WHERE id=1",
        )
        .fetch_one(&mut f.control)
        .await
        .unwrap();
        assert_eq!(restored, revision + 1);
        assert_eq!(own(&f, ACCESS).await.0, StatusCode::OK);
        f.command(&Command::RevokeAccess {}).await.unwrap();
        let denied = own(&f, ACCESS).await;
        assert_eq!(denied.0, StatusCode::UNAUTHORIZED);
        assert!(denied.2);
        assert_eq!(
            exchange(address, "GET", "/v1/instances", SERVICE, "")
                .await
                .0,
            StatusCode::OK
        );
        f.command(&Command::RestoreAccess {}).await.unwrap();
        assert_eq!(own(&f, ACCESS).await.0, StatusCode::OK);
        f.command(&Command::DeleteInventory {}).await.unwrap();
        assert_eq!(own(&f, ACCESS).await.0, StatusCode::NOT_FOUND);
        assert_eq!(
            exchange(
                address,
                "PUT",
                "/v1/instances/runtime-captured/inventory",
                ACCESS,
                &body
            )
            .await
            .0,
            StatusCode::CREATED
        );
        assert_eq!(own(&f, ACCESS).await.0, StatusCode::OK);
        assert!(f.command(&start()).await.is_err());
        f.command(&Command::Shutdown {}).await.unwrap();
        f.shutdown().await.unwrap();
        assert!(TcpStream::connect(address).await.is_err());
        assert!(
            TcpStream::connect(("127.0.0.1", postgres_port))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    #[ignore = "real PostgreSQL TLS, public Inventory and realtime sockets"]
    async fn realtime_fixture_postgres_tcp_contract() {
        let settings =
            serde_json::from_value::<Object<RealtimeSettings>>(realtime_json(READ_SCOPE))
                .unwrap()
                .0;
        let f = LiveFixture::start(start().into_inventory().unwrap(), Some(settings))
            .await
            .unwrap();
        let address = f.address;
        let pg = f.postgres.port;
        let origin = format!("http://{address}");
        let body = serde_json::json!({"projects":[{"project_id":PROJECT,"versions":["main"]}]})
            .to_string();
        assert_eq!(
            exchange(
                address,
                "PUT",
                "/v1/instances/runtime-second/inventory",
                ACCESS,
                &body
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let mut first = publish_ws(&origin, ACCESS, "runtime-captured", PROJECT).await;
        let mut second = publish_ws(&origin, ACCESS, "runtime-second", PROJECT).await;
        let mut sub = socket(&origin, ACCESS).await;
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
                instance["now"]["sections"]["memories"]["availability"],
                "available"
            );
        }
        // Presence Any does not promote Task read outside Start.projects.
        let outside = "01D39ZY06FGSCTVN4T2V9PKHG0";
        let body = serde_json::json!({"projects":[{"project_id":outside,"versions":["main"]}]})
            .to_string();
        assert_eq!(
            exchange(
                address,
                "PUT",
                "/v1/instances/runtime-outside/inventory",
                ACCESS,
                &body
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let mut outsider = publish_ws(&origin, ACCESS, "runtime-outside", outside).await;
        let mut outside_sub = socket(&origin, ACCESS).await;
        send_ws(
            &mut outside_sub,
            serde_json::json!({"op":"subscribe","project_id":outside}),
        )
        .await;
        assert_eq!(receive_ws(&mut outside_sub).await["type"], "welcome");
        let outside_view = receive_ws(&mut outside_sub).await;
        assert_eq!(outside_view["instances"].as_array().unwrap().len(), 1);
        assert_ne!(
            outside_view["instances"][0]["now"]["sections"]["tasks"]["availability"],
            "available"
        );
        f.shutdown().await.unwrap();
        assert_socket_closed(&mut sub).await;
        assert_socket_closed(&mut first).await;
        assert_socket_closed(&mut second).await;
        assert_socket_closed(&mut outsider).await;
        assert_socket_closed(&mut outside_sub).await;
        assert!(TcpStream::connect(address).await.is_err());
        assert!(TcpStream::connect(("127.0.0.1", pg)).await.is_err());
    }

    #[tokio::test]
    async fn realtime_configuration_rejects_invalid_before_setup() {
        let mut value = serde_json::json!({"command":"start","instance_id":"rt","projects":[]});
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
