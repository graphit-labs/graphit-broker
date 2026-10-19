//! Public native PROJECT JWT fixture for the actual Auth HTTP consumer.
#[allow(
    dead_code,
    reason = "shared native PostgreSQL support serves other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use broker_control::{
    BrokerAccessIssuer, BrokerAccessTokenInput, BrokerAccessVerifier, PostgresControlStore,
    ProjectResourceAction, ProjectResourceModule,
};
use broker_presence::{BrokerProjectAuthorizationHttpConfig, broker_project_authorization_router};
use futures_util::FutureExt;
use jsonwebtoken::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    io::{BufRead, Write},
    net::SocketAddr,
    panic::AssertUnwindSafe,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

struct Object<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an IPC object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(Visitor(std::marker::PhantomData))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    issuer: String,
    api_audience: String,
    resource: String,
    client_id: String,
    subject: String,
    scope: String,
    project_ids: Vec<String>,
    access_ttl_seconds: u64,
}
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Start {
        #[serde(flatten)]
        setup: Setup,
    },
    DenyAccess {},
    AllowAccess {},
    CorruptPolicy {},
    RestorePolicy {},
    Shutdown {},
}
impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Start { .. } => "start",
            Self::DenyAccess {} => "deny_access",
            Self::AllowAccess {} => "allow_access",
            Self::CorruptPolicy {} => "corrupt_policy",
            Self::RestorePolicy {} => "restore_policy",
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
            Self::InvalidCommand => "invalid PROJECT fixture command",
            Self::Input => "PROJECT fixture input failed",
            Self::Output => "PROJECT fixture output failed",
            Self::Setup => "PROJECT fixture setup failed",
            Self::Storage => "PROJECT fixture SQL operation failed",
            Self::Server => "PROJECT fixture HTTP server failed",
            Self::Shutdown => "PROJECT fixture shutdown failed",
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
fn emit(output: &mut impl Write, value: &impl Serialize) -> Result<(), Failure> {
    serde_json::to_writer(&mut *output, value).map_err(|_| Failure::Output)?;
    output.write_all(b"\n").map_err(|_| Failure::Output)?;
    output.flush().map_err(|_| Failure::Output)
}
const MODULES: [ProjectResourceModule; 4] = [
    ProjectResourceModule::Task,
    ProjectResourceModule::Memory,
    ProjectResourceModule::Knowledge,
    ProjectResourceModule::Ast,
];
const ACTIONS: [ProjectResourceAction; 2] =
    [ProjectResourceAction::Read, ProjectResourceAction::Write];
fn literal_pattern(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if "\\*?[]{}".contains(ch) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}
fn signed(setup: &Setup) -> Result<(Arc<BrokerAccessVerifier>, JwkSet, String, u64), Failure> {
    if setup.project_ids.is_empty()
        || setup.access_ttl_seconds == 0
        || setup
            .project_ids
            .iter()
            .enumerate()
            .any(|(i, p)| setup.project_ids[..i].contains(p))
    {
        return Err(Failure::InvalidCommand);
    }
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|_| Failure::Setup)?;
    let pkcs8 = zeroize::Zeroizing::new(pair.serialize_der());
    let issuer = BrokerAccessIssuer::new(
        &setup.issuer,
        &setup.api_audience,
        "project-fixture",
        &pkcs8,
    )
    .map_err(|_| Failure::InvalidCommand)?;
    let keys = issuer.jwks().clone();
    let verifier = Arc::new(
        BrokerAccessVerifier::new(
            &setup.issuer,
            &setup.api_audience,
            Some(&setup.resource),
            &keys,
            n(8192),
        )
        .map_err(|_| Failure::InvalidCommand)?,
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::Setup)?
        .as_secs();
    let exp = now
        .checked_add(setup.access_ttl_seconds)
        .ok_or(Failure::InvalidCommand)?;
    let bearer = issuer
        .sign_access(
            BrokerAccessTokenInput {
                subject: &setup.subject,
                client_id: &setup.client_id,
                resource: Some(&setup.resource),
                scope: &setup.scope,
                jti: "project-fixture-access",
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
    verifier
        .verify(&bearer, &[], deadline())
        .map_err(|_| Failure::InvalidCommand)?;
    Ok((verifier, keys, bearer, exp))
}
fn config(f: &Fixture) -> Result<broker_control::PostgresConfig, Failure> {
    broker_control::PostgresConfig::new(
        broker_control::PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: std::num::NonZeroU16::new(f.port).ok_or(Failure::Setup)?,
            database: "postgres".into(),
        },
        broker_control::PostgresCredentials::new(
            "project_fixture_owner".into(),
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

#[derive(Serialize)]
struct Ready<'a> {
    event: &'static str,
    authorize_endpoint: String,
    issuer: &'a str,
    api_audience: &'a str,
    resource: &'a str,
    client_id: &'a str,
    subject: &'a str,
    scope: &'a str,
    project_ids: &'a [String],
    required_scopes: [String; 0],
    access_bearer: &'a str,
    trusted_jwks: &'a JwkSet,
    expires_at: u64,
}
#[derive(Serialize)]
struct Ack {
    event: &'static str,
    command: &'static str,
    ok: bool,
}
struct Live {
    postgres: Fixture,
    control: PgConnection,
    store: Arc<PostgresControlStore>,
    setup: Setup,
    keys: JwkSet,
    bearer: String,
    expires_at: u64,
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    server: JoinHandle<Result<(), std::io::Error>>,
}
impl Live {
    async fn start(setup: Setup) -> Result<Self, Failure> {
        let (verifier, keys, bearer, expires_at) = signed(&setup)?;
        let postgres = Fixture::new(true).await;
        let mut control = postgres.connection().await;
        control.execute("CREATE ROLE project_fixture_owner LOGIN NOSUPERUSER PASSWORD 'fixture-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION project_fixture_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO project_fixture_owner").await.map_err(|_|Failure::Setup)?;
        let store = Arc::new(
            PostgresControlStore::open(config(&postgres)?, support::digester(), deadline())
                .await
                .map_err(|_| Failure::Setup)?,
        );
        let superuser: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT rolsuper FROM pg_roles WHERE rolname='project_fixture_owner'",
        )
        .fetch_one(&mut control)
        .await
        .map_err(|_| Failure::Setup)?;
        if superuser {
            return Err(Failure::Setup);
        }
        let mut state = Self::seed_grant(&mut control, &setup, true).await?;
        state
            .execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
            .await
            .map_err(|_| Failure::Setup)?;
        state.commit().await.map_err(|_| Failure::Setup)?;
        for project in &setup.project_ids {
            for module in MODULES {
                for action in ACTIONS {
                    store
                        .broker_project_authorizer(&verifier, n(65536))
                        .map_err(|_| Failure::Setup)?
                        .authorize(&bearer, &[], module, action, project, deadline())
                        .await
                        .map_err(|_| Failure::InvalidCommand)?;
                }
            }
        }
        let app = broker_project_authorization_router(
            store.clone(),
            verifier,
            BrokerProjectAuthorizationHttpConfig {
                required_scopes: vec![],
                grants_json_bytes: n(65536),
                body_bytes: n(4096),
                request_timeout: Duration::from_secs(4),
            },
        )
        .map_err(|_| Failure::Setup)?;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| Failure::Server)?;
        let address = listener.local_addr().map_err(|_| Failure::Server)?;
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
            setup,
            keys,
            bearer,
            expires_at,
            address,
            stop,
            server,
        })
    }
    async fn seed_grant<'a>(
        control: &'a mut PgConnection,
        setup: &Setup,
        allow: bool,
    ) -> Result<sqlx_core::transaction::Transaction<'a, sqlx_postgres::Postgres>, Failure> {
        let mut tx = control.begin().await.map_err(|_| Failure::Storage)?;
        tx.execute("DELETE FROM public.resource_grants WHERE id='project-fixture'")
            .await
            .map_err(|_| Failure::Storage)?;
        if allow {
            sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('project-fixture','PROJECT fixture','subject',$1,'',0,0)")
                .bind(literal_pattern(&format!("{}|{}", setup.issuer, setup.subject)))
                .execute(&mut *tx).await.map_err(|_| Failure::Storage)?;
            for project in &setup.project_ids {
                sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES('project-fixture',$1)")
                    .bind(project).execute(&mut *tx).await.map_err(|_| Failure::Storage)?;
            }
            for module in MODULES {
                for action in ACTIONS {
                    sqlx_core::query::query("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('project-fixture',$1)")
                        .bind(format!("{}:{}",module.as_str(),action.as_str()))
                        .execute(&mut *tx).await.map_err(|_| Failure::Storage)?;
                }
            }
        }
        Ok(tx)
    }
    fn ready(&self) -> Ready<'_> {
        Ready {
            event: "ready",
            authorize_endpoint: format!("http://{}/v1/project/access/authorize", self.address),
            issuer: &self.setup.issuer,
            api_audience: &self.setup.api_audience,
            resource: &self.setup.resource,
            client_id: &self.setup.client_id,
            subject: &self.setup.subject,
            scope: &self.setup.scope,
            project_ids: &self.setup.project_ids,
            required_scopes: [],
            access_bearer: &self.bearer,
            trusted_jwks: &self.keys,
            expires_at: self.expires_at,
        }
    }
    async fn command(&mut self, command: &Command) -> Result<(), Failure> {
        match command {
            Command::Start { .. } => return Err(Failure::InvalidCommand),
            Command::DenyAccess {} | Command::AllowAccess {} => {
                let mut tx = Self::seed_grant(
                    &mut self.control,
                    &self.setup,
                    matches!(command, Command::AllowAccess {}),
                )
                .await?;
                tx.execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
                    .await
                    .map_err(|_| Failure::Storage)?;
                tx.commit().await.map_err(|_| Failure::Storage)?;
            }
            Command::CorruptPolicy {} | Command::RestorePolicy {} => {
                let mut tx = self.control.begin().await.map_err(|_| Failure::Storage)?;
                tx.execute("DELETE FROM public.resource_grants WHERE id='invalid-fixture'")
                    .await
                    .map_err(|_| Failure::Storage)?;
                if matches!(command, Command::CorruptPolicy {}) {
                    tx.execute("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('invalid-fixture','Invalid fixture','subject','unrelated','',0,0); INSERT INTO public.grant_capabilities(grant_id,value) VALUES('invalid-fixture','task:read'); INSERT INTO public.grant_projects(grant_id,value) VALUES('invalid-fixture','[')").await.map_err(|_|Failure::Storage)?;
                }
                tx.execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
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
            ..
        } = self;
        let _ = stop.send(());
        let server_result = match tokio::time::timeout(Duration::from_secs(3), &mut server).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(_) => Err(Failure::Shutdown),
            Err(_) => {
                server.abort();
                let _ = server.await;
                Err(Failure::Shutdown)
            }
        };
        let store_result = store
            .shutdown(deadline())
            .await
            .map_err(|_| Failure::Shutdown);
        let control_result = control.close().await.map_err(|_| Failure::Shutdown);
        drop(store);
        let postgres_result = postgres.shutdown().map_err(|_| Failure::Shutdown);
        server_result
            .and(store_result)
            .and(control_result)
            .and(postgres_result)
    }
}
async fn run(input: &mut impl BufRead, output: &mut impl Write) -> Result<(), Failure> {
    let Some(start) = read_command(input)? else {
        return Ok(());
    };
    let Command::Start { setup } = start else {
        return Err(Failure::InvalidCommand);
    };
    let mut live = Live::start(setup).await?;
    let mut requested_shutdown = false;
    let result = async {
        emit(output, &live.ready())?;
        while let Some(command) = read_command(input)? {
            live.command(&command).await?;
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
    let stopped = live.shutdown().await;
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
    std::panic::set_hook(Box::new(|_| {
        eprintln!("PROJECT fixture internal failure");
    }));
    match AssertUnwindSafe(run(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    ))
    .catch_unwind()
    .await
    {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        Ok(Err(e)) => {
            eprintln!("{}", e.message());
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
    fn start_json() -> serde_json::Value {
        serde_json::json!({"command":"start","issuer":"https://broker.example.test","api_audience":"native-api",
            "resource":"https://broker.example.test/v1","client_id":"web-client","subject":"native-subject",
            "scope":"","project_ids":[PROJECT],"access_ttl_seconds":600})
    }
    fn setup() -> Setup {
        let Command::Start { setup } = read_command(&mut Cursor::new(start_json().to_string()))
            .unwrap()
            .unwrap()
        else {
            panic!("start expected")
        };
        setup
    }
    #[test]
    fn start_and_finite_commands_are_strict_and_values_explicit() {
        let s = setup();
        let (verifier, _, bearer, exp) = signed(&s).unwrap();
        let proof = verifier.verify(&bearer, &[], deadline()).unwrap();
        assert_eq!(proof.issuer(), s.issuer);
        assert_eq!(proof.subject(), s.subject);
        assert!(
            exp > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        for field in [
            "issuer",
            "api_audience",
            "resource",
            "client_id",
            "subject",
            "scope",
            "project_ids",
            "access_ttl_seconds",
        ] {
            let mut value = start_json();
            value.as_object_mut().unwrap().remove(field);
            assert!(read_command(&mut Cursor::new(value.to_string())).is_err());
        }
        for raw in [
            "[]",
            "null",
            r#"["start"]"#,
            r#"{"command":"unknown"}"#,
            r#"{"command":"shutdown","extra":1}"#,
            r#"{"command":"shutdown","command":"shutdown"}"#,
        ] {
            assert!(read_command(&mut Cursor::new(raw)).is_err());
        }
        let extra = format!(
            "{},\"extra\":1}}",
            start_json().to_string().trim_end_matches('}')
        );
        assert!(read_command(&mut Cursor::new(extra)).is_err());
        let duplicate = start_json().to_string().replace(
            "\"client_id\":\"web-client\"",
            "\"client_id\":\"web-client\",\"client_id\":\"other\"",
        );
        assert!(read_command(&mut Cursor::new(duplicate)).is_err());
        assert!(read_command(&mut Cursor::new(format!("{} {{}}", start_json()))).is_err());
        let mut s = setup();
        s.access_ttl_seconds = 0;
        assert!(signed(&s).is_err());
        s.access_ttl_seconds = u64::MAX;
        assert!(signed(&s).is_err());
        let mut s = setup();
        s.project_ids.push(PROJECT.into());
        assert!(signed(&s).is_err());
        for name in [
            "deny_access",
            "allow_access",
            "corrupt_policy",
            "restore_policy",
            "shutdown",
        ] {
            let cmd = read_command(&mut Cursor::new(format!(r#"{{"command":"{name}"}}"#)))
                .unwrap()
                .unwrap();
            assert_eq!(cmd.name(), name);
        }
        assert_eq!(
            literal_pattern("a*?[x]{z}\\b"),
            "a\\*\\?\\[x\\]\\{z\\}\\\\b"
        );
    }
    #[tokio::test]
    async fn initial_eof_does_not_create_a_fixture_or_output() {
        let mut out = Vec::new();
        run(&mut Cursor::new(""), &mut out).await.unwrap();
        assert!(out.is_empty());
        assert!(
            run(&mut Cursor::new(r#"{"command":"shutdown"}"#), &mut out)
                .await
                .is_err()
        );
        assert!(out.is_empty());
    }
    async fn post(
        live: &Live,
        module: ProjectResourceModule,
        action: ProjectResourceAction,
    ) -> (StatusCode, serde_json::Value) {
        let stream = TcpStream::connect(live.address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let worker = tokio::spawn(connection);
        let request=Request::builder().method("POST").uri("/v1/project/access/authorize")
            .header(header::AUTHORIZATION,format!("Bearer {}",live.bearer)).header(header::CONTENT_TYPE,"application/json")
            .body(Body::from(serde_json::json!({"project_id":PROJECT,"module":module.as_str(),"action":action.as_str()}).to_string())).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(10), sender.send_request(request))
            .await
            .unwrap()
            .unwrap();
        let status = response.status();
        let json =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        (status, json)
    }
    #[tokio::test]
    #[ignore = "native public PROJECT fixture SQL TLS ordinary owner and actual TCP JWT endpoint"]
    async fn project_authorization_fixture_postgres_contract() {
        let mut live = Live::start(setup()).await.unwrap();
        let address = live.address;
        let ready = serde_json::to_value(live.ready()).unwrap();
        assert_eq!(
            ready["authorize_endpoint"],
            format!("http://{address}/v1/project/access/authorize")
        );
        assert_eq!(ready["required_scopes"], serde_json::json!([]));
        assert_eq!(ready["scope"], "");
        assert_eq!(ready["client_id"], "web-client");
        for module in MODULES {
            for action in ACTIONS {
                let response = post(&live, module, action).await;
                assert_eq!(response.0, StatusCode::OK);
                assert_eq!(
                    response.1["subject"],
                    serde_json::json!({"issuer":live.setup.issuer,"subject":live.setup.subject})
                );
                assert_eq!(response.1["project_id"], PROJECT);
                assert_eq!(response.1["module"], module.as_str());
                assert_eq!(response.1["action"], action.as_str());
            }
        }
        let before = post(&live, MODULES[0], ACTIONS[0]).await.1["authorization_revision"]
            .as_i64()
            .unwrap();
        live.command(&Command::DenyAccess {}).await.unwrap();
        for module in MODULES {
            for action in ACTIONS {
                let r = post(&live, module, action).await;
                assert_eq!(r.0, StatusCode::FORBIDDEN);
                assert_eq!(r.1, serde_json::json!({"error":{"code":"forbidden"}}));
            }
        }
        live.command(&Command::AllowAccess {}).await.unwrap();
        let restored = post(&live, MODULES[0], ACTIONS[0]).await;
        assert_eq!(restored.0, StatusCode::OK);
        assert_eq!(
            restored.1["authorization_revision"].as_i64().unwrap(),
            before + 2
        );
        live.command(&Command::CorruptPolicy {}).await.unwrap();
        let bad = post(&live, MODULES[0], ACTIONS[0]).await;
        assert_eq!(bad.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            bad.1,
            serde_json::json!({"error":{"code":"invalid_policy"}})
        );
        live.command(&Command::RestorePolicy {}).await.unwrap();
        assert_eq!(post(&live, MODULES[0], ACTIONS[0]).await.0, StatusCode::OK);
        live.shutdown().await.unwrap();
        assert!(TcpStream::connect(address).await.is_err());
    }
}
