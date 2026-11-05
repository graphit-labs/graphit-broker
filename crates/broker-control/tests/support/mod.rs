mod command;
use broker_control::{
    ConnectionLimits, FlowLimits, PoolConfig, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint,
};
use broker_security::{CredentialDigester, DigestLimits};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use sqlx_core::connection::{ConnectOptions, Connection};
use sqlx_postgres::{PgConnectOptions, PgConnection, PgSslMode};
use std::{
    fs,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeroize::Zeroizing;

pub const IMAGE: &str =
    "postgres@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3";
pub fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
pub fn limits() -> FlowLimits {
    FlowLimits {
        provider_bytes: n(128),
        request_bytes: n(128),
        continuation_bytes: n(512),
    }
}
pub fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(vec![0x91; 32].into_boxed_slice()),
        DigestLimits::new(n(64), n(256), n(256), n(256), n(256)).unwrap(),
    )
    .unwrap()
}
pub fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}
pub fn pool(max: u32) -> PoolConfig {
    PoolConfig {
        max_connections: NonZeroU32::new(max).unwrap(),
        min_connections: 0,
        statement_cache_capacity: 0,
        connect_timeout: Duration::from_secs(8),
        acquire_timeout: Duration::from_secs(5),
        operation_timeout: Duration::from_secs(8),
        startup_timeout: Duration::from_secs(15),
        shutdown_timeout: Duration::from_secs(2),
        max_lifetime: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(30),
        statement_timeout: Duration::from_secs(10),
        lock_timeout: Duration::from_secs(10),
        idle_transaction_timeout: Duration::from_secs(15),
    }
}
// Drain and reap the normal Docker command; avoid exposing fixture stderr.
fn docker(args: &[&str]) -> String {
    let diagnostic =
        std::env::var_os("GRAPHIT_BROKER_FIXTURE_DIAGNOSTICS").is_some_and(|v| v == "1");
    let phase = match args.first().copied() {
        Some("create") => "docker-create",
        Some("start") => "docker-start",
        Some("cp") => "docker-copy-tls",
        Some("exec") => "docker-configure-tls",
        Some("port") => "docker-mapped-port",
        _ => "docker-control",
    };
    let started = Instant::now();
    if diagnostic {
        eprintln!("broker-fixture phase={phase} event=begin");
    }
    let mut command = Command::new("docker");
    command.args(args).stderr(Stdio::null());
    let output = command::output(&mut command, &[], Instant::now() + Duration::from_secs(60));
    if diagnostic {
        let status = match &output {
            Ok(output) if output.status.success() => "success",
            Ok(_) => "failure",
            Err(_) => "spawn-or-wait-failure",
        };
        eprintln!(
            "broker-fixture phase={phase} event=end status={status} elapsed_ms={}",
            started.elapsed().as_millis()
        );
    }
    let output = output.expect("Docker executable");
    assert!(output.status.success(), "owned Docker control failed");
    String::from_utf8(output.stdout).unwrap()
}
pub struct Fixture {
    id: String,
    _files: TempDir,
    pub port: u16,
    pub ca: Vec<u8>,
}
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "public Presence fixtures consume explicit cleanup; SQL suites use RAII"
)]
pub struct FixtureCleanupError;
impl Fixture {
    #[allow(
        dead_code,
        reason = "public Presence fixtures consume explicit cleanup; SQL suites use RAII"
    )]
    pub fn shutdown(mut self) -> Result<(), FixtureCleanupError> {
        let removed = command::output(
            Command::new("docker").args(["rm", "--force", "--volumes", &self.id]),
            &[],
            Instant::now() + Duration::from_secs(60),
        );
        if !removed.is_ok_and(|output| output.status.success()) {
            return Err(FixtureCleanupError);
        }
        self.id.clear();
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.id.is_empty() {
            return;
        }
        let removed = command::output(
            Command::new("docker").args(["rm", "--force", "--volumes", &self.id]),
            &[],
            Instant::now() + Duration::from_secs(60),
        );
        if !removed.is_ok_and(|output| output.status.success()) {
            eprintln!("owned PostgreSQL fixture cleanup failed");
        }
    }
}
fn private_file(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    assert!(file.metadata().unwrap().is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(
            metadata.uid(),
            path.parent().unwrap().metadata().unwrap().uid()
        );
    }
}
impl Fixture {
    pub async fn new(tls: bool) -> Self {
        let diagnostic =
            std::env::var_os("GRAPHIT_BROKER_FIXTURE_DIAGNOSTICS").is_some_and(|v| v == "1");
        let started = Instant::now();
        if diagnostic {
            eprintln!("broker-fixture phase=postgres-fixture event=begin");
        }
        let mut builder = tempfile::Builder::new();
        builder.prefix("broker-control-tls-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let files = builder.tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                files.path().metadata().unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let server_key = KeyPair::generate().unwrap();
        let server = CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .signed_by(&server_key, &issuer)
            .unwrap();
        private_file(&files.path().join("server.crt"), server.pem().as_bytes());
        private_file(
            &files.path().join("server.key"),
            server_key.serialize_pem().as_bytes(),
        );
        // Install the guard before any Docker create/start can fail.
        let id = format!(
            "broker-pg-{}",
            files.path().file_name().unwrap().to_str().unwrap()
        );
        let mut fixture = Self {
            id,
            _files: files,
            port: 1,
            ca: ca.pem().into_bytes(),
        };
        docker(&[
            "create",
            "--name",
            &fixture.id,
            "--publish",
            "127.0.0.1::5432",
            "--env",
            "POSTGRES_PASSWORD=ephemeral-fixture",
            IMAGE,
        ]);
        eprintln!(
            "broker-fixture pid={} container={}",
            std::process::id(),
            fixture.id
        );
        docker(&["start", &fixture.id]);
        if tls {
            let cert = fixture._files.path().join("server.crt");
            let key = fixture._files.path().join("server.key");
            docker(&[
                "cp",
                cert.to_str().unwrap(),
                &format!("{}:/tmp/server.crt", fixture.id),
            ]);
            docker(&[
                "cp",
                key.to_str().unwrap(),
                &format!("{}:/tmp/server.key", fixture.id),
            ]);
            docker(&[
                "exec",
                "--user",
                "root",
                &fixture.id,
                "chown",
                "postgres:postgres",
                "/tmp/server.crt",
                "/tmp/server.key",
            ]);
            docker(&[
                "exec",
                "--user",
                "root",
                &fixture.id,
                "chmod",
                "600",
                "/tmp/server.key",
                "/tmp/server.crt",
            ]);
        }
        let port = docker(&["port", &fixture.id, "5432/tcp"]);
        assert!(port.trim().starts_with("127.0.0.1:"));
        fixture.port = port.trim().rsplit(':').next().unwrap().parse().unwrap();
        let startup = Instant::now();
        if diagnostic {
            eprintln!("broker-fixture phase=postgres-startup event=begin");
        }
        let limit = deadline();
        loop {
            if let Ok(mut connection) = fixture.connection_without_tls().await {
                if tls {
                    sqlx_core::query::query("ALTER SYSTEM SET ssl='on'")
                        .execute(&mut connection)
                        .await
                        .unwrap();
                    sqlx_core::query::query("ALTER SYSTEM SET ssl_cert_file='/tmp/server.crt'")
                        .execute(&mut connection)
                        .await
                        .unwrap();
                    sqlx_core::query::query("ALTER SYSTEM SET ssl_key_file='/tmp/server.key'")
                        .execute(&mut connection)
                        .await
                        .unwrap();
                    sqlx_core::query::query("SELECT pg_reload_conf()")
                        .execute(&mut connection)
                        .await
                        .unwrap();
                }
                connection.close().await.unwrap();
                break;
            }
            assert!(Instant::now() < limit, "Postgres startup deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if tls {
            fixture.connection().await.close().await.unwrap();
        }
        if diagnostic {
            eprintln!(
                "broker-fixture phase=postgres-startup event=end status=success elapsed_ms={}",
                startup.elapsed().as_millis()
            );
            eprintln!(
                "broker-fixture phase=postgres-fixture event=end status=success elapsed_ms={}",
                started.elapsed().as_millis()
            );
        }
        fixture
    }
    fn options(&self) -> PgConnectOptions {
        PgConnectOptions::new_without_pgpass()
            .host("127.0.0.1")
            .port(self.port)
            .database("postgres")
            .username("postgres")
            .password("ephemeral-fixture")
            .disable_statement_logging()
    }
    async fn connection_without_tls(&self) -> Result<PgConnection, sqlx_core::error::Error> {
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            PgConnection::connect_with(&self.options().ssl_mode(PgSslMode::Disable)),
        )
        .await;
        if std::env::var_os("GRAPHIT_BROKER_FIXTURE_DIAGNOSTICS").is_some_and(|value| value == "1")
        {
            match &result {
                Err(_) => eprintln!(
                    "broker-fixture phase=postgres-startup-connect event=timeout timeout_ms=2000"
                ),
                Ok(Err(sqlx_core::error::Error::Io(error))) => eprintln!(
                    "broker-fixture phase=postgres-startup-connect event=io-error kind={:?}",
                    error.kind()
                ),
                Ok(Err(_)) => {
                    eprintln!("broker-fixture phase=postgres-startup-connect event=sql-error")
                }
                Ok(Ok(_)) => {}
            }
        }
        result.expect("bounded fixture connection")
    }
    pub async fn connection(&self) -> PgConnection {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            PgConnection::connect_with(
                &self
                    .options()
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert_from_pem(self.ca.clone()),
            ),
        )
        .await;
        if std::env::var_os("GRAPHIT_BROKER_FIXTURE_DIAGNOSTICS").is_some_and(|value| value == "1")
        {
            match &result {
                Err(_) => eprintln!(
                    "broker-fixture phase=postgres-tls-connect event=timeout timeout_ms=5000"
                ),
                Ok(Err(sqlx_core::error::Error::Io(error))) => eprintln!(
                    "broker-fixture phase=postgres-tls-connect event=io-error kind={:?}",
                    error.kind()
                ),
                Ok(Err(_)) => {
                    eprintln!("broker-fixture phase=postgres-tls-connect event=sql-or-tls-error")
                }
                Ok(Ok(_)) => {}
            }
        }
        result.unwrap().unwrap()
    }
    pub fn config(&self, max: u32) -> PostgresConfig {
        self.config_fields("127.0.0.1", "ephemeral-fixture", self.ca.clone(), max)
    }
    pub fn config_fields(
        &self,
        host: &str,
        password: &str,
        ca: Vec<u8>,
        max: u32,
    ) -> PostgresConfig {
        PostgresConfig::new(
            PostgresEndpoint {
                host: host.into(),
                port: NonZeroU16::new(self.port).unwrap(),
                database: "postgres".into(),
            },
            PostgresCredentials::new("postgres".into(), Zeroizing::new(password.into())),
            ca,
            ConnectionLimits {
                text_bytes: n(256),
                ca_bytes: n(8192),
            },
            pool(max),
            limits(),
        )
        .unwrap()
    }
    pub async fn open(&self, max: u32) -> PostgresControlStore {
        PostgresControlStore::open(self.config(max), digester(), deadline())
            .await
            .unwrap()
    }
    pub async fn reset(&self) {
        let mut c = self.connection().await;
        sqlx_core::raw_sql::raw_sql(
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION postgres",
        )
        .execute(&mut c)
        .await
        .unwrap();
        c.close().await.unwrap();
    }
}
