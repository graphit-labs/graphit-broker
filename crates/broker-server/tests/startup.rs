#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture also serves other SQL suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use broker_control::{BrokerAccessIssuer, BrokerAccessTokenInput};
use broker_security::{CredentialDigester, DigestLimits, TokenKind};
use broker_server::{ServerError, load_config};
use broker_storage::{FilesystemStore, FilesystemStoreConfig};
use object_store::{
    ClientOptions, ObjectStoreExt,
    aws::{AmazonS3, AmazonS3Builder},
    path::Path as ObjectPath,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    net::SocketAddr,
    num::NonZeroU64,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::{Child, Command},
};
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const PEPPER: &str = "ephemeral-startup-fixture-pepper-32-bytes";
const ISSUER: &str = "https://broker.example.test";
const AUDIENCE: &str = "storage-api";
const RESOURCE: &str = "https://broker.example.test/v1";
const ACCESS: &str = "gb_at_startup-access";
const SERVICE: &str = "gb_sc_startup-service";
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
        .try_into()
        .unwrap()
}
fn yaml(address: SocketAddr, pg: u16) -> String {
    format!(
        r#"server:
  address: {address}
  public_url: http://{address}
  shutdown_timeout: 3s
database:
  backend: postgres
  host: 127.0.0.1
  port: {pg}
  database: postgres
  username: startup_owner
  password: ephemeral-owner
  ca_file: ca.pem
  text_bytes: 256
  ca_bytes: 8192
  pool:
    max_connections: 2
    min_connections: 0
    statement_cache_capacity: 0
    connect_timeout: 3s
    acquire_timeout: 3s
    operation_timeout: 8s
    startup_timeout: 10s
    shutdown_timeout: 2s
    max_lifetime: 60s
    idle_timeout: 30s
    statement_timeout: 10s
    lock_timeout: 10s
    idle_transaction_timeout: 15s
  flows:
    provider_bytes: 128
    request_bytes: 128
    continuation_bytes: 512
auth:
  issuer: {ISSUER}
  audience: {AUDIENCE}
  kid: startup-key
  resource: {RESOURCE}
  pkcs8_file: signing.pk8
  key_bytes: 8192
  pepper: {PEPPER}
  digest:
    pepper_bytes: 256
    token_bytes: 8192
    binding_bytes: 256
    subject_bytes: 256
    recovery_bytes: 256
storage:
  enabled: true
  required_scopes: []
  request_timeout: 10s
  sts_timeout: 5s
  identity_json_bytes: 8192
  grants_json_bytes: 65536
  head_bytes: 16384
  token_bytes: 8192
  metadata_bytes: 65536
  routes:
    native-fs:
      driver: filesystem
      bucket: native-storage
      base_prefix: graphit
      directory: volume
"#
    )
}
fn files(root: &Path, ca: &[u8]) -> BrokerAccessIssuer {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let der = Zeroizing::new(key.serialize_der());
    std::fs::write(root.join("signing.pk8"), &der).unwrap();
    std::fs::write(root.join("ca.pem"), ca).unwrap();
    BrokerAccessIssuer::new(ISSUER, AUDIENCE, "startup-key", &der).unwrap()
}
fn ephemeral_ca() -> Vec<u8> {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.self_signed(&key).unwrap().pem().into_bytes()
}
fn port() -> SocketAddr {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}
fn write_config(root: &Path, config: &str) -> PathBuf {
    let file = root.join("config.yaml");
    std::fs::write(&file, config).unwrap();
    file
}
fn command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_graphit-broker"));
    cmd.kill_on_drop(true);
    cmd
}
async fn check(path: &Path) -> std::process::Output {
    command()
        .args(["--config", path.to_str().unwrap(), "--check-config"])
        .output()
        .await
        .unwrap()
}
#[tokio::test]
async fn actual_cli_configuration_without_effects() {
    let root = tempfile::tempdir().unwrap();
    let address = port();
    let _key = files(root.path(), &ephemeral_ca());
    let config = yaml(address, 1);
    let path = write_config(root.path(), &config);
    assert!(load_config(&path).await.is_ok());
    let checked = check(&path).await;
    assert!(checked.status.success());
    assert!(!root.path().join("volume").exists());
    assert!(TcpStream::connect(address).await.is_err());
    // The maintained operator example is also consumed by the real executable.
    let example = include_str!("../../../docs/rust-broker-server.md")
        .split_once("```yaml\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0;
    std::fs::copy(
        root.path().join("ca.pem"),
        root.path().join("postgres-ca.pem"),
    )
    .unwrap();
    write_config(root.path(), &example.replace('\n', "\r\n"));
    let out = command()
        .args(["--config", path.to_str().unwrap(), "--check-config"])
        .env("BROKER_DATABASE_PASSWORD", "ephemeral-password")
        .env("BROKER_PEPPER", PEPPER)
        .output()
        .await
        .unwrap();
    assert!(out.status.success());
    assert!(!root.path().join("volumes").exists());
    write_config(root.path(), &config);
    let version = command().arg("--version").output().await.unwrap();
    assert!(version.status.success());
    assert!(
        String::from_utf8(version.stdout)
            .unwrap()
            .starts_with("graphit-broker 0.1.0")
    );
    let default = command()
        .env("GRAPHIT_BROKER_CONFIG", &path)
        .arg("--check-config")
        .output()
        .await
        .unwrap();
    assert!(default.status.success());
    let global = root.path().join("global/broker");
    std::fs::create_dir_all(&global).unwrap();
    for name in ["ca.pem", "signing.pk8"] {
        std::fs::copy(root.path().join(name), global.join(name)).unwrap();
    }
    std::fs::write(global.join("config.yaml"), &config).unwrap();
    let default = command()
        .env_remove("GRAPHIT_BROKER_CONFIG")
        .env("GRAPHIT_GLOBAL_DIR", root.path().join("global"))
        .arg("--check-config")
        .output()
        .await
        .unwrap();
    assert!(default.status.success());
    for bad in [
        config.replace("backend: postgres", "backend: sqlite"),
        config.replace("backend: postgres", "backend: mysql"),
        config.replace("driver: filesystem", "driver: invented"),
        config.replace(
            "driver: filesystem",
            "driver: filesystem\n      conditional_delete: true",
        ),
        config.replace(
            "driver: filesystem",
            "driver: filesystem\n      conditional_delete: false",
        ),
        config
            .replace("  enabled: true", "  enabled: false")
            .replace(
                "driver: filesystem",
                "driver: filesystem\n      conditional_delete: false",
            ),
        config.replace(
            "directory: volume",
            "directory: volume\n      role_arn: secret-should-not-log",
        ),
        config.replace("host: 127.0.0.1", "host: 127.0.0.1\n  host: other"),
        format!("{config}\nunknown: secret-should-not-log"),
        format!("{config}\n---\n{config}"),
        config.replace(PEPPER, "${MISSING_STARTUP_VALUE:?secret-should-not-log}"),
        config.replace("public_url: http://", "public_url: http://private-"),
    ] {
        write_config(root.path(), &bad);
        let out = check(&path).await;
        assert!(!out.status.success());
        assert!(
            !String::from_utf8(out.stderr)
                .unwrap()
                .contains("secret-should-not-log")
        );
        assert!(!root.path().join("volume").exists());
    }
    // Omitted driver/region/session name/duration resolve active S3 defaults using mature constructors.
    let aws = config.replace("      driver: filesystem\n", "").replace("      directory: volume", "      role_arn: arn:aws:iam::123456789012:role/native-storage\n      access_key_id: ephemeral-key\n      secret_access_key: ephemeral-secret");
    write_config(root.path(), &aws);
    assert!(check(&path).await.status.success());
    for capability in ["true", "false"] {
        let explicit = aws.replace(
            "      base_prefix: graphit",
            &format!("      base_prefix: graphit\n      conditional_delete: {capability}"),
        );
        write_config(root.path(), &explicit);
        assert!(load_config(&path).await.is_ok());
        assert!(check(&path).await.status.success());
    }
    for value in [
        "invented",
        "1",
        "[true]",
        "true\n      conditional_delete: false",
    ] {
        let invalid = aws.replace(
            "      base_prefix: graphit",
            &format!("      base_prefix: graphit\n      conditional_delete: {value}"),
        );
        write_config(root.path(), &invalid);
        assert!(load_config(&path).await.is_err());
    }
    assert!(!root.path().join("volume").exists());
    let bad = aws.replace("      secret_access_key: ephemeral-secret", "");
    write_config(root.path(), &bad);
    assert!(load_config(&path).await.is_err());
    let overflow = config.replace("  key_bytes: 8192", &format!("  key_bytes: {}", u64::MAX));
    write_config(root.path(), &overflow);
    assert!(load_config(&path).await.is_err());
    for field in ["identity_json_bytes", "grants_json_bytes", "metadata_bytes"] {
        let old = format!(
            "  {field}: {}",
            if field == "identity_json_bytes" {
                8192
            } else {
                65536
            }
        );
        let invalid = config.replace(
            &old,
            &format!(
                "  {field}: {}",
                if field == "metadata_bytes" {
                    u64::MAX as u128
                } else {
                    usize::MAX as u128
                }
            ),
        );
        write_config(root.path(), &invalid);
        let out = check(&path).await;
        assert!(!out.status.success());
        assert_eq!(
            String::from_utf8(out.stderr).unwrap().trim(),
            ServerError::Configuration.to_string()
        );
        assert!(!root.path().join("volume").exists());
        assert!(TcpStream::connect(address).await.is_err());
    }
    write_config(root.path(), &config);
    std::fs::write(root.path().join("signing.pk8"), b"invalid-key-secret").unwrap();
    let out = check(&path).await;
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        ServerError::Key.to_string()
    );
    let out = command()
        .args(["--config", path.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        ServerError::Key.to_string()
    );
    let _key = files(root.path(), &ephemeral_ca());
    std::fs::write(root.path().join("ca.pem"), b"invalid-ca-secret").unwrap();
    assert_eq!(
        load_config(&path).await.err(),
        Some(ServerError::Certificate)
    );
    let out = command()
        .args(["--config", path.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        ServerError::Certificate.to_string()
    );
    std::fs::remove_file(root.path().join("signing.pk8")).unwrap();
    assert_eq!(load_config(&path).await.err(), Some(ServerError::Key));
    let out = command()
        .args(["--config", path.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        ServerError::Key.to_string()
    );
    assert!(!root.path().join("volume").exists());
    assert!(TcpStream::connect(address).await.is_err());
}
async fn seed(c: &mut PgConnection) {
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Alice','','','[]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','','[]',1,0,1,0,0)").await.unwrap();
    let digester = CredentialDigester::new(
        Zeroizing::new(PEPPER.as_bytes().to_vec().into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(256), n(256)).unwrap(),
    )
    .unwrap();
    for (raw, id, kind, tk, subject) in [
        (
            ACCESS,
            "startup-access",
            "access",
            TokenKind::LocalAccess,
            "alice-subject",
        ),
        (
            SERVICE,
            "startup-service",
            "service",
            TokenKind::ServiceCredential,
            "bot-subject",
        ),
    ] {
        let hash = digester.token(tk, raw.as_bytes()).unwrap();
        let principal=json!({"issuer":"local","subject":subject,"username":"stale","auth_method":"local-token","organization":"","teams":[],"local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'different-subject',$5,'explicit-client',$6,'','[]',1,'',0,$7,0)").bind(hash.to_sql_hex()).bind(id).bind(kind).bind(subject).bind(principal).bind(AUDIENCE).bind(micros()+600_000_000).execute(&mut *c).await.unwrap();
    }
    for (id, kind, principal) in [
        ("jwt", "subject", "jwt-subject"),
        ("access", "user", "alice"),
        ("service", "user", "bot"),
    ] {
        sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'startup',$2,$3,'native-fs',0,0)").bind(id).bind(kind).bind(principal).execute(&mut *c).await.unwrap();
        for (query, values) in [
            (
                "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
                vec!["s3"],
            ),
            (
                "INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)",
                vec![A],
            ),
            (
                "INSERT INTO public.grant_s3_operations(grant_id,value) VALUES($1,$2)",
                vec!["read", "write", "publish", "delete"],
            ),
            (
                "INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES($1,$2)",
                vec!["v1"],
            ),
        ] {
            for value in values {
                sqlx_core::query::query(query)
                    .bind(id)
                    .bind(value)
                    .execute(&mut *c)
                    .await
                    .unwrap();
            }
        }
    }
}
fn native(issuer: &BrokerAccessIssuer) -> Zeroizing<String> {
    let now = seconds();
    issuer
        .sign_access(
            BrokerAccessTokenInput {
                subject: "jwt-subject",
                client_id: "explicit-client",
                resource: Some(RESOURCE),
                scope: "",
                jti: "startup-jti",
                issued_at: now,
                expires_at: now + 600,
                preferred_username: None,
                name: None,
                email: None,
                organization: None,
                groups: &[],
                roles: &[],
            },
            deadline(),
        )
        .unwrap()
        .into()
}
async fn start(path: &Path, address: SocketAddr) -> Child {
    let mut child = command()
        .args(["--config", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let limit = deadline();
    let client = reqwest::Client::new();
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "native bin exited before ready"
        );
        if let Ok(response) = client.get(format!("http://{address}/readyz")).send().await
            && response.status().is_success()
        {
            break;
        }
        assert!(Instant::now() < limit, "native server startup deadline");
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    child
}
async fn terminate(child: Child) {
    stop(child, true).await;
}
async fn stop(mut child: Child, success: bool) {
    #[cfg(unix)]
    {
        let result = Command::new("kill")
            .args(["-TERM", &child.id().unwrap().to_string()])
            .output()
            .await
            .unwrap();
        assert!(result.status.success());
    }
    #[cfg(not(unix))]
    {
        child.start_kill().unwrap();
    }
    let exit = tokio::time::timeout(Duration::from_secs(8), child.wait())
        .await
        .unwrap()
        .unwrap();
    #[cfg(unix)]
    assert_eq!(exit.success(), success, "native shutdown result");
    #[cfg(not(unix))]
    let _ = (exit, success);
}
async fn credentials(address: SocketAddr, bearer: &str) -> Value {
    let reply = reqwest::Client::new()
        .post(format!("http://{address}/v1/s3/credentials"))
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(json!({"scope":"project","project_id":A,"module":"hub"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.headers()["cache-control"], "no-store");
    serde_json::from_slice(&reply.bytes().await.unwrap()).unwrap()
}
fn objects(keys: &Value) -> AmazonS3 {
    let field = |name: &str| keys[name].as_str().unwrap().to_string();
    AmazonS3Builder::new()
        .with_bucket_name(field("bucket"))
        .with_region(field("region"))
        .with_endpoint(field("endpoint"))
        .with_access_key_id(field("access_key_id"))
        .with_secret_access_key(field("secret_access_key"))
        .with_token(field("session_token"))
        .with_virtual_hosted_style_request(false)
        .with_client_options(
            ClientOptions::new()
                .with_allow_http(true)
                .with_pool_max_idle_per_host(0)
                .with_timeout(Duration::from_secs(5)),
        )
        .with_retry(object_store::RetryConfig {
            max_retries: 0,
            retry_timeout: Duration::from_secs(5),
            ..Default::default()
        })
        .build()
        .unwrap()
}
fn volume(root: &Path) -> FilesystemStoreConfig {
    FilesystemStoreConfig {
        directory: root.join("volume"),
        bucket: "native-storage".into(),
        max_object_bytes: NonZeroU64::new(5 * 1024 * 1024 * 1024).unwrap(),
        metadata_bytes: n(65536),
    }
}
fn signed_stall(keys: &Value, url: &str) -> String {
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
        UriPathNormalizationMode, sign,
    };
    let field = |name: &str| keys[name].as_str().unwrap();
    let identity = aws_credential_types::Credentials::new(
        field("access_key_id"),
        field("secret_access_key"),
        Some(field("session_token").into()),
        None,
        "startup-fixture",
    )
    .into();
    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    let params = aws_sigv4::sign::v4::SigningParams::builder()
        .identity(&identity)
        .region(field("region"))
        .name("s3")
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let host = url::Url::parse(url).unwrap().authority().to_string();
    let request = SignableRequest::new(
        "PUT",
        url,
        [("host", host.as_str())].into_iter(),
        SignableBody::UnsignedPayload,
    )
    .unwrap();
    let (instructions, _) = sign(request, &params).unwrap().into_parts();
    let parsed = url::Url::parse(url).unwrap();
    let mut wire = format!(
        "PUT {} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10000\r\n",
        parsed.path()
    );
    for (name, value) in instructions.headers() {
        wire.push_str(&format!("{name}: {value}\r\n"));
    }
    wire.push_str("\r\na");
    wire
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "owned Docker PostgreSQL TLS and native executable"]
async fn broker_storage_server_startup_contract() {
    let f = Fixture::new(true).await;
    let mut sql = f.connection().await;
    sql.execute("CREATE ROLE startup_owner LOGIN PASSWORD 'ephemeral-owner' NOSUPERUSER NOCREATEDB NOCREATEROLE; GRANT CONNECT,CREATE ON DATABASE postgres TO startup_owner; GRANT USAGE,CREATE ON SCHEMA public TO startup_owner").await.unwrap();
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='startup_owner'",
    )
    .fetch_one(&mut sql)
    .await
    .unwrap();
    assert!(!superuser);
    let root = tempfile::tempdir().unwrap();
    let address = port();
    let issuer = files(root.path(), &f.ca);
    let config = yaml(address, f.port);
    let path = write_config(root.path(), &config);
    assert!(check(&path).await.status.success());
    assert!(!root.path().join("volume").exists());
    let child = start(&path, address).await;
    seed(&mut sql).await;
    let jwt = native(&issuer);
    let client = reqwest::Client::new();
    for token in [&*jwt, ACCESS, SERVICE] {
        let keys = credentials(address, token).await;
        assert_eq!(keys["region"], "us-east-1");
        assert_eq!(keys["endpoint"], format!("http://{address}"));
        let store = objects(&keys);
        let prefix = keys["prefixes"][0].as_str().unwrap();
        let key = ObjectPath::from(format!("{prefix}/v1/projects/{A}/registry/startup.bin"));
        store
            .put(&key, vec![0x5a; 4 * 1024 * 1024 + 17].into())
            .await
            .unwrap();
        assert_eq!(
            store
                .get(&key)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            vec![0x5a; 4 * 1024 * 1024 + 17].as_slice()
        );
        assert!(
            store
                .get(&ObjectPath::from("outside/denied"))
                .await
                .is_err()
        );
    }
    for token in [
        "gb_at_not-a-real-local-token",
        "gb_sc_not-a-real-local-token",
        "malformed.jwt",
    ] {
        let out = client
            .post(format!("http://{address}/v1/s3/credentials"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body("not-json")
            .send()
            .await
            .unwrap();
        assert_eq!(out.status(), 401);
    }
    let keys = client
        .get(format!("http://{address}/v1/oidc/keys"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let keys: Value = serde_json::from_slice(&keys).unwrap();
    assert_eq!(keys["keys"][0]["kid"], "startup-key");
    assert!(keys["keys"][0].get("d").is_none());
    for route in [
        "/.well-known/openid-configuration",
        "/oauth/token",
        "/admin",
        "/v1/ai/providers",
    ] {
        assert_eq!(
            client
                .get(format!("http://{address}{route}"))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }
    assert!(
        command()
            .args(["--healthcheck", &format!("http://{address}/healthz")])
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    let keys = credentials(address, &jwt).await;
    let prefix = keys["prefixes"][0].as_str().unwrap();
    let stallkey = format!("{prefix}/v1/projects/{A}/registry/stalled.bin");
    let wire = signed_stall(
        &keys,
        &format!("http://{address}/native-storage/{stallkey}"),
    );
    let mut stalled = TcpStream::connect(address).await.unwrap();
    stalled.write_all(wire.as_bytes()).await.unwrap();
    let limit = deadline();
    loop {
        if std::fs::read_dir(root.path().join("volume/tmp"))
            .unwrap()
            .next()
            .is_some()
        {
            break;
        }
        assert!(
            Instant::now() < limit,
            "stalled PUT did not own native temp IO"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut keepalive = TcpStream::connect(address).await.unwrap();
    keepalive
        .write_all(format!("GET /healthz HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = [0; 1024];
    assert!(keepalive.read(&mut response).await.unwrap() > 0);
    terminate(child).await;
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stalled.read_to_end(&mut output))
        .await
        .unwrap()
        .unwrap();
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), keepalive.read_to_end(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert!(TcpStream::connect(address).await.is_err());
    assert_eq!(
        std::fs::read_dir(root.path().join("volume/tmp"))
            .unwrap()
            .count(),
        0
    );
    drop(FilesystemStore::open(volume(root.path())).unwrap());
    let child = start(&path, address).await;
    assert!(
        objects(&credentials(address, SERVICE).await)
            .get(&ObjectPath::from(stallkey.as_str()))
            .await
            .is_err()
    );
    terminate(child).await;
    // An expired shutdown Original remains an error while IO and sockets still join.
    let impatient = config.replace("shutdown_timeout: 3s", "shutdown_timeout: 1ns");
    write_config(root.path(), &impatient);
    let child = start(&path, address).await;
    let timeout_keys = credentials(address, &jwt).await;
    let wire = signed_stall(
        &timeout_keys,
        &format!("http://{address}/native-storage/{stallkey}"),
    );
    let mut timed = TcpStream::connect(address).await.unwrap();
    timed.write_all(wire.as_bytes()).await.unwrap();
    let limit = deadline();
    loop {
        if std::fs::read_dir(root.path().join("volume/tmp"))
            .unwrap()
            .next()
            .is_some()
        {
            break;
        }
        assert!(
            Instant::now() < limit,
            "timeout PUT did not own native temp IO"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop(child, false).await;
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(2), timed.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(
        result.is_ok()
            || result.is_err_and(|e| matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ))
    );
    assert!(TcpStream::connect(address).await.is_err());
    assert_eq!(
        std::fs::read_dir(root.path().join("volume/tmp"))
            .unwrap()
            .count(),
        0
    );
    drop(FilesystemStore::open(volume(root.path())).unwrap());
    write_config(root.path(), &config);
    // Actual bind failure closes SQL and releases the initialized volume.
    let occupied = tokio::net::TcpListener::bind(address).await.unwrap();
    let out = command()
        .args(["--config", path.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        ServerError::Bind.to_string()
    );
    drop(FilesystemStore::open(volume(root.path())).unwrap());
    drop(occupied);
    // A second volume's real exclusive owner fails startup and releases the first volume.
    let mut busy_config = volume(root.path());
    busy_config.directory = root.path().join("other-volume");
    busy_config.bucket = "other-storage".into();
    let busy = FilesystemStore::open(busy_config).unwrap();
    let two = format!(
        "{}    other-fs:\n      driver: filesystem\n      bucket: other-storage\n      base_prefix: graphit\n      directory: other-volume\n",
        config.replace("  routes:", "  default_route: native-fs\n  routes:")
    );
    write_config(root.path(), &two);
    let out = command()
        .args(["--config", path.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        ServerError::Storage.to_string()
    );
    drop(FilesystemStore::open(volume(root.path())).unwrap());
    drop(busy);
    write_config(root.path(), &config);
    let untrusted = ephemeral_ca();
    std::fs::write(root.path().join("ca.pem"), untrusted).unwrap();
    let out = command()
        .args(["--config", path.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        ServerError::Database.to_string()
    );
    assert!(TcpStream::connect(address).await.is_err());
    std::fs::write(root.path().join("ca.pem"), &f.ca).unwrap();
    let disabled = config.replace("enabled: true", "enabled: false");
    write_config(root.path(), &disabled);
    let owner = FilesystemStore::open(volume(root.path())).unwrap();
    let child = start(&path, address).await;
    let disabled = client
        .post(format!("http://{address}/v1/s3/credentials"))
        .body("invalid")
        .send()
        .await
        .unwrap();
    assert_eq!(disabled.status(), 404);
    terminate(child).await;
    drop(owner);
    sql.close().await.unwrap();
    f.shutdown().unwrap();
    let plaintext = Fixture::new(false).await;
    let _issuer = files(root.path(), &plaintext.ca);
    write_config(root.path(), &yaml(address, plaintext.port));
    let out = command()
        .args(["--config", path.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap().trim(),
        ServerError::Database.to_string()
    );
    assert!(TcpStream::connect(address).await.is_err());
    plaintext.shutdown().unwrap();
}
