#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture also serves other SQL suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use broker_control::LocalPasswordEngine;
use broker_security::LocalPasswordHasher;
use rcgen::KeyPair;
use rusqlite::Connection as SqliteConnection;
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
};
use zeroize::Zeroizing;
const PEPPER: &str = "ephemeral-bootstrap-fixture-pepper-32bytes";
const PASSWORD: &str = "  first administrator password  ";
const CHANGED: &str = "changed administrator password";
fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn block(doc: &str) -> &str {
    doc.split_once("\x60\x60\x60yaml\n")
        .unwrap()
        .1
        .split_once("\x60\x60\x60")
        .unwrap()
        .0
}
fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn private(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(bytes).unwrap();
}
fn config(root: &Path, addr: SocketAddr) -> Value {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    private(
        &root.join("signing.pk8"),
        &Zeroizing::new(key.serialize_der()),
    );
    let mut value: Value =
        serde_saphyr::from_str(block(include_str!("../../../docs/rust-broker-server.md"))).unwrap();
    value["server"]["address"] = json!(addr.to_string());
    value["server"]["public_url"] = json!(format!("http://{addr}"));
    value["server"]["shutdown_timeout"] = json!("3s");
    let sqlite_example = include_str!("../../../docs/rust-broker-server.md")
        .split_once("## Select private SQLite")
        .unwrap()
        .1
        .split_once("~~~yaml\n")
        .unwrap()
        .1
        .split_once("~~~")
        .unwrap()
        .0;
    let sqlite: Value = serde_saphyr::from_str(sqlite_example).unwrap();
    value["database"] = sqlite["database"].clone();
    value["auth"]["issuer"] = json!(format!("http://{addr}"));
    value["auth"]["pepper"] = json!(PEPPER);
    value["auth"].as_object_mut().unwrap().remove("resource");
    value["storage"]["routes"] = json!({"native-fs":{"driver":"filesystem","bucket":"native-storage","base_prefix":"graphit","directory":"volume"}});
    value["storage"]["default_route"] = json!("native-fs");
    value
}
fn write(root: &Path, value: &Value) -> PathBuf {
    let path = root.join("broker.json");
    private(&path, &serde_json::to_vec(value).unwrap());
    path
}
fn command() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphit-broker"));
    c.kill_on_drop(true);
    c
}
async fn start(path: &Path, addr: SocketAddr) -> Child {
    let mut child = command()
        .args(["--config", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let original = end();
    loop {
        if reqwest::get(format!("http://{addr}/readyz"))
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return child;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().await.unwrap();
            assert!(!String::from_utf8_lossy(&output.stderr).contains(PEPPER));
            panic!(
                "native SQLite Broker exited before ready: {status}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            Instant::now() < original,
            "native SQLite readiness deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn stop(mut child: Child, success: bool) {
    #[cfg(unix)]
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().unwrap().to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    #[cfg(not(unix))]
    child.kill().await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .unwrap()
        .unwrap();
    #[cfg(unix)]
    assert_eq!(status.success(), success, "native process close outcome");
    #[cfg(not(unix))]
    let _ = (status, success);
}
fn local_admin(value: &mut Value) {
    let local: Value = serde_saphyr::from_str(block(include_str!(
        "../../../docs/rust-admin-local-login.md"
    )))
    .unwrap();
    value["auth"]["local"] = local["auth"]["local"].clone();
    let admin: Value = serde_saphyr::from_str(block(include_str!(
        "../../../docs/rust-admin-cookie-session.md"
    )))
    .unwrap();
    value["administration"] = admin["administration"].clone();
    value["administration"]["cookie_secure"] = json!(false);
    value["administration"]["request_timeout"] = json!("20s");
    value["database"]["operation_timeout"] = json!("20s");
}
async fn data(response: reqwest::Response, status: u16) -> Value {
    assert_eq!(response.status(), status, "{}", response.url().path());
    let bytes = Zeroizing::new(response.bytes().await.unwrap().to_vec());
    serde_json::from_slice(&bytes).unwrap()
}
fn cookie(response: &reqwest::Response) -> Zeroizing<String> {
    let value = response.headers()["set-cookie"].to_str().unwrap();
    assert!(value.contains("HttpOnly") && value.contains("SameSite=Lax"));
    assert!(!value.contains("; Secure"));
    Zeroizing::new(value.split(';').next().unwrap().to_owned())
}
async fn bootstrap(path: &Path, bytes: &[u8]) -> std::process::Output {
    let mut child = command()
        .args([
            "--config",
            path.to_str().unwrap(),
            "--bootstrap-admin-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(bytes).await.unwrap();
    input.shutdown().await.unwrap();
    drop(input);
    tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .unwrap()
        .unwrap()
}
fn output_has_no_secrets(output: &std::process::Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        for secret in [PASSWORD, CHANGED, PEPPER, "$argon2id$"] {
            assert!(!text.contains(secret));
        }
    }
}
fn already_initialized(output: &std::process::Output) {
    output_has_no_secrets(output);
    assert!(!output.status.success());
    assert_eq!(
        output.stderr,
        b"local user catalog is already initialized\n"
    );
    assert!(output.stdout.is_empty());
}
async fn verify_password(hash: String, raw: &str) {
    let hasher = LocalPasswordHasher::new(Zeroizing::new(
        PEPPER.as_bytes().to_vec().into_boxed_slice(),
    ))
    .unwrap();
    let engine = LocalPasswordEngine::new(hasher, n(1), end()).await.unwrap();
    assert!(engine.verify(raw, Some(&hash), end()).await.unwrap());
    engine.close().await;
}
async fn admin_journey(path: &Path, addr: SocketAddr, required: bool) {
    let child = start(path, addr).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .unwrap();
    let base = format!("http://{addr}");
    let response = client
        .post(format!("{base}/admin/auth/local"))
        .header("content-type", "application/json")
        .body(json!({"username":"admin","password":PASSWORD}).to_string())
        .send()
        .await
        .unwrap();
    assert!(!response.headers().contains_key("set-cookie"));
    let pending = data(response, 200).await;
    assert_eq!(pending["status"], "password-change");
    let response = client
        .post(format!("{base}/admin/auth/local/continue"))
        .header("content-type", "application/json")
        .body(
            json!({"challenge_token":pending["challenge_token"],"new_password":CHANGED})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    let response = if required {
        assert!(!response.headers().contains_key("set-cookie"));
        let enrollment = data(response, 200).await;
        assert_eq!(enrollment["status"], "mfa-enrollment");
        let uri = Zeroizing::new(enrollment["otpauth_uri"].as_str().unwrap().to_owned());
        let sdk = totp_rs::Totp::from_url(&uri).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = Zeroizing::new(sdk.generate(now).to_string());
        client
            .post(format!("{base}/admin/auth/local/continue"))
            .header("content-type", "application/json")
            .body(
                json!({"challenge_token":enrollment["challenge_token"],"code":code.as_str()})
                    .to_string(),
            )
            .send()
            .await
            .unwrap()
    } else {
        response
    };
    let session_cookie = cookie(&response);
    if required {
        let complete = data(response, 200).await;
        assert_eq!(complete["status"], "complete");
        assert_eq!(complete["recovery_codes"].as_array().unwrap().len(), 10);
    } else {
        // Mature cookie completion without new recovery codes is 204.
        assert_eq!(response.status(), 204);
        assert!(response.bytes().await.unwrap().is_empty());
    }
    let session = data(
        client
            .get(format!("{base}/admin/api/v1/session"))
            .header("cookie", session_cookie.as_str())
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(session["username"], "admin");
    assert_eq!(session["role_source"], "database");
    assert!(
        session["roles"]
            .as_array()
            .unwrap()
            .contains(&json!("admin"))
    );
    assert_eq!(
        client
            .get(format!("{base}/admin/api/v1/config"))
            .header("cookie", session_cookie.as_str())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .post(format!("{base}/admin/auth/logout"))
            .header("cookie", session_cookie.as_str())
            .header("x-csrf-token", session["csrf_token"].as_str().unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    stop(child, true).await;
}
#[tokio::test]
async fn sqlite_cli_empty_database_to_changed_password_and_admin_cookie() {
    for required in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let addr = address();
        let mut value = config(root.path(), addr);
        local_admin(&mut value);
        value["auth"]["local"]["mfa"]["required"] = json!(required);
        let path = write(root.path(), &value);
        // The bootstrap must not bind a listener or create storage volumes.
        let occupied = std::net::TcpListener::bind(addr).unwrap();
        let output = bootstrap(&path, format!("{PASSWORD}\r\n").as_bytes()).await;
        output_has_no_secrets(&output);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"local administrator created\n");
        assert!(!root.path().join("volume").exists());
        drop(occupied);
        let dbpath = root.path().join("private/broker.db");
        let db = SqliteConnection::open(&dbpath).unwrap();
        let row: (String,String,String,String,i64,i64,i64) = db.query_row("SELECT username,subject,identity_kind,password_hash,enabled,password_change_required,revision FROM local_users", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).unwrap();
        assert_eq!(
            (&*row.0, &*row.1, &*row.2, row.4, row.5, row.6),
            ("admin", "admin", "human", 1, 1, 1)
        );
        assert_eq!(db.query_row("SELECT (SELECT count(*) FROM admin_sessions)+(SELECT count(*) FROM resource_grants)+(SELECT count(*) FROM local_tokens)", [], |r| r.get::<_,i64>(0)).unwrap(),0);
        assert!(row.3.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
        assert_eq!(db.query_row("SELECT count(*) FROM role_assignments WHERE subject='local|admin' AND role='admin'",[],|r|r.get::<_,i64>(0)).unwrap(),1);
        assert_eq!(
            db.query_row("SELECT count(*) FROM role_assignments", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM local_mfa", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        drop(db);
        verify_password(row.3.clone(), PASSWORD).await;
        let second = bootstrap(&path, PASSWORD.as_bytes()).await;
        output_has_no_secrets(&second);
        assert!(!second.status.success());
        let db = SqliteConnection::open(&dbpath).unwrap();
        assert_eq!(
            db.query_row("SELECT password_hash FROM local_users", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            row.3
        );
        drop(db);
        admin_journey(&path, addr, required).await;
        let db = SqliteConnection::open(&dbpath).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT password_change_required FROM local_users",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM local_mfa", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            i64::from(required)
        );
        let changed: String = db
            .query_row("SELECT password_hash FROM local_users", [], |r| r.get(0))
            .unwrap();
        drop(db);
        verify_password(changed, CHANGED).await;
    }
}

#[tokio::test]
#[ignore = "real PostgreSQL TLS binary bootstrap, password change, MFA and database-backed admin cookie"]
async fn postgres_cli_empty_database_to_changed_password_and_admin_cookie() {
    let fixture = support::Fixture::new(true).await;
    let mut conn = fixture.connection().await;
    conn.execute("CREATE ROLE first_admin_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'")
        .await
        .unwrap();
    conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION first_admin_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO first_admin_owner").await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let mut value = config(root.path(), addr);
    let base: Value =
        serde_saphyr::from_str(block(include_str!("../../../docs/rust-broker-server.md"))).unwrap();
    value["database"] = base["database"].clone();
    value["database"]["host"] = json!("127.0.0.1");
    value["database"]["port"] = json!(fixture.port);
    value["database"]["database"] = json!("postgres");
    value["database"]["username"] = json!("first_admin_owner");
    value["database"]["password"] = json!("ephemeral-owner");
    value["database"]["ca_file"] = json!("ca.pem");
    private(&root.path().join("ca.pem"), &fixture.ca);
    local_admin(&mut value);
    value["database"]
        .as_object_mut()
        .unwrap()
        .remove("operation_timeout");
    value["database"]["pool"]["operation_timeout"] = json!("20s");
    let path = write(root.path(), &value);
    let occupied = std::net::TcpListener::bind(addr).unwrap();
    let (a, b) = tokio::join!(
        bootstrap(&path, PASSWORD.as_bytes()),
        bootstrap(&path, PASSWORD.as_bytes())
    );
    output_has_no_secrets(&a);
    output_has_no_secrets(&b);
    assert_ne!(
        a.status.success(),
        b.status.success(),
        "only one CLI may initialize"
    );
    already_initialized(if a.status.success() { &b } else { &a });
    drop(occupied);
    assert!(!root.path().join("volume").exists());
    let row: (String,String,String,String,i64,i64,i64) = sqlx_core::query_as::query_as("SELECT username,subject,identity_kind,password_hash,enabled::bigint,password_change_required::bigint,revision FROM local_users").fetch_one(&mut conn).await.unwrap();
    assert_eq!(
        (&*row.0, &*row.1, &*row.2, row.4, row.5, row.6),
        ("admin", "admin", "human", 1, 1, 1)
    );
    let assignments: Vec<(String, String)> =
        sqlx_core::query_as::query_as("SELECT subject,role FROM role_assignments")
            .fetch_all(&mut conn)
            .await
            .unwrap();
    assert_eq!(assignments, vec![("local|admin".into(), "admin".into())]);
    let factors: i64 = sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM local_mfa")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(factors, 0);
    let extra: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT (SELECT count(*) FROM admin_sessions)+(SELECT count(*) FROM resource_grants)+(SELECT count(*) FROM local_tokens)",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    assert_eq!(extra, 0);
    verify_password(row.3, PASSWORD).await;
    let second = bootstrap(&path, PASSWORD.as_bytes()).await;
    assert!(!second.status.success());
    output_has_no_secrets(&second);
    admin_journey(&path, addr, true).await;
    let flag: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT password_change_required::bigint FROM local_users",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    assert_eq!(flag, 0);
    let changed: String =
        sqlx_core::query_scalar::query_scalar("SELECT password_hash FROM local_users")
            .fetch_one(&mut conn)
            .await
            .unwrap();
    verify_password(changed, CHANGED).await;
    conn.close().await.unwrap();
    fixture.shutdown().unwrap();
}
#[tokio::test]
async fn sqlite_cli_invalid_input_and_configuration_have_no_side_effects() {
    for invalid in [
        Vec::new(),
        b"short".to_vec(),
        vec![0xff; 32],
        vec![b'x'; 4099],
    ] {
        let root = tempfile::tempdir().unwrap();
        let addr = address();
        let mut value = config(root.path(), addr);
        local_admin(&mut value);
        let path = write(root.path(), &value);
        let output = bootstrap(&path, &invalid).await;
        assert!(!output.status.success());
        output_has_no_secrets(&output);
        assert!(!root.path().join("private").exists());
        assert!(!root.path().join("volume").exists());
    }
    for missing in [
        "local",
        "administration",
        "cookie",
        "local-disabled",
        "admin-disabled",
    ] {
        let root = tempfile::tempdir().unwrap();
        let addr = address();
        let mut value = config(root.path(), addr);
        local_admin(&mut value);
        match missing {
            "local-disabled" => {
                value["auth"]["local"]["enabled"] = json!(false);
            }
            "admin-disabled" => {
                value["administration"]["enabled"] = json!(false);
            }
            "local" => {
                value["auth"].as_object_mut().unwrap().remove("local");
            }
            "administration" => {
                value.as_object_mut().unwrap().remove("administration");
            }
            _ => {
                value["administration"]["cookie"]["enabled"] = json!(false);
            }
        }
        let path = write(root.path(), &value);
        let output = bootstrap(&path, PASSWORD.as_bytes()).await;
        assert!(!output.status.success(), "missing {missing} must fail");
        output_has_no_secrets(&output);
        assert!(!root.path().join("private").exists());
        assert!(!root.path().join("volume").exists());
    }
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let mut value = config(root.path(), addr);
    local_admin(&mut value);
    let path = write(root.path(), &value);
    for mode in ["--check-config", "--healthcheck"] {
        let output = command()
            .args([
                "--config",
                path.to_str().unwrap(),
                "--bootstrap-admin-stdin",
                mode,
            ])
            .output()
            .await
            .unwrap();
        assert!(!output.status.success());
        assert!(!root.path().join("private").exists());
    }
    // Rejection at the concrete byte bound cannot wait for an unclosed input stream.
    let mut child = command()
        .args([
            "--config",
            path.to_str().unwrap(),
            "--bootstrap-admin-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(&vec![b'x'; 4099]).await.unwrap();
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    output_has_no_secrets(&output);
    drop(input);
    assert!(!root.path().join("private").exists());
}
#[tokio::test]
async fn sqlite_cli_concurrent_initializers_create_only_one_administrator() {
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let mut value = config(root.path(), addr);
    local_admin(&mut value);
    let path = write(root.path(), &value);
    let (a, b) = tokio::join!(
        bootstrap(&path, PASSWORD.as_bytes()),
        bootstrap(&path, PASSWORD.as_bytes())
    );
    output_has_no_secrets(&a);
    output_has_no_secrets(&b);
    assert_ne!(a.status.success(), b.status.success());
    already_initialized(if a.status.success() { &b } else { &a });
    let second = bootstrap(&path, PASSWORD.as_bytes()).await;
    already_initialized(&second);
    let db = SqliteConnection::open(root.path().join("private/broker.db")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM local_users", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM role_assignments", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
