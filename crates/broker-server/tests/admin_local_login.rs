#[path = "support/upstream_commit.rs"]
mod commit;
#[path = "../../broker-control/tests/support/admin_cookie.rs"]
#[allow(
    dead_code,
    reason = "shared genuine password/cookie fixture serves multiple contracts"
)]
mod cookie;
#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "shared genuine PostgreSQL fixture serves multiple contracts"
)]
mod support;
use cookie::CookieFixture;
use rcgen::KeyPair;
use reqwest::{Client, Response};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::process::{Child, Command};
use zeroize::Zeroizing;

fn block(doc: &str) -> &str {
    doc.split_once("```yaml\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0
}
fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn private_file(path: &Path, bytes: &[u8]) {
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
fn files(root: &Path, ca: &[u8]) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let der = Zeroizing::new(key.serialize_der());
    private_file(&root.join("signing.pk8"), &der);
    private_file(&root.join("ca.pem"), ca);
}
fn yaml(addr: SocketAddr, pg: u16, required: bool) -> String {
    let base = block(include_str!("../../../docs/rust-broker-server.md"))
        .replace("127.0.0.1:8080", &addr.to_string())
        .replace(
            "  public_url: https://broker.example.test",
            &format!("  public_url: http://{addr}"),
        )
        .replace("  host: postgres.example.test", "  host: 127.0.0.1")
        .replace("  port: 5432", &format!("  port: {pg}"))
        .replace("  database: graphit", "  database: postgres")
        .replace(
            "  username: graphit_owner",
            "  username: admin_cookie_owner",
        )
        .replace(
            "\"${BROKER_DATABASE_PASSWORD:?required}\"",
            "ephemeral-owner",
        )
        .replace("postgres-ca.pem", "ca.pem")
        .replace("\"${BROKER_PEPPER:?required}\"", cookie::PEPPER)
        .replace("operation_timeout: 8s", "operation_timeout: 20s");
    let local = block(include_str!("../../../docs/rust-admin-local-login.md"))
        .strip_prefix("auth:\n")
        .unwrap()
        .replace(
            "      required: true",
            if required {
                "      required: true"
            } else {
                "      required: false"
            },
        );
    let base = base.replace("storage:\n", &format!("{local}storage:\n"));
    let admin = block(include_str!("../../../docs/rust-admin-cookie-session.md"))
        .replace("  cookie_secure: true", "  cookie_secure: false")
        .replace("  request_timeout: 3s", "  request_timeout: 20s");
    format!("{base}{admin}")
}
fn write(root: &Path, doc: &str) -> PathBuf {
    let p = root.join("config.yaml");
    private_file(&p, doc.as_bytes());
    p
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
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let end = support::deadline();
    loop {
        if reqwest::get(format!("http://{addr}/readyz"))
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return child;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "native Broker exited before readiness"
        );
        assert!(Instant::now() < end, "native Broker must become ready");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn stop(mut child: Child) {
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
    let exit = tokio::time::timeout(Duration::from_secs(25), child.wait())
        .await
        .unwrap()
        .unwrap();
    #[cfg(unix)]
    assert!(exit.success(), "native Broker must close and join");
    #[cfg(not(unix))]
    let _ = exit;
}
async fn initial(client: &Client, addr: SocketAddr, password: &str) -> Response {
    client
        .post(format!("http://{addr}/admin/auth/local"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&json!({"username":" alice ","password":password})).unwrap())
        .send()
        .await
        .unwrap()
}
async fn next(client: &Client, addr: SocketAddr, value: &Value) -> Response {
    client
        .post(format!("http://{addr}/admin/auth/local/continue"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(value).unwrap())
        .send()
        .await
        .unwrap()
}
async fn data(response: Response, status: u16) -> Value {
    let actual = response.status();
    let path = response.url().path().to_owned();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = Zeroizing::new(response.bytes().await.unwrap().to_vec());
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let stage = match value.get("status").and_then(Value::as_str) {
        Some("password-change") => "password-change",
        Some("mfa") => "mfa",
        Some("mfa-enrollment") => "mfa-enrollment",
        Some("complete") => "complete",
        _ if value.get("csrf_token").is_some() => "session",
        _ => "finite-error-or-other",
    };
    assert!(
        actual == status,
        "native HTTP path={path} actual={actual} expected={status} stage={stage}"
    );
    value
}
async fn denied(response: Response, status: u16, code: &str) {
    assert!(!response.headers().contains_key("set-cookie"));
    let value = data(response, status).await;
    assert_eq!(value["error"]["code"], code);
    let encoded = Zeroizing::new(value.to_string());
    for forbidden in [
        cookie::PEPPER,
        cookie::PASSWORD,
        "ephemeral-owner",
        "SELECT ",
        "otpauth://",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}
fn issued(response: &Response) -> Zeroizing<String> {
    let raw = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    for attribute in ["Path=/", "HttpOnly", "SameSite=Lax", "Expires=", "Max-Age="] {
        assert!(raw.contains(attribute));
    }
    assert!(!raw.contains("; Secure"));
    let raw = raw
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("graphit_admin_session=")
        .unwrap();
    assert_eq!(raw.len(), 43);
    Zeroizing::new(raw.to_owned())
}
async fn session(client: &Client, addr: SocketAddr, raw: &str) -> Response {
    client
        .get(format!("http://{addr}/admin/api/v1/session"))
        .header("Cookie", format!("graphit_admin_session={raw}"))
        .send()
        .await
        .unwrap()
}
fn code(uri: &str, offset: u64) -> Zeroizing<String> {
    let sdk = totp_rs::Totp::from_url(uri).unwrap();
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + offset;
    Zeroizing::new(sdk.generate(seconds).to_string())
}
async fn options_and_inputs(client: &Client, addr: SocketAddr) {
    let value = data(
        client
            .get(format!("http://{addr}/admin/api/v1/login-options"))
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(value, json!({"oidc_providers":[],"local":true}));
    let head = client
        .head(format!("http://{addr}/admin/api/v1/login-options"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert!(head.bytes().await.unwrap().is_empty());
    for (body, media, status, expected) in [
        (
            r#"{"username":"alice","password":"fixture"}"#,
            "text/plain",
            415,
            "content_type_required",
        ),
        (
            r#"{"username":"alice","password":"fixture","purpose":"admin-login"}"#,
            "application/json",
            400,
            "invalid_request",
        ),
        (
            r#"{"username":"alice","password":"fixture","password":"other"}"#,
            "application/json",
            400,
            "invalid_request",
        ),
        (
            r#"{"username":"alice","password":"fixture","captcha_token":null}"#,
            "application/json",
            400,
            "invalid_request",
        ),
    ] {
        denied(
            client
                .post(format!("http://{addr}/admin/auth/local"))
                .header("Content-Type", media)
                .body(body)
                .send()
                .await
                .unwrap(),
            status,
            expected,
        )
        .await;
    }
    denied(
        next(
            client,
            addr,
            &json!({"challenge_token":"bad","new_password":"one","code":"123456"}),
        )
        .await,
        400,
        "invalid_request",
    )
    .await;
    denied(
        initial(client, addr, "incorrect fixture password").await,
        401,
        "local_login_failed",
    )
    .await;
}
async fn exempt_cookie(client: &Client, addr: SocketAddr) -> Zeroizing<String> {
    let response = initial(client, addr, cookie::PASSWORD).await;
    assert_eq!(response.status(), 204);
    let raw = issued(&response);
    assert!(response.bytes().await.unwrap().is_empty());
    let current = data(session(client, addr, &raw).await, 200).await;
    assert_eq!(current["username"], "alice");
    assert_eq!(current["role_source"], "database");
    let csrf = Zeroizing::new(current["csrf_token"].as_str().unwrap().to_owned());
    assert_eq!(csrf.len(), 43);
    let out = client
        .post(format!("http://{addr}/admin/auth/logout"))
        .header("Cookie", format!("graphit_admin_session={}", raw.as_str()))
        .header("X-CSRF-Token", csrf.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 204);
    denied(session(client, addr, &raw).await, 401, "admin_unauthorized").await;
    raw
}
async fn mfa_and_change(f: &mut CookieFixture, client: &Client, addr: SocketAddr) {
    let response = initial(client, addr, cookie::PASSWORD).await;
    assert!(!response.headers().contains_key("set-cookie"));
    let pending = data(response, 200).await;
    assert_eq!(pending["status"], "mfa-enrollment");
    let uri = Zeroizing::new(pending["otpauth_uri"].as_str().unwrap().to_owned());
    assert!(
        pending["qr_code_data_url"]
            .as_str()
            .unwrap()
            .starts_with("data:image/png;base64,")
    );
    assert_eq!(
        totp_rs::Totp::from_url(&uri)
            .unwrap()
            .secret()
            .as_bytes()
            .len(),
        32
    );
    let challenge = Zeroizing::new(pending["challenge_token"].as_str().unwrap().to_owned());
    let response = next(
        client,
        addr,
        &json!({"challenge_token":challenge.as_str(),"code":code(&uri,0).as_str()}),
    )
    .await;
    assert_eq!(response.status(), 200);
    let first = issued(&response);
    let complete = data(response, 200).await;
    assert_eq!(complete["status"], "complete");
    assert_eq!(complete["recovery_codes"].as_array().unwrap().len(), 10);
    let recovery = Zeroizing::new(complete["recovery_codes"][0].as_str().unwrap().to_owned());
    assert_eq!(session(client, addr, &first).await.status(), 200);
    denied(
        next(
            client,
            addr,
            &json!({"challenge_token":challenge.as_str(),"code":code(&uri,0).as_str()}),
        )
        .await,
        401,
        "local_login_step_failed",
    )
    .await;
    let pending = data(initial(client, addr, cookie::PASSWORD).await, 200).await;
    assert_eq!(pending["status"], "mfa");
    let response=next(client,addr,&json!({"challenge_token":pending["challenge_token"].as_str().unwrap(),"code":recovery.as_str()})).await;
    assert_eq!(response.status(), 204);
    let second = issued(&response);
    assert!(response.bytes().await.unwrap().is_empty());
    let pending = data(initial(client, addr, cookie::PASSWORD).await, 200).await;
    let count = f.count().await;
    let rejected = next(client,addr,&json!({"challenge_token":pending["challenge_token"].as_str().unwrap(),"code":recovery.as_str()})).await;
    assert!(!rejected.headers().contains_key("set-cookie"));
    let rejected = data(rejected, 200).await;
    assert_eq!(rejected["status"], "mfa");
    assert!(rejected["recovery_codes"].is_null());
    assert_eq!(f.count().await, count);
    let remaining: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.local_mfa_recovery_codes WHERE subject='alice-subject'",
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(remaining, 9);
    f.admin.execute("UPDATE public.local_users SET password_change_required=1,revision=revision+1 WHERE username='alice'").await.unwrap();
    denied(
        session(client, addr, &second).await,
        401,
        "admin_unauthorized",
    )
    .await;
    let pending = data(initial(client, addr, cookie::PASSWORD).await, 200).await;
    assert_eq!(pending["status"], "password-change");
    let new_password = "new native HTTP fixture password";
    let response=next(client,addr,&json!({"challenge_token":pending["challenge_token"].as_str().unwrap(),"new_password":new_password})).await;
    assert!(!response.headers().contains_key("set-cookie"));
    let pending = data(response, 200).await;
    assert_eq!(pending["status"], "mfa");
    denied(
        initial(client, addr, cookie::PASSWORD).await,
        401,
        "local_login_failed",
    )
    .await;
    let response=next(client,addr,&json!({"challenge_token":pending["challenge_token"].as_str().unwrap(),"code":code(&uri,30).as_str()})).await;
    assert_eq!(response.status(), 204);
    let final_cookie = issued(&response);
    assert!(response.bytes().await.unwrap().is_empty());
    assert_eq!(session(client, addr, &final_cookie).await.status(), 200);
    let state: (i64, i64) = sqlx_core::query_as::query_as(
        "SELECT revision,password_change_required::bigint FROM public.local_users WHERE username='alice'",
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(state, (4, 0));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native executable, PostgreSQL TLS NOSUPERUSER, same-pepper Argon2/MFA, SDK TOTP/recovery/change/cookies and disabled routes"]
async fn broker_admin_local_login_http_contract() {
    let mut f = CookieFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    files(root.path(), &f.fixture.ca);
    let addr = address();
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let config = yaml(addr, f.fixture.port, false);
    let path = write(root.path(), &config);
    let child = start(&path, addr).await;
    options_and_inputs(&client, addr).await;
    let _ = exempt_cookie(&client, addr).await;
    f.admin
        .execute("DELETE FROM public.role_permissions WHERE role='user' AND action='session.read'")
        .await
        .unwrap();
    denied(
        initial(&client, addr, cookie::PASSWORD).await,
        403,
        "admin_forbidden",
    )
    .await;
    f.admin
        .execute("INSERT INTO public.role_permissions(role,action) VALUES('user','session.read')")
        .await
        .unwrap();
    stop(child).await;
    let required = yaml(addr, f.fixture.port, true);
    write(root.path(), &required);
    let child = start(&path, addr).await;
    mfa_and_change(&mut f, &client, addr).await;
    stop(child).await;
    let disabled = required.replace(
        "    login:\n      enabled: true",
        "    login:\n      enabled: false",
    );
    write(root.path(), &disabled);
    let child = start(&path, addr).await;
    let options = data(
        client
            .get(format!("http://{addr}/admin/api/v1/login-options"))
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(options, json!({"oidc_providers":[],"local":false}));
    denied(
        initial(&client, addr, cookie::PASSWORD).await,
        503,
        "administration_unavailable",
    )
    .await;
    denied(
        next(
            &client,
            addr,
            &json!({"challenge_token":"bad","code":"123456"}),
        )
        .await,
        503,
        "administration_unavailable",
    )
    .await;
    stop(child).await;
    let noadmin = disabled.replace(
        "administration:\n  enabled: true",
        "administration:\n  enabled: false",
    );
    write(root.path(), &noadmin);
    let child = start(&path, addr).await;
    assert_eq!(initial(&client, addr, cookie::PASSWORD).await.status(), 404);
    assert_eq!(
        client
            .get(format!("http://{addr}/admin/api/v1/login-options"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    stop(child).await;
    f.engine.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native check-config: sourced defaults/strict validation and no SQL/listener effects"]
async fn broker_admin_local_login_configuration_contract() {
    let root = tempfile::tempdir().unwrap();
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = params.self_signed(&key).unwrap();
    files(root.path(), ca.pem().as_bytes());
    let sql = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = yaml(
        http.local_addr().unwrap(),
        sql.local_addr().unwrap().port(),
        true,
    );
    let omitted = base
        .replace("      max_failures: 5\n", "")
        .replace("      window: 1m\n", "")
        .replace("      lockout: 5m\n", "")
        .replace("      max_concurrent: 2\n", "")
        .replace("      saturation_multiplier: 4\n", "")
        .replace("      required: true\n", "")
        .replace("      issuer_label: Graphit Broker\n", "")
        .replace("      challenge_ttl: 10m\n", "");
    let enabled=base.replace("    captcha:\n      enabled: false", "    captcha:\n      enabled: true\n      provider: turnstile\n      site_key: public-fixture-site\n      secret_key: private-fixture-provider\n      trigger_multiplier: 0\n      verification_timeout: 500ms");
    for (case, config, success) in [
        ("explicit-values", base.clone(), true),
        ("sourced-omissions", omitted, true),
        ("fixed-captcha", enabled.clone(), true),
        (
            "no-local",
            base.replace(
                "    login:\n      enabled: true",
                "    login:\n      enabled: false",
            ),
            true,
        ),
        (
            "missing-cookie",
            base.replace(
                "  cookie:\n    enabled: true",
                "  cookie:\n    enabled: false",
            ),
            false,
        ),
        (
            "no-administration",
            base.replace(
                "administration:\n  enabled: true",
                "administration:\n  enabled: false",
            ),
            false,
        ),
        (
            "zero-workers",
            base.replace("max_concurrent: 2", "max_concurrent: 0"),
            false,
        ),
        (
            "zero-window",
            base.replace("window: 1m", "window: 0s"),
            false,
        ),
        (
            "mfa-ttl-under",
            base.replace("challenge_ttl: 10m", "challenge_ttl: 1m"),
            false,
        ),
        (
            "mfa-ttl-over",
            base.replace("challenge_ttl: 10m", "challenge_ttl: 31m"),
            false,
        ),
        (
            "empty-label",
            base.replace("issuer_label: Graphit Broker", "issuer_label: ' '"),
            false,
        ),
        (
            "sdk-invalid-issuer",
            base.replace(
                "issuer_label: Graphit Broker",
                "issuer_label: 'Broker:invalid'",
            ),
            false,
        ),
        (
            "unknown-provider",
            enabled.replace("provider: turnstile", "provider: unknown"),
            false,
        ),
        (
            "captcha-under",
            enabled.replace("verification_timeout: 500ms", "verification_timeout: 499ms"),
            false,
        ),
        (
            "captcha-over",
            enabled.replace(
                "verification_timeout: 500ms",
                "verification_timeout: 10001ms",
            ),
            false,
        ),
        (
            "captcha-trigger-over",
            enabled.replace("trigger_multiplier: 0", "trigger_multiplier: 5"),
            false,
        ),
        (
            "endpoint-rejected",
            enabled.replace(
                "provider: turnstile",
                "provider: turnstile\n      endpoint: https://other.example.test",
            ),
            false,
        ),
        (
            "second-key-rejected",
            base.replace(
                "      required: true",
                "      required: true\n      key_file: other.key",
            ),
            false,
        ),
    ] {
        let path = write(root.path(), &config);
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            command()
                .args(["--config", path.to_str().unwrap(), "--check-config"])
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success() == success,
            "native check-config case={case} status expectation mismatch"
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains(cookie::PEPPER));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-fixture-provider"));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), sql.accept())
                .await
                .is_err(),
            "check-config must not contact SQL: {case}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), http.accept())
                .await
                .is_err(),
            "check-config must not serve HTTP: {case}"
        );
    }
}

async fn wait_password_locks(admin: &mut sqlx_postgres::PgConnection, count: i64) {
    let end = support::deadline();
    loop {
        let found:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='admin_cookie_owner' AND wait_event_type='Lock' AND query LIKE '%FROM public.local_users WHERE subject=%FOR SHARE%'").fetch_one(&mut *admin).await.unwrap();
        if found >= count {
            return;
        }
        assert!(
            Instant::now() < end,
            "actual password final SQL must reach held user row"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native password admission saturation/lockout, storage faults, current human state and fixed CAPTCHA denial before KDF"]
async fn broker_admin_local_login_failure_contract() {
    let mut f = CookieFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    files(root.path(), &f.fixture.ca);
    let addr = address();
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let config = yaml(addr, f.fixture.port, false)
        .replace("server:\n", "server:\n  body_bytes: 16384\n")
        .replace("max_failures: 5", "max_failures: 2")
        .replace("lockout: 5m", "lockout: 1s")
        .replace("max_concurrent: 2", "max_concurrent: 1")
        .replace("saturation_multiplier: 4", "saturation_multiplier: 2");
    let path = write(root.path(), &config);
    let child = start(&path, addr).await;
    let before = f.count().await;
    let oversized = client
        .post(format!("http://{addr}/admin/auth/local"))
        .header("Content-Type", "application/json")
        .body(
            serde_json::to_vec(
                &json!({"username":"alice","password":"bounded-data".repeat(16384)}),
            )
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert!(!oversized.headers().contains_key("set-cookie"));
    let rejection = data(oversized, 413).await;
    assert!(rejection["error"]["code"].is_string());
    assert!(!rejection.to_string().contains("bounded-data"));
    assert_eq!(f.count().await, before);
    for value in [
        json!({"username":"alice","password":"bounded-data".repeat(400)}),
        json!({"username":"invalid username","password":cookie::PASSWORD}),
        json!({"username":"x".repeat(129),"password":cookie::PASSWORD}),
    ] {
        let rejected = client
            .post(format!("http://{addr}/admin/auth/local"))
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&value).unwrap())
            .send()
            .await
            .unwrap();
        denied(rejected, 401, "local_login_failed").await;
        assert_eq!(f.count().await, before);
    }
    f.admin
        .execute("REVOKE SELECT ON public.local_users FROM admin_cookie_owner")
        .await
        .unwrap();
    denied(
        initial(&client, addr, cookie::PASSWORD).await,
        500,
        "authorization_failed",
    )
    .await;
    f.admin
        .execute("GRANT SELECT ON public.local_users TO admin_cookie_owner")
        .await
        .unwrap();
    denied(
        initial(&client, addr, "incorrect fixture password").await,
        401,
        "local_login_failed",
    )
    .await;
    denied(
        initial(&client, addr, "incorrect fixture password").await,
        401,
        "local_login_failed",
    )
    .await;
    let saturated = initial(&client, addr, cookie::PASSWORD).await;
    assert!(saturated.headers().contains_key("retry-after"));
    denied(saturated, 429, "authentication_rate_limited").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let healthy = initial(&client, addr, cookie::PASSWORD).await;
    assert_eq!(healthy.status(), 204);
    let _ = issued(&healthy);
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; SELECT subject FROM public.local_users WHERE username='alice' FOR UPDATE")
        .await
        .unwrap();
    {
        let first = initial(&client, addr, cookie::PASSWORD);
        let second = initial(&client, addr, cookie::PASSWORD);
        tokio::pin!(first);
        tokio::pin!(second);
        tokio::select! {_=wait_password_locks(&mut f.admin,2)=>{},result=&mut first=>panic!("first actual password work must wait SQL, status {}",result.status()),result=&mut second=>panic!("second actual password work must wait SQL, status {}",result.status())};
        denied(
            initial(&client, addr, cookie::PASSWORD).await,
            429,
            "authentication_rate_limited",
        )
        .await;
        locker.execute("ROLLBACK").await.unwrap();
        assert_eq!(first.await.status(), 204);
        assert_eq!(second.await.status(), 204);
    }
    sqlx_core::connection::Connection::close(locker)
        .await
        .unwrap();
    f.admin
        .execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
        .await
        .unwrap();
    denied(
        initial(&client, addr, cookie::PASSWORD).await,
        401,
        "local_login_failed",
    )
    .await;
    f.admin
        .execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'")
        .await
        .unwrap();
    f.admin
        .execute("REVOKE INSERT ON public.admin_sessions FROM admin_cookie_owner")
        .await
        .unwrap();
    denied(
        initial(&client, addr, cookie::PASSWORD).await,
        500,
        "authorization_failed",
    )
    .await;
    f.admin
        .execute("GRANT INSERT ON public.admin_sessions TO admin_cookie_owner")
        .await
        .unwrap();
    let healthy = initial(&client, addr, cookie::PASSWORD).await;
    assert_eq!(healthy.status(), 204);
    let _ = issued(&healthy);
    let before = f.count().await;
    f.admin
        .execute("UPDATE public.local_users SET identity_kind='service' WHERE username='alice'")
        .await
        .unwrap();
    denied(
        initial(&client, addr, cookie::PASSWORD).await,
        401,
        "local_login_failed",
    )
    .await;
    assert_eq!(f.count().await, before);
    f.admin
        .execute("UPDATE public.local_users SET identity_kind='human' WHERE username='alice'")
        .await
        .unwrap();
    let healthy = initial(&client, addr, cookie::PASSWORD).await;
    assert_eq!(healthy.status(), 204);
    let _ = issued(&healthy);
    let before = f.count().await;
    let unknown = client
        .post(format!("http://{addr}/admin/auth/local"))
        .header("Content-Type", "application/json")
        .body(
            serde_json::to_vec(
                &json!({"username":"unregistered-fixture","password":cookie::PASSWORD}),
            )
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    denied(unknown, 401, "local_login_failed").await;
    assert_eq!(f.count().await, before);
    stop(child).await;
    let captcha=config.replace("    captcha:\n      enabled: false","    captcha:\n      enabled: true\n      provider: turnstile\n      site_key: public-fixture-site\n      secret_key: private-fixture-provider\n      trigger_multiplier: 0\n      verification_timeout: 500ms");
    write(root.path(), &captcha);
    let child = start(&path, addr).await;
    let options = data(
        client
            .get(format!("http://{addr}/admin/api/v1/login-options"))
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(
        options["captcha"],
        json!({"provider":"turnstile","site_key":"public-fixture-site","action":"admin-login"})
    );
    let page = client
        .get(format!("http://{addr}/admin/"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let csp = page.headers()["content-security-policy"].to_str().unwrap();
    assert!(
        csp.contains("script-src 'unsafe-inline' https://challenges.cloudflare.com")
            && csp.contains("frame-src https://challenges.cloudflare.com")
    );
    assert!(!csp.contains("google.com") && !csp.contains("private-fixture-provider"));
    let before = f.count().await;
    let response = initial(&client, addr, cookie::PASSWORD).await;
    assert!(!response.headers().contains_key("set-cookie"));
    let value = data(response, 403).await;
    assert_eq!(value["error"]["code"], "captcha_required");
    assert_eq!(value["captcha"], options["captcha"]);
    assert!(!value.to_string().contains("private-fixture-provider"));
    assert_eq!(f.count().await, before);
    stop(child).await;
    let recaptcha = captcha.replace("provider: turnstile", "provider: recaptcha");
    write(root.path(), &recaptcha);
    let child = start(&path, addr).await;
    let page = client
        .get(format!("http://{addr}/admin/"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let csp = page.headers()["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/") && csp.contains("connect-src 'self' https://www.google.com/recaptcha/") && csp.contains("frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/"));
    assert!(!csp.contains("cloudflare.com") && !csp.contains("private-fixture-provider"));
    stop(child).await;
    let required = config.replace("      required: false", "      required: true");
    write(root.path(), &required);
    let child = start(&path, addr).await;
    let pending = initial(&client, addr, cookie::PASSWORD).await;
    assert!(!pending.headers().contains_key("set-cookie"));
    let pending = data(pending, 200).await;
    assert_eq!(pending["status"], "mfa-enrollment");
    let challenge = Zeroizing::new(pending["challenge_token"].as_str().unwrap().to_owned());
    let before = f.count().await;
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros();
    sqlx_core::query::query(
        "UPDATE public.local_auth_challenges SET expires_at=$1 WHERE subject='alice-subject'",
    )
    .bind(i64::try_from(expiry).unwrap())
    .execute(&mut f.admin)
    .await
    .unwrap();
    denied(
        next(
            &client,
            addr,
            &json!({"challenge_token":challenge.as_str(),"code":"123456"}),
        )
        .await,
        401,
        "local_login_step_failed",
    )
    .await;
    assert_eq!(f.count().await, before);
    let factor_rows: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.local_mfa WHERE subject='alice-subject'",
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(factor_rows, 0);
    stop(child).await;
    f.engine.close().await;
    f.close().await;
}

async fn wait_cookie_role_pid(admin: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = support::deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='admin_cookie_owner' AND wait_event_type='Lock' AND query LIKE '%octet_length(u.username)%' LIMIT 1").fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "actual final cookie SQL must wait on held permissions"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual final-cookie COMMIT idle/TLS ACK withheld after genuine native HTTP password/login, request cancel and Original deadline"]
async fn broker_admin_local_login_uncertainty_contract() {
    let mut f = CookieFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    files(root.path(), &f.fixture.ca);
    let addr = address();
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let base = yaml(addr, f.fixture.port, false);
    let path = write(root.path(), &base);
    let child = start(&path, addr).await;
    let before = f.count().await;
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    {
        use tokio::io::AsyncWriteExt;
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = Zeroizing::new(
            serde_json::to_string(&json!({"username":"alice","password":cookie::PASSWORD}))
                .unwrap(),
        );
        let request = Zeroizing::new(format!(
            "POST /admin/auth/local HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body.as_str()
        ));
        socket.write_all(request.as_bytes()).await.unwrap();
        let pid = wait_cookie_role_pid(&mut f.admin).await;
        drop(socket);
        let end = support::deadline();
        loop {
            let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')").bind(pid).fetch_one(&mut f.admin).await.unwrap();
            if !waiting {
                break;
            }
            assert!(
                Instant::now() < end,
                "disconnected HTTP must release actual pending cookie SQL"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    locker.execute("ROLLBACK").await.unwrap();
    assert_eq!(f.count().await, before);
    sqlx_core::connection::Connection::close(locker)
        .await
        .unwrap();
    let healthy = initial(&client, addr, cookie::PASSWORD).await;
    assert_eq!(healthy.status(), 204);
    let _ = issued(&healthy);
    stop(child).await;
    let deadline_config = base.replace("  request_timeout: 20s", "  request_timeout: 50ms");
    write(root.path(), &deadline_config);
    let child = start(&path, addr).await;
    let before = f.count().await;
    denied(
        initial(&client, addr, cookie::PASSWORD).await,
        504,
        "administration_unavailable",
    )
    .await;
    assert_eq!(f.count().await, before);
    stop(child).await;
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let proxy = base
        .replace(
            &format!("  port: {}", f.fixture.port),
            &format!("  port: {}", relay.port),
        )
        .replace("  request_timeout: 20s", "  request_timeout: 8s");
    write(root.path(), &proxy);
    let child = start(&path, addr).await;
    let before = f.count().await;
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    {
        let pending = initial(&client, addr, cookie::PASSWORD);
        tokio::pin!(pending);
        let pid = tokio::select! {pid=wait_cookie_role_pid(&mut f.admin)=>pid,result=&mut pending=>panic!("real final cookie phase must reach held SQL, status {}",result.status())};
        relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        locker.execute("ROLLBACK").await.unwrap();
        loop {
            let decision = tokio::select! {decision=relay.replies.recv()=>decision.unwrap(),result=&mut pending=>panic!("actual final cookie COMMIT ACK must be withheld, status {}",result.status())};
            let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
                "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
            )
            .bind(pid)
            .fetch_one(&mut f.admin)
            .await
            .unwrap();
            if query == "COMMIT" && idle {
                decision.send(false).unwrap();
                break;
            }
            decision.send(true).unwrap();
        }
        denied(pending.await, 503, "administration_unavailable").await;
    }
    assert_eq!(
        f.count().await,
        before + 1,
        "actual committed session may remain despite missing acknowledgement; no output/retry promise"
    );
    sqlx_core::connection::Connection::close(locker)
        .await
        .unwrap();
    relay.close().await;
    stop(child).await;
    write(root.path(), &base);
    let child = start(&path, addr).await;
    let healthy = initial(&client, addr, cookie::PASSWORD).await;
    assert_eq!(healthy.status(), 204);
    let raw = issued(&healthy);
    assert_eq!(session(&client, addr, &raw).await.status(), 200);
    stop(child).await;
    f.engine.close().await;
    f.close().await;
}
