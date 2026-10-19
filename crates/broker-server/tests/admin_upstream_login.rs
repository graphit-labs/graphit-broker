//! Native H3 adapters: actual binary, TLS NOSUPERUSER SQL and HTTPS OIDC issuer.
#[allow(
    dead_code,
    reason = "shared HTTPS producer also serves H1 fault contracts"
)]
#[path = "../../broker-control/tests/support/browser_upstream.rs"]
mod browser;
#[allow(
    dead_code,
    reason = "shared SQL configuration also serves producer tests"
)]
#[path = "../../broker-control/tests/support/browser_sql.rs"]
mod browser_sql;
#[path = "support/admin_read_commit.rs"]
mod commit;
#[allow(
    dead_code,
    reason = "shared owned PostgreSQL fixtures serve multiple suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use browser::{BrowserIssuer, ClientAuth, ClientRegistration, Fault};
use browser_sql::BrowserSql;
use rcgen::KeyPair;
use reqwest::{Client, Response, cookie::Jar};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::process::{Child, Command};
use url::Url;
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
fn configuration(addr: SocketAddr, pg: u16, issuer: &BrowserIssuer) -> String {
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
            "  username: browser_login_owner",
        )
        .replace(
            "\"${BROKER_DATABASE_PASSWORD:?required}\"",
            "ephemeral-browser",
        )
        .replace("postgres-ca.pem", "ca.pem")
        .replace(
            "\"${BROKER_PEPPER:?required}\"",
            "fixture-browser-pepper-with-at-least-32-bytes",
        );
    let upstream = block(include_str!("../../../docs/rust-admin-upstream-login.md"))
        .strip_prefix("auth:\n")
        .unwrap()
        .replace("https://issuer.example.test", &issuer.issuer)
        .replace(
            "https://broker.example.test/oauth/oidc/callback",
            &format!("http://{addr}/oauth/oidc/callback"),
        )
        .replace(
            "\"${BROKER_BROWSER_CLIENT_SECRET:?required}\"",
            "fixture-confidential-secret",
        );
    let base = base.replace("storage:\n", &format!("{upstream}storage:\n"));
    let cookie = block(include_str!("../../../docs/rust-admin-cookie-session.md"))
        .replace("  cookie_secure: true", "  cookie_secure: false");
    format!("{base}{cookie}")
}
fn command() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphit-broker"));
    c.kill_on_drop(true);
    c
}
async fn start(config: &Path, addr: SocketAddr) -> Child {
    let mut child = command()
        .args(["--config", config.to_str().unwrap()])
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
    let status = tokio::time::timeout(Duration::from_secs(25), child.wait())
        .await
        .unwrap()
        .unwrap();
    #[cfg(unix)]
    assert!(status.success(), "native server must drain and close");
    #[cfg(not(unix))]
    let _ = status;
}
async fn assign_admin(admin: &mut sqlx_postgres::PgConnection, issuer: &str) {
    sqlx_core::query::query(
        "INSERT INTO public.role_assignments(subject,role,created_at) VALUES($1,'admin',0)",
    )
    .bind(format!("{issuer}|id-user"))
    .execute(admin)
    .await
    .unwrap();
}
struct Native {
    sql: BrowserSql,
    issuer: BrowserIssuer,
    root: tempfile::TempDir,
    path: PathBuf,
    config: String,
    addr: SocketAddr,
    child: Option<Child>,
}
impl Native {
    async fn new() -> Self {
        Self::with_issuer(BrowserIssuer::new().await, false).await
    }
    async fn with_issuer(issuer: BrowserIssuer, loopback_browser: bool) -> Self {
        let mut sql = BrowserSql::new().await;
        assign_admin(&mut sql.admin, &issuer.issuer).await;
        let root = tempfile::tempdir().unwrap();
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        private_file(
            &root.path().join("signing.pk8"),
            &Zeroizing::new(key.serialize_der()),
        );
        private_file(&root.path().join("ca.pem"), &sql.fixture.ca);
        private_file(&root.path().join("browser-ca.pem"), &issuer.ca);
        let addr = address();
        for (id, secret, auth) in [
            ("graphit-admin", None, ClientAuth::Public),
            (
                "graphit-admin-confidential",
                Some("fixture-confidential-secret".into()),
                ClientAuth::Basic,
            ),
        ] {
            issuer.register(ClientRegistration {
                id: id.into(),
                secret,
                redirect: format!("http://{addr}/oauth/oidc/callback"),
                auth,
            });
        }
        let config = configuration(addr, sql.fixture.port, &issuer);
        let config = if loopback_browser {
            assert!(issuer.issuer.starts_with("http://127.0.0.1:"));
            config.replace("allow_loopback_http: false", "allow_loopback_http: true")
        } else {
            assert!(issuer.issuer.starts_with("https://127.0.0.1:"));
            config
        };
        let path = root.path().join("config.yaml");
        private_file(&path, config.as_bytes());
        let child = Some(start(&path, addr).await);
        Self {
            sql,
            issuer,
            root,
            path,
            config,
            addr,
            child,
        }
    }
    fn client(&self) -> Client {
        Client::builder()
            .cookie_provider(Arc::new(Jar::default()))
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(&self.issuer.ca).unwrap())
            .build()
            .unwrap()
    }
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
    fn login_url(&self, provider: &str) -> Url {
        let mut url = Url::parse(&self.url("/admin/auth/login")).unwrap();
        url.query_pairs_mut().append_pair("provider", provider);
        url
    }
    async fn options(&self, client: &Client) -> Value {
        document(
            client
                .get(self.url("/admin/api/v1/login-options"))
                .send()
                .await
                .unwrap(),
            200,
        )
        .await
    }
    async fn begin(&self, client: &Client, provider: &str) -> (Url, String) {
        let response = client.get(self.login_url(provider)).send().await.unwrap();
        assert_eq!(response.status(), 302);
        no_auth_cookie(&response);
        let binding = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .find_map(|v| {
                v.to_str()
                    .ok()
                    .filter(|s| s.starts_with("graphit_oidc_flow_"))
                    .map(str::to_owned)
            })
            .unwrap();
        assert!(
            binding.contains("; Path=/; HttpOnly; SameSite=Lax;") && binding.contains("Max-Age=")
        );
        (
            Url::parse(response.headers()["location"].to_str().unwrap()).unwrap(),
            binding,
        )
    }
    async fn authorize(&self, client: &Client, location: Url) -> Url {
        let response = client
            .get(location)
            .basic_auth("browser-fixture", Some("fixture-password"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            302,
            "actual credential/PKCE authorization"
        );
        Url::parse(response.headers()["location"].to_str().unwrap()).unwrap()
    }
    async fn restart(&mut self, config: String) {
        stop(self.child.take().unwrap()).await;
        private_file(&self.path, config.as_bytes());
        self.child = Some(start(&self.path, self.addr).await);
    }
    async fn close(mut self) {
        stop(self.child.take().unwrap()).await;
        self.issuer.close().await;
        self.sql.close().await;
        self.root.close().unwrap();
    }
}
async fn document(response: Response, status: u16) -> Value {
    assert_eq!(response.status().as_u16(), status);
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}
fn no_auth_cookie(response: &Response) {
    assert!(
        !response.headers().get_all("set-cookie").iter().any(|v| v
            .to_str()
            .is_ok_and(|s| s.starts_with("graphit_admin_session="))),
        "failure must not emit authentication cookie"
    );
}
async fn invalid_state(response: Response) {
    no_auth_cookie(&response);
    assert_eq!(
        document(response, 401).await["error"]["code"],
        "invalid_state"
    );
}
fn login_error(response: &Response, code: &str) {
    assert_eq!(response.status(), 303);
    no_auth_cookie(response);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(
        location.starts_with(&format!("/admin/#login_error={code}&request_id=")),
        "fixed finite Admin error continuation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual binary, TLS PostgreSQL NOSUPERUSER, real HTTPS code exchange and cookie Jar"]
async fn broker_admin_upstream_login_http_contract() {
    let mut h = Native::new().await;
    let client = h.client();
    let options = h.options(&client).await;
    assert_eq!(options["local"], false);
    assert_eq!(options["oidc_providers"].as_array().unwrap().len(), 2);
    assert_eq!(options["oidc_providers"][0]["name"], "Workforce");
    assert_eq!(
        options["oidc_providers"][1]["name"],
        "Workforce confidential"
    );
    let provider = options["oidc_providers"][0]["id"].as_str().unwrap();
    assert_eq!(
        client
            .get(h.url("/admin/auth/options"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let head = client
        .head(h.url("/admin/api/v1/login-options"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert!(head.bytes().await.unwrap().is_empty());
    for path in ["/admin", "/admin/"] {
        let response = client.get(h.url(path)).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-src 'none'")
        );
        let html = response.text().await.unwrap();
        assert!(
            html.contains("/admin/api/v1/login-options") && html.contains("/admin/api/v1/projects")
        );
        assert!(
            client
                .head(h.url(path))
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        client
            .head(h.url("/admin/auth/login"))
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    assert_eq!(
        client
            .get(h.url("/admin/auth/login?provider=untrusted"))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let (first, binding) = h.begin(&client, provider).await;
    let (second, other_binding) = h.begin(&client, provider).await;
    assert_ne!(
        binding.split_once('=').unwrap().0,
        other_binding.split_once('=').unwrap().0,
        "parallel flow cookies have distinct names"
    );
    let first = h.authorize(&client, first).await;
    let second = h.authorize(&client, second).await;
    invalid_state(h.client().get(first.clone()).send().await.unwrap()).await;
    for callback in [second, first.clone()] {
        let response = client.get(callback).send().await.unwrap();
        assert_eq!(response.status(), 303);
        assert_eq!(response.headers()["location"], "/admin/");
        assert!(response.headers().get_all("set-cookie").iter().any(|v| {
            v.to_str()
                .is_ok_and(|v| v.starts_with("graphit_admin_session=") && v.contains("HttpOnly"))
        }));
        assert!(response.headers().get_all("set-cookie").iter().any(|v| {
            v.to_str()
                .is_ok_and(|v| v.starts_with("graphit_oidc_flow_") && v.contains("Max-Age=0"))
        }));
    }
    invalid_state(client.get(first).send().await.unwrap()).await;
    let session = document(
        client
            .get(h.url("/admin/api/v1/session"))
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(
        session["subject"], "id-user",
        "session identity uses the configured verified subject selector"
    );
    assert_eq!(session["username"], "id-user");
    assert_eq!(session["name"], "ID Name");
    assert_eq!(
        h.issuer.userinfo_hits(),
        0,
        "complete profile needs no UserInfo poll"
    );
    for route in [
        "projects",
        "roles",
        "role-assignments",
        "local-users",
        "principals",
        "grants",
        "config",
    ] {
        let path = format!("/admin/api/v1/{route}");
        let response = client.get(h.url(&path)).send().await.unwrap();
        assert_eq!(response.status(), 200, "real read loader {route}");
        assert!(response.headers().get("set-cookie").is_none());
        let bytes = response.bytes().await.unwrap();
        let _: Value = serde_json::from_slice(&bytes).unwrap();
        if route == "config" {
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(
                !text.contains("fixture-confidential-secret")
                    && text.contains("[configured-secret]")
            );
        }
        let head = client.head(h.url(&path)).send().await.unwrap();
        assert_eq!(head.status(), 200);
        assert!(head.bytes().await.unwrap().is_empty());
    }
    assert_eq!(
        client
            .post(h.url("/admin/auth/logout"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let csrf = session["csrf_token"].as_str().unwrap();
    let logout = client
        .post(h.url("/admin/auth/logout"))
        .header("x-csrf-token", csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), 204);
    assert_eq!(
        client
            .get(h.url("/admin/api/v1/session"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    for fault in [
        Fault {
            wrong_signature: true,
            ..Fault::default()
        },
        Fault {
            omit_id: true,
            ..Fault::default()
        },
        Fault {
            extra_audiences: vec!["not-trusted".into()],
            ..Fault::default()
        },
        Fault {
            id_overrides: [("azp".into(), json!("not-this-client"))].into(),
            ..Fault::default()
        },
        Fault {
            id_overrides: [("sub".into(), json!(""))].into(),
            ..Fault::default()
        },
    ] {
        let browser = h.client();
        let (location, _) = h.begin(&browser, provider).await;
        let callback = h.authorize(&browser, location).await;
        h.issuer.fault(fault);
        login_error(
            &browser.get(callback).send().await.unwrap(),
            "invalid_identity",
        );
        assert_eq!(
            browser
                .get(h.url("/admin/api/v1/session"))
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        h.issuer.fault(Fault::default());
    }
    let browser = h.client();
    let (location, _) = h.begin(&browser, provider).await;
    let mut callback = h.authorize(&browser, location).await;
    callback
        .query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("error_description", "untrusted diagnostic");
    let response = browser
        .get(callback)
        .header("x-request-id", "a&login_error=evil#fragment")
        .send()
        .await
        .unwrap();
    login_error(&response, "oidc_error");
    assert!(
        !response.headers()["location"]
            .to_str()
            .unwrap()
            .contains("untrusted diagnostic")
    );
    assert!(
        response.headers()["location"]
            .to_str()
            .unwrap()
            .contains("a%26login_error%3Devil%23fragment")
    );
    let mut userinfo_config: Value = serde_saphyr::from_str(&h.config).unwrap();
    userinfo_config["auth"]["oidc"][0]["browser_clients"][0]["claims_source"] = json!("userinfo");
    h.restart(serde_json::to_string(&userinfo_config).unwrap())
        .await;
    let complete = h.client();
    let (location, _) = h.begin(&complete, provider).await;
    let callback = h.authorize(&complete, location).await;
    assert_eq!(complete.get(callback).send().await.unwrap().status(), 303);
    assert_eq!(
        h.issuer.userinfo_hits(),
        0,
        "configured UserInfo still skips a complete primary profile"
    );
    let browser = h.client();
    let (location, _) = h.begin(&browser, provider).await;
    let callback = h.authorize(&browser, location).await;
    h.issuer.fault(Fault {
        missing_profile: true,
        ..Fault::default()
    });
    assert_eq!(browser.get(callback).send().await.unwrap().status(), 303);
    let profile = document(
        browser
            .get(h.url("/admin/api/v1/session"))
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(profile["name"], "Supplementary Name");
    assert_eq!(profile["subject"], "id-user");
    assert_eq!(
        h.issuer.userinfo_hits(),
        1,
        "only missing profile invokes real UserInfo"
    );
    h.issuer.fault(Fault::default());
    assert_eq!(
        browser
            .get(h.url("/admin/api/v1/session"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        h.issuer.userinfo_hits(),
        1,
        "cookie validity does not poll UserInfo"
    );
    h.sql.admin.execute("DELETE FROM public.role_assignments; DELETE FROM public.role_permissions WHERE role='user' AND action='session.read'; INSERT INTO public.role_assignments(subject,role,created_at) VALUES('unrelated-subject','admin',0)").await.unwrap();
    let denied = h.client();
    let (location, _) = h.begin(&denied, provider).await;
    let callback = h.authorize(&denied, location).await;
    login_error(
        &denied.get(callback).send().await.unwrap(),
        "admin_forbidden",
    );
    assert_eq!(
        browser
            .get(h.url("/admin/api/v1/session"))
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "existing cookie observes current roles"
    );
    h.sql
        .admin
        .execute("DELETE FROM public.role_assignments")
        .await
        .unwrap();
    assign_admin(&mut h.sql.admin, &h.issuer.issuer).await;
    h.sql
        .admin
        .execute("INSERT INTO public.role_permissions(role,action) VALUES('user','session.read')")
        .await
        .unwrap();
    h.restart(h.config.clone()).await;
    let confidential = options["oidc_providers"][1]["id"].as_str().unwrap();
    let browser = h.client();
    let (location, _) = h.begin(&browser, confidential).await;
    let callback = h.authorize(&browser, location).await;
    assert_eq!(browser.get(callback).send().await.unwrap().status(), 303);
    assert_eq!(
        browser
            .get(h.url("/admin/api/v1/session"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let mut trusted: Value = serde_saphyr::from_str(&h.config).unwrap();
    trusted["auth"]["oidc"][0]["browser_clients"][1]["require_nonce"] = json!(false);
    trusted["auth"]["oidc"][0]["browser_clients"][1]["id_token_additional_audiences"] =
        json!(["explicit-extra"]);
    h.restart(serde_json::to_string(&trusted).unwrap()).await;
    h.issuer.fault(Fault {
        extra_audiences: vec!["explicit-extra".into()],
        ..Fault::default()
    });
    let extra = h.client();
    let (location, _) = h.begin(&extra, confidential).await;
    assert!(
        !location.query_pairs().any(|(key, _)| key == "nonce"),
        "explicit native nonce opt-out reaches the existing producer"
    );
    let callback = h.authorize(&extra, location).await;
    assert_eq!(
        extra.get(callback).send().await.unwrap().status(),
        303,
        "explicit native additional audience reaches mature ID verification"
    );
    assert_eq!(
        extra
            .get(h.url("/admin/api/v1/session"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    h.issuer.fault(Fault::default());
    trusted["auth"]["oidc"][0]["browser_clients"] = json!([]);
    h.restart(serde_json::to_string(&trusted).unwrap()).await;
    assert!(
        h.options(&extra).await["oidc_providers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        extra
            .get(h.url("/admin/api/v1/session"))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "removing only browser clients retains current issuer cookie trust"
    );
    assert_eq!(
        extra
            .get(h.login_url(confidential))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    h.restart(h.config.clone()).await;
    let pending = h.client();
    let (location, _) = h.begin(&pending, provider).await;
    let callback = h.authorize(&pending, location).await;
    h.restart(h.config.replace(
        "    - id: workforce\n      enabled: true",
        "    - id: workforce\n      enabled: false",
    ))
    .await;
    login_error(
        &pending.get(callback).send().await.unwrap(),
        "invalid_identity",
    );
    assert_eq!(
        browser
            .get(h.url("/admin/api/v1/session"))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "current disabled trust invalidates observation"
    );
    assert!(
        h.options(&browser).await["oidc_providers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    h.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native check-config against documented YAML, closed types and no SQL/network effects"]
async fn broker_admin_upstream_login_configuration_contract() {
    let mut h = Native::new().await;
    let small = h
        .config
        .replace("server:\n", "server:\n  body_bytes: 256\n");
    h.restart(small).await;
    let browser = h.client();
    for path in [
        format!("/admin/auth/login?provider={}", "x".repeat(257)),
        format!("/oauth/oidc/callback?state={}", "x".repeat(257)),
    ] {
        let response = browser.get(h.url(&path)).send().await.unwrap();
        no_auth_cookie(&response);
        assert_eq!(
            document(response, 400).await["error"]["code"],
            "invalid_request"
        );
    }
    let response = browser
        .get(h.url("/oauth/oidc/callback?state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        .header("cookie", format!("untrusted={}", "x".repeat(257)))
        .send()
        .await
        .unwrap();
    assert_eq!(
        document(response, 400).await["error"]["code"],
        "invalid_request"
    );
    assert_eq!(rows(&mut h.sql.admin, "flow").await, 0);
    assert_eq!(rows(&mut h.sql.admin, "session").await, 0);
    stop(h.child.take().unwrap()).await;
    let absent = address();
    let network = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = h
        .config
        .replace(
            &format!("  port: {}", h.sql.fixture.port),
            &format!("  port: {}", absent.port()),
        )
        .replace(
            &h.issuer.issuer,
            &format!("https://{}", network.local_addr().unwrap()),
        );
    private_file(&h.path, config.as_bytes());
    assert!(
        command()
            .args(["--config", h.path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap()
            .status
            .success(),
        "check-config does not open unreachable SQL"
    );
    assert_eq!(h.issuer.token_hits(), 0);
    assert_eq!(h.issuer.jwks_hits(), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), network.accept())
            .await
            .is_err(),
        "preparation performs no issuer connection"
    );
    let good: Value = serde_saphyr::from_str(&config).unwrap();
    let mut invalid = Vec::new();
    for (pointer, value) in [
        ("/auth/oidc/0/browser_clients", Value::Null),
        ("/auth/oidc/0/browser_clients/0/client_id", json!("")),
        (
            "/auth/oidc/0/browser_clients/1/client_id",
            json!("graphit-admin"),
        ),
        ("/auth/oidc/0/browser_clients/0/require_nonce", Value::Null),
        ("/administration/cookie/enabled", json!(false)),
        ("/administration/enabled", json!(false)),
        ("/administration/response_json_bytes", json!(0)),
    ] {
        let mut config = good.clone();
        if pointer.ends_with("require_nonce") {
            config["auth"]["oidc"][0]["browser_clients"][0]["require_nonce"] = value;
        } else {
            *config.pointer_mut(pointer).unwrap() = value;
        }
        invalid.push((pointer, config));
    }
    let mut unknown = good.clone();
    unknown["auth"]["oidc"][0]["browser_clients"][0]["unknown_browser_field"] = json!(true);
    invalid.push(("unknown_browser_field", unknown));
    for (case, config) in invalid {
        private_file(&h.path, &serde_json::to_vec(&config).unwrap());
        assert!(
            !command()
                .args(["--config", h.path.to_str().unwrap(), "--check-config"])
                .output()
                .await
                .unwrap()
                .status
                .success(),
            "invalid or ownerless browser config rejected before effects: {case}"
        );
    }
    h.issuer.close().await;
    h.sql.close().await;
    h.root.close().unwrap();
}

async fn locked_pid(admin: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = support::deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='browser_login_owner' AND wait_event_type='Lock' LIMIT 1").fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "actual Native statement must reach the held SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn closed_pid(admin: &mut sqlx_postgres::PgConnection, pid: i32) {
    let end = support::deadline();
    loop {
        let exists: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
        )
        .bind(pid)
        .fetch_one(&mut *admin)
        .await
        .unwrap();
        if !exists {
            return;
        }
        assert!(
            Instant::now() < end,
            "unconfirmed/cancelled operation must close its exact SQL channel"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn rows(admin: &mut sqlx_postgres::PgConnection, table: &str) -> i64 {
    let statement = match table {
        "flow" => "SELECT count(*) FROM public.oidc_flows",
        "session" => "SELECT count(*) FROM public.admin_sessions",
        _ => panic!("fixed test table selector"),
    };
    sqlx_core::query_scalar::query_scalar(statement)
        .fetch_one(admin)
        .await
        .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual Native save/consume/issue COMMIT ACK withheld, SQL rollback, Original and cancellation"]
async fn broker_admin_upstream_login_uncertainty_contract() {
    let mut h = Native::new().await;
    // Only the fault scenario uses one TLS channel, so every held ACK has an exact PID.
    let mut relay = commit::CommitRelay::new(h.sql.fixture.port).await;
    let config = h
        .config
        .replace(
            &format!("  port: {}", h.sql.fixture.port),
            &format!("  port: {}", relay.port),
        )
        .replace("max_connections: 2", "max_connections: 1");
    assert!(config.contains("max_connections: 1"));
    h.restart(config).await;
    let browser = h.client();
    let options = h.options(&browser).await;
    let provider = options["oidc_providers"][0]["id"].as_str().unwrap();
    // A real PostgreSQL constraint/trigger failure rolls the flow INSERT back.
    h.sql.admin.execute("CREATE FUNCTION reject_h3_flow() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rejection'; END $$; CREATE TRIGGER reject_h3_flow BEFORE INSERT ON public.oidc_flows FOR EACH ROW EXECUTE FUNCTION reject_h3_flow()").await.unwrap();
    let response = browser.get(h.login_url(provider)).send().await.unwrap();
    assert_eq!(response.status(), 500);
    assert!(response.headers().get("set-cookie").is_none());
    assert_eq!(rows(&mut h.sql.admin, "flow").await, 0);
    h.sql
        .admin
        .execute("DROP TRIGGER reject_h3_flow ON public.oidc_flows; DROP FUNCTION reject_h3_flow()")
        .await
        .unwrap();
    let mut locker = h.sql.fixture.connection().await;
    for phase in ["save", "consume", "issue"] {
        h.sql
            .admin
            .execute("DELETE FROM public.oidc_flows; DELETE FROM public.admin_sessions")
            .await
            .unwrap();
        let callback = if phase == "save" {
            None
        } else {
            let (location, _) = h.begin(&browser, provider).await;
            Some(h.authorize(&browser, location).await)
        };
        let lock = if phase == "issue" {
            "BEGIN; LOCK TABLE public.admin_sessions IN ACCESS EXCLUSIVE MODE"
        } else {
            "BEGIN; LOCK TABLE public.oidc_flows IN ACCESS EXCLUSIVE MODE"
        };
        locker.execute(lock).await.unwrap();
        let pending = match callback {
            Some(callback) => browser.get(callback).send(),
            None => browser.get(h.login_url(provider)).send(),
        };
        tokio::pin!(pending);
        let pid = tokio::select! {pid=locked_pid(&mut h.sql.admin)=>pid,result=&mut pending=>panic!("{phase} must reach held SQL lock: {:?}",result.unwrap().status())};
        relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        locker.execute("ROLLBACK").await.unwrap();
        loop {
            let decision = tokio::select! {decision=relay.replies.recv()=>decision.unwrap(),result=&mut pending=>panic!("{phase} success cannot precede real COMMIT ACK: {:?}",result.unwrap().status())};
            let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
                "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
            )
            .bind(pid)
            .fetch_one(&mut h.sql.admin)
            .await
            .unwrap();
            if query == "COMMIT" && idle {
                assert_eq!(
                    rows(&mut h.sql.admin, "flow").await,
                    if phase == "save" { 1 } else { 0 }
                );
                assert_eq!(
                    rows(&mut h.sql.admin, "session").await,
                    if phase == "issue" { 1 } else { 0 }
                );
                decision.send(false).unwrap();
                break;
            }
            decision.send(true).unwrap();
        }
        let response = pending.await.unwrap();
        assert_eq!(
            response.status(),
            503,
            "unknown COMMIT retains priority over the expired Original"
        );
        no_auth_cookie(&response);
        if phase == "save" {
            assert!(response.headers().get("set-cookie").is_none());
        }
        relay
            .armed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        while let Ok(decision) = relay.replies.try_recv() {
            let _ = decision.send(true);
        }
        closed_pid(&mut h.sql.admin, pid).await;
        // A fresh genuine login recovers; the uncertain operation is never replayed.
        let fresh = h.client();
        let (location, _) = h.begin(&fresh, provider).await;
        let callback = h.authorize(&fresh, location).await;
        assert_eq!(fresh.get(callback).send().await.unwrap().status(), 303);
        assert_eq!(
            fresh
                .get(h.url("/admin/api/v1/session"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    h.sql
        .admin
        .execute("DELETE FROM public.oidc_flows; DELETE FROM public.admin_sessions")
        .await
        .unwrap();
    let fresh = h.client();
    let (location, _) = h.begin(&fresh, provider).await;
    let callback = h.authorize(&fresh, location).await;
    let token_hits = h.issuer.token_hits();
    // Preserve the stored flow's valid duration while moving it into the past.
    let expired = h.sql.admin.execute("UPDATE public.oidc_flows SET created_at=created_at-(expires_at-created_at)-1, expires_at=created_at-1").await.unwrap();
    assert_eq!(expired.rows_affected(), 1);
    invalid_state(fresh.get(callback).send().await.unwrap()).await;
    assert_eq!(h.issuer.token_hits(), token_hits);
    assert_eq!(rows(&mut h.sql.admin, "flow").await, 0);
    let fresh = h.client();
    let (location, _) = h.begin(&fresh, provider).await;
    let callback = h.authorize(&fresh, location).await;
    h.issuer.fault(Fault {
        token_delay: Duration::from_secs(4),
        ..Fault::default()
    });
    let response = fresh.get(callback).send().await.unwrap();
    assert_eq!(response.status(), 504);
    no_auth_cookie(&response);
    h.issuer.fault(Fault::default());
    let (location, _) = h.begin(&fresh, provider).await;
    let callback = h.authorize(&fresh, location).await;
    locker
        .execute("BEGIN; LOCK TABLE public.oidc_flows IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let pending = tokio::spawn(async move { fresh.get(callback).send().await });
    let pid = locked_pid(&mut h.sql.admin).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    closed_pid(&mut h.sql.admin, pid).await;
    locker.execute("ROLLBACK").await.unwrap();
    assert_eq!(
        rows(&mut h.sql.admin, "session").await,
        0,
        "cancelled blocked callback never issued an authentication cookie"
    );
    h.close().await;
    relay.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "interactive real-browser fixture; explicit stop-file environment and CUA proof required"]
async fn broker_admin_upstream_login_browser_fixture() {
    let stop = PathBuf::from(
        std::env::var_os("GRAPHIT_BROKER_BROWSER_FIXTURE_STOP")
            .expect("explicit browser fixture stop-file path required"),
    );
    assert!(
        !stop.exists(),
        "stop file must be absent before starting the owned fixture"
    );
    let mut h = Native::with_issuer(BrowserIssuer::new_loopback_browser().await, true).await;
    // Resource-policy DATA creates a real catalog entry; identity and cookies are never seeded.
    h.sql.admin.execute("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('browser-ui','Browser UI proof','authenticated','','',0,0); INSERT INTO public.grant_capabilities(grant_id,value) VALUES('browser-ui','hub'); INSERT INTO public.grant_projects(grant_id,value) VALUES('browser-ui','01M1YEAE1WYMWG9KJKV1XQC4T4')").await.unwrap();
    eprintln!("H3_BROWSER_READY {}", h.url("/admin/"));
    while !stop.exists() {
        assert!(
            h.child.as_mut().unwrap().try_wait().unwrap().is_none(),
            "owned Native browser fixture must remain running"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let exchanged = h.issuer.token_hits() > 0;
    let sessions = rows(&mut h.sql.admin, "session").await;
    h.close().await;
    std::fs::remove_file(stop).unwrap();
    assert!(
        exchanged,
        "real browser must perform the code exchange before stopping"
    );
    assert_eq!(sessions, 0, "browser logout must confirm session deletion");
}
