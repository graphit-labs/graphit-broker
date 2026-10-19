//! Genuine native Broker process and credentials shared by administrative read/write contracts.
use crate::{cookie, support, upstream};
use broker_control::{
    OidcAuthorizationConfiguration, OidcAuthorizationInput, OidcAuthorizationLimits,
    OidcAuthorizationPolicy, PreparedOidcLogin, SystemAction,
};
use broker_security::{LocalAuthBinding, TokenKind};
use cookie::CookieFixture;
use rcgen::KeyPair;
use reqwest::{Client, Method, Response};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use support::{deadline, n};
use tokio::process::{Child, Command};
use zeroize::Zeroizing;
pub(super) const AUDIENCE: &str = "storage-api";
pub(super) const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
pub(super) fn block(doc: &str) -> &str {
    doc.split_once("```yaml\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0
}
pub(super) fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
pub(super) fn private_file(path: &Path, bytes: &[u8]) {
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
pub(super) fn files(root: &Path, ca: &[u8]) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let der = Zeroizing::new(key.serialize_der());
    private_file(&root.join("signing.pk8"), &der);
    private_file(&root.join("ca.pem"), ca);
}
pub(super) fn yaml(address: SocketAddr, pg: u16, op: &upstream::UpstreamFixture) -> String {
    let base = block(include_str!("../../../../docs/rust-broker-server.md"))
        .replace("127.0.0.1:8080", &address.to_string())
        .replace(
            "  public_url: https://broker.example.test",
            &format!("  public_url: http://{address}"),
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
        .replace(
            "  issuer: https://broker.example.test",
            &format!("  issuer: http://{address}"),
        )
        .replace("  resource: https://broker.example.test/v1\n", "")
        .replace("\"${BROKER_PEPPER:?required}\"", cookie::PEPPER);
    let federation = block(include_str!(
        "../../../../docs/rust-admin-upstream-session.md"
    ))
    .strip_prefix("auth:\n")
    .unwrap()
    .replace("https://issuer.example.test", &op.issuer);
    let base = base.replace("storage:\n", &format!("{federation}storage:\n"));
    let cookie=block(include_str!("../../../../docs/rust-admin-cookie-session.md"))
        .replace("  cookie_secure: true","  cookie_secure: false")
        .replace("  cookie:\n","  local_bearer:\n    enabled: true\n    audience: explicit-admin-api\n    identity_json_bytes: 8192\n    required_scopes: [admin:session]\n  cookie:\n");
    format!(
        "{base}{}{cookie}",
        block(include_str!("../../../../docs/rust-oidc-token-exchange.md"))
    )
}
pub(super) fn write(root: &Path, config: &str) -> PathBuf {
    let path = root.join("config.yaml");
    private_file(&path, config.as_bytes());
    path
}
pub(super) fn command() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphit-broker"));
    c.kill_on_drop(true);
    c
}
pub(super) async fn start(path: &Path, address: SocketAddr) -> Child {
    let mut child = command()
        .args(["--config", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let end = deadline();
    loop {
        if reqwest::get(format!("http://{address}/readyz"))
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return child;
        }
        if child.try_wait().unwrap().is_some() {
            let exit = child.wait().await.unwrap();
            let diagnostic = diagnostic(&mut child).await;
            panic!("native Broker exited before readiness ({exit}): {diagnostic}");
        }
        assert!(Instant::now() < end, "native Broker did not become ready");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn diagnostic(child: &mut Child) -> String {
    use tokio::io::AsyncReadExt;
    let mut diagnostic = String::new();
    if let Some(stderr) = child.stderr.take() {
        stderr
            .take(4096)
            .read_to_string(&mut diagnostic)
            .await
            .unwrap();
    }
    for secret in [cookie::PEPPER, cookie::PASSWORD, "ephemeral-owner"] {
        assert!(
            !diagnostic.contains(secret),
            "child diagnostics must remain finite and redacted"
        );
    }
    diagnostic
}
pub(super) async fn stop(mut child: Child) {
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
    let exit = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .unwrap()
        .unwrap();
    #[cfg(unix)]
    if !exit.success() {
        let diagnostic = diagnostic(&mut child).await;
        panic!("native Broker must join and close cleanly: {diagnostic}");
    }
    #[cfg(not(unix))]
    let _ = exit;
}
pub(super) async fn denied(response: Response, status: u16, code: &str) {
    assert_eq!(
        response.status(),
        status,
        "{} {}",
        response.url().path(),
        code
    );
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = Zeroizing::new(response.bytes().await.unwrap().to_vec());
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["error"]["code"], code);
    for forbidden in [cookie::PEPPER, "alice-subject", "ephemeral-owner", "SELECT"] {
        assert!(!String::from_utf8_lossy(&bytes).contains(forbidden));
    }
}
pub(super) async fn access(
    f: &CookieFixture,
    client: &Client,
    addr: SocketAddr,
) -> Zeroizing<String> {
    let original = deadline();
    let policy = OidcAuthorizationPolicy::new(
        OidcAuthorizationConfiguration {
            cli_client_id: "graphit-cli".into(),
            cli_redirect_path: "/oauth/callback".into(),
            api_audience: AUDIENCE.into(),
            accepted_resources: vec!["https://broker.example.test/v1".into()],
            dynamic_registration: true,
            authorization_ttl: Duration::from_secs(60),
        },
        OidcAuthorizationLimits::new(n(8192), n(8192)).unwrap(),
    )
    .unwrap();
    let service = f.store.oidc_authorization_service(&f.digester, &policy);
    let pending = service
        .create(
            OidcAuthorizationInput {
                client_id: "graphit-cli",
                redirect_uri: "http://localhost:49152/oauth/callback",
                response_type: "code",
                scope: "openid profile email",
                state: "cookie-native-coexist",
                nonce: "cookie-native-coexist",
                code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
                code_challenge_method: "S256",
                response_mode: Some("query"),
                resources: &[],
                prompts: &[],
            },
            original,
        )
        .await
        .unwrap();
    let login = f
        .login(LocalAuthBinding::OauthAuthorize(
            pending.request().as_bytes(),
        ))
        .await;
    let code = service
        .complete(
            pending.request(),
            PreparedOidcLogin::try_from(login).unwrap(),
            original,
        )
        .await
        .unwrap();
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "authorization_code")
        .append_pair("client_id", "graphit-cli")
        .append_pair("code", code.code())
        .append_pair("redirect_uri", "http://localhost:49152/oauth/callback")
        .append_pair("code_verifier", VERIFIER);
    let response = client
        .post(format!("http://{addr}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form.finish())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let value: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    Zeroizing::new(value["access_token"].as_str().unwrap().to_owned())
}
pub(super) async fn opaque(f: &mut CookieFixture) -> Zeroizing<String> {
    // Operational credential state, not a forged private authentication proof.
    let raw = Zeroizing::new(format!(
        "gb_at_{}",
        broker_security::new_local_auth_challenge()
            .unwrap()
            .as_str()
    ));
    let digest = f
        .digester
        .token(TokenKind::LocalAccess, raw.as_bytes())
        .unwrap();
    let principal = json!({"issuer":"local","subject":"alice-subject","username":"alice","auth_method":"local-password","local_user_revision":1});
    sqlx_core::query::query("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,'cookie-coexist-access','access','alice-subject','other-subject',$2,'explicit-client','explicit-admin-api','','[\"admin:session\"]',1,'',0,$3,0)")
        .bind(digest.to_sql_hex()).bind(principal.to_string()).bind(cookie::micros()+600_000_000).execute(&mut f.admin).await.unwrap();
    raw
}

pub(super) struct Native {
    pub(super) f: CookieFixture,
    pub(super) op: upstream::UpstreamFixture,
    pub(super) root: tempfile::TempDir,
    pub(super) addr: SocketAddr,
    pub(super) config: String,
    pub(super) child: Child,
    pub(super) client: Client,
}
impl Native {
    pub(super) async fn new() -> Self {
        Self::with_config(|config, _| config).await
    }
    pub(super) async fn with_config(transform: impl FnOnce(String, &Path) -> String) -> Self {
        let f = CookieFixture::new().await;
        let op = upstream::UpstreamFixture::new().await;
        let root = tempfile::tempdir().unwrap();
        let addr = address();
        files(root.path(), &f.fixture.ca);
        private_file(&root.path().join("issuer-ca.pem"), &op.ca);
        let config = transform(yaml(addr, f.fixture.port, &op), root.path());
        let path = write(root.path(), &config);
        let child = start(&path, addr).await;
        Self {
            f,
            op,
            root,
            addr,
            config,
            child,
            client: Client::new(),
        }
    }
    pub(super) async fn action(&mut self, action: SystemAction) {
        self.f
            .admin
            .execute("DELETE FROM public.role_permissions WHERE role='user'")
            .await
            .unwrap();
        sqlx_core::query::query(
            "INSERT INTO public.role_permissions(role,action) VALUES('user',$1)",
        )
        .bind(action.as_str())
        .execute(&mut self.f.admin)
        .await
        .unwrap();
    }
    pub(super) async fn request(
        &self,
        route: &str,
        method: Method,
        cookie: Option<&str>,
        bearer: Option<&str>,
    ) -> Response {
        let mut request = self
            .client
            .request(method, format!("http://{}/admin/api/v1/{route}", self.addr))
            .header("x-request-id", "  admin-read-proof  ")
            .header("origin", "https://unrelated.example.invalid");
        if let Some(raw) = cookie {
            request = request.header("cookie", format!("graphit_admin_session={raw}"));
        }
        if let Some(raw) = bearer {
            request = request.bearer_auth(raw);
        }
        request.send().await.unwrap()
    }
    pub(super) async fn get(&self, route: &str, raw: &str) -> Value {
        document(self.request(route, Method::GET, Some(raw), None).await).await
    }
    pub(super) async fn close(mut self) {
        stop(self.child).await;
        self.op.close().await;
        self.f.close().await;
    }
}
pub(super) async fn document(response: Response) -> Value {
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    assert_eq!(response.headers()["x-request-id"], "admin-read-proof");
    assert!(!response.headers().contains_key("set-cookie"));
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}
