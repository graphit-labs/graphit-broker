#[path = "support/upstream_commit.rs"]
mod commit;
#[allow(
    dead_code,
    reason = "shared genuine cookie fixture also serves SQL contracts"
)]
#[path = "../../broker-control/tests/support/admin_cookie.rs"]
mod cookie;
#[allow(
    dead_code,
    reason = "shared genuine PostgreSQL fixture also serves SQL contracts"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
#[path = "support/upstream.rs"]
#[allow(
    dead_code,
    reason = "shared issuer's fault/rotation methods are exercised by the upstream contract"
)]
mod upstream;
use broker_control::{
    OidcAuthorizationConfiguration, OidcAuthorizationInput, OidcAuthorizationLimits,
    OidcAuthorizationPolicy, PreparedOidcLogin,
};
use broker_presence::admin_cookie_header;
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
use tokio::{
    net::TcpStream,
    process::{Child, Command},
};
use zeroize::Zeroizing;
const AUDIENCE: &str = "storage-api";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
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
fn yaml(address: SocketAddr, pg: u16, op: &upstream::UpstreamFixture) -> String {
    let base = block(include_str!("../../../docs/rust-broker-server.md"))
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
    let federation = block(include_str!("../../../docs/rust-admin-upstream-session.md"))
        .strip_prefix("auth:\n")
        .unwrap()
        .replace("https://issuer.example.test", &op.issuer);
    let base = base.replace("storage:\n", &format!("{federation}storage:\n"));
    let cookie=block(include_str!("../../../docs/rust-admin-cookie-session.md"))
        .replace("  cookie_secure: true","  cookie_secure: false")
        .replace("  cookie:\n","  local_bearer:\n    enabled: true\n    audience: explicit-admin-api\n    identity_json_bytes: 8192\n    required_scopes: [admin:session]\n  cookie:\n");
    format!(
        "{base}{}{cookie}",
        block(include_str!("../../../docs/rust-oidc-token-exchange.md"))
    )
}
fn write(root: &Path, config: &str) -> PathBuf {
    let path = root.join("config.yaml");
    private_file(&path, config.as_bytes());
    path
}
fn command() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphit-broker"));
    c.kill_on_drop(true);
    c
}
async fn start(path: &Path, address: SocketAddr) -> Child {
    let mut child = command()
        .args(["--config", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
        assert!(
            child.try_wait().unwrap().is_none(),
            "native Broker exited before readiness"
        );
        assert!(Instant::now() < end, "native Broker did not become ready");
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
    let exit = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .unwrap()
        .unwrap();
    #[cfg(unix)]
    assert!(exit.success(), "native Broker must join and close cleanly");
    #[cfg(not(unix))]
    let _ = exit;
}
async fn session(client: &Client, addr: SocketAddr, raw: &str) -> Response {
    client
        .get(format!("http://{addr}/admin/api/v1/session"))
        .header("Cookie", format!("graphit_admin_session={raw}"))
        .header("X-Request-ID", "cookie-read")
        .send()
        .await
        .unwrap()
}
async fn denied(response: Response, status: u16, code: &str) {
    assert_eq!(response.status(), status);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = Zeroizing::new(response.bytes().await.unwrap().to_vec());
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["error"]["code"], code);
    for forbidden in [cookie::PEPPER, "alice-subject", "ephemeral-owner", "SELECT"] {
        assert!(!String::from_utf8_lossy(&bytes).contains(forbidden));
    }
}
async fn access(f: &CookieFixture, client: &Client, addr: SocketAddr) -> Zeroizing<String> {
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
async fn opaque(f: &mut CookieFixture) -> Zeroizing<String> {
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
async fn wait_sql_lock(admin: &mut sqlx_postgres::PgConnection, pattern: &str) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='admin_cookie_owner' AND wait_event_type='Lock' AND query LIKE $1")
            .bind(pattern).fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "actual native HTTP SQL lock must be observed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn commit_http(
    f: &mut CookieFixture,
    root: &Path,
    config: &str,
    addr: SocketAddr,
    client: &Client,
) {
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let config = config.replace(
        &format!("  port: {}", f.fixture.port),
        &format!("  port: {}", relay.port),
    );
    let path = write(root, &config);
    let child = start(&path, addr).await;
    let issued = f.cookie().await;
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    {
        let pending = session(client, addr, issued.secret());
        tokio::pin!(pending);
        let pid = tokio::select! {pid=wait_sql_lock(&mut f.admin,"%octet_length(u.username)%")=>pid,result=&mut pending=>panic!("real cookie HTTP must reach SQL wait, status {}",result.status())};
        relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        locker.execute("ROLLBACK").await.unwrap();
        loop {
            let decision = tokio::select! {decision=relay.replies.recv()=>decision.unwrap(),result=&mut pending=>panic!("HTTP COMMIT ACK must be withheld, status {}",result.status())};
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
    sqlx_core::connection::Connection::close(locker)
        .await
        .unwrap();
    relay.close().await;
    stop(child).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native Broker, genuine LOCAL cookie, mature HTTPS issuer and TLS NOSUPERUSER PostgreSQL"]
async fn broker_admin_cookie_http_contract() {
    let mut f = CookieFixture::new().await;
    let mut op = upstream::UpstreamFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    files(root.path(), &f.fixture.ca);
    private_file(&root.path().join("issuer-ca.pem"), &op.ca);
    let config = yaml(addr, f.fixture.port, &op);
    let path = write(root.path(), &config);
    let checked = command()
        .args(["--config", path.to_str().unwrap(), "--check-config"])
        .output()
        .await
        .unwrap();
    assert!(
        checked.status.success(),
        "native Broker rejected the fixture configuration: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert_eq!(op.hits(), 0);
    for bad in [
        config.replace("    csrf_bytes: 43", "    csrf_bytes: 42"),
        config.replace("  session_ttl: 8h", "  session_ttl: 4m"),
        config.replace("  session_ttl: 8h", "  session_ttl: 169h"),
        config.replace("    max_teams: 16\n", ""),
        config.replace("    text_bytes: 2048", "    text_bytes: 0"),
        config.replace("  token_bytes: 8192", "  token_bytes: 42"),
        config.replace(
            &format!("  public_url: http://{addr}"),
            "  public_url: https://broker.example.test",
        ),
    ] {
        write(root.path(), &bad);
        let output = command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap();
        assert!(
            !output.status.success(),
            "invalid enabled cookie configuration must fail"
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains(cookie::PEPPER));
        assert!(TcpStream::connect(addr).await.is_err());
        assert_eq!(op.hits(), 0);
    }
    write(root.path(), &config);
    let child = start(&path, addr).await;
    let client = Client::new();
    let issued = f.cookie().await;
    let header = admin_cookie_header(&issued, false).unwrap();
    assert!(header.is_sensitive());
    let attrs = header.to_str().unwrap();
    for expected in ["Path=/", "HttpOnly", "SameSite=Lax", "Expires=", "Max-Age="] {
        assert!(attrs.contains(expected));
    }
    assert!(!attrs.contains("; Secure"));
    assert!(
        admin_cookie_header(&issued, true)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("; Secure")
    );
    let response = session(&client, addr, issued.secret()).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    assert_eq!(response.headers()["x-request-id"], "cookie-read");
    assert!(!response.headers().contains_key("set-cookie"));
    let value: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(value["subject"], "alice-subject");
    assert_eq!(value["role_source"], "database");
    let csrf = Zeroizing::new(value["csrf_token"].as_str().unwrap().to_owned());
    assert_eq!(csrf.len(), 43);
    let head = client
        .head(format!("http://{addr}/admin/api/v1/session"))
        .header(
            "Cookie",
            format!("graphit_admin_session={}", issued.secret()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert!(!head.headers().contains_key("set-cookie"));
    assert!(head.bytes().await.unwrap().is_empty());
    let jwt = access(&f, &client, addr).await;
    let opaque = opaque(&mut f).await;
    let federated = op.sign(&op.claims(), "upstream-key", "at+jwt");
    for bearer in [&*jwt, &*opaque, &*federated] {
        let url = format!("http://{addr}/admin/api/v1/session");
        assert_eq!(
            client
                .get(&url)
                .bearer_auth(bearer)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            client
                .get(&url)
                .bearer_auth(bearer)
                .header("Cookie", "graphit_admin_session=\"\"")
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        denied(
            client
                .get(&url)
                .bearer_auth(bearer)
                .header("Cookie", "graphit_admin_session=invalid")
                .send()
                .await
                .unwrap(),
            401,
            "admin_unauthorized",
        )
        .await;
        denied(
            client
                .get(&url)
                .bearer_auth(bearer)
                .header(
                    "Cookie",
                    format!(
                        "graphit_admin_session={}; graphit_admin_session={}",
                        issued.secret(),
                        issued.secret()
                    ),
                )
                .send()
                .await
                .unwrap(),
            401,
            "admin_unauthorized",
        )
        .await;
    }
    f.admin
        .execute("UPDATE public.local_users SET name='Current HTTP'")
        .await
        .unwrap();
    let current: Value = serde_json::from_slice(
        &session(&client, addr, issued.secret())
            .await
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(current["name"], "Current HTTP");
    let logout_url = format!("http://{addr}/admin/auth/logout");
    for csrf in [None, Some("wrong")] {
        let mut req = client
            .post(&logout_url)
            .header(
                "Cookie",
                format!("graphit_admin_session={}", issued.secret()),
            )
            .header("Origin", "https://hostile.example");
        if let Some(csrf) = csrf {
            req = req.header("X-CSRF-Token", csrf);
        }
        denied(req.send().await.unwrap(), 403, "csrf_failed").await;
    }
    let preflight = client
        .request(Method::OPTIONS, &logout_url)
        .header("Origin", "https://hostile.example")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "X-CSRF-Token")
        .send()
        .await
        .unwrap();
    assert!(
        !preflight
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    f.admin
        .execute("DELETE FROM public.role_permissions WHERE role='user' AND action='session.read'")
        .await
        .unwrap();
    denied(
        session(&client, addr, issued.secret()).await,
        403,
        "admin_forbidden",
    )
    .await;
    let result = client
        .post(&logout_url)
        .header(
            "Cookie",
            format!("graphit_admin_session={}", issued.secret()),
        )
        .header("X-CSRF-Token", csrf.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), 204);
    let clear = result.headers()["set-cookie"].to_str().unwrap();
    assert!(clear.contains("Max-Age=0"));
    assert!(clear.contains("Path=/"));
    assert!(clear.contains("HttpOnly"));
    assert!(result.bytes().await.unwrap().is_empty());
    f.admin
        .execute("INSERT INTO public.role_permissions(role,action) VALUES('user','session.read')")
        .await
        .unwrap();
    denied(
        session(&client, addr, issued.secret()).await,
        401,
        "admin_unauthorized",
    )
    .await;
    for raw in [None, Some("invalid"), Some(issued.secret())] {
        let mut req = client.post(&logout_url);
        if let Some(raw) = raw {
            req = req.header("Cookie", format!("graphit_admin_session={raw}"));
        }
        let response = req.send().await.unwrap();
        assert_eq!(response.status(), 204);
        assert!(
            response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
    }
    let active = f.cookie().await;
    let current = f
        .store
        .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
        .unwrap()
        .read(active.secret(), deadline())
        .await
        .unwrap();
    let active_csrf = Zeroizing::new(current.csrf_token().to_owned());
    f.admin
        .execute("REVOKE DELETE ON public.admin_sessions FROM admin_cookie_owner")
        .await
        .unwrap();
    denied(
        client
            .post(&logout_url)
            .header(
                "Cookie",
                format!("graphit_admin_session={}", active.secret()),
            )
            .header("X-CSRF-Token", active_csrf.as_str())
            .send()
            .await
            .unwrap(),
        500,
        "authorization_failed",
    )
    .await;
    f.admin
        .execute("GRANT DELETE ON public.admin_sessions TO admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(session(&client, addr, active.secret()).await.status(), 200);
    denied(
        client
            .post(&logout_url)
            .header(
                "Cookie",
                format!("graphit_admin_session={}", active.secret()),
            )
            .header("X-CSRF-Token", active_csrf.as_str())
            .header("X-CSRF-Token", active_csrf.as_str())
            .send()
            .await
            .unwrap(),
        403,
        "csrf_failed",
    )
    .await;
    let mut locker = f.fixture.connection().await;
    locker.execute("BEGIN").await.unwrap();
    let hash = f
        .digester
        .token(TokenKind::AdminSession, active.secret().as_bytes())
        .unwrap()
        .to_sql_hex();
    sqlx_core::query::query(
        "SELECT token_hash FROM public.admin_sessions WHERE token_hash=$1 FOR UPDATE",
    )
    .bind(&hash)
    .fetch_one(&mut locker)
    .await
    .unwrap();
    denied(
        session(&client, addr, active.secret()).await,
        504,
        "administration_unavailable",
    )
    .await;
    denied(
        client
            .post(&logout_url)
            .header(
                "Cookie",
                format!("graphit_admin_session={}", active.secret()),
            )
            .header("X-CSRF-Token", active_csrf.as_str())
            .send()
            .await
            .unwrap(),
        504,
        "administration_unavailable",
    )
    .await;
    locker.execute("ROLLBACK").await.unwrap();
    sqlx_core::connection::Connection::close(locker)
        .await
        .unwrap();
    assert_eq!(
        session(&client, addr, active.secret()).await.status(),
        200,
        "failed/deadline logout must preserve the actual session"
    );
    let output = client
        .post(&logout_url)
        .header(
            "Cookie",
            format!("graphit_admin_session={}", active.secret()),
        )
        .header("X-CSRF-Token", active_csrf.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(output.status(), 204);
    assert_eq!(
        client
            .get(format!("http://{addr}/admin/api/v1/session"))
            .bearer_auth(&*jwt)
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "cookie logout must not revoke an independently signed access token"
    );
    stop(child).await;
    commit_http(&mut f, root.path(), &config, addr, &client).await;
    let disabled = config.replace(
        "  cookie:\n    enabled: true",
        "  cookie:\n    enabled: false",
    );
    write(root.path(), &disabled);
    let child = start(&path, addr).await;
    assert_eq!(client.post(&logout_url).send().await.unwrap().status(), 404);
    stop(child).await;
    let noadmin = config.replace(
        "administration:\n  enabled: true",
        "administration:\n  enabled: false",
    );
    write(root.path(), &noadmin);
    let child = start(&path, addr).await;
    assert_eq!(session(&client, addr, issued.secret()).await.status(), 404);
    stop(child).await;
    op.close().await;
    f.close().await;
}
