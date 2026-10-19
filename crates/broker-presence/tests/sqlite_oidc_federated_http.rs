#[path = "../../broker-control/tests/support/browser_upstream.rs"]
pub mod browser;
#[path = "support/sqlite_oidc_fixture.rs"]
pub mod fixture;
use axum::{
    Router,
    http::{StatusCode, header},
};
use broker_control::{
    UpstreamAccessPolicy, UpstreamBearerVerifier, UpstreamBrowserClaimsSource,
    UpstreamBrowserClient, UpstreamClaimSelectors, UpstreamProviderConfig, UpstreamReadLimits,
};
use broker_presence::{
    OidcBrowserHttpConfig, OidcTokenHttpConfig, OidcUpstreamLoginHttpConfig,
    OidcUserInfoHttpConfig, SqliteOidcUpstreamLoginHttpConfig, sqlite_oidc_browser_router,
    sqlite_oidc_token_router, sqlite_oidc_upstream_login_router, sqlite_oidc_userinfo_router,
};
use browser::{BrowserIssuer, ClientAuth, ClientRegistration};
use fixture::*;
use serde_json::json;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
pub fn client(id: &str) -> UpstreamBrowserClient {
    UpstreamBrowserClient {
        display_name: id.into(),
        client_id: id.into(),
        client_secret: None,
        redirect_url: "https://broker.example/oauth/oidc/callback".into(),
        scopes: vec!["profile".into(), "email".into()],
        require_nonce: true,
        claims_source: UpstreamBrowserClaimsSource::IdToken,
        id_token_additional_audiences: vec![],
    }
}
pub fn register(issuer: &BrowserIssuer, id: &str) {
    issuer.register(ClientRegistration {
        id: id.into(),
        secret: None,
        redirect: client(id).redirect_url.clone(),
        auth: ClientAuth::Public,
    });
}
pub fn configured(
    issuer: &BrowserIssuer,
    clients: Vec<UpstreamBrowserClient>,
    selector: Option<&str>,
) -> UpstreamProviderConfig {
    UpstreamProviderConfig {
        id: "external".into(),
        issuer: issuer.issuer.clone(),
        audiences: vec!["graphit-broker-resource".into()],
        required_scopes: vec![],
        allowed_algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
        access_policy: UpstreamAccessPolicy::ResourceAudience {
            id_token_audiences: vec!["public".into(), "other".into()],
        },
        predicates: vec![],
        claims: UpstreamClaimSelectors {
            subject: "mapped_subject".into(),
            username: "preferred_username".into(),
            name: Some("name".into()),
            email: Some("email".into()),
            organization: Some("organization.id".into()),
            teams: Some("$.groups[*].name".into()),
            roles: selector.map(str::to_owned),
            scope: "scope".into(),
        },
        limits: UpstreamReadLimits {
            token_bytes: n(16384),
            response_bytes: n(65536),
            keys: n(16),
            selector_bytes: n(512),
            claim_string_bytes: n(2048),
            profile_json_bytes: n(8192),
            teams: n(32),
        },
        request_timeout: Duration::from_secs(5),
        cache_max_age: Duration::from_secs(300),
        min_refresh_interval: Duration::from_millis(10),
        allow_loopback_http: false,
        trusted_ca_pem: Some(issuer.ca.clone()),
        browser_clients: clients,
    }
}
pub fn verifier(
    issuer: &BrowserIssuer,
    clients: Vec<UpstreamBrowserClient>,
    selector: Option<&str>,
) -> UpstreamBearerVerifier {
    UpstreamBearerVerifier::new(
        ISSUER,
        n(16384),
        vec![configured(issuer, clients, selector)],
    )
    .unwrap()
}

async fn new_op() -> BrowserIssuer {
    let op = BrowserIssuer::new().await;
    let mut fault = browser::Fault::default();
    fault
        .id_overrides
        .insert("mapped_subject".into(), json!("alice-subject"));
    fault.id_overrides.insert("roles".into(), json!(["editor"]));
    op.fault(fault);
    op
}

struct HttpServer {
    base: String,
    client: reqwest::Client,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}
impl HttpServer {
    async fn new(f: &Fixture, verifier: Arc<UpstreamBearerVerifier>, ca: &[u8]) -> Self {
        let timeout = Duration::from_secs(10);
        let browser = sqlite_oidc_browser_router(
            f.store.clone(),
            OidcBrowserHttpConfig {
                authorization: f.authorization.clone(),
                body_bytes: n(8192),
                request_timeout: timeout,
                cookie_secure: false,
            },
            None,
            verifier.clone(),
        )
        .unwrap();
        let callback = sqlite_oidc_upstream_login_router(
            f.store.clone(),
            verifier.clone(),
            SqliteOidcUpstreamLoginHttpConfig {
                input_bytes: n(16384),
                cookie_secure: false,
                oidc: OidcUpstreamLoginHttpConfig {
                    authorization: f.authorization.clone(),
                    request_timeout: timeout,
                },
            },
        )
        .unwrap();
        let token = sqlite_oidc_token_router(
            f.store.clone(),
            f.issuer.clone(),
            f.authorization.clone(),
            f.policy.clone(),
            OidcTokenHttpConfig::new(timeout, n(8192))
                .unwrap()
                .with_upstream(verifier.clone()),
        )
        .unwrap();
        let info = sqlite_oidc_userinfo_router(
            f.store.clone(),
            f.verifier(),
            f.authorization.clone(),
            Some(verifier),
            OidcUserInfoHttpConfig {
                request_timeout: timeout,
                body_bytes: n(8192),
            },
        )
        .unwrap();
        let app = Router::new()
            .merge(browser)
            .merge(callback)
            .merge(token)
            .merge(info);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(ca).unwrap())
            .build()
            .unwrap();
        Self {
            base,
            client,
            stop,
            task,
        }
    }
    async fn close(self) {
        let _ = self.stop.send(());
        self.task.await.unwrap();
    }
    async fn token(&self, fields: &[(&str, &str)]) -> reqwest::Response {
        self.client
            .post(format!("{}/oauth/token", self.base))
            .form(fields)
            .send()
            .await
            .unwrap()
    }
}
fn privacy(response: &reqwest::Response) {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
}
fn fields(mode: &str) -> Vec<(&str, &str)> {
    vec![
        ("client_id", DYNAMIC),
        ("redirect_uri", "https://client.example/cb"),
        ("response_type", "code"),
        ("scope", "openid profile email offline_access"),
        ("state", "literal-state"),
        ("nonce", "literal-nonce"),
        (
            "code_challenge",
            "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
        ),
        ("code_challenge_method", "S256"),
        ("resource", RESOURCE),
        ("response_mode", mode),
    ]
}
fn query_url(base: &str, values: &[(&str, &str)]) -> String {
    let mut url = url::Url::parse(base).unwrap();
    url.query_pairs_mut().extend_pairs(values.iter().copied());
    url.into()
}
fn parameter(url: &str, key: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == key)
        .unwrap()
        .1
        .into_owned()
}
fn hidden(html: &str, name: &str) -> String {
    html.split_once(&format!("name=\"{name}\" value=\""))
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
        .replace("&amp;", "&")
        .replace("&#x27;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}
async fn begin(server: &HttpServer, mode: &str) -> (String, String, String) {
    let response = server
        .client
        .get(query_url(
            &format!("{}/oauth/authorize", server.base),
            &fields(mode),
        ))
        .send()
        .await
        .unwrap();
    privacy(&response);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    let response = server
        .client
        .get(format!("{}{}", server.base, location))
        .send()
        .await
        .unwrap();
    privacy(&response);
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.text().await.unwrap();
    assert!(html.contains("aria-label=\"Organization sign-in\""));
    assert!(html.contains("Continue with public"));
    assert!(!html.contains("name=\"password\""));
    assert!(html.contains("--action:#3155D9") && html.contains("a:focus-visible"));
    let provider = html
        .split_once("class=\"provider\" href=\"")
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
        .replace("&amp;", "&")
        .replace("&#x2f;", "/")
        .replace("&#x2F;", "/");
    assert!(
        provider.starts_with('/'),
        "provider href must decode to a local route"
    );
    let response = server
        .client
        .get(format!("{}{}", server.base, provider))
        .send()
        .await
        .unwrap();
    privacy(&response);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        cookie.contains("HttpOnly")
            && cookie.contains("SameSite=Lax")
            && !cookie.contains("Secure")
    );
    let cookie = cookie.split(';').next().unwrap().to_owned();
    (
        location,
        cookie,
        parameter(&format!("https://broker.example{provider}"), "id"),
    )
}
async fn op_callback(server: &HttpServer, authorize: &str) -> String {
    let response = server
        .client
        .get(authorize)
        .basic_auth("browser-fixture", Some("fixture-password"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = url::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    format!(
        "{}{}?{}",
        server.base,
        location.path(),
        location.query().unwrap()
    )
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native Axum TCP, HTTPS OP authorization, matching H1, code, signed JWT/refresh and offline UserInfo"]
async fn sqlite_federated_http_complete_journey_and_userinfo_transports() {
    let f = Fixture::new().await;
    let mut op = new_op().await;
    register(&op, "public");
    register(&op, "other");
    let v = Arc::new(verifier(
        &op,
        vec![client("public"), client("other")],
        Some("roles"),
    ));
    let server = HttpServer::new(&f, v, &op.ca).await;
    let (authorize, cookie, _) = begin(&server, "query").await;
    let callback = op_callback(&server, &authorize).await;
    let name = cookie.split('=').next().unwrap();
    let wrong = server
        .client
        .get(&callback)
        .header(header::COOKIE, format!("{name}={}", "A".repeat(43)))
        .send()
        .await
        .unwrap();
    privacy(&wrong);
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert!(!wrong.headers().contains_key(header::SET_COOKIE));
    assert_eq!(op.token_hits(), 0);
    let response = server
        .client
        .get(&callback)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    privacy(&response);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let location = response.headers()[header::LOCATION].to_str().unwrap();
    assert_eq!(parameter(location, "state"), "literal-state");
    let code = parameter(location, "code");
    let replay = server
        .client
        .get(&callback)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    privacy(&replay);
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert!(!replay.headers().contains_key(header::SET_COOKIE));
    let hits = (op.token_hits(), op.userinfo_hits(), op.jwks_hits());
    assert_eq!(hits.0, 1);
    op.close().await;
    let token = server
        .token(&[
            ("grant_type", "authorization_code"),
            ("client_id", DYNAMIC),
            ("redirect_uri", "https://client.example/cb"),
            ("code", &code),
            ("code_verifier", VERIFIER),
            ("resource", RESOURCE),
        ])
        .await;
    privacy(&token);
    assert_eq!(token.status(), StatusCode::OK);
    let token: Value = token.json().await.unwrap();
    let access = token["access_token"].as_str().unwrap();
    let initialid = claims(&f.issuer, token["id_token"].as_str().unwrap(), DYNAMIC);
    assert_eq!(initialid["amr"], json!(["federated"]));
    let info = server
        .client
        .get(format!("{}/oauth/userinfo", server.base))
        .bearer_auth(access)
        .send()
        .await
        .unwrap();
    privacy(&info);
    assert_eq!(info.status(), StatusCode::OK);
    let profile: Value = info.json().await.unwrap();
    assert_eq!(profile["sub"], initialid["sub"]);
    assert_eq!(profile["roles"], json!(["editor", "user"]));
    for response in [
        server
            .client
            .get(query_url(
                &format!("{}/oauth/userinfo", server.base),
                &[("access_token", access)],
            ))
            .send()
            .await
            .unwrap(),
        server
            .client
            .post(format!("{}/oauth/userinfo", server.base))
            .form(&[("access_token", access)])
            .send()
            .await
            .unwrap(),
    ] {
        privacy(&response);
        assert_eq!(response.status(), StatusCode::OK);
    }
    for (method, path, auth, body, status) in [
        ("GET", "/oauth/userinfo", None, "", 401),
        ("HEAD", "/oauth/userinfo", Some("Bearer invalid"), "", 405),
        ("GET", "/oauth/userinfo", Some("Basic !!!"), "", 401),
        (
            "GET",
            "/oauth/userinfo?access_token=a&access_token=b",
            None,
            "",
            400,
        ),
        (
            "POST",
            "/oauth/userinfo",
            None,
            "access_token=a&access_token=b",
            400,
        ),
    ] {
        let mut request = server
            .client
            .request(method.parse().unwrap(), format!("{}{}", server.base, path));
        if let Some(auth) = auth {
            request = request.header(header::AUTHORIZATION, auth);
        }
        if !body.is_empty() {
            request = request
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body);
        }
        let response = request.send().await.unwrap();
        privacy(&response);
        assert_eq!(response.status().as_u16(), status);
    }
    let response = server
        .client
        .get(query_url(
            &format!("{}/oauth/userinfo", server.base),
            &[("access_token", access)],
        ))
        .header(header::AUTHORIZATION, "Basic !!!")
        .send()
        .await
        .unwrap();
    privacy(&response);
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "invalid header never falls through to valid query"
    );
    let rotated = server
        .token(&[
            ("grant_type", "refresh_token"),
            ("client_id", DYNAMIC),
            ("refresh_token", token["refresh_token"].as_str().unwrap()),
            ("scope", "openid email"),
            ("resource", RESOURCE),
        ])
        .await;
    privacy(&rotated);
    assert_eq!(rotated.status(), StatusCode::OK);
    let rotated: Value = rotated.json().await.unwrap();
    let id = claims(&f.issuer, rotated["id_token"].as_str().unwrap(), DYNAMIC);
    assert_eq!(id["amr"], json!(["oidc"]));
    assert_eq!(id["auth_time"], initialid["auth_time"]);
    f.db.execute("DELETE FROM oauth_dynamic_clients", [])
        .unwrap();
    let response = server
        .client
        .get(format!("{}/oauth/userinfo", server.base))
        .bearer_auth(rotated["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    privacy(&response);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!((op.token_hits(), op.userinfo_hits(), op.jwks_hits()), hits);
    server.close().await;
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real TCP callback denial, form_post and cookie consumption, ingress privacy"]
async fn sqlite_federated_http_callback_denials_and_form_post() {
    let f = Fixture::new().await;
    let mut op = new_op().await;
    register(&op, "public");
    register(&op, "other");
    let v = Arc::new(verifier(&op, vec![client("public"), client("other")], None));
    assert!(
        sqlite_oidc_token_router(
            f.store.clone(),
            f.issuer.clone(),
            f.authorization.clone(),
            f.policy.clone(),
            OidcTokenHttpConfig::new(Duration::from_secs(10), n(8192)).unwrap()
        )
        .is_err(),
        "federated factory requires a real owner"
    );
    assert!(
        broker_presence::sqlite_local_oidc_token_router(
            f.store.clone(),
            f.issuer.clone(),
            f.authorization.clone(),
            f.policy.clone(),
            OidcTokenHttpConfig::new(Duration::from_secs(10), n(8192))
                .unwrap()
                .with_upstream(v.clone())
        )
        .is_err(),
        "LOCAL factory does not ignore upstream"
    );
    let server = HttpServer::new(&f, v, &op.ca).await;
    let (authorize, cookie, _) = begin(&server, "form_post").await;
    let callback = op_callback(&server, &authorize).await;
    let response = server
        .client
        .get(&callback)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    privacy(&response);
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.text().await.unwrap();
    let code = hidden(&html, "code");
    assert_eq!(hidden(&html, "state"), "literal-state");
    assert!(html.contains("method=\"post\""));
    assert!(
        html.replace("&#x2f;", "/")
            .replace("&#x2F;", "/")
            .contains("https://client.example/cb")
    );
    let token = server
        .token(&[
            ("grant_type", "authorization_code"),
            ("client_id", DYNAMIC),
            ("redirect_uri", "https://client.example/cb"),
            ("code", &code),
            ("code_verifier", VERIFIER),
            ("resource", RESOURCE),
        ])
        .await;
    privacy(&token);
    assert_eq!(token.status(), StatusCode::OK);
    let (authorize, cookie, _) = begin(&server, "query").await;
    let state = parameter(&authorize, "state");
    let response = server
        .client
        .get(query_url(
            &format!("{}/oauth/oidc/callback", server.base),
            &[("state", state.as_str()), ("error", "access_denied")],
        ))
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    privacy(&response);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        parameter(
            response.headers()[header::LOCATION].to_str().unwrap(),
            "error"
        ),
        "access_denied"
    );
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let response = server
        .client
        .get(format!("{}/admin/auth/login", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    for path in [
        "/oauth/oidc/callback?state=a&state=b",
        "/oauth/oidc/callback?state=invalid",
        "/oauth/oidc/callback?state=admin.invalid",
    ] {
        let response = server
            .client
            .get(format!("{}{}", server.base, path))
            .send()
            .await
            .unwrap();
        privacy(&response);
        assert!(!response.status().is_success());
        assert!(!response.headers().contains_key(header::LOCATION));
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    let response = server
        .client
        .get(format!(
            "{}/oauth/oidc/callback?padding={}",
            server.base,
            "x".repeat(16385)
        ))
        .send()
        .await
        .unwrap();
    privacy(&response);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::LOCATION));
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    server.close().await;
    op.close().await;
    f.close().await;
}
