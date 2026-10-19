#[path = "../../broker-control/tests/support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine H1/H2 fixtures serve the ingress consumers"
)]
mod ingress;

use axum::http::{StatusCode, header};
use broker_control::{OidcAuthorizationPolicy, UpstreamBrowserClaimsSource};
use broker_presence::{
    AdminCookieHttpConfig, AdminLocalLoginHttpConfig, AdminSessionHttpConfig,
    AdminUpstreamLoginHttpConfig, OidcBrowserHttpConfig, OidcUpstreamLoginHttpConfig,
    UpstreamLoginHttpConfig, sqlite_admin_local_login_router_with_upstream,
    sqlite_admin_session_router_with_cookie, sqlite_oidc_browser_router,
    sqlite_upstream_login_router,
};
use ingress::browser::{BrowserIssuer, ClientAuth, ClientRegistration, Fault};
use ingress::fixture::*;
use reqwest::{Client, Response, cookie::Jar};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use url::Url;

const CALLBACK: &str = "/oauth/oidc/callback";
const SESSION: &str = "/admin/api/v1/session";

fn cookies() -> AdminCookieHttpConfig {
    AdminCookieHttpConfig {
        limits: ingress::limits(),
        policy: ingress::policy(),
        secure: false,
    }
}
fn configuration(
    timeout: Duration,
    authorization: Arc<OidcAuthorizationPolicy>,
) -> UpstreamLoginHttpConfig {
    UpstreamLoginHttpConfig {
        input_bytes: n(16384),
        cookie_secure: false,
        administration: Some(AdminUpstreamLoginHttpConfig {
            response_json_bytes: n(8192),
            request_timeout: timeout,
            cookie: Some(cookies()),
        }),
        oidc: Some(OidcUpstreamLoginHttpConfig {
            authorization,
            request_timeout: timeout,
        }),
    }
}
fn reader_fault() -> Fault {
    let mut fault = Fault::default();
    fault
        .id_overrides
        .insert("roles".into(), serde_json::json!(["browser-reader"]));
    fault
        .userinfo_overrides
        .insert("roles".into(), serde_json::json!(["browser-reader"]));
    fault
}
struct Native {
    sql: Fixture,
    op: BrowserIssuer,
    post: BrowserIssuer,
    resource: BrowserIssuer,
    base: String,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}
impl Native {
    async fn new(timeout: Duration) -> Self {
        let sql = Fixture::new().await;
        sql.db.execute_batch("INSERT OR IGNORE INTO roles(name,created_at)VALUES('browser-reader',0);INSERT OR IGNORE INTO role_permissions(role,action)VALUES('browser-reader','session.read')").unwrap();
        let op = BrowserIssuer::new().await;
        let post = BrowserIssuer::new().await;
        let resource = BrowserIssuer::new().await;
        let mut clients = Vec::new();
        for (id, name, auth, source) in [
            (
                "public",
                "Zulu public",
                ClientAuth::Public,
                UpstreamBrowserClaimsSource::IdToken,
            ),
            (
                "basic",
                "Alpha confidential",
                ClientAuth::Basic,
                UpstreamBrowserClaimsSource::Userinfo,
            ),
        ] {
            let secret = (!matches!(auth, ClientAuth::Public))
                .then(|| "fixture-confidential-secret".to_owned());
            let mut client = ingress::browser_client();
            client.client_id = id.into();
            client.display_name = name.into();
            client.client_secret = secret.clone();
            client.claims_source = source;
            op.register(ClientRegistration {
                id: id.into(),
                secret,
                redirect: client.redirect_url.clone(),
                auth,
            });
            clients.push(client);
        }
        op.fault(reader_fault());
        let mut browser = ingress::config(&op.issuer, &op.ca, true, Some("roles"));
        browser.browser_clients = clients;

        // Discovery must match a client registered as POST-only. The real SDK
        // prefers Basic when the issuer advertises both authentication methods.
        let mut post_client = ingress::browser_client();
        post_client.client_id = "post".into();
        post_client.display_name = "Middle confidential".into();
        post_client.client_secret = Some("synthetic browser secret".into());
        post.register(ClientRegistration {
            id: post_client.client_id.clone(),
            secret: post_client.client_secret.clone(),
            redirect: post_client.redirect_url.clone(),
            auth: ClientAuth::Post,
        });
        let mut post_fault = reader_fault();
        let mut metadata = post.metadata();
        metadata["token_endpoint_auth_methods_supported"] =
            serde_json::json!(["client_secret_post"]);
        post_fault.metadata_override = Some(metadata);
        post.fault(post_fault);
        let mut post_provider = ingress::config(&post.issuer, &post.ca, true, Some("roles"));
        post_provider.id = "post-only".into();
        post_provider.browser_clients = vec![post_client];
        let mut only_resource = ingress::config(&resource.issuer, &resource.ca, false, None);
        only_resource.id = "resource-only".into();
        let verifier = ingress::trust(vec![browser, post_provider, only_resource]);

        let router = sqlite_admin_local_login_router_with_upstream(
            sql.store.clone(),
            AdminLocalLoginHttpConfig {
                body_bytes: n(8192),
                response_json_bytes: n(8192),
                request_timeout: timeout,
                cookie: Some(cookies()),
            },
            None,
            Some(verifier.clone()),
        )
        .unwrap()
        .merge(
            sqlite_upstream_login_router(
                sql.store.clone(),
                Some(verifier.clone()),
                configuration(timeout, sql.authorization.clone()),
            )
            .unwrap(),
        )
        .merge(
            sqlite_admin_session_router_with_cookie(
                sql.store.clone(),
                sql.verifier(),
                AdminSessionHttpConfig {
                    limits: ingress::limits().authorization,
                    request_timeout: timeout,
                },
                None,
                Some(verifier.clone()),
                Some(cookies()),
            )
            .unwrap(),
        )
        .merge(
            sqlite_oidc_browser_router(
                sql.store.clone(),
                OidcBrowserHttpConfig {
                    authorization: sql.authorization.clone(),
                    body_bytes: n(8192),
                    request_timeout: timeout,
                    cookie_secure: false,
                },
                None,
                verifier,
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            sql,
            op,
            post,
            resource,
            base,
            stop,
            task,
        }
    }
    fn client(&self) -> Client {
        Client::builder()
            .cookie_provider(Arc::new(Jar::default()))
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(&self.op.ca).unwrap())
            .add_root_certificate(reqwest::Certificate::from_pem(&self.post.ca).unwrap())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
    }
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
    fn count(&self, table: &str) -> i64 {
        let query = match table {
            "flows" => "SELECT count(*) FROM oidc_flows",
            "sessions" => "SELECT count(*) FROM admin_sessions",
            _ => panic!("fixed fixture table"),
        };
        self.sql.db.query_row(query, [], |r| r.get(0)).unwrap()
    }
    async fn options(&self, client: &Client) -> Vec<Value> {
        let response = client
            .get(self.url("/admin/api/v1/login-options"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        privacy(&response);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["local"], false);
        body["oidc_providers"].as_array().unwrap().clone()
    }
    async fn begin(&self, client: &Client, provider: &str) -> String {
        let mut url = Url::parse(&self.url("/admin/auth/login")).unwrap();
        url.query_pairs_mut().append_pair("provider", provider);
        let response = expected(client.get(url).send().await.unwrap(), StatusCode::FOUND).await;
        privacy(&response);
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(
            cookie.starts_with("graphit_oidc_flow_")
                && cookie.contains("HttpOnly")
                && cookie.contains("SameSite=Lax")
                && cookie.contains("Path=/")
                && !cookie.contains("Secure")
        );
        response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned()
    }
    async fn authorize(&self, client: &Client, location: &str) -> String {
        let response = client
            .get(location)
            .basic_auth("browser-fixture", Some("fixture-password"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        format!(
            "{}{}?{}",
            self.base,
            location.path(),
            location.query().unwrap()
        )
    }
    async fn close(mut self) {
        let _ = self.stop.send(());
        self.task.await.unwrap();
        self.sql.close().await;
        self.op.close().await;
        self.post.close().await;
        self.resource.close().await;
    }
}
async fn expected(response: Response, status: StatusCode) -> Response {
    if response.status() != status {
        let actual = response.status();
        let body = response.text().await.unwrap();
        panic!("expected {status}, received {actual}: {body}");
    }
    response
}
fn privacy(response: &Response) {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(response.headers().contains_key("x-request-id"));
}
fn no_auth(response: &Response) {
    assert!(
        !response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("graphit_admin_session="))
    );
}
fn clear_flow(response: &Response) -> bool {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| {
            let v = v.to_str().unwrap();
            v.starts_with("graphit_oidc_flow_") && v.contains("Max-Age=0")
        })
}
fn parameter(value: &str, key: &str) -> String {
    Url::parse(value)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == key)
        .unwrap()
        .1
        .into_owned()
}
fn public(options: &[Value]) -> &str {
    options.iter().find(|o| o["name"] == "Zulu public").unwrap()["id"]
        .as_str()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real SQLite, HTTPS public/confidential OIDC, CookieJar and Admin session/logout"]
async fn sqlite_admin_browser_options_cookie_and_current_session_logout() {
    let h = Native::new(Duration::from_secs(5)).await;
    let client = h.client();
    let options = h.options(&client).await;
    assert_eq!(
        options
            .iter()
            .map(|o| o["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["Zulu public", "Alpha confidential", "Middle confidential"],
        "providers and clients preserve their configured order",
    );
    assert_eq!(
        options
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    assert!(
        !serde_json::to_string(&options)
            .unwrap()
            .contains("resource-only")
    );
    for path in ["/admin", "/admin/", "/admin/api/v1/login-options"] {
        let response = client.head(h.url(path)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        privacy(&response);
        assert!(response.bytes().await.unwrap().is_empty());
    }
    let page = client.get(h.url("/admin/")).send().await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(
        page.text()
            .await
            .unwrap()
            .contains("/admin/api/v1/login-options")
    );
    for option in &options {
        let supplementary = option["name"] == "Alpha confidential";
        if supplementary {
            let mut fault = reader_fault();
            fault.missing_profile = true;
            h.op.fault(fault);
        }
        let client = h.client();
        let authorize = h.begin(&client, option["id"].as_str().unwrap()).await;
        let callback = h.authorize(&client, &authorize).await;
        let response = expected(
            client.get(callback).send().await.unwrap(),
            StatusCode::SEE_OTHER,
        )
        .await;
        assert_eq!(response.headers()[header::LOCATION], "/admin/");
        privacy(&response);
        assert!(clear_flow(&response));
        let auth = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|v| {
                let v = v.to_str().unwrap();
                v.starts_with("graphit_admin_session=").then_some(v)
            })
            .unwrap();
        assert!(
            auth.contains("HttpOnly") && auth.contains("SameSite=Lax") && auth.contains("Path=/")
        );
        let response = client.get(h.url(SESSION)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        privacy(&response);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["role_source"], "claims");
        assert!(!body["name"].as_str().unwrap().is_empty());
        if supplementary {
            assert_eq!(body["name"], "Supplementary Name");
        }
        let csrf = body["csrf_token"].as_str().unwrap();
        let response = client.head(h.url(SESSION)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.bytes().await.unwrap().is_empty());
        let response = client
            .post(h.url("/admin/auth/logout"))
            .header("x-csrf-token", "wrong")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = client
            .post(h.url("/admin/auth/logout"))
            .header("x-csrf-token", csrf)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        assert_eq!(
            client.get(h.url(SESSION)).send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        h.op.userinfo_hits(),
        1,
        "confidential UserInfo used its genuine claim source"
    );
    assert_eq!(
        h.post.token_hits(),
        1,
        "POST-only discovery selected RequestBody authentication"
    );
    h.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real concurrent H1 cookies, SQL purpose, HEAD, replay and provider errors"]
async fn sqlite_admin_browser_binding_purpose_parallel_replay_and_failures() {
    let h = Native::new(Duration::from_secs(5)).await;
    let client = h.client();
    let options = h.options(&client).await;
    let provider = public(&options);
    let first = h.begin(&client, provider).await;
    let second = h.begin(&client, provider).await;
    let first = h.authorize(&client, &first).await;
    let second = h.authorize(&client, &second).await;
    assert_eq!(h.count("flows"), 2);
    for callback in [&first, &second] {
        let response = client.head(callback).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        no_auth(&response);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    assert_eq!(h.count("flows"), 2);
    assert_eq!(h.op.token_hits(), 0);
    let wrong = h.client().get(&first).send().await.unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert!(!wrong.headers().contains_key(header::SET_COOKIE));
    let mut tampered = Url::parse(&first).unwrap();
    let state = parameter(&first, "state");
    let code = parameter(&first, "code");
    let changed = state.replacen("admin.", "oauth.", 1);
    assert_ne!(state, changed);
    tampered.set_query(None);
    tampered
        .query_pairs_mut()
        .append_pair("state", &changed)
        .append_pair("code", &code);
    assert_eq!(
        client.get(tampered).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.op.token_hits(), 0);
    let (a, b) = tokio::join!(client.get(&first).send(), client.get(&second).send());
    for response in [a.unwrap(), b.unwrap()] {
        let response = expected(response, StatusCode::SEE_OTHER).await;
        assert_eq!(response.headers()[header::LOCATION], "/admin/");
        assert!(clear_flow(&response));
    }
    assert_eq!(h.count("flows"), 0);
    assert_eq!(h.count("sessions"), 2);
    let replay = client.get(first).send().await.unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert!(!replay.headers().contains_key(header::SET_COOKIE));
    let location = h.begin(&client, provider).await;
    let mut denied = Url::parse(&h.url(CALLBACK)).unwrap();
    denied
        .query_pairs_mut()
        .append_pair("state", &parameter(&location, "state"))
        .append_pair("error", "access_denied");
    let response = client.get(denied).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .contains("login_error=oidc_error")
    );
    no_auth(&response);
    assert!(clear_flow(&response));
    let mut fault = reader_fault();
    fault.wrong_signature = true;
    h.op.fault(fault);
    let location = h.begin(&client, provider).await;
    let callback = h.authorize(&client, &location).await;
    let response = client.get(callback).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .contains("login_error=invalid_identity")
    );
    no_auth(&response);
    assert!(clear_flow(&response));
    h.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real shared Admin/OAuth callback with SQL continuation and HTTPS issuer"]
async fn sqlite_admin_browser_and_oauth_share_one_verified_callback() {
    let h = Native::new(Duration::from_secs(5)).await;
    let client = h.client();
    let mut url = Url::parse(&h.url("/oauth/authorize")).unwrap();
    url.query_pairs_mut().extend_pairs([
        ("client_id", "graphit-cli"),
        ("redirect_uri", "http://localhost:49152/oauth/callback"),
        ("response_type", "code"),
        ("scope", "openid profile email"),
        ("state", "caller-state"),
        ("nonce", "caller-nonce"),
        (
            "code_challenge",
            "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
        ),
        ("code_challenge_method", "S256"),
        ("response_mode", "query"),
    ]);
    let response = client.get(url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let path = response.headers()[header::LOCATION].to_str().unwrap();
    let response = client.get(h.url(path)).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.text().await.unwrap();
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
    let response = client.get(h.url(&provider)).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let authorize = response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    let callback = h.authorize(&client, &authorize).await;
    let response = expected(
        client.get(callback).send().await.unwrap(),
        StatusCode::SEE_OTHER,
    )
    .await;
    no_auth(&response);
    assert!(clear_flow(&response));
    let result = response.headers()[header::LOCATION].to_str().unwrap();
    assert_eq!(parameter(result, "state"), "caller-state");
    assert!(!parameter(result, "code").is_empty());
    assert_eq!(h.count("sessions"), 0);
    h.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real SQLite lock, original callback deadline, consumed flow and closed owner"]
async fn sqlite_admin_browser_sql_failures_preserve_cookie_and_original_boundaries() {
    let h = Native::new(Duration::from_secs(1)).await;
    let client = h.client();
    let options = h.options(&client).await;
    let provider = public(&options);
    h.sql.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut url = Url::parse(&h.url("/admin/auth/login")).unwrap();
    url.query_pairs_mut().append_pair("provider", provider);
    let response = client.get(url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    h.sql.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(h.count("flows"), 0);
    let location = h.begin(&client, provider).await;
    let callback = h.authorize(&client, &location).await;
    h.sql.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let response = client.get(&callback).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    no_auth(&response);
    assert!(
        !clear_flow(&response),
        "unconfirmed H1 consumption must not clear binding"
    );
    h.sql.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(h.count("flows"), 1);
    let mut fault = reader_fault();
    fault.token_delay = Duration::from_millis(400);
    h.op.fault(fault);
    let pending = {
        let client = client.clone();
        tokio::spawn(async move { client.get(callback).send().await.unwrap() })
    };
    let start = Instant::now();
    while h.op.token_hits() == 0 {
        assert!(start.elapsed() < Duration::from_secs(2));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    h.sql.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let response = expected(pending.await.unwrap(), StatusCode::GATEWAY_TIMEOUT).await;
    no_auth(&response);
    assert!(
        clear_flow(&response),
        "H1 consumption was confirmed before the H2 lock"
    );
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "H2 must not renew the original callback budget"
    );
    h.sql.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(h.count("flows"), 0);
    assert_eq!(h.count("sessions"), 0);
    h.sql.store.shutdown(end()).await.unwrap();
    let mut url = Url::parse(&h.url("/admin/auth/login")).unwrap();
    url.query_pairs_mut().append_pair("provider", provider);
    let response = client.get(url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    no_auth(&response);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    h.close().await;
}
