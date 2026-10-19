//! Actual shared callback: native binary, TLS SQL, genuine HTTPS H1, DCR and W3.
#[allow(
    dead_code,
    reason = "shared HTTPS issuer also serves H1 fault contracts"
)]
#[path = "../../broker-control/tests/support/browser_upstream.rs"]
mod browser;
#[path = "support/upstream_commit.rs"]
mod commit;
#[allow(dead_code, reason = "shared federated producer serves grant contracts")]
#[path = "../../broker-control/tests/support/oidc_federated.rs"]
mod federated;
#[allow(
    dead_code,
    reason = "shared token process fixture supports other protocol checks"
)]
#[path = "support/oidc_http.rs"]
mod http;
#[allow(
    dead_code,
    reason = "shared LOCAL/SQL fixture supports other authentication checks"
)]
#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared PostgreSQL fixture methods serve other contracts"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use broker_control::{
    FlowContinuation, IssuedUpstreamAuthorization, OidcAuthorizationInput,
    PendingOidcAuthorization, UpstreamBearerVerifier,
};
use browser::{BrowserIssuer, Fault};
use oidc::{OidcFixture, RESOURCE, VERIFIER};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};
use support::deadline;

fn provider(issuer: &BrowserIssuer) -> Value {
    let recipe: Value = serde_saphyr::from_str(http::block(include_str!(
        "../../../docs/rust-admin-upstream-login.md"
    )))
    .unwrap();
    let mut provider = recipe["auth"]["oidc"][0].clone();
    provider["id"] = json!("external");
    provider["issuer"] = json!(issuer.issuer);
    provider["ca_file"] = json!("upstream-ca.pem");
    provider["claims"]["subject"] = json!("mapped_subject");
    provider["claims"]["roles"] = json!("roles");
    provider["required_scopes"] = json!([]);
    provider["browser_clients"] = json!([{"display_name":"Callback issuer","client_id":"public","redirect_url":federated::client("public").redirect_url,"scopes":["profile","email"],"require_nonce":true,"claims_source":"id_token","id_token_additional_audiences":[]}]);
    provider
}
fn configuration(
    root: &Path,
    f: &OidcFixture,
    issuer: &BrowserIssuer,
    addr: SocketAddr,
    pg: u16,
) -> Value {
    let _signer = http::files(root, &f.fixture.ca, &format!("http://{addr}"));
    std::fs::write(root.join("upstream-ca.pem"), &issuer.ca).unwrap();
    let mut config: Value = serde_saphyr::from_str(&http::yaml(addr, pg)).unwrap();
    config["auth"]["oidc"] = json!([provider(issuer)]);
    config
}
fn no_redirect() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}
async fn register(addr: SocketAddr, redirect: &str) -> String {
    let response=no_redirect().post(format!("http://{addr}/oauth/register")).header("content-type","application/json").body(serde_json::to_vec(&json!({"redirect_uris":["https://client.example/cb",redirect],"token_endpoint_auth_method":"none","client_name":"Callback consumer"})).unwrap()).send().await.unwrap();
    assert_eq!(response.status(), 201);
    let registered = http::value(response).await;
    assert_eq!(
        registered["application_type"], "web",
        "a registered Web client keeps its exact mixed callback set"
    );
    registered["client_id"].as_str().unwrap().into()
}
async fn create_pending(
    f: &OidcFixture,
    client: &str,
    redirect: &str,
    mode: &str,
    state: &str,
) -> PendingOidcAuthorization {
    f.store
        .browser_oidc_authorizations(&f.policy)
        .create(
            OidcAuthorizationInput {
                client_id: client,
                redirect_uri: redirect,
                response_type: "code",
                scope: "openid profile email offline_access",
                state,
                nonce: "literal nonce",
                code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
                code_challenge_method: "S256",
                response_mode: Some(mode),
                resources: &[RESOURCE],
                prompts: &[],
            },
            deadline(),
        )
        .await
        .unwrap()
}
async fn issued(
    f: &OidcFixture,
    verifier: &UpstreamBearerVerifier,
    request: &str,
) -> IssuedUpstreamAuthorization {
    f.store
        .upstream_logins(verifier)
        .begin(federated::continuation(verifier, request), deadline())
        .await
        .unwrap()
}
fn cookie(flow: &IssuedUpstreamAuthorization, secure: bool) -> String {
    broker_presence::upstream_login_flow_cookie(flow, secure)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into()
}
fn callback_url(addr: SocketAddr, state: &str, code: Option<&str>) -> String {
    let mut url = url::Url::parse(&format!("http://{addr}/oauth/oidc/callback")).unwrap();
    url.query_pairs_mut().append_pair("state", state);
    match code {
        Some(code) => {
            url.query_pairs_mut().append_pair("code", code);
        }
        None => {
            url.query_pairs_mut().append_pair("error", "access_denied");
        }
    }
    url.into()
}
async fn callback(
    addr: SocketAddr,
    flow: &IssuedUpstreamAuthorization,
    code: Option<&str>,
    secure: bool,
) -> reqwest::Response {
    no_redirect()
        .get(callback_url(addr, flow.state(), code))
        .header("cookie", cookie(flow, secure))
        .send()
        .await
        .unwrap()
}
fn headers(response: &reqwest::Response, flow: &IssuedUpstreamAuthorization, secure: bool) {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ] {
        assert_eq!(response.headers()[name], value);
    }
    let name = broker_presence::upstream_login_flow_cookie_name(flow.state(), secure);
    let cookies: Vec<_> = response.headers().get_all("set-cookie").iter().collect();
    assert_eq!(
        cookies.len(),
        1,
        "callback clears its flow and never emits an Admin authentication cookie for OAuth"
    );
    let clear = cookies[0].to_str().unwrap();
    assert!(clear.starts_with(&format!("{name}=")) && clear.contains("Max-Age=0"));
    assert_eq!(clear.contains("; Secure"), secure);
}
fn parameter(location: &str, mode: &str, name: &str) -> String {
    let url = url::Url::parse(location).unwrap();
    let encoded = if mode == "fragment" {
        url.fragment().unwrap()
    } else {
        url.query().unwrap()
    };
    url::form_urlencoded::parse(encoded.as_bytes())
        .find(|(key, _)| key == name)
        .unwrap()
        .1
        .into_owned()
}
async fn response_code(
    response: reqwest::Response,
    mode: &str,
    redirect: &str,
    state: &str,
) -> String {
    if mode == "form_post" {
        assert_eq!(response.status(), 200);
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("script-src 'sha256-")
        );
        let html = response.text().await.unwrap();
        assert!(
            html.contains("method=\"post\"") && html.contains("application/x-www-form-urlencoded")
        );
        assert!(!html.contains("<danger>"));
        // This extracts only the fixed CSPRNG code for token redemption. Browser QA separately
        // proves HTML parsing/actual state echo, rather than treating this fixture as a browser.
        regex::Regex::new(r#"name="code" value="([A-Za-z0-9_-]{43})"#)
            .unwrap()
            .captures(&html)
            .unwrap()[1]
            .into()
    } else {
        assert_eq!(response.status(), 303);
        let location = response.headers()["location"].to_str().unwrap();
        assert!(
            location.starts_with(redirect),
            "registered literal redirect is retained"
        );
        assert_eq!(parameter(location, mode, "state"), state);
        parameter(location, mode, "code")
    }
}
fn token_body(code: &str, client: &str, redirect: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("client_id", client),
            ("code", code),
            ("redirect_uri", redirect),
            ("code_verifier", VERIFIER),
            ("resource", RESOURCE),
        ])
        .finish()
}
async fn exchange(addr: SocketAddr, code: &str, client: &str, redirect: &str) -> Value {
    let response = http::post(addr, token_body(code, client, redirect), None).await;
    assert_eq!(response.status(), 200);
    let issued = http::value(response).await;
    let refresh = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "refresh_token"),
            ("client_id", client),
            ("refresh_token", issued["refresh_token"].as_str().unwrap()),
            ("resource", RESOURCE),
        ])
        .finish();
    let rotated = http::post(addr, refresh, None).await;
    assert_eq!(rotated.status(), 200);
    issued
}
#[tokio::test]
#[ignore = "native executable, real TLS PostgreSQL and genuine HTTPS H1→callback→W3→token/refresh; Admin off"]
async fn broker_oidc_browser_callback_http_contract() {
    let mut f = OidcFixture::new().await;
    let issuer = std::sync::Arc::new(BrowserIssuer::new().await);
    federated::register(&issuer, "public");
    issuer.fault(Fault {
        id_overrides: [
            ("mapped_subject".into(), json!("alice-subject")),
            ("roles".into(), json!(["admin"])),
        ]
        .into(),
        ..Fault::default()
    });
    let verifier = federated::verifier(&issuer, vec![federated::client("public")], Some("roles"));
    let root = tempfile::tempdir().unwrap();
    let addr = http::address();
    let config = configuration(root.path(), &f, &issuer, addr, f.fixture.port);
    let path = http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    assert!(
        http::command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .status()
            .await
            .unwrap()
            .success()
    );
    let mut too_small = config.clone();
    too_small["auth"]["digest"]["token_bytes"] = json!(48);
    http::write(root.path(), &serde_saphyr::to_string(&too_small).unwrap());
    assert!(
        !http::command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .status()
            .await
            .unwrap()
            .success(),
        "full state49 must be representable with Admin off"
    );
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = start_native(root.path(), &path, addr, "protocol").await;
    assert_eq!(
        reqwest::get(format!("http://{addr}/admin"))
            .await
            .unwrap()
            .status(),
        404
    );
    let redirect = "http://127.0.0.1:49158/cb?kept=%2F";
    let client = register(addr, redirect).await;
    for mode in ["query", "fragment", "form_post"] {
        let state = if mode == "form_post" {
            " state café +%<danger>\"'& "
        } else {
            " state\0\r\n café +%<danger>\"'& "
        };
        let pending = create_pending(&f, &client, redirect, mode, state).await;
        let flow = issued(&f, &verifier, pending.request()).await;
        let code = issuer.authorize(&flow).await;
        let missing = no_redirect()
            .get(callback_url(addr, flow.state(), Some(&code)))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 401);
        assert!(missing.headers().get("set-cookie").is_none());
        let duplicate = no_redirect()
            .get(format!(
                "{}&state={}",
                callback_url(addr, flow.state(), Some(&code)),
                flow.state()
            ))
            .header("cookie", cookie(&flow, true))
            .send()
            .await
            .unwrap();
        assert_eq!(duplicate.status(), 401);
        let hits = issuer.token_hits();
        let response = callback(addr, &flow, Some(&code), true).await;
        headers(&response, &flow, true);
        let granted = response_code(response, mode, redirect, state).await;
        assert_eq!(issuer.token_hits(), hits + 1);
        let _tokens = exchange(addr, &granted, &client, redirect).await;
        let replay = callback(addr, &flow, Some(&code), true).await;
        assert_eq!(replay.status(), 401);
        assert!(replay.headers().get("location").is_none());
        assert_eq!(issuer.token_hits(), hits + 1);
        let pending = create_pending(&f, &client, redirect, mode, "denied literal").await;
        let flow = issued(&f, &verifier, pending.request()).await;
        let denied = callback(addr, &flow, None, true).await;
        headers(&denied, &flow, true);
        if mode == "form_post" {
            assert_eq!(denied.status(), 200);
            let html = denied.text().await.unwrap();
            assert!(html.contains("name=\"error\" value=\"access_denied\""));
        } else {
            assert_eq!(denied.status(), 303);
            let location = denied.headers()["location"].to_str().unwrap();
            assert_eq!(parameter(location, mode, "error"), "access_denied");
            assert_eq!(parameter(location, mode, "state"), "denied literal");
        }
    }
    for state in ["state\0x", "state\rx", "state\nx"] {
        let pending = create_pending(&f, &client, redirect, "form_post", state).await;
        let flow = issued(&f, &verifier, pending.request()).await;
        let code = issuer.authorize(&flow).await;
        let response = callback(addr, &flow, Some(&code), true).await;
        assert_eq!(response.status(), 400);
        assert!(response.headers().get("location").is_none());
        let body = response.text().await.unwrap();
        assert!(!body.contains("name=\"code\""));
    }
    let pending = create_pending(&f, &client, redirect, "query", "current redirect").await;
    let flow = issued(&f, &verifier, pending.request()).await;
    sqlx_core::query::query(
        "UPDATE public.oauth_dynamic_clients SET redirect_uris_json=$2 WHERE client_id=$1",
    )
    .bind(&client)
    .bind(r#"["https://client.example/other"]"#)
    .execute(&mut f.admin)
    .await
    .unwrap();
    let denied = callback(addr, &flow, None, true).await;
    assert!(denied.status().is_client_error() || denied.status().is_server_error());
    assert!(
        denied.headers().get("location").is_none(),
        "revoked redirect cannot remain a response destination"
    );
    stop_native(child, root.path(), "protocol").await;
    if let Some(index) = std::env::var_os("GRAPHIT_BROKER_FORM_POST_UI") {
        browser_qualification(&f, issuer.clone(), root.path(), Path::new(&index)).await;
    }
    let mut issuer = std::sync::Arc::try_unwrap(issuer)
        .ok()
        .expect("browser fixture must release issuer ownership");
    issuer.close().await;
    f.close().await;
}

async fn auth_request_lock(admin: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock' AND query LIKE '%public.oidc_auth_requests%' LIMIT 1").fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "native completion must reach the held authorization table"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn hold_known_commit(
    relay: &mut commit::CommitRelay,
    admin: &mut sqlx_postgres::PgConnection,
    pid: i32,
    hash: &str,
) {
    loop {
        let decision = tokio::time::timeout_at(deadline().into(), relay.replies.recv())
            .await
            .unwrap()
            .unwrap();
        let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
            "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
        )
        .bind(pid)
        .fetch_one(&mut *admin)
        .await
        .unwrap();
        let completed:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.oidc_auth_requests WHERE request_hash=$1 AND code_hash IS NOT NULL").bind(hash).fetch_one(&mut *admin).await.unwrap();
        if query == "COMMIT" && idle && completed == 1 {
            decision.send(false).unwrap();
            return;
        }
        decision.send(true).unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native callback with real purpose-specific lock deadlines and known COMMIT idle while TLS ACK withheld"]
async fn broker_oidc_browser_callback_uncertainty_contract() {
    let mut f = OidcFixture::new().await;
    let mut issuer = BrowserIssuer::new().await;
    federated::register(&issuer, "public");
    issuer.fault(Fault {
        id_overrides: [
            ("mapped_subject".into(), json!("alice-subject")),
            ("roles".into(), json!(["admin"])),
        ]
        .into(),
        ..Fault::default()
    });
    let verifier = federated::verifier(&issuer, vec![federated::client("public")], Some("roles"));
    let root = tempfile::tempdir().unwrap();
    let addr = http::address();
    let mut config = configuration(root.path(), &f, &issuer, addr, f.fixture.port);
    let recipe: Value = serde_saphyr::from_str(http::block(include_str!(
        "../../../docs/rust-admin-cookie-session.md"
    )))
    .unwrap();
    config["administration"] = recipe["administration"].clone();
    config["administration"]["cookie_secure"] = json!(false);
    config["administration"]["request_timeout"] = json!("2s");
    config["oidc"]["request_timeout"] = json!("200ms");
    let path = http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = start_native(root.path(), &path, addr, "budgets").await;
    let redirect = "http://127.0.0.1:49158/cb";
    let client = register(addr, redirect).await;
    let oauth_pending = create_pending(&f, &client, redirect, "query", "budget literal").await;
    let oauth = issued(&f, &verifier, oauth_pending.request()).await;
    let admin = f
        .store
        .upstream_logins(&verifier)
        .begin(
            FlowContinuation::Admin {
                provider_id: verifier.browser_options(deadline()).unwrap()[0].id.clone(),
            },
            deadline(),
        )
        .await
        .unwrap();
    let swapped = format!("admin.{}", oauth.state().split_once('.').unwrap().1);
    let renamed = format!(
        "{}={}",
        broker_presence::upstream_login_flow_cookie_name(&swapped, false),
        oauth.browser_binding()
    );
    let before: i64 =
        sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.oidc_flows")
            .fetch_one(&mut f.admin)
            .await
            .unwrap();
    let response = no_redirect()
        .get(callback_url(addr, &swapped, None))
        .header("cookie", renamed)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert!(response.headers().get("set-cookie").is_none());
    let after: i64 =
        sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.oidc_flows")
            .fetch_one(&mut f.admin)
            .await
            .unwrap();
    assert_eq!(
        before, after,
        "renamed cookie cannot turn a hint into a matching SQL state"
    );
    let mut locker = f.fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("BEGIN; LOCK TABLE public.oidc_flows IN ACCESS EXCLUSIVE MODE")
        .execute(&mut locker)
        .await
        .unwrap();
    let unlock = async {
        let end = deadline();
        loop {
            let waiting:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock' AND query LIKE '%public.oidc_flows%'").fetch_one(&mut f.admin).await.unwrap();
            if waiting >= 2 {
                break;
            }
            assert!(
                Instant::now() < end,
                "both purpose callbacks must reach actual held SQL"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(350)).await;
        sqlx_core::raw_sql::raw_sql("ROLLBACK")
            .execute(&mut locker)
            .await
            .unwrap();
    };
    let (admin_result, oauth_result, ()) = tokio::join!(
        callback(addr, &admin, None, false),
        callback(addr, &oauth, None, false),
        unlock
    );
    assert_eq!(
        admin_result.status(),
        303,
        "OAuth's shorter timeout cannot shorten the Admin Original"
    );
    assert!(
        admin_result.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("/admin/#login_error=oidc_error")
    );
    assert_eq!(oauth_result.status(), 504);
    assert!(
        oauth_result.headers().get("location").is_none()
            && oauth_result.headers().get("set-cookie").is_none()
    );
    let recovery = callback(addr, &oauth, None, false).await;
    assert_eq!(
        recovery.status(),
        303,
        "deadline before consume preserves the genuine original flow"
    );
    assert_eq!(
        issuer.token_hits(),
        0,
        "provider-error branch never exchanges a code"
    );
    stop_native(child, root.path(), "budgets").await;

    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let addr = http::address();
    let mut config = configuration(root.path(), &f, &issuer, addr, relay.port);
    config["administration"] = json!({"enabled":false,"cookie_secure":false});
    config["oidc"]["request_timeout"] = json!("2s");
    let path = http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = start_native(root.path(), &path, addr, "completion-ack").await;
    let p = create_pending(&f, &client, redirect, "query", "uncertain literal").await;
    let flow = issued(&f, &verifier, p.request()).await;
    let code = issuer.authorize(&flow).await;
    let hash = oidc::digester()
        .token(
            broker_security::TokenKind::OidcAuthRequest,
            p.request().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    sqlx_core::raw_sql::raw_sql(
        "BEGIN; LOCK TABLE public.oidc_auth_requests IN ACCESS EXCLUSIVE MODE",
    )
    .execute(&mut locker)
    .await
    .unwrap();
    let pending_response = callback(addr, &flow, Some(&code), false);
    tokio::pin!(pending_response);
    let pid = tokio::select! {pid=auth_request_lock(&mut f.admin)=>pid,result=&mut pending_response=>panic!("completion must wait before a response: {}",result.status())};
    relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    sqlx_core::raw_sql::raw_sql("ROLLBACK")
        .execute(&mut locker)
        .await
        .unwrap();
    tokio::select! {_=hold_known_commit(&mut relay,&mut f.admin,pid,&hash)=>{},result=&mut pending_response=>panic!("completion ACK must be withheld after COMMIT idle: {}",result.status())};
    let response = pending_response.await;
    assert_eq!(response.status(), 503);
    headers(&response, &flow, false);
    assert!(response.headers().get("location").is_none());
    relay
        .armed
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let hits = issuer.token_hits();
    let replay = callback(addr, &flow, Some(&code), false).await;
    assert_eq!(replay.status(), 401);
    assert_eq!(
        issuer.token_hits(),
        hits,
        "uncertain completion never replays H1"
    );
    let p = create_pending(&f, &client, redirect, "query", "fresh after uncertain").await;
    let flow = issued(&f, &verifier, p.request()).await;
    let code = issuer.authorize(&flow).await;
    let response = callback(addr, &flow, Some(&code), false).await;
    headers(&response, &flow, false);
    let code = response_code(response, "query", redirect, "fresh after uncertain").await;
    let _ = exchange(addr, &code, &client, redirect).await;
    // End the injected TCP blackhole before asking the native SQL owner to drain.
    // All uncertain/no-replay/fresh-recovery assertions above run while the fault exists.
    relay.close().await;
    let closed_by = deadline();
    loop {
        let remaining: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE pid=$1",
        )
        .bind(pid)
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        if remaining == 0 {
            break;
        }
        assert!(
            Instant::now() < closed_by,
            "injected connection must close before native shutdown"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    stop_native(child, root.path(), "completion-ack").await;
    sqlx_core::connection::Connection::close(locker)
        .await
        .unwrap();
    issuer.close().await;
    f.close().await;
}

async fn start_native(
    root: &Path,
    path: &Path,
    addr: SocketAddr,
    phase: &str,
) -> tokio::process::Child {
    let log = std::fs::File::create(root.join(format!("{phase}.stderr"))).unwrap();
    let mut child = http::command()
        .args(["--config", path.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .unwrap();
    let end = deadline();
    loop {
        if reqwest::get(format!("http://{addr}/readyz"))
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return child;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "native {phase} exited during startup: {}",
            std::fs::read_to_string(root.join(format!("{phase}.stderr"))).unwrap()
        );
        assert!(Instant::now() < end, "native {phase} readiness deadline");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn stop_native(child: tokio::process::Child, root: &Path, phase: &str) {
    if let Err(error) = tokio::spawn(http::stop(child)).await {
        let diagnostics = std::fs::read_to_string(root.join(format!("{phase}.stderr"))).unwrap();
        panic!(
            "native {phase} shutdown failed: {error}; stderr: {}",
            diagnostics.chars().take(4000).collect::<String>()
        );
    }
}

struct BrowserRp {
    store: std::sync::Arc<broker_control::PostgresControlStore>,
    policy: std::sync::Arc<broker_control::OidcAuthorizationPolicy>,
    verifier: std::sync::Arc<UpstreamBearerVerifier>,
    issuer: std::sync::Arc<BrowserIssuer>,
    signer: broker_control::BrokerAccessIssuer,
    client: String,
    redirect: String,
    broker: SocketAddr,
    manual_state: String,
    automatic_state: String,
    results: std::sync::Mutex<std::collections::HashSet<&'static str>>,
    changed: tokio::sync::Notify,
}
async fn rp_issue(state: &BrowserRp, literal_state: &str) -> IssuedUpstreamAuthorization {
    let original = deadline();
    let pending = state
        .store
        .browser_oidc_authorizations(&state.policy)
        .create(
            OidcAuthorizationInput {
                client_id: &state.client,
                redirect_uri: &state.redirect,
                response_type: "code",
                scope: "openid profile email offline_access",
                state: literal_state,
                nonce: "literal nonce",
                code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
                code_challenge_method: "S256",
                response_mode: Some("form_post"),
                resources: &[RESOURCE],
                prompts: &[],
            },
            original,
        )
        .await
        .unwrap();
    state
        .store
        .upstream_logins(&state.verifier)
        .begin(
            federated::continuation(&state.verifier, pending.request()),
            original,
        )
        .await
        .unwrap()
}
async fn rp_preview(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<BrowserRp>>,
) -> axum::response::Response {
    let flow = rp_issue(&state, &state.manual_state).await;
    let code = state.issuer.authorize(&flow).await;
    let manual = callback(state.broker, &flow, Some(&code), false).await;
    assert_eq!(manual.status(), 200);
    headers(&manual, &flow, false);
    let mut manual_headers = axum::http::HeaderMap::new();
    // A replay of the representation must not replay transfer framing or cookies.
    for name in [
        "content-type",
        "content-security-policy",
        "cache-control",
        "pragma",
        "referrer-policy",
        "x-content-type-options",
        "x-frame-options",
    ] {
        manual_headers.insert(name, manual.headers()[name].clone());
    }
    // This preview only tightens CSP so keyboard/layout can be inspected. The automatic
    // case returns through the actual native callback with its original script hash CSP.
    let original_csp = manual_headers["content-security-policy"].to_str().unwrap();
    let script = original_csp
        .split("script-src ")
        .nth(1)
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let preview_csp = original_csp.replace(&format!("script-src {script}"), "script-src 'none'");
    manual_headers.insert(
        "content-security-policy",
        axum::http::HeaderValue::from_str(&preview_csp).unwrap(),
    );
    let manual_html = manual.text().await.unwrap();
    let mut response = axum::response::Response::new(axum::body::Body::from(manual_html));
    *response.headers_mut() = manual_headers;
    response
}
async fn rp_start(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<BrowserRp>>,
) -> axum::response::Response {
    let flow = rp_issue(&state, &state.automatic_state).await;
    let code = state.issuer.authorize(&flow).await;
    let cookie = broker_presence::upstream_login_flow_cookie(&flow, false).unwrap();
    let mut response = axum::response::Response::new(axum::body::Body::empty());
    *response.status_mut() = axum::http::StatusCode::FOUND;
    response.headers_mut().insert("set-cookie", cookie);
    response.headers_mut().insert(
        "location",
        axum::http::HeaderValue::from_str(&callback_url(state.broker, flow.state(), Some(&code)))
            .unwrap(),
    );
    flow.check().unwrap();
    response
}
async fn rp_post(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<BrowserRp>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Html<String> {
    assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
    let fields: Vec<_> = url::form_urlencoded::parse(&body).collect();
    assert_eq!(fields.len(), 2);
    let code = fields
        .iter()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .as_ref();
    let actual = fields
        .iter()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .as_ref();
    let branch = if actual == state.manual_state {
        "manual"
    } else {
        assert_eq!(
            actual, state.automatic_state,
            "real browser must echo original state bytes"
        );
        "automatic"
    };
    assert!(
        !state.results.lock().unwrap().contains(branch),
        "browser response is consumed once"
    );
    let tokens = exchange(state.broker, code, &state.client, &state.redirect).await;
    let access = http::claims(
        &state.signer,
        &format!("http://{}", state.broker),
        tokens["access_token"].as_str().unwrap(),
    );
    let id = http::claims(
        &state.signer,
        &format!("http://{}", state.broker),
        tokens["id_token"].as_str().unwrap(),
    );
    assert_eq!(access["client_id"], state.client);
    assert_eq!(id["nonce"], "literal nonce");
    assert_eq!(id["amr"], json!(["federated"]));
    state.results.lock().unwrap().insert(branch);
    state.changed.notify_one();
    let next = if branch == "manual" {
        "<p><a href=\"/start\">Test automatic return</a></p>"
    } else {
        ""
    };
    axum::response::Html(format!(
        "<!doctype html><html lang=\"en\"><title>Browser callback verified</title><main><h1>{branch} browser POST verified</h1><p>State bytes, PKCE exchange, signed tokens and refresh verified.</p>{next}</main></html>"
    ))
}
async fn browser_qualification(
    f: &OidcFixture,
    issuer: std::sync::Arc<BrowserIssuer>,
    root: &Path,
    index: &Path,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rp = listener.local_addr().unwrap();
    let redirect = format!("http://{rp}/cb");
    let broker = http::address();
    let mut config = configuration(root, f, &issuer, broker, f.fixture.port);
    config["administration"] = json!({"enabled":false,"cookie_secure":false});
    let path = http::write(root, &serde_saphyr::to_string(&config).unwrap());
    let child = start_native(root, &path, broker, "browser-ui").await;
    let client = register(broker, &redirect).await;
    let verifier = std::sync::Arc::new(federated::verifier(
        &issuer,
        vec![federated::client("public")],
        Some("roles"),
    ));
    let manual_state = "manual café +%<&\"'> literal".to_owned();
    let automatic_state = "automatic café +%<&\"'> literal".to_owned();
    let key = zeroize::Zeroizing::new(std::fs::read(root.join("signing.pk8")).unwrap());
    let signer = broker_control::BrokerAccessIssuer::new(
        &format!("http://{broker}"),
        oidc::AUDIENCE,
        "configured-key",
        &key,
    )
    .unwrap();
    let state = std::sync::Arc::new(BrowserRp {
        store: f.store.clone(),
        policy: f.policy.clone(),
        verifier,
        issuer,
        signer,
        client,
        redirect,
        broker,
        manual_state,
        automatic_state,
        results: std::sync::Mutex::new(std::collections::HashSet::new()),
        changed: tokio::sync::Notify::new(),
    });
    let router = axum::Router::new()
        .route("/preview", axum::routing::get(rp_preview))
        .route("/start", axum::routing::get(rp_start))
        .route("/cb", axum::routing::post(rp_post))
        .with_state(state.clone());
    let (stop, stopping) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopping.await;
            })
            .await
            .unwrap();
    });
    let preview = no_redirect()
        .get(format!("http://{rp}/preview"))
        .send()
        .await
        .unwrap();
    assert_eq!(preview.status(), 200);
    assert!(
        preview
            .text()
            .await
            .unwrap()
            .contains("id=\"oauth-response\"")
    );
    let cancel = index.with_extension("stop");
    if cancel.exists() {
        std::fs::remove_file(&cancel).unwrap();
    }
    std::fs::write(index,serde_json::to_vec(&json!({"status":"ready","preview":format!("http://{rp}/preview"),"automatic":format!("http://{rp}/start")})).unwrap()).unwrap();
    let completed = tokio::time::timeout(Duration::from_secs(600), async {
        loop {
            let changed = state.changed.notified();
            if state.results.lock().unwrap().len() == 2 { break true; }
            if cancel.exists() { break false; }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep(Duration::from_millis(250)) => {} }
        }
    })
    .await.unwrap_or(false);
    let _ = stop.send(());
    server.await.unwrap();
    drop(state);
    stop_native(child, root, "browser-ui").await;
    assert!(
        completed,
        "complete the actual manual and automatic browser POST checks within the fixture window; create the index .stop sibling to cancel safely"
    );
    std::fs::write(index,serde_json::to_vec(&json!({"status":"passed","manual_post":true,"automatic_post":true,"signed_tokens":true,"refresh":true})).unwrap()).unwrap();
}
