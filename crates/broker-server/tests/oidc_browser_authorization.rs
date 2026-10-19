//! Native public browser journeys over HTTP, TLS PostgreSQL and genuine producers.
#[path = "../../broker-control/tests/support/browser_upstream.rs"]
#[allow(
    dead_code,
    reason = "HTTPS fixture also covers upstream fault contracts"
)]
mod browser;
#[path = "support/upstream_commit.rs"]
mod commit;
#[path = "../../broker-control/tests/support/oidc_federated.rs"]
#[allow(
    dead_code,
    reason = "shared provider recipe covers other grant contracts"
)]
mod federated;
#[path = "support/oidc_http.rs"]
#[allow(
    dead_code,
    reason = "shared process fixture covers other token contracts"
)]
mod http;
#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
#[allow(dead_code, reason = "shared SQL fixture covers producer contracts")]
mod oidc;
#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(dead_code, reason = "shared PostgreSQL fixture covers other contracts")]
mod support;
#[path = "support/oidc_browser_ui.rs"]
mod ui;
use broker_control::{BrokerAccessIssuer, LocalPasswordEngine};
use broker_security::LocalPasswordHasher;
use oidc::{OidcFixture, PASSWORD, PEPPER, RESOURCE, VERIFIER};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use std::{net::SocketAddr, path::Path, time::Duration};
use support::{deadline, n};
use zeroize::Zeroizing;

const REDIRECT: &str = "http://127.0.0.1:49158/cb?kept=%2F";
const STATE: &str = " literal state café +%<>&\"' ";
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}
fn config(addr: SocketAddr, pg: u16, mfa: bool) -> Value {
    let mut value: Value = serde_saphyr::from_str(&http::yaml(addr, pg)).unwrap();
    value["auth"]["local"] = json!({"login":{"enabled":true},"mfa":{"required":mfa,"issuer_label":"Graphit Broker","challenge_ttl":"10m"},"rate_limit":{"max_failures":20,"window":"60s","lockout":"300s","max_concurrent":2,"saturation_multiplier":4}});
    value
}
async fn seed(f: &mut OidcFixture) {
    let engine = LocalPasswordEngine::new(
        LocalPasswordHasher::new(Zeroizing::new(
            PEPPER.as_bytes().to_vec().into_boxed_slice(),
        ))
        .unwrap(),
        n(1),
        deadline(),
    )
    .await
    .unwrap();
    let hash = engine.hash(PASSWORD, deadline()).await.unwrap();
    sqlx_core::query::query(
        "UPDATE public.local_users SET password_hash=$1 WHERE username='alice'",
    )
    .bind(hash.as_str())
    .execute(&mut f.admin)
    .await
    .unwrap();
    engine.close().await;
}
async fn start(root: &Path, config: &Value, addr: SocketAddr) -> tokio::process::Child {
    let path = http::write(root, &serde_saphyr::to_string(config).unwrap());
    let checked = http::command()
        .args(["--config", path.to_str().unwrap(), "--check-config"])
        .output()
        .await
        .unwrap();
    assert!(
        checked.status.success(),
        "native configuration: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
    http::start(&path, addr).await
}
async fn register(addr: SocketAddr) -> String {
    let response = client().post(format!("http://{addr}/oauth/register")).header("content-type","application/json").body(serde_json::to_vec(&json!({"redirect_uris":["https://client.example/cb",REDIRECT],"token_endpoint_auth_method":"none","client_name":"Browser application"})).unwrap()).send().await.unwrap();
    assert_eq!(response.status(), 201);
    http::value(response).await["client_id"]
        .as_str()
        .unwrap()
        .into()
}
fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}
fn authorize_form(client: &str, mode: &str) -> String {
    form(&[
        ("client_id", client),
        ("redirect_uri", REDIRECT),
        ("response_type", "code"),
        ("scope", "openid profile email offline_access"),
        ("state", STATE),
        ("nonce", "browser nonce"),
        (
            "code_challenge",
            "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
        ),
        ("code_challenge_method", "S256"),
        ("response_mode", mode),
        ("resource", RESOURCE),
    ])
}
async fn pending(addr: SocketAddr, client_id: &str, mode: &str) -> String {
    let response = client()
        .get(format!(
            "http://{addr}/oauth/authorize?{}",
            authorize_form(client_id, mode)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    privacy(&response);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.starts_with("/oauth/login?id="));
    location.into()
}
fn privacy(response: &reqwest::Response) {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ] {
        assert_eq!(response.headers()[name], value);
    }
}
fn destination_csp(response: &reqwest::Response) {
    let csp = response.headers()["content-security-policy"]
        .to_str()
        .unwrap();
    assert!(
        csp.contains("form-action 'self' http://127.0.0.1:49158;"),
        "native POST must permit its admitted cross-origin return: {csp}"
    );
}
async fn post(addr: SocketAddr, path: &str, pairs: &[(&str, &str)]) -> reqwest::Response {
    client()
        .post(format!("http://{addr}{path}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(pairs))
        .send()
        .await
        .unwrap()
}
fn input(html: &str, name: &str) -> String {
    regex::Regex::new(&format!(r#"name="{name}" value="([A-Za-z0-9_-]{{43}})"#))
        .unwrap()
        .captures(html)
        .unwrap()[1]
        .into()
}
// Fixed fixture fields are URI/base32 DATA. Real browser QA separately parses HTML.
fn html_parameter(html: &str, name: &str) -> String {
    let pattern = format!(r"{name}=([A-Za-z0-9%._~*+\-]+)");
    let captures = regex::Regex::new(&pattern).unwrap().captures(html).unwrap();
    let field = format!("{name}={}", &captures[1]);
    url::form_urlencoded::parse(field.as_bytes())
        .next()
        .unwrap()
        .1
        .into_owned()
}
fn enrollment_sdk(html: &str) -> totp_rs::Totp {
    let captures = regex::Regex::new(r"Setup key: <code>([A-Z2-7]+)</code>")
        .unwrap()
        .captures(html)
        .unwrap();
    totp_rs::Totp::from_url(format!(
        "otpauth://totp/Graphit%20Broker:alice?secret={}&issuer=Graphit%20Broker&algorithm=SHA1&digits=6&period=30",
        &captures[1]
    ))
    .unwrap()
}
fn parameter(location: &str, mode: &str, name: &str) -> String {
    let url = url::Url::parse(location).unwrap();
    let encoded = if mode == "fragment" {
        url.fragment().unwrap()
    } else {
        url.query().unwrap()
    };
    url::form_urlencoded::parse(encoded.as_bytes())
        .find(|(k, _)| k == name)
        .unwrap()
        .1
        .into_owned()
}
async fn code(
    response: reqwest::Response,
    mode: &str,
    recovery: bool,
) -> (String, Vec<Zeroizing<String>>) {
    privacy(&response);
    assert!(
        response.headers().get("set-cookie").is_none(),
        "LOCAL never emits an administrative session"
    );
    if mode == "form_post" || recovery {
        assert_eq!(response.status(), 200);
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .to_owned();
        let html = response.text().await.unwrap();
        let codes = if recovery {
            assert!(!html.contains("<script") && !csp.contains("sha256-"));
            assert!(
                html.contains("Save your recovery codes")
                    && html.contains("Continue to application")
            );
            regex::Regex::new(r"<li><code>([A-Z2-7-]+)</code></li>")
                .unwrap()
                .captures_iter(&html)
                .map(|c| Zeroizing::new(c[1].to_owned()))
                .collect::<Vec<_>>()
        } else {
            assert!(csp.contains("sha256-"));
            Vec::new()
        };
        if recovery {
            assert_eq!(codes.len(), 10);
        }
        if mode == "form_post" {
            (input(&html, "code"), codes)
        } else {
            assert_eq!(html_parameter(&html, "state"), STATE);
            (html_parameter(&html, "code"), codes)
        }
    } else {
        assert_eq!(response.status(), 303);
        let location = response.headers()["location"].to_str().unwrap();
        assert!(location.starts_with(REDIRECT));
        assert_eq!(parameter(location, mode, "state"), STATE);
        (parameter(location, mode, "code"), Vec::new())
    }
}
async fn exchange(addr: SocketAddr, code: &str, client: &str, signer: &BrokerAccessIssuer) {
    let response = http::post(
        addr,
        form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    let tokens = http::value(response).await;
    let access = http::claims(
        signer,
        &format!("http://{addr}"),
        tokens["access_token"].as_str().unwrap(),
    );
    let id = http::claims(
        signer,
        &format!("http://{addr}"),
        tokens["id_token"].as_str().unwrap(),
    );
    assert_eq!(access["client_id"], client);
    assert_eq!(id["nonce"], "browser nonce");
    let response = http::post(
        addr,
        form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    let refreshed = http::value(response).await;
    let _ = http::claims(
        signer,
        &format!("http://{addr}"),
        refreshed["access_token"].as_str().unwrap(),
    );
}
async fn count(f: &mut OidcFixture) -> i64 {
    sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.oidc_auth_requests")
        .fetch_one(&mut f.admin)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native public authorize/LOCAL HTTP and TLS PostgreSQL, DCR/token/refresh"]
async fn broker_oidc_browser_authorization_local_http() {
    let mut f = OidcFixture::new().await;
    seed(&mut f).await;
    let root = tempfile::tempdir().unwrap();
    let addr = http::address();
    let signer = http::files(root.path(), &f.fixture.ca, &format!("http://{addr}"));
    let child = start(root.path(), &config(addr, f.fixture.port, false), addr).await;
    let client_id = register(addr).await;
    // Holding the request table proves unsupported HEAD does not enter SQL.
    let mut lock = f.fixture.connection().await;
    lock.execute("BEGIN; LOCK TABLE public.oidc_auth_requests IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    for path in ["/oauth/authorize", "/oauth/login"] {
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            client().head(format!("http://{addr}{path}")).send(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), 405);
    }
    lock.execute("ROLLBACK").await.unwrap();
    let before = count(&mut f).await;
    for (path, body, content, status) in [
        (
            "/oauth/authorize?client_id=x",
            "client_id=y",
            Some("application/x-www-form-urlencoded"),
            400,
        ),
        (
            "/oauth/authorize",
            "client_id=x",
            Some("application/json"),
            415,
        ),
        (
            "/oauth/authorize",
            "state=%FF",
            Some("application/x-www-form-urlencoded"),
            400,
        ),
        (
            "/oauth/login?id=x",
            "id=y",
            Some("application/x-www-form-urlencoded"),
            400,
        ),
        ("/oauth/login?id=x&password=secret", "", None, 400),
    ] {
        let mut request = client().post(format!("http://{addr}{path}")).body(body);
        if let Some(content) = content {
            request = request.header("content-type", content);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), status);
        privacy(&response);
        assert!(response.headers().get("location").is_none());
    }
    assert_eq!(count(&mut f).await, before);
    for mode in ["query", "fragment", "form_post"] {
        for (key, value, expected) in [
            ("response_type", "token", "invalid_request"),
            ("scope", "unknown", "invalid_scope"),
            ("prompt", "none", "login_required"),
            (
                "resource",
                "https://unconfigured.example/v1",
                "invalid_target",
            ),
        ] {
            let mut pairs: Vec<(String, String)> =
                url::form_urlencoded::parse(authorize_form(&client_id, mode).as_bytes())
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
            if let Some(pair) = pairs.iter_mut().find(|(k, _)| k == key) {
                pair.1 = value.into();
            } else {
                pairs.push((key.into(), value.into()));
            }
            let encoded = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .finish();
            let response = client()
                .get(format!("http://{addr}/oauth/authorize?{encoded}"))
                .send()
                .await
                .unwrap();
            privacy(&response);
            if mode == "form_post" {
                assert_eq!(response.status(), 200);
                let html = response.text().await.unwrap();
                assert!(html.contains(&format!("name=\"error\" value=\"{expected}\"")));
            } else {
                assert_eq!(response.status(), 303);
                let location = response.headers()["location"].to_str().unwrap();
                assert_eq!(parameter(location, mode, "error"), expected);
                assert_eq!(parameter(location, mode, "state"), STATE);
            }
            assert_eq!(
                count(&mut f).await,
                before,
                "semantic rejection does not insert a pending row"
            );
        }
    }
    for mode in ["query", "fragment", "form_post", "unknown-mode"] {
        let path = pending(addr, &client_id, mode).await;
        let response = client()
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        privacy(&response);
        destination_csp(&response);
        let html = response.text().await.unwrap();
        assert!(
            html.contains("autocomplete=\"username\"")
                && html.contains("Sign in to your application")
        );
        assert!(!html.contains(PASSWORD));
        let response = post(
            addr,
            &path,
            &[
                ("login_method", "local"),
                ("username", "alice"),
                ("password", PASSWORD),
            ],
        )
        .await;
        let actual_mode = if mode == "unknown-mode" {
            "query"
        } else {
            mode
        };
        let (issued, _) = code(response, actual_mode, false).await;
        exchange(addr, &issued, &client_id, &signer).await;
        assert_eq!(
            post(
                addr,
                &path,
                &[("username", "alice"), ("password", PASSWORD)]
            )
            .await
            .status(),
            400,
            "consumed request cannot log in again"
        );
    }
    let body = authorize_form(&client_id, "query");
    let response = client()
        .post(format!("http://{addr}/oauth/authorize?{body}"))
        .body("")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        303,
        "empty POST body uses query without Content-Type"
    );
    http::stop(child).await;
    let mut off = config(addr, f.fixture.port, false);
    off["oidc"]["enabled"] = json!(false);
    off["auth"]["local"]["login"]["enabled"] = json!(false);
    let child = start(root.path(), &off, addr).await;
    for path in ["/oauth/authorize", "/oauth/login"] {
        assert_eq!(
            client()
                .get(format!("http://{addr}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }
    http::stop(child).await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native password change, bound MFA/enrollment and one-time manual recovery with TLS PostgreSQL"]
async fn broker_oidc_browser_authorization_mfa_recovery() {
    let mut f = OidcFixture::new().await;
    seed(&mut f).await;
    let root = tempfile::tempdir().unwrap();
    if let Some(index) = std::env::var_os("GRAPHIT_BROKER_PUBLIC_BROWSER_UI") {
        ui::qualify(&mut f, root.path(), Path::new(&index)).await;
        f.close().await;
        return;
    }
    let addr = http::address();
    let signer = http::files(root.path(), &f.fixture.ca, &format!("http://{addr}"));
    let child = start(root.path(), &config(addr, f.fixture.port, true), addr).await;
    let client_id = register(addr).await;
    let mut password = Zeroizing::new(PASSWORD.to_owned());
    for (index, mode) in ["query", "fragment", "form_post"].into_iter().enumerate() {
        f.admin.execute("DELETE FROM public.local_mfa; DELETE FROM public.local_mfa_recovery_codes; UPDATE public.local_users SET password_change_required=1").await.unwrap();
        let path = pending(addr, &client_id, mode).await;
        let response = post(
            addr,
            &path,
            &[("username", "alice"), ("password", &password)],
        )
        .await;
        assert_eq!(response.status(), 200);
        destination_csp(&response);
        let html = response.text().await.unwrap();
        assert!(html.contains("Choose a new password"));
        let challenge = input(&html, "challenge_token");
        let next = Zeroizing::new(format!("native changed browser password {index}"));
        let response = post(
            addr,
            &path,
            &[
                ("challenge_token", &challenge),
                ("new_password", &next),
                ("confirm_password", "different"),
            ],
        )
        .await;
        assert_eq!(response.status(), 400);
        destination_csp(&response);
        let html = response.text().await.unwrap();
        assert!(!html.contains(next.as_str()) && html.contains(&challenge));
        let response = post(
            addr,
            &path,
            &[
                ("challenge_token", &challenge),
                ("new_password", &next),
                ("confirm_password", &next),
            ],
        )
        .await;
        assert_eq!(response.status(), 200);
        destination_csp(&response);
        let html = response.text().await.unwrap();
        assert!(html.contains("Set up two-step verification"));
        let challenge = input(&html, "challenge_token");
        let sdk = enrollment_sdk(&html);
        let response = post(
            addr,
            &path,
            &[("challenge_token", &challenge), ("code", "invalid")],
        )
        .await;
        assert_eq!(response.status(), 401);
        destination_csp(&response);
        let html = response.text().await.unwrap();
        assert!(
            html.contains("Set up two-step verification") && !html.contains("value=\"invalid\"")
        );
        let otp = Zeroizing::new(
            sdk.generate((oidc::micros() as u64) / 1_000_000)
                .to_string(),
        );
        let response = post(
            addr,
            &path,
            &[("challenge_token", &challenge), ("code", &otp)],
        )
        .await;
        let (issued, recovery) = code(response, mode, true).await;
        exchange(addr, &issued, &client_id, &signer).await;
        assert_eq!(recovery.len(), 10);
        password = next;
        let path = pending(addr, &client_id, mode).await;
        let response = post(
            addr,
            &path,
            &[("username", "alice"), ("password", &password)],
        )
        .await;
        assert_eq!(response.status(), 200);
        destination_csp(&response);
        let html = response.text().await.unwrap();
        assert!(html.contains("Verify your sign-in") && !html.contains("Save your recovery codes"));
        let challenge = input(&html, "challenge_token");
        let wrong = pending(addr, &client_id, mode).await;
        let response = post(
            addr,
            &wrong,
            &[("challenge_token", &challenge), ("code", &recovery[0])],
        )
        .await;
        assert_eq!(
            response.status(),
            401,
            "challenge cannot migrate to another pending request"
        );
        let attempts = [
            ("challenge_token", challenge.as_str()),
            ("code", recovery[0].as_str()),
        ];
        let (a, b) = tokio::join!(post(addr, &path, &attempts), post(addr, &path, &attempts));
        let (winner, loser) = if a.status().is_success() || a.status() == 303 {
            (a, b)
        } else {
            (b, a)
        };
        assert!(loser.status() == 401 || loser.status() == 400 || loser.status() == 429);
        let (issued, codes) = code(winner, mode, false).await;
        assert!(codes.is_empty());
        exchange(addr, &issued, &client_id, &signer).await;
    }

    for state_invalid in [true, false] {
        f.admin.execute("DELETE FROM public.local_mfa; DELETE FROM public.local_mfa_recovery_codes; UPDATE public.local_users SET password_change_required=0").await.unwrap();
        let raw_state = if state_invalid {
            "bad\0\r\nstate"
        } else {
            STATE
        };
        // The direct P2 API remains literal; the HTTP initial-admission guard is not this proof.
        let p2 = f
            .store
            .browser_oidc_authorizations(&f.policy)
            .create(
                broker_control::OidcAuthorizationInput {
                    client_id: &client_id,
                    redirect_uri: REDIRECT,
                    response_type: "code",
                    scope: "openid profile email offline_access",
                    state: raw_state,
                    nonce: "browser nonce",
                    code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
                    code_challenge_method: "S256",
                    response_mode: Some("form_post"),
                    resources: &[RESOURCE],
                    prompts: &[],
                },
                deadline(),
            )
            .await
            .unwrap();
        let path = format!("/oauth/login?id={}", p2.request());
        let response = post(
            addr,
            &path,
            &[("username", "alice"), ("password", &password)],
        )
        .await;
        assert_eq!(response.status(), 200);
        let html = response.text().await.unwrap();
        let challenge = input(&html, "challenge_token");
        let sdk = enrollment_sdk(&html);
        let otp = Zeroizing::new(
            sdk.generate((oidc::micros() as u64) / 1_000_000)
                .to_string(),
        );
        if !state_invalid {
            f.admin
                .execute("CREATE FUNCTION public.c2b_reject_code() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''fixture code commit failure''; END;'; CREATE CONSTRAINT TRIGGER c2b_code_commit AFTER UPDATE ON public.oidc_auth_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.code_hash IS NOT NULL) EXECUTE FUNCTION public.c2b_reject_code()")
                .await
                .unwrap();
        }
        let response = post(
            addr,
            &path,
            &[("challenge_token", &challenge), ("code", &otp)],
        )
        .await;
        assert_eq!(response.status(), if state_invalid { 400 } else { 503 });
        privacy(&response);
        assert!(response.headers().get("location").is_none());
        let html = response.text().await.unwrap();
        assert!(
            !html.contains("Save your recovery codes")
                && !html.contains("name=\"code\"")
                && !html.contains("<li><code>")
        );
        let count: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM public.local_mfa_recovery_codes",
        )
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        assert_eq!(
            count, 10,
            "MFA commit is real but presentation owner is discarded on later failure; state_invalid={state_invalid}"
        );
        if !state_invalid {
            f.admin
                .execute("DROP TRIGGER c2b_code_commit ON public.oidc_auth_requests; DROP FUNCTION public.c2b_reject_code()")
                .await
                .unwrap();
        }
    }
    http::stop(child).await;
    f.close().await;
}

fn upstream_provider(issuer: &browser::BrowserIssuer, multiple: bool) -> Value {
    let recipe: Value = serde_saphyr::from_str(http::block(include_str!(
        "../../../docs/rust-admin-upstream-login.md"
    )))
    .unwrap();
    let mut value = recipe["auth"]["oidc"][0].clone();
    value["id"] = json!("external");
    value["issuer"] = json!(issuer.issuer);
    value["ca_file"] = json!("upstream-ca.pem");
    value["claims"]["subject"] = json!("mapped_subject");
    value["claims"]["roles"] = json!("roles");
    value["required_scopes"] = json!([]);
    value["browser_clients"] = json!([{"display_name":"Organization one","client_id":"public","redirect_url":federated::client("public").redirect_url,"scopes":["profile","email"],"require_nonce":true,"claims_source":"id_token","id_token_additional_audiences":[]}]);
    if multiple {
        let mut second = value["browser_clients"][0].clone();
        second["display_name"] = json!("Organization two");
        second["client_id"] = json!("second");
        value["browser_clients"]
            .as_array_mut()
            .unwrap()
            .push(second);
    }
    value
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native browser provider selection/auto-forward, HTTPS IdP, TLS PostgreSQL, callback/code/token/refresh"]
async fn broker_oidc_browser_authorization_upstream_http() {
    let f = OidcFixture::new().await;
    let mut issuer = browser::BrowserIssuer::new().await;
    federated::register(&issuer, "public");
    federated::register(&issuer, "second");
    issuer.fault(browser::Fault {
        id_overrides: [
            ("mapped_subject".into(), json!("alice-subject")),
            ("roles".into(), json!(["admin"])),
        ]
        .into(),
        ..browser::Fault::default()
    });
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("upstream-ca.pem"), &issuer.ca).unwrap();
    for multiple in [false, true] {
        let addr = http::address();
        let signer = http::files(root.path(), &f.fixture.ca, &format!("http://{addr}"));
        let mut value = config(addr, f.fixture.port, false);
        value["auth"]["local"]["login"]["enabled"] = json!(false);
        value["auth"]["oidc"] = json!([upstream_provider(&issuer, multiple)]);
        let child = start(root.path(), &value, addr).await;
        let client_id = register(addr).await;
        for mode in ["query", "fragment", "form_post"] {
            let path = pending(addr, &client_id, mode).await;
            let mut response = client()
                .get(format!("http://{addr}{path}"))
                .send()
                .await
                .unwrap();
            if multiple {
                assert_eq!(response.status(), 200);
                let html = response.text().await.unwrap();
                assert!(
                    html.contains("Organization one")
                        && html.contains("Organization two")
                        && !html.contains("name=\"password\"")
                );
                let selected = html_parameter(&html, "provider");
                response = post(
                    addr,
                    &path,
                    &[("login_method", "oidc"), ("provider", &selected)],
                )
                .await;
            }
            assert_eq!(response.status(), 303);
            privacy(&response);
            let binding = response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            assert!(
                binding.contains("graphit_oidc_flow_")
                    && !binding.contains("graphit_broker_session")
            );
            let location =
                url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
            assert!(location.as_str().starts_with(&issuer.issuer));
            let state = location
                .query_pairs()
                .find(|(k, _)| k == "state")
                .unwrap()
                .1
                .into_owned();
            let authorized = issuer
                .client
                .get(location)
                .basic_auth("browser-fixture", Some("fixture-password"))
                .send()
                .await
                .unwrap();
            assert_eq!(authorized.status(), 302);
            let callback =
                url::Url::parse(authorized.headers()["location"].to_str().unwrap()).unwrap();
            assert_eq!(
                callback
                    .query_pairs()
                    .find(|(k, _)| k == "state")
                    .unwrap()
                    .1,
                state
            );
            let response = client()
                .get(format!(
                    "http://{addr}/oauth/oidc/callback?{}",
                    callback.query().unwrap()
                ))
                .header("cookie", &binding)
                .send()
                .await
                .unwrap();
            assert!(
                response.headers()["set-cookie"]
                    .to_str()
                    .unwrap()
                    .contains("Max-Age=0")
            );
            // The callback's only cookie clears H1; remove it before the common LOCAL assertion.
            let mut response = response;
            response.headers_mut().remove("set-cookie");
            let (issued, _) = code(response, mode, false).await;
            exchange(addr, &issued, &client_id, &signer).await;
            let response = client()
                .get(format!(
                    "http://{addr}/oauth/oidc/callback?{}",
                    callback.query().unwrap()
                ))
                .header("cookie", &binding)
                .send()
                .await
                .unwrap();
            assert!(!response.status().is_success() && response.status() != 303);
        }
        http::stop(child).await;
    }
    // No selected method is represented honestly; no implicit LOCAL fallback.
    let addr = http::address();
    let _signer = http::files(root.path(), &f.fixture.ca, &format!("http://{addr}"));
    let mut value = config(addr, f.fixture.port, false);
    value["auth"]["local"]["login"]["enabled"] = json!(false);
    let child = start(root.path(), &value, addr).await;
    let client_id = register(addr).await;
    let path = pending(addr, &client_id, "query").await;
    assert_eq!(
        client()
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    http::stop(child).await;
    issuer.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real native CAPTCHA render/input/403, request bounds and shared LOCAL rate admission; Siteverify TLS is separate producer evidence"]
async fn broker_oidc_browser_authorization_captcha_and_rates() {
    let mut f = OidcFixture::new().await;
    seed(&mut f).await;
    let root = tempfile::tempdir().unwrap();
    let addr = http::address();
    let _signer = http::files(root.path(), &f.fixture.ca, &format!("http://{addr}"));
    let mut value = config(addr, f.fixture.port, false);
    value["auth"]["local"]["captcha"] = json!({"enabled":true,"provider":"turnstile","site_key":"public-fixture-site","secret_key":"fixture-only-siteverify-secret","trigger_multiplier":0,"verification_timeout":"500ms"});
    let child = start(root.path(), &value, addr).await;
    let client_id = register(addr).await;
    let path = pending(addr, &client_id, "query").await;
    let response = client()
        .get(format!("http://{addr}{path}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let policy = response.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    let html = response.text().await.unwrap();
    assert!(
        html.contains("cf-turnstile")
            && html.contains("data-action=\"oauth-login\"")
            && html.contains("public-fixture-site")
    );
    assert!(policy.contains("https://challenges.cloudflare.com") && !policy.contains("google.com"));
    assert!(!html.contains("fixture-only-siteverify-secret"));
    let response = post(
        addr,
        &path,
        &[("username", "alice"), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(response.status(), 403);
    privacy(&response);
    let html = response.text().await.unwrap();
    assert!(html.contains("Complete the verification") && !html.contains(PASSWORD));
    let oversized = Zeroizing::new("x".repeat(2049));
    let response = post(
        addr,
        &path,
        &[
            ("username", "alice"),
            ("password", PASSWORD),
            ("cf-turnstile-response", &oversized),
        ],
    )
    .await;
    assert_eq!(
        response.status(),
        403,
        "producer bounds the forwarded proof before vendor network"
    );
    for pairs in [
        vec![
            ("username", "alice"),
            ("password", PASSWORD),
            ("g-recaptcha-response", "wrong-provider"),
        ],
        vec![
            ("cf-turnstile-response", "a"),
            ("cf-turnstile-response", "b"),
        ],
    ] {
        assert_eq!(post(addr, &path, &pairs).await.status(), 400);
    }
    for method in [reqwest::Method::GET, reqwest::Method::POST] {
        let response = client()
            .request(method, format!("http://{addr}{path}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("x".repeat(16 * 1024 + 1))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
    }
    http::stop(child).await;
    value["auth"]["local"]["captcha"]["enabled"] = json!(false);
    value["auth"]["local"]["rate_limit"]["max_failures"] = json!(1);
    let child = start(root.path(), &value, addr).await;
    let path = pending(addr, &client_id, "query").await;
    assert_eq!(
        post(
            addr,
            &path,
            &[
                ("username", "alice"),
                ("password", "wrong fixture password")
            ]
        )
        .await
        .status(),
        401
    );
    let response = post(
        addr,
        &path,
        &[("username", "alice"), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(response.status(), 429);
    assert!(
        response.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            >= 1
    );
    assert_eq!(
        client()
            .get(format!("http://{addr}/admin/api/v1/login-options"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    http::stop(child).await;
    f.close().await;
}

async fn locked_backend(f: &mut OidcFixture, table: &str) -> i32 {
    let end = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock' AND query LIKE $1 LIMIT 1").bind(format!("%FROM public.{table}%")).fetch_optional(&mut f.admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            std::time::Instant::now() < end,
            "native SQL operation never reached the held table"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native HTTP Original deadline and real PostgreSQL TLS COMMIT-idle ACK uncertainty, cleanup and healthy recovery"]
async fn broker_oidc_browser_authorization_sql_outcomes() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let addr = http::address();
    let _signer = http::files(root.path(), &f.fixture.ca, &format!("http://{addr}"));
    let mut value = config(addr, relay.port, false);
    value["auth"]["local"]["login"]["enabled"] = json!(false);
    value["oidc"]["request_timeout"] = json!("3s");
    let child = start(root.path(), &value, addr).await;
    let client_id = register(addr).await;
    let before = count(&mut f).await;
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.oauth_dynamic_clients IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let query = authorize_form(&client_id, "query").replace("nonce=browser+nonce", "nonce=");
    let request = client()
        .get(format!("http://{addr}/oauth/authorize?{query}"))
        .send();
    tokio::pin!(request);
    let pid = tokio::select! {pid=locked_backend(&mut f,"oauth_dynamic_clients")=>pid,result=&mut request=>panic!("native authorize did not wait for real SQL: {:?}",result.map(|r|r.status()))};
    relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    locker.execute("ROLLBACK").await.unwrap();
    let hold = async {
        loop {
            let decision = tokio::time::timeout(Duration::from_secs(5), relay.replies.recv())
                .await
                .unwrap()
                .unwrap();
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
    };
    tokio::select! {_=hold=>{},result=&mut request=>panic!("COMMIT ACK was not withheld: {:?}",result.map(|r|r.status()))};
    let response = request.await.unwrap();
    assert_eq!(response.status(), 503);
    privacy(&response);
    assert!(response.headers().get("location").is_none());
    let html = response.text().await.unwrap();
    assert!(html.contains("could not be confirmed") && !html.contains("name=\"code\""));
    assert_eq!(
        count(&mut f).await,
        before,
        "uncertain read commit inserts no pending and emits no target"
    );
    relay
        .armed
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let _ = pending(addr, &client_id, "query").await;
    // An uncommitted read cutoff is a deadline, not a conclusive OAuth rejection.
    locker
        .execute("BEGIN; LOCK TABLE public.oauth_dynamic_clients IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let request = client()
        .get(format!(
            "http://{addr}/oauth/authorize?{}",
            authorize_form(&client_id, "query")
        ))
        .send();
    tokio::pin!(request);
    tokio::select! {_=locked_backend(&mut f,"oauth_dynamic_clients")=>{},result=&mut request=>panic!("native deadline request did not reach lock: {:?}",result.map(|r|r.status()))};
    let response = tokio::time::timeout(Duration::from_secs(8), request)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 504);
    privacy(&response);
    assert!(response.headers().get("location").is_none());
    locker.execute("ROLLBACK").await.unwrap();
    let _ = pending(addr, &client_id, "query").await;
    http::stop(child).await;
    relay.close().await;
    f.close().await;
}
