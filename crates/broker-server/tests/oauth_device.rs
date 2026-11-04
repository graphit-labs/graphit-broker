//! Complete native Device journeys over loopback, private SQLite and genuine LOCAL authentication.
#[path = "support/oidc_http.rs"]
#[allow(dead_code, reason = "shared process fixture covers all native grants")]
mod http;
#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
#[allow(dead_code, reason = "shared SQL fixture covers producer contracts")]
mod oidc;
#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "shared TLS PostgreSQL fixture covers other contracts"
)]
mod support;
use broker_control::LocalPasswordEngine;
use broker_security::LocalPasswordHasher;
use graphit_auth::broker::{
    BrokerPolicy, BrokerRequestContext, BrokerVerifier, JsonLimits, VerifierLimits,
    oauth::{NativeOAuth, OAuthLimits},
};
use graphit_core::{file_io::SnapshotContext, file_lock::Cancellation};
use graphit_http::client::{ClientPolicy, Limits as NetworkLimits};
use oidc::{AUDIENCE, PASSWORD, PEPPER, RESOURCE};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::Path, time::Duration};
use support::{deadline, n};
use zeroize::Zeroizing;
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(45))
        .build()
        .unwrap()
}
fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}
fn config(addr: SocketAddr, mfa: bool) -> Value {
    let guide = include_str!("../../../docs/rust-broker-server.md");
    let mut v: Value = serde_saphyr::from_str(http::block(guide)).unwrap();
    let sqlite_example = guide.split_once("## Select private SQLite").unwrap().1;
    let sqlite_example = sqlite_example.split_once("~~~yaml").unwrap().1;
    let sqlite: Value =
        serde_saphyr::from_str(sqlite_example.split_once("~~~").unwrap().0).unwrap();
    v["database"] = sqlite["database"].clone();
    v["server"]["address"] = json!(addr.to_string());
    v["server"]["public_url"] = json!(format!("http://{addr}"));
    v["auth"]["issuer"] = v["server"]["public_url"].clone();
    v["auth"]["audience"] = json!(AUDIENCE);
    v["auth"]["pepper"] = json!(PEPPER);
    v["auth"].as_object_mut().unwrap().remove("resource");
    let oidc: Value = serde_saphyr::from_str(http::block(include_str!(
        "../../../docs/rust-oidc-token-exchange.md"
    )))
    .unwrap();
    v["oidc"] = oidc["oidc"].clone();
    v["oidc"]["accepted_resources"] = json!([RESOURCE]);
    v["auth"]["local"] = json!({"login":{"enabled":true},"mfa":{"required":mfa,"issuer_label":"Graphit Broker","challenge_ttl":"10m"},"rate_limit":{"max_failures":20,"window":"60s","lockout":"300s","max_concurrent":2,"saturation_multiplier":4}});
    v["oidc"]["device_poll_interval"] = json!("1s");
    v["oidc"]["access_ttl"] = json!("60s");
    v["oidc"]["allowed_origins"] = json!(["https://ui.example"]);
    v
}
async fn seed(root: &Path, password_change_required: bool) -> Connection {
    let db = Connection::open(root.join("private/broker.db")).unwrap();
    db.busy_timeout(Duration::from_secs(5)).unwrap();
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
    let now = oidc::micros();
    db.execute(
        "INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at)
         VALUES('alice','alice-subject','human',?1,'Alice','alice@example.invalid','org','[\"engineering\"]',1,?2,1,?3,?3)",
        params![hash.as_str(), password_change_required, now],
    )
    .unwrap();
    db.execute(
        "INSERT INTO oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at)
         VALUES('web-client','Client','[\"https://client.example/cb\"]','[\"openid\",\"offline_access\"]','web',?1)",
        [now],
    )
    .unwrap();
    engine.close().await;
    db
}
async fn start(root: &Path, config: &Value, addr: SocketAddr) -> tokio::process::Child {
    http::start(
        &http::write(root, &serde_saphyr::to_string(config).unwrap()),
        addr,
    )
    .await
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
async fn error(r: reqwest::Response, status: u16, code: &str) {
    assert_eq!(r.status(), status);
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(r.headers()["pragma"], "no-cache");
    assert_eq!(http::value(r).await, json!({"error":code}));
}
fn privacy(r: &reqwest::Response) {
    for (k, v) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
    ] {
        assert_eq!(r.headers()[k], v);
    }
    assert!(r.headers().get("set-cookie").is_none());
    let csp = r.headers()["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("form-action 'self';") && csp.contains("frame-ancestors 'none'"));
}
fn capture(name: &str, html: &str) {
    if let Some(root) = std::env::var_os("GRAPHIT_BROKER_DEVICE_UI_DIR") {
        let root = std::path::PathBuf::from(root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(format!("{name}.html")), html).unwrap();
    }
}
async fn page(r: reqwest::Response, status: u16, name: &str) -> String {
    assert_eq!(r.status(), status, "{name}");
    privacy(&r);
    let html = r.text().await.unwrap();
    capture(name, &html);
    html
}
fn secret(html: &str, name: &str) -> String {
    regex::Regex::new(&format!(r#"name="{name}" value="([A-Za-z0-9_-]{{43}})""#))
        .unwrap()
        .captures(html)
        .unwrap()[1]
        .into()
}
async fn issue(addr: SocketAddr, interval: u64) -> Value {
    let r = post(
        addr,
        "/oauth/device/authorize",
        &[("client_id", "graphit-cli")],
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["cache-control"], "no-store");
    let v = http::value(r).await;
    assert_eq!(v.as_object().unwrap().len(), 6);
    assert!(v["device_code"].as_str().unwrap().starts_with("gb_dc_"));
    assert_eq!(v["verification_uri"], format!("http://{addr}/oauth/device"));
    let complete = url::Url::parse(v["verification_uri_complete"].as_str().unwrap()).unwrap();
    assert_eq!(
        complete.query_pairs().next().unwrap().1,
        v["user_code"].as_str().unwrap()
    );
    assert!(v["expires_in"].as_u64().unwrap() <= 600);
    assert_eq!(v["interval"], interval);
    v
}
fn browser_path(v: &Value) -> String {
    format!(
        "/oauth/device?{}",
        form(&[("user_code", v["user_code"].as_str().unwrap())])
    )
}
async fn poll(addr: SocketAddr, v: &Value) -> reqwest::Response {
    post(
        addr,
        "/oauth/token",
        &[
            ("grant_type", broker_control::DEVICE_GRANT_TYPE),
            ("client_id", "graphit-cli"),
            ("device_code", v["device_code"].as_str().unwrap()),
        ],
    )
    .await
}
async fn login(addr: SocketAddr, v: &Value, password: &str) -> String {
    page(
        post(
            addr,
            &browser_path(v),
            &[("username", "alice"), ("password", password)],
        )
        .await,
        200,
        "consent",
    )
    .await
}
async fn decide(addr: SocketAddr, v: &Value, secret: &str, allow: &str) -> reqwest::Response {
    post(
        addr,
        &browser_path(v),
        &[
            ("client_id", "graphit-cli"),
            ("consent_secret", secret),
            ("decision", allow),
        ],
    )
    .await
}
fn count(db: &Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |r| r.get(0)).unwrap()
}
#[tokio::test]
async fn broker_device_http_contract() {
    let root = tempfile::tempdir().unwrap();
    let addr = http::address();
    let signer = http::signing_key(root.path(), &format!("http://{addr}"));
    let mut config = config(addr, false);
    config["oidc"]["device_poll_interval"] = json!("30s");
    let child = start(root.path(), &config, addr).await;
    let db = seed(root.path(), false).await;
    let doc = http::value(
        client()
            .get(format!("http://{addr}/.well-known/openid-configuration"))
            .header("host", "untrusted.invalid")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        doc["device_authorization_endpoint"],
        format!("http://{addr}/oauth/device/authorize")
    );
    assert!(
        doc["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!(broker_control::DEVICE_GRANT_TYPE))
    );
    for scope in [
        "custom",
        "openid",
        "profile",
        "email",
        "offline_access",
        " ",
        "\t",
    ] {
        error(
            post(
                addr,
                "/oauth/device/authorize",
                &[("client_id", "graphit-cli"), ("scope", scope)],
            )
            .await,
            400,
            "invalid_scope",
        )
        .await;
    }
    assert_eq!(count(&db, "SELECT count(*) FROM oauth_device_codes"), 0);
    error(
        post(
            addr,
            "/oauth/device/authorize",
            &[("client_id", "web-client")],
        )
        .await,
        401,
        "invalid_client",
    )
    .await;
    for raw in [
        "client_id=a&client_id=b",
        "client_id=graphit-cli&scope=%FF",
        "client_id=graphit-cli&resource=x",
        "client_id=graphit-cli&client_secret=",
    ] {
        error(
            client()
                .post(format!("http://{addr}/oauth/device/authorize"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(raw)
                .send()
                .await
                .unwrap(),
            400,
            "invalid_request",
        )
        .await;
    }
    error(
        post(addr, "/oauth/device/authorize?client_id=graphit-cli", &[]).await,
        400,
        "invalid_request",
    )
    .await;
    error(
        client()
            .post(format!("http://{addr}/oauth/device/authorize"))
            .basic_auth("graphit-cli", Some(""))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("client_id=graphit-cli")
            .send()
            .await
            .unwrap(),
        400,
        "invalid_request",
    )
    .await;
    let entry = page(
        client()
            .get(format!("http://{addr}/oauth/device"))
            .send()
            .await
            .unwrap(),
        200,
        "entry",
    )
    .await;
    assert!(entry.contains("for=\"user-code\""));
    let d = issue(addr, 30).await;
    let path = browser_path(&d);
    error(poll(addr, &d).await, 400, "authorization_pending").await;
    error(poll(addr, &d).await, 400, "slow_down").await;
    assert_eq!(
        count(&db, "SELECT interval_seconds FROM oauth_device_codes"),
        35
    );
    let login_page = page(
        client()
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap(),
        200,
        "password",
    )
    .await;
    assert!(
        login_page.contains("name=\"password\"") && !login_page.contains("Organization sign-in")
    );
    let denied = page(
        post(
            addr,
            &path,
            &[("username", "alice"), ("password", "wrong secret")],
        )
        .await,
        401,
        "invalid-password",
    )
    .await;
    assert!(!denied.contains("wrong secret"));
    let head = client()
        .head(format!("http://{addr}{path}"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 405);
    assert_eq!(head.headers()["allow"], "GET, POST");
    for (uri, body) in [
        (format!("{path}&password=secret"), String::new()),
        (path.clone(), "user_code=ABCD2345".into()),
        (path.clone(), "username=a&username=b".into()),
        (path.clone(), "provider=x".into()),
        (path.clone(), "username=%FF".into()),
    ] {
        let r = client()
            .post(format!("http://{addr}{uri}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
    }
    let oversized = "x".repeat(16385);
    assert_eq!(
        client()
            .post(format!("http://{addr}{path}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(oversized)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let consent = login(addr, &d, PASSWORD).await;
    assert!(
        consent.contains("Review device sign-in")
            && !consent.contains(d["device_code"].as_str().unwrap())
    );
    let s = secret(&consent, "consent_secret");
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM oauth_device_codes WHERE status='pending'"
        ),
        1
    );
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM local_tokens WHERE token_kind='oidc_access'"
        ),
        0
    );
    let other = issue(addr, 30).await;
    assert_eq!(decide(addr, &other, &s, "allow").await.status(), 400);
    assert_eq!(
        decide(addr, &d, &"a".repeat(43), "allow").await.status(),
        400
    );
    page(decide(addr, &d, &s, "allow").await, 200, "allowed").await;
    assert_eq!(decide(addr, &d, &s, "allow").await.status(), 400);
    db.execute("UPDATE oauth_device_codes SET last_poll_at=NULL", [])
        .unwrap();
    let r = poll(addr, &d).await;
    assert_eq!(r.status(), 200);
    let tokens = http::value(r).await;
    assert_eq!(tokens.as_object().unwrap().len(), 4);
    assert_eq!(tokens["scope"], "");
    assert_eq!(tokens["token_type"], "Bearer");
    assert!(tokens["id_token"].is_null() && tokens["refresh_token"].is_null());
    assert!(tokens["expires_in"].as_u64().unwrap() <= 60);
    let claims = http::claims(
        &signer,
        &format!("http://{addr}"),
        tokens["access_token"].as_str().unwrap(),
    );
    assert_eq!(claims["client_id"], "graphit-cli");
    assert_eq!(claims["scope"], "");
    assert_eq!(claims["token_use"], "access");
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        60
    );
    let api = client()
        .post(format!("http://{addr}/v1/s3/credentials"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .header("content-type", "application/json")
        .body(r#"{"scope":"project","project_id":"01KSH1CRFFG8Z74B5ZS78WW808","module":"hub"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(api.status(), 403);
    error(poll(addr, &d).await, 400, "invalid_grant").await;
    let d = issue(addr, 30).await;
    let c = login(addr, &d, PASSWORD).await;
    page(
        decide(addr, &d, &secret(&c, "consent_secret"), "deny").await,
        200,
        "denied",
    )
    .await;
    error(poll(addr, &d).await, 400, "access_denied").await;
    let expired = issue(addr, 30).await;
    db.execute("UPDATE oauth_device_codes SET created_at=created_at-700000000,expires_at=expires_at-700000000", []).unwrap();
    error(poll(addr, &expired).await, 400, "expired_token").await;
    for (k, v) in [
        ("resource", "https://x"),
        ("scope", "openid"),
        ("code", "literal"),
        ("refresh_token", "literal"),
    ] {
        let mut pairs = vec![
            ("grant_type", broker_control::DEVICE_GRANT_TYPE),
            ("client_id", "graphit-cli"),
            ("device_code", "gb_dc_invalid"),
        ];
        pairs.push((k, v));
        error(
            post(addr, "/oauth/token", &pairs).await,
            400,
            if k == "scope" {
                "invalid_scope"
            } else {
                "invalid_request"
            },
        )
        .await;
    }
    error(
        post(
            addr,
            "/oauth/token",
            &[("grant_type", "authorization_code"), ("device_code", "x")],
        )
        .await,
        400,
        "invalid_request",
    )
    .await;
    let cors = client()
        .post(format!("http://{addr}/oauth/device/authorize"))
        .header("origin", "https://ui.example")
        .header("content-type", "application/x-www-form-urlencoded")
        .body("client_id=graphit-cli&scope=&extension=a&extension=b")
        .send()
        .await
        .unwrap();
    assert_eq!(cors.status(), 200);
    assert_eq!(
        cors.headers()["access-control-allow-origin"],
        "https://ui.example"
    );
    http::stop(child).await;
}
#[tokio::test]
async fn broker_device_mfa_http_contract() {
    let root = tempfile::tempdir().unwrap();
    let addr = http::address();
    http::signing_key(root.path(), &format!("http://{addr}"));
    let mut config = config(addr, true);
    // Password change verifies and hashes with production Argon2 in the unoptimized test build.
    config["database"]["operation_timeout"] = json!("30s");
    config["oidc"]["request_timeout"] = json!("30s");
    let child = start(root.path(), &config, addr).await;
    let db = seed(root.path(), true).await;
    let d = issue(addr, 1).await;
    let path = browser_path(&d);
    let html = page(
        post(
            addr,
            &path,
            &[("username", "alice"), ("password", PASSWORD)],
        )
        .await,
        200,
        "password-change",
    )
    .await;
    assert!(html.contains("Choose a new password"));
    let challenge = secret(&html, "challenge_token");
    let next = "native Device changed password";
    let html = page(
        post(
            addr,
            &path,
            &[
                ("challenge_token", &challenge),
                ("new_password", next),
                ("confirm_password", "different"),
            ],
        )
        .await,
        400,
        "password-change-error",
    )
    .await;
    assert!(html.contains(&challenge) && !html.contains(next));
    let html = page(
        post(
            addr,
            &path,
            &[
                ("challenge_token", &challenge),
                ("new_password", next),
                ("confirm_password", next),
            ],
        )
        .await,
        200,
        "enrollment",
    )
    .await;
    assert!(html.contains("Set up two-step verification"));
    let challenge = secret(&html, "challenge_token");
    let base32 = regex::Regex::new(r"Setup key: <code>([A-Z2-7]+)</code>")
        .unwrap()
        .captures(&html)
        .unwrap()[1]
        .to_owned();
    let sdk=totp_rs::Totp::from_url(format!("otpauth://totp/Graphit%20Broker:alice?secret={base32}&issuer=Graphit%20Broker&algorithm=SHA1&digits=6&period=30")).unwrap();
    let other = issue(addr, 1).await;
    assert!(
        !post(
            addr,
            &browser_path(&other),
            &[("challenge_token", &challenge), ("code", "123456")]
        )
        .await
        .status()
        .is_success()
    );
    let html = page(
        post(
            addr,
            &path,
            &[("challenge_token", &challenge), ("code", "invalid")],
        )
        .await,
        401,
        "mfa-error",
    )
    .await;
    assert!(html.contains(&challenge));
    let otp = sdk
        .generate((oidc::micros() as u64) / 1_000_000)
        .to_string();
    let html = page(
        post(
            addr,
            &path,
            &[("challenge_token", &challenge), ("code", &otp)],
        )
        .await,
        200,
        "recovery-consent",
    )
    .await;
    assert!(html.find("Recovery codes").unwrap() < html.find("name=\"decision\"").unwrap());
    let recovery: Vec<String> = regex::Regex::new(r"<li><code>([^<]+)</code></li>")
        .unwrap()
        .captures_iter(&html)
        .map(|c| c[1].to_owned())
        .collect();
    assert_eq!(recovery.len(), 10);
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM oauth_device_codes WHERE status='approved'"
        ),
        0
    );
    error(poll(addr, &d).await, 400, "authorization_pending").await;
    let s = secret(&html, "consent_secret");
    page(decide(addr, &d, &s, "allow").await, 200, "mfa-allowed").await;
    db.execute("UPDATE oauth_device_codes SET last_poll_at=NULL", [])
        .unwrap();
    assert_eq!(poll(addr, &d).await.status(), 200);
    let oauth_query = form(&[
        ("client_id", "graphit-cli"),
        ("redirect_uri", "http://localhost:49152/oauth/callback"),
        ("response_type", "code"),
        ("scope", "openid"),
        ("state", "native-device-cross-purpose"),
        ("nonce", "native-device-cross-purpose-nonce"),
        (
            "code_challenge",
            "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
        ),
        ("code_challenge_method", "S256"),
    ]);
    let response = client()
        .get(format!("http://{addr}/oauth/authorize?{oauth_query}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    let oauth_path = response.headers()["location"].to_str().unwrap().to_owned();
    assert!(
        oauth_path.starts_with("/oauth/login?id="),
        "genuine Code admission: {oauth_path}"
    );
    let oauth_response = post(
        addr,
        &oauth_path,
        &[("username", "alice"), ("password", next)],
    )
    .await;
    assert_eq!(oauth_response.status(), 200);
    assert!(oauth_response.headers().get("set-cookie").is_none());
    assert!(
        oauth_response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    let oauth_html = oauth_response.text().await.unwrap();
    let foreign = secret(&oauth_html, "challenge_token");
    let d = issue(addr, 1).await;
    assert_eq!(
        post(
            addr,
            &browser_path(&d),
            &[("challenge_token", &foreign), ("code", &recovery[0])]
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        count(&db, "SELECT count(*) FROM local_mfa_recovery_codes"),
        10
    );
    let html = page(
        post(
            addr,
            &browser_path(&d),
            &[("username", "alice"), ("password", next)],
        )
        .await,
        200,
        "mfa",
    )
    .await;
    let challenge = secret(&html, "challenge_token");
    let html = page(
        post(
            addr,
            &browser_path(&d),
            &[("challenge_token", &challenge), ("code", &recovery[0])],
        )
        .await,
        200,
        "recovery-login-consent",
    )
    .await;
    assert!(!html.contains("Recovery codes"));
    let s = secret(&html, "consent_secret");
    assert_eq!(
        count(&db, "SELECT count(*) FROM local_mfa_recovery_codes"),
        9
    );
    db.execute("UPDATE local_users SET revision=revision+1,enabled=0", [])
        .unwrap();
    assert!(!decide(addr, &d, &s, "allow").await.status().is_success());
    http::stop(child).await;
}
#[tokio::test]
async fn broker_device_configuration_contract() {
    let root = tempfile::tempdir().unwrap();
    let addr = http::address();
    http::signing_key(root.path(), &format!("http://{addr}"));
    let original = config(addr, false);
    for (key, values) in [
        ("device_code_ttl", vec!["299s", "1801s", "300.5s"]),
        ("device_poll_interval", vec!["0s", "31s", "1.5s"]),
    ] {
        for value in values {
            let mut config = original.clone();
            config["oidc"][key] = json!(value);
            let path = http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
            let output = http::command()
                .args(["--config", path.to_str().unwrap(), "--check-config"])
                .output()
                .await
                .unwrap();
            assert!(!output.status.success());
            assert!(!String::from_utf8_lossy(&output.stderr).contains(PEPPER));
        }
    }
    for (ttl, poll) in [("5m", "1s"), ("30m", "30s")] {
        let mut v = original.clone();
        v["oidc"]["device_code_ttl"] = json!(ttl);
        v["oidc"]["device_poll_interval"] = json!(poll);
        let path = http::write(root.path(), &serde_saphyr::to_string(&v).unwrap());
        assert!(
            http::command()
                .args(["--config", path.to_str().unwrap(), "--check-config"])
                .status()
                .await
                .unwrap()
                .success()
        );
    }
    let mut config = original.clone();
    config["oidc"]
        .as_object_mut()
        .unwrap()
        .remove("device_code_ttl");
    config["oidc"]
        .as_object_mut()
        .unwrap()
        .remove("device_poll_interval");
    let child = start(root.path(), &config, addr).await;
    let r = post(
        addr,
        "/oauth/device/authorize",
        &[("client_id", "graphit-cli")],
    )
    .await;
    assert_eq!(r.status(), 200);
    let v = http::value(r).await;
    assert_eq!(v["interval"], 5);
    assert!((1..=600).contains(&v["expires_in"].as_u64().unwrap()));
    let db = Connection::open(root.path().join("private/broker.db")).unwrap();
    assert_eq!(
        count(
            &db,
            "SELECT expires_at - created_at FROM oauth_device_codes"
        ),
        600_000_000
    );
    drop(db);
    http::stop(child).await;
    let mut literal = config.clone();
    literal["server"]["public_url"] = json!("https://Broker.Example:443/");
    literal["auth"]["issuer"] = json!("https://Broker.Example:443/");
    let child = start(root.path(), &literal, addr).await;
    let discovery = http::value(
        client()
            .get(format!("http://{addr}/.well-known/openid-configuration"))
            .header("host", "attacker.invalid")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        discovery["device_authorization_endpoint"],
        "https://Broker.Example:443/oauth/device/authorize"
    );
    let issued = http::value(
        post(
            addr,
            "/oauth/device/authorize",
            &[("client_id", "graphit-cli")],
        )
        .await,
    )
    .await;
    assert_eq!(
        issued["verification_uri"],
        "https://Broker.Example:443/oauth/device"
    );
    http::stop(child).await;
    let mut captcha = config.clone();
    captcha["auth"]["local"]["captcha"] = json!({"enabled":true,"provider":"turnstile","site_key":"native-device-site","secret_key":"native-device-test-secret","trigger_multiplier":0.0,"verification_timeout":"1s"});
    let child = start(root.path(), &captcha, addr).await;
    let r = client()
        .get(format!("http://{addr}/oauth/device?user_code=ABCD2345"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let csp = r.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    let h = r.text().await.unwrap();
    capture("captcha", &h);
    assert!(
        h.contains("data-action=\"device-login\"")
            && h.contains("native-device-site")
            && csp.contains("https://challenges.cloudflare.com")
    );
    let h = page(
        post(
            addr,
            "/oauth/device?user_code=ABCD2345",
            &[("username", "alice"), ("password", PASSWORD)],
        )
        .await,
        403,
        "captcha-required",
    )
    .await;
    assert!(h.contains("verification") && !h.contains(PASSWORD));
    assert_eq!(
        post(
            addr,
            "/oauth/device?user_code=ABCD2345",
            &[
                ("username", "alice"),
                ("password", PASSWORD),
                ("g-recaptcha-response", "wrong-provider")
            ]
        )
        .await
        .status(),
        400
    );
    http::stop(child).await;
    config["auth"]["local"]["login"]["enabled"] = json!(false);
    let child = start(root.path(), &config, addr).await;
    let doc = http::value(
        client()
            .get(format!("http://{addr}/.well-known/openid-configuration"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert!(doc["device_authorization_endpoint"].is_null());
    assert!(
        !doc["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!(broker_control::DEVICE_GRANT_TYPE))
    );
    error(
        post(
            addr,
            "/oauth/device/authorize",
            &[("client_id", "graphit-cli")],
        )
        .await,
        503,
        "temporarily_unavailable",
    )
    .await;
    error(poll(addr, &v).await, 503, "temporarily_unavailable").await;
    page(
        client()
            .get(format!("http://{addr}/oauth/device"))
            .send()
            .await
            .unwrap(),
        503,
        "unavailable",
    )
    .await;
    http::stop(child).await;
    config["oidc"]["enabled"] = json!(false);
    let child = start(root.path(), &config, addr).await;
    for path in [
        "/oauth/device",
        "/oauth/device/authorize",
        "/.well-known/openid-configuration",
    ] {
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
}

#[tokio::test]
async fn broker_device_native_auth_login_contract() {
    let root = tempfile::tempdir().unwrap();
    let addr = http::address();
    let issuer = format!("http://{addr}");
    let signer = http::signing_key(root.path(), &issuer);
    let broker = start(root.path(), &config(addr, false), addr).await;
    let db = seed(root.path(), false).await;
    let original = SnapshotContext::new(deadline(), Cancellation::default());
    let context = BrokerRequestContext::new(&original);
    let verifier = BrokerVerifier::new(
        BrokerPolicy {
            endpoint: &issuer,
            mcp_resource: None,
            provider_revision: 1,
            network: ClientPolicy {
                origin: &issuer,
                allow_loopback_http: true,
                proxy: None,
                additional_roots: &[],
            },
        },
        NetworkLimits {
            request_body_bytes: 8192,
            response_body_bytes: 8192,
            url_bytes: 4096,
            header_bytes: 16384,
            header_count: 32,
            max_in_flight: 2,
            max_idle_per_host: 2,
            idle_timeout: Duration::from_secs(30),
            max_certificates: 2,
            max_certificate_bytes: 8192,
        },
        VerifierLimits {
            token_bytes: 8192,
            json: JsonLimits {
                bytes: 8192,
                nodes: 512,
                depth: 16,
                scalar_bytes: 2048,
                collection_entries: 64,
            },
            max_keys: 8,
            metadata_ttl: Duration::from_secs(300),
            key_ttl: Duration::from_secs(300),
            unknown_key_cooldown: Duration::from_millis(100),
        },
    )
    .unwrap();
    let oauth = NativeOAuth::new(
        &verifier,
        OAuthLimits {
            authorization_url_bytes: 4096,
            callback_bytes: 4096,
            callback_query_entries: 16,
            form_body_bytes: 8192,
            token_bytes: 8192,
            response_nodes: 512,
            response_scalar_bytes: 2048,
        },
    )
    .unwrap();
    let pending = oauth.begin_device(context).await.unwrap();
    let instructions = pending.instructions(context).unwrap();
    assert_eq!(
        instructions.verification_uri(),
        format!("{issuer}/oauth/device")
    );
    assert!(
        regex::Regex::new(r"^[A-Z2-9]{4}-[A-Z2-9]{4}$")
            .unwrap()
            .is_match(instructions.user_code())
    );
    // The browser receives only public instructions; the Auth consumer owns the private grant.
    let prompt = json!({"user_code": instructions.user_code()});
    let browser_url = format!("{issuer}{}", browser_path(&prompt));
    assert_eq!(
        instructions.verification_uri_complete(),
        Some(browser_url.as_str())
    );
    let entry = client().get(&browser_url).send().await.unwrap();
    privacy(&entry);
    assert_eq!(entry.status(), 200);
    assert!(entry.text().await.unwrap().contains("name=\"password\""));
    let consent = login(addr, &prompt, PASSWORD).await;
    assert!(consent.contains("Review device sign-in"));
    assert!(consent.contains("name=\"client_id\" value=\"graphit-cli\""));
    let decision = decide(addr, &prompt, &secret(&consent, "consent_secret"), "allow").await;
    privacy(&decision);
    assert_eq!(decision.status(), 200);

    // Neither the grant decision nor the polling schedule is injected through SQL.
    let tokens = oauth.receive_device(pending, context).await.unwrap();
    let access = tokens.access_token(context).unwrap();
    let claims = http::claims(&signer, &issuer, access);
    let identity = tokens.identity(context).unwrap();
    assert_eq!(identity.issuer(), issuer);
    assert_eq!(identity.subject(), claims["sub"].as_str().unwrap());
    assert!(!identity.subject().is_empty());
    assert_eq!(claims["client_id"], "graphit-cli");
    assert_eq!(claims["token_use"], "access");
    assert_eq!(claims["scope"], "");
    assert!(tokens.expires_at(context).unwrap() <= claims["exp"].as_i64().unwrap());
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM local_tokens WHERE token_kind='oidc_access'"
        ),
        1
    );
    http::stop(broker).await;
}
