//! Genuine shared LOCAL owner, native configuration and OAuth token consumers.
#[path = "../../broker-control/tests/support/admin_cookie.rs"]
#[allow(
    dead_code,
    reason = "shared genuine LOCAL fixture serves other contracts"
)]
mod cookie;
#[path = "support/oidc_http.rs"]
#[allow(
    dead_code,
    reason = "shared native process fixture serves other contracts"
)]
mod http;
#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
#[allow(
    dead_code,
    reason = "shared OIDC protocol fixtures supply native constants"
)]
mod oidc;
#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "shared TLS PostgreSQL fixture serves other contracts"
)]
mod support;
use broker_control::{
    ControlError, LocalAuthPolicy, LocalAuthStep, LocalCaptcha, LocalCaptchaConfiguration,
    LocalMfaAttemptLimiter, LocalMfaAttemptPolicy, LocalPasswordAdmission,
    LocalPasswordAdmissionError, LocalPasswordAdmissionPolicy, OidcAuthorizationInput,
    PreparedAdminLogin, PreparedOidcLogin,
};
use broker_presence::LocalLoginRuntime;
use broker_security::{LocalAuthBinding, LocalAuthPurpose, LocalMfaProtector};
use serde_json::{Value, json};
use std::{net::SocketAddr, num::NonZeroU32, path::Path, sync::Arc, time::Duration};
use support::{deadline, n};
use zeroize::Zeroizing;

fn configuration(address: SocketAddr, pg: u16) -> Value {
    let yaml = http::yaml(address, pg)
        .replace(
            "  username: exchange_owner",
            "  username: admin_cookie_owner",
        )
        .replace(oidc::PEPPER, cookie::PEPPER);
    let mut value: Value = serde_saphyr::from_str(&yaml).unwrap();
    let local: Value = serde_saphyr::from_str(http::block(include_str!(
        "../../../docs/rust-admin-local-login.md"
    )))
    .unwrap();
    value["auth"]["local"] = local["auth"]["local"].clone();
    value["auth"]["local"]["mfa"]["required"] = json!(false);
    value
}
fn administration(enabled: bool, cookie_enabled: bool) -> Value {
    let mut value: Value = serde_saphyr::from_str(http::block(include_str!(
        "../../../docs/rust-admin-cookie-session.md"
    )))
    .unwrap();
    value["administration"]["enabled"] = json!(enabled);
    value["administration"]["cookie"]["enabled"] = json!(cookie_enabled);
    value["administration"]["cookie_secure"] = json!(false);
    value["administration"].clone()
}
fn runtime(f: &cookie::CookieFixture) -> LocalLoginRuntime {
    let policy = LocalPasswordAdmissionPolicy {
        max_failures: n(2),
        window: Duration::from_secs(60),
        lockout: Duration::from_secs(300),
        workers: n(1),
        saturation_multiplier: n(2),
        max_tracked: n(4096),
    };
    let captcha = LocalCaptcha::new(LocalCaptchaConfiguration::Disabled, n(1), n(2)).unwrap();
    let admission = Arc::new(LocalPasswordAdmission::new(policy, &f.engine, captcha).unwrap());
    LocalLoginRuntime::new(
        f.engine.clone(),
        admission,
        cookie::digester(),
        LocalMfaProtector::new(Zeroizing::new(
            cookie::PEPPER.as_bytes().to_vec().into_boxed_slice(),
        ))
        .unwrap(),
        LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(600)).unwrap(),
        LocalMfaAttemptLimiter::new(
            LocalMfaAttemptPolicy::new(
                NonZeroU32::new(5).unwrap(),
                Duration::from_secs(60),
                Duration::from_secs(300),
                n(4096),
            )
            .unwrap(),
        ),
    )
}
async fn check(root: &Path, value: &Value, expected: bool, name: &str) {
    let path = http::write(root, &serde_saphyr::to_string(value).unwrap());
    let output = http::command()
        .args(["--config", path.to_str().unwrap(), "--check-config"])
        .output()
        .await
        .unwrap();
    assert_eq!(
        output.status.success(),
        expected,
        "configuration case {name}"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(cookie::PEPPER));
}
#[tokio::test]
#[ignore = "actual native check-config matrix with zero SQL/listener effects"]
async fn broker_local_login_runtime_configuration_contract() {
    let root = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = params.self_signed(&key).unwrap();
    let sql = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _signer = http::files(
        root.path(),
        ca.pem().as_bytes(),
        &format!("http://{}", listener.local_addr().unwrap()),
    );
    let base = configuration(
        listener.local_addr().unwrap(),
        sql.local_addr().unwrap().port(),
    );
    for local in [false, true] {
        for oidc in [false, true] {
            for admin in [
                None,
                Some((false, false)),
                Some((true, false)),
                Some((true, true)),
            ] {
                let mut value = base.clone();
                value["auth"]["local"]["login"]["enabled"] = json!(local);
                value["oidc"]["enabled"] = json!(oidc);
                if let Some((enabled, cookie_enabled)) = admin {
                    value["administration"] = administration(enabled, cookie_enabled);
                }
                let expected = !local || oidc || admin == Some((true, true));
                check(
                    root.path(),
                    &value,
                    expected,
                    &format!("local={local}/oidc={oidc}/admin={admin:?}"),
                )
                .await;
            }
        }
    }
    for (field, bound, expected) in [
        ("token_bytes", 42, false),
        ("token_bytes", 43, true),
        ("binding_bytes", 42, false),
        ("binding_bytes", 43, true),
    ] {
        let mut value = base.clone();
        value["auth"]["digest"][field] = json!(bound);
        check(root.path(), &value, expected, &format!("{field}={bound}")).await;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), sql.accept())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}
async fn login(
    runtime: &LocalLoginRuntime,
    f: &cookie::CookieFixture,
    purpose: LocalAuthPurpose,
    binding: LocalAuthBinding<'_>,
) -> broker_control::CompletedLocalLogin {
    let original = deadline();
    let proof = runtime
        .passwords(&f.store, purpose)
        .unwrap()
        .authenticate("alice", cookie::PASSWORD, None, original)
        .await
        .unwrap();
    match runtime
        .authentication(&f.store)
        .begin(proof, binding, original)
        .await
        .unwrap()
    {
        LocalAuthStep::Complete(login) => login,
        _ => panic!("genuine password-only fixture must complete LOCAL"),
    }
}
async fn register(address: SocketAddr) -> String {
    let response = reqwest::Client::new().post(format!("http://{address}/oauth/register"))
        .header("content-type","application/json")
        .body(serde_json::to_vec(&json!({"redirect_uris":["https://client.example/cb"],"scope":"openid profile email offline_access","token_endpoint_auth_method":"none"})).unwrap()).send().await.unwrap();
    assert_eq!(response.status(), 201);
    http::value(response).await["client_id"]
        .as_str()
        .unwrap()
        .to_owned()
}
async fn exchange(
    address: SocketAddr,
    code: &str,
    client: &str,
    signer: &broker_control::BrokerAccessIssuer,
) {
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("client_id", client),
            ("code", code),
            ("redirect_uri", "https://client.example/cb"),
            ("code_verifier", oidc::VERIFIER),
            ("resource", oidc::RESOURCE),
        ])
        .finish();
    let response = http::post(address, form, None).await;
    assert_eq!(response.status(), 200);
    let tokens = http::value(response).await;
    let access = http::claims(
        signer,
        &format!("http://{address}"),
        tokens["access_token"].as_str().unwrap(),
    );
    let id = http::claims(
        signer,
        &format!("http://{address}"),
        tokens["id_token"].as_str().unwrap(),
    );
    assert_eq!(access["client_id"], client);
    assert_eq!(id["nonce"], "runtime nonce");
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "refresh_token"),
            ("client_id", client),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("resource", oidc::RESOURCE),
        ])
        .finish();
    let rotated = http::post(address, form, None).await;
    assert_eq!(rotated.status(), 200);
    let rotated = http::value(rotated).await;
    let _ = http::claims(
        signer,
        &format!("http://{address}"),
        rotated["access_token"].as_str().unwrap(),
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "genuine common LOCAL runtime with TLS PostgreSQL, Admin cookie and native OAuth token/refresh consumers"]
async fn broker_local_login_runtime_consumers_contract() {
    let mut f = cookie::CookieFixture::new().await;
    let runtime = runtime(&f);
    let root = tempfile::tempdir().unwrap();
    assert!(runtime.challenge(LocalAuthPurpose::AdminLogin).is_none());
    assert!(
        runtime
            .next_password_challenge(LocalAuthPurpose::OauthAuthorize)
            .unwrap()
            .is_none()
    );
    let completed = login(
        &runtime,
        &f,
        LocalAuthPurpose::AdminLogin,
        LocalAuthBinding::AdminLogin,
    )
    .await;
    let cookie = f
        .store
        .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
        .unwrap()
        .issue_local(
            PreparedAdminLogin::try_from(completed).unwrap(),
            runtime.policy(),
            deadline(),
        )
        .await
        .unwrap();
    cookie.check().unwrap();
    assert_eq!(cookie.secret().len(), 43);
    assert_eq!(f.count().await, 1);
    for admin in [None, Some(false), Some(true)] {
        let address = http::address();
        let signer = http::files(root.path(), &f.fixture.ca, &format!("http://{address}"));
        let mut value = configuration(address, f.fixture.port);
        if let Some(enabled) = admin {
            value["administration"] = administration(enabled, false);
        }
        let path = http::write(root.path(), &serde_saphyr::to_string(&value).unwrap());
        let child = http::start(&path, address).await;
        let options = reqwest::get(format!("http://{address}/admin/api/v1/login-options"))
            .await
            .unwrap();
        let post = reqwest::Client::new()
            .post(format!("http://{address}/admin/auth/local"))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap();
        if admin == Some(true) {
            assert_eq!(options.status(), 200);
            assert_eq!(http::value(options).await["local"], false);
            assert_eq!(post.status(), 503);
        } else {
            assert_eq!(options.status(), 404);
            assert_eq!(post.status(), 404);
        }
        let client = register(address).await;
        let policy = oidc::policy();
        let authorization = f.store.browser_oidc_authorizations(&policy);
        let pending = authorization
            .create(
                OidcAuthorizationInput {
                    client_id: &client,
                    redirect_uri: "https://client.example/cb",
                    response_type: "code",
                    scope: "openid profile email offline_access",
                    state: "literal runtime state café +%",
                    nonce: "runtime nonce",
                    code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
                    code_challenge_method: "S256",
                    response_mode: Some("query"),
                    resources: &[oidc::RESOURCE],
                    prompts: &[],
                },
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(pending.request().len(), 43);
        assert_eq!(pending.info().state(), "literal runtime state café +%");
        let wrong = broker_security::new_local_auth_challenge().unwrap();
        let completed = login(
            &runtime,
            &f,
            LocalAuthPurpose::OauthAuthorize,
            LocalAuthBinding::OauthAuthorize(wrong.as_bytes()),
        )
        .await;
        assert!(
            authorization
                .complete(
                    pending.request(),
                    PreparedOidcLogin::try_from(completed).unwrap(),
                    deadline()
                )
                .await
                .is_err()
        );
        let completed = login(
            &runtime,
            &f,
            LocalAuthPurpose::OauthAuthorize,
            LocalAuthBinding::OauthAuthorize(pending.request().as_bytes()),
        )
        .await;
        let authorized = authorization
            .complete(
                pending.request(),
                PreparedOidcLogin::try_from(completed).unwrap(),
                deadline(),
            )
            .await
            .unwrap();
        exchange(address, authorized.code(), &client, &signer).await;
        http::stop(child).await;
    }
    let admin = runtime
        .passwords(&f.store, LocalAuthPurpose::AdminLogin)
        .unwrap();
    let oauth = runtime
        .passwords(&f.store, LocalAuthPurpose::OauthAuthorize)
        .unwrap();
    let one = runtime.admit_password_change(deadline()).unwrap();
    let two = runtime.admit_password_change(deadline()).unwrap();
    for view in [&admin, &oauth] {
        assert!(matches!(
            view.authenticate("alice", cookie::PASSWORD, None, deadline())
                .await,
            Err(LocalPasswordAdmissionError::RateLimited(_))
        ));
    }
    drop((one, two));
    for _ in 0..2 {
        assert!(matches!(
            admin
                .authenticate("alice", "wrong genuine password", None, deadline())
                .await,
            Err(LocalPasswordAdmissionError::Unauthenticated)
        ));
    }
    assert!(matches!(
        oauth
            .authenticate("alice", cookie::PASSWORD, None, deadline())
            .await,
        Err(LocalPasswordAdmissionError::RateLimited(_))
    ));
    runtime.stop_admission();
    for view in [&admin, &oauth] {
        assert!(matches!(
            view.authenticate("alice", cookie::PASSWORD, None, deadline())
                .await,
            Err(LocalPasswordAdmissionError::Control(ControlError::Closed))
        ));
    }
    assert!(
        runtime
            .next_password_challenge(LocalAuthPurpose::AdminLogin)
            .is_err()
    );
    runtime.close().await;
    f.close().await;
}
