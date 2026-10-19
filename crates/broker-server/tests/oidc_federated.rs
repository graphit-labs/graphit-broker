#[allow(
    dead_code,
    reason = "shared real HTTPS issuer supports other protocol contracts"
)]
#[path = "../../broker-control/tests/support/browser_upstream.rs"]
mod browser;
#[allow(
    dead_code,
    reason = "shared H1 helper also registers clients through Control; HTTP uses the real endpoint"
)]
#[path = "../../broker-control/tests/support/oidc_federated.rs"]
mod federated;
#[path = "support/oidc_http.rs"]
mod http;
#[allow(
    dead_code,
    reason = "shared real LOCAL and PostgreSQL fixture supports other contracts"
)]
#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared real PostgreSQL fixture supports multiple suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use broker_control::BrokerAccessVerifier;
use browser::{BrowserIssuer, Fault};
use federated as fed;
use oidc::{AUDIENCE, OidcFixture, RESOURCE, VERIFIER};
use serde_json::{Value, json};
use support::{deadline, n};

fn body(code: &str, client: &str) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "authorization_code")
        .append_pair("client_id", client)
        .append_pair("code", code)
        .append_pair("redirect_uri", fed::REDIRECT)
        .append_pair("code_verifier", VERIFIER)
        .append_pair("resource", RESOURCE);
    form.finish()
}
fn refresh(raw: &str, client: &str) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "refresh_token")
        .append_pair("client_id", client)
        .append_pair("refresh_token", raw)
        .append_pair("resource", RESOURCE);
    form.finish()
}
fn provider(issuer: &BrowserIssuer, id: &str) -> Value {
    let recipe: Value = serde_saphyr::from_str(http::block(include_str!(
        "../../../docs/rust-admin-upstream-login.md"
    )))
    .unwrap();
    let mut p = recipe["auth"]["oidc"][0].clone();
    p["id"] = json!(id);
    p["issuer"] = json!(issuer.issuer);
    p["ca_file"] = json!(format!("{id}-ca.pem"));
    p["claims"]["subject"] = json!("mapped_subject");
    p["claims"]["roles"] = json!("roles");
    p["required_scopes"] = json!([]);
    p["browser_clients"] = json!([{"display_name":"W3 upstream","client_id":"public","redirect_url":fed::client("public").redirect_url,"scopes":["profile","email"],"require_nonce":true,"claims_source":"id_token","id_token_additional_audiences":[]}]);
    p
}
#[tokio::test]
#[ignore = "native executable, real PostgreSQL TLS and real HTTPS H1 issuer; Admin disabled"]
async fn broker_oidc_federated_http_contract() {
    let f = OidcFixture::new().await;
    let mut first = BrowserIssuer::new().await;
    let mut second = BrowserIssuer::new().await;
    for issuer in [&first, &second] {
        fed::register(issuer, "public");
        issuer.fault(Fault {
            id_overrides: [
                ("mapped_subject".into(), json!("alice-subject")),
                ("roles".into(), json!(["admin"])),
            ]
            .into(),
            ..Fault::default()
        });
    }
    let v1 = fed::verifier(&first, vec![fed::client("public")], Some("roles"));
    let v2 = fed::verifier(&second, vec![fed::client("public")], Some("roles"));
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let signer = http::files(root.path(), &f.fixture.ca, &format!("http://{address}"));
    std::fs::write(root.path().join("first-ca.pem"), &first.ca).unwrap();
    std::fs::write(root.path().join("second-ca.pem"), &second.ca).unwrap();
    let mut config: Value = serde_saphyr::from_str(&http::yaml(address, f.fixture.port)).unwrap();
    assert!(config.get("administration").is_none());
    config["auth"]["oidc"] = json!([provider(&first, "first"), provider(&second, "second")]);
    let path = http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    assert!(
        http::command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap()
            .status
            .success(),
        "OAuth upstream configuration works without an Admin cookie owner"
    );
    let mut disabled = config.clone();
    disabled["oidc"]["enabled"] = json!(false);
    http::write(root.path(), &serde_saphyr::to_string(&disabled).unwrap());
    assert!(
        !http::command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap()
            .status
            .success(),
        "browser channels still require either OAuth or Admin runtime"
    );
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    assert_eq!(
        reqwest::get(format!("http://{address}/admin"))
            .await
            .unwrap()
            .status(),
        404
    );
    let registration = reqwest::Client::new()
        .post(format!("http://{address}/oauth/register"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(
                &json!({"redirect_uris":[fed::REDIRECT],"token_endpoint_auth_method":"none"}),
            )
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(registration.status(), 201);
    let client = http::value(registration).await["client_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let local = f.code(false, false).await;
    let mut localform = url::form_urlencoded::Serializer::new(String::new());
    localform
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", "graphit-cli")
        .append_pair("code", local.code())
        .append_pair("redirect_uri", "http://localhost:49152/oauth/callback")
        .append_pair("code_verifier", VERIFIER);
    let localresponse = http::post(address, localform.finish(), None).await;
    assert_eq!(localresponse.status(), 200);
    let local = http::value(localresponse).await;
    let localclaims = http::claims(
        &signer,
        &format!("http://{address}"),
        local["access_token"].as_str().unwrap(),
    );
    let code = fed::code(&f, &first, &v1, &client).await;
    let good = body(code.code(), &client);
    for bad in [
        good.replace(&client, "graphit-cli"),
        good.replace("client.example%2Fcb", "client.example%2Fother"),
        good.replace(VERIFIER, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"),
        good.replace("broker.example%2Fv1", "other.example%2Fv1"),
    ] {
        let response = http::post(address, bad, None).await;
        assert_eq!(response.status(), 400);
        assert!(http::value(response).await["error"].is_string());
    }
    let response = http::post(address, good, None).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let issued = http::value(response).await;
    let access = http::claims(
        &signer,
        &format!("http://{address}"),
        issued["access_token"].as_str().unwrap(),
    );
    let id = http::claims(
        &signer,
        &format!("http://{address}"),
        issued["id_token"].as_str().unwrap(),
    );
    let expected = oidc::digester()
        .oidc_subject(first.issuer.as_bytes(), b"alice-subject")
        .unwrap();
    assert_eq!(access["iss"], format!("http://{address}"));
    assert_eq!(access["sub"], expected.as_str());
    assert_ne!(access["sub"], localclaims["sub"]);
    assert_eq!(id["amr"], json!(["federated"]));
    assert_eq!(id["client_id"], client);
    let keys = reqwest::get(format!("http://{address}/v1/oidc/keys"))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let keys: jsonwebtoken::jwk::JwkSet = serde_json::from_slice(&keys).unwrap();
    let verify = BrokerAccessVerifier::new(
        &format!("http://{address}"),
        AUDIENCE,
        Some(RESOURCE),
        &keys,
        n(16384),
    )
    .unwrap();
    assert!(
        verify
            .verify(issued["access_token"].as_str().unwrap(), &[], deadline())
            .is_ok()
    );
    let response = http::post(
        address,
        refresh(issued["refresh_token"].as_str().unwrap(), &client),
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    let rotated = http::value(response).await;
    let rid = http::claims(
        &signer,
        &format!("http://{address}"),
        rotated["id_token"].as_str().unwrap(),
    );
    assert_eq!(rid["amr"], json!(["oidc"]));
    assert_eq!(rid["auth_time"], id["auth_time"]);
    assert_eq!(rid["sub"], access["sub"]);
    let code2 = fed::code(&f, &second, &v2, &client).await;
    let response = http::post(address, body(code2.code(), &client), None).await;
    assert_eq!(response.status(), 200);
    let issued2 = http::value(response).await;
    let secondclaims = http::claims(
        &signer,
        &format!("http://{address}"),
        issued2["access_token"].as_str().unwrap(),
    );
    assert_ne!(secondclaims["sub"], access["sub"]);
    assert_ne!(secondclaims["sub"], localclaims["sub"]);
    let raw = "  usuário|联合  ";
    let username = "  Usuário 联合  ";
    first.fault(Fault {
        id_overrides: [
            ("mapped_subject".into(), json!(raw)),
            ("preferred_username".into(), json!(username)),
            ("roles".into(), json!(["admin"])),
        ]
        .into(),
        ..Fault::default()
    });
    let literal = fed::code(&f, &first, &v1, &client).await;
    let response = http::post(address, body(literal.code(), &client), None).await;
    assert_eq!(response.status(), 200);
    let literal = http::value(response).await;
    let literalclaims = http::claims(
        &signer,
        &format!("http://{address}"),
        literal["access_token"].as_str().unwrap(),
    );
    assert!(
        verify
            .verify(literal["access_token"].as_str().unwrap(), &[], deadline())
            .is_ok(),
        "HTTP literal identity remains a verifiable Broker bearer"
    );
    let expected = oidc::digester()
        .oidc_subject(first.issuer.as_bytes(), raw.as_bytes())
        .unwrap();
    assert!(
        literalclaims["sub"] == expected.as_str(),
        "native HTTP preserves framed issuer/rawsubject identity"
    );
    assert_eq!(literalclaims["preferred_username"], username);
    let pending = fed::code(&f, &first, &v1, &client).await;
    http::stop(child).await;
    config["auth"]["oidc"][0]["browser_clients"] = json!([]);
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    for form in [
        body(pending.code(), &client),
        refresh(rotated["refresh_token"].as_str().unwrap(), &client),
    ] {
        let response = http::post(address, form, None).await;
        assert_eq!(response.status(), 400);
        assert_eq!(
            http::value(response).await,
            json!({"error":"invalid_grant"})
        );
    }
    assert!(
        verify
            .verify(issued["access_token"].as_str().unwrap(), &[], deadline())
            .is_ok()
    );
    http::stop(child).await;
    first.close().await;
    second.close().await;
    f.close().await;
}
