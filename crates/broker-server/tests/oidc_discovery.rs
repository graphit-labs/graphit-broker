//! Native discovery consumers, configured issuer and productive OAuth endpoints.
#[path = "support/oidc_http.rs"]
#[allow(
    dead_code,
    reason = "shared native process fixture also covers token failures"
)]
mod http;
#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
#[allow(
    dead_code,
    reason = "shared SQL fixture also covers producer contracts"
)]
mod oidc;
#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "shared PostgreSQL fixture also covers other contracts"
)]
mod support;

use broker_control::{BrokerAccessTokenInput, LocalPasswordEngine};
use broker_security::LocalPasswordHasher;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, jwk::JwkSet};
use oidc::{AUDIENCE, OidcFixture, PASSWORD, PEPPER, RESOURCE, VERIFIER};
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use std::{
    net::SocketAddr,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::{deadline, n};
use zeroize::Zeroizing;

const GRAPHIT: &str = "/.well-known/graphit-broker";
const OPENID: &str = "/.well-known/openid-configuration";
const SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];
const REDIRECT: &str = "http://127.0.0.1:49159/cb";
const STATE: &str = "discovery state café +%";

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}
fn base(addr: SocketAddr, pg: u16) -> Value {
    serde_saphyr::from_str(&http::yaml(addr, pg)).unwrap()
}
fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}
async fn start(root: &Path, config: &Value, addr: SocketAddr) -> tokio::process::Child {
    let path = http::write(root, &serde_saphyr::to_string(config).unwrap());
    http::start(&path, addr).await
}
async fn check(root: &Path, config: &Value, expected: bool, diagnostic: Option<&str>) {
    let path = http::write(root, &serde_saphyr::to_string(config).unwrap());
    let output = http::command()
        .args(["--config", path.to_str().unwrap(), "--check-config"])
        .output()
        .await
        .unwrap();
    assert_eq!(output.status.success(), expected);
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!error.contains(PEPPER));
    if let Some(diagnostic) = diagnostic {
        assert!(error.contains(diagnostic), "{error}");
    }
    assert!(!root.join("volumes").exists());
}

#[tokio::test]
async fn discovery_configuration_literal_contract_without_effects() {
    let root = tempfile::tempdir().unwrap();
    let sql = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = params.self_signed(&key).unwrap().pem();
    http::files(root.path(), ca.as_bytes(), "https://broker.example");
    let original = base(addr, sql.local_addr().unwrap().port());
    for public in [
        "https://broker.example",
        "https://broker.example/",
        "https://Broker.Example",
        "https://broker.example:443",
    ] {
        let mut config = original.clone();
        config["server"]["public_url"] = json!(public);
        config["auth"]["issuer"] = json!(public);
        for dcr in [false, true] {
            config["oidc"]["dynamic_registration"] = json!(dcr);
            check(root.path(), &config, true, None).await;
        }
        for different in [
            "https://broker.example",
            "https://broker.example/",
            "https://Broker.Example",
            "https://broker.example:443",
        ] {
            if public == different {
                continue;
            }
            config["auth"]["issuer"] = json!(different);
            check(
                root.path(),
                &config,
                false,
                Some("auth.issuer to equal server.public_url literally"),
            )
            .await;
            config["oidc"]["enabled"] = json!(false);
            check(root.path(), &config, true, None).await;
            config["oidc"]["enabled"] = json!(true);
        }
    }
    for resources in [
        json!([]),
        json!([RESOURCE]),
        json!([RESOURCE, "https://other.example/v1"]),
    ] {
        let mut config = original.clone();
        config["oidc"]["accepted_resources"] = resources;
        check(root.path(), &config, true, None).await;
    }
    for resources in [
        json!([""]),
        json!([" "]),
        json!([format!(" {RESOURCE}")]),
        json!([format!("{RESOURCE} ")]),
        json!([RESOURCE, RESOURCE]),
    ] {
        let mut config = original.clone();
        config["oidc"]["accepted_resources"] = resources;
        check(
            root.path(),
            &config,
            false,
            Some("oidc.accepted_resources requires"),
        )
        .await;
        config["oidc"]["enabled"] = json!(false);
        check(root.path(), &config, true, None).await;
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

async fn document(client: &reqwest::Client, origin: &str, path: &str) -> Value {
    let get = client
        .get(format!("{origin}{path}"))
        .header("host", "untrusted.example:9443")
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let mut headers = get.headers().clone();
    // RFC9110 9.3.2 / RFC9112 6.1: preserve representation metadata,
    // while Date and transfer framing describe the individual message.
    headers.remove("date").expect("native HTTP Date header");
    let framing = headers.remove("transfer-encoding");
    assert_eq!(
        framing.as_ref().map(|v| v.as_bytes()),
        Some(b"chunked".as_slice())
    );
    let bytes = get.bytes().await.unwrap();
    let head = client
        .head(format!("{origin}{path}"))
        .header("host", "untrusted.example:9443")
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    let mut head_headers = head.headers().clone();
    head_headers
        .remove("date")
        .expect("native HEAD Date header");
    assert!(head_headers.remove("transfer-encoding").is_none());
    assert_eq!(headers, head_headers);
    assert_eq!(headers["content-type"], "application/json");
    assert!(head.bytes().await.unwrap().is_empty());
    serde_json::from_slice(&bytes).unwrap()
}
fn storage_service() -> Value {
    json!({"s3_credentials":{"protocol":"graphit-s3-credentials-v3","path":"/v1/s3/credentials"}})
}

fn metadata(
    graphit: &Value,
    openid: &Value,
    issuer: &str,
    resources: &Value,
    dcr: bool,
    device: bool,
) {
    assert_eq!(
        graphit,
        &json!({"version":"1","issuer":issuer,"authentication":{
        "type":"oidc","issuer":issuer,"client_id":"discovery-cli","scopes":SCOPES,
        "audiences":[AUDIENCE],"access_token_audience":AUDIENCE,"redirect_uri_path":"/discovery/callback",
        "mcp_resources":resources},"services":storage_service()})
    );
    let base = issuer.trim_end_matches('/');
    assert_eq!(openid["issuer"], issuer);
    for (key, path) in [
        ("authorization_endpoint", "/oauth/authorize"),
        ("token_endpoint", "/oauth/token"),
        ("revocation_endpoint", "/oauth/revoke"),
        ("jwks_uri", "/v1/oidc/keys"),
    ] {
        assert_eq!(openid[key], format!("{base}{path}"));
    }
    assert_eq!(openid["scopes_supported"], json!(SCOPES));
    if device {
        assert_eq!(
            openid["device_authorization_endpoint"],
            format!("{base}/oauth/device/authorize")
        );
    } else {
        assert!(openid["device_authorization_endpoint"].is_null());
    }
    let mut grants = vec!["authorization_code", "refresh_token"];
    if device {
        grants.push(broker_control::DEVICE_GRANT_TYPE);
    }
    assert_eq!(openid["grant_types_supported"], json!(grants));
    for (key, values) in [
        ("response_types_supported", json!(["code"])),
        (
            "response_modes_supported",
            json!(["query", "fragment", "form_post"]),
        ),
        ("subject_types_supported", json!(["public"])),
        ("id_token_signing_alg_values_supported", json!(["EdDSA"])),
        ("token_endpoint_auth_methods_supported", json!(["none"])),
        (
            "revocation_endpoint_auth_methods_supported",
            json!(["none"]),
        ),
        ("code_challenge_methods_supported", json!(["S256"])),
    ] {
        assert_eq!(openid[key], values);
    }
    if dcr {
        assert_eq!(
            openid["registration_endpoint"],
            format!("{base}/oauth/register")
        );
    } else {
        assert!(openid.get("registration_endpoint").is_none());
    }
    assert_eq!(
        openid["userinfo_endpoint"],
        format!("{base}/oauth/userinfo")
    );
    assert_eq!(
        openid["introspection_endpoint"],
        format!("{base}/oauth/introspect")
    );
    assert_eq!(
        openid["introspection_endpoint_auth_methods_supported"],
        json!(["Bearer"])
    );
    assert_eq!(
        openid["end_session_endpoint"],
        format!("{base}/oauth/end-session")
    );
}
fn claims(keys: &JwkSet, expected_issuer: &str, token: &str) -> Value {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&[expected_issuer]);
    decode::<Value>(
        token,
        &DecodingKey::from_jwk(&keys.keys[0]).unwrap(),
        &validation,
    )
    .unwrap()
    .claims
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native binary, TLS PostgreSQL NOSUPERUSER, LOCAL login, discovery endpoints and real EdDSA"]
async fn discovery_native_journey_and_static_reads_without_database() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = http::address();
    let origin = format!("http://{addr}");
    let issuer = format!("http://localhost:{}/", addr.port());
    http::files(root.path(), &f.fixture.ca, &issuer);
    let mut config = base(addr, f.fixture.port);
    config["server"]["public_url"] = json!(issuer);
    config["auth"]["issuer"] = json!(issuer);
    config["oidc"]["cli_client_id"] = json!("discovery-cli");
    config["oidc"]["cli_redirect_path"] = json!("/discovery/callback");
    let web_resource = format!("{}/v1", issuer.trim_end_matches('/'));
    let resources = json!([web_resource, RESOURCE]);
    config["oidc"]["accepted_resources"] = resources.clone();
    config["auth"]["local"] = json!({"login":{"enabled":true},"mfa":{"required":false,"issuer_label":"Graphit Broker","challenge_ttl":"10m"},"rate_limit":{"max_failures":20,"window":"60s","lockout":"300s","max_concurrent":2,"saturation_multiplier":4}});
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
    let child = start(root.path(), &config, addr).await;
    let client = client();
    // Consumer order is deliberate: neither document substitutes for the other.
    let graphit = document(&client, &origin, GRAPHIT).await;
    let openid = document(&client, &origin, OPENID).await;
    metadata(&graphit, &openid, &issuer, &resources, true, true);
    let registered = client.post(openid["registration_endpoint"].as_str().unwrap())
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"redirect_uris":[REDIRECT],"scope":SCOPES.join(" "),"token_endpoint_auth_method":"none"})).unwrap())
        .send().await.unwrap();
    assert_eq!(registered.status(), 201);
    let registered = http::value(registered).await;
    let client_id = registered["client_id"].as_str().unwrap();
    let pairs = [
        ("client_id", client_id),
        ("redirect_uri", REDIRECT),
        ("response_type", "code"),
        ("scope", "openid profile email offline_access"),
        ("state", STATE),
        ("nonce", "discovery nonce"),
        (
            "code_challenge",
            "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
        ),
        ("code_challenge_method", "S256"),
        ("resource", web_resource.as_str()),
    ];
    let authorize = client
        .get(format!(
            "{}?{}",
            openid["authorization_endpoint"].as_str().unwrap(),
            form(&pairs)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(authorize.status(), 303);
    let login = format!(
        "{}{}",
        issuer.trim_end_matches('/'),
        authorize.headers()["location"].to_str().unwrap()
    );
    assert_eq!(client.get(&login).send().await.unwrap().status(), 200);
    let complete = client
        .post(&login)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("login_method", "local"),
            ("username", "alice"),
            ("password", PASSWORD),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(complete.status(), 303);
    let target = url::Url::parse(complete.headers()["location"].to_str().unwrap()).unwrap();
    assert!(target.as_str().starts_with(REDIRECT));
    let parameters = target
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(parameters["state"], STATE);
    let token = client
        .post(openid["token_endpoint"].as_str().unwrap())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", &parameters["code"]),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("resource", &web_resource),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(token.status(), 200);
    let tokens = http::value(token).await;
    let keys = client
        .get(openid["jwks_uri"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(keys.status(), 200);
    let keys_value = http::value(keys).await;
    assert!(keys_value["keys"][0].get("d").is_none());
    let keys: JwkSet = serde_json::from_value(keys_value.clone()).unwrap();
    let access = claims(&keys, &issuer, tokens["access_token"].as_str().unwrap());
    let id = claims(&keys, &issuer, tokens["id_token"].as_str().unwrap());
    assert_eq!(access["client_id"], client_id);
    assert_eq!(access["aud"], json!([AUDIENCE, web_resource]));
    assert_eq!(id["nonce"], "discovery nonce");
    let refreshed = client
        .post(openid["token_endpoint"].as_str().unwrap())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("resource", &web_resource),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(refreshed.status(), 200);
    let refreshed = http::value(refreshed).await;
    let rotated = claims(&keys, &issuer, refreshed["access_token"].as_str().unwrap());
    assert_eq!(rotated["sub"], access["sub"]);
    assert_eq!(rotated["aud"], json!([AUDIENCE, web_resource]));
    let rotated_id = claims(&keys, &issuer, refreshed["id_token"].as_str().unwrap());
    assert_eq!(rotated_id["sub"], id["sub"]);
    assert_eq!(rotated_id["auth_time"], id["auth_time"]);
    assert!(
        refreshed["refresh_token"] != tokens["refresh_token"],
        "native refresh must rotate its opaque secret"
    );
    for endpoint in ["authorization_endpoint", "token_endpoint"] {
        let response = client
            .head(openid[endpoint].as_str().unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 405);
    }
    // Remove the real SQL service. Static documents remain available with identical bodies.
    f.engine.close().await;
    f.store.shutdown(deadline()).await.unwrap();
    f.admin.close().await.unwrap();
    f.fixture.shutdown().unwrap();
    assert_eq!(document(&client, &origin, GRAPHIT).await, graphit);
    assert_eq!(document(&client, &origin, OPENID).await, openid);
    assert_eq!(
        document(&client, &origin, "/v1/oidc/keys").await,
        keys_value
    );
    http::stop(child).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native binary and TLS PostgreSQL for OIDCoff, DCRoff, empty resources and independent Native issuer"]
async fn discovery_native_capability_profiles() {
    let f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let client = client();
    for (enabled, dcr, empty) in [
        (true, false, false),
        (true, true, true),
        (false, false, false),
    ] {
        let addr = http::address();
        let origin = format!("http://{addr}");
        let issuer = if enabled {
            origin.clone()
        } else {
            "https://native-independent.example".into()
        };
        let signer = http::files(root.path(), &f.fixture.ca, &issuer);
        let mut config = base(addr, f.fixture.port);
        config["auth"]["issuer"] = json!(issuer);
        config["oidc"]["enabled"] = json!(enabled);
        config["oidc"]["dynamic_registration"] = json!(dcr);
        config["oidc"]["cli_client_id"] = json!("discovery-cli");
        config["oidc"]["cli_redirect_path"] = json!("/discovery/callback");
        let resources = if empty { json!([]) } else { json!([RESOURCE]) };
        config["oidc"]["accepted_resources"] = resources.clone();
        let child = start(root.path(), &config, addr).await;
        if enabled {
            let graphit = document(&client, &origin, GRAPHIT).await;
            let openid = document(&client, &origin, OPENID).await;
            metadata(&graphit, &openid, &issuer, &resources, dcr, false);
            if !dcr {
                assert_eq!(
                    client
                        .post(format!("{origin}/oauth/register"))
                        .body("{}")
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    404
                );
            }
            let mut pairs = vec![
                ("client_id", "discovery-cli"),
                ("redirect_uri", "http://localhost:49159/discovery/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", STATE),
                ("nonce", "nonce"),
                (
                    "code_challenge",
                    "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
                ),
                ("code_challenge_method", "S256"),
            ];
            // P2 still admits no extra resource. Metadata never injects the Web /v1 resource.
            let response = client
                .get(format!(
                    "{}?{}",
                    openid["authorization_endpoint"].as_str().unwrap(),
                    form(&pairs)
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 303);
            assert!(
                response.headers()["location"]
                    .to_str()
                    .unwrap()
                    .starts_with("/oauth/login?id=")
            );
            pairs.push(("resource", "https://not-configured.example/v1"));
            let response = client
                .get(format!(
                    "{}?{}",
                    openid["authorization_endpoint"].as_str().unwrap(),
                    form(&pairs)
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 303);
            let location =
                url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
            assert!(
                location
                    .query_pairs()
                    .any(|(k, v)| k == "error" && v == "invalid_target")
            );
        } else {
            let graphit = document(&client, &origin, GRAPHIT).await;
            assert_eq!(
                graphit,
                json!({"version":"1","issuer":origin,"services":storage_service()})
            );
            for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
                assert_eq!(
                    client
                        .request(method, format!("{origin}{OPENID}"))
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    404
                );
            }
            let keys = document(&client, &origin, "/v1/oidc/keys").await;
            assert_eq!(keys, serde_json::to_value(signer.jwks()).unwrap());
            assert!(keys["keys"][0].get("d").is_none());
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let token = Zeroizing::new(
                signer
                    .sign_access(
                        BrokerAccessTokenInput {
                            subject: "native-subject",
                            client_id: "native-client",
                            resource: None,
                            scope: "",
                            jti: "native-discovery",
                            issued_at: now,
                            expires_at: now + 600,
                            preferred_username: None,
                            name: None,
                            email: None,
                            organization: None,
                            groups: &[],
                            roles: &[],
                        },
                        deadline(),
                    )
                    .unwrap(),
            );
            let keys: JwkSet = serde_json::from_value(keys).unwrap();
            assert_eq!(claims(&keys, &issuer, &token)["iss"], issuer);
            for (bearer, expected) in [(token.as_str(), 400), ("invalid.jwt", 401)] {
                let response = client
                    .post(format!("{origin}/v1/s3/credentials"))
                    .bearer_auth(bearer)
                    .header("content-type", "application/json")
                    .body("invalid JSON")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), expected);
            }
        }
        http::stop(child).await;
    }
    f.close().await;
}
