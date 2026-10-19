#[allow(
    dead_code,
    reason = "shared genuine HTTPS issuer supports independent contracts"
)]
#[path = "../../broker-control/tests/support/browser_upstream.rs"]
mod browser;
#[path = "support/upstream_commit.rs"]
mod commit;
#[allow(
    dead_code,
    reason = "shared H1 producer supports independent contracts"
)]
#[path = "../../broker-control/tests/support/oidc_federated.rs"]
mod federated;
#[allow(
    dead_code,
    reason = "shared native process helpers support independent contracts"
)]
#[path = "support/oidc_http.rs"]
mod http;
#[allow(
    dead_code,
    reason = "shared genuine LOCAL producer supports independent contracts"
)]
#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared TLS SQL fixture supports independent contracts"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use broker_control::{
    BrokerAccessVerifier, LocalAuthPolicy, LocalAuthStep, OidcAuthorizationInput,
    OidcEndSessionInput, OidcTokenExchangeError, PreparedOidcLogin,
};
use broker_security::{LocalAuthBinding, LocalMfaProtector};
use browser::{BrowserIssuer, Fault};
use oidc::{AUDIENCE, OidcFixture, RESOURCE, VERIFIER};
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use support::{deadline, n};
use zeroize::Zeroizing;

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}
async fn local_code(
    f: &OidcFixture,
    user: &str,
    client: &str,
    offline: bool,
) -> broker_control::AuthorizedOidcAuthorization {
    let digester = oidc::digester();
    let service = f.store.oidc_authorization_service(&digester, &f.policy);
    let dynamic = client != "graphit-cli";
    let pending = service
        .create(
            OidcAuthorizationInput {
                client_id: client,
                redirect_uri: if dynamic {
                    federated::REDIRECT
                } else {
                    "http://localhost:49152/oauth/callback"
                },
                response_type: "code",
                scope: if offline {
                    "openid profile email offline_access"
                } else {
                    "openid profile email"
                },
                state: "literal-state",
                nonce: "literal-nonce",
                code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
                code_challenge_method: "S256",
                response_mode: Some("query"),
                resources: if dynamic { &[RESOURCE] } else { &[] },
                prompts: &[],
            },
            deadline(),
        )
        .await
        .unwrap();
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify(user, oidc::PASSWORD, deadline())
        .await
        .unwrap();
    let protector =
        LocalMfaProtector::new(Zeroizing::new(vec![51; 32].into_boxed_slice())).unwrap();
    let policy =
        LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(600)).unwrap();
    let LocalAuthStep::Complete(proof) = f
        .store
        .local_auth_service(&digester, &protector, &policy)
        .begin(
            proof,
            LocalAuthBinding::OauthAuthorize(pending.request().as_bytes()),
            deadline(),
        )
        .await
        .unwrap()
    else {
        panic!("genuine completed LOCAL proof expected")
    };
    service
        .complete(
            pending.request(),
            PreparedOidcLogin::try_from(proof).unwrap(),
            deadline(),
        )
        .await
        .unwrap()
}
async fn exchange(address: std::net::SocketAddr, code: &str, id: &str) -> reqwest::Response {
    let dynamic = id != "graphit-cli";
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("client_id", id),
        ("code", code),
        (
            "redirect_uri",
            if dynamic {
                federated::REDIRECT
            } else {
                "http://localhost:49152/oauth/callback"
            },
        ),
        ("code_verifier", VERIFIER),
    ];
    if dynamic {
        pairs.push(("resource", RESOURCE));
    }
    http::post(address, form(&pairs), None).await
}
async fn issue_for(
    f: &OidcFixture,
    address: std::net::SocketAddr,
    user: &str,
    id: &str,
    offline: bool,
) -> Value {
    let code = local_code(f, user, id, offline).await;
    let response = exchange(address, code.code(), id).await;
    assert_eq!(response.status(), 200);
    http::value(response).await
}
async fn issue(f: &OidcFixture, address: std::net::SocketAddr) -> Value {
    issue_for(f, address, "alice", "web-client", true).await
}
async fn refresh(address: std::net::SocketAddr, raw: &str) -> reqwest::Response {
    http::post(
        address,
        form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "web-client"),
            ("refresh_token", raw),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await
}
async fn post(c: &reqwest::Client, origin: &str, body: String) -> reqwest::Response {
    c.post(format!("{origin}/oauth/end-session"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap_or_else(|_| panic!("end-session transport failed"))
}
async fn dispose(c: &reqwest::Client, origin: &str, hint: &str) -> reqwest::Response {
    post(c, origin, form(&[("id_token_hint", hint)])).await
}
fn hint(t: &Value) -> &str {
    t["id_token"].as_str().unwrap()
}
fn access(t: &Value) -> &str {
    t["access_token"].as_str().unwrap()
}
fn refresh_token(t: &Value) -> &str {
    t["refresh_token"].as_str().unwrap()
}
fn private(r: &reqwest::Response) {
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(r.headers()["pragma"], "no-cache");
    assert!(!r.headers().contains_key("location"));
    assert!(!r.headers().contains_key("www-authenticate"));
}
async fn empty(r: reqwest::Response) {
    assert_eq!(r.status(), 204);
    private(&r);
    assert!(r.bytes().await.unwrap().is_empty());
}
async fn error(r: reqwest::Response, status: u16, code: &str) {
    assert_eq!(r.status(), status);
    private(&r);
    assert_eq!(http::value(r).await, json!({"error":code}));
}
async fn active_pair(f: &mut OidcFixture, subject: &str, client: &str) -> i64 {
    sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.local_tokens WHERE oidc_subject=$1 AND client_id=$2 AND token_kind IN ('oidc_access','refresh') AND revoked_at IS NULL")
        .bind(subject).bind(client).fetch_one(&mut f.admin).await.unwrap()
}
async fn waiting(f: &mut OidcFixture, prefix: &str) {
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let count: i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND query LIKE $1 AND wait_event_type='Lock'")
            .bind(prefix).fetch_one(&mut f.admin).await.unwrap();
        if count > 0 {
            return;
        }
        assert!(
            Instant::now() < end,
            "expected bounded SQL lock observation"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
fn signed(root: &std::path::Path, value: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some("configured-key".into());
    let der = Zeroizing::new(std::fs::read(root.join("signing.pk8")).unwrap());
    jsonwebtoken::encode(
        &header,
        value,
        &jsonwebtoken::EncodingKey::from_ed_der(&der),
    )
    .unwrap()
}
#[tokio::test]
#[ignore = "native executable, real DCR/LOCAL/P3, strict hint/wire isolation and elapsed ID expiry"]
async fn broker_oidc_end_session_local_http_contract() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    let signer = http::files(root.path(), &f.fixture.ca, &origin);
    let mut config: Value = serde_saphyr::from_str(&http::yaml(address, f.fixture.port)).unwrap();
    config["oidc"]["access_ttl"] = json!("60s");
    let path = http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    let c = client();
    let metadata = http::value(
        c.get(format!("{origin}/.well-known/openid-configuration"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        metadata["end_session_endpoint"],
        format!("{origin}/oauth/end-session")
    );
    let registration=c.post(format!("{origin}/oauth/register")).header("content-type", "application/json").body(json!({"redirect_uris":[federated::REDIRECT],"token_endpoint_auth_method":"none","client_name":"end-session genuine DCR"}).to_string()).send().await.unwrap();
    assert_eq!(registration.status(), 201);
    let registered = http::value(registration).await;
    let dynamic = registered["client_id"].as_str().unwrap();
    let tokens = issue_for(&f, address, "alice", dynamic, true).await;
    let sibling = issue_for(&f, address, "alice", dynamic, true).await;
    let only_access = issue_for(&f, address, "alice", dynamic, false).await;
    assert!(only_access.get("refresh_token").is_none());
    let other_client = issue_for(&f, address, "alice", "graphit-cli", true).await;
    f.admin.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) SELECT 'bob','bob-subject',identity_kind,password_hash,'Bob',email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at FROM public.local_users WHERE username='alice'").await.unwrap();
    let other_subject = issue_for(&f, address, "bob", dynamic, true).await;
    let claims = http::claims(&signer, &origin, hint(&tokens));
    let subject = claims["sub"].as_str().unwrap();
    assert_eq!(active_pair(&mut f, subject, dynamic).await, 5);
    let verifier =
        BrokerAccessVerifier::new(&origin, AUDIENCE, Some(RESOURCE), signer.jwks(), n(8192))
            .unwrap();
    assert!(verifier.verify(hint(&tokens), &[], deadline()).is_err());
    for raw in ["", "unknown", access(&tokens), refresh_token(&tokens)] {
        error(dispose(&c, &origin, raw).await, 400, "invalid_request").await;
    }
    let mut invalids = Vec::new();
    for (key, value) in [
        ("iss", json!("https://wrong.example")),
        ("aud", json!([AUDIENCE])),
        ("azp", json!("other")),
        ("client_id", json!("other")),
        ("iat", json!(claims["exp"].as_u64().unwrap() + 1)),
        ("auth_time", json!(claims["iat"].as_u64().unwrap() + 1)),
        ("nbf", json!(claims["exp"])),
        ("exp", json!(claims["iat"])),
        ("exp", Value::Null),
        ("amr", json!([])),
        ("at_hash", json!("bad")),
        ("jti", Value::Null),
        ("token_use", json!("access")),
        ("scope", json!("openid")),
    ] {
        let mut bad = claims.clone();
        bad[key] = value;
        invalids.push(signed(root.path(), &bad));
    }
    let mut missing = claims.clone();
    missing.as_object_mut().unwrap().remove("exp");
    invalids.push(signed(root.path(), &missing));
    let good = signed(root.path(), &claims);
    let parts: Vec<_> = good.split('.').collect();
    let mut bad_signature = parts[2].as_bytes().to_vec();
    bad_signature[0] = if bad_signature[0] == b'A' { b'B' } else { b'A' };
    invalids.push(format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        String::from_utf8(bad_signature).unwrap()
    ));
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let encoding = jsonwebtoken::EncodingKey::from_ed_der(
        &std::fs::read(root.path().join("signing.pk8")).unwrap(),
    );
    for payload in [
        format!(
            "{},\"exp\":1}}",
            serde_json::to_string(&claims)
                .unwrap()
                .trim_end_matches('}')
        ),
        format!(
            "{},\"extension\":0,\"extension\":1}}",
            serde_json::to_string(&claims)
                .unwrap()
                .trim_end_matches('}')
        ),
    ] {
        let message = format!("{}.{}", parts[0], URL_SAFE_NO_PAD.encode(payload));
        let signature = jsonwebtoken::crypto::sign(
            message.as_bytes(),
            &encoding,
            jsonwebtoken::Algorithm::EdDSA,
        )
        .unwrap();
        invalids.push(format!("{message}.{signature}"));
    }
    for header in [
        json!({"alg":"EdDSA","kid":"unknown"}),
        json!({"alg":"HS256","kid":"configured-key"}),
        json!({"alg":"EdDSA","kid":"configured-key","jwk":{}}),
        json!({"alg":"EdDSA","kid":"configured-key","crit":[]}),
    ] {
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            parts[1]
        );
        invalids.push(format!(
            "{message}.{}",
            jsonwebtoken::crypto::sign(
                message.as_bytes(),
                &encoding,
                jsonwebtoken::Algorithm::EdDSA
            )
            .unwrap()
        ));
    }
    for bad in invalids {
        error(dispose(&c, &origin, &bad).await, 400, "invalid_request").await;
    }
    for body in [
        "",
        "id_token_hint=x&id_token_hint=x",
        "id_token_hint=%FF",
        "id_token_hint=x&client_id=a&client_id=a",
        "id_token_hint=x&post_logout_redirect_uri=",
        "id_token_hint=x&state=a&state=b",
    ] {
        error(post(&c, &origin, body.into()).await, 400, "invalid_request").await;
    }
    error(
        post(
            &c,
            &origin,
            form(&[
                ("id_token_hint", hint(&tokens)),
                ("client_id", "graphit-cli"),
            ]),
        )
        .await,
        400,
        "invalid_request",
    )
    .await;
    for request in [
        c.post(format!("{origin}/oauth/end-session"))
            .header("content-type", "application/json")
            .body("{}"),
        c.post(format!("{origin}/oauth/end-session?id_token_hint=x"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(&[("id_token_hint", hint(&tokens))])),
        c.post(format!("{origin}/oauth/end-session"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(vec![b'a'; 32769]),
        c.get(format!(
            "{origin}/oauth/end-session?{}",
            form(&[("id_token_hint", hint(&tokens))])
        ))
        .body("unexpected"),
        c.post(format!("{origin}/oauth/end-session"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(&[
                ("id_token_hint", hint(&tokens)),
                ("state", &"a".repeat(8193)),
            ])),
        c.get(format!(
            "{origin}/oauth/end-session?{}&ignored={}",
            form(&[("id_token_hint", hint(&tokens))]),
            "a".repeat(8193)
        )),
    ] {
        error(
            request
                .send()
                .await
                .unwrap_or_else(|_| panic!("wire transport failed")),
            400,
            "invalid_request",
        )
        .await;
    }
    for auth in ["Basic d2ViOm5v", "Bearer invalid"] {
        error(
            c.post(format!("{origin}/oauth/end-session"))
                .header("authorization", auth)
                .header("cookie", "session=ignored")
                .header("content-type", "application/x-www-form-urlencoded")
                .body("")
                .send()
                .await
                .unwrap(),
            400,
            "invalid_request",
        )
        .await;
    }
    for method in [
        reqwest::Method::HEAD,
        reqwest::Method::PUT,
        reqwest::Method::DELETE,
    ] {
        let response = c
            .request(method, format!("{origin}/oauth/end-session"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 405);
        private(&response);
        assert_eq!(response.headers()["allow"], "GET, POST");
    }
    let preflight = c
        .request(
            reqwest::Method::OPTIONS,
            format!("{origin}/oauth/end-session"),
        )
        .header("origin", "https://ui.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .send()
        .await
        .unwrap();
    assert_eq!(preflight.status(), 200);
    assert_eq!(
        preflight.headers()["access-control-allow-origin"],
        "https://ui.example"
    );
    assert!(
        !preflight
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    assert_eq!(active_pair(&mut f, subject, dynamic).await, 5);
    let done = c
        .get(format!(
            "{origin}/oauth/end-session?{}",
            form(&[
                ("id_token_hint", hint(&tokens)),
                ("client_id", dynamic),
                ("state", "ignored"),
                ("ui_locales", "pt-BR"),
                ("logout_hint", "ignored")
            ])
        ))
        .header("authorization", "Bearer invalid")
        .header("cookie", "session=ignored")
        .header("origin", "https://ui.example")
        .send()
        .await
        .unwrap_or_else(|_| panic!("GET disposal transport failed"));
    assert_eq!(
        done.headers()["access-control-allow-origin"],
        "https://ui.example"
    );
    empty(done).await;
    assert_eq!(active_pair(&mut f, subject, dynamic).await, 0);
    let times:Vec<i64>=sqlx_core::query_scalar::query_scalar("SELECT revoked_at FROM public.local_tokens WHERE oidc_subject=$1 AND client_id=$2 ORDER BY token_id")
        .bind(subject).bind(dynamic).fetch_all(&mut f.admin).await.unwrap();
    assert_eq!(times.len(), 5);
    assert!(times.iter().all(|t| *t == times[0]));
    empty(dispose(&c, &origin, hint(&sibling)).await).await;
    let same:Vec<i64>=sqlx_core::query_scalar::query_scalar("SELECT revoked_at FROM public.local_tokens WHERE oidc_subject=$1 AND client_id=$2 ORDER BY token_id")
        .bind(subject).bind(dynamic).fetch_all(&mut f.admin).await.unwrap();
    assert_eq!(times, same);
    let other_claims = http::claims(&signer, &origin, hint(&other_client));
    assert_eq!(active_pair(&mut f, subject, "graphit-cli").await, 2);
    assert_ne!(
        http::claims(&signer, &origin, hint(&other_subject))["sub"],
        other_claims["sub"]
    );
    let subject_b = http::claims(&signer, &origin, hint(&other_subject));
    assert_eq!(
        active_pair(&mut f, subject_b["sub"].as_str().unwrap(), dynamic).await,
        2
    );
    let denied = http::post(
        address,
        form(&[
            ("grant_type", "refresh_token"),
            ("client_id", dynamic),
            ("refresh_token", refresh_token(&tokens)),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await;
    assert_eq!(denied.status(), 400);
    assert_eq!(
        c.get(format!("{origin}/oauth/userinfo"))
            .bearer_auth(access(&tokens))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        c.post(format!("{origin}/oauth/introspect"))
            .bearer_auth(access(&tokens))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(&[("token", access(&tokens))]))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    verifier.verify(access(&tokens), &[], deadline()).unwrap();
    // A real newly issued ID remains a disposal credential after elapsed native TTL.
    let expired = issue(&f, address).await;
    let exp = http::claims(&signer, &origin, hint(&expired))["exp"]
        .as_u64()
        .unwrap();
    f.admin
        .execute("DELETE FROM public.oauth_dynamic_clients WHERE client_id='web-client'")
        .await
        .unwrap();
    let wait = exp.saturating_sub((oidc::micros() / 1_000_000) as u64) + 1;
    tokio::time::sleep(Duration::from_secs(wait)).await;
    assert_eq!(
        verifier
            .verify(access(&expired), &[], deadline())
            .unwrap_err(),
        broker_control::BrokerAccessError::Expired
    );
    empty(dispose(&c, &origin, hint(&expired)).await).await;
    http::stop(child).await;
    config["oidc"]["enabled"] = json!(false);
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    for route in ["/oauth/end-session", "/.well-known/openid-configuration"] {
        assert_eq!(
            c.get(format!("{origin}{route}"))
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

fn provider(upstream: &BrowserIssuer) -> Value {
    let recipe: Value = serde_saphyr::from_str(http::block(include_str!(
        "../../../docs/rust-admin-upstream-login.md"
    )))
    .unwrap();
    let mut p = recipe["auth"]["oidc"][0].clone();
    p["id"] = json!("external");
    p["issuer"] = json!(upstream.issuer);
    p["ca_file"] = json!("upstream-ca.pem");
    p["claims"]["subject"] = json!("mapped_subject");
    p["claims"]["roles"] = json!("roles");
    p["required_scopes"] = json!([]);
    p["browser_clients"] = json!([{"display_name":"Profile upstream","client_id":"public","redirect_url":federated::client("public").redirect_url,"scopes":["profile","email"],"require_nonce":true,"claims_source":"id_token","id_token_additional_audiences":[]}]);
    p
}

async fn password_change_job(f: &OidcFixture) -> tokio::task::JoinHandle<()> {
    use broker_control::{LocalAuthPolicy, LocalAuthStep, LocalPasswordEngine};
    use broker_security::{LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher};
    use zeroize::Zeroizing;
    let digester = oidc::digester();
    let protector =
        LocalMfaProtector::new(Zeroizing::new(vec![51; 32].into_boxed_slice())).unwrap();
    let policy =
        LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(600)).unwrap();
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", oidc::PASSWORD, deadline())
        .await
        .unwrap();
    let step = f
        .store
        .local_auth_service(&digester, &protector, &policy)
        .begin(proof, LocalAuthBinding::AdminLogin, deadline())
        .await
        .unwrap();
    let LocalAuthStep::Pending(pending) = step else {
        panic!("genuine required-password challenge expected")
    };
    let challenge = Zeroizing::new(pending.challenge().to_owned());
    let engine = LocalPasswordEngine::new(
        LocalPasswordHasher::new(Zeroizing::new(vec![29; 32].into_boxed_slice())).unwrap(),
        n(1),
        deadline(),
    )
    .await
    .unwrap();
    let store = f.store.clone();
    tokio::spawn(async move {
        let result = store
            .local_auth_service(&digester, &protector, &policy)
            .complete_password_change(
                &engine,
                &challenge,
                LocalAuthBinding::AdminLogin,
                "a different genuine LOCAL password",
                deadline(),
            )
            .await
            .unwrap();
        assert!(matches!(result, LocalAuthStep::Complete(_)));
        engine.close().await;
    })
}

#[tokio::test]
#[ignore = "native executable, genuine HTTPS H1 and P3, then closed upstream and removed trust/DCR"]
async fn broker_oidc_end_session_federated_http_contract() {
    let mut f = OidcFixture::new().await;
    let mut upstream = BrowserIssuer::new().await;
    federated::register(&upstream, "public");
    upstream.fault(Fault {
        id_overrides: [
            ("mapped_subject".into(), json!("federated-subject")),
            ("roles".into(), json!(["profile-role"])),
        ]
        .into(),
        ..Fault::default()
    });
    let trust = federated::verifier(&upstream, vec![federated::client("public")], Some("roles"));
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    let signer = http::files(root.path(), &f.fixture.ca, &origin);
    std::fs::write(root.path().join("upstream-ca.pem"), &upstream.ca).unwrap();
    let mut config: Value = serde_saphyr::from_str(&http::yaml(address, f.fixture.port)).unwrap();
    config["auth"]["oidc"] = json!([provider(&upstream)]);
    let path = http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    let c = client();
    let dynamic = federated::registered(&f).await;
    let mut issued = Vec::new();
    for _ in 0..2 {
        let code = federated::code(&f, &upstream, &trust, &dynamic).await;
        let response = exchange(address, code.code(), &dynamic).await;
        assert_eq!(response.status(), 200);
        issued.push(http::value(response).await);
    }
    let other = issue(&f, address).await;
    let other_claims = http::claims(&signer, &origin, hint(&other));
    let claims = http::claims(&signer, &origin, hint(&issued[0]));
    let subject = claims["sub"].as_str().unwrap();
    assert_eq!(active_pair(&mut f, subject, &dynamic).await, 4);
    upstream.close().await;
    http::stop(child).await;
    config["auth"]["oidc"] = json!([]);
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    sqlx_core::query::query("DELETE FROM public.oauth_dynamic_clients WHERE client_id=$1")
        .bind(&dynamic)
        .execute(&mut f.admin)
        .await
        .unwrap();
    let child = http::start(&path, address).await;
    empty(dispose(&c, &origin, hint(&issued[0])).await).await;
    empty(
        post(
            &c,
            &origin,
            form(&[("id_token_hint", hint(&issued[1])), ("client_id", &dynamic)]),
        )
        .await,
    )
    .await;
    assert_eq!(active_pair(&mut f, subject, &dynamic).await, 0);
    assert_eq!(
        active_pair(&mut f, other_claims["sub"].as_str().unwrap(), "web-client").await,
        2
    );
    BrokerAccessVerifier::new(&origin, AUDIENCE, Some(RESOURCE), signer.jwks(), n(8192))
        .unwrap()
        .verify(access(&issued[0]), &[], deadline())
        .unwrap();
    http::stop(child).await;
    f.close().await;
}
#[tokio::test]
#[ignore = "native HTTP and real PostgreSQL durable pair disposal COMMIT ACK withheld"]
async fn broker_oidc_end_session_commit_ack_contract() {
    let mut f = OidcFixture::new().await;
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    let signer = http::files(root.path(), &f.fixture.ca, &origin);
    let path = http::write(root.path(), &http::yaml(address, relay.port));
    let child = http::start(&path, address).await;
    let c = client();
    let tokens = issue(&f, address).await;
    let _sibling = issue(&f, address).await;
    let claims = http::claims(&signer, &origin, hint(&tokens));
    let subject = claims["sub"].as_str().unwrap();
    assert_eq!(active_pair(&mut f, subject, "web-client").await, 4);
    f.admin.execute("CREATE FUNCTION hold_end_session_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(718364); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER hold_end_session_commit AFTER UPDATE ON public.local_tokens DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hold_end_session_commit(); SELECT pg_advisory_lock(718364)").await.unwrap();
    let pending = {
        let c = c.clone();
        let origin = origin.clone();
        let hint = hint(&tokens).to_owned();
        tokio::spawn(async move { dispose(&c, &origin, &hint).await })
    };
    waiting(&mut f, "COMMIT").await;
    relay.armed.store(true, Ordering::SeqCst);
    f.admin
        .execute("SELECT pg_advisory_unlock(718364)")
        .await
        .unwrap();
    let ack = tokio::time::timeout_at(deadline().into(), relay.replies.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        active_pair(&mut f, subject, "web-client").await,
        0,
        "whole pair must be durable before withheld ACK"
    );
    let timestamps:Vec<i64>=sqlx_core::query_scalar::query_scalar("SELECT revoked_at FROM public.local_tokens WHERE oidc_subject=$1 AND client_id='web-client'").bind(subject).fetch_all(&mut f.admin).await.unwrap();
    assert_eq!(timestamps.len(), 4);
    assert!(timestamps.iter().all(|v| *v == timestamps[0]));
    ack.send(false).unwrap();
    error(pending.await.unwrap(), 503, "temporarily_unavailable").await;
    relay.armed.store(false, Ordering::SeqCst);
    relay.close().await;
    http::stop(child).await;
    f.close().await;
}

async fn lock_refresh(blocker: &mut sqlx_postgres::PgConnection, raw: &str) {
    let hash = oidc::digester()
        .token(broker_security::TokenKind::LocalRefresh, raw.as_bytes())
        .unwrap()
        .to_sql_hex();
    sqlx_core::query::query(
        "SELECT token_hash FROM public.local_tokens WHERE token_hash=$1 FOR UPDATE",
    )
    .bind(hash)
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
}
fn disposal_job(
    c: &reqwest::Client,
    origin: &str,
    t: &Value,
) -> tokio::task::JoinHandle<reqwest::Response> {
    let c = c.clone();
    let origin = origin.to_owned();
    let hint = hint(t).to_owned();
    tokio::spawn(async move { dispose(&c, &origin, &hint).await })
}
fn rotation_job(
    address: std::net::SocketAddr,
    t: &Value,
) -> tokio::task::JoinHandle<reqwest::Response> {
    let raw = refresh_token(t).to_owned();
    tokio::spawn(async move { refresh(address, &raw).await })
}
#[tokio::test]
#[ignore = "real SQL lock order, genuine P3/P4/revoke/LOCAL invalidation and finite failure outcomes"]
async fn broker_oidc_end_session_sql_outcomes() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    let signer = http::files(root.path(), &f.fixture.ca, &origin);
    let mut config: Value = serde_saphyr::from_str(&http::yaml(address, f.fixture.port)).unwrap();
    let path = http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    let c = client();
    let tokens = issue(&f, address).await;
    let _sibling = issue(&f, address).await;
    let other = issue_for(&f, address, "alice", "graphit-cli", true).await;
    let claims = http::claims(&signer, &origin, hint(&tokens));
    let subject = claims["sub"].as_str().unwrap();
    let mut blocker = f.fixture.connection().await;
    // P4 holds shared-pair authority before logout: its committed child is included.
    blocker.execute("BEGIN").await.unwrap();
    lock_refresh(&mut blocker, refresh_token(&tokens)).await;
    let rotate = rotation_job(address, &tokens);
    waiting(&mut f, "SELECT token_id,%").await;
    let logout = disposal_job(&c, &origin, &tokens);
    waiting(&mut f, "SELECT pg_advisory_xact_lock($1,%").await;
    blocker.execute("COMMIT").await.unwrap();
    let response = rotate.await.unwrap();
    assert_eq!(response.status(), 200);
    let child_tokens = http::value(response).await;
    empty(logout.await.unwrap()).await;
    assert_eq!(active_pair(&mut f, subject, "web-client").await, 0);
    assert_eq!(
        refresh(address, refresh_token(&child_tokens))
            .await
            .status(),
        400
    );
    assert_eq!(active_pair(&mut f, subject, "graphit-cli").await, 2);
    // A valid preexisting authorization code may issue a new family after logout.
    let code = local_code(&f, "alice", "web-client", true).await;
    empty(dispose(&c, &origin, hint(&tokens)).await).await;
    let response = exchange(address, code.code(), "web-client").await;
    assert_eq!(response.status(), 200);
    let later = http::value(response).await;
    assert_eq!(active_pair(&mut f, subject, "web-client").await, 2);
    // Logout gets exclusive pair first, while the genuine P4 waits behind it.
    blocker.execute("BEGIN").await.unwrap();
    blocker
        .execute("SELECT subject FROM public.local_users WHERE username='alice' FOR UPDATE")
        .await
        .unwrap();
    let logout = disposal_job(&c, &origin, &later);
    waiting(&mut f, "SELECT subject FROM public.local_users%").await;
    let rotate = rotation_job(address, &later);
    waiting(&mut f, "SELECT pg_advisory_xact_lock_shared%").await;
    blocker.execute("COMMIT").await.unwrap();
    empty(logout.await.unwrap()).await;
    assert_eq!(rotate.await.unwrap().status(), 400);
    assert_eq!(active_pair(&mut f, subject, "web-client").await, 0);
    // Family disposal takes the shared pair; logout waits and disposes other families.
    let revoke_tokens = issue(&f, address).await;
    let _sibling = issue(&f, address).await;
    blocker.execute("BEGIN").await.unwrap();
    lock_refresh(&mut blocker, refresh_token(&revoke_tokens)).await;
    let revoke = {
        let c = c.clone();
        let origin = origin.clone();
        let raw = refresh_token(&revoke_tokens).to_owned();
        tokio::spawn(async move {
            c.post(format!("{origin}/oauth/revoke"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(form(&[("token", &raw), ("client_id", "web-client")]))
                .send()
                .await
                .unwrap()
        })
    };
    waiting(&mut f, "SELECT token_id,%").await;
    let logout = disposal_job(&c, &origin, &revoke_tokens);
    waiting(&mut f, "SELECT pg_advisory_xact_lock($1,%").await;
    blocker.execute("COMMIT").await.unwrap();
    assert_eq!(revoke.await.unwrap().status(), 200);
    empty(logout.await.unwrap()).await;
    assert_eq!(active_pair(&mut f, subject, "web-client").await, 0);
    let live = issue(&f, address).await;
    // Stored corruption is DATA failure, never idempotent success.
    let original:String=sqlx_core::query_scalar::query_scalar("SELECT principal_json FROM public.local_tokens WHERE oidc_subject=$1 AND client_id='web-client' ORDER BY created_at DESC LIMIT 1")
        .bind(subject).fetch_one(&mut f.admin).await.unwrap();
    let mut corruptions = vec!["not-json".to_owned(), "x".repeat(8193)];
    let profile: Value = serde_json::from_str(&original).unwrap();
    let mut bad = profile.clone();
    bad.as_object_mut().unwrap().remove("email");
    corruptions.push(bad.to_string());
    let mut bad = profile.clone();
    bad["email"] = Value::Null;
    corruptions.push(bad.to_string());
    let mut bad = profile;
    bad["auth_method"] = json!("service-credential");
    corruptions.push(bad.to_string());
    for bad in corruptions {
        sqlx_core::query::query("UPDATE public.local_tokens SET principal_json=$1 WHERE oidc_subject=$2 AND client_id='web-client'").bind(&bad).bind(subject).execute(&mut f.admin).await.unwrap();
        error(dispose(&c, &origin, hint(&live)).await, 500, "server_error").await;
        assert_eq!(active_pair(&mut f, subject, "web-client").await, 2);
        sqlx_core::query::query("UPDATE public.local_tokens SET principal_json=$1 WHERE oidc_subject=$2 AND client_id='web-client'").bind(&original).bind(subject).execute(&mut f.admin).await.unwrap();
    }
    f.admin
        .execute("REVOKE UPDATE ON public.local_tokens FROM exchange_owner")
        .await
        .unwrap();
    error(dispose(&c, &origin, hint(&live)).await, 500, "server_error").await;
    f.admin
        .execute("GRANT UPDATE ON public.local_tokens TO exchange_owner")
        .await
        .unwrap();
    assert_eq!(active_pair(&mut f, subject, "web-client").await, 2);
    let verifier =
        BrokerAccessVerifier::new(&origin, AUDIENCE, None, signer.jwks(), n(8192)).unwrap();
    let small = BrokerAccessVerifier::new(&origin, AUDIENCE, None, signer.jwks(), n(32)).unwrap();
    assert_eq!(
        f.store
            .oidc_end_session(&f.policy, &small)
            .unwrap()
            .end_session(
                OidcEndSessionInput {
                    id_token_hint: Some(hint(&live)),
                    client_id: None
                },
                deadline()
            )
            .await
            .unwrap_err(),
        OidcTokenExchangeError::InvalidRequest
    );
    // Cancellation while waiting on an actual exclusive pair leaves the grant untouched.
    let key = serde_json::to_string(&(subject, "web-client")).unwrap();
    blocker.execute("BEGIN").await.unwrap();
    sqlx_core::query::query("SELECT pg_advisory_xact_lock(4750302,hashtext($1))")
        .bind(&key)
        .execute(&mut blocker)
        .await
        .unwrap();
    let store = f.store.clone();
    let policy = f.policy.clone();
    let service = store.oidc_end_session(&policy, &verifier).unwrap();
    {
        let pending = service.end_session(
            OidcEndSessionInput {
                id_token_hint: Some(hint(&live)),
                client_id: None,
            },
            deadline(),
        );
        tokio::pin!(pending);
        tokio::select! { _=waiting(&mut f,"SELECT pg_advisory_xact_lock($1,%")=>{},r=&mut pending=>panic!("disposal must wait: {:?}",r.err()) }
    }
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let waiting:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND query LIKE 'SELECT pg_advisory_xact_lock($1,%' AND wait_event_type='Lock'").fetch_one(&mut f.admin).await.unwrap();
        if waiting == 0 {
            break;
        }
        assert!(Instant::now() < end, "cancelled SQL must leave lock wait");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(active_pair(&mut f, subject, "web-client").await, 2);
    blocker.execute("COMMIT").await.unwrap();
    // A genuine HTTP Original deadline is finite and does not revoke the pair.
    http::stop(child).await;
    config["oidc"]["request_timeout"] = json!("1s");
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    blocker.execute("BEGIN").await.unwrap();
    sqlx_core::query::query("SELECT pg_advisory_xact_lock(4750302,hashtext($1))")
        .bind(&key)
        .execute(&mut blocker)
        .await
        .unwrap();
    error(
        dispose(&c, &origin, hint(&live)).await,
        504,
        "temporarily_unavailable",
    )
    .await;
    assert_eq!(active_pair(&mut f, subject, "web-client").await, 2);
    blocker.execute("COMMIT").await.unwrap();
    empty(dispose(&c, &origin, hint(&live)).await).await;
    http::stop(child).await;
    config["oidc"]["request_timeout"] = json!("10s");
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    // Managed LOCAL password invalidation holds user before token updates, never pair.
    let before_password = issue(&f, address).await;
    f.admin
        .execute("UPDATE public.local_users SET password_change_required=1 WHERE username='alice'")
        .await
        .unwrap();
    blocker.execute("BEGIN").await.unwrap();
    lock_refresh(&mut blocker, refresh_token(&before_password)).await;
    let invalidator = password_change_job(&f).await;
    waiting(&mut f, "%UPDATE%local_tokens%revoked_at%").await;
    let logout = disposal_job(&c, &origin, &before_password);
    waiting(&mut f, "SELECT subject FROM public.local_users%").await;
    blocker.execute("COMMIT").await.unwrap();
    tokio::time::timeout_at(deadline().into(), invalidator)
        .await
        .unwrap()
        .unwrap();
    empty(logout.await.unwrap()).await;
    assert_eq!(active_pair(&mut f, subject, "web-client").await, 0);
    BrokerAccessVerifier::new(&origin, AUDIENCE, None, signer.jwks(), n(8192))
        .unwrap()
        .verify(access(&other), &[], deadline())
        .unwrap();
    http::stop(child).await;
    blocker.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        service
            .end_session(
                OidcEndSessionInput {
                    id_token_hint: Some(hint(&live)),
                    client_id: None
                },
                deadline()
            )
            .await
            .unwrap_err(),
        OidcTokenExchangeError::Control(broker_control::ControlError::Closed)
    );
    f.close().await;
}
