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
use broker_control::{BrokerAccessIssuer, BrokerAccessTokenInput, BrokerAccessVerifier};
use browser::{BrowserIssuer, Fault};
use oidc::{AUDIENCE, OidcFixture, RESOURCE, VERIFIER};
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use sqlx_core::executor::Executor;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use support::{deadline, n};

fn form(pairs: &[(&str, &str)]) -> String {
    let mut f = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        f.append_pair(k, v);
    }
    f.finish()
}
async fn issue(f: &OidcFixture, address: std::net::SocketAddr) -> Value {
    let code = f.code(true, true).await;
    let response = http::post(
        address,
        form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "web-client"),
            ("code", code.code()),
            ("redirect_uri", federated::REDIRECT),
            ("code_verifier", VERIFIER),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    http::value(response).await
}
fn sign(issuer: &BrokerAccessIssuer, c: &Value, jti: &str, scope: &str, exp: u64) -> String {
    issuer
        .sign_access(
            BrokerAccessTokenInput {
                subject: c["sub"].as_str().unwrap(),
                client_id: c["client_id"].as_str().unwrap(),
                resource: Some(RESOURCE),
                scope,
                jti,
                issued_at: c["iat"].as_u64().unwrap(),
                expires_at: exp,
                preferred_username: None,
                name: None,
                email: None,
                organization: None,
                groups: &[],
                roles: &[],
            },
            deadline(),
        )
        .unwrap()
}
async fn expect_error(response: reqwest::Response, status: u16, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    if status == 401 {
        assert!(
            response.headers()["www-authenticate"]
                .to_str()
                .unwrap()
                .contains("Bearer")
        );
    }
    assert_eq!(http::value(response).await, json!({"error":code}));
}

async fn inspect(
    client: &reqwest::Client,
    origin: &str,
    authority: &str,
    target: Option<&str>,
) -> reqwest::Response {
    let pairs: Vec<_> = target.into_iter().map(|value| ("token", value)).collect();
    client
        .post(format!("{origin}/oauth/introspect"))
        .bearer_auth(authority)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&pairs))
        .send()
        .await
        .unwrap()
}
async fn active(response: reqwest::Response, claims: &Value, scope: Option<&str>) {
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    let mut expected = json!({"active":true,"client_id":claims["client_id"],"exp":claims["exp"]});
    if let Some(scope) = scope {
        expected["scope"] = json!(scope);
    }
    assert_eq!(http::value(response).await, expected);
}
async fn inactive(response: reqwest::Response) {
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(http::value(response).await, json!({"active":false}));
}
async fn issue_for(
    f: &OidcFixture,
    address: std::net::SocketAddr,
    username: &str,
    dynamic: bool,
) -> Value {
    let code = f.code_for(username, dynamic, true).await;
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        (
            "client_id",
            if dynamic { "web-client" } else { "graphit-cli" },
        ),
        ("code", code.code()),
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
    let response = http::post(address, form(&pairs), None).await;
    assert_eq!(response.status(), 200);
    http::value(response).await
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

#[tokio::test]
#[ignore = "native HTTP, genuine LOCAL subjects/clients and PostgreSQL TLS"]
async fn broker_oidc_introspection_local_http_contract() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    let signer = http::files(root.path(), &f.fixture.ca, &origin);
    let path = http::write(root.path(), &http::yaml(address, f.fixture.port));
    let child = http::start(&path, address).await;
    let client = reqwest::Client::new();
    let authority_tokens = issue(&f, address).await;
    let target_tokens = issue(&f, address).await;
    let authority = authority_tokens["access_token"].as_str().unwrap();
    let raw = target_tokens["access_token"].as_str().unwrap();
    let claims = http::claims(&signer, &origin, raw);
    let scope = claims["scope"].as_str().unwrap();
    active(
        inspect(&client, &origin, authority, Some(raw)).await,
        &claims,
        Some(scope),
    )
    .await;
    active(
        inspect(&client, &origin, raw, Some(authority)).await,
        &http::claims(&signer, &origin, authority),
        Some(scope),
    )
    .await;
    let cors = client
        .post(format!("{origin}/oauth/introspect"))
        .bearer_auth(authority)
        .header("origin", "https://ui.example")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[("token", raw)]))
        .send()
        .await
        .unwrap();
    assert_eq!(
        cors.headers()["access-control-allow-origin"],
        "https://ui.example"
    );
    assert!(
        !cors
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    active(cors, &claims, Some(scope)).await;
    let denied = client
        .post(format!("{origin}/oauth/introspect"))
        .bearer_auth(authority)
        .header("origin", "https://unlisted.example")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[("token", raw)]))
        .send()
        .await
        .unwrap();
    assert!(!denied.headers().contains_key("access-control-allow-origin"));
    inactive(inspect(&client, &origin, authority, None).await).await;
    for invalid in [
        "",
        "unknown",
        target_tokens["refresh_token"].as_str().unwrap(),
        target_tokens["id_token"].as_str().unwrap(),
    ] {
        inactive(inspect(&client, &origin, authority, Some(invalid)).await).await;
    }
    for header in [
        None,
        Some("Basic d2ViLWNsaWVudDo=".to_owned()),
        Some("Bearer invalid".to_owned()),
        Some(format!(
            "Bearer {}",
            authority_tokens["id_token"].as_str().unwrap()
        )),
        Some(format!(
            "Bearer {}",
            authority_tokens["refresh_token"].as_str().unwrap()
        )),
    ] {
        let mut request = client
            .post(format!("{origin}/oauth/introspect"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("token=unknown");
        if let Some(header) = header {
            request = request.header("authorization", header);
        }
        expect_error(request.send().await.unwrap(), 401, "invalid_token").await;
    }
    expect_error(
        client
            .post(format!("{origin}/oauth/introspect"))
            .bearer_auth(authority)
            .header("authorization", format!("Bearer {authority}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("token=unknown")
            .send()
            .await
            .unwrap(),
        401,
        "invalid_token",
    )
    .await;
    for (suffix, content, body) in [
        ("", "application/json", "{}"),
        ("?token=unknown", "application/x-www-form-urlencoded", ""),
        ("", "application/x-www-form-urlencoded", "token=x&token=y"),
        (
            "",
            "application/x-www-form-urlencoded",
            "token_type_hint=x&token_type_hint=y",
        ),
        ("", "application/x-www-form-urlencoded", "token=%FF"),
    ] {
        expect_error(
            client
                .post(format!("{origin}/oauth/introspect{suffix}"))
                .bearer_auth(authority)
                .header("content-type", content)
                .body(body)
                .send()
                .await
                .unwrap(),
            400,
            "invalid_request",
        )
        .await;
    }
    for body in [
        format!("token={}", "x".repeat(8193)),
        format!("ignored={}", "x".repeat(65537)),
    ] {
        expect_error(
            client
                .post(format!("{origin}/oauth/introspect"))
                .bearer_auth(authority)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await
                .unwrap(),
            400,
            "invalid_request",
        )
        .await;
    }
    for method in [
        reqwest::Method::GET,
        reqwest::Method::HEAD,
        reqwest::Method::PUT,
    ] {
        let response = client
            .request(method, format!("{origin}/oauth/introspect"))
            .bearer_auth(authority)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 405);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let hinted = client
        .post(format!("{origin}/oauth/introspect"))
        .bearer_auth(authority)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("token", raw),
            ("token_type_hint", "refresh_token"),
        ]))
        .send()
        .await
        .unwrap();
    active(hinted, &claims, Some(scope)).await;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    let expiring = sign(
        &signer,
        &claims,
        claims["jti"].as_str().unwrap(),
        scope,
        expires,
    );
    sqlx_core::query::query("UPDATE public.local_tokens SET expires_at=$1 WHERE token_id=$2")
        .bind(i64::try_from(expires * 1_000_000).unwrap())
        .bind(claims["jti"].as_str().unwrap())
        .execute(&mut f.admin)
        .await
        .unwrap();
    let mut expiring_claims = claims.clone();
    expiring_claims["exp"] = json!(expires);
    active(
        inspect(&client, &origin, authority, Some(&expiring)).await,
        &expiring_claims,
        Some(scope),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    inactive(inspect(&client, &origin, authority, Some(&expiring)).await).await;
    expect_error(
        inspect(&client, &origin, &expiring, Some(raw)).await,
        401,
        "invalid_token",
    )
    .await;
    sqlx_core::query::query("UPDATE public.local_tokens SET expires_at=$1 WHERE token_id=$2")
        .bind(i64::try_from(claims["exp"].as_u64().unwrap() * 1_000_000).unwrap())
        .bind(claims["jti"].as_str().unwrap())
        .execute(&mut f.admin)
        .await
        .unwrap();
    let mut missing_jti = claims["jti"].as_str().unwrap().as_bytes().to_vec();
    let at = missing_jti.len() - 3;
    missing_jti[at] = if missing_jti[at] == b'a' { b'b' } else { b'a' };
    let missing_jti = String::from_utf8(missing_jti).unwrap();
    assert!(broker_security::validate_local_auth_challenge(&missing_jti).is_ok());
    let missing = sign(
        &signer,
        &claims,
        &missing_jti,
        scope,
        claims["exp"].as_u64().unwrap(),
    );
    inactive(inspect(&client, &origin, authority, Some(&missing)).await).await;
    // Both negative scope boundaries use genuinely completed password/code producers.
    let other_client = issue_for(&f, address, "alice", false).await;
    inactive(
        inspect(
            &client,
            &origin,
            authority,
            other_client["access_token"].as_str(),
        )
        .await,
    )
    .await;
    let hash = f.engine.hash(oidc::PASSWORD, deadline()).await.unwrap();
    sqlx_core::query::query("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('bob','bob-subject','human',$1,'Bob','','','[]',1,0,1,$2,$2)")
        .bind(hash.as_str()).bind(oidc::micros()).execute(&mut f.admin).await.unwrap();
    let other_subject = issue_for(&f, address, "bob", true).await;
    let bob = other_subject["access_token"].as_str().unwrap();
    inactive(inspect(&client, &origin, authority, Some(bob)).await).await;
    inactive(inspect(&client, &origin, bob, Some(raw)).await).await;
    let untouched: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT last_used_at FROM public.local_tokens WHERE token_id=$1",
    )
    .bind(http::claims(&signer, &origin, bob)["jti"].as_str().unwrap())
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert!(
        untouched.is_none(),
        "out-of-subject token must not acquire audit usage"
    );
    // LOCAL profile and DCR state are not introspection gates; access row state is.
    f.admin.execute("UPDATE public.local_users SET enabled=0,revision=revision+1 WHERE username='alice'; DELETE FROM public.oauth_dynamic_clients WHERE client_id='web-client'").await.unwrap();
    active(
        inspect(&client, &origin, authority, Some(raw)).await,
        &claims,
        Some(scope),
    )
    .await;
    // A valid empty scope has no extra openid requirement and omits the wire scope field.
    sqlx_core::query::query("UPDATE public.local_tokens SET scopes_json='[]' WHERE token_id=$1")
        .bind(claims["jti"].as_str().unwrap())
        .execute(&mut f.admin)
        .await
        .unwrap();
    let empty_scope = sign(
        &signer,
        &claims,
        claims["jti"].as_str().unwrap(),
        "",
        claims["exp"].as_u64().unwrap(),
    );
    active(
        inspect(&client, &origin, authority, Some(&empty_scope)).await,
        &claims,
        None,
    )
    .await;
    sqlx_core::query::query("UPDATE public.local_tokens SET revoked_at=$1 WHERE token_id=$2")
        .bind(oidc::micros())
        .bind(claims["jti"].as_str().unwrap())
        .execute(&mut f.admin)
        .await
        .unwrap();
    inactive(inspect(&client, &origin, authority, Some(&empty_scope)).await).await;
    let verifier =
        BrokerAccessVerifier::new(&origin, AUDIENCE, Some(RESOURCE), signer.jwks(), n(16384))
            .unwrap();
    assert!(
        verifier.verify(&empty_scope, &[], deadline()).is_ok(),
        "explicit SQL revocation does not alter local JWT validity"
    );
    sqlx_core::query::query("UPDATE public.local_tokens SET revoked_at=$1 WHERE token_id=$2")
        .bind(oidc::micros())
        .bind(
            http::claims(&signer, &origin, authority)["jti"]
                .as_str()
                .unwrap(),
        )
        .execute(&mut f.admin)
        .await
        .unwrap();
    expect_error(
        inspect(&client, &origin, authority, Some(raw)).await,
        401,
        "invalid_token",
    )
    .await;
    http::stop(child).await;
    let mut config: Value = serde_saphyr::from_str(&http::yaml(address, f.fixture.port)).unwrap();
    config["oidc"]["enabled"] = json!(false);
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    assert_eq!(
        inspect(&client, &origin, authority, Some(raw))
            .await
            .status(),
        404
    );
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
#[tokio::test]
#[ignore = "native executable, real HTTPS H1, code exchange and PostgreSQL TLS"]
async fn broker_oidc_introspection_federated_http_contract() {
    let f = OidcFixture::new().await;
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
    let dynamic = federated::registered(&f).await;
    let code = federated::code(&f, &upstream, &trust, &dynamic).await;
    let issued = http::post(
        address,
        form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &dynamic),
            ("code", code.code()),
            ("redirect_uri", federated::REDIRECT),
            ("code_verifier", VERIFIER),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await;
    assert_eq!(issued.status(), 200);
    let tokens = http::value(issued).await;
    let raw = tokens["access_token"].as_str().unwrap();
    let claims = http::claims(&signer, &origin, raw);
    // No current trust lookup or upstream request belongs to explicit introspection.
    upstream.close().await;
    let client = reqwest::Client::new();
    let response = inspect(&client, &origin, raw, Some(raw)).await;
    assert_eq!(response.status(), 200);
    let data = http::value(response).await;
    assert_eq!(
        data,
        json!({"active":true,"client_id":claims["client_id"],"exp":claims["exp"],"scope":claims["scope"]})
    );
    http::stop(child).await;
    config["auth"]["oidc"][0]["claims"]["roles"] = json!("different_roles");
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    active(
        inspect(&client, &origin, raw, Some(raw)).await,
        &claims,
        claims["scope"].as_str(),
    )
    .await;
    http::stop(child).await;
    config["auth"]["oidc"] = json!([]);
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    active(
        inspect(&client, &origin, raw, Some(raw)).await,
        &claims,
        claims["scope"].as_str(),
    )
    .await;
    http::stop(child).await;
    f.close().await;
}

async fn waiting(f: &mut OidcFixture, query: &str) {
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let observed: Option<String> = sqlx_core::query_scalar::query_scalar(
            "SELECT json_build_object('query_bytes',OCTET_LENGTH(query),'track_bytes',pg_size_bytes(current_setting('track_activity_query_size')),'suffix_visible',query LIKE '%FOR UPDATE')::text FROM pg_stat_activity WHERE usename='exchange_owner' AND query LIKE $1 AND wait_event_type='Lock' LIMIT 1"
        ).bind(query).fetch_optional(&mut f.admin).await.unwrap();
        if let Some(observed) = observed {
            if query == "SELECT token_hash,%" {
                // The SQL observation must survive pg_stat_activity query truncation.
                eprintln!("bounded SQL lock observation: {observed}");
            }
            return;
        }
        assert!(
            Instant::now() < end,
            "real introspection SQL did not reach lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
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
#[ignore = "native HTTP, real SQL caps/permissions/locks/cancel and same-family P4 writers"]
async fn broker_oidc_introspection_sql_outcomes() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    let signer = http::files(root.path(), &f.fixture.ca, &origin);
    let path = http::write(root.path(), &http::yaml(address, f.fixture.port));
    let child = http::start(&path, address).await;
    let client = reqwest::Client::new();
    let authority_tokens = issue(&f, address).await;
    let target_tokens = issue(&f, address).await;
    let authority = authority_tokens["access_token"].as_str().unwrap();
    let target = target_tokens["access_token"].as_str().unwrap();
    let claims = http::claims(&signer, &origin, target);
    let jti = claims["jti"].as_str().unwrap();
    let principal: String = sqlx_core::query_scalar::query_scalar(
        "SELECT principal_json FROM public.local_tokens WHERE token_id=$1",
    )
    .bind(jti)
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    for malformed in ["[]".to_owned(), "x".repeat(8193)] {
        sqlx_core::query::query(
            "UPDATE public.local_tokens SET principal_json=$1 WHERE token_id=$2",
        )
        .bind(malformed)
        .bind(jti)
        .execute(&mut f.admin)
        .await
        .unwrap();
        expect_error(
            inspect(&client, &origin, authority, Some(target)).await,
            500,
            "server_error",
        )
        .await;
    }
    sqlx_core::query::query("UPDATE public.local_tokens SET principal_json=$1 WHERE token_id=$2")
        .bind(principal)
        .bind(jti)
        .execute(&mut f.admin)
        .await
        .unwrap();
    for field in [
        "oidc_subject",
        "subject",
        "client_id",
        "audience",
        "resource",
        "scopes_json",
    ] {
        let previous: String =
            sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(format!(
                "SELECT {field} FROM public.local_tokens WHERE token_id=$1"
            )))
            .bind(jti)
            .fetch_one(&mut f.admin)
            .await
            .unwrap();
        let changed = if field == "scopes_json" {
            r#"["profile"]"#
        } else {
            "mismatched"
        };
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "UPDATE public.local_tokens SET {field}=$1 WHERE token_id=$2"
        )))
        .bind(changed)
        .bind(jti)
        .execute(&mut f.admin)
        .await
        .unwrap();
        inactive(inspect(&client, &origin, authority, Some(target)).await).await;
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "UPDATE public.local_tokens SET {field}=$1 WHERE token_id=$2"
        )))
        .bind(previous)
        .bind(jti)
        .execute(&mut f.admin)
        .await
        .unwrap();
    }
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=expires_at-1 WHERE token_id=$1",
    )
    .bind(jti)
    .execute(&mut f.admin)
    .await
    .unwrap();
    inactive(inspect(&client, &origin, authority, Some(target)).await).await;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=expires_at+1 WHERE token_id=$1",
    )
    .bind(jti)
    .execute(&mut f.admin)
    .await
    .unwrap();
    f.admin
        .execute("ALTER TABLE public.local_tokens OWNER TO postgres")
        .await
        .unwrap();
    expect_error(
        inspect(&client, &origin, authority, Some(target)).await,
        500,
        "server_error",
    )
    .await;
    f.admin
        .execute("ALTER TABLE public.local_tokens OWNER TO exchange_owner")
        .await
        .unwrap();
    let mut blocker = f.fixture.connection().await;
    let mut tx = blocker.begin().await.unwrap();
    sqlx_core::query::query(
        "SELECT token_id FROM public.local_tokens WHERE token_id=$1 FOR UPDATE",
    )
    .bind(jti)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let pending = {
        let client = client.clone();
        let origin = origin.clone();
        let authority = authority.to_owned();
        let target = target.to_owned();
        tokio::spawn(async move { inspect(&client, &origin, &authority, Some(&target)).await })
    };
    waiting(&mut f, "SELECT token_hash,%").await;
    // Reversed authority is locked elsewhere; a snapshot authority must not wait for it.
    active(
        inspect(&client, &origin, target, Some(authority)).await,
        &http::claims(&signer, &origin, authority),
        claims["scope"].as_str(),
    )
    .await;
    expect_error(pending.await.unwrap(), 504, "temporarily_unavailable").await;
    tx.rollback().await.unwrap();
    let unused: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT last_used_at FROM public.local_tokens WHERE token_id=$1",
    )
    .bind(jti)
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert!(
        unused.is_none(),
        "timed-out target did not confirm audit usage"
    );
    let mut tx = blocker.begin().await.unwrap();
    sqlx_core::query::query(
        "SELECT token_id FROM public.local_tokens WHERE token_id=$1 FOR UPDATE",
    )
    .bind(jti)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let verifier = std::sync::Arc::new(
        BrokerAccessVerifier::new(&origin, AUDIENCE, Some(RESOURCE), signer.jwks(), n(16384))
            .unwrap(),
    );
    let pending = {
        let store = f.store.clone();
        let policy = f.policy.clone();
        let verifier = verifier.clone();
        let authority = authority.to_owned();
        let target = target.to_owned();
        tokio::spawn(async move {
            store
                .oidc_introspection(&policy, &verifier)
                .unwrap()
                .introspect(&authority, Some(&target), deadline())
                .await
        })
    };
    waiting(&mut f, "SELECT token_hash,%").await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    tx.rollback().await.unwrap();
    active(
        inspect(&client, &origin, authority, Some(target)).await,
        &claims,
        claims["scope"].as_str(),
    )
    .await;
    // Genuine P4 generations of one family contend with the actual family revocation writers.
    for writer_kind in 0..3 {
        let reuse = writer_kind == 1;
        let first = issue(&f, address).await;
        let rotated = refresh(address, first["refresh_token"].as_str().unwrap()).await;
        assert_eq!(rotated.status(), 200);
        let second = http::value(rotated).await;
        let a = first["access_token"].as_str().unwrap();
        let b = second["access_token"].as_str().unwrap();
        let a_claims = http::claims(&signer, &origin, a);
        let b_claims = http::claims(&signer, &origin, b);
        let family_a: String = sqlx_core::query_scalar::query_scalar(
            "SELECT family_id FROM public.local_tokens WHERE token_id=$1",
        )
        .bind(a_claims["jti"].as_str().unwrap())
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        let family_b: String = sqlx_core::query_scalar::query_scalar(
            "SELECT family_id FROM public.local_tokens WHERE token_id=$1",
        )
        .bind(b_claims["jti"].as_str().unwrap())
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        assert_eq!(family_a, family_b);
        let mut tx = blocker.begin().await.unwrap();
        sqlx_core::query::query(
            "SELECT token_id FROM public.local_tokens WHERE token_id=$1 FOR UPDATE",
        )
        .bind(b_claims["jti"].as_str().unwrap())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        let writer = if writer_kind == 2 {
            f.admin.execute("UPDATE public.local_users SET password_change_required=1 WHERE username='alice'").await.unwrap();
            password_change_job(&f).await
        } else {
            let client = client.clone();
            let origin = origin.clone();
            let token = if reuse {
                first["refresh_token"].as_str().unwrap()
            } else {
                second["refresh_token"].as_str().unwrap()
            }
            .to_owned();
            tokio::spawn(async move {
                let response = if reuse {
                    refresh(address, &token).await
                } else {
                    client
                        .post(format!("{origin}/oauth/revoke"))
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(form(&[("token", &token), ("client_id", "web-client")]))
                        .send()
                        .await
                        .unwrap()
                };
                assert_eq!(response.status(), if reuse { 400 } else { 200 });
            })
        };
        waiting(&mut f, "%UPDATE%local_tokens%revoked_at%").await;
        let inspection = {
            let client = client.clone();
            let origin = origin.clone();
            let a = a.to_owned();
            let b = b.to_owned();
            tokio::spawn(async move { inspect(&client, &origin, &a, Some(&b)).await })
        };
        waiting(&mut f, "SELECT token_hash,%").await;
        tx.rollback().await.unwrap();
        tokio::time::timeout_at(deadline().into(), writer)
            .await
            .unwrap()
            .unwrap();
        inactive(
            tokio::time::timeout_at(deadline().into(), inspection)
                .await
                .unwrap()
                .unwrap(),
        )
        .await;
        let unused: Option<i64> = sqlx_core::query_scalar::query_scalar(
            "SELECT last_used_at FROM public.local_tokens WHERE token_id=$1",
        )
        .bind(b_claims["jti"].as_str().unwrap())
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        assert!(
            unused.is_none(),
            "family revocation winner must not confirm target usage"
        );
    }
    blocker.close().await.unwrap();
    http::stop(child).await;
    f.close().await;
}
#[tokio::test]
#[ignore = "native HTTP and real PostgreSQL durable last_used COMMIT ACK withheld"]
async fn broker_oidc_introspection_commit_ack_contract() {
    let mut f = OidcFixture::new().await;
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    let issuer = http::files(root.path(), &f.fixture.ca, &origin);
    let path = http::write(root.path(), &http::yaml(address, relay.port));
    let child = http::start(&path, address).await;
    let client = reqwest::Client::new();
    let tokens = issue(&f, address).await;
    let raw = tokens["access_token"].as_str().unwrap();
    let jti = http::claims(&issuer, &origin, raw)["jti"]
        .as_str()
        .unwrap()
        .to_owned();
    f.admin.execute("CREATE FUNCTION hold_introspection_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(718363); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER hold_introspection_commit AFTER UPDATE ON public.local_tokens DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hold_introspection_commit(); SELECT pg_advisory_lock(718363)").await.unwrap();
    let pending = {
        let client = client.clone();
        let origin = origin.clone();
        let raw = raw.to_owned();
        tokio::spawn(async move { inspect(&client, &origin, &raw, Some(&raw)).await })
    };
    waiting(&mut f, "COMMIT").await;
    relay.armed.store(true, Ordering::SeqCst);
    f.admin
        .execute("SELECT pg_advisory_unlock(718363)")
        .await
        .unwrap();
    let ack = tokio::time::timeout_at(deadline().into(), relay.replies.recv())
        .await
        .unwrap()
        .unwrap();
    let used: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT last_used_at FROM public.local_tokens WHERE token_id=$1",
    )
    .bind(jti)
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert!(
        used.is_some_and(|v| v > 0),
        "last_used must be durable before withholding ACK"
    );
    ack.send(false).unwrap();
    expect_error(pending.await.unwrap(), 503, "temporarily_unavailable").await;
    relay.armed.store(false, Ordering::SeqCst);
    relay.close().await;
    http::stop(child).await;
    f.close().await;
}
