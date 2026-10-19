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
async fn profile(client: &reqwest::Client, origin: &str, raw: &str) -> reqwest::Response {
    client
        .get(format!("{origin}/oauth/userinfo"))
        .bearer_auth(raw)
        .send()
        .await
        .unwrap()
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

#[tokio::test]
#[ignore = "native executable, genuine LOCAL code/access tokens and PostgreSQL TLS"]
async fn broker_oidc_userinfo_local_http_contract() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    let issuer = http::files(root.path(), &f.fixture.ca, &origin);
    // UserInfo OP accepts this resource although the generic API verifier is bound elsewhere.
    let config = http::yaml(address, f.fixture.port).replace(
        "  audience: graphit-broker\n",
        "  audience: graphit-broker\n  resource: https://api.example/other\n",
    );
    let path = http::write(root.path(), &config);
    let child = http::start(&path, address).await;
    let client = reqwest::Client::new();
    let tokens = issue(&f, address).await;
    let raw = tokens["access_token"].as_str().unwrap();
    let claims = http::claims(&issuer, &origin, raw);
    let id = http::claims(&issuer, &origin, tokens["id_token"].as_str().unwrap());
    let jti = claims["jti"].as_str().unwrap();
    let verify =
        BrokerAccessVerifier::new(&origin, AUDIENCE, Some(RESOURCE), issuer.jwks(), n(16384))
            .unwrap();
    let metadata = http::value(
        client
            .get(format!("{origin}/.well-known/openid-configuration"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        metadata["userinfo_endpoint"],
        format!("{origin}/oauth/userinfo")
    );
    assert_eq!(
        metadata["introspection_endpoint"],
        format!("{origin}/oauth/introspect")
    );
    assert_eq!(
        metadata["introspection_endpoint_auth_methods_supported"],
        json!(["Bearer"])
    );
    let response = profile(&client, &origin, raw).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let expected = http::value(response).await;
    assert_eq!(
        expected,
        json!({"sub":id["sub"],"preferred_username":"alice","name":"Alice","email":"alice@example.invalid","organization":"org","groups":["engineering"],"roles":["user"]})
    );
    let used: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT last_used_at FROM public.local_tokens WHERE token_id=$1",
    )
    .bind(jti)
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert!(used.is_some_and(|v| v > 0));
    for response in [
        client
            .post(format!("{origin}/oauth/userinfo"))
            .bearer_auth(raw)
            .send()
            .await
            .unwrap(),
        client
            .get(format!(
                "{origin}/oauth/userinfo?{}",
                form(&[("access_token", raw)])
            ))
            .send()
            .await
            .unwrap(),
        client
            .post(format!("{origin}/oauth/userinfo"))
            .header(
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .body(form(&[("access_token", raw)]))
            .send()
            .await
            .unwrap(),
    ] {
        assert_eq!(response.status(), 200);
        assert_eq!(http::value(response).await, expected);
    }
    sqlx_core::query::query("UPDATE public.local_users SET name='Current Name',email='',organization='',teams_json='[]' WHERE subject='alice-subject'").execute(&mut f.admin).await.unwrap();
    f.admin.execute("INSERT INTO public.roles(name,created_at) VALUES('profile-role',1); INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','profile-role',1)").await.unwrap();
    let current = http::value(profile(&client, &origin, raw).await).await;
    assert_eq!(current["name"], "Current Name");
    assert_eq!(current["roles"], json!(["profile-role", "user"]));
    for absent in ["email", "organization", "groups"] {
        assert!(current.get(absent).is_none());
    }
    let missing = client
        .get(format!("{origin}/oauth/userinfo"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 401);
    assert_eq!(
        missing.headers()["www-authenticate"],
        "Bearer realm=\"graphit-broker\""
    );
    for request in [
        client.get(format!(
            "{origin}/oauth/userinfo?access_token=x&access_token=x"
        )),
        client
            .get(format!("{origin}/oauth/userinfo?access_token=x"))
            .bearer_auth(raw),
        client
            .get(format!("{origin}/oauth/userinfo"))
            .header("authorization", format!("Bearer {raw}"))
            .header("authorization", format!("Bearer {raw}")),
        client
            .post(format!("{origin}/oauth/userinfo"))
            .bearer_auth(raw)
            .header("content-type", "application/x-www-form-urlencoded")
            .body("access_token=x"),
        client
            .post(format!("{origin}/oauth/userinfo"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("access_token=x&access_token=y"),
        client
            .post(format!("{origin}/oauth/userinfo"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("access_token=%FF"),
        client
            .post(format!("{origin}/oauth/userinfo"))
            .header("content-type", "application/json")
            .body("{}"),
        client
            .get(format!("{origin}/oauth/userinfo"))
            .bearer_auth(raw)
            .body("access_token=x"),
        client
            .post(format!("{origin}/oauth/userinfo"))
            .bearer_auth(raw)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(vec![b'a'; 32769]),
    ] {
        expect_error(request.send().await.unwrap(), 400, "invalid_request").await;
    }
    expect_error(
        client
            .get(format!(
                "{origin}/oauth/userinfo?{}",
                form(&[("access_token", raw)])
            ))
            .header("authorization", "Basic eDp5")
            .send()
            .await
            .unwrap(),
        401,
        "invalid_token",
    )
    .await;
    let exp = claims["exp"].as_u64().unwrap();
    for bad in [
        tokens["id_token"].as_str().unwrap().to_owned(),
        tokens["refresh_token"].as_str().unwrap().to_owned(),
        format!("{raw}x"),
        sign(
            &issuer,
            &claims,
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "openid",
            exp,
        ),
        sign(&issuer, &claims, jti, "openid", exp + 1),
    ] {
        expect_error(profile(&client, &origin, &bad).await, 401, "invalid_token").await;
    }
    for (change, restore) in [
        ("resource=''", "resource='https://broker.example/v1'"),
        ("expires_at=expires_at+1", "expires_at=expires_at-1"),
        ("client_id='other-client'", "client_id='web-client'"),
    ] {
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "UPDATE public.local_tokens SET {change} WHERE token_id=$1"
        )))
        .bind(jti)
        .execute(&mut f.admin)
        .await
        .unwrap();
        expect_error(profile(&client, &origin, raw).await, 401, "invalid_token").await;
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "UPDATE public.local_tokens SET {restore} WHERE token_id=$1"
        )))
        .bind(jti)
        .execute(&mut f.admin)
        .await
        .unwrap();
    }
    // Active profile semantics have no additional openid/profile/email filter.
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET scopes_json='[\"profile\"]' WHERE token_id=$1",
    )
    .bind(jti)
    .execute(&mut f.admin)
    .await
    .unwrap();
    let narrow = sign(&issuer, &claims, jti, "profile", exp);
    f.admin.execute("UPDATE public.local_users SET email='current@example.invalid' WHERE subject='alice-subject'").await.unwrap();
    let narrow_response = profile(&client, &origin, &narrow).await;
    assert_eq!(narrow_response.status(), 200);
    let narrow_profile = http::value(narrow_response).await;
    assert_eq!(narrow_profile["email"], "current@example.invalid");
    assert_eq!(narrow_profile["roles"], json!(["profile-role", "user"]));
    sqlx_core::query::query("UPDATE public.local_tokens SET scopes_json=$1 WHERE token_id=$2")
        .bind(
            serde_json::to_string(
                &claims["scope"]
                    .as_str()
                    .unwrap()
                    .split(' ')
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        )
        .bind(jti)
        .execute(&mut f.admin)
        .await
        .unwrap();
    let cors = client
        .get(format!("{origin}/oauth/userinfo"))
        .bearer_auth(raw)
        .header("origin", "https://ui.example")
        .send()
        .await
        .unwrap();
    assert_eq!(cors.status(), 200);
    assert_eq!(
        cors.headers()["access-control-allow-origin"],
        "https://ui.example"
    );
    assert!(
        !cors
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    let denied = client
        .get(format!("{origin}/oauth/userinfo"))
        .bearer_auth(raw)
        .header("origin", "https://unlisted.example")
        .send()
        .await
        .unwrap();
    assert!(!denied.headers().contains_key("access-control-allow-origin"));
    for mutation in ["enabled=0", "enabled=1,revision=2"] {
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "UPDATE public.local_users SET {mutation} WHERE subject='alice-subject'"
        )))
        .execute(&mut f.admin)
        .await
        .unwrap();
        expect_error(profile(&client, &origin, raw).await, 401, "invalid_token").await;
        assert!(verify.verify(raw, &[], deadline()).is_ok());
    }
    f.admin.execute("UPDATE public.local_users SET enabled=1,revision=1 WHERE subject='alice-subject'; DELETE FROM public.oauth_dynamic_clients WHERE client_id='web-client'").await.unwrap();
    assert_eq!(profile(&client, &origin, raw).await.status(), 200);
    sqlx_core::query::query("UPDATE public.local_tokens SET revoked_at=$1 WHERE token_id=$2")
        .bind(oidc::micros())
        .bind(jti)
        .execute(&mut f.admin)
        .await
        .unwrap();
    expect_error(profile(&client, &origin, raw).await, 401, "invalid_token").await;
    assert!(verify.verify(raw, &[], deadline()).is_ok());
    http::stop(child).await;
    let disabled = config.replace(
        "  enabled: true\n  cli_client_id:",
        "  enabled: false\n  cli_client_id:",
    );
    http::write(root.path(), &disabled);
    let child = http::start(&path, address).await;
    assert_eq!(profile(&client, &origin, raw).await.status(), 404);
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
async fn broker_oidc_userinfo_federated_http_contract() {
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
    // Profile cannot contact this upstream anymore; only configured trust is needed.
    upstream.close().await;
    let client = reqwest::Client::new();
    let response = profile(&client, &origin, raw).await;
    assert_eq!(response.status(), 200);
    let data = http::value(response).await;
    assert_eq!(data["sub"], claims["sub"]);
    assert_eq!(data["roles"], json!(["profile-role", "user"]));
    assert_ne!(data["sub"], "federated-subject");
    http::stop(child).await;
    config["auth"]["oidc"][0]["claims"]["roles"] = json!("different_roles");
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    expect_error(profile(&client, &origin, raw).await, 401, "invalid_token").await;
    http::stop(child).await;
    config["auth"]["oidc"] = json!([]);
    http::write(root.path(), &serde_saphyr::to_string(&config).unwrap());
    let child = http::start(&path, address).await;
    expect_error(profile(&client, &origin, raw).await, 401, "invalid_token").await;
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
        let blocked:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='exchange_owner' AND query LIKE $1 AND wait_event_type='Lock')")
            .bind(query).fetch_one(&mut f.admin).await.unwrap();
        if blocked {
            return;
        }
        assert!(Instant::now() < end, "real UserInfo SQL did not reach lock");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test]
#[ignore = "native HTTP and real SQL failure, deadline and cancelled transaction"]
async fn broker_oidc_userinfo_sql_outcomes() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    let issuer = http::files(root.path(), &f.fixture.ca, &origin);
    let config =
        http::yaml(address, f.fixture.port).replace("request_timeout: 10s", "request_timeout: 1s");
    let path = http::write(root.path(), &config);
    let child = http::start(&path, address).await;
    let tokens = issue(&f, address).await;
    let raw = tokens["access_token"].as_str().unwrap();
    let jti = http::claims(&issuer, &origin, raw)["jti"]
        .as_str()
        .unwrap()
        .to_owned();
    let original: String = sqlx_core::query_scalar::query_scalar(
        "SELECT principal_json FROM public.local_tokens WHERE token_id=$1",
    )
    .bind(&jti)
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    let client = reqwest::Client::new();
    for malformed in ["[]".to_owned(), "x".repeat(8193)] {
        sqlx_core::query::query(
            "UPDATE public.local_tokens SET principal_json=$1 WHERE token_id=$2",
        )
        .bind(malformed)
        .bind(&jti)
        .execute(&mut f.admin)
        .await
        .unwrap();
        expect_error(profile(&client, &origin, raw).await, 500, "server_error").await;
    }
    sqlx_core::query::query("UPDATE public.local_tokens SET principal_json=$1 WHERE token_id=$2")
        .bind(original)
        .bind(&jti)
        .execute(&mut f.admin)
        .await
        .unwrap();
    f.admin
        .execute("ALTER TABLE public.local_tokens OWNER TO postgres")
        .await
        .unwrap();
    expect_error(profile(&client, &origin, raw).await, 500, "server_error").await;
    f.admin
        .execute("ALTER TABLE public.local_tokens OWNER TO exchange_owner")
        .await
        .unwrap();
    let mut blocker = f.fixture.connection().await;
    let mut tx = blocker.begin().await.unwrap();
    sqlx_core::query::query(
        "SELECT token_id FROM public.local_tokens WHERE token_id=$1 FOR UPDATE",
    )
    .bind(&jti)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let head = client
        .head(format!("{origin}/oauth/userinfo"))
        .bearer_auth(raw)
        .timeout(Duration::from_millis(750))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 405);
    assert_eq!(head.headers()["cache-control"], "no-store");
    let pending = {
        let client = client.clone();
        let origin = origin.clone();
        let raw = raw.to_owned();
        tokio::spawn(async move { profile(&client, &origin, &raw).await })
    };
    waiting(&mut f, "SELECT token_hash,%").await;
    expect_error(pending.await.unwrap(), 504, "temporarily_unavailable").await;
    tx.rollback().await.unwrap();
    // Drop an actual in-flight producer while SQL waits; its connection guard must release.
    let mut tx = blocker.begin().await.unwrap();
    sqlx_core::query::query(
        "SELECT token_id FROM public.local_tokens WHERE token_id=$1 FOR UPDATE",
    )
    .bind(&jti)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let verifier = std::sync::Arc::new(
        BrokerAccessVerifier::new(&origin, AUDIENCE, Some(RESOURCE), issuer.jwks(), n(16384))
            .unwrap(),
    );
    let pending = {
        let store = f.store.clone();
        let policy = f.policy.clone();
        let verifier = verifier.clone();
        let raw = raw.to_owned();
        tokio::spawn(async move {
            store
                .oidc_userinfo(&policy, &verifier)
                .unwrap()
                .profile(&raw, deadline())
                .await
        })
    };
    waiting(&mut f, "SELECT token_hash,%").await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    tx.rollback().await.unwrap();
    blocker.close().await.unwrap();
    assert_eq!(profile(&client, &origin, raw).await.status(), 200);
    http::stop(child).await;
    f.close().await;
}
#[tokio::test]
#[ignore = "native HTTP and real PostgreSQL durable last_used COMMIT ACK withheld"]
async fn broker_oidc_userinfo_commit_ack_contract() {
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
    f.admin.execute("CREATE FUNCTION hold_userinfo_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(718363); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER hold_userinfo_commit AFTER UPDATE ON public.local_tokens DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hold_userinfo_commit(); SELECT pg_advisory_lock(718363)").await.unwrap();
    let pending = {
        let client = client.clone();
        let origin = origin.clone();
        let raw = raw.to_owned();
        tokio::spawn(async move { profile(&client, &origin, &raw).await })
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
