#[path = "support/upstream_commit.rs"]
mod commit;
#[path = "support/oidc_http.rs"]
#[allow(
    dead_code,
    reason = "shared native process helpers support independent contracts"
)]
mod http;
#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
#[allow(
    dead_code,
    reason = "shared genuine LOCAL fixture supports independent contracts"
)]
mod oidc;
#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture supports independent contracts"
)]
mod support;
use broker_control::BrokerAccessVerifier;
use oidc::{AUDIENCE, OidcFixture, RESOURCE, VERIFIER};
use sqlx_core::executor::Executor;
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use support::{deadline, n};

fn form(pairs: &[(&str, &str)]) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        form.append_pair(key, value);
    }
    form.finish()
}
async fn issue(f: &OidcFixture, address: std::net::SocketAddr) -> serde_json::Value {
    let code = f.code(true, true).await;
    let response = http::post(
        address,
        form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "web-client"),
            ("code", code.code()),
            ("redirect_uri", "https://client.example/cb"),
            ("code_verifier", VERIFIER),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    http::value(response).await
}
async fn post(client: &reqwest::Client, origin: &str, body: String) -> reqwest::Response {
    client
        .post(format!("{origin}/oauth/revoke"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap()
}
fn revoke(raw: &str, client: &str, hint: &str) -> String {
    form(&[
        ("token", raw),
        ("client_id", client),
        ("token_type_hint", hint),
    ])
}
async fn family(f: &mut OidcFixture, raw: &str) -> String {
    let hash = oidc::digester()
        .token(broker_security::TokenKind::LocalRefresh, raw.as_bytes())
        .unwrap()
        .to_sql_hex();
    sqlx_core::query_scalar::query_scalar(
        "SELECT family_id FROM public.local_tokens WHERE token_hash=$1",
    )
    .bind(hash)
    .fetch_one(&mut f.admin)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "actual native binary and PostgreSQL TLS with genuine P3/P4 tokens"]
async fn broker_oidc_revocation_http_contract() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    let issuer = http::files(root.path(), &f.fixture.ca, &origin);
    let yaml = http::yaml(address, f.fixture.port);
    let path = http::write(root.path(), &yaml);
    let child = http::start(&path, address).await;
    let client = reqwest::Client::new();
    let metadata = http::value(
        client
            .get(format!("{origin}/.well-known/openid-configuration"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        metadata["revocation_endpoint"],
        format!("{origin}/oauth/revoke")
    );
    assert_eq!(
        metadata["revocation_endpoint_auth_methods_supported"],
        serde_json::json!(["none"])
    );
    let tokens = issue(&f, address).await;
    let raw = tokens["refresh_token"].as_str().unwrap();
    let access = tokens["access_token"].as_str().unwrap();
    let family = family(&mut f, raw).await;
    for body in [
        "token=x&token=y&client_id=web-client",
        "client_id=web-client",
        "token=x",
        "token=%FF&client_id=web-client",
        "token=x&client_id=web-client&client_id=web-client",
        "token=x&client_id=web-client&client_assertion=unsupported",
    ] {
        let response = post(&client, &origin, body.into()).await;
        assert_eq!(response.status(), 400);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    for body in [
        "token=x&client_id=unknown-client",
        "token=x&client_id=web-client&client_secret=secret",
    ] {
        assert_eq!(post(&client, &origin, body.into()).await.status(), 401);
    }
    assert_eq!(
        client
            .post(format!("{origin}/oauth/revoke"))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client
            .post(format!("{origin}/oauth/revoke?token=x"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(revoke("x", "web-client", ""))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client
            .post(format!("{origin}/oauth/revoke"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(vec![b'a'; 32769])
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client
            .post(format!("{origin}/oauth/revoke"))
            .basic_auth("web-client", Some("secret"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(revoke(raw, "web-client", ""))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .post(format!("{origin}/oauth/revoke"))
            .header("authorization", "Basic eDp5")
            .header("authorization", "Basic eDp5")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(revoke(raw, "web-client", ""))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let preflight = client
        .request(reqwest::Method::OPTIONS, format!("{origin}/oauth/revoke"))
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
    let unknown = client.post(format!("{origin}/oauth/revoke")).header("origin", "https://ui.example")
        .header("content-type", "application/x-www-form-urlencoded")
        .body("token=unknown&client_id=web-client&token_type_hint=unsupported&extension=1&extension=2")
        .send().await.unwrap();
    assert_eq!(unknown.status(), 200);
    assert_eq!(unknown.headers()["cache-control"], "no-store");
    assert_eq!(unknown.headers()["pragma"], "no-cache");
    assert_eq!(
        unknown.headers()["access-control-allow-origin"],
        "https://ui.example"
    );
    assert!(unknown.bytes().await.unwrap().is_empty());
    assert_eq!(
        post(&client, &origin, revoke(raw, "graphit-cli", "access_token"))
            .await
            .status(),
        200
    );
    let count: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.local_tokens WHERE family_id=$1 AND revoked_at IS NOT NULL",
    )
    .bind(&family)
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        post(
            &client,
            &origin,
            revoke(access, "web-client", "refresh_token")
        )
        .await
        .status(),
        200
    );
    let check =
        BrokerAccessVerifier::new(&origin, AUDIENCE, None, issuer.jwks(), n(16384)).unwrap();
    assert!(check.verify(access, &[], deadline()).is_ok());
    let refreshed = http::post(
        address,
        form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "web-client"),
            ("refresh_token", raw),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await;
    assert_eq!(refreshed.status(), 200);
    let refreshed = http::value(refreshed).await;
    assert_eq!(
        post(&client, &origin, revoke(raw, "web-client", "access_token"))
            .await
            .status(),
        200
    );
    let denied = http::post(
        address,
        form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "web-client"),
            (
                "refresh_token",
                refreshed["refresh_token"].as_str().unwrap(),
            ),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await;
    assert_eq!(denied.status(), 400);
    assert_eq!(http::value(denied).await["error"], "invalid_grant");
    assert!(
        check
            .verify(refreshed["access_token"].as_str().unwrap(), &[], deadline())
            .is_ok()
    );
    http::stop(child).await;
    let disabled = yaml.replace("oidc:\n  enabled: true", "oidc:\n  enabled: false");
    assert_ne!(disabled, yaml);
    let path = http::write(root.path(), &disabled);
    let child = http::start(&path, address).await;
    assert_eq!(
        post(&client, &origin, revoke("unknown", "graphit-cli", ""))
            .await
            .status(),
        404
    );
    http::stop(child).await;
    f.close().await;
}

#[tokio::test]
#[ignore = "native HTTP and genuine TLS PostgreSQL durable COMMIT ACK withheld"]
async fn broker_oidc_revocation_commit_ack_contract() {
    let mut f = OidcFixture::new().await;
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let root = tempfile::tempdir().unwrap();
    let address = http::address();
    let origin = format!("http://{address}");
    http::files(root.path(), &f.fixture.ca, &origin);
    let path = http::write(root.path(), &http::yaml(address, relay.port));
    let child = http::start(&path, address).await;
    let client = reqwest::Client::new();
    let tokens = issue(&f, address).await;
    let raw = tokens["refresh_token"].as_str().unwrap();
    let family = family(&mut f, raw).await;
    f.admin.execute("CREATE FUNCTION hold_revocation_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(718289); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER hold_revocation_commit AFTER UPDATE ON public.local_tokens DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hold_revocation_commit(); SELECT pg_advisory_lock(718289)").await.unwrap();
    let pending = {
        let client = client.clone();
        let origin = origin.clone();
        let body = revoke(raw, "web-client", "");
        tokio::spawn(async move { post(&client, &origin, body).await })
    };
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let waiting: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='exchange_owner' AND query='COMMIT' AND wait_event_type='Lock')")
            .fetch_one(&mut f.admin).await.unwrap();
        if waiting {
            break;
        }
        assert!(
            !pending.is_finished(),
            "revocation must enter the real COMMIT"
        );
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    relay.armed.store(true, Ordering::SeqCst);
    f.admin
        .execute("SELECT pg_advisory_unlock(718289)")
        .await
        .unwrap();
    let ack = tokio::time::timeout_at(deadline().into(), relay.replies.recv())
        .await
        .unwrap()
        .unwrap();
    let committed: bool = sqlx_core::query_scalar::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM public.local_tokens WHERE family_id=$1 AND revoked_at IS NULL)")
        .bind(&family).fetch_one(&mut f.admin).await.unwrap();
    assert!(
        committed,
        "SQL effect must be durable before withholding the acknowledgement"
    );
    ack.send(false).unwrap();
    let response = pending.await.unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        http::value(response).await["error"],
        "temporarily_unavailable"
    );
    relay.armed.store(false, Ordering::SeqCst);
    // Release owned fault IO before the server waits for its SQL pool to close.
    relay.close().await;
    http::stop(child).await;
    f.close().await;
}
