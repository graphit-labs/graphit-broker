#[path = "support/oidc_http.rs"]
mod http;
use http::*;
#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
#[allow(
    dead_code,
    reason = "shared producer fixture retains its independent issuer"
)]
mod oidc;
#[allow(
    dead_code,
    reason = "shared real PostgreSQL TLS fixture also supports other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use broker_control::BrokerAccessVerifier;
use oidc::{AUDIENCE, OidcFixture, PEPPER, RESOURCE, VERIFIER};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use serde_json::json;
use sqlx_core::executor::Executor;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use support::{deadline, n};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::Zeroizing;
const PROJECT: &str = "01KSH1CRFFG8Z74B5ZS78WW808";
fn body(code: &str, dynamic: bool, verifier: &str) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "authorization_code")
        .append_pair(
            "client_id",
            if dynamic { "web-client" } else { "graphit-cli" },
        )
        .append_pair("code", code)
        .append_pair(
            "redirect_uri",
            if dynamic {
                "https://client.example/cb"
            } else {
                "http://localhost:49152/oauth/callback"
            },
        )
        .append_pair("code_verifier", verifier);
    if dynamic {
        form.append_pair("resource", RESOURCE);
    }
    form.finish()
}
fn refresh_body(raw: &str, dynamic: bool, scope: Option<&str>) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "refresh_token")
        .append_pair(
            "client_id",
            if dynamic { "web-client" } else { "graphit-cli" },
        )
        .append_pair("refresh_token", raw);
    if dynamic {
        form.append_pair("resource", RESOURCE);
    }
    if let Some(scope) = scope {
        form.append_pair("scope", scope);
    }
    form.finish()
}
async fn storage(address: SocketAddr, raw: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{address}/v1/s3/credentials"))
        .bearer_auth(raw)
        .header("content-type", "application/json")
        .body(json!({"scope":"project","project_id":PROJECT,"module":"hub"}).to_string())
        .send()
        .await
        .unwrap()
}
async fn grant(f: &mut OidcFixture, subject: &str) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('oidc-grant','OIDC fixture','subject',$1,'native-fs',0,0)").bind(subject).execute(&mut f.admin).await.unwrap();
    for (table, values) in [
        ("grant_capabilities", vec!["s3"]),
        ("grant_projects", vec![PROJECT]),
        ("grant_s3_operations", vec!["read", "write"]),
        ("grant_s3_prefixes", vec!["v1"]),
    ] {
        for v in values {
            sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
                "INSERT INTO public.{table}(grant_id,value) VALUES('oidc-grant',$1)"
            )))
            .bind(v)
            .execute(&mut f.admin)
            .await
            .unwrap();
        }
    }
}
#[tokio::test]
async fn actual_cli_oidc_configuration_without_effects() {
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let pair = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = p.self_signed(&pair).unwrap().pem().into_bytes();
    files(root.path(), &ca, &format!("http://{addr}"));
    let good = yaml(addr, 9);
    let path = write(root.path(), &good);
    assert!(
        command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    for bad in [
        good.replace(
            "  json_bytes: 8192",
            &format!("  json_bytes: {}", usize::MAX),
        ),
        good.replace(
            "  parameter_bytes: 8192\n  request_timeout: 10s",
            "  parameter_bytes: 8192\n  request_timeout: 0s",
        ),
        good.replace(
            "  enabled: true\n  cli_client_id:",
            "  enabled: true\n  access_ttl: 59s\n  cli_client_id:",
        ),
        good.replace(
            "  enabled: true\n  cli_client_id:",
            "  enabled: true\n  access_ttl: 1h\n  refresh_ttl: 1m\n  cli_client_id:",
        ),
        good.replace("  parameter_bytes: 8192\n", ""),
    ] {
        write(root.path(), &bad);
        let out = command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap();
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stderr).contains(PEPPER));
        assert!(!root.path().join("volumes").exists());
        assert!(TcpStream::connect(addr).await.is_err());
    }
}
#[tokio::test]
#[ignore = "actual native binary, PostgreSQL TLS and configured Ed25519 key"]
async fn broker_oidc_authorization_code_http_contract() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let issuer = files(root.path(), &f.fixture.ca, &format!("http://{addr}"));
    let config = yaml(addr, f.fixture.port);
    let path = write(root.path(), &config);
    let child = start(&path, addr).await;
    let client = reqwest::Client::new();
    let keys = value(
        client
            .get(format!("http://{addr}/v1/oidc/keys"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(keys["keys"][0]["kid"], "configured-key");
    assert!(keys["keys"][0].get("d").is_none());
    assert_eq!(
        client
            .get(format!("http://{addr}/admin"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let code = f.code(true, true).await;
    grant(&mut f, code.oidc_subject()).await;
    let wrong = post(
        addr,
        body(
            code.code(),
            true,
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ),
        Some("https://ui.example"),
    )
    .await;
    assert_eq!(wrong.status(), 400);
    assert_eq!(value(wrong).await["error"], "invalid_grant");
    let reply = post(
        addr,
        format!(
            "{}&extension=a&extension=b",
            body(code.code(), true, VERIFIER)
        ),
        Some("https://ui.example"),
    )
    .await;
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.headers()["cache-control"], "no-store");
    assert_eq!(reply.headers()["pragma"], "no-cache");
    assert_eq!(
        reply.headers()["access-control-allow-origin"],
        "https://ui.example"
    );
    assert!(
        !reply
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    let tokens = value(reply).await;
    let access = Zeroizing::new(tokens["access_token"].as_str().unwrap().to_owned());
    let id = Zeroizing::new(tokens["id_token"].as_str().unwrap().to_owned());
    assert_eq!(tokens["token_type"], "Bearer");
    assert!((1..=600).contains(&tokens["expires_in"].as_u64().unwrap()));
    assert!(
        tokens["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("gb_rt_")
    );
    let access_claims = claims(&issuer, &format!("http://{addr}"), &access);
    let id_claims = claims(&issuer, &format!("http://{addr}"), &id);
    assert_eq!(
        access_claims["exp"].as_u64().unwrap() - access_claims["iat"].as_u64().unwrap(),
        600
    );
    assert_eq!(id_claims["exp"], access_claims["exp"]);
    assert_eq!(id_claims["nonce"], "literal-nonce");
    assert_eq!(id_claims["amr"], json!(["pwd"]));
    assert_eq!(id_claims["aud"], json!([AUDIENCE, RESOURCE, "web-client"]));
    assert!(id_claims.get("token_use").is_none());
    BrokerAccessVerifier::new(
        &format!("http://{addr}"),
        AUDIENCE,
        None,
        issuer.jwks(),
        n(8192),
    )
    .unwrap()
    .verify(&access, &[], deadline())
    .unwrap();
    assert_eq!(storage(addr, &access).await.status(), 200);
    assert_eq!(storage(addr, &id).await.status(), 401);
    assert_eq!(
        value(post(addr, body(code.code(), true, VERIFIER), None).await).await["error"],
        "invalid_grant"
    );
    // Existing native JWT consumer uses local expiry/current ACL, without mandatory UserInfo or token-row lookup.
    f.admin
        .execute("UPDATE public.local_tokens SET revoked_at=1 WHERE token_kind='oidc_access'")
        .await
        .unwrap();
    assert_eq!(storage(addr, &access).await.status(), 200);
    f.admin.execute("UPDATE public.resource_grants SET principal='different-native-subject' WHERE id='oidc-grant'").await.unwrap();
    assert_eq!(storage(addr, &access).await.status(), 403);
    sqlx_core::query::query("UPDATE public.resource_grants SET principal=$1 WHERE id='oidc-grant'")
        .bind(code.oidc_subject())
        .execute(&mut f.admin)
        .await
        .unwrap();
    assert_eq!(storage(addr, &access).await.status(), 200);
    let cli = f.code(false, false).await;
    let reply = post(
        addr,
        body(cli.code(), false, VERIFIER),
        Some("https://unmatched.example"),
    )
    .await;
    assert_eq!(reply.status(), 200);
    assert!(!reply.headers().contains_key("access-control-allow-origin"));
    let token = value(reply).await;
    assert_eq!(
        claims(
            &issuer,
            &format!("http://{addr}"),
            token["access_token"].as_str().unwrap()
        )["aud"],
        json!([AUDIENCE])
    );
    assert!(token.get("refresh_token").is_none());
    let preflight = client
        .request(
            reqwest::Method::OPTIONS,
            format!("http://{addr}/oauth/token"),
        )
        .header("origin", "https://ui.example")
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "authorization,content-type",
        )
        .send()
        .await
        .unwrap();
    assert!(preflight.status().is_success());
    assert_eq!(
        preflight.headers()["access-control-allow-origin"],
        "https://ui.example"
    );
    assert!(
        !preflight
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    let fresh = f.code(false, false).await;
    let before = f.token_count().await;
    for bad in [
        format!("{}&code=duplicate", body(fresh.code(), false, VERIFIER)),
        "grant_type=refresh_token&refresh_token=unused".into(),
        "code=%FF".into(),
        "a".repeat(32769),
    ] {
        let r = post(addr, bad, None).await;
        assert_eq!(r.status(), 400);
        assert!(value(r).await.get("access_token").is_none());
        assert_eq!(f.token_count().await, before);
    }
    let basic = client
        .post(format!("http://{addr}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", "Basic invalid")
        .body(body(fresh.code(), false, VERIFIER))
        .send()
        .await
        .unwrap();
    assert_eq!(basic.status(), 401);
    assert!(basic.headers().contains_key("www-authenticate"));
    assert_eq!(value(basic).await["error"], "invalid_client");
    // A fully valid partial form is not admitted before body EOF; one Original bounds its read.
    let payload = body(fresh.code(), false, VERIFIER);
    let mut stalled = TcpStream::connect(addr).await.unwrap();
    let wire = format!(
        "POST /oauth/token HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len() + 100
    );
    stalled.write_all(wire.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), stalled.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        std::str::from_utf8(&response)
            .unwrap()
            .starts_with("HTTP/1.1 504")
    );
    assert_eq!(f.token_count().await, before);
    let accepted = post(addr, body(fresh.code(), false, VERIFIER), None).await;
    assert_eq!(accepted.status(), 200);
    stop(child).await;
    // Configured minimum TTL is exercised by the actual process and existing HTTP JWT consumer.
    let short = config
        .replace(
            "  enabled: true\n  cli_client_id:",
            "  enabled: true\n  access_ttl: 60s\n  cli_client_id:",
        )
        .replace(
            "  allowed_origins: [https://ui.example]",
            "  allowed_origins: []",
        );
    write(root.path(), &short);
    let child = start(&path, addr).await;
    let code = f.code(false, false).await;
    let r = post(
        addr,
        body(code.code(), false, VERIFIER),
        Some("https://ui.example"),
    )
    .await;
    assert_eq!(r.status(), 200);
    assert!(!r.headers().contains_key("access-control-allow-origin"));
    let tokens = value(r).await;
    let access = Zeroizing::new(tokens["access_token"].as_str().unwrap().to_owned());
    let c = claims(&issuer, &format!("http://{addr}"), &access);
    assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 60);
    assert_eq!(storage(addr, &access).await.status(), 200);
    let until = c["exp"].as_u64().unwrap();
    loop {
        let now = oidc::micros() / 1_000_000;
        if u64::try_from(now).unwrap() >= until {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(storage(addr, &access).await.status(), 401);
    stop(child).await;
    let disabled = short.replace(
        "  enabled: true\n  access_ttl:",
        "  enabled: false\n  access_ttl:",
    );
    write(root.path(), &disabled);
    let child = start(&path, addr).await;
    assert_eq!(
        post(addr, "grant_type=authorization_code".into(), None)
            .await
            .status(),
        404
    );
    stop(child).await;
    f.close().await;
}

#[tokio::test]
#[ignore = "actual native binary, PostgreSQL TLS, genuine P3 refresh and configured key"]
async fn broker_oidc_refresh_http_contract() {
    use sqlx_core::row::Row;
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let issuer = files(root.path(), &f.fixture.ca, &format!("http://{addr}"));
    let path = write(root.path(), &yaml(addr, f.fixture.port));
    let child = start(&path, addr).await;
    let code = f.code(true, true).await;
    grant(&mut f, code.oidc_subject()).await;
    let first = value(post(addr, body(code.code(), true, VERIFIER), None).await).await;
    let raw = Zeroizing::new(first["refresh_token"].as_str().unwrap().to_owned());
    let hash = |raw: &str| {
        oidc::digester()
            .token(broker_security::TokenKind::LocalRefresh, raw.as_bytes())
            .unwrap()
            .to_sql_hex()
    };
    let before = sqlx_core::query::query(
        "SELECT family_id,expires_at,auth_time FROM public.local_tokens WHERE token_hash=$1",
    )
    .bind(hash(&raw))
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    let family: String = before.get("family_id");
    let original_expiry: i64 = before.get("expires_at");
    let original_auth: i64 = before.get("auth_time");
    let count = f.token_count().await;
    let invalid = [
        (refresh_body(&raw, true, Some("")), "invalid_scope"),
        (refresh_body(&raw, true, Some("address")), "invalid_scope"),
        (
            refresh_body(&raw, true, Some("openid  profile")),
            "invalid_scope",
        ),
        (
            refresh_body(&raw, true, None).replace("web-client", "graphit-cli"),
            "invalid_grant",
        ),
        (
            refresh_body(&raw, true, None).replace(
                "resource=https%3A%2F%2Fbroker.example%2Fv1",
                "resource=https%3A%2F%2Fother.example%2Fv1",
            ),
            "invalid_target",
        ),
        (
            refresh_body(&raw, true, None)
                .replace("&resource=https%3A%2F%2Fbroker.example%2Fv1", ""),
            "invalid_target",
        ),
        (
            format!(
                "{}&scope=openid&scope=profile",
                refresh_body(&raw, true, None)
            ),
            "invalid_request",
        ),
    ];
    for (form, expected) in invalid {
        let response = post(addr, form, None).await;
        assert_eq!(response.status(), 400);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(value(response).await["error"], expected);
        assert_eq!(f.token_count().await, count);
        let consumed: Option<i64> = sqlx_core::query_scalar::query_scalar(
            "SELECT consumed_at FROM public.local_tokens WHERE token_hash=$1",
        )
        .bind(hash(&raw))
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        assert!(consumed.is_none());
    }
    f.admin
        .execute(
            "UPDATE public.local_users SET name='Refresh profile',email='' WHERE username='alice'",
        )
        .await
        .unwrap();
    let reply = post(
        addr,
        refresh_body(&raw, true, Some("openid profile")),
        Some("https://ui.example"),
    )
    .await;
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.headers()["cache-control"], "no-store");
    assert_eq!(reply.headers()["pragma"], "no-cache");
    assert_eq!(
        reply.headers()["access-control-allow-origin"],
        "https://ui.example"
    );
    let rotated = value(reply).await;
    let access = Zeroizing::new(rotated["access_token"].as_str().unwrap().to_owned());
    let id = Zeroizing::new(rotated["id_token"].as_str().unwrap().to_owned());
    let next = Zeroizing::new(rotated["refresh_token"].as_str().unwrap().to_owned());
    assert!(next.as_str() != raw.as_str());
    assert_eq!(rotated["token_type"], "Bearer");
    assert_eq!(rotated["scope"], "openid profile");
    assert!((1..=600).contains(&rotated["expires_in"].as_u64().unwrap()));
    let access_claims = claims(&issuer, &format!("http://{addr}"), &access);
    let id_claims = claims(&issuer, &format!("http://{addr}"), &id);
    assert_eq!(
        access_claims["exp"].as_u64().unwrap() - access_claims["iat"].as_u64().unwrap(),
        600
    );
    assert_eq!(access_claims["name"], "Refresh profile");
    assert!(access_claims.get("email").is_none());
    assert_eq!(id_claims["exp"], access_claims["exp"]);
    assert_eq!(id_claims["auth_time"], original_auth / 1_000_000);
    assert_eq!(id_claims["amr"], json!(["local-token"]));
    assert!(id_claims.get("nonce").is_none() && id_claims.get("c_hash").is_none());
    assert_eq!(
        jsonwebtoken::decode_header(&id).unwrap().kid,
        jsonwebtoken::decode_header(&access).unwrap().kid
    );
    let row = sqlx_core::query::query(
        "SELECT family_id,expires_at,scopes_json FROM public.local_tokens WHERE token_hash=$1",
    )
    .bind(hash(&next))
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("family_id"), family);
    assert_eq!(row.get::<i64, _>("expires_at"), original_expiry);
    assert_eq!(
        row.get::<String, _>("scopes_json"),
        "[\"openid\",\"profile\"]"
    );
    assert_eq!(storage(addr, &access).await.status(), 200);
    assert_eq!(storage(addr, &id).await.status(), 401);
    // Removing offline_access narrows the grant but does not disable its rotation.
    let third_reply = post(addr, refresh_body(&next, true, None), None).await;
    assert_eq!(third_reply.status(), 200);
    let third = value(third_reply).await;
    assert_eq!(third["scope"], "openid profile");
    assert!(third.get("refresh_token").is_some());
    let reused = post(addr, refresh_body(&raw, true, None), None).await;
    assert_eq!(reused.status(), 400);
    assert_eq!(value(reused).await["error"], "invalid_grant");
    let active: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.local_tokens WHERE family_id=$1 AND revoked_at IS NULL",
    )
    .bind(&family)
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(active, 0);
    let refused = post(
        addr,
        refresh_body(third["refresh_token"].as_str().unwrap(), true, None),
        None,
    )
    .await;
    assert_eq!(refused.status(), 400);
    assert_eq!(value(refused).await["error"], "invalid_grant");
    // Family DATA revocation cannot become a per-request JWT blacklist.
    assert_eq!(storage(addr, &access).await.status(), 200);
    f.admin
        .execute(
            "UPDATE public.resource_grants SET principal='other-subject' WHERE id='oidc-grant'",
        )
        .await
        .unwrap();
    assert_eq!(storage(addr, &access).await.status(), 403);
    sqlx_core::query::query("UPDATE public.resource_grants SET principal=$1 WHERE id='oidc-grant'")
        .bind(code.oidc_subject())
        .execute(&mut f.admin)
        .await
        .unwrap();
    assert_eq!(storage(addr, &access).await.status(), 200);
    let cli = f.code(false, true).await;
    let first = value(post(addr, body(cli.code(), false, VERIFIER), None).await).await;
    let example = include_str!("../../../docs/rust-oidc-refresh.md")
        .split_once("```text\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0
        .trim()
        .replace(
            "<opaque-native-P3-refresh>",
            first["refresh_token"].as_str().unwrap(),
        );
    let reply = post(addr, example, Some("https://unmatched.example")).await;
    assert_eq!(reply.status(), 200);
    assert!(!reply.headers().contains_key("access-control-allow-origin"));
    let cli = value(reply).await;
    assert_eq!(
        claims(
            &issuer,
            &format!("http://{addr}"),
            cli["access_token"].as_str().unwrap()
        )["aud"],
        json!([AUDIENCE])
    );
    stop(child).await;
    f.close().await;
}

#[path = "support/upstream_commit.rs"]
mod registration_commit;

async fn registration_count(c: &mut sqlx_postgres::PgConnection) -> i64 {
    sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.oauth_dynamic_clients")
        .fetch_one(c)
        .await
        .unwrap()
}
async fn registration_post(address: SocketAddr, raw: String) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{address}/oauth/register"))
        .header("origin", "https://ui.example")
        .body(raw)
        .send()
        .await
        .unwrap()
}
async fn registration_error(response: reqwest::Response, status: u16, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    assert_eq!(value(response).await, json!({"error":code}));
}
fn registration_authorization<'a>(
    id: &'a str,
    redirect: &'a str,
) -> broker_control::OidcAuthorizationInput<'a> {
    broker_control::OidcAuthorizationInput {
        client_id: id,
        redirect_uri: redirect,
        response_type: "code",
        scope: "openid profile email offline_access",
        state: "registration-state",
        nonce: "registration-nonce",
        code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
        code_challenge_method: "S256",
        response_mode: Some("query"),
        resources: &[RESOURCE],
        prompts: &[],
    }
}
async fn registration_locked_pid(c: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock' AND query LIKE 'INSERT INTO public.oauth_dynamic_clients%' LIMIT 1").fetch_optional(&mut *c).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "registration reached actual INSERT lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn registration_closed_pid(c: &mut sqlx_postgres::PgConnection, pid: i32) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let exists: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
        )
        .bind(pid)
        .fetch_one(&mut *c)
        .await
        .unwrap();
        if !exists {
            return;
        }
        assert!(
            Instant::now() < end,
            "registration guard closes uncertain connection"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "native DCR HTTP, PostgreSQL TLS NOSUPERUSER, exact committed metadata and P2 admission"]
async fn broker_oidc_registration_http_contract() {
    use sqlx_core::row::Row;
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    files(root.path(), &f.fixture.ca, &format!("http://{addr}"));
    let configuration =
        yaml(addr, f.fixture.port).replace("request_timeout: 10s", "request_timeout: 3s");
    let path = write(root.path(), &configuration);
    let child = start(&path, addr).await;
    let d = oidc::digester();
    let service = f.store.oidc_authorization_service(&d, &f.policy);
    let cases = [
        (
            json!({"redirect_uris":[" HTTPS://Client.example:443/cb?q=%2F ","HTTPS://Client.example:443/cb?q=%2F"],"client_name":" Cliente ","scope":"openid profile openid"}),
            "web",
        ),
        (
            json!({"redirect_uris":["http://localhost:8123/cb"]}),
            "native",
        ),
        (
            json!({"redirect_uris":["https://app.example/cb?q=%2F","http://localhost:8123/cb?q=x"],"application_type":"native","grant_types":[],"response_types":[],"token_endpoint_auth_method":" none "}),
            "web",
        ),
        (
            json!({"redirect_uris":["https://app.example/profile"],"scope":"profile","client_name":"🙂".repeat(256)}),
            "web",
        ),
    ];
    for (metadata, kind) in cases {
        let before = registration_count(&mut f.admin).await;
        let response = registration_post(addr, metadata.to_string()).await;
        assert_eq!(response.status(), 201);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://ui.example"
        );
        let wire = value(response).await;
        let id = wire["client_id"].as_str().unwrap();
        assert_eq!(id.len(), 43);
        assert_ne!(id, "graphit-cli");
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_eq!(wire["application_type"], kind);
        assert_eq!(wire["token_endpoint_auth_method"], "none");
        assert_eq!(
            wire["grant_types"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(wire["response_types"], json!(["code"]));
        for secret in [
            "client_secret",
            "client_secret_expires_at",
            "registration_access_token",
            "registration_client_uri",
        ] {
            assert!(wire.get(secret).is_none());
        }
        let row=sqlx_core::query::query("SELECT client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at FROM public.oauth_dynamic_clients WHERE client_id=$1").bind(id).fetch_one(&mut f.admin).await.unwrap();
        assert_eq!(row.len(), 6);
        assert_eq!(registration_count(&mut f.admin).await, before + 1);
        assert_eq!(row.get::<String, _>("client_id"), id);
        assert_eq!(row.get::<String, _>("application_type"), kind);
        assert_eq!(row.get::<String, _>("client_name"), wire["client_name"]);
        let created = row.get::<i64, _>("created_at");
        assert!(created > 0 && created <= oidc::micros());
        assert_eq!(
            wire["client_id_issued_at"].as_i64(),
            Some(created / 1_000_000)
        );
        let redirects: Vec<String> =
            serde_json::from_str(&row.get::<String, _>("redirect_uris_json")).unwrap();
        let scopes: Vec<String> =
            serde_json::from_str(&row.get::<String, _>("scopes_json")).unwrap();
        assert_eq!(json!(redirects), wire["redirect_uris"]);
        assert_eq!(scopes.join(" "), wire["scope"]);
        for redirect in &redirects {
            let pending = service
                .create(registration_authorization(id, redirect), deadline())
                .await
                .unwrap();
            let loaded = service
                .load(pending.request(), deadline())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(loaded.client_id(), id);
            assert_eq!(loaded.redirect_uri(), redirect);
            assert_eq!(loaded.resource(), Some(RESOURCE));
            assert_eq!(loaded.state(), "registration-state");
            assert_eq!(loaded.nonce(), "registration-nonce");
        }
        if kind == "native" {
            service
                .create(
                    registration_authorization(id, "http://127.0.0.1:54322/cb"),
                    deadline(),
                )
                .await
                .unwrap();
        }
        if redirects.len() == 2 {
            for changed in [
                "http://localhost:8124/cb?q=x",
                "http://127.0.0.1:8123/cb?q=x",
                "http://localhost:8123/other?q=x",
                "http://localhost:8123/cb?q=%78",
                "https://app.example/cb?q=%2f",
            ] {
                assert_eq!(
                    service
                        .create(registration_authorization(id, changed), deadline())
                        .await
                        .unwrap_err(),
                    broker_control::OidcAuthorizationError::InvalidRedirect
                );
            }
        }
    }
    let mut cli =
        registration_authorization("graphit-cli", "http://localhost:49152/oauth/callback");
    cli.resources = &[];
    service.create(cli, deadline()).await.unwrap();
    assert_eq!(
        service
            .create(
                registration_authorization("unknown-client", "https://app.example/cb"),
                deadline()
            )
            .await
            .unwrap_err(),
        broker_control::OidcAuthorizationError::InvalidClient
    );
    let before = registration_count(&mut f.admin).await;
    let invalid=[
        "{}".to_owned(),json!({"redirect_uris":[]}).to_string(),
        json!({"redirect_uris":["http://outside.example/cb"]}).to_string(),
        json!({"redirect_uris":["https://localhost/cb"]}).to_string(),
        json!({"redirect_uris":["http://127.1/cb"]}).to_string(),
        json!({"redirect_uris":["https://user@app.example/cb"]}).to_string(),
        json!({"redirect_uris":["https://app.example/cb#bad"]}).to_string(),
        json!({"redirect_uris":["http://localhost:0/cb"]}).to_string(),
        json!({"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}).to_string(),
        json!({"redirect_uris":["https://app.example/cb"],"scope":"phone"}).to_string(),
        json!({"redirect_uris":["https://app.example/cb"],"grant_types":["client_credentials"]}).to_string(),
        json!({"redirect_uris":["https://app.example/cb"],"response_types":["code token"]}).to_string(),
        json!({"redirect_uris":["https://app.example/cb"],"client_name":"🙂".repeat(257)}).to_string(),
        json!({"redirect_uris":["https://app.example/cb"],"client_name":-1}).to_string(),
        json!({"redirect_uris":[format!("https://app.example/{}", "x".repeat(8192))]}).to_string(),
        json!({"redirect_uris":[format!("https://app.example/a{}", "x".repeat(5000)),format!("https://app.example/b{}", "x".repeat(5000))]}).to_string(),
        json!({"redirect_uris":["https://app.example/cb"],"extension":"x".repeat(32768)}).to_string(),
        r#"{"redirect_uris":["https://app.example/cb"],"client_name":null,"client_name":"duplicate"}"#.to_owned(),
        r#"{"redirect_uris":["https://app.example/cb"],"scope":null,"scope":"openid"}"#.to_owned(),
        r#"{"redirect_uris":["https://app.example/cb"]} {}"#.to_owned(),
    ];
    for raw in invalid {
        registration_error(
            registration_post(addr, raw).await,
            400,
            "invalid_client_metadata",
        )
        .await;
        assert_eq!(registration_count(&mut f.admin).await, before);
    }
    // Actual SQL lock exhausts the same Original without a committed client or ID.
    f.admin
        .execute("BEGIN; LOCK TABLE public.oauth_dynamic_clients IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let pending = registration_post(
        addr,
        json!({"redirect_uris":["https://locked.example/cb"]}).to_string(),
    );
    tokio::pin!(pending);
    let pid = tokio::select! {pid=registration_locked_pid(&mut f.admin)=>pid,_=&mut pending=>panic!("DCR must reach INSERT lock")};
    registration_error(pending.await, 504, "temporarily_unavailable").await;
    registration_closed_pid(&mut f.admin, pid).await;
    f.admin.execute("ROLLBACK").await.unwrap();
    assert_eq!(registration_count(&mut f.admin).await, before);
    stop(child).await;
    for disabled in [
        configuration.replace("dynamic_registration: true", "dynamic_registration: false"),
        configuration.replace("oidc:\n  enabled: true", "oidc:\n  enabled: false"),
    ] {
        let path = write(root.path(), &disabled);
        let child = start(&path, addr).await;
        f.admin
            .execute("REVOKE SELECT,INSERT ON public.oauth_dynamic_clients FROM exchange_owner")
            .await
            .unwrap();
        assert_eq!(
            registration_post(addr, "invalid JSON".into())
                .await
                .status(),
            404
        );
        assert_eq!(
            reqwest::get(format!("http://{addr}/oauth/register"))
                .await
                .unwrap()
                .status(),
            404
        );
        assert_eq!(registration_count(&mut f.admin).await, before);
        f.admin
            .execute("GRANT SELECT,INSERT ON public.oauth_dynamic_clients TO exchange_owner")
            .await
            .unwrap();
        stop(child).await;
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "actual DCR PostgreSQL COMMIT observed before withheld TLS acknowledgement; no phantom success"]
async fn broker_oidc_registration_uncertainty_contract() {
    let mut f = OidcFixture::new().await;
    let mut relay = registration_commit::CommitRelay::new(f.fixture.port).await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    files(root.path(), &f.fixture.ca, &format!("http://{addr}"));
    let configuration =
        yaml(addr, relay.port).replace("request_timeout: 10s", "request_timeout: 3s");
    let path = write(root.path(), &configuration);
    let child = start(&path, addr).await;
    let before = registration_count(&mut f.admin).await;
    f.admin
        .execute("BEGIN; LOCK TABLE public.oauth_dynamic_clients IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let pending = registration_post(
        addr,
        json!({"redirect_uris":["https://uncertain.example/cb"],"client_name":"commit-fault"})
            .to_string(),
    );
    tokio::pin!(pending);
    let pid = tokio::select! {pid=registration_locked_pid(&mut f.admin)=>pid,_=&mut pending=>panic!("DCR must reach actual INSERT before fault")};
    relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    f.admin.execute("ROLLBACK").await.unwrap();
    let withheld = loop {
        let decision = tokio::select! {decision=relay.replies.recv()=>decision.unwrap(),_=&mut pending=>panic!("DCR response cannot precede actual COMMIT ACK")};
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
            "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
        )
        .bind(pid)
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        if query == "COMMIT" && idle {
            assert_eq!(registration_count(&mut f.admin).await, before + 1);
            break decision;
        }
        decision.send(true).unwrap();
    };
    registration_error(pending.await, 503, "temporarily_unavailable").await;
    relay
        .armed
        .store(false, std::sync::atomic::Ordering::SeqCst);
    // Restore the deliberately withheld network reply only after the finite 503.
    let _ = withheld.send(true);
    while let Ok(decision) = relay.replies.try_recv() {
        let _ = decision.send(true);
    }
    registration_closed_pid(&mut f.admin, pid).await;
    assert_eq!(
        registration_count(&mut f.admin).await,
        before + 1,
        "no automatic INSERT retry"
    );
    let recovery = registration_post(
        addr,
        json!({"redirect_uris":["https://recovered.example/cb"],"client_name":"fresh-after-fault"})
            .to_string(),
    )
    .await;
    assert_eq!(recovery.status(), 201);
    assert!(value(recovery).await["client_id"].as_str().is_some());
    assert_eq!(registration_count(&mut f.admin).await, before + 2);
    stop(child).await;
    relay.close().await;
    f.close().await;
}
