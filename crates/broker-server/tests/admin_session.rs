#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared real TLS PostgreSQL fixture serves other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
#[path = "support/upstream.rs"]
mod upstream;
#[path = "support/upstream_commit.rs"]
mod upstream_commit;
use broker_control::{BrokerAccessIssuer, BrokerAccessVerifier};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use oidc::{AUDIENCE, ISSUER, OidcFixture, PEPPER, RESOURCE, VERIFIER};
use rcgen::KeyPair;
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{deadline, n};
use tokio::{
    net::TcpStream,
    process::{Child, Command},
};
use zeroize::Zeroizing;
fn block(doc: &str) -> &str {
    doc.split_once("```yaml\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0
}
fn yaml(address: SocketAddr, pg: u16) -> String {
    let base = block(include_str!("../../../docs/rust-broker-server.md"))
        .replace("127.0.0.1:8080", &address.to_string())
        .replace(
            "  public_url: https://broker.example.test",
            &format!("  public_url: http://{address}"),
        )
        .replace("  host: postgres.example.test", "  host: 127.0.0.1")
        .replace("  port: 5432", &format!("  port: {pg}"))
        .replace("  database: graphit", "  database: postgres")
        .replace("  username: graphit_owner", "  username: exchange_owner")
        .replace(
            "\"${BROKER_DATABASE_PASSWORD:?required}\"",
            "ephemeral-owner",
        )
        .replace("postgres-ca.pem", "ca.pem")
        .replace(
            "  issuer: https://broker.example.test",
            &format!("  issuer: {ISSUER}"),
        )
        .replace(
            "  audience: storage-api",
            &format!("  audience: {AUDIENCE}"),
        )
        .replace("  resource: https://broker.example.test/v1\n", "")
        .replace("\"${BROKER_PEPPER:?required}\"", PEPPER);
    format!(
        "{base}{}{}",
        block(include_str!("../../../docs/rust-oidc-token-exchange.md"))
            .replace(
                "accepted_resources: [https://broker.example.test/v1]",
                &format!("accepted_resources: [{RESOURCE}]")
            )
            .replace(
                "  enabled: true\n  cli_client_id:",
                "  enabled: true\n  access_ttl: 60s\n  cli_client_id:"
            ),
        block(include_str!("../../../docs/rust-admin-session-http.md"))
    )
}
fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn files(root: &Path, ca: &[u8]) -> BrokerAccessIssuer {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let der = Zeroizing::new(key.serialize_der());
    std::fs::write(root.join("signing.pk8"), &der).unwrap();
    std::fs::write(root.join("ca.pem"), ca).unwrap();
    BrokerAccessIssuer::new(ISSUER, AUDIENCE, "configured-key", &der).unwrap()
}
fn write(root: &Path, yaml: &str) -> PathBuf {
    let path = root.join("config.yaml");
    std::fs::write(&path, yaml).unwrap();
    path
}
fn command() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphit-broker"));
    c.kill_on_drop(true);
    c
}
async fn start(path: &Path, address: SocketAddr) -> Child {
    let mut child = command()
        .args(["--config", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let end = deadline();
    loop {
        if reqwest::get(format!("http://{address}/readyz"))
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return child;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "native Broker exited before readiness"
        );
        assert!(Instant::now() < end, "native Broker did not become ready");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn stop(mut child: Child) {
    #[cfg(unix)]
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().unwrap().to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    #[cfg(not(unix))]
    child.kill().await.unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .unwrap()
        .unwrap();
    #[cfg(unix)]
    assert!(exit.success());
    #[cfg(not(unix))]
    let _ = exit;
}
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
async fn admin(addr: SocketAddr, token: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("http://{addr}/admin/api/v1/session"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}
async fn json_response(response: reqwest::Response) -> Value {
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}
async fn error(response: reqwest::Response, status: u16, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let value = json_response(response).await;
    assert_eq!(value["error"]["code"], code);
    assert_eq!(value["request_id"], request_id);
    for excluded in ["alice", PEPPER, "SELECT", "ephemeral-owner"] {
        assert!(!value.to_string().contains(excluded));
    }
}
#[tokio::test]
#[ignore = "genuine LOCAL P3/P4, native binary, configured key and TLS PostgreSQL"]
async fn broker_admin_session_http_contract() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let issuer = files(root.path(), &f.fixture.ca);
    let config = yaml(addr, f.fixture.port);
    let path = write(root.path(), &config);
    // Validate the actual CLI before any pool, socket or filesystem volume effect.
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
        config.replace("  profile_json_bytes: 8192\n", ""),
        config.replace("  rows: 128", &format!("  rows: {}", usize::MAX)),
        config.replace(
            "  profile_json_bytes: 8192",
            &format!("  profile_json_bytes: {}", usize::MAX),
        ),
        config.replace("  request_timeout: 3s", "  request_timeout: 0s"),
        config.replace(
            "administration:\n  enabled: true",
            "administration:\n  enabled: true\n  invented_ttl: 1h",
        ),
        config.replace("  roles: 16", "  roles: 16\n  roles: 17"),
    ] {
        write(root.path(), &bad);
        let out = command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap();
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stderr).contains(PEPPER));
        assert!(TcpStream::connect(addr).await.is_err());
        assert!(!root.path().join("volumes").exists());
    }
    write(root.path(), &config);
    let child = start(&path, addr).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/admin/api/v1/session");
    error(
        client.get(&url).send().await.unwrap(),
        401,
        "admin_unauthorized",
    )
    .await;
    error(
        admin(addr, "invalid-fixture-secret").await,
        401,
        "admin_unauthorized",
    )
    .await;
    let code = f.code(true, true).await;
    let tokens = json_response(
        client
            .post(format!("http://{addr}/oauth/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body(code.code(), true, VERIFIER))
            .send()
            .await
            .unwrap(),
    )
    .await;
    let access = Zeroizing::new(tokens["access_token"].as_str().unwrap().to_owned());
    let refresh = Zeroizing::new(tokens["refresh_token"].as_str().unwrap().to_owned());
    let count_before_read = f.token_count().await;
    let response = client
        .get(&url)
        .bearer_auth(&*access)
        .header("x-request-id", "  session-read  ")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-request-id"], "session-read");
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    assert!(!response.headers().contains_key("set-cookie"));
    let value = json_response(response).await;
    assert_eq!(f.token_count().await, count_before_read);
    assert_eq!(
        value,
        json!({"subject":"alice-subject","name":"Alice","email":"alice@example.invalid","username":"alice","organization":"org","teams":["engineering"],"roles":["user"],"role_source":"database","permissions":["projects.read","session.read"],"csrf_token":""})
    );
    let head = client
        .head(&url)
        .bearer_auth(&*access)
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert!(head.bytes().await.unwrap().is_empty());
    for cookie in [
        "graphit_admin_session=opaque-cookie",
        "graphit_admin_session=; graphit_admin_session=opaque-cookie",
        "graphit_admin_session=; graphit_admin_session=",
    ] {
        error(
            client
                .get(&url)
                .bearer_auth(&*access)
                .header("cookie", cookie)
                .send()
                .await
                .unwrap(),
            401,
            "admin_unauthorized",
        )
        .await;
    }
    for cookie in [
        "other=unrelated",
        "graphit_admin_session=",
        "graphit_admin_session=\"\"",
    ] {
        assert_eq!(
            client
                .get(&url)
                .bearer_auth(&*access)
                .header("cookie", cookie)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    error(
        client
            .get(&url)
            .bearer_auth(&*access)
            .header("authorization", format!("Bearer {}", *access))
            .send()
            .await
            .unwrap(),
        401,
        "admin_unauthorized",
    )
    .await;
    error(
        admin(addr, tokens["id_token"].as_str().unwrap()).await,
        401,
        "admin_unauthorized",
    )
    .await;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&[ISSUER]);
    let claims = decode::<Value>(
        &access,
        &DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("configured-key".into());
    let der = Zeroizing::new(std::fs::read(root.path().join("signing.pk8")).unwrap());
    let encoding = EncodingKey::from_ed_der(&der);
    for (field, value) in [
        ("iss", json!("https://untrusted.example")),
        ("aud", json!(["wrong-api"])),
        ("client_id", json!("")),
        ("token_use", json!("id")),
        ("exp", json!(claims["iat"].as_u64().unwrap())),
    ] {
        let mut bad = claims.clone();
        bad[field] = value;
        let bad = Zeroizing::new(encode(&header, &bad, &encoding).unwrap());
        error(admin(addr, &bad).await, 401, "admin_unauthorized").await;
    }
    let mut no_username = claims.clone();
    no_username
        .as_object_mut()
        .unwrap()
        .remove("preferred_username");
    let raw = Zeroizing::new(encode(&header, &no_username, &encoding).unwrap());
    error(admin(addr, &raw).await, 403, "admin_forbidden").await;
    f.admin
        .execute("DELETE FROM public.role_permissions WHERE role='user' AND action='session.read'")
        .await
        .unwrap();
    let mut supplied = claims.clone();
    supplied["roles"] = json!(["admin"]);
    supplied["permissions"] = json!(["*"]);
    let supplied = Zeroizing::new(encode(&header, &supplied, &encoding).unwrap());
    error(admin(addr, &supplied).await, 403, "admin_forbidden").await;
    f.admin
        .execute("INSERT INTO public.role_permissions(role,action) VALUES('user','*')")
        .await
        .unwrap();
    assert_eq!(admin(addr, &access).await.status(), 200);
    f.admin.execute("DELETE FROM public.role_permissions WHERE role='user' AND action='*';INSERT INTO public.role_permissions(role,action) VALUES('user','session.read');UPDATE public.local_users SET name='Current',teams_json='[\" z \",\"a\",\"z\"]',revision=revision+1 WHERE username='alice'").await.unwrap();
    let current = json_response(admin(addr, &access).await).await;
    assert_eq!(current["name"], "Current");
    assert_eq!(current["teams"], json!(["a", "z"]));
    for update in [
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_users SET subject='changed' WHERE username='alice'",
    ] {
        f.admin.execute(update).await.unwrap();
        error(admin(addr, &access).await, 403, "admin_forbidden").await;
        f.admin.execute("UPDATE public.local_users SET enabled=1,subject='alice-subject' WHERE username='alice'").await.unwrap();
    }
    f.admin
        .execute("UPDATE public.local_users SET revision=1 WHERE username='alice'")
        .await
        .unwrap();
    // Actual refresh rotation and reuse revoke the family, not local JWT authenticity.
    let form = |raw: &str| {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", "web-client")
            .append_pair("resource", RESOURCE)
            .append_pair("refresh_token", raw)
            .finish()
    };
    let rotated = client
        .post(format!("http://{addr}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&refresh))
        .send()
        .await
        .unwrap();
    assert_eq!(rotated.status(), 200);
    let rotated = json_response(rotated).await;
    assert_eq!(
        admin(addr, rotated["access_token"].as_str().unwrap())
            .await
            .status(),
        200
    );
    assert_eq!(
        client
            .post(format!("http://{addr}/oauth/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(&refresh))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(admin(addr, &access).await.status(), 200);
    let verifier =
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, None, issuer.jwks(), n(8192)).unwrap();
    let proof = verifier
        .verify(&access, &[], Instant::now() + Duration::from_secs(120))
        .unwrap();
    let (utc, mono) = proof.authentication_expiry();
    let duration =
        utc.duration_since(SystemTime::now()).unwrap_or_default() + Duration::from_millis(30);
    tokio::time::sleep(duration).await;
    assert!(Instant::now() >= mono);
    assert_eq!(
        proof.check(),
        Err(broker_control::BrokerAccessError::Expired)
    );
    error(admin(addr, &access).await, 401, "admin_unauthorized").await;
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        60
    );
    assert!(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            >= claims["exp"].as_u64().unwrap()
    );
    stop(child).await;
    // Explicit disable removes the route; it does not create a permissive fallback.
    write(
        root.path(),
        &config.replace(
            "administration:\n  enabled: true",
            "administration:\n  enabled: false",
        ),
    );
    let disabled = start(&path, addr).await;
    assert_eq!(admin(addr, &access).await.status(), 404);
    stop(disabled).await;
    f.close().await;
}

#[tokio::test]
#[ignore = "actual native Admin opaque access/service, current SQL and genuine P3 JWT coexistence"]
async fn broker_admin_local_bearer_http_contract() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    let _issuer = files(root.path(), &f.fixture.ca);
    let config = yaml(addr, f.fixture.port).replace(
        block(include_str!("../../../docs/rust-admin-session-http.md")),
        block(include_str!(
            "../../../docs/rust-admin-local-bearer-session.md"
        )),
    );
    let path = write(root.path(), &config);
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
        config.replace("    audience: explicit-admin-api\n", ""),
        config.replace("    identity_json_bytes: 8192\n", ""),
        config.replace("    required_scopes: [admin:session]\n", ""),
        config.replace("    audience: explicit-admin-api", "    audience: '   '"),
        config.replace(
            "    identity_json_bytes: 8192",
            &format!("    identity_json_bytes: {}", usize::MAX),
        ),
        config.replace(
            "    required_scopes: [admin:session]",
            "    required_scopes: ['']",
        ),
        config.replace(
            "  local_bearer:",
            "  local_bearer:\n    extra_issuer: untrusted",
        ),
    ] {
        write(root.path(), &bad);
        let out = command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap();
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stderr).contains(PEPPER));
        assert!(TcpStream::connect(addr).await.is_err());
        assert!(!root.path().join("volumes").exists());
    }
    seed_opaque_admin_credentials(&mut f).await;
    write(root.path(), &config);
    let child = start(&path, addr).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/admin/api/v1/session");
    let access = "gb_at_admin-http-fixture";
    let service = "gb_sc_admin-http-fixture";
    for (raw, username, subject) in [
        (access, "alice", "alice-subject"),
        (service, "bot", "bot-subject"),
    ] {
        let response = client
            .get(&url)
            .bearer_auth(raw)
            .header("x-request-id", "  opaque-read  ")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["x-request-id"], "opaque-read");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
        assert!(!response.headers().contains_key("set-cookie"));
        let value = json_response(response).await;
        assert_eq!(value["username"], username);
        assert_eq!(value["subject"], subject);
        assert_eq!(value["role_source"], "database");
        assert_eq!(value["roles"], json!(["user"]));
        assert_eq!(value["csrf_token"], "");
        assert!(
            value["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "session.read")
        );
        assert!(!value.to_string().contains("stale"));
        let head = client.head(&url).bearer_auth(raw).send().await.unwrap();
        assert_eq!(head.status(), 200);
        assert!(head.bytes().await.unwrap().is_empty());
    }
    // Native token authority still comes from the actual mounted P3 exchange.
    let code = f.code(true, false).await;
    let tokens = json_response(
        client
            .post(format!("http://{addr}/oauth/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body(code.code(), true, VERIFIER))
            .send()
            .await
            .unwrap(),
    )
    .await;
    let jwt = Zeroizing::new(tokens["access_token"].as_str().unwrap().to_owned());
    assert_eq!(admin(addr, &jwt).await.status(), 200);
    error(
        admin(addr, tokens["id_token"].as_str().unwrap()).await,
        401,
        "admin_unauthorized",
    )
    .await;
    for raw in [access, service] {
        for cookie in [
            "graphit_admin_session=known-cookie",
            "graphit_admin_session=; graphit_admin_session=",
            "graphit_admin_session=; graphit_admin_session=known-cookie",
        ] {
            error(
                client
                    .get(&url)
                    .bearer_auth(raw)
                    .header("cookie", cookie)
                    .send()
                    .await
                    .unwrap(),
                401,
                "admin_unauthorized",
            )
            .await;
        }
        assert_eq!(
            client
                .get(&url)
                .bearer_auth(raw)
                .header("cookie", "graphit_admin_session=\"\"")
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        error(
            client
                .get(&url)
                .bearer_auth(raw)
                .header("authorization", format!("Bearer {raw}"))
                .send()
                .await
                .unwrap(),
            401,
            "admin_unauthorized",
        )
        .await;
    }
    error(
        client.get(&url).send().await.unwrap(),
        401,
        "admin_unauthorized",
    )
    .await;
    for raw in [
        "gb_at_wrong-hash",
        "gb_sc_wrong-hash",
        "gb_rt_refresh",
        "GB_AT_admin-http-fixture",
    ] {
        error(admin(addr, raw).await, 401, "admin_unauthorized").await;
    }
    f.admin
        .execute("DELETE FROM role_permissions WHERE role='user' AND action='session.read'")
        .await
        .unwrap();
    for raw in [access, service, &jwt] {
        error(admin(addr, raw).await, 403, "admin_forbidden").await;
    }
    f.admin.execute("INSERT INTO role_permissions(role,action) VALUES('user','session.read'); UPDATE local_users SET name='Current',teams_json='[\" z \",\"a\",\"z\"]' WHERE username='alice'").await.unwrap();
    let current = json_response(admin(addr, access).await).await;
    assert_eq!(current["name"], "Current");
    assert_eq!(current["teams"], json!(["a", "z"]));
    for (change, restore) in [
        (
            "UPDATE local_tokens SET audience='wrong-api' WHERE token_id='admin-access'",
            "UPDATE local_tokens SET audience='explicit-admin-api' WHERE token_id='admin-access'",
        ),
        (
            "UPDATE local_tokens SET scopes_json='[]' WHERE token_id='admin-access'",
            "UPDATE local_tokens SET scopes_json='[\"admin:session\"]' WHERE token_id='admin-access'",
        ),
        (
            "UPDATE local_tokens SET revoked_at=0 WHERE token_id='admin-access'",
            "UPDATE local_tokens SET revoked_at=NULL WHERE token_id='admin-access'",
        ),
        (
            "UPDATE local_users SET enabled=0 WHERE username='alice'",
            "UPDATE local_users SET enabled=1 WHERE username='alice'",
        ),
        (
            "UPDATE local_users SET revision=2 WHERE username='alice'",
            "UPDATE local_users SET revision=1 WHERE username='alice'",
        ),
    ] {
        f.admin.execute(change).await.unwrap();
        error(admin(addr, access).await, 401, "admin_unauthorized").await;
        f.admin.execute(restore).await.unwrap();
    }
    assert_eq!(admin(addr, &jwt).await.status(), 200);
    assert_eq!(admin(addr, access).await.status(), 200);
    f.admin
        .execute("UPDATE local_tokens SET expires_at=0 WHERE token_id='admin-access'")
        .await
        .unwrap();
    error(admin(addr, access).await, 401, "admin_unauthorized").await;
    assert_eq!(admin(addr, &jwt).await.status(), 200);
    stop(child).await;
    write(
        root.path(),
        &config.replace(
            "  local_bearer:\n    enabled: true",
            "  local_bearer:\n    enabled: false",
        ),
    );
    let local_off = start(&path, addr).await;
    error(admin(addr, service).await, 401, "admin_unauthorized").await;
    assert_eq!(admin(addr, &jwt).await.status(), 200);
    stop(local_off).await;
    write(
        root.path(),
        &config.replace(
            "administration:\n  enabled: true",
            "administration:\n  enabled: false",
        ),
    );
    let all_off = start(&path, addr).await;
    assert_eq!(admin(addr, service).await.status(), 404);
    stop(all_off).await;
    f.close().await;
}
async fn seed_opaque_admin_credentials(f: &mut OidcFixture) {
    use broker_security::TokenKind;
    f.admin.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('bot','bot-subject','service','','Bot','','Automation','[]',1,0,1,0,0)").await.unwrap();
    for (raw, id, kind, domain, subject) in [
        (
            "gb_at_admin-http-fixture",
            "admin-access",
            "access",
            TokenKind::LocalAccess,
            "alice-subject",
        ),
        (
            "gb_sc_admin-http-fixture",
            "admin-service",
            "service",
            TokenKind::ServiceCredential,
            "bot-subject",
        ),
    ] {
        let digest = oidc::digester().token(domain, raw.as_bytes()).unwrap();
        let principal = json!({"issuer":"local","subject":subject,"username":"stale","auth_method":"stale","name":"stale","local_user_revision":1});
        sqlx_core::query::query("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'other-subject',$5,'explicit-client','explicit-admin-api','','[\"admin:session\"]',1,'',0,$6,0)")
            .bind(digest.to_sql_hex()).bind(id).bind(kind).bind(subject).bind(principal.to_string()).bind(oidc::micros()+600_000_000).execute(&mut f.admin).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "actual Rust HTTPS OIDC issuer/JWKS, native Broker binary and TLS NOSUPERUSER PostgreSQL"]
async fn broker_admin_upstream_bearer_http_contract() {
    let mut f = OidcFixture::new().await;
    let mut op = upstream::UpstreamFixture::new().await;
    let mut keys = op.keys();
    // RFC7517 Appendix A public RSA modulus (also the pinned SDK thumbprint vector).
    // This valid anonymous RS256 key is unrelated to this issuer's configured EdDSA admission.
    let unrelated = serde_json::json!({"kty":"RSA","alg":"RS256","use":"sig","key_ops":["verify"],"e":"AQAB","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"});
    keys["keys"].as_array_mut().unwrap().push(unrelated);
    op.replace_keys(keys);
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    files(root.path(), &f.fixture.ca);
    std::fs::write(root.path().join("issuer-ca.pem"), &op.ca).unwrap();
    let upstream = block(include_str!("../../../docs/rust-admin-upstream-session.md"))
        .strip_prefix("auth:\n")
        .unwrap()
        .replace("https://issuer.example.test", &op.issuer);
    let config = yaml(addr, f.fixture.port)
        .replace("storage:\n", &format!("{upstream}storage:\n"))
        .replace(
            block(include_str!("../../../docs/rust-admin-session-http.md")),
            block(include_str!(
                "../../../docs/rust-admin-local-bearer-session.md"
            )),
        );
    let path = write(root.path(), &config);
    assert!(
        command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    assert_eq!(op.hits(), 0, "config checking must not discover an issuer");
    for bad in [
        config.replace("      required_scopes: [admin:session]\n", ""),
        config.replace(
            "      allowed_algorithms: [EdDSA]",
            "      allowed_algorithms: [HS256]",
        ),
        config.replace(
            "        teams: \"$.groups[*].name\"",
            "        teams: '$..['",
        ),
        config.replace(
            "        id_token_audiences: [broker-browser]",
            "        id_token_audiences: [graphit-broker-resource]",
        ),
        config.replace("      issuer: ", "      unknown_issuer: "),
        config.replace("      ca_bytes: 8192\n", ""),
        config.replace("      cache_max_age: 5m", "      cache_max_age: 10ms"),
        config.replace(&op.issuer, ISSUER),
    ] {
        write(root.path(), &bad);
        let out = command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap();
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stderr).contains(PEPPER));
        assert!(TcpStream::connect(addr).await.is_err());
        assert_eq!(op.hits(), 0);
    }
    seed_opaque_admin_credentials(&mut f).await;
    write(root.path(), &config);
    let child = start(&path, addr).await;
    let claims = op.claims();
    let token = op.sign(&claims, "upstream-key", "at+jwt");
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/admin/api/v1/session");
    let r = client
        .get(&url)
        .bearer_auth(&*token)
        .header("x-request-id", "fed-read")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(r.headers()["pragma"], "no-cache");
    assert_eq!(r.headers()["x-request-id"], "fed-read");
    assert!(!r.headers().contains_key("set-cookie"));
    let profile = json_response(r).await;
    assert_eq!(profile["subject"], "external|subject");
    assert_eq!(profile["username"], "alice");
    assert_eq!(profile["name"], "Federated");
    assert_eq!(profile["organization"], "external-org");
    assert_eq!(profile["teams"], json!(["a", "z"]));
    assert_eq!(profile["roles"], json!(["user"]));
    assert_eq!(profile["role_source"], "database");
    assert_eq!(profile["csrf_token"], "");
    assert_eq!(op.hits(), 2);
    let head = client.head(&url).bearer_auth(&*token).send().await.unwrap();
    assert_eq!(head.status(), 200);
    assert!(head.bytes().await.unwrap().is_empty());
    assert_eq!(op.hits(), 2);
    let canonical = format!("{}|external|subject", op.issuer);
    sqlx_core::query::query(
        "INSERT INTO public.role_assignments(subject,role,created_at) VALUES($1,'admin',0)",
    )
    .bind(&canonical)
    .execute(&mut f.admin)
    .await
    .unwrap();
    let p = json_response(admin(addr, &token).await).await;
    assert_eq!(p["roles"], json!(["admin", "user"]));
    let mut changed = claims.clone();
    changed["preferred_username"] = json!("different username");
    let p = json_response(admin(addr, &op.sign(&changed, "upstream-key", "at+jwt")).await).await;
    assert_eq!(p["username"], "different username");
    assert_eq!(p["roles"], json!(["admin", "user"]));
    sqlx_core::query::query("DELETE FROM public.role_assignments WHERE subject=$1")
        .bind(&canonical)
        .execute(&mut f.admin)
        .await
        .unwrap();
    for (field, value) in [
        ("iss", json!("https://untrusted.example.invalid")),
        ("aud", json!("broker-browser")),
        ("aud", json!(["graphit-broker-resource", "broker-browser"])),
        ("aud", json!(["elsewhere"])),
        ("exp", json!(1)),
        ("exp", Value::Null),
        ("nbf", json!(u64::MAX)),
        ("iat", json!(u64::MAX)),
        ("sub", json!("")),
        ("preferred_username", json!(["alice"])),
        ("name", Value::Null),
        ("groups", json!([{"name":[["nested"]]}])),
        ("scope", json!("wrong")),
        ("scope", json!("admin:session,extra")),
        ("client_id", json!("wrong")),
    ] {
        let mut bad = claims.clone();
        bad[field] = value;
        let r = admin(addr, &op.sign(&bad, "upstream-key", "at+jwt")).await;
        assert_eq!(r.status(), 401, "invalid {field}");
    }
    let mut no_scope = claims.clone();
    no_scope["scope"] = json!(["admin:session", "extra"]);
    assert_eq!(
        admin(addr, &op.sign(&no_scope, "upstream-key", "at+jwt"))
            .await
            .status(),
        200
    );
    let mut bad_signature = upstream::UpstreamFixture::new().await;
    let wrong = bad_signature.sign(&claims, "upstream-key", "at+jwt");
    assert_eq!(admin(addr, &wrong).await.status(), 401);
    bad_signature.close().await;
    for cookie in [
        "graphit_admin_session=known",
        "graphit_admin_session=; graphit_admin_session=",
    ] {
        assert_eq!(
            client
                .get(&url)
                .bearer_auth(&*token)
                .header("cookie", cookie)
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
    }
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(&*token)
            .header("cookie", "graphit_admin_session=")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let code = f.code(true, false).await;
    let local = json_response(
        client
            .post(format!("http://{addr}/oauth/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body(code.code(), true, VERIFIER))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        admin(addr, local["access_token"].as_str().unwrap())
            .await
            .status(),
        200
    );
    assert_eq!(
        admin(addr, local["id_token"].as_str().unwrap())
            .await
            .status(),
        401
    );
    assert_eq!(admin(addr, "gb_at_admin-http-fixture").await.status(), 200);
    assert_eq!(admin(addr, "gb_sc_admin-http-fixture").await.status(), 200);
    sqlx_core::query::query(
        "DELETE FROM public.role_permissions WHERE role='user' AND action='session.read'",
    )
    .execute(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(admin(addr, &token).await.status(), 403);
    f.admin
        .execute("INSERT INTO public.role_permissions(role,action) VALUES('user','session.read')")
        .await
        .unwrap();

    // The production helper holds actual cryptographic authority while current SQL waits.
    let configured = || broker_control::UpstreamProviderConfig {
        id: "sql-fence".into(),
        issuer: op.issuer.clone(),
        audiences: vec!["graphit-broker-resource".into()],
        required_scopes: vec!["admin:session".into()],
        allowed_algorithms: vec![Algorithm::EdDSA],
        access_policy: broker_control::UpstreamAccessPolicy::ResourceAudience {
            id_token_audiences: vec!["broker-browser".into()],
        },
        predicates: vec![broker_control::UpstreamClaimPredicate {
            selector: "client_id".into(),
            value: "broker-resource-client".into(),
        }],
        claims: broker_control::UpstreamClaimSelectors {
            subject: "sub".into(),
            username: "preferred_username".into(),
            name: Some("name".into()),
            email: Some("email".into()),
            organization: Some("organization.id".into()),
            teams: Some("$.groups[*].name".into()),
            roles: None,
            scope: "scope".into(),
        },
        limits: broker_control::UpstreamReadLimits {
            token_bytes: n(16384),
            response_bytes: n(65536),
            keys: n(16),
            selector_bytes: n(512),
            claim_string_bytes: n(2048),
            profile_json_bytes: n(8192),
            teams: n(32),
        },
        request_timeout: Duration::from_secs(5),
        cache_max_age: Duration::from_secs(300),
        min_refresh_interval: Duration::from_millis(100),
        allow_loopback_http: false,
        trusted_ca_pem: Some(op.ca.clone()),
        browser_clients: Vec::new(),
    };
    let build = |config| {
        broker_control::UpstreamBearerVerifier::new(ISSUER, n(16384), vec![config]).unwrap()
    };
    let verifier = std::sync::Arc::new(build(configured()));
    let limits = broker_control::AdminBrokerSessionLimits {
        identity: broker_control::IdentityReadLimits {
            username_bytes: n(128),
            subject_bytes: n(512),
            role_bytes: n(128),
            roles: n(16),
            rows: n(128),
        },
        profile_json_bytes: n(8192),
    };
    f.store
        .admin_upstream_sessions(&verifier, limits)
        .unwrap()
        .read(&token, deadline())
        .await
        .unwrap();
    let mut cap = limits;
    cap.profile_json_bytes = n(1);
    assert!(matches!(
        f.store
            .admin_upstream_sessions(&verifier, cap)
            .unwrap()
            .read(&token, deadline())
            .await,
        Err(broker_control::AdminBrokerSessionError::Control(
            broker_control::ControlError::IdentityLimitExceeded
        ))
    ));

    // Trusted network/parser/key failures remain infrastructure, never authentication.
    for (field, value) in [
        ("issuer", json!("https://wrong.example.invalid")),
        ("jwks_uri", json!("http://127.0.0.1:1/jwks")),
    ] {
        let mut meta = op.metadata();
        meta[field] = value;
        op.override_metadata(Some(meta));
        let isolated = build(configured());
        assert!(matches!(
            f.store
                .admin_upstream_sessions(&isolated, limits)
                .unwrap()
                .read(&token, deadline())
                .await,
            Err(broker_control::AdminBrokerSessionError::Control(
                broker_control::ControlError::Unavailable
            ))
        ));
    }
    op.override_metadata(None);
    let real_keys = op.keys();
    let mut private_keys = real_keys.clone();
    private_keys["keys"][0]["d"] = json!("forbidden-private-field");
    for keys in [json!({"keys":[]}), private_keys] {
        op.replace_keys(keys);
        let isolated = build(configured());
        assert!(matches!(
            f.store
                .admin_upstream_sessions(&isolated, limits)
                .unwrap()
                .read(&token, deadline())
                .await,
            Err(broker_control::AdminBrokerSessionError::Control(
                broker_control::ControlError::Unavailable
            ))
        ));
    }
    op.replace_keys(real_keys);
    let mut tiny = configured();
    tiny.limits.response_bytes = n(16);
    let isolated = build(tiny);
    assert!(matches!(
        f.store
            .admin_upstream_sessions(&isolated, limits)
            .unwrap()
            .read(&token, deadline())
            .await,
        Err(broker_control::AdminBrokerSessionError::Control(
            broker_control::ControlError::Unavailable
        ))
    ));
    let mut exact = op.claims();
    exact["organization.id"] = json!("literal dotted key");
    let observation = f
        .store
        .admin_upstream_sessions(&verifier, limits)
        .unwrap()
        .read(&op.sign(&exact, "upstream-key", "at+jwt"), deadline())
        .await
        .unwrap();
    assert_eq!(observation.organization(), "literal dotted key");
    let mut nested = op.claims();
    nested["groups"] = json!([{"name":[" z ","a"]},{"name":"a"}]);
    assert_eq!(
        f.store
            .admin_upstream_sessions(&verifier, limits)
            .unwrap()
            .read(&op.sign(&nested, "upstream-key", "at+jwt"), deadline())
            .await
            .unwrap()
            .teams(),
        ["a", "z"]
    );
    let mut observer = f.fixture.connection().await;
    for scenario in ["owner", "expiry", "cancel"] {
        f.admin
            .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let store = f.store.clone();
        let reading_verifier = verifier.clone();
        let mut claims = op.claims();
        if scenario == "expiry" {
            claims["exp"] = json!(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 2
            );
        }
        let raw = op.sign(&claims, "upstream-key", "at+jwt");
        let end = if scenario == "owner" {
            Instant::now() + Duration::from_millis(400)
        } else {
            deadline()
        };
        let reading = tokio::spawn(async move {
            store
                .admin_upstream_sessions(&reading_verifier, limits)
                .unwrap()
                .read(&raw, end)
                .await
        });
        let wait = deadline();
        loop {
            let locked:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE usename='exchange_owner' AND query LIKE 'WITH selected AS%' AND wait_event_type='Lock')").fetch_one(&mut observer).await.unwrap();
            if locked {
                break;
            }
            assert!(
                Instant::now() < wait,
                "actual external role SQL did not wait"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if scenario == "cancel" {
            reading.abort();
            assert!(reading.await.unwrap_err().is_cancelled());
        } else {
            let result = reading.await.unwrap();
            assert!(matches!(
                (scenario, result),
                (
                    "owner",
                    Err(broker_control::AdminBrokerSessionError::Control(
                        broker_control::ControlError::Deadline
                    ))
                ) | (
                    "expiry",
                    Err(broker_control::AdminBrokerSessionError::Authentication(
                        broker_control::BrokerAccessError::Expired
                    ))
                )
            ));
        }
        f.admin.execute("ROLLBACK").await.unwrap();
        assert!(
            f.store
                .admin_upstream_sessions(&verifier, limits)
                .unwrap()
                .read(&token, deadline())
                .await
                .is_ok()
        );
    }

    // Withhold the actual COMMIT ACK after observed SELECT, preserving end-to-end TLS.
    let mut relay = upstream_commit::CommitRelay::new(f.fixture.port).await;
    let relay_config = broker_control::PostgresConfig::new(
        broker_control::PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: std::num::NonZeroU16::new(relay.port).unwrap(),
            database: "postgres".into(),
        },
        broker_control::PostgresCredentials::new(
            "exchange_owner".into(),
            Zeroizing::new("ephemeral-owner".into()),
        ),
        f.fixture.ca.clone(),
        broker_control::ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap();
    let relay_store =
        broker_control::PostgresControlStore::open(relay_config, oidc::digester(), deadline())
            .await
            .unwrap();
    let mut claims = op.claims();
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 5;
    claims["exp"] = json!(expiry);
    let commit_token = op.sign(&claims, "upstream-key", "at+jwt");
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let reader = relay_store
        .admin_upstream_sessions(&verifier, limits)
        .unwrap();
    let pending = reader.read(&commit_token, Instant::now() + Duration::from_secs(2));
    tokio::pin!(pending);
    let observed = async {
        loop {
            let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='exchange_owner' AND query LIKE 'WITH selected AS%' AND wait_event_type='Lock'").fetch_optional(&mut observer).await.unwrap();
            if let Some(pid) = pid {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let pid = tokio::select! {pid=observed=>pid,result=&mut pending=>panic!("actual federated role SELECT must wait: {:?}",result.err())};
    locker.execute("ROLLBACK").await.unwrap();
    let wait = deadline();
    loop {
        let ready: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT state='idle in transaction' FROM pg_stat_activity WHERE pid=$1",
        )
        .bind(pid)
        .fetch_one(&mut observer)
        .await
        .unwrap();
        if ready {
            break;
        }
        assert!(Instant::now() < wait);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    loop {
        let decision = tokio::select! {decision=relay.replies.recv()=>decision.unwrap(),result=&mut pending=>panic!("actual federated COMMIT ACK was not withheld: {:?}",result.err())};
        let query: String = sqlx_core::query_scalar::query_scalar(
            "SELECT query FROM pg_stat_activity WHERE pid=$1",
        )
        .bind(pid)
        .fetch_one(&mut observer)
        .await
        .unwrap();
        if query == "COMMIT" {
            decision.send(false).unwrap();
            break;
        }
        decision.send(true).unwrap();
    }
    assert!(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            < expiry
    );
    let until = std::time::UNIX_EPOCH + Duration::from_secs(expiry);
    tokio::time::sleep(
        until.duration_since(SystemTime::now()).unwrap() + Duration::from_millis(30),
    )
    .await;
    assert!(matches!(
        pending.await,
        Err(broker_control::AdminBrokerSessionError::Control(
            broker_control::ControlError::OutcomeUncertain
        ))
    ));
    sqlx_core::connection::Connection::close(locker)
        .await
        .unwrap();
    relay.close().await;
    relay_store.shutdown(deadline()).await.unwrap();
    let closed_token = op.sign(&op.claims(), "upstream-key", "at+jwt");
    assert!(matches!(
        relay_store
            .admin_upstream_sessions(&verifier, limits)
            .unwrap()
            .read(&closed_token, deadline())
            .await,
        Err(broker_control::AdminBrokerSessionError::Control(
            broker_control::ControlError::Closed
        ))
    ));
    tokio::time::sleep(Duration::from_millis(120)).await;
    op.rotate("rotated-key");
    let rotated = op.sign(&op.claims(), "rotated-key", "at+jwt");
    assert_eq!(admin(addr, &rotated).await.status(), 200);
    assert_eq!(admin(addr, &token).await.status(), 401);
    stop(child).await;
    // Claim roles replace current SQL assignments, even when missing or empty.
    let claim_config = config.replace(
        "        scope: scope",
        "        roles: '$.realm_access.roles[*]'\n        scope: scope",
    );
    write(root.path(), &claim_config);
    let child = start(&path, addr).await;
    sqlx_core::query::query(
        "INSERT INTO public.role_assignments(subject,role,created_at) VALUES($1,'admin',0)",
    )
    .bind(&canonical)
    .execute(&mut f.admin)
    .await
    .unwrap();
    let claims = op.claims();
    let r = json_response(admin(addr, &op.sign(&claims, "rotated-key", "at+jwt")).await).await;
    assert_eq!(r["roles"], json!(["user"]));
    assert_eq!(r["role_source"], "claims");
    let mut claims = claims;
    claims["realm_access"] = json!({"roles":["admin"," admin "]});
    assert_eq!(
        json_response(admin(addr, &op.sign(&claims, "rotated-key", "at+jwt")).await).await["roles"],
        json!(["admin", "user"])
    );
    claims["realm_access"] = json!({"roles":["../admin"]});
    assert_eq!(
        admin(addr, &op.sign(&claims, "rotated-key", "at+jwt"))
            .await
            .status(),
        401
    );
    claims["realm_access"] = json!({"roles":["unknown"]});
    let r = json_response(admin(addr, &op.sign(&claims, "rotated-key", "at+jwt")).await).await;
    assert_eq!(r["roles"], json!(["unknown", "user"]));
    assert!(
        !r["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "*")
    );
    stop(child).await;
    let marker_config=config.replace("        type: resource_audience\n        id_token_audiences: [broker-browser]",
        "        type: signed_marker\n        typ: at+jwt\n        claim:\n          selector: token_use\n          value: access");
    write(root.path(), &marker_config);
    let child = start(&path, addr).await;
    let claims = op.claims();
    assert_eq!(
        admin(addr, &op.sign(&claims, "rotated-key", "at+jwt"))
            .await
            .status(),
        200
    );
    assert_eq!(
        admin(addr, &op.sign(&claims, "rotated-key", "JWT"))
            .await
            .status(),
        401
    );
    let mut id = claims.clone();
    id["token_use"] = json!("id");
    assert_eq!(
        admin(addr, &op.sign(&id, "rotated-key", "at+jwt"))
            .await
            .status(),
        401
    );
    stop(child).await;
    let timed = config.replace("      request_timeout: 5s", "      request_timeout: 50ms");
    write(root.path(), &timed);
    op.delay(Duration::from_millis(200));
    let child = start(&path, addr).await;
    let token = op.sign(&op.claims(), "rotated-key", "at+jwt");
    assert_eq!(
        admin(addr, &token).await.status(),
        504,
        "one captured discovery/JWKS deadline"
    );
    op.delay(Duration::ZERO);
    stop(child).await;
    let short_cache = config.replace("      cache_max_age: 5m", "      cache_max_age: 1s");
    write(root.path(), &short_cache);
    let child = start(&path, addr).await;
    let token = op.sign(&op.claims(), "rotated-key", "at+jwt");
    assert_eq!(admin(addr, &token).await.status(), 200);
    let wrong_offline = bad_signature.sign(&op.claims(), "rotated-key", "at+jwt");
    op.close().await;
    let hits = op.hits();
    assert_eq!(
        admin(addr, &wrong_offline).await.status(),
        401,
        "known-key bad signature stays invalid offline"
    );
    assert_eq!(
        op.hits(),
        hits,
        "bad signature never refreshes a fresh known key"
    );
    assert_eq!(
        admin(addr, &token).await.status(),
        200,
        "fresh cached verification works offline"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        admin(addr, &token).await.status(),
        503,
        "expired cache has no offline fallback"
    );
    stop(child).await;
    f.store.shutdown(deadline()).await.unwrap();
}
