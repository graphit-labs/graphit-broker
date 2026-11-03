#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared real TLS PostgreSQL fixture serves other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use broker_control::{BrokerAccessIssuer, BrokerAccessVerifier};
use broker_presence::{BrokerProjectAuthorizationHttpConfig, broker_project_authorization_router};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use oidc::{AUDIENCE, ISSUER, OidcFixture, PEPPER, RESOURCE, VERIFIER};
use rcgen::KeyPair;
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use support::{deadline, n};
use tokio::{
    net::{TcpListener, TcpStream},
    process::{Child, Command},
};
use zeroize::Zeroizing;

const PROJECT: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const OTHER: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const ROUTE: &str = "/v1/project/access/authorize";
const MODULES: [&str; 4] = ["task", "memory", "knowledge", "ast"];
fn block(doc: &str) -> &str {
    doc.split_once("```yaml\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0
}
fn base_yaml(address: SocketAddr, pg: u16) -> String {
    // The listener is local while the configured HTTPS issuer models the public origin.
    let base = block(include_str!("../../../docs/rust-broker-server.md"))
        .replace("127.0.0.1:8080", &address.to_string())
        .replace(
            "  public_url: https://broker.example.test",
            &format!("  public_url: {ISSUER}"),
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
        .replace(
            "  resource: https://broker.example.test/v1",
            &format!("  resource: {RESOURCE}"),
        )
        .replace("\"${BROKER_PEPPER:?required}\"", PEPPER);
    format!(
        "{base}{}{}",
        block(include_str!("../../../docs/rust-oidc-token-exchange.md")).replace(
            "accepted_resources: [https://broker.example.test/v1]",
            &format!("accepted_resources: [{RESOURCE}]")
        ),
        block(include_str!("../../../docs/rust-admin-session-http.md"))
    )
}
fn project_yaml() -> String {
    block(include_str!("../../../docs/rust-project-access-http.md"))
        .replace("required_scopes: []", "required_scopes: [openid]")
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
async fn value(response: reqwest::Response) -> Value {
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}
async fn authorize(
    address: SocketAddr,
    token: &str,
    project: &str,
    module: &str,
    action: &str,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{address}{ROUTE}"))
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body(json!({"project_id":project,"module":module,"action":action}).to_string())
        .send()
        .await
        .unwrap()
}
async fn error(response: reqwest::Response, status: u16, code: &str) {
    assert_eq!(response.status(), status);
    if status == 401 {
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
    }
    assert_eq!(value(response).await, json!({"error":{"code":code}}));
}
async fn clear(f: &mut OidcFixture) {
    f.admin.execute("DELETE FROM public.resource_grants; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
}
async fn grant(f: &mut OidcFixture, id: &str, principal: &str, project: &str, caps: &[String]) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture','subject',$2,'',0,0)")
        .bind(id).bind(principal).execute(&mut f.admin).await.unwrap();
    for cap in caps {
        sqlx_core::query::query(
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
        )
        .bind(id)
        .bind(cap)
        .execute(&mut f.admin)
        .await
        .unwrap();
    }
    sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
        .bind(id)
        .bind(project)
        .execute(&mut f.admin)
        .await
        .unwrap();
    f.admin
        .execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
        .await
        .unwrap();
}
async fn allowed(
    response: reqwest::Response,
    f: &mut OidcFixture,
    subject: &str,
    module: &str,
    action: &str,
) {
    assert_eq!(response.status(), 200);
    let revision: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT revision FROM public.resource_acl_state WHERE id=1",
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(
        value(response).await,
        json!({"subject":{"issuer":ISSUER,"subject":subject},"authorization_revision":revision,"project_id":PROJECT,"module":module,"action":action})
    );
}

#[tokio::test]
#[ignore = "native binary, genuine P3, public JWKS consumer and TLS PostgreSQL ordinary owner"]
async fn broker_project_access_http_contract() {
    let mut f = OidcFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    files(root.path(), &f.fixture.ca);
    let base = base_yaml(addr, f.fixture.port);
    let project = project_yaml();
    let path = write(root.path(), &format!("{base}{project}"));
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
        project.replace("  required_scopes: [openid]\n", ""),
        project.replace("  grants_json_bytes: 65536\n", ""),
        project.replace("  body_bytes: 4096\n", ""),
        project.replace("  request_timeout: 3s\n", ""),
        project.replace("body_bytes: 4096", "body_bytes: 0"),
        project.replace("request_timeout: 3s", "request_timeout: 0s"),
        project.replace(
            "grants_json_bytes: 65536",
            &format!("grants_json_bytes: {}", usize::MAX),
        ),
        project.replace("body_bytes: 4096", &format!("body_bytes: {}", usize::MAX)),
        project.replace("required_scopes: [openid]", "required_scopes: ['']"),
        project.replace("required_scopes: [openid]", "required_scopes: ['a b']"),
        project.replace(
            "  enabled: true",
            "  enabled: true\n  inferred_project: false",
        ),
        project.replace("body_bytes: 4096", "body_bytes: 4096\n  body_bytes: 4097"),
    ] {
        write(root.path(), &format!("{base}{bad}"));
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
    write(root.path(), &format!("{base}{project}"));
    let child = start(&path, addr).await;
    let client = reqwest::Client::new();
    for route in ["/healthz", "/readyz", "/v1/oidc/keys"] {
        assert_eq!(
            client
                .get(format!("http://{addr}{route}"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    let code = f.code(true, true).await;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", "web-client")
        .append_pair("code", code.code())
        .append_pair("redirect_uri", "https://client.example/cb")
        .append_pair("code_verifier", VERIFIER)
        .append_pair("resource", RESOURCE)
        .finish();
    let response = client
        .post(format!("http://{addr}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let tokens = value(response).await;
    let remaining = tokens["expires_in"].as_u64().unwrap();
    assert!(remaining > 0 && remaining <= 600);
    let access = Zeroizing::new(tokens["access_token"].as_str().unwrap().to_owned());
    let token_count = f.token_count().await;
    assert_eq!(
        client
            .get(format!("http://{addr}/admin/api/v1/session"))
            .bearer_auth(&*access)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let jwks = value(
        client
            .get(format!("http://{addr}/v1/oidc/keys"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert!(!jwks.to_string().contains("\"d\""));
    let keys = serde_json::from_value(jwks).unwrap();
    let verifier = Arc::new(
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), &keys, n(8192)).unwrap(),
    );
    let subject = verifier
        .verify(&access, &["openid".into()], deadline())
        .unwrap()
        .subject()
        .to_owned();
    assert_ne!(subject, "alice-subject");
    let principal = format!("{ISSUER}|{subject}");
    clear(&mut f).await;
    error(
        authorize(addr, &access, PROJECT, "task", "read").await,
        403,
        "forbidden",
    )
    .await;

    grant(&mut f, "hub-project", &principal, PROJECT, &["hub".into()]).await;
    allowed(
        authorize(addr, &access, PROJECT, "hub", "read").await,
        &mut f,
        &subject,
        "hub",
        "read",
    )
    .await;
    error(
        authorize(addr, &access, OTHER, "hub", "read").await,
        403,
        "forbidden",
    )
    .await;
    error(
        authorize(addr, &access, PROJECT, "hub", "write").await,
        400,
        "invalid_request",
    )
    .await;
    f.admin
        .execute("DELETE FROM public.resource_grants WHERE id='hub-project'")
        .await
        .unwrap();
    error(
        authorize(addr, &access, PROJECT, "hub", "read").await,
        403,
        "forbidden",
    )
    .await;
    for module in MODULES {
        for action in ["read", "write"] {
            clear(&mut f).await;
            grant(
                &mut f,
                "logical",
                &principal,
                PROJECT,
                &[format!("{module}:{action}")],
            )
            .await;
            allowed(
                authorize(addr, &access, PROJECT, module, action).await,
                &mut f,
                &subject,
                module,
                action,
            )
            .await;
            error(
                authorize(
                    addr,
                    &access,
                    PROJECT,
                    module,
                    if action == "read" { "write" } else { "read" },
                )
                .await,
                403,
                "forbidden",
            )
            .await;
            error(
                authorize(addr, &access, OTHER, module, action).await,
                403,
                "forbidden",
            )
            .await;
        }
    }
    clear(&mut f).await;
    let readonly: Vec<_> = MODULES.iter().map(|m| format!("{m}:read")).collect();
    grant(&mut f, "readonly", &principal, PROJECT, &readonly).await;
    for module in MODULES {
        allowed(
            authorize(addr, &access, PROJECT, module, "read").await,
            &mut f,
            &subject,
            module,
            "read",
        )
        .await;
        error(
            authorize(addr, &access, PROJECT, module, "write").await,
            403,
            "forbidden",
        )
        .await;
    }
    // This separate TCP service takes public trust from the actual native producer.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let consumer = listener.local_addr().unwrap();
    let router = broker_project_authorization_router(
        f.store.clone(),
        verifier.clone(),
        BrokerProjectAuthorizationHttpConfig {
            required_scopes: vec!["openid".into()],
            grants_json_bytes: n(65536),
            body_bytes: n(4096),
            request_timeout: Duration::from_secs(3),
        },
    )
    .unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    allowed(
        authorize(consumer, &access, PROJECT, "memory", "read").await,
        &mut f,
        &subject,
        "memory",
        "read",
    )
    .await;
    clear(&mut f).await;
    for endpoint in [addr, consumer] {
        error(
            authorize(endpoint, &access, PROJECT, "memory", "read").await,
            403,
            "forbidden",
        )
        .await;
        error(
            authorize(
                endpoint,
                tokens["id_token"].as_str().unwrap(),
                PROJECT,
                "memory",
                "read",
            )
            .await,
            401,
            "unauthenticated",
        )
        .await;
        error(
            authorize(endpoint, "not-a-jwt", PROJECT, "memory", "read").await,
            401,
            "unauthenticated",
        )
        .await;
    }
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE, RESOURCE]);
    let claims = decode::<Value>(
        &access,
        &DecodingKey::from_jwk(&keys.keys[0]).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        600
    );
    let foreign_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("configured-key".into());
    let untrusted = Zeroizing::new(
        encode(
            &header,
            &claims,
            &EncodingKey::from_ed_der(&foreign_key.serialize_der()),
        )
        .unwrap(),
    );
    for endpoint in [addr, consumer] {
        error(
            authorize(endpoint, &untrusted, PROJECT, "memory", "read").await,
            401,
            "unauthenticated",
        )
        .await;
    }
    verifier
        .verify(&access, &[], deadline())
        .unwrap()
        .check()
        .unwrap();
    grant(&mut f, "restored", &principal, PROJECT, &readonly).await;
    for endpoint in [addr, consumer] {
        allowed(
            authorize(endpoint, &access, PROJECT, "memory", "read").await,
            &mut f,
            &subject,
            "memory",
            "read",
        )
        .await;
    }
    clear(&mut f).await;
    grant(
        &mut f,
        "different",
        "local|alice-subject",
        PROJECT,
        &readonly,
    )
    .await;
    grant(&mut f, "other-project", &principal, OTHER, &readonly).await;
    error(
        authorize(addr, &access, PROJECT, "memory", "read").await,
        403,
        "forbidden",
    )
    .await;
    // A genuine issuer with a different key cannot supply configured trust.
    let other = files(tempfile::tempdir().unwrap().path(), &f.fixture.ca);
    let wrong =
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), other.jwks(), n(8192)).unwrap();
    assert!(wrong.verify(&access, &[], deadline()).is_err());
    assert!(
        BrokerAccessVerifier::new(
            "https://other.example",
            AUDIENCE,
            Some(RESOURCE),
            &keys,
            n(8192)
        )
        .unwrap()
        .verify(&access, &[], deadline())
        .is_err()
    );
    assert!(
        BrokerAccessVerifier::new(ISSUER, "other-api", Some(RESOURCE), &keys, n(8192))
            .unwrap()
            .verify(&access, &[], deadline())
            .is_err()
    );
    // Input and method limits continue to be enforced by the mounted factory.
    error(
        client
            .get(format!("http://{addr}{ROUTE}"))
            .send()
            .await
            .unwrap(),
        405,
        "method_not_allowed",
    )
    .await;
    error(
        authorize(addr, &access, AUDIENCE, "task", "read").await,
        400,
        "invalid_request",
    )
    .await;
    for raw in [
        "{}".to_owned(),
        format!(
            "{{\"project_id\":\"{PROJECT}\",\"module\":\"task\",\"action\":\"read\",\"unknown\":true}}"
        ),
    ] {
        error(
            client
                .post(format!("http://{addr}{ROUTE}"))
                .bearer_auth(&*access)
                .header("content-type", "application/json")
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
        client
            .post(format!("http://{addr}{ROUTE}"))
            .bearer_auth(&*access)
            .header("content-type", "application/json")
            .body("x".repeat(4097))
            .send()
            .await
            .unwrap(),
        413,
        "body_too_large",
    )
    .await;
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .unwrap()
        .unwrap();
    stop(child).await;
    // Omitted/false route stays unmounted; missing required scopes denies on the actual server.
    for section in [
        String::new(),
        "project_access:\n  enabled: false\n".into(),
        project.replace("[openid]", "[project-sdk]"),
    ] {
        write(root.path(), &format!("{base}{section}"));
        let child = start(&path, addr).await;
        let response = authorize(addr, &access, PROJECT, "task", "read").await;
        if section.contains("project-sdk") {
            error(response, 403, "insufficient_scope").await;
        } else {
            assert_eq!(response.status(), 404);
        }
        stop(child).await;
    }
    assert_eq!(f.token_count().await, token_count);
    f.close().await;
}
