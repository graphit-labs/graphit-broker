//! Shared native Broker process and token HTTP fixture; no protocol authority.
use crate::{
    oidc::{AUDIENCE, PEPPER, RESOURCE},
    support::deadline,
};
use broker_control::BrokerAccessIssuer;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use rcgen::KeyPair;
use serde_json::Value;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::process::{Child, Command};
use zeroize::Zeroizing;
pub fn block(doc: &str) -> &str {
    doc.split_once("```yaml\n")
        .or_else(|| doc.split_once("```yaml\r\n"))
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0
}
pub fn yaml(address: SocketAddr, pg: u16) -> String {
    let base = block(include_str!("../../../../docs/rust-broker-server.md"))
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
            &format!("  issuer: http://{address}"),
        )
        .replace(
            "  audience: storage-api",
            &format!("  audience: {AUDIENCE}"),
        )
        .replace("  resource: https://broker.example.test/v1\n", "")
        .replace("\"${BROKER_PEPPER:?required}\"", PEPPER);
    format!(
        "{base}{}",
        block(include_str!("../../../../docs/rust-oidc-token-exchange.md")).replace(
            "accepted_resources: [https://broker.example.test/v1]",
            &format!("accepted_resources: [{RESOURCE}]")
        )
    )
}
pub fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
pub fn files(root: &Path, ca: &[u8], expected_issuer: &str) -> BrokerAccessIssuer {
    std::fs::write(root.join("ca.pem"), ca).unwrap();
    signing_key(root, expected_issuer)
}
pub fn signing_key(root: &Path, expected_issuer: &str) -> BrokerAccessIssuer {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let der = Zeroizing::new(key.serialize_der());
    std::fs::write(root.join("signing.pk8"), &der).unwrap();
    BrokerAccessIssuer::new(expected_issuer, AUDIENCE, "configured-key", &der).unwrap()
}
pub fn write(root: &Path, yaml: &str) -> PathBuf {
    let path = root.join("config.yaml");
    std::fs::write(&path, yaml).unwrap();
    path
}
pub fn command() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphit-broker"));
    c.kill_on_drop(true);
    c
}
pub async fn start(path: &Path, address: SocketAddr) -> Child {
    let mut child = command()
        .args(["--config", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let end = deadline();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    loop {
        if client
            .get(format!("http://{address}/readyz"))
            .send()
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
pub async fn stop(mut child: Child) {
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
    assert!(exit.success(), "native Broker shutdown exit: {exit}");
    #[cfg(not(unix))]
    let _ = exit;
}
pub async fn post(address: SocketAddr, body: String, origin: Option<&str>) -> reqwest::Response {
    let request = reqwest::Client::new()
        .post(format!("http://{address}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body);
    match origin {
        Some(origin) => request.header("origin", origin),
        None => request,
    }
    .send()
    .await
    .unwrap()
}
pub async fn value(response: reqwest::Response) -> Value {
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}
pub fn claims(issuer: &BrokerAccessIssuer, expected_issuer: &str, raw: &str) -> Value {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&[expected_issuer]);
    decode::<Value>(
        raw,
        &DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap(),
        &validation,
    )
    .unwrap()
    .claims
}
