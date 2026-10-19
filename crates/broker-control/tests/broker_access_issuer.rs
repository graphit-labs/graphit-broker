use broker_control::{
    BrokerAccessError, BrokerAccessIssueError, BrokerAccessIssuer, BrokerAccessTokenInput,
    BrokerAccessVerifier, BrokerIdTokenInput,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;
use std::{
    num::NonZeroUsize,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ISSUER: &str = "https://broker.invalid";
const API: &str = "graphit-broker";
const RESOURCE: &str = "https://broker.invalid/v1";
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn pair() -> rcgen::KeyPair {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap()
}
fn owner(pair: &rcgen::KeyPair) -> BrokerAccessIssuer {
    BrokerAccessIssuer::new(ISSUER, API, "configured-kid", &pair.serialize_der()).unwrap()
}
fn input<'a>() -> BrokerAccessTokenInput<'a> {
    let iat = now();
    BrokerAccessTokenInput {
        subject: "broker-subject",
        client_id: "web-client",
        resource: Some(RESOURCE),
        scope: "openid profile offline_access",
        jti: "explicit-jti",
        issued_at: iat,
        expires_at: iat + 600,
        preferred_username: None,
        name: None,
        email: None,
        organization: None,
        groups: &[],
        roles: &[],
    }
}
fn verifier(issuer: &BrokerAccessIssuer, resource: &str) -> BrokerAccessVerifier {
    BrokerAccessVerifier::new(
        ISSUER,
        API,
        Some(resource),
        issuer.jwks(),
        NonZeroUsize::new(8192).unwrap(),
    )
    .unwrap()
}
fn claims(issuer: &BrokerAccessIssuer, token: &str) -> Value {
    let key = DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap();
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.set_audience(&[API]);
    validation.set_issuer(&[ISSUER]);
    decode::<Value>(token, &key, &validation).unwrap().claims
}
#[test]
fn sdk_key_owner_public_jwks_and_real_verifier_roundtrip() {
    let pair = pair();
    let owner = owner(&pair);
    let jwks = serde_json::to_value(owner.jwks()).unwrap();
    let jwk = &jwks["keys"][0];
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["kid"], "configured-kid");
    assert_eq!(jwk["alg"], "EdDSA");
    assert_eq!(jwk["use"], "sig");
    assert_eq!(jwk["key_ops"], serde_json::json!(["verify"]));
    assert!(jwk.get("d").is_none());
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    assert_eq!(
        URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap(),
        pair.public_key_raw()
    );
    let token = owner.sign_access(input(), deadline()).unwrap();
    let header = decode_header(&token).unwrap();
    assert_eq!(header.alg, Algorithm::EdDSA);
    assert_eq!(header.kid.as_deref(), Some("configured-kid"));
    let verifier = verifier(&owner, RESOURCE);
    let proof = verifier
        .verify(&token, &["openid".into()], deadline())
        .unwrap();
    assert_eq!(proof.issuer(), ISSUER);
    assert_eq!(proof.subject(), "broker-subject");
    assert_eq!(proof.client_id(), "web-client");
    proof.check().unwrap();
    let claims = claims(&owner, &token);
    assert_eq!(claims["token_use"], "access");
    assert_eq!(claims["jti"], "explicit-jti");
    assert_eq!(claims["aud"], serde_json::json!([API, RESOURCE]));
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        600
    );
    for absent in [
        "resource",
        "nbf",
        "preferred_username",
        "name",
        "email",
        "organization",
        "groups",
        "roles",
    ] {
        assert!(claims.get(absent).is_none());
    }
}
#[test]
fn explicit_attributes_and_audience_deduplication_preserve_values() {
    let owner = owner(&pair());
    let groups = vec!["engineering".into(), "security".into()];
    let roles = vec!["viewer".into()];
    let mut data = input();
    data.resource = Some(API);
    data.scope = "";
    data.preferred_username = Some("operator");
    data.name = Some("Example Operator");
    data.email = Some("operator@example.invalid");
    data.organization = Some("");
    data.groups = &groups;
    data.roles = &roles;
    let token = owner.sign_access(data, deadline()).unwrap();
    let claims = claims(&owner, &token);
    assert_eq!(claims["aud"], serde_json::json!([API]));
    assert_eq!(claims["scope"], "");
    assert_eq!(claims["name"], "Example Operator");
    assert_eq!(claims["email"], "operator@example.invalid");
    assert_eq!(claims["organization"], "");
    assert_eq!(claims["groups"], serde_json::json!(groups));
    assert_eq!(claims["roles"], serde_json::json!(roles));
    let verifier = verifier(&owner, API);
    let proof = verifier.verify(&token, &[], deadline()).unwrap();
    assert_eq!(proof.username(), Some("operator"));
    assert_eq!(proof.organization(), Some(""));
    assert_eq!(proof.teams(), groups);
    assert!(proof.scopes().is_empty());
}
#[test]
fn empty_username_remains_signed_and_verifier_normalizes_it() {
    let owner = owner(&pair());
    let mut data = input();
    data.preferred_username = Some("");
    let token = owner.sign_access(data, deadline()).unwrap();
    assert_eq!(claims(&owner, &token)["preferred_username"], "");
    assert_eq!(
        verifier(&owner, RESOURCE)
            .verify(&token, &[], deadline())
            .unwrap()
            .username(),
        None
    );
}
#[test]
fn sdk_rejects_non_pkcs8_truncated_wrong_algorithm_and_blank_configuration() {
    let pair = pair();
    let der = pair.serialize_der();
    let ec = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .serialize_der();
    for invalid in [
        &[][..],
        &der[..der.len() - 1],
        pair.public_key_raw(),
        &[7; 32][..],
        &ec,
    ] {
        assert_eq!(
            BrokerAccessIssuer::new(ISSUER, API, "kid", invalid).unwrap_err(),
            BrokerAccessIssueError::InvalidConfiguration
        );
    }
    for (issuer, api, kid) in [
        ("", API, "kid"),
        (" ", API, "kid"),
        (ISSUER, "", "kid"),
        (
            ISSUER, API, "
 ",
        ),
    ] {
        assert_eq!(
            BrokerAccessIssuer::new(issuer, api, kid, &der).unwrap_err(),
            BrokerAccessIssueError::InvalidConfiguration
        );
    }
}
#[test]
fn invalid_claims_and_numeric_date_overflow_never_emit() {
    let owner = owner(&pair());
    for case in 0..9 {
        let mut data = input();
        match case {
            0 => data.subject = "",
            1 => data.client_id = "",
            2 => data.resource = Some(" "),
            3 => data.jti = "",
            4 => data.issued_at = now() + 60,
            5 => data.expires_at = data.issued_at,
            6 => data.expires_at = now().saturating_sub(1),
            7 => data.expires_at = u64::MAX,
            _ => data.expires_at = 0,
        }
        assert_eq!(
            issue_failure(owner.sign_access(data, deadline())),
            BrokerAccessIssueError::InvalidClaims
        );
    }
}
#[test]
fn deadline_has_precedence_over_invalid_claims() {
    let owner = owner(&pair());
    let mut data = input();
    data.subject = "";
    assert_eq!(
        issue_failure(owner.sign_access(data, Instant::now() - Duration::from_secs(1))),
        BrokerAccessIssueError::Deadline
    );
}
#[test]
fn actual_signature_rejects_tampering_wrong_trust_and_wrong_resource() {
    let owner = owner(&pair());
    let token = owner.sign_access(input(), deadline()).unwrap();
    let verifier = verifier(&owner, RESOURCE);
    let mut tampered = token.clone().into_bytes();
    let offset = token.rfind('.').unwrap() + 1;
    tampered[offset] = if tampered[offset] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        verifier
            .verify(std::str::from_utf8(&tampered).unwrap(), &[], deadline())
            .unwrap_err(),
        BrokerAccessError::InvalidToken
    );
    let other = owner_for_other_key();
    assert_eq!(
        other.verify(&token, &[], deadline()).unwrap_err(),
        BrokerAccessError::InvalidToken
    );
    assert_eq!(
        verifier_for_wrong_resource(&owner)
            .verify(&token, &[], deadline())
            .unwrap_err(),
        BrokerAccessError::InvalidToken
    );
}
fn owner_for_other_key() -> BrokerAccessVerifier {
    verifier(&owner(&pair()), RESOURCE)
}
fn verifier_for_wrong_resource(owner: &BrokerAccessIssuer) -> BrokerAccessVerifier {
    verifier(owner, "https://other.invalid/v1")
}
#[test]
fn owner_input_and_errors_are_redacted() {
    let pair = pair();
    let owner = owner(&pair);
    assert_eq!(format!("{owner:?}"), "BrokerAccessIssuer([REDACTED])");
    assert_eq!(
        format!("{:?}", input()),
        "BrokerAccessTokenInput([REDACTED])"
    );
    for error in [
        BrokerAccessIssueError::InvalidConfiguration,
        BrokerAccessIssueError::InvalidClaims,
        BrokerAccessIssueError::Signing,
        BrokerAccessIssueError::Deadline,
    ] {
        assert!(!error.to_string().contains("subject"));
        assert!(!error.to_string().contains("configured-kid"));
    }
}

#[test]
fn emitted_access_expires_in_the_real_verifier() {
    let owner = owner(&pair());
    let mut data = input();
    data.expires_at = data.issued_at + 3;
    let token = owner.sign_access(data, deadline()).unwrap();
    let verifier = verifier(&owner, RESOURCE);
    verifier.verify(&token, &[], deadline()).unwrap();
    std::thread::sleep(Duration::from_millis(3100));
    assert_eq!(
        verifier.verify(&token, &[], deadline()).unwrap_err(),
        BrokerAccessError::Expired
    );
}

fn issue_failure(result: Result<String, BrokerAccessIssueError>) -> BrokerAccessIssueError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("unexpected bearer issuance"),
    }
}

#[test]
fn optional_resource_issues_api_only_without_inventing_a_target() {
    let owner = owner(&pair());
    let mut data = input();
    data.resource = None;
    let token = owner.sign_access(data, deadline()).unwrap();
    assert_eq!(claims(&owner, &token)["aud"], serde_json::json!([API]));
    let unbound = BrokerAccessVerifier::new(
        ISSUER,
        API,
        None,
        owner.jwks(),
        NonZeroUsize::new(8192).unwrap(),
    )
    .unwrap();
    unbound.verify(&token, &[], deadline()).unwrap();
    assert_eq!(
        verifier(&owner, RESOURCE)
            .verify(&token, &[], deadline())
            .unwrap_err(),
        BrokerAccessError::InvalidToken
    );
}

#[test]
fn id_token_uses_same_configured_key_and_binds_real_access_and_code() {
    let owner = owner(&pair());
    let access = owner.sign_access(input(), deadline()).unwrap();
    let amr = vec!["pwd".to_owned(), "otp".to_owned()];
    let iat = now();
    let make = |nonce| BrokerIdTokenInput {
        subject: "broker-subject",
        client_id: "web-client",
        resource: Some(RESOURCE),
        issued_at: iat,
        expires_at: iat + 600,
        auth_time: iat - 10,
        amr: &amr,
        nonce,
        access_token: &access,
        code: Some("admitted-code"),
        preferred_username: Some("operator"),
        name: Some("Operator"),
        email: Some("operator@example.invalid"),
        organization: None,
        groups: &[],
        roles: &[],
    };
    let token = owner
        .sign_id(make(Some("literal nonce")), deadline())
        .unwrap();
    let id = claims(&owner, &token);
    assert_eq!(
        decode_header(&token).unwrap().kid,
        decode_header(&access).unwrap().kid
    );
    assert_eq!(id["aud"], serde_json::json!([API, RESOURCE, "web-client"]));
    assert_eq!(id["azp"], "web-client");
    assert_eq!(id["client_id"], "web-client");
    assert_eq!(id["auth_time"], iat - 10);
    assert_eq!(id["amr"], serde_json::json!(["pwd", "otp"]));
    assert_eq!(id["nonce"], "literal nonce");
    // Independent SHA-512/base64url vector for the literal code.
    assert_eq!(id["c_hash"], "paHfG0_CKtRKNuDmcV1WJyzlOwLJPrRI68GccnK4-vE");
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha512};
    assert_eq!(
        id["at_hash"],
        URL_SAFE_NO_PAD.encode(&Sha512::digest(access.as_bytes())[..32])
    );
    assert!(id.get("token_use").is_none());
    assert_eq!(
        verifier(&owner, RESOURCE)
            .verify(&token, &[], deadline())
            .unwrap_err(),
        BrokerAccessError::InvalidToken
    );
    let mut without = make(Some(""));
    without.resource = Some(API);
    assert!(
        claims(&owner, &owner.sign_id(without, deadline()).unwrap())
            .get("nonce")
            .is_none()
    );
    let mut invalid = make(None);
    invalid.code = Some("");
    assert_eq!(
        issue_failure(owner.sign_id(invalid, deadline())),
        BrokerAccessIssueError::InvalidClaims
    );
    let mut refreshed = make(None);
    refreshed.code = None;
    let canonical = vec!["local-token".to_owned()];
    refreshed.amr = &canonical;
    let refreshed = claims(&owner, &owner.sign_id(refreshed, deadline()).unwrap());
    assert!(refreshed.get("c_hash").is_none());
    assert!(refreshed.get("nonce").is_none());
    assert_eq!(refreshed["amr"], serde_json::json!(["local-token"]));
    assert_eq!(refreshed["at_hash"], id["at_hash"]);
    let mut invalid = make(None);
    invalid.auth_time = iat + 100;
    assert_eq!(
        issue_failure(owner.sign_id(invalid, deadline())),
        BrokerAccessIssueError::InvalidClaims
    );
    assert_eq!(
        issue_failure(owner.sign_id(make(None), Instant::now())),
        BrokerAccessIssueError::Deadline
    );
}
