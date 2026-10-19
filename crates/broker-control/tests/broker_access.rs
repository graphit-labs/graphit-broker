use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{BrokerAccessError, BrokerAccessVerifier};
use jsonwebtoken::{Algorithm, EncodingKey, Header, crypto::sign, encode, jwk::JwkSet};
use serde_json::{Value, json};
use std::{
    num::NonZeroUsize,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ISSUER: &str = "https://broker.example.test";
const API: &str = "graphit-api";
const RESOURCE: &str = "https://broker.example.test/v1/project";
const KID: &str = "key-one";

struct Signer {
    encoding: EncodingKey,
    jwk: Value,
}
impl Signer {
    fn new(kid: &str) -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self {
            encoding: EncodingKey::from_ed_der(&pair.serialize_der()),
            jwk: json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw()),
                "kid":kid,"alg":"EdDSA","use":"sig","key_ops":["verify"]}),
        }
    }
    fn keys(&self) -> JwkSet {
        serde_json::from_value(json!({"keys":[self.jwk.clone()]})).unwrap()
    }
    fn token(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = self.jwk["kid"].as_str().map(str::to_owned);
        encode(&header, claims, &self.encoding).unwrap()
    }
    fn raw(&self, header: &str, payload: &str) -> String {
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature = sign(message.as_bytes(), &self.encoding, Algorithm::EdDSA).unwrap();
        format!("{message}.{signature}")
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn claims() -> Value {
    let time = now();
    json!({"iss":ISSUER,"sub":"broker-subject","aud":[API,RESOURCE],"iat":time-1,"exp":time+600,
        "token_use":"access","client_id":"approved-client","jti":"token-id",
        "scope":"project:read project:write","preferred_username":"alice",
        "organization":"engineering","groups":["platform"],"roles":["superuser"]})
}
fn verifier(signer: &Signer) -> BrokerAccessVerifier {
    BrokerAccessVerifier::new(
        ISSUER,
        API,
        Some(RESOURCE),
        &signer.keys(),
        NonZeroUsize::new(8192).unwrap(),
    )
    .unwrap()
}
fn invalid(verifier: &BrokerAccessVerifier, token: &str) {
    assert_eq!(
        verifier.verify(token, &[], deadline()).unwrap_err(),
        BrokerAccessError::InvalidToken
    );
}

#[test]
fn optional_resource_preserves_api_audience_and_access_checks() {
    let signer = Signer::new(KID);
    let optional = BrokerAccessVerifier::new(
        ISSUER,
        API,
        None,
        &signer.keys(),
        NonZeroUsize::new(8192).unwrap(),
    )
    .unwrap();
    let required = verifier(&signer);
    for audience in [json!(API), json!([API]), json!([API, "other-resource"])] {
        let mut value = claims();
        value["aud"] = audience;
        let token = signer.token(&value);
        let proof = optional.verify(&token, &[], deadline()).unwrap();
        assert_eq!(proof.issuer(), ISSUER);
        assert_eq!(proof.subject(), "broker-subject");
        invalid(&required, &token);
    }
    optional
        .verify(&signer.token(&claims()), &[], deadline())
        .unwrap();
    for audience in [
        json!(RESOURCE),
        json!([RESOURCE]),
        json!([API, API]),
        json!([API, ""]),
        json!([API, 1]),
        json!([]),
        json!(null),
        json!(""),
    ] {
        let mut value = claims();
        value["aud"] = audience;
        invalid(&optional, &signer.token(&value));
    }
    let mut missing = claims();
    missing.as_object_mut().unwrap().remove("aud");
    invalid(&optional, &signer.token(&missing));
    for (field, bad) in [
        ("iss", json!("other-issuer")),
        ("token_use", json!("id")),
        ("client_id", json!("")),
        ("jti", json!("")),
        ("sub", json!("")),
        ("iat", json!(now() + 60)),
        ("nbf", json!(now() + 60)),
    ] {
        let mut value = claims();
        value[field] = bad;
        invalid(&optional, &signer.token(&value));
    }
    invalid(&optional, &Signer::new(KID).token(&claims()));
    let mut expired = claims();
    expired["iat"] = json!(now() - 60);
    expired["exp"] = json!(now() - 1);
    assert_eq!(
        optional
            .verify(&signer.token(&expired), &[], deadline())
            .unwrap_err(),
        BrokerAccessError::Expired
    );
    assert_eq!(
        optional
            .verify(&signer.token(&claims()), &["missing".into()], deadline())
            .unwrap_err(),
        BrokerAccessError::InsufficientScope
    );
    assert_eq!(
        optional
            .verify(&signer.token(&claims()), &[], Instant::now())
            .unwrap_err(),
        BrokerAccessError::Deadline
    );
    for resource in ["", " \t"] {
        assert_eq!(
            BrokerAccessVerifier::new(
                ISSUER,
                API,
                Some(resource),
                &signer.keys(),
                NonZeroUsize::new(8192).unwrap()
            )
            .unwrap_err(),
            BrokerAccessError::InvalidConfiguration
        );
    }
}

#[test]
fn signed_identity_attributes_and_explicit_scopes() {
    let signer = Signer::new(KID);
    let verifier = verifier(&signer);
    let proof = verifier
        .verify(
            &signer.token(&claims()),
            &["project:read".into()],
            deadline(),
        )
        .unwrap();
    assert_eq!(proof.issuer(), ISSUER);
    assert_eq!(proof.subject(), "broker-subject");
    assert_eq!(proof.client_id(), "approved-client");
    assert_eq!(proof.username(), Some("alice"));
    assert_eq!(proof.organization(), Some("engineering"));
    assert_eq!(proof.teams(), ["platform"]);
    assert_eq!(proof.scopes(), ["project:read", "project:write"]);
    assert!(proof.expires_at() > SystemTime::now());
    proof.check().unwrap();
    assert_eq!(format!("{proof:?}"), "VerifiedBrokerAccess([REDACTED])");
    assert_eq!(format!("{verifier:?}"), "BrokerAccessVerifier([REDACTED])");
    let mut value = claims();
    value["client_id"] = json!("another-issuer-approved-client");
    verifier
        .verify(&signer.token(&value), &[], deadline())
        .unwrap();
}

#[test]
fn optional_attributes_and_broker_header_purpose() {
    let signer = Signer::new(KID);
    let verifier = verifier(&signer);
    let mut value = claims();
    for field in ["preferred_username", "organization", "groups"] {
        value.as_object_mut().unwrap().remove(field);
    }
    let proof = verifier
        .verify(&signer.token(&value), &[], deadline())
        .unwrap();
    assert_eq!(proof.username(), None);
    assert_eq!(proof.organization(), None);
    assert!(proof.teams().is_empty());
    value["preferred_username"] = Value::Null;
    value["organization"] = Value::Null;
    verifier
        .verify(&signer.token(&value), &[], deadline())
        .unwrap();
    value["preferred_username"] = json!("");
    value["organization"] = json!("");
    let proof = verifier
        .verify(&signer.token(&value), &[], deadline())
        .unwrap();
    assert_eq!(proof.username(), None);
    assert_eq!(proof.organization(), Some(""));
    let payload = value.to_string();
    for header in [
        r#"{"alg":"EdDSA","kid":"key-one"}"#,
        r#"{"alg":"EdDSA","kid":"key-one","typ":"JWT"}"#,
    ] {
        verifier
            .verify(&signer.raw(header, &payload), &[], deadline())
            .unwrap();
    }
}

#[test]
fn issuer_subject_audience_resource_and_required_claims() {
    let signer = Signer::new(KID);
    let verifier = verifier(&signer);
    for field in [
        "iss",
        "sub",
        "aud",
        "iat",
        "exp",
        "token_use",
        "client_id",
        "jti",
        "scope",
    ] {
        let mut value = claims();
        value.as_object_mut().unwrap().remove(field);
        invalid(&verifier, &signer.token(&value));
    }
    for (field, bad) in [
        ("iss", json!("https://other.test")),
        ("iss", json!(format!("{ISSUER}/"))),
        ("sub", json!("")),
        ("token_use", json!("id")),
        ("client_id", json!("")),
        ("jti", json!("")),
        ("aud", json!([API])),
        ("aud", json!([RESOURCE])),
        ("aud", json!(API)),
        ("aud", json!([API, RESOURCE, API])),
        ("aud", json!([])),
        ("aud", json!([API, RESOURCE, ""])),
        ("aud", json!([API, 42])),
        ("aud", Value::Null),
    ] {
        let mut value = claims();
        value[field] = bad;
        invalid(&verifier, &signer.token(&value));
    }
    let one = BrokerAccessVerifier::new(
        ISSUER,
        API,
        Some(API),
        &signer.keys(),
        NonZeroUsize::new(8192).unwrap(),
    )
    .unwrap();
    let mut value = claims();
    value["aud"] = json!(API);
    one.verify(&signer.token(&value), &[], deadline()).unwrap();
    value["aud"] = json!([API, RESOURCE, "extra-audience"]);
    verifier
        .verify(&signer.token(&value), &[], deadline())
        .unwrap();
}

#[test]
fn crypto_tamper_unknown_key_and_unsigned_algorithm_rejected() {
    let signer = Signer::new(KID);
    let other = Signer::new(KID);
    let verifier = verifier(&signer);
    invalid(&verifier, &other.token(&claims()));
    let value = claims();
    let token = signer.token(&value);
    let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
    let mut changed = value.clone();
    changed["sub"] = json!("forged");
    parts[1] = URL_SAFE_NO_PAD.encode(changed.to_string());
    invalid(&verifier, &parts.join("."));
    invalid(
        &verifier,
        &signer.raw(r#"{"alg":"EdDSA","kid":"unknown"}"#, &value.to_string()),
    );
    invalid(
        &verifier,
        &format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none","kid":"key-one"}"#),
            URL_SAFE_NO_PAD.encode(value.to_string())
        ),
    );
    let mut hmac = Header::new(Algorithm::HS256);
    hmac.kid = Some(KID.into());
    invalid(
        &verifier,
        &encode(
            &hmac,
            &value,
            &EncodingKey::from_secret(b"test-only-hmac-key"),
        )
        .unwrap(),
    );
    for header in [
        r#"{"alg":"none","kid":"key-one"}"#,
        r#"{"alg":"HS256","kid":"key-one"}"#,
        r#"{"alg":"RS256","kid":"key-one"}"#,
        r#"{"alg":null,"kid":"key-one"}"#,
        r#"{"alg":"EdDSA","kid":""}"#,
        r#"{"alg":"EdDSA"}"#,
        r#"{"alg":"EdDSA","kid":null}"#,
        r#"{"alg":"EdDSA","kid":42}"#,
        r#"{"alg":"EdDSA","kid":"key-one","typ":42}"#,
    ] {
        invalid(&verifier, &signer.raw(header, &value.to_string()));
    }
}

#[test]
fn forbidden_header_presence_even_null_and_root_codec() {
    let signer = Signer::new(KID);
    let verifier = verifier(&signer);
    for field in ["crit", "b64", "jku", "x5u", "jwk", "x5c"] {
        for bad in [
            Value::Null,
            json!(false),
            json!("https://untrusted.test"),
            json!([]),
            json!({}),
        ] {
            let mut header = json!({"alg":"EdDSA","kid":KID});
            header[field] = bad;
            invalid(
                &verifier,
                &signer.raw(&header.to_string(), &claims().to_string()),
            );
        }
    }
    for header in [
        r#"{"alg":"EdDSA","alg":"EdDSA","kid":"key-one"}"#,
        r#"{"alg":"EdDSA","kid":"key-one","x":0,"x":1}"#,
        r#"["EdDSA","key-one"]"#,
        r#"{"alg":"EdDSA","kid":"key-one"} {}"#,
        r#"{"alg":"EdDSA""#,
    ] {
        invalid(&verifier, &signer.raw(header, &claims().to_string()));
    }
    for token in [
        "", ".", "..", "a.b.c.d", ".b.c", "a..c", "a.b.", "%%%%.b.c", "a.b.%%%%",
    ] {
        invalid(&verifier, token);
    }
}

#[test]
fn malformed_claim_types_dates_and_payload_objects_fail_closed() {
    let signer = Signer::new(KID);
    let verifier = verifier(&signer);
    for (field, bad) in [
        ("iss", Value::Null),
        ("sub", json!(42)),
        ("scope", json!(["project:read"])),
        ("client_id", json!({})),
        ("jti", json!(false)),
        ("token_use", json!(42)),
        ("preferred_username", json!(42)),
        ("organization", json!([])),
        ("groups", Value::Null),
        ("groups", json!("platform")),
        ("groups", json!(["platform", 42])),
    ] {
        let mut value = claims();
        value[field] = bad;
        invalid(&verifier, &signer.token(&value));
    }
    for field in ["iat", "exp", "nbf"] {
        for bad in [
            Value::Null,
            json!(-1),
            json!(1.5),
            json!("42"),
            json!([]),
            json!({}),
        ] {
            let mut value = claims();
            value[field] = bad;
            invalid(&verifier, &signer.token(&value));
        }
    }
    let payload_value = claims();
    let payload = payload_value.to_string();
    let duplicated = format!("{},\"sub\":\"forged\"}}", &payload[..payload.len() - 1]);
    let extension = format!(
        "{},\"extension\":0,\"extension\":1}}",
        &payload[..payload.len() - 1]
    );
    for malformed in [
        duplicated,
        extension,
        format!("[{payload}]"),
        format!("{payload} {{}}"),
        "{".into(),
        payload.replace(
            &format!("\"exp\":{}", payload_value["exp"]),
            "\"exp\":18446744073709551616",
        ),
    ] {
        invalid(
            &verifier,
            &signer.raw(r#"{"alg":"EdDSA","kid":"key-one"}"#, &malformed),
        );
    }
}

#[test]
fn times_have_zero_leeway_and_checked_expiry() {
    let signer = Signer::new(KID);
    let verifier = verifier(&signer);
    let mut value = claims();
    value["nbf"] = json!(now() - 1);
    verifier
        .verify(&signer.token(&value), &[], deadline())
        .unwrap();
    value["nbf"] = json!(now() + 60);
    invalid(&verifier, &signer.token(&value));
    value = claims();
    value["iat"] = json!(now() + 60);
    invalid(&verifier, &signer.token(&value));
    value = claims();
    value["exp"] = value["iat"].clone();
    assert_eq!(
        verifier
            .verify(&signer.token(&value), &[], deadline())
            .unwrap_err(),
        BrokerAccessError::Expired
    );
    value = claims();
    value["exp"] = json!(u64::MAX);
    invalid(&verifier, &signer.token(&value));
    value = claims();
    value["iat"] = json!(now() - 20);
    value["exp"] = json!(now() - 1);
    assert_eq!(
        verifier
            .verify(&signer.token(&value), &[], deadline())
            .unwrap_err(),
        BrokerAccessError::Expired
    );
    value["exp"] = json!(now());
    assert_eq!(
        verifier
            .verify(&signer.token(&value), &[], deadline())
            .unwrap_err(),
        BrokerAccessError::Expired
    );
}

#[test]
fn local_proof_expires_and_original_deadline_is_not_renewed() {
    let signer = Signer::new(KID);
    let verifier = verifier(&signer);
    let token = signer.token(&claims());
    assert_eq!(
        verifier.verify(&token, &[], Instant::now()).unwrap_err(),
        BrokerAccessError::Deadline
    );
    let proof = verifier
        .verify(&token, &[], Instant::now() + Duration::from_millis(30))
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(proof.check().unwrap_err(), BrokerAccessError::Deadline);
    let mut value = claims();
    value["exp"] = json!(now() + 2);
    let proof = verifier
        .verify(&signer.token(&value), &[], deadline())
        .unwrap();
    let wait = proof
        .expires_at()
        .duration_since(SystemTime::now())
        .unwrap_or_default()
        + Duration::from_millis(30);
    std::thread::sleep(wait);
    assert_eq!(proof.check().unwrap_err(), BrokerAccessError::Expired);
}

#[test]
fn scopes_are_explicit_literal_and_do_not_imply_read_from_write() {
    let signer = Signer::new(KID);
    let verifier = verifier(&signer);
    let mut value = claims();
    value["scope"] = json!("project:write");
    assert_eq!(
        verifier
            .verify(&signer.token(&value), &["project:read".into()], deadline())
            .unwrap_err(),
        BrokerAccessError::InsufficientScope
    );
    assert_eq!(
        verifier
            .verify(&signer.token(&value), &["PROJECT:write".into()], deadline())
            .unwrap_err(),
        BrokerAccessError::InsufficientScope
    );
    value["scope"] = json!("  project:read  project:write ");
    verifier
        .verify(
            &signer.token(&value),
            &["project:read".into(), "project:write".into()],
            deadline(),
        )
        .unwrap();
    value["scope"] = json!("");
    let proof = verifier
        .verify(&signer.token(&value), &[], deadline())
        .unwrap();
    assert!(proof.scopes().is_empty());
    for required in ["", " ", "project:read project:write"] {
        assert_eq!(
            verifier
                .verify(&signer.token(&value), &[required.into()], deadline())
                .unwrap_err(),
            BrokerAccessError::InvalidConfiguration
        );
    }
}

#[test]
fn exact_raw_limit_and_explicit_configuration() {
    let signer = Signer::new(KID);
    let token = signer.token(&claims());
    let exact = BrokerAccessVerifier::new(
        ISSUER,
        API,
        Some(RESOURCE),
        &signer.keys(),
        NonZeroUsize::new(token.len()).unwrap(),
    )
    .unwrap();
    exact.verify(&token, &[], deadline()).unwrap();
    let short = BrokerAccessVerifier::new(
        ISSUER,
        API,
        Some(RESOURCE),
        &signer.keys(),
        NonZeroUsize::new(token.len() - 1).unwrap(),
    )
    .unwrap();
    invalid(&short, &token);
    for (issuer, api, resource) in [
        ("", API, RESOURCE),
        (ISSUER, " ", RESOURCE),
        (ISSUER, API, ""),
    ] {
        assert_eq!(
            BrokerAccessVerifier::new(
                issuer,
                api,
                Some(resource),
                &signer.keys(),
                NonZeroUsize::new(8192).unwrap()
            )
            .unwrap_err(),
            BrokerAccessError::InvalidConfiguration
        );
    }
    assert_eq!(
        BrokerAccessVerifier::new(
            ISSUER,
            API,
            Some(RESOURCE),
            &JwkSet { keys: vec![] },
            NonZeroUsize::new(8192).unwrap()
        )
        .unwrap_err(),
        BrokerAccessError::InvalidConfiguration
    );
    assert_eq!(
        BrokerAccessVerifier::new(
            ISSUER,
            API,
            Some(RESOURCE),
            &signer.keys(),
            NonZeroUsize::new(usize::MAX).unwrap()
        )
        .unwrap_err(),
        BrokerAccessError::InvalidConfiguration
    );
}

#[test]
fn entire_trusted_key_snapshot_is_strict_and_rotation_explicit() {
    let signer = Signer::new(KID);
    let mut cases = vec![];
    for (field, bad) in [
        ("kid", json!("")),
        ("crv", json!("X25519")),
        ("alg", json!("RS256")),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("key_ops", json!([])),
        ("key_ops", json!(["verify", "sign"])),
        ("x", json!("%%%")),
        ("x", json!(URL_SAFE_NO_PAD.encode([1u8; 31]))),
        ("x", json!(URL_SAFE_NO_PAD.encode([1u8; 33]))),
    ] {
        let mut key = signer.jwk.clone();
        key[field] = bad;
        cases.push(vec![signer.jwk.clone(), key]);
    }
    let mut no_kid = signer.jwk.clone();
    no_kid.as_object_mut().unwrap().remove("kid");
    cases.push(vec![no_kid]);
    cases.push(vec![signer.jwk.clone(), signer.jwk.clone()]);
    cases.push(vec![json!({"kty":"RSA","kid":"rsa","n":"AQAB","e":"AQAB"})]);
    for keys in cases {
        let set: JwkSet = serde_json::from_value(json!({"keys":keys})).unwrap();
        assert_eq!(
            BrokerAccessVerifier::new(
                ISSUER,
                API,
                Some(RESOURCE),
                &set,
                NonZeroUsize::new(8192).unwrap()
            )
            .unwrap_err(),
            BrokerAccessError::InvalidConfiguration
        );
    }
    let mut optional = signer.jwk.clone();
    for field in ["alg", "use", "key_ops"] {
        optional.as_object_mut().unwrap().remove(field);
    }
    let set = serde_json::from_value(json!({"keys":[optional]})).unwrap();
    BrokerAccessVerifier::new(
        ISSUER,
        API,
        Some(RESOURCE),
        &set,
        NonZeroUsize::new(8192).unwrap(),
    )
    .unwrap()
    .verify(&signer.token(&claims()), &[], deadline())
    .unwrap();
    let next = Signer::new("key-next");
    let before = verifier(&signer);
    invalid(&before, &next.token(&claims()));
    let overlap: JwkSet =
        serde_json::from_value(json!({"keys":[signer.jwk,next.jwk.clone()]})).unwrap();
    let during = BrokerAccessVerifier::new(
        ISSUER,
        API,
        Some(RESOURCE),
        &overlap,
        NonZeroUsize::new(8192).unwrap(),
    )
    .unwrap();
    during
        .verify(&signer.token(&claims()), &[], deadline())
        .unwrap();
    during
        .verify(&next.token(&claims()), &[], deadline())
        .unwrap();
    let after = verifier(&next);
    invalid(&after, &signer.token(&claims()));
    after
        .verify(&next.token(&claims()), &[], deadline())
        .unwrap();
}
