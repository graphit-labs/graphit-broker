use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use broker_security::{
    CredentialDigester, CredentialError, DigestLimits, LocalAuthBinding, LocalAuthPurpose,
    LocalMfaError, LocalMfaProtector, new_local_auth_challenge, validate_local_auth_challenge,
};
use std::num::NonZeroUsize;
use totp_rs::{Algorithm, Totp};
use zeroize::Zeroizing;
fn protector(key: u8) -> LocalMfaProtector {
    LocalMfaProtector::new(Zeroizing::new(vec![key; 32].into_boxed_slice())).unwrap()
}
fn digester(key: u8) -> CredentialDigester {
    let cap = NonZeroUsize::new(512).unwrap();
    CredentialDigester::new(
        Zeroizing::new(vec![key; 32].into_boxed_slice()),
        DigestLimits::new(cap, cap, cap, cap, cap).unwrap(),
    )
    .unwrap()
}
#[test]
fn encrypted_enrollment_roundtrip_and_real_sdk_presentation() {
    let protector = protector(41);
    let prepared = protector
        .prepare("subject", "Graphit Broker", "alice")
        .unwrap();
    assert_eq!(prepared.ciphertext().len(), 90);
    assert!(prepared.ciphertext().starts_with("rust-mfa1."));
    let presentation = prepared.enrollment();
    let parsed = Totp::from_url(presentation.otpauth_uri()).unwrap();
    assert_eq!(parsed.algorithm(), Algorithm::SHA1);
    assert_eq!(parsed.digits(), 6);
    assert_eq!(parsed.step(), 30);
    assert_eq!(parsed.secret().as_bytes().len(), 32);
    assert!(
        parsed.secret().to_base32() == presentation.secret(),
        "SDK secret representation must match"
    );
    assert_eq!(parsed.account_name(), "alice");
    assert!(presentation.qr_png().starts_with(b"\x89PNG\r\n\x1a\n"));
    let encoded = presentation
        .qr_data_url()
        .strip_prefix("data:image/png;base64,")
        .unwrap();
    assert_eq!(STANDARD.decode(encoded).unwrap(), presentation.qr_png());
    let loaded = protector
        .load("subject", prepared.ciphertext(), "Graphit Broker", "alice")
        .unwrap();
    assert!(
        loaded.secret() == presentation.secret(),
        "decrypted secret must match"
    );
    assert!(
        loaded.otpauth_uri() == presentation.otpauth_uri(),
        "decrypted URI must match"
    );
    assert!(
        loaded.qr_png() == presentation.qr_png(),
        "decrypted QR must match"
    );
    let other = protector
        .prepare("subject", "Graphit Broker", "alice")
        .unwrap();
    let a = URL_SAFE_NO_PAD
        .decode(&prepared.ciphertext()[10..])
        .unwrap();
    let b = URL_SAFE_NO_PAD.decode(&other.ciphertext()[10..]).unwrap();
    assert_ne!(&a[..12], &b[..12]);
    assert!(
        other.enrollment().secret() != presentation.secret(),
        "new enrollment must have fresh secret"
    );
    assert_eq!(format!("{protector:?}"), "LocalMfaProtector([REDACTED])");
    assert_eq!(format!("{prepared:?}"), "PreparedLocalMfa([REDACTED])");
    assert_eq!(format!("{loaded:?}"), "LocalMfaEnrollment([REDACTED])");
}
#[test]
fn aead_fails_closed_for_subject_key_tamper_and_non_native_codec() {
    let owner = protector(42);
    let wrong = protector(43);
    let prepared = owner.prepare("subject", "Graphit Broker", "alice").unwrap();
    assert!(matches!(
        owner.load("other", prepared.ciphertext(), "Graphit Broker", "alice"),
        Err(LocalMfaError::InvalidCiphertext)
    ));
    assert!(matches!(
        wrong.load("subject", prepared.ciphertext(), "Graphit Broker", "alice"),
        Err(LocalMfaError::InvalidCiphertext)
    ));
    let mut bytes = URL_SAFE_NO_PAD
        .decode(&prepared.ciphertext()[10..])
        .unwrap();
    for i in [0, 12, 59] {
        bytes[i] ^= 1;
        let tampered = format!("rust-mfa1.{}", URL_SAFE_NO_PAD.encode(&bytes));
        assert!(matches!(
            owner.load("subject", &tampered, "Graphit Broker", "alice"),
            Err(LocalMfaError::InvalidCiphertext)
        ));
        bytes[i] ^= 1;
    }
    for bad in ["", "rust-mfa1.x", "go-format"] {
        assert!(matches!(
            owner.load("subject", bad, "Graphit Broker", "alice"),
            Err(LocalMfaError::InvalidCiphertext)
        ));
    }
    let padded = format!("{}=", prepared.ciphertext());
    assert!(
        owner
            .load("subject", &padded, "Graphit Broker", "alice")
            .is_err()
    );
    for bad in ["", " leading", "trailing ", "with\0nul"] {
        assert!(matches!(
            owner.prepare(bad, "Graphit Broker", "alice"),
            Err(LocalMfaError::InvalidSubject)
        ));
    }
    assert!(
        owner
            .prepare(&"s".repeat(513), "Graphit Broker", "alice")
            .is_err()
    );
    assert!(matches!(
        owner.prepare("subject", "bad:issuer", "alice"),
        Err(LocalMfaError::Presentation)
    ));
    assert!(matches!(
        LocalMfaProtector::new(Zeroizing::new(vec![1; 31].into_boxed_slice())),
        Err(LocalMfaError::InvalidPepper)
    ));
    for _ in 0..8 {
        let raw = new_local_auth_challenge().unwrap();
        assert_eq!(raw.len(), 43);
        validate_local_auth_challenge(&raw).unwrap();
    }
    for raw in [
        "",
        "x",
        "local-auth.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
    ] {
        assert!(validate_local_auth_challenge(raw).is_err());
    }
}
#[test]
fn typed_admin_empty_preserves_generic_binding_frame_and_nonempty_guards() {
    let digester = digester(44);
    let wrong = crate::digester(45);
    let admin = digester
        .local_auth_binding(LocalAuthBinding::AdminLogin)
        .unwrap();
    digester
        .verify_local_auth_binding(LocalAuthBinding::AdminLogin, &admin)
        .unwrap();
    // Independent mature-MAC frame oracle: domain13, arity2, purpose1, empty binding.
    let mut oracle =
        <hmac::Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(&[44; 32]).unwrap();
    hmac::Mac::update(&mut oracle, b"graphit-broker/rust-credential-digest/v1");
    hmac::Mac::update(&mut oracle, &[13, 2]);
    hmac::Mac::update(&mut oracle, &1u64.to_be_bytes());
    hmac::Mac::update(&mut oracle, &[1]);
    hmac::Mac::update(&mut oracle, &0u64.to_be_bytes());
    assert_eq!(
        admin.to_sql_hex(),
        hex::encode(hmac::Mac::finalize(oracle).into_bytes())
    );
    assert!(
        wrong
            .verify_local_auth_binding(LocalAuthBinding::AdminLogin, &admin)
            .is_err()
    );
    assert_eq!(
        digester
            .binding(LocalAuthPurpose::AdminLogin, b"")
            .unwrap_err(),
        CredentialError::EmptyInput
    );
    assert_eq!(
        digester.verify_binding(LocalAuthPurpose::AdminLogin, b"", &admin),
        Err(CredentialError::EmptyInput)
    );
    for ctx in [
        LocalAuthBinding::OauthAuthorize(b""),
        LocalAuthBinding::DeviceApprove(b""),
    ] {
        assert_eq!(
            digester.local_auth_binding(ctx).unwrap_err(),
            CredentialError::EmptyInput
        );
    }
    for (ctx, purpose) in [
        (
            LocalAuthBinding::OauthAuthorize(b"request\0x"),
            LocalAuthPurpose::OauthAuthorize,
        ),
        (
            LocalAuthBinding::DeviceApprove(b"ABCD-EFGH"),
            LocalAuthPurpose::DeviceApprove,
        ),
    ] {
        let digest = digester.local_auth_binding(ctx).unwrap();
        let bytes = match ctx {
            LocalAuthBinding::OauthAuthorize(b) | LocalAuthBinding::DeviceApprove(b) => b,
            LocalAuthBinding::AdminLogin => unreachable!(),
        };
        assert_eq!(
            digest.to_sql_hex(),
            digester.binding(purpose, bytes).unwrap().to_sql_hex()
        );
        digester.verify_local_auth_binding(ctx, &digest).unwrap();
        assert_ne!(admin.to_sql_hex(), digest.to_sql_hex());
        assert!(
            digester
                .verify_local_auth_binding(LocalAuthBinding::AdminLogin, &digest)
                .is_err()
        );
    }
    assert!(
        digester
            .verify_local_auth_binding(LocalAuthBinding::OauthAuthorize(b"request"), &admin)
            .is_err()
    );
    assert_eq!(
        format!("{:?}", LocalAuthBinding::OauthAuthorize(b"sensitive")),
        "LocalAuthBinding([REDACTED])"
    );
}

#[test]
fn sdk_verification_orders_steps_rejects_replay_and_reencrypts_same_secret() {
    let owner = protector(48);
    let prepared = owner.prepare("subject", "Graphit Broker", "alice").unwrap();
    let sdk = Totp::from_url(prepared.enrollment().otpauth_uri()).unwrap();
    let seconds = 1_234_567_890u64;
    let current = seconds / 30;
    let steps = [current, current - 1, current + 1];
    let oracle = totp_rs::Builder::new()
        .with_secret(sdk.secret().as_bytes().to_vec())
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_skew(0)
        .build()
        .unwrap();
    for candidate in steps {
        let code = Zeroizing::new(sdk.generate(candidate * 30).to_string());
        let expected = steps
            .into_iter()
            .find(|step| oracle.check(code.as_str(), step * 30).is_some())
            .map(|step| step as i64);
        assert_eq!(
            owner
                .verify("subject", prepared.ciphertext(), &code, seconds, -1)
                .unwrap(),
            expected
        );
        assert_eq!(
            owner
                .verify(
                    "subject",
                    prepared.ciphertext(),
                    &code,
                    seconds,
                    (current + 1) as i64
                )
                .unwrap(),
            None
        );
    }
    for bad in ["", "+12345", "１２３４５６", "1234567", "12 456"] {
        assert!(
            owner
                .verify("subject", prepared.ciphertext(), bad, seconds, -1)
                .unwrap()
                .is_none()
        );
    }
    let cipher = owner.reencrypt("subject", prepared.ciphertext()).unwrap();
    assert!(
        cipher.as_str() != prepared.ciphertext(),
        "reencryption needs a fresh nonce"
    );
    let loaded = owner
        .load("subject", &cipher, "Graphit Broker", "alice")
        .unwrap();
    assert!(
        loaded.secret() == prepared.enrollment().secret(),
        "the verified secret must survive reencryption"
    );
    assert!(
        owner
            .verify("other", &cipher, "123456", seconds, -1)
            .is_err()
    );
    owner
        .verify("subject", &cipher, "123456", u64::MAX, i64::MAX)
        .unwrap();
}
#[test]
fn native_recovery_codes_are_distinct_sdk_canonical_and_subject_bound() {
    use broker_security::{LocalRecoveryCodes, normalize_local_recovery_code};
    let codes = LocalRecoveryCodes::generate().unwrap();
    assert_eq!(format!("{codes:?}"), "LocalRecoveryCodes([REDACTED])");
    let digester = digester(49);
    for (index, code) in codes.iter().enumerate() {
        assert_eq!(code.len(), 35);
        assert!(code.split('-').all(|group| group.len() == 8));
        let native = normalize_local_recovery_code(code).unwrap();
        assert_eq!(native.len(), 32);
        assert_eq!(
            totp_rs::Secret::try_from_base32(native.as_str())
                .unwrap()
                .as_bytes()
                .len(),
            20
        );
        assert!(
            !codes.iter().take(index).any(|earlier| earlier == code),
            "ten distinct codes required"
        );
        let displayed =
            Zeroizing::new(format!(" {} ", code.to_ascii_lowercase().replace('-', " ")));
        assert!(normalize_local_recovery_code(&displayed).unwrap().as_str() == native.as_str());
        let expected = digester.recovery(b"subject", native.as_bytes()).unwrap();
        digester
            .verify_recovery(b"subject", native.as_bytes(), &expected)
            .unwrap();
        assert!(
            digester
                .verify_recovery(b"other", native.as_bytes(), &expected)
                .is_err()
        );
    }
    for bad in [
        "",
        "ABCDE-FGHIJ",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAé",
    ] {
        assert!(normalize_local_recovery_code(bad).is_none());
    }
    assert!(normalize_local_recovery_code(&"A".repeat(65)).is_none());
}
