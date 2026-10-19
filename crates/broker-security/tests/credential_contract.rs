use std::num::NonZeroUsize;

use broker_security::{
    CredentialDigest, CredentialDigester, CredentialError, DigestLimits, LocalAuthPurpose,
    TokenKind,
};
use zeroize::Zeroizing;

const KINDS: [TokenKind; 12] = [
    TokenKind::AdminSession,
    TokenKind::OidcFlowState,
    TokenKind::OidcBrowserBinding,
    TokenKind::LocalAccess,
    TokenKind::LocalRefresh,
    TokenKind::ServiceCredential,
    TokenKind::DeviceCode,
    TokenKind::DeviceUserCode,
    TokenKind::OidcAuthRequest,
    TokenKind::OidcAuthorizationCode,
    TokenKind::OidcStoredAccess,
    TokenKind::LocalAuthChallenge,
];
const PURPOSES: [LocalAuthPurpose; 3] = [
    LocalAuthPurpose::AdminLogin,
    LocalAuthPurpose::OauthAuthorize,
    LocalAuthPurpose::DeviceApprove,
];

fn nz(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn limits() -> DigestLimits {
    DigestLimits::new(nz(40), nz(32), nz(24), nz(16), nz(10)).unwrap()
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new((0..32).collect::<Vec<u8>>().into_boxed_slice()),
        limits(),
    )
    .unwrap()
}
fn wrong_key() -> CredentialDigester {
    CredentialDigester::new(Zeroizing::new(vec![0xff; 32].into_boxed_slice()), limits()).unwrap()
}

#[test]
fn three_public_families_match_independent_python_hmac_oracles() {
    // Python 3 standard library, independent of RustCrypto:
    // frame = prefix + bytes([domain,len(fields)]) +
    //         b''.join(struct.pack('>Q',len(f)) + f for f in fields)
    // hmac.new(bytes(range(32)),frame,'sha256').hexdigest()
    // Source recipe and synthetic vectors are documented in rust-credentials.md.
    let digester = digester();
    assert_eq!(
        digester
            .token(TokenKind::AdminSession, b"token-fixture")
            .unwrap()
            .to_sql_hex(),
        "e4deb32593bd14d863cca3b4a881a616028f8240121f1e8657646bb92ea96216"
    );
    assert_eq!(
        digester
            .binding(LocalAuthPurpose::OauthAuthorize, b"browser-fixture")
            .unwrap()
            .to_sql_hex(),
        "6a0ed0823f9daa50766c8b47578a4c7012c6e2b3183db41f081c8009afc5aee0"
    );
    assert_eq!(
        digester
            .recovery(b"subject-fixture", b"ABCDEFG234")
            .unwrap()
            .to_sql_hex(),
        "81520287c6cd44f8f063a5b04b70a57e7202973ed608a7b331ea0ab9d2ef7d71"
    );
}

#[test]
fn closed_ids_and_all_fourteen_domains_are_distinct() {
    let digester = digester();
    let mut digests = Vec::new();
    for (index, kind) in KINDS.iter().enumerate() {
        assert_eq!(*kind as usize, index + 1);
        let digest = digester.token(*kind, b"value").unwrap();
        digester.verify_token(*kind, b"value", &digest).unwrap();
        for other in &KINDS {
            if *other as u8 != *kind as u8 {
                assert_eq!(
                    digester.verify_token(*other, b"value", &digest),
                    Err(CredentialError::VerificationFailed)
                );
            }
        }
        digests.push(digest.to_sql_hex());
    }
    let binding = digester
        .binding(LocalAuthPurpose::AdminLogin, b"value")
        .unwrap();
    let recovery = digester.recovery(b"value", b"value").unwrap();
    assert_eq!(
        digester.verify_binding(LocalAuthPurpose::AdminLogin, b"value", &recovery),
        Err(CredentialError::VerificationFailed)
    );
    assert_eq!(
        digester.verify_recovery(b"value", b"value", &binding),
        Err(CredentialError::VerificationFailed)
    );
    for digest in [&binding, &recovery] {
        for kind in KINDS {
            assert_eq!(
                digester.verify_token(kind, b"value", digest),
                Err(CredentialError::VerificationFailed)
            );
        }
        digests.push(digest.to_sql_hex());
    }
    for (index, digest) in digests.iter().enumerate() {
        for other in &digests[index + 1..] {
            assert_ne!(digest, other);
        }
    }
    for (index, purpose) in PURPOSES.iter().enumerate() {
        assert_eq!(*purpose as usize, index + 1);
    }
}

#[test]
fn wrong_key_value_purpose_and_subject_never_verify() {
    let digester = digester();
    let wrong = wrong_key();
    let token = digester.token(TokenKind::LocalAccess, b"token").unwrap();
    assert_eq!(
        wrong.verify_token(TokenKind::LocalAccess, b"token", &token),
        Err(CredentialError::VerificationFailed)
    );
    assert_eq!(
        digester.verify_token(TokenKind::LocalAccess, b"other", &token),
        Err(CredentialError::VerificationFailed)
    );
    for purpose in PURPOSES {
        let binding = digester.binding(purpose, b"browser").unwrap();
        digester
            .verify_binding(purpose, b"browser", &binding)
            .unwrap();
        assert_eq!(
            wrong.verify_binding(purpose, b"browser", &binding),
            Err(CredentialError::VerificationFailed)
        );
        assert_eq!(
            digester.verify_binding(purpose, b"other", &binding),
            Err(CredentialError::VerificationFailed)
        );
        for other in PURPOSES {
            if purpose as u8 != other as u8 {
                assert_eq!(
                    digester.verify_binding(other, b"browser", &binding),
                    Err(CredentialError::VerificationFailed)
                );
            }
        }
    }
    let recovery = digester.recovery(b"subject", b"ABCDEFG234").unwrap();
    digester
        .verify_recovery(b"subject", b"ABCDEFG234", &recovery)
        .unwrap();
    assert_eq!(
        wrong.verify_recovery(b"subject", b"ABCDEFG234", &recovery),
        Err(CredentialError::VerificationFailed)
    );
    assert_eq!(
        digester.verify_recovery(b"other", b"ABCDEFG234", &recovery),
        Err(CredentialError::VerificationFailed)
    );
    assert_eq!(
        digester.verify_recovery(b"subject", b"ABCDEFG235", &recovery),
        Err(CredentialError::VerificationFailed)
    );
}

#[test]
fn tampering_any_of_thirty_two_bytes_fails_in_every_family() {
    let digester = digester();
    let digests = [
        digester.token(TokenKind::AdminSession, b"value").unwrap(),
        digester
            .binding(LocalAuthPurpose::AdminLogin, b"value")
            .unwrap(),
        digester.recovery(b"subject", b"value").unwrap(),
    ];
    for (family, digest) in digests.iter().enumerate() {
        let mut bytes = [0; 32];
        hex::decode_to_slice(digest.to_sql_hex(), &mut bytes).unwrap();
        for index in 0..32 {
            let mut changed = bytes;
            changed[index] ^= 1;
            let changed = CredentialDigest::parse_sql_hex(&hex::encode(changed)).unwrap();
            let result = match family {
                0 => digester.verify_token(TokenKind::AdminSession, b"value", &changed),
                1 => digester.verify_binding(LocalAuthPurpose::AdminLogin, b"value", &changed),
                _ => digester.verify_recovery(b"subject", b"value", &changed),
            };
            assert_eq!(result, Err(CredentialError::VerificationFailed));
        }
    }
}

#[test]
fn limits_are_explicit_and_pepper_boundaries_are_enforced() {
    assert!(NonZeroUsize::new(0).is_none());
    assert_eq!(
        DigestLimits::new(nz(31), nz(1), nz(1), nz(1), nz(1)).unwrap_err(),
        CredentialError::InvalidLimits
    );
    for length in [0, 1, 31, 41] {
        assert_eq!(
            CredentialDigester::new(Zeroizing::new(vec![9; length].into_boxed_slice()), limits())
                .unwrap_err(),
            CredentialError::InvalidPepper
        );
    }
    for length in [32, 40] {
        CredentialDigester::new(Zeroizing::new(vec![9; length].into_boxed_slice()), limits())
            .unwrap();
    }
    let minimum = DigestLimits::new(nz(32), nz(1), nz(1), nz(1), nz(1)).unwrap();
    CredentialDigester::new(Zeroizing::new(vec![9; 32].into_boxed_slice()), minimum).unwrap();
}

#[test]
fn each_field_rejects_empty_and_one_over_cap_for_digest_and_verify() {
    let digester = digester();
    let expected = CredentialDigest::parse_sql_hex(&"00".repeat(32)).unwrap();
    for kind in KINDS {
        digester.token(kind, &[1; 32]).unwrap();
        for (value, error) in [
            (&b""[..], CredentialError::EmptyInput),
            (&[1; 33][..], CredentialError::InputTooLong),
        ] {
            assert_eq!(digester.token(kind, value).unwrap_err(), error);
            assert_eq!(digester.verify_token(kind, value, &expected), Err(error));
        }
    }
    for purpose in PURPOSES {
        digester.binding(purpose, &[1; 24]).unwrap();
        for (value, error) in [
            (&b""[..], CredentialError::EmptyInput),
            (&[1; 25][..], CredentialError::InputTooLong),
        ] {
            assert_eq!(digester.binding(purpose, value).unwrap_err(), error);
            assert_eq!(
                digester.verify_binding(purpose, value, &expected),
                Err(error)
            );
        }
    }
    digester.recovery(&[1; 16], &[2; 10]).unwrap();
    for (subject, code, error) in [
        (&b""[..], &b"code"[..], CredentialError::EmptyInput),
        (&b"subject"[..], &b""[..], CredentialError::EmptyInput),
        (&[1; 17][..], &b"code"[..], CredentialError::InputTooLong),
        (&b"subject"[..], &[1; 11][..], CredentialError::InputTooLong),
    ] {
        assert_eq!(digester.recovery(subject, code).unwrap_err(), error);
        assert_eq!(
            digester.verify_recovery(subject, code, &expected),
            Err(error)
        );
    }
}

#[test]
fn length_framing_separates_nul_and_concatenation_ambiguities() {
    let digester = digester();
    // These raw tuples demonstrate byte framing only, not a human factor policy.
    for (subject_a, code_a, subject_b, code_b) in [
        (&b"a\0b"[..], &b"c"[..], &b"a"[..], &b"b\0c"[..]),
        (&b"ab"[..], &b"c"[..], &b"a"[..], &b"bc"[..]),
    ] {
        let digest = digester.recovery(subject_a, code_a).unwrap();
        assert_ne!(
            digest.to_sql_hex(),
            digester.recovery(subject_b, code_b).unwrap().to_sql_hex()
        );
        assert_eq!(
            digester.verify_recovery(subject_b, code_b, &digest),
            Err(CredentialError::VerificationFailed)
        );
    }
    let token = digester.token(TokenKind::AdminSession, b"a\0b").unwrap();
    assert_eq!(
        digester.verify_token(TokenKind::AdminSession, b"ab", &token),
        Err(CredentialError::VerificationFailed)
    );
    let binding = digester
        .binding(LocalAuthPurpose::AdminLogin, b"a\0b")
        .unwrap();
    assert_eq!(
        digester.verify_binding(LocalAuthPurpose::AdminLogin, b"ab", &binding),
        Err(CredentialError::VerificationFailed)
    );
}

#[test]
fn sql_codec_accepts_only_exact_lowercase_ascii_hex_and_roundtrips() {
    let digest = digester().token(TokenKind::AdminSession, b"value").unwrap();
    let sql = digest.to_sql_hex();
    assert_eq!(sql.len(), 64);
    assert_eq!(
        CredentialDigest::parse_sql_hex(&sql).unwrap().to_sql_hex(),
        sql
    );
    for invalid in [
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        "é".repeat(32),
        format!("{}\n", "a".repeat(63)),
        format!("{}\0", "a".repeat(63)),
    ] {
        assert_eq!(
            CredentialDigest::parse_sql_hex(&invalid).unwrap_err(),
            CredentialError::InvalidSqlDigest
        );
    }
}

#[test]
fn debug_and_errors_are_redacted_and_recovery_does_not_normalize() {
    let digester = digester();
    let digest = digester
        .token(TokenKind::AdminSession, b"private-input")
        .unwrap();
    assert_eq!(format!("{digester:?}"), "CredentialDigester([REDACTED])");
    assert_eq!(format!("{digest:?}"), "CredentialDigest([REDACTED])");
    for error in [
        CredentialError::InvalidLimits,
        CredentialError::InvalidPepper,
        CredentialError::EmptyInput,
        CredentialError::InputTooLong,
        CredentialError::InvalidSqlDigest,
        CredentialError::VerificationFailed,
    ] {
        assert!(!format!("{error:?} {error}").contains("private-input"));
        assert!(!format!("{error:?} {error}").contains(&digest.to_sql_hex()));
    }
    let digest = digester.recovery(b"subject", b"a-b c").unwrap();
    assert_eq!(
        digester.verify_recovery(b"subject", b"ABC", &digest),
        Err(CredentialError::VerificationFailed)
    );
}
