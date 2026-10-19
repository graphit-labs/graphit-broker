use std::{fmt, num::NonZeroUsize};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const FRAME: &[u8] = b"graphit-broker/rust-credential-digest/v1";
const BINDING_DOMAIN: u8 = 13;
const RECOVERY_DOMAIN: u8 = 14;
const OIDC_SUBJECT_DOMAIN: u8 = 15;
const MIN_PEPPER_BYTES: usize = 32;

/// Required byte limits chosen by the caller's startup policy. No defaults.
#[derive(Clone, Copy, Debug)]
pub struct DigestLimits {
    pepper: NonZeroUsize,
    token: NonZeroUsize,
    binding: NonZeroUsize,
    subject: NonZeroUsize,
    recovery: NonZeroUsize,
}

impl DigestLimits {
    /// Reject a policy whose pepper cap cannot admit the minimum key size.
    pub fn new(
        pepper: NonZeroUsize,
        token: NonZeroUsize,
        binding: NonZeroUsize,
        subject: NonZeroUsize,
        recovery: NonZeroUsize,
    ) -> Result<Self, CredentialError> {
        if pepper.get() < MIN_PEPPER_BYTES {
            return Err(CredentialError::InvalidLimits);
        }
        Ok(Self {
            pepper,
            token,
            binding,
            subject,
            recovery,
        })
    }
}

/// Closed credential domains. Discriminants are part of digest frame v1.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum TokenKind {
    AdminSession = 1,
    OidcFlowState = 2,
    OidcBrowserBinding = 3,
    LocalAccess = 4,
    LocalRefresh = 5,
    ServiceCredential = 6,
    DeviceCode = 7,
    DeviceUserCode = 8,
    OidcAuthRequest = 9,
    OidcAuthorizationCode = 10,
    OidcStoredAccess = 11,
    LocalAuthChallenge = 12,
}

/// Closed browser-binding purposes with stable one-byte representations.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum LocalAuthPurpose {
    AdminLogin = 1,
    OauthAuthorize = 2,
    DeviceApprove = 3,
}

/// The only purpose allowed to omit external binding is typed AdminLogin.
#[derive(Clone, Copy)]
pub enum LocalAuthBinding<'a> {
    AdminLogin,
    OauthAuthorize(&'a [u8]),
    DeviceApprove(&'a [u8]),
}
impl fmt::Debug for LocalAuthBinding<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalAuthBinding([REDACTED])")
    }
}
impl LocalAuthBinding<'_> {
    pub fn purpose(&self) -> LocalAuthPurpose {
        match self {
            Self::AdminLogin => LocalAuthPurpose::AdminLogin,
            Self::OauthAuthorize(_) => LocalAuthPurpose::OauthAuthorize,
            Self::DeviceApprove(_) => LocalAuthPurpose::DeviceApprove,
        }
    }
}

/// Static errors never carry credential inputs, keys or digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    InvalidLimits,
    InvalidPepper,
    EmptyInput,
    InputTooLong,
    InvalidSqlDigest,
    VerificationFailed,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "invalid credential digest limits",
            Self::InvalidPepper => "invalid credential digest pepper",
            Self::EmptyInput => "empty credential digest input",
            Self::InputTooLong => "credential digest input exceeds limit",
            Self::InvalidSqlDigest => "invalid SQL credential digest",
            Self::VerificationFailed => "credential digest verification failed",
        })
    }
}

impl std::error::Error for CredentialError {}

/// Fixed-size data with an explicit canonical SQL codec and redacted Debug.
/// There is no ordinary equality operation; verify through the digester.
pub struct CredentialDigest([u8; 32]);

impl CredentialDigest {
    /// Accept exactly 64 lowercase ASCII hexadecimal characters.
    pub fn parse_sql_hex(value: &str) -> Result<Self, CredentialError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CredentialError::InvalidSqlDigest);
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| CredentialError::InvalidSqlDigest)?;
        Ok(Self(bytes))
    }

    /// Explicit persistence export. The returned allocation is always 64 bytes.
    pub fn to_sql_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for CredentialDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialDigest([REDACTED])")
    }
}

/// Native pseudonym, not authentication or authorization evidence.
/// ```compile_fail
/// let _ = broker_security::NativeOidcSubject::default();
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {}
/// clone::<broker_security::NativeOidcSubject>();
/// ```
pub struct NativeOidcSubject(String);
impl NativeOidcSubject {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for NativeOidcSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeOidcSubject([REDACTED])")
    }
}

/// Owns the zeroizing pepper; neither cloning nor key export is available.
/// SDK zeroize features protect MAC/hash state, without claiming to wipe every
/// compiler temporary, register, caller copy or swap page.
pub struct CredentialDigester {
    pepper: Zeroizing<Box<[u8]>>,
    limits: DigestLimits,
}

impl fmt::Debug for CredentialDigester {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialDigester([REDACTED])")
    }
}

impl CredentialDigester {
    /// Consume the pepper, including on rejection (its owner zeroizes on drop).
    pub fn new(
        pepper: Zeroizing<Box<[u8]>>,
        limits: DigestLimits,
    ) -> Result<Self, CredentialError> {
        if pepper.len() < MIN_PEPPER_BYTES || pepper.len() > limits.pepper.get() {
            return Err(CredentialError::InvalidPepper);
        }
        Ok(Self { pepper, limits })
    }

    /// Frame issuer and subject separately in domain 15 using the existing pepper.
    /// Both fields use the explicit subject byte cap; no concatenated canonical ID.
    pub fn oidc_subject(
        &self,
        issuer: &[u8],
        subject: &[u8],
    ) -> Result<NativeOidcSubject, CredentialError> {
        validate(issuer, self.limits.subject)?;
        validate(subject, self.limits.subject)?;
        let mac = self.framed_mac(OIDC_SUBJECT_DOMAIN, &[issuer, subject])?;
        Ok(NativeOidcSubject(
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
        ))
    }

    pub fn token(
        &self,
        kind: TokenKind,
        value: &[u8],
    ) -> Result<CredentialDigest, CredentialError> {
        validate(value, self.limits.token)?;
        digest(self.framed_mac(kind as u8, &[value])?)
    }

    pub fn verify_token(
        &self,
        kind: TokenKind,
        value: &[u8],
        expected: &CredentialDigest,
    ) -> Result<(), CredentialError> {
        validate(value, self.limits.token)?;
        verify(self.framed_mac(kind as u8, &[value])?, expected)
    }

    pub fn binding(
        &self,
        purpose: LocalAuthPurpose,
        value: &[u8],
    ) -> Result<CredentialDigest, CredentialError> {
        validate(value, self.limits.binding)?;
        digest(self.framed_mac(BINDING_DOMAIN, &[&[purpose as u8], value])?)
    }

    pub fn verify_binding(
        &self,
        purpose: LocalAuthPurpose,
        value: &[u8],
        expected: &CredentialDigest,
    ) -> Result<(), CredentialError> {
        validate(value, self.limits.binding)?;
        verify(
            self.framed_mac(BINDING_DOMAIN, &[&[purpose as u8], value])?,
            expected,
        )
    }

    /// Empty Admin is reachable only by its typed variant; generic methods stay nonempty.
    pub fn local_auth_binding(
        &self,
        context: LocalAuthBinding<'_>,
    ) -> Result<CredentialDigest, CredentialError> {
        match context {
            LocalAuthBinding::AdminLogin => digest(self.framed_mac(
                BINDING_DOMAIN,
                &[&[LocalAuthPurpose::AdminLogin as u8], &[]],
            )?),
            LocalAuthBinding::OauthAuthorize(value) => {
                self.binding(LocalAuthPurpose::OauthAuthorize, value)
            }
            LocalAuthBinding::DeviceApprove(value) => {
                self.binding(LocalAuthPurpose::DeviceApprove, value)
            }
        }
    }
    pub fn verify_local_auth_binding(
        &self,
        context: LocalAuthBinding<'_>,
        expected: &CredentialDigest,
    ) -> Result<(), CredentialError> {
        match context {
            LocalAuthBinding::AdminLogin => verify(
                self.framed_mac(
                    BINDING_DOMAIN,
                    &[&[LocalAuthPurpose::AdminLogin as u8], &[]],
                )?,
                expected,
            ),
            LocalAuthBinding::OauthAuthorize(value) => {
                self.verify_binding(LocalAuthPurpose::OauthAuthorize, value, expected)
            }
            LocalAuthBinding::DeviceApprove(value) => {
                self.verify_binding(LocalAuthPurpose::DeviceApprove, value, expected)
            }
        }
    }

    /// `normalized_code` must already follow the caller's recovery-code policy.
    /// This library validates byte bounds; it does not normalize human input or
    /// assert that a code is an enrolled, unused authentication factor.
    pub fn recovery(
        &self,
        subject: &[u8],
        normalized_code: &[u8],
    ) -> Result<CredentialDigest, CredentialError> {
        self.validate_recovery(subject, normalized_code)?;
        digest(self.framed_mac(RECOVERY_DOMAIN, &[subject, normalized_code])?)
    }

    pub fn verify_recovery(
        &self,
        subject: &[u8],
        normalized_code: &[u8],
        expected: &CredentialDigest,
    ) -> Result<(), CredentialError> {
        self.validate_recovery(subject, normalized_code)?;
        verify(
            self.framed_mac(RECOVERY_DOMAIN, &[subject, normalized_code])?,
            expected,
        )
    }

    fn validate_recovery(&self, subject: &[u8], code: &[u8]) -> Result<(), CredentialError> {
        validate(subject, self.limits.subject)?;
        validate(code, self.limits.recovery)
    }

    fn framed_mac(&self, domain: u8, fields: &[&[u8]]) -> Result<Hmac<Sha256>, CredentialError> {
        // Validate representability before constructing any MAC state.
        let arity = u8::try_from(fields.len()).map_err(|_| CredentialError::InputTooLong)?;
        for field in fields {
            u64::try_from(field.len()).map_err(|_| CredentialError::InputTooLong)?;
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.pepper)
            .map_err(|_| CredentialError::InvalidPepper)?;
        mac.update(FRAME);
        mac.update(&[domain, arity]);
        for field in fields {
            let length = u64::try_from(field.len()).map_err(|_| CredentialError::InputTooLong)?;
            mac.update(&length.to_be_bytes());
            mac.update(field);
        }
        Ok(mac)
    }
}

fn validate(value: &[u8], cap: NonZeroUsize) -> Result<(), CredentialError> {
    if value.is_empty() {
        return Err(CredentialError::EmptyInput);
    }
    if value.len() > cap.get() {
        return Err(CredentialError::InputTooLong);
    }
    Ok(())
}

fn digest(mac: Hmac<Sha256>) -> Result<CredentialDigest, CredentialError> {
    Ok(CredentialDigest(mac.finalize().into_bytes().into()))
}

fn verify(mac: Hmac<Sha256>, expected: &CredentialDigest) -> Result<(), CredentialError> {
    mac.verify_slice(&expected.0)
        .map_err(|_| CredentialError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_oidc_subject_frames_two_fields_in_its_own_domain() {
        let limit = NonZeroUsize::new(128).unwrap();
        let limits = DigestLimits::new(limit, limit, limit, limit, limit).unwrap();
        let d = CredentialDigester::new(Zeroizing::new(vec![41; 32].into_boxed_slice()), limits)
            .unwrap();
        let subject = d.oidc_subject(b"local", b"subject").unwrap();
        assert_eq!(subject.as_str().len(), 43);
        assert_eq!(
            subject.as_str(),
            d.oidc_subject(b"local", b"subject").unwrap().as_str()
        );
        assert_eq!(format!("{subject:?}"), "NativeOidcSubject([REDACTED])");
        let changed =
            CredentialDigester::new(Zeroizing::new(vec![42; 32].into_boxed_slice()), limits)
                .unwrap();
        for other in [
            d.oidc_subject(b"issuer", b"subject").unwrap(),
            d.oidc_subject(b"local", b"another").unwrap(),
            changed.oidc_subject(b"local", b"subject").unwrap(),
        ] {
            assert_ne!(subject.as_str(), other.as_str());
        }
        for (a, b, c, e) in [
            (&b"a|b"[..], &b"c"[..], &b"a"[..], &b"b|c"[..]),
            (&b"a\0b"[..], &b"c"[..], &b"a"[..], &b"b\0c"[..]),
        ] {
            assert_ne!(
                d.oidc_subject(a, b).unwrap().as_str(),
                d.oidc_subject(c, e).unwrap().as_str()
            );
        }
        for domain in 1..=14 {
            let other = URL_SAFE_NO_PAD.encode(
                d.framed_mac(domain, &[b"local", b"subject"])
                    .unwrap()
                    .finalize()
                    .into_bytes(),
            );
            assert_ne!(subject.as_str(), other);
        }
        for (issuer, sub, error) in [
            (&b""[..], &b"subject"[..], CredentialError::EmptyInput),
            (&b"local"[..], &b""[..], CredentialError::EmptyInput),
            (
                &[b'x'; 129][..],
                &b"subject"[..],
                CredentialError::InputTooLong,
            ),
            (
                &b"local"[..],
                &[b'x'; 129][..],
                CredentialError::InputTooLong,
            ),
        ] {
            assert_eq!(d.oidc_subject(issuer, sub).err(), Some(error));
        }
        assert!(d.oidc_subject(&[b'x'; 128], &[b'y'; 128]).is_ok());
    }

    #[test]
    fn mature_mac_matches_rfc_4231_cases_one_two_and_three() {
        // RFC keys intentionally shorter than the public API minimum. This
        // helper is private to tests, not a public bypass of Broker policy.
        for (key, message, expected) in [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
        ] {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
            mac.update(&message);
            assert_eq!(hex::encode(mac.finalize().into_bytes()), expected);
        }
    }
}
