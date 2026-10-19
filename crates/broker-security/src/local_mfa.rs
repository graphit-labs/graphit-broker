//! Native factor encryption, SDK verification and protected recovery codes.
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use totp_rs::{Algorithm, Builder, Secret};
use zeroize::Zeroizing;

const KEY_DOMAIN: &[u8] = b"graphit-broker/rust-local-mfa-key/v1\0";
const SECRET_DOMAIN: &[u8] = b"graphit-broker/rust-local-mfa-secret/v1\0";
const PREFIX: &str = "rust-mfa1.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalMfaError {
    InvalidPepper,
    InvalidSubject,
    InvalidCiphertext,
    Random,
    Crypto,
    Presentation,
}
impl fmt::Display for LocalMfaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPepper => "invalid LOCAL MFA pepper",
            Self::InvalidSubject => "invalid LOCAL MFA subject",
            Self::InvalidCiphertext => "invalid native LOCAL MFA ciphertext",
            Self::Random => "LOCAL MFA randomness failed",
            Self::Crypto => "LOCAL MFA encryption failed",
            Self::Presentation => "LOCAL MFA presentation failed",
        })
    }
}
impl std::error::Error for LocalMfaError {}

/// Owns the SDK cipher with zeroize features. No key export or Clone.
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_security::LocalMfaProtector>();
/// ```
/// ```compile_fail
/// fn key(value: &broker_security::LocalMfaProtector) { let _=&value.cipher; }
/// ```
pub struct LocalMfaProtector {
    cipher: Aes256Gcm,
}
impl fmt::Debug for LocalMfaProtector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalMfaProtector([REDACTED])")
    }
}
/// Explicit secret-bearing presentation; callers must protect exported borrows.
pub struct LocalMfaEnrollment {
    secret: Zeroizing<String>,
    uri: Zeroizing<String>,
    png: Zeroizing<Vec<u8>>,
    data_url: Zeroizing<String>,
}
impl fmt::Debug for LocalMfaEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalMfaEnrollment([REDACTED])")
    }
}
impl LocalMfaEnrollment {
    pub fn secret(&self) -> &str {
        &self.secret
    }
    pub fn otpauth_uri(&self) -> &str {
        &self.uri
    }
    pub fn qr_png(&self) -> &[u8] {
        &self.png
    }
    pub fn qr_data_url(&self) -> &str {
        &self.data_url
    }
}
pub struct PreparedLocalMfa {
    ciphertext: Zeroizing<String>,
    enrollment: LocalMfaEnrollment,
}
impl fmt::Debug for PreparedLocalMfa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedLocalMfa([REDACTED])")
    }
}
impl PreparedLocalMfa {
    pub fn ciphertext(&self) -> &str {
        &self.ciphertext
    }
    pub fn enrollment(&self) -> &LocalMfaEnrollment {
        &self.enrollment
    }
    pub fn into_parts(self) -> (Zeroizing<String>, LocalMfaEnrollment) {
        (self.ciphertext, self.enrollment)
    }
}
impl LocalMfaProtector {
    pub fn new(pepper: Zeroizing<Box<[u8]>>) -> Result<Self, LocalMfaError> {
        if pepper.len() < 32 {
            return Err(LocalMfaError::InvalidPepper);
        }
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&pepper)
            .map_err(|_| LocalMfaError::InvalidPepper)?;
        mac.update(KEY_DOMAIN);
        let key = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| LocalMfaError::Crypto)?;
        Ok(Self { cipher })
    }
    pub fn prepare(
        &self,
        subject: &str,
        issuer: &str,
        account: &str,
    ) -> Result<PreparedLocalMfa, LocalMfaError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(secret.as_mut()).map_err(|_| LocalMfaError::Random)?;
        let ciphertext = self.encrypt_secret(subject, secret.as_ref())?;
        let enrollment = presentation(secret.as_ref(), issuer, account)?;
        Ok(PreparedLocalMfa {
            ciphertext,
            enrollment,
        })
    }
    pub fn load(
        &self,
        subject: &str,
        ciphertext: &str,
        issuer: &str,
        account: &str,
    ) -> Result<LocalMfaEnrollment, LocalMfaError> {
        let secret = self.decrypt(subject, ciphertext)?;
        presentation(&secret, issuer, account)
    }
    /// Re-encrypts the verified enrollment secret with a fresh nonce.
    pub fn reencrypt(
        &self,
        subject: &str,
        ciphertext: &str,
    ) -> Result<Zeroizing<String>, LocalMfaError> {
        self.encrypt_secret(subject, &self.decrypt(subject, ciphertext)?)
    }
    /// SDK comparison, persisted accepted step and explicit Current/Previous/Next order.
    pub fn verify(
        &self,
        subject: &str,
        ciphertext: &str,
        code: &str,
        seconds: u64,
        last_step: i64,
    ) -> Result<Option<i64>, LocalMfaError> {
        let secret = self.decrypt(subject, ciphertext)?;
        let code = code.trim();
        if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(None);
        }
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(6)
            .with_step_duration(30)
            .with_skew(0)
            .with_secret(secret.to_vec())
            .build()
            .map_err(|_| LocalMfaError::Crypto)?;
        let current = seconds / 30;
        for step in [
            Some(current),
            current.checked_sub(1),
            current.checked_add(1),
        ]
        .into_iter()
        .flatten()
        {
            let Some(timestamp) = step.checked_mul(30) else {
                continue;
            };
            let Ok(accepted) = i64::try_from(step) else {
                continue;
            };
            if accepted > last_step && totp.check(code, timestamp).is_some() {
                return Ok(Some(accepted));
            }
        }
        Ok(None)
    }
    fn encrypt_secret(
        &self,
        subject: &str,
        secret: &[u8],
    ) -> Result<Zeroizing<String>, LocalMfaError> {
        let aad = aad(subject)?;
        if secret.len() != 32 {
            return Err(LocalMfaError::InvalidCiphertext);
        }
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| LocalMfaError::Random)?;
        let encrypted = Zeroizing::new(
            self.cipher
                .encrypt(
                    &nonce.into(),
                    Payload {
                        msg: secret,
                        aad: &aad,
                    },
                )
                .map_err(|_| LocalMfaError::Crypto)?,
        );
        let mut bytes = Zeroizing::new(Vec::with_capacity(60));
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&encrypted);
        Ok(Zeroizing::new(format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(&*bytes)
        )))
    }
    fn decrypt(
        &self,
        subject: &str,
        ciphertext: &str,
    ) -> Result<Zeroizing<Vec<u8>>, LocalMfaError> {
        let aad = aad(subject)?;
        if ciphertext.len() != 90 || !ciphertext.starts_with(PREFIX) {
            return Err(LocalMfaError::InvalidCiphertext);
        }
        let encoded = &ciphertext[PREFIX.len()..];
        let mut bytes = Zeroizing::new([0u8; 60]);
        let count = URL_SAFE_NO_PAD
            .decode_slice(encoded, bytes.as_mut())
            .map_err(|_| LocalMfaError::InvalidCiphertext)?;
        if count != 60 || URL_SAFE_NO_PAD.encode(bytes.as_ref()) != encoded {
            return Err(LocalMfaError::InvalidCiphertext);
        }
        let nonce: [u8; 12] = bytes[..12]
            .try_into()
            .map_err(|_| LocalMfaError::InvalidCiphertext)?;
        let secret = Zeroizing::new(
            self.cipher
                .decrypt(
                    &nonce.into(),
                    Payload {
                        msg: &bytes[12..],
                        aad: &aad,
                    },
                )
                .map_err(|_| LocalMfaError::InvalidCiphertext)?,
        );
        if secret.len() != 32 {
            return Err(LocalMfaError::InvalidCiphertext);
        }
        Ok(secret)
    }
}
/// One owned set emitted only by a successful enrollment. Protect explicit borrows.
/// ```compile_fail
/// fn cloned<T: Clone>() {} cloned::<broker_security::LocalRecoveryCodes>();
/// ```
/// ```compile_fail
/// fn defaulted<T: Default>() {} defaulted::<broker_security::LocalRecoveryCodes>();
/// ```
pub struct LocalRecoveryCodes(Box<[Zeroizing<String>; 10]>);
impl fmt::Debug for LocalRecoveryCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalRecoveryCodes([REDACTED])")
    }
}
impl LocalRecoveryCodes {
    pub fn generate() -> Result<Self, LocalMfaError> {
        let mut codes = std::array::from_fn(|_| Zeroizing::new(String::new()));
        for index in 0..10 {
            let mut bytes = Zeroizing::new([0u8; 20]);
            getrandom::fill(bytes.as_mut()).map_err(|_| LocalMfaError::Random)?;
            let encoded = Zeroizing::new(Secret::from(*bytes).to_base32());
            let code = Zeroizing::new(format!(
                "{}-{}-{}-{}",
                &encoded[..8],
                &encoded[8..16],
                &encoded[16..24],
                &encoded[24..]
            ));
            if codes[..index]
                .iter()
                .any(|previous| previous.as_str() == code.as_str())
            {
                return Err(LocalMfaError::Random);
            }
            codes[index] = code;
        }
        Ok(Self(Box::new(codes)))
    }
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|code| code.as_str())
    }
}
/// Native SDK base32 only, with bounded ASCII presentation normalization.
pub fn normalize_local_recovery_code(code: &str) -> Option<Zeroizing<String>> {
    if code.len() > 64 {
        return None;
    }
    let normalized = Zeroizing::new(
        code.trim()
            .bytes()
            .filter(|b| !matches!(b, b' ' | b'-'))
            .map(|b| char::from(b.to_ascii_uppercase()))
            .collect::<String>(),
    );
    if normalized.len() != 32
        || !normalized
            .bytes()
            .all(|b| b.is_ascii_uppercase() || matches!(b, b'2'..=b'7'))
    {
        return None;
    }
    let secret = Secret::try_from_base32(normalized.as_str()).ok()?;
    let canonical = Zeroizing::new(secret.to_base32());
    if secret.as_bytes().len() != 20 || canonical.as_str() != normalized.as_str() {
        return None;
    }
    Some(normalized)
}
fn aad(subject: &str) -> Result<Vec<u8>, LocalMfaError> {
    if subject.is_empty()
        || subject.len() > 512
        || subject.trim() != subject
        || subject.contains('\0')
    {
        return Err(LocalMfaError::InvalidSubject);
    }
    let mut aad = Vec::with_capacity(SECRET_DOMAIN.len() + 8 + subject.len());
    aad.extend_from_slice(SECRET_DOMAIN);
    aad.extend_from_slice(&(subject.len() as u64).to_be_bytes());
    aad.extend_from_slice(subject.as_bytes());
    Ok(aad)
}
fn presentation(
    secret: &[u8],
    issuer: &str,
    account: &str,
) -> Result<LocalMfaEnrollment, LocalMfaError> {
    // SDK owns this copied secret and zeroizes it on drop. Some SDK errors
    // contain an otpauth URL, so none is carried into diagnostics.
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_skew(0)
        .with_secret(secret.to_vec())
        .with_issuer(Some(issuer))
        .with_account_name(account)
        .build()
        .map_err(|_| LocalMfaError::Presentation)?;
    let secret = Zeroizing::new(totp.secret().to_base32());
    let uri = Zeroizing::new(totp.to_url().map_err(|_| LocalMfaError::Presentation)?);
    let png = Zeroizing::new(totp.to_qr_png().map_err(|_| LocalMfaError::Presentation)?);
    let data_url = Zeroizing::new(format!("data:image/png;base64,{}", STANDARD.encode(&*png)));
    Ok(LocalMfaEnrollment {
        secret,
        uri,
        png,
        data_url,
    })
}
pub fn new_local_auth_challenge() -> Result<Zeroizing<String>, LocalMfaError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| LocalMfaError::Random)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}
pub fn validate_local_auth_challenge(raw: &str) -> Result<(), LocalMfaError> {
    if raw.len() != 43 {
        return Err(LocalMfaError::InvalidCiphertext);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    let count = URL_SAFE_NO_PAD
        .decode_slice(raw, bytes.as_mut())
        .map_err(|_| LocalMfaError::InvalidCiphertext)?;
    if count != 32 || URL_SAFE_NO_PAD.encode(bytes.as_ref()) != raw {
        return Err(LocalMfaError::InvalidCiphertext);
    }
    Ok(())
}
