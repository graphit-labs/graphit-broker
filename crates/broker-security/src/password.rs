//! Native LOCAL password PHC creation and verification with RustCrypto.
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, phc::PasswordHash},
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const DOMAIN: &[u8] = b"graphit-broker/rust-local-password/v1\0";
pub const LOCAL_PASSWORD_MAX_BYTES: usize = 4096;
const PHC_MAX_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPasswordError {
    Configuration,
    InvalidPassword,
    InvalidHash,
    Hashing,
}
impl fmt::Display for LocalPasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid LOCAL password configuration",
            Self::InvalidPassword => "invalid LOCAL password",
            Self::InvalidHash => "invalid LOCAL password hash",
            Self::Hashing => "LOCAL password cryptography failed",
        })
    }
}
impl std::error::Error for LocalPasswordError {}

/// Owns the native password pepper. PHC is data, never authentication authority.
/// Neither key export nor cloning is available.
pub struct LocalPasswordHasher {
    pepper: Zeroizing<Box<[u8]>>,
}
impl fmt::Debug for LocalPasswordHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalPasswordHasher([REDACTED])")
    }
}
impl LocalPasswordHasher {
    pub fn new(pepper: Zeroizing<Box<[u8]>>) -> Result<Self, LocalPasswordError> {
        if pepper.len() < 32 {
            return Err(LocalPasswordError::Configuration);
        }
        Ok(Self { pepper })
    }
    /// Creation uses explicit Argon2id v19, 64 MiB, t3/p4, random salt16/hash32.
    /// This synchronous operation belongs on a blocking worker.
    pub fn hash(&self, password: &str) -> Result<Zeroizing<String>, LocalPasswordError> {
        if password.len() > LOCAL_PASSWORD_MAX_BYTES || password.chars().count() < 15 {
            return Err(LocalPasswordError::InvalidPassword);
        }
        let prehash = self.prehash(password)?;
        let params =
            Params::new(65536, 3, 4, Some(32)).map_err(|_| LocalPasswordError::Configuration)?;
        let hash = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password(&*prehash)
            .map_err(|_| LocalPasswordError::Hashing)?;
        Ok(Zeroizing::new(hash.to_string()))
    }
    /// Validate the SDK PHC and physical work bounds before allocating KDF memory.
    pub fn validate_hash(phc: &str) -> Result<(), LocalPasswordError> {
        Self::parsed(phc).map(|_| ())
    }
    /// Verify native PHC with SDK KDF and constant-time SDK Output equality.
    /// A successful comparison alone is not a login, MFA or OAuth grant.
    pub fn verify(&self, password: &str, phc: &str) -> Result<bool, LocalPasswordError> {
        if password.len() > LOCAL_PASSWORD_MAX_BYTES {
            return Err(LocalPasswordError::InvalidPassword);
        }
        let (parsed, params) = Self::parsed(phc)?;
        let prehash = self.prehash(password)?;
        let salt = parsed
            .salt
            .as_ref()
            .ok_or(LocalPasswordError::InvalidHash)?;
        let computed = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_with_salt(&*prehash, salt)
            .map_err(|_| LocalPasswordError::Hashing)?;
        // Output's PartialEq performs the SDK's constant-time comparison.
        Ok(computed.hash == parsed.hash)
    }
    fn parsed(phc: &str) -> Result<(PasswordHash, Params), LocalPasswordError> {
        let invalid = LocalPasswordError::InvalidHash;
        if phc.len() > PHC_MAX_BYTES {
            return Err(invalid);
        }
        let parsed = PasswordHash::new(phc).map_err(|_| invalid)?;
        if parsed.algorithm.as_str() != "argon2id"
            || parsed.version != Some(19)
            || parsed.params.iter().count() != 3
            || parsed
                .params
                .iter()
                .any(|(name, _)| !matches!(name.as_str(), "m" | "t" | "p"))
        {
            return Err(invalid);
        }
        let m = parsed.params.get_decimal("m").ok_or(invalid)?;
        let t = parsed.params.get_decimal("t").ok_or(invalid)?;
        let p = parsed.params.get_decimal("p").ok_or(invalid)?;
        let salt = parsed.salt.as_ref().ok_or(invalid)?;
        let hash = parsed.hash.as_ref().ok_or(invalid)?;
        if m > 1048576
            || t > 10
            || p > 16
            || !(16..=48).contains(&salt.len())
            || !(32..=64).contains(&hash.len())
        {
            return Err(invalid);
        }
        let params = Params::new(m, t, p, Some(hash.len())).map_err(|_| invalid)?;
        Ok((parsed, params))
    }
    fn prehash(&self, password: &str) -> Result<Zeroizing<[u8; 32]>, LocalPasswordError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.pepper)
            .map_err(|_| LocalPasswordError::Configuration)?;
        mac.update(DOMAIN);
        mac.update(password.as_bytes());
        let mut digest = mac.finalize().into_bytes();
        let mut out = Zeroizing::new([0; 32]);
        out.copy_from_slice(&digest);
        digest.zeroize();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Exercise non-default output length through the actual SDK and native prehash.
    #[test]
    fn sdk_output64_verifies_without_truncation_or_default32() {
        let owner =
            LocalPasswordHasher::new(Zeroizing::new(vec![7; 32].into_boxed_slice())).unwrap();
        let password = "native password with enough characters";
        let prehash = owner.prehash(password).unwrap();
        let params = Params::new(65536, 3, 4, Some(64)).unwrap();
        let phc = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_with_salt(&*prehash, &[11; 48])
            .unwrap()
            .to_string();
        assert!(owner.verify(password, &phc).unwrap());
        assert!(
            !owner
                .verify("different password long enough", &phc)
                .unwrap()
        );
    }
}
