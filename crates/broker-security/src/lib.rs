//! Bounded, domain-separated credential digests for Broker server persistence.
//!
//! These values are data. Authentication and authorization must additionally
//! consult current persistent state, revocation, expiry and grants.
//!
//! The policy values here are synthetic example limits, not server defaults.
//! ```
//! use broker_security::{CredentialDigester, DigestLimits, TokenKind};
//! use std::num::NonZeroUsize;
//! use zeroize::Zeroizing;
//! let limit = NonZeroUsize::new(128).unwrap();
//! let limits = DigestLimits::new(limit, limit, limit, limit, limit)?;
//! let pepper = Zeroizing::new(vec![42; 32].into_boxed_slice());
//! let digester = CredentialDigester::new(pepper, limits)?;
//! let digest = digester.token(TokenKind::AdminSession, b"synthetic-session")?;
//! let stored = digest.to_sql_hex();
//! let expected = broker_security::CredentialDigest::parse_sql_hex(&stored)?;
//! digester.verify_token(TokenKind::AdminSession, b"synthetic-session", &expected)?;
//! # Ok::<(), broker_security::CredentialError>(())
//! ```
//!
//! The digester deliberately does not allow cloning or key access. The input
//! wrapper itself permits access and cloning before ownership is transferred;
//! callers remain responsible for their earlier copies.
//! ```compile_fail
//! use broker_security::CredentialDigester;
//! fn duplicate(value: &CredentialDigester) -> CredentialDigester {
//!     Clone::clone(value)
//! }
//! ```
//! ```compile_fail
//! use broker_security::CredentialDigester;
//! fn key(value: &CredentialDigester) -> &[u8] { &value.pepper }
//! ```
//! ```compile_fail
//! use broker_security::CredentialDigester;
//! fn key(value: &CredentialDigester) -> &[u8] {
//!     AsRef::<[u8]>::as_ref(value)
//! }
//! ```
//! ```compile_fail
//! use broker_security::{CredentialDigester, DigestLimits};
//! use zeroize::Zeroizing;
//! fn transferred(limits: DigestLimits) {
//!     let pepper = Zeroizing::new(vec![42; 32].into_boxed_slice());
//!     let _digester = CredentialDigester::new(pepper, limits);
//!     let _copy = pepper.clone();
//! }
//! ```

pub mod credentials;

pub use credentials::{
    CredentialDigest, CredentialDigester, CredentialError, DigestLimits, LocalAuthBinding,
    LocalAuthPurpose, NativeOidcSubject, TokenKind,
};

mod password;
pub use password::{LOCAL_PASSWORD_MAX_BYTES, LocalPasswordError, LocalPasswordHasher};

mod local_mfa;
pub use local_mfa::{
    LocalMfaEnrollment, LocalMfaError, LocalMfaProtector, LocalRecoveryCodes, PreparedLocalMfa,
    new_local_auth_challenge, normalize_local_recovery_code, validate_local_auth_challenge,
};
