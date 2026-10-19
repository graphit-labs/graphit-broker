//! Explicit first-administrator creation over a deployment-owned SQL store.
//! This operation never authenticates a request or issues a session.
use crate::ControlError;
use broker_security::LocalPasswordHasher;
use std::fmt;

/// A finite result that never contains a password, PHC or driver diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAdministratorBootstrapError {
    InvalidPasswordInput,
    InvalidPasswordHash,
    AlreadyInitialized,
    Control(ControlError),
}
impl From<ControlError> for LocalAdministratorBootstrapError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}
impl fmt::Display for LocalAdministratorBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPasswordInput => {
                f.write_str("invalid initial administrator password input")
            }
            Self::InvalidPasswordHash => {
                f.write_str("invalid initial administrator password verifier")
            }
            Self::AlreadyInitialized => f.write_str("local user catalog is already initialized"),
            Self::Control(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for LocalAdministratorBootstrapError {}
pub(crate) fn validate_hash(hash: &str) -> Result<(), LocalAdministratorBootstrapError> {
    LocalPasswordHasher::validate_hash(hash)
        .map_err(|_| LocalAdministratorBootstrapError::InvalidPasswordHash)
}

/// Validate the existing LOCAL creation policy before starting a KDF or SQL owner.
pub fn validate_initial_administrator_password(
    password: &str,
) -> Result<(), LocalAdministratorBootstrapError> {
    if crate::admin_users::validation::valid_new_password(password) {
        Ok(())
    } else {
        Err(LocalAdministratorBootstrapError::InvalidPasswordInput)
    }
}
