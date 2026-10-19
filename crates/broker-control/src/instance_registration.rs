//! The authenticated server operation returns the registry's confirmed commit result.
use crate::{InstanceRegistryError, PresenceAuthorizationError};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceRegistrationError {
    Authorization(PresenceAuthorizationError),
    Registry(InstanceRegistryError),
}
impl From<PresenceAuthorizationError> for InstanceRegistrationError {
    fn from(value: PresenceAuthorizationError) -> Self {
        Self::Authorization(value)
    }
}
impl From<InstanceRegistryError> for InstanceRegistrationError {
    fn from(value: InstanceRegistryError) -> Self {
        Self::Registry(value)
    }
}
impl fmt::Display for InstanceRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => error.fmt(f),
            Self::Registry(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for InstanceRegistrationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlError;
    #[test]
    fn writer_uncertainty_and_authorization_errors_keep_their_finite_variants() {
        assert_eq!(
            InstanceRegistrationError::from(InstanceRegistryError::Control(
                ControlError::OutcomeUncertain
            )),
            InstanceRegistrationError::Registry(InstanceRegistryError::Control(
                ControlError::OutcomeUncertain
            ))
        );
        assert_eq!(
            InstanceRegistrationError::from(PresenceAuthorizationError::Forbidden),
            InstanceRegistrationError::Authorization(PresenceAuthorizationError::Forbidden)
        );
    }
}
