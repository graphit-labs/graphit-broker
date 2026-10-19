//! Native authenticated registration preserves the authorization/read and write
//! failure origins, including the SQL writer's uncertain COMMIT outcome.
use crate::{BrokerPresenceAuthorizationError, InstanceRegistryError};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerInstanceRegistrationError {
    Authorization(BrokerPresenceAuthorizationError),
    Registry(InstanceRegistryError),
}
impl From<BrokerPresenceAuthorizationError> for BrokerInstanceRegistrationError {
    fn from(value: BrokerPresenceAuthorizationError) -> Self {
        Self::Authorization(value)
    }
}
impl From<InstanceRegistryError> for BrokerInstanceRegistrationError {
    fn from(value: InstanceRegistryError) -> Self {
        Self::Registry(value)
    }
}
impl fmt::Display for BrokerInstanceRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => error.fmt(f),
            Self::Registry(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for BrokerInstanceRegistrationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrokerAccessError, ControlError};
    #[test]
    fn finite_errors_keep_authentication_and_both_uncertainty_origins() {
        let read = BrokerPresenceAuthorizationError::Control(ControlError::OutcomeUncertain);
        let write = InstanceRegistryError::Control(ControlError::OutcomeUncertain);
        assert_eq!(
            BrokerInstanceRegistrationError::from(read),
            BrokerInstanceRegistrationError::Authorization(read)
        );
        assert_eq!(
            BrokerInstanceRegistrationError::from(write),
            BrokerInstanceRegistrationError::Registry(write)
        );
        let expiry = BrokerPresenceAuthorizationError::Authentication(BrokerAccessError::Expired);
        assert_eq!(
            BrokerInstanceRegistrationError::from(expiry),
            BrokerInstanceRegistrationError::Authorization(expiry)
        );
        let error =
            BrokerInstanceRegistrationError::from(BrokerPresenceAuthorizationError::Forbidden);
        assert_eq!(error.to_string(), "presence access denied");
        assert!(std::error::Error::source(&error).is_none());
    }
}
