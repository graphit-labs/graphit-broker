//! A completed Native own-inventory observation, not an authority lease.
use crate::{
    BrokerPresenceAuthorizationError, InstanceInventory, InstanceReadError,
    StoredInstanceInventory, VerifiedBrokerAccess,
};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerInstanceInventoryReadError {
    Authorization(BrokerPresenceAuthorizationError),
    Inventory(InstanceReadError),
    NotFound,
    OwnerConflict,
}
impl From<BrokerPresenceAuthorizationError> for BrokerInstanceInventoryReadError {
    fn from(value: BrokerPresenceAuthorizationError) -> Self {
        Self::Authorization(value)
    }
}
impl From<InstanceReadError> for BrokerInstanceInventoryReadError {
    fn from(value: InstanceReadError) -> Self {
        Self::Inventory(value)
    }
}
impl fmt::Display for BrokerInstanceInventoryReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => error.fmt(f),
            Self::Inventory(error) => error.fmt(f),
            Self::NotFound => f.write_str("installation not found"),
            Self::OwnerConflict => f.write_str("installation belongs to another owner"),
        }
    }
}
impl std::error::Error for BrokerInstanceInventoryReadError {}

/// Completed read data exposes neither its stored owner nor verified credential.
/// It retains the actual verifier borrow; getters are not renewable ACL leases.
/// ~~~compile_fail
/// let _ = broker_control::AuthorizedBrokerInstanceInventory::new();
/// ~~~
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::AuthorizedBrokerInstanceInventory<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::AuthorizedBrokerInstanceInventory<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require_deserialize<'de, T: serde::Deserialize<'de>>() {}
/// require_deserialize::<broker_control::AuthorizedBrokerInstanceInventory<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn expose(value: broker_control::AuthorizedBrokerInstanceInventory<'_>) {
///     let _ = value.snapshot;
/// }
/// ~~~
/// ~~~compile_fail
/// fn expose(value: broker_control::AuthorizedBrokerInstanceInventory<'_>) {
///     let _ = value.principal();
/// }
/// ~~~
pub struct AuthorizedBrokerInstanceInventory<'a> {
    pub(crate) snapshot: StoredInstanceInventory,
    // The real verified principal anchors the verifier lifetime. It is not
    // exposed as authority for another operation or checked by data getters.
    pub(crate) _principal: VerifiedBrokerAccess<'a>,
    pub(crate) policy_revision: i64,
}
impl AuthorizedBrokerInstanceInventory<'_> {
    pub fn inventory(&self) -> &InstanceInventory {
        self.snapshot.inventory()
    }
    pub fn created_at_micros(&self) -> i64 {
        self.snapshot.created_at_micros()
    }
    pub fn updated_at_micros(&self) -> i64 {
        self.snapshot.updated_at_micros()
    }
    pub fn policy_revision(&self) -> i64 {
        self.policy_revision
    }
}
impl fmt::Debug for AuthorizedBrokerInstanceInventory<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedBrokerInstanceInventory([REDACTED])")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrokerAccessError, ControlError};
    #[test]
    fn finite_errors_preserve_read_origins_and_do_not_keep_causes() {
        let auth = BrokerPresenceAuthorizationError::Control(ControlError::OutcomeUncertain);
        let data = InstanceReadError::Control(ControlError::OutcomeUncertain);
        assert_eq!(
            BrokerInstanceInventoryReadError::from(auth),
            BrokerInstanceInventoryReadError::Authorization(auth)
        );
        assert_eq!(
            BrokerInstanceInventoryReadError::from(data),
            BrokerInstanceInventoryReadError::Inventory(data)
        );
        let expired = BrokerPresenceAuthorizationError::Authentication(BrokerAccessError::Expired);
        assert_eq!(
            BrokerInstanceInventoryReadError::from(expired),
            BrokerInstanceInventoryReadError::Authorization(expired)
        );
        for (error, expected) in [
            (
                BrokerInstanceInventoryReadError::NotFound,
                "installation not found",
            ),
            (
                BrokerInstanceInventoryReadError::OwnerConflict,
                "installation belongs to another owner",
            ),
        ] {
            assert_eq!(error.to_string(), expected);
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}
