//! A completed local-authenticated own-inventory read, not a reusable authority lease.
use crate::{
    InstanceInventory, InstanceReadError, PresenceAuthorizationError, StoredInstanceInventory,
};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceInventoryReadError {
    Authorization(PresenceAuthorizationError),
    Inventory(InstanceReadError),
    OwnerConflict,
}
impl From<PresenceAuthorizationError> for InstanceInventoryReadError {
    fn from(value: PresenceAuthorizationError) -> Self {
        Self::Authorization(value)
    }
}
impl From<InstanceReadError> for InstanceInventoryReadError {
    fn from(value: InstanceReadError) -> Self {
        Self::Inventory(value)
    }
}
impl fmt::Display for InstanceInventoryReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => error.fmt(f),
            Self::Inventory(error) => error.fmt(f),
            Self::OwnerConflict => f.write_str("installation belongs to another owner"),
        }
    }
}
impl std::error::Error for InstanceInventoryReadError {}

/// A completed authorized read exposes no stored owner or credential.
/// ~~~compile_fail
/// fn fabricate() { let _ = broker_control::AuthorizedInstanceInventory::new(); }
/// ~~~
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::AuthorizedInstanceInventory>();
/// ~~~
/// ~~~compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::AuthorizedInstanceInventory>();
/// ~~~
/// ~~~compile_fail
/// fn require_deserialize<'de, T: serde::Deserialize<'de>>() {}
/// require_deserialize::<broker_control::AuthorizedInstanceInventory>();
/// ~~~
pub struct AuthorizedInstanceInventory {
    pub(crate) snapshot: StoredInstanceInventory,
}
impl AuthorizedInstanceInventory {
    pub fn inventory(&self) -> &InstanceInventory {
        self.snapshot.inventory()
    }
    pub fn created_at_micros(&self) -> i64 {
        self.snapshot.created_at_micros()
    }
    pub fn updated_at_micros(&self) -> i64 {
        self.snapshot.updated_at_micros()
    }
}
impl fmt::Debug for AuthorizedInstanceInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedInstanceInventory([REDACTED])")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ControlError, LocalBearerStateError, LocalBearerVerificationError, ResourceGrantReadError,
    };
    #[test]
    fn finite_read_errors_preserve_nested_uncertainty_and_redact_data() {
        let uncertain = ControlError::OutcomeUncertain;
        let inventory = InstanceInventoryReadError::from(InstanceReadError::Control(uncertain));
        assert_eq!(
            inventory,
            InstanceInventoryReadError::Inventory(InstanceReadError::Control(uncertain))
        );
        let auth = PresenceAuthorizationError::from(LocalBearerVerificationError::State(
            LocalBearerStateError::Control(uncertain),
        ));
        let grants = PresenceAuthorizationError::from(ResourceGrantReadError::Control(uncertain));
        for error in [
            inventory,
            InstanceInventoryReadError::from(auth),
            InstanceInventoryReadError::from(grants),
            InstanceInventoryReadError::OwnerConflict,
            InstanceInventoryReadError::Authorization(PresenceAuthorizationError::Forbidden),
        ] {
            let message = format!("{error:?} {error}");
            assert!(!message.contains("gb_at_"));
            assert!(!message.contains("SELECT"));
        }
    }
}
