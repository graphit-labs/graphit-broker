use super::{SqliteControlStore, SqliteResourceGrants};
use crate::{
    BrokerAccessVerifier, BrokerInstanceRegistrationError, BrokerPresenceAuthorizationError,
    InstanceInventory, InstanceOwner, PresenceCapability, RegistrationResult,
    resource_policy::{ResourcePolicy, check_deadline},
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Real JWT and fresh whole SQLite ACL, borrowing the actual store and verifier.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore,
///     verifier: &broker_control::BrokerAccessVerifier) -> broker_control::SqliteBrokerInstanceRegistrar<'static> {
///     let cap = std::num::NonZeroUsize::new(4096).unwrap();
///     store.broker_instance_registrar(verifier, cap).unwrap()
/// }
/// ```
pub struct SqliteBrokerInstanceRegistrar<'a> {
    owner: &'a SqliteControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants: SqliteResourceGrants<'a>,
}
impl fmt::Debug for SqliteBrokerInstanceRegistrar<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteBrokerInstanceRegistrar([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn broker_instance_registrar<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
    ) -> Result<SqliteBrokerInstanceRegistrar<'a>, BrokerInstanceRegistrationError> {
        Ok(SqliteBrokerInstanceRegistrar {
            owner: self,
            verifier,
            grants: self
                .resource_grants(grants_json_bytes)
                .map_err(BrokerPresenceAuthorizationError::from)?,
        })
    }
}
impl SqliteBrokerInstanceRegistrar<'_> {
    /// ALL projects require current Presence Publish; empty requires explicit Any.
    /// The signed identity is checked again before denying or entering the writer.
    /// These observations do not freeze authorization during the write.
    pub async fn register(
        &self,
        raw: &str,
        required_scopes: &[String],
        inventory: &InstanceInventory,
        original: Instant,
    ) -> Result<RegistrationResult, BrokerInstanceRegistrationError> {
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(crate::ControlError::from)
            .map_err(BrokerPresenceAuthorizationError::from)?;
        let principal = self
            .verifier
            .verify(raw, required_scopes, end)
            .map_err(BrokerPresenceAuthorizationError::from)?;
        let snapshot = self
            .grants
            .read(end)
            .await
            .map_err(BrokerPresenceAuthorizationError::from)?;
        let policy = ResourcePolicy::compile(&snapshot, end)
            .map_err(BrokerPresenceAuthorizationError::from)?;
        let allowed = if inventory.projects().is_empty() {
            policy
                .allows_any_broker(&principal, PresenceCapability::Publish.as_str(), end)
                .map_err(BrokerPresenceAuthorizationError::from)?
        } else {
            let mut allowed = true;
            for project in inventory.projects() {
                if !policy
                    .allows_broker(
                        &principal,
                        PresenceCapability::Publish.as_str(),
                        project.project_id(),
                        end,
                    )
                    .map_err(BrokerPresenceAuthorizationError::from)?
                {
                    allowed = false;
                    break;
                }
            }
            allowed
        };
        principal
            .check()
            .map_err(BrokerPresenceAuthorizationError::from)?;
        check_deadline(end).map_err(BrokerPresenceAuthorizationError::from)?;
        if !allowed {
            return Err(BrokerPresenceAuthorizationError::Forbidden.into());
        }
        let owner = InstanceOwner::new(principal.issuer(), principal.subject())?;
        // The unchanged writer owns cancellation and COMMIT uncertainty. An
        // outer timeout or automatic replay could hide an already started COMMIT.
        self.owner
            .replace_instance_inventory(&owner, inventory, end)
            .await
            .map_err(Into::into)
    }
}
