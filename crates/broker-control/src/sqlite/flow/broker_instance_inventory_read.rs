use super::{SqliteControlStore, SqliteInstanceInventories, SqliteResourceGrants};
use crate::{
    AuthorizedBrokerInstanceInventory, BrokerAccessVerifier, BrokerInstanceInventoryReadError,
    BrokerPresenceAuthorizationError, PresenceCapability,
    resource_policy::{ResourcePolicy, check_deadline},
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Real JWT and fresh whole SQLite ACL, borrowing the actual store and verifier.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore,
///     verifier: &broker_control::BrokerAccessVerifier) -> broker_control::SqliteBrokerInstanceInventoryReader<'static> {
///     let cap = std::num::NonZeroUsize::new(4096).unwrap();
///     store.broker_instance_inventory_reader(verifier, cap, cap).unwrap()
/// }
/// ```
pub struct SqliteBrokerInstanceInventoryReader<'a> {
    owner: &'a SqliteControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants: SqliteResourceGrants<'a>,
    inventories: SqliteInstanceInventories<'a>,
}
impl fmt::Debug for SqliteBrokerInstanceInventoryReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteBrokerInstanceInventoryReader([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn broker_instance_inventory_reader<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
        inventory_json_bytes: NonZeroUsize,
    ) -> Result<SqliteBrokerInstanceInventoryReader<'a>, BrokerInstanceInventoryReadError> {
        Ok(SqliteBrokerInstanceInventoryReader {
            owner: self,
            verifier,
            grants: self
                .resource_grants(grants_json_bytes)
                .map_err(BrokerPresenceAuthorizationError::from)?,
            inventories: self.instance_inventories(inventory_json_bytes)?,
        })
    }
}
impl<'a> SqliteBrokerInstanceInventoryReader<'a> {
    /// The original deadline is bounded once; each SQL reader owns its COMMIT.
    /// Missing, foreign and forbidden decisions follow the final JWT/time check.
    pub async fn read(
        &self,
        raw: &str,
        required_scopes: &[String],
        instance_id: &str,
        original: Instant,
    ) -> Result<AuthorizedBrokerInstanceInventory<'a>, BrokerInstanceInventoryReadError> {
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
        let grants = self
            .grants
            .read(end)
            .await
            .map_err(BrokerPresenceAuthorizationError::from)?;
        let policy = ResourcePolicy::compile(&grants, end)
            .map_err(BrokerPresenceAuthorizationError::from)?;
        // No outer timeout/replay may hide either reader's COMMIT uncertainty.
        let snapshot = self.inventories.read(instance_id, end).await?;
        let decision = if let Some(snapshot) = snapshot.as_ref() {
            if snapshot.owner().issuer() != principal.issuer()
                || snapshot.owner().subject() != principal.subject()
            {
                Err(BrokerInstanceInventoryReadError::OwnerConflict)
            } else {
                let allowed = if snapshot.inventory().projects().is_empty() {
                    policy
                        .allows_any_broker(&principal, PresenceCapability::Read.as_str(), end)
                        .map_err(BrokerPresenceAuthorizationError::from)?
                } else {
                    let mut allowed = true;
                    for project in snapshot.inventory().projects() {
                        if !policy
                            .allows_broker(
                                &principal,
                                PresenceCapability::Read.as_str(),
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
                if allowed {
                    Ok(())
                } else {
                    Err(BrokerPresenceAuthorizationError::Forbidden.into())
                }
            }
        } else {
            Err(BrokerInstanceInventoryReadError::NotFound)
        };
        principal
            .check()
            .map_err(BrokerPresenceAuthorizationError::from)?;
        check_deadline(end).map_err(BrokerPresenceAuthorizationError::from)?;
        decision?;
        let snapshot = snapshot.ok_or(BrokerInstanceInventoryReadError::NotFound)?;
        Ok(AuthorizedBrokerInstanceInventory {
            snapshot,
            _principal: principal,
            policy_revision: grants.revision(),
        })
    }
}
