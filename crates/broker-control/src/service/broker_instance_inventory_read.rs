use super::{
    PostgresControlStore, PostgresInstanceInventories, PostgresResourceGrants, bounded_deadline,
};
use crate::{
    AuthorizedBrokerInstanceInventory, BrokerAccessVerifier, BrokerInstanceInventoryReadError,
    BrokerPresenceAuthorizationError, PresenceCapability,
    resource_policy::{ResourcePolicy, check_deadline},
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Native JWT plus whole current Read policy and literal own SQL inventory.
/// ~~~
/// use broker_control::{BrokerAccessVerifier, BrokerInstanceInventoryReadError,
///     PostgresBrokerInstanceInventoryReader, PostgresControlStore};
/// use std::num::NonZeroUsize;
/// fn configured<'a>(store: &'a PostgresControlStore, verifier: &'a BrokerAccessVerifier,
///     grants_bytes: NonZeroUsize, inventory_bytes: NonZeroUsize,
/// ) -> Result<PostgresBrokerInstanceInventoryReader<'a>, BrokerInstanceInventoryReadError> {
///     store.broker_instance_inventory_reader(verifier, grants_bytes, inventory_bytes)
/// }
/// ~~~
/// ~~~compile_fail
/// fn escape(store: &broker_control::PostgresControlStore,
///     verifier: &broker_control::BrokerAccessVerifier,
/// ) -> broker_control::PostgresBrokerInstanceInventoryReader<'static> {
///     let n=std::num::NonZeroUsize::new(4096).unwrap();
///     store.broker_instance_inventory_reader(verifier,n,n).unwrap()
/// }
/// ~~~
/// ~~~compile_fail
/// async fn escape(store: &broker_control::PostgresControlStore,
///     verifier: &broker_control::BrokerAccessVerifier, token: &str,
/// ) -> broker_control::AuthorizedBrokerInstanceInventory<'static> {
///     let n=std::num::NonZeroUsize::new(4096).unwrap();
///     store.broker_instance_inventory_reader(verifier,n,n).unwrap()
///         .read(token,&[],"station",std::time::Instant::now()).await.unwrap()
/// }
/// ~~~
pub struct PostgresBrokerInstanceInventoryReader<'a> {
    owner: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants: PostgresResourceGrants<'a>,
    inventories: PostgresInstanceInventories<'a>,
}
impl fmt::Debug for PostgresBrokerInstanceInventoryReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresBrokerInstanceInventoryReader([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn broker_instance_inventory_reader<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
        inventory_json_bytes: NonZeroUsize,
    ) -> Result<PostgresBrokerInstanceInventoryReader<'a>, BrokerInstanceInventoryReadError> {
        Ok(PostgresBrokerInstanceInventoryReader {
            owner: self,
            verifier,
            grants: self
                .resource_grants(grants_json_bytes)
                .map_err(BrokerPresenceAuthorizationError::from)?,
            inventories: self.instance_inventories(inventory_json_bytes)?,
        })
    }
}
impl<'a> PostgresBrokerInstanceInventoryReader<'a> {
    /// The original deadline is bounded once; each SQL reader owns its COMMIT.
    /// Missing, foreign and forbidden decisions follow the final JWT/time check.
    pub async fn read(
        &self,
        raw: &str,
        required_scopes: &[String],
        instance_id: &str,
        original: Instant,
    ) -> Result<AuthorizedBrokerInstanceInventory<'a>, BrokerInstanceInventoryReadError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)
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
