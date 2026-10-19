use super::{
    SqliteControlStore, SqliteInstanceInventories, SqliteLocalBearerVerifier, SqliteResourceGrants,
};
use crate::{
    AuthorizedInstanceInventory, ControlError, InstanceInventoryReadError,
    PresenceAuthorizationError, PresenceCapability, flow::now_micros,
    presence_authorization::check_deadline, resource_policy::ResourcePolicy,
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Current local Auth plus complete own-inventory Read permission.
/// ~~~compile_fail
/// fn escape(store: &broker_control::SqliteControlStore) -> broker_control::SqliteLocalInstanceInventoryReader<'static> {
///     let n=std::num::NonZeroUsize::new(4096).unwrap();
///     store.local_instance_inventory_reader("aud",n,n,n).unwrap()
/// }
/// ~~~
pub struct SqliteLocalInstanceInventoryReader<'a> {
    owner: &'a SqliteControlStore,
    verifier: SqliteLocalBearerVerifier<'a>,
    grants: SqliteResourceGrants<'a>,
    inventories: SqliteInstanceInventories<'a>,
}
impl fmt::Debug for SqliteLocalInstanceInventoryReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalInstanceInventoryReader([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn local_instance_inventory_reader<'a>(
        &'a self,
        audience: &'a str,
        identity_json_bytes: NonZeroUsize,
        grants_json_bytes: NonZeroUsize,
        inventory_json_bytes: NonZeroUsize,
    ) -> Result<SqliteLocalInstanceInventoryReader<'a>, InstanceInventoryReadError> {
        Ok(SqliteLocalInstanceInventoryReader {
            owner: self,
            verifier: self
                .local_bearer_verifier(audience, identity_json_bytes)
                .map_err(PresenceAuthorizationError::from)?,
            grants: self
                .resource_grants(grants_json_bytes)
                .map_err(PresenceAuthorizationError::from)?,
            inventories: self.instance_inventories(inventory_json_bytes)?,
        })
    }
}
impl SqliteLocalInstanceInventoryReader<'_> {
    pub async fn read(
        &self,
        raw: &str,
        required_scopes: &[String],
        instance_id: &str,
        caller: Instant,
    ) -> Result<Option<AuthorizedInstanceInventory>, InstanceInventoryReadError> {
        let end = self
            .owner
            .executor
            .deadline(caller)
            .map_err(ControlError::from)
            .map_err(PresenceAuthorizationError::from)?;
        let mut principal = self
            .verifier
            .verify(raw, required_scopes, end)
            .await
            .map_err(PresenceAuthorizationError::from)?;
        // This SQL reader owns its COMMIT confirmation; no outer timeout replaces it.
        let snapshot = self.inventories.read(instance_id, end).await?;
        principal
            .finish(now_micros().map_err(PresenceAuthorizationError::from)?)
            .map_err(PresenceAuthorizationError::from)?;
        check_deadline(end)?;
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        let user = principal.current_local_user();
        if snapshot.owner().issuer() != user.issuer()
            || snapshot.owner().subject() != user.subject()
        {
            return Err(InstanceInventoryReadError::OwnerConflict);
        }
        let grants = self
            .grants
            .read(end)
            .await
            .map_err(PresenceAuthorizationError::from)?;
        let policy =
            ResourcePolicy::compile(&grants, end).map_err(PresenceAuthorizationError::from)?;
        let allowed = if snapshot.inventory().projects().is_empty() {
            policy
                .allows_any_project(user, PresenceCapability::Read.as_str(), end)
                .map_err(PresenceAuthorizationError::from)?
        } else {
            let mut allowed = true;
            for project in snapshot.inventory().projects() {
                if !policy
                    .allows(
                        user,
                        PresenceCapability::Read.as_str(),
                        project.project_id(),
                        end,
                    )
                    .map_err(PresenceAuthorizationError::from)?
                {
                    allowed = false;
                    break;
                }
            }
            allowed
        };
        if !allowed {
            return Err(PresenceAuthorizationError::Forbidden.into());
        }
        principal
            .finish(now_micros().map_err(PresenceAuthorizationError::from)?)
            .map_err(PresenceAuthorizationError::from)?;
        check_deadline(end)?;
        Ok(Some(AuthorizedInstanceInventory { snapshot }))
    }
}
