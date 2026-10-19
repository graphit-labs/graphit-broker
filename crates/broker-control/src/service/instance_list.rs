use super::{
    PostgresControlStore, PostgresInstanceInventories, PostgresInstanceInventoryCandidates,
    PostgresLocalBearerVerifier, PostgresResourceGrants, bounded_deadline,
};
use crate::{
    AuthorizedInstanceList, AuthorizedInstanceListItem, InstanceInventory, InstanceListError,
    InstanceListQuery, InstanceProjectVersions, InstanceReadError, LocalBearerUser,
    PresenceAuthorizationError, PresenceCapability, StoredInstanceInventory, flow::now_micros,
    presence_authorization::check_deadline, resource_policy::ResourcePolicy,
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Current raw local Auth and a fresh whole policy for one partially projected page.
/// ~~~compile_fail
/// fn escape(store: &broker_control::PostgresControlStore) -> broker_control::PostgresLocalInstanceInventoryLister<'static> {
///     let n=std::num::NonZeroUsize::new(4096).unwrap();
///     store.local_instance_inventory_lister("aud",n,n,n).unwrap()
/// }
/// ~~~
pub struct PostgresLocalInstanceInventoryLister<'a> {
    owner: &'a PostgresControlStore,
    verifier: PostgresLocalBearerVerifier<'a>,
    grants: PostgresResourceGrants<'a>,
    candidates: PostgresInstanceInventoryCandidates<'a>,
    inventories: PostgresInstanceInventories<'a>,
}
impl fmt::Debug for PostgresLocalInstanceInventoryLister<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresLocalInstanceInventoryLister([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn local_instance_inventory_lister<'a>(
        &'a self,
        audience: &'a str,
        identity_json_bytes: NonZeroUsize,
        grants_json_bytes: NonZeroUsize,
        inventory_json_bytes: NonZeroUsize,
    ) -> Result<PostgresLocalInstanceInventoryLister<'a>, InstanceListError> {
        Ok(PostgresLocalInstanceInventoryLister {
            owner: self,
            verifier: self
                .local_bearer_verifier(audience, identity_json_bytes)
                .map_err(PresenceAuthorizationError::from)?,
            grants: self
                .resource_grants(grants_json_bytes)
                .map_err(PresenceAuthorizationError::from)?,
            candidates: self.instance_inventory_candidates(inventory_json_bytes)?,
            inventories: self.instance_inventories(inventory_json_bytes)?,
        })
    }
}
impl PostgresLocalInstanceInventoryLister<'_> {
    pub async fn list(
        &self,
        raw: &str,
        required_scopes: &[String],
        query: &InstanceListQuery,
        original: Instant,
    ) -> Result<AuthorizedInstanceList, InstanceListError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)
            .map_err(PresenceAuthorizationError::from)?;
        let mut principal = self
            .verifier
            .verify(raw, required_scopes, end)
            .await
            .map_err(PresenceAuthorizationError::from)?;
        let grants = self
            .grants
            .read(end)
            .await
            .map_err(PresenceAuthorizationError::from)?;
        let policy =
            ResourcePolicy::compile(&grants, end).map_err(PresenceAuthorizationError::from)?;
        principal
            .finish(now_micros().map_err(PresenceAuthorizationError::from)?)
            .map_err(PresenceAuthorizationError::from)?;
        check_deadline(end)?;
        let mut items = Vec::new();
        let mut more = false;
        if let Some(id) = query.instance_id.as_deref() {
            if !query.after.as_deref().is_some_and(|after| after >= id) {
                // The SQL producer owns COMMIT classification; there is no outer business timeout.
                let snapshot = self.inventories.read(id, end).await?;
                principal
                    .finish(now_micros().map_err(PresenceAuthorizationError::from)?)
                    .map_err(PresenceAuthorizationError::from)?;
                check_deadline(end)?;
                if let Some(snapshot) = snapshot
                    && let Some(item) = project(
                        &snapshot,
                        principal.current_local_user(),
                        &policy,
                        query,
                        end,
                    )?
                {
                    items.push(item);
                }
            }
        } else {
            let mut cursor = query.after.clone();
            loop {
                check_deadline(end)?;
                let snapshot = self.candidates.read_next(cursor.as_deref(), end).await?;
                principal
                    .finish(now_micros().map_err(PresenceAuthorizationError::from)?)
                    .map_err(PresenceAuthorizationError::from)?;
                check_deadline(end)?;
                let Some(snapshot) = snapshot else {
                    break;
                };
                cursor = Some(snapshot.inventory().instance_id().to_owned());
                if let Some(item) = project(
                    &snapshot,
                    principal.current_local_user(),
                    &policy,
                    query,
                    end,
                )? {
                    if items.len() == query.limit.get() {
                        more = true;
                        break;
                    }
                    items.push(item);
                }
            }
        }
        principal
            .finish(now_micros().map_err(PresenceAuthorizationError::from)?)
            .map_err(PresenceAuthorizationError::from)?;
        check_deadline(end)?;
        let next_after = if more {
            items
                .last()
                .map(|item| item.inventory().instance_id().to_owned())
        } else {
            None
        };
        Ok(AuthorizedInstanceList { items, next_after })
    }
}
fn project(
    snapshot: &StoredInstanceInventory,
    user: &LocalBearerUser,
    policy: &ResourcePolicy<'_>,
    query: &InstanceListQuery,
    end: Instant,
) -> Result<Option<AuthorizedInstanceListItem>, InstanceListError> {
    check_deadline(end)?;
    let inventory = snapshot.inventory();
    let mut projects = Vec::new();
    if inventory.projects().is_empty() {
        if query.project_id.is_some()
            || query.version.is_some()
            || snapshot.owner().issuer() != user.issuer()
            || snapshot.owner().subject() != user.subject()
            || !policy
                .allows_any_project(user, PresenceCapability::Read.as_str(), end)
                .map_err(PresenceAuthorizationError::from)?
        {
            return Ok(None);
        }
    } else {
        for stored in inventory.projects() {
            check_deadline(end)?;
            if query
                .project_id
                .as_deref()
                .is_some_and(|id| id != stored.project_id())
                || !policy
                    .allows(
                        user,
                        PresenceCapability::Read.as_str(),
                        stored.project_id(),
                        end,
                    )
                    .map_err(PresenceAuthorizationError::from)?
            {
                continue;
            }
            let mut versions = Vec::new();
            for version in stored.versions() {
                check_deadline(end)?;
                if query
                    .version
                    .as_deref()
                    .is_none_or(|requested| requested == version)
                {
                    versions.push(version.clone());
                }
            }
            if !versions.is_empty() {
                projects.push(
                    InstanceProjectVersions::new(stored.project_id().to_owned(), versions)
                        .map_err(|_| InstanceReadError::MalformedStored)?,
                );
            }
        }
        if projects.is_empty() {
            return Ok(None);
        }
    }
    check_deadline(end)?;
    let inventory = InstanceInventory::new(inventory.instance_id().to_owned(), projects)
        .map_err(|_| InstanceReadError::MalformedStored)?;
    Ok(Some(AuthorizedInstanceListItem {
        inventory,
        created_at: snapshot.created_at_micros(),
        updated_at: snapshot.updated_at_micros(),
    }))
}
