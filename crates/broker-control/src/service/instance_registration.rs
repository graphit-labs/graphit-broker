use super::{
    PostgresControlStore, PostgresLocalBearerVerifier, PostgresResourceGrants, bounded_deadline,
};
use crate::{
    ControlError, InstanceInventory, InstanceOwner, InstanceRegistrationError,
    PresenceAuthorizationError, PresenceCapability, RegistrationResult, flow::now_micros,
    presence_authorization::check_deadline, resource_policy::ResourcePolicy,
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Registers only through a raw bearer and current grants; the input contains no owner.
/// The registrar borrows its store:
/// ~~~compile_fail
/// fn escape(store: &broker_control::PostgresControlStore)
///     -> broker_control::PostgresLocalInstanceRegistrar<'static> {
///     store.local_instance_registrar("aud", std::num::NonZeroUsize::new(4096).unwrap(),
///         std::num::NonZeroUsize::new(16384).unwrap()).unwrap()
/// }
/// ~~~
pub struct PostgresLocalInstanceRegistrar<'a> {
    owner: &'a PostgresControlStore,
    verifier: PostgresLocalBearerVerifier<'a>,
    grants: PostgresResourceGrants<'a>,
}
impl fmt::Debug for PostgresLocalInstanceRegistrar<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresLocalInstanceRegistrar([REDACTED])")
    }
}
impl PostgresControlStore {
    /// Use the explicit local audience and existing useful identity/grant byte limits.
    pub fn local_instance_registrar<'a>(
        &'a self,
        audience: &'a str,
        identity_json_bytes: NonZeroUsize,
        grants_json_bytes: NonZeroUsize,
    ) -> Result<PostgresLocalInstanceRegistrar<'a>, InstanceRegistrationError> {
        Ok(PostgresLocalInstanceRegistrar {
            owner: self,
            verifier: self
                .local_bearer_verifier(audience, identity_json_bytes)
                .map_err(PresenceAuthorizationError::from)?,
            grants: self
                .resource_grants(grants_json_bytes)
                .map_err(PresenceAuthorizationError::from)?,
        })
    }
}
impl PostgresLocalInstanceRegistrar<'_> {
    /// Verify current local identity and Publish permission for every project.
    /// Empty inventories require an explicit Any-project Publish rule.
    /// Authentication and ACL observations are not frozen during the SQL write.
    pub async fn register(
        &self,
        raw: &str,
        required_scopes: &[String],
        inventory: &InstanceInventory,
        caller: Instant,
    ) -> Result<RegistrationResult, InstanceRegistrationError> {
        let end = bounded_deadline(caller, self.owner.budgets.operation_timeout)
            .map_err(PresenceAuthorizationError::from)?;
        let owner = tokio::time::timeout_at(end.into(), async {
            let mut principal = self
                .verifier
                .verify(raw, required_scopes, end)
                .await
                .map_err(PresenceAuthorizationError::from)?;
            let snapshot = self
                .grants
                .read(end)
                .await
                .map_err(PresenceAuthorizationError::from)?;
            let policy = ResourcePolicy::compile(&snapshot, end)
                .map_err(PresenceAuthorizationError::from)?;
            let user = principal.current_local_user();
            let allowed = if inventory.projects().is_empty() {
                policy
                    .allows_any_project(user, PresenceCapability::Publish.as_str(), end)
                    .map_err(PresenceAuthorizationError::from)?
            } else {
                let mut allowed = true;
                for project in inventory.projects() {
                    if !policy
                        .allows(
                            user,
                            PresenceCapability::Publish.as_str(),
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
            let owner = InstanceOwner::new(user.issuer(), user.subject())?;
            principal
                .finish(now_micros().map_err(PresenceAuthorizationError::from)?)
                .map_err(PresenceAuthorizationError::from)?;
            check_deadline(end)?;
            Ok::<_, InstanceRegistrationError>(owner)
        })
        .await
        .map_err(|_| PresenceAuthorizationError::Control(ControlError::Deadline))??;
        // The writer owns commit timeout classification; an outer timeout would hide
        // OutcomeUncertain after COMMIT has started. Pass the original deadline through.
        self.owner
            .replace_instance_inventory(&owner, inventory, end)
            .await
            .map_err(Into::into)
    }
}
