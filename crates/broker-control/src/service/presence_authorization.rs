use super::{
    PostgresControlStore, PostgresLocalBearerVerifier, PostgresResourceGrants, bounded_deadline,
};
use crate::{
    AuthorizedLocalPresence, ControlError, PresenceAuthorizationError, PresenceCapability,
    flow::now_micros, instance_registry::canonical_project_id,
    presence_authorization::check_deadline, resource_policy::ResourcePolicy,
};
use std::{fmt, num::NonZeroUsize, time::Instant};

pub struct PostgresLocalPresenceAuthorizer<'a> {
    owner: &'a PostgresControlStore,
    verifier: PostgresLocalBearerVerifier<'a>,
    grants: PostgresResourceGrants<'a>,
}
impl fmt::Debug for PostgresLocalPresenceAuthorizer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresLocalPresenceAuthorizer([REDACTED])")
    }
}
impl PostgresControlStore {
    /// Explicit local audience and useful identity/grant JSON byte limits.
    pub fn local_presence_authorizer<'a>(
        &'a self,
        audience: &'a str,
        identity_json_bytes: NonZeroUsize,
        grants_json_bytes: NonZeroUsize,
    ) -> Result<PostgresLocalPresenceAuthorizer<'a>, PresenceAuthorizationError> {
        Ok(PostgresLocalPresenceAuthorizer {
            owner: self,
            verifier: self.local_bearer_verifier(audience, identity_json_bytes)?,
            grants: self.resource_grants(grants_json_bytes)?,
        })
    }
}
impl PostgresLocalPresenceAuthorizer<'_> {
    /// Authenticate the raw local bearer and consult current grants for this project.
    /// A returned observation does not freeze revocation or authorize another operation.
    pub async fn authorize_project(
        &self,
        raw: &str,
        required_scopes: &[String],
        capability: PresenceCapability,
        project_id: &str,
        caller: Instant,
    ) -> Result<AuthorizedLocalPresence, PresenceAuthorizationError> {
        let end = bounded_deadline(caller, self.owner.budgets.operation_timeout)?;
        if !canonical_project_id(project_id) {
            return Err(PresenceAuthorizationError::InvalidProject);
        }
        tokio::time::timeout_at(end.into(), async {
            let mut principal = self.verifier.verify(raw, required_scopes, end).await?;
            let snapshot = self.grants.read(end).await?;
            let policy = ResourcePolicy::compile(&snapshot, end)
                .map_err(PresenceAuthorizationError::from)?;
            let allowed = policy
                .allows(
                    principal.current_local_user(),
                    capability.as_str(),
                    project_id,
                    end,
                )
                .map_err(PresenceAuthorizationError::from)?;
            principal.finish(now_micros()?)?;
            check_deadline(end)?;
            if !allowed {
                return Err(PresenceAuthorizationError::Forbidden);
            }
            Ok(AuthorizedLocalPresence::new(
                principal,
                project_id,
                capability,
                snapshot.revision(),
            ))
        })
        .await
        .map_err(|_| PresenceAuthorizationError::Control(ControlError::Deadline))?
    }
}
