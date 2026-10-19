use super::{SqliteControlStore, SqliteLocalBearerVerifier, SqliteResourceGrants};
use crate::{
    AuthorizedLocalProjectAccess, ProjectAuthorizationError, ProjectResourceAction,
    ProjectResourceModule,
    flow::now_micros,
    instance_registry::canonical_project_id,
    resource_policy::{ResourcePolicy, check_deadline},
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// The local authorizer borrows the actual store and explicit audience.
/// ~~~compile_fail
/// fn escape(store: &broker_control::SqliteControlStore)->broker_control::SqliteLocalProjectAuthorizer<'static> {
///     let n=std::num::NonZeroUsize::new(4096).unwrap();
///     store.local_project_authorizer("aud",n,n).unwrap()
/// }
/// ~~~
pub struct SqliteLocalProjectAuthorizer<'a> {
    owner: &'a SqliteControlStore,
    verifier: SqliteLocalBearerVerifier<'a>,
    grants: SqliteResourceGrants<'a>,
}
impl fmt::Debug for SqliteLocalProjectAuthorizer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalProjectAuthorizer([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn local_project_authorizer<'a>(
        &'a self,
        audience: &'a str,
        identity_json_bytes: NonZeroUsize,
        grants_json_bytes: NonZeroUsize,
    ) -> Result<SqliteLocalProjectAuthorizer<'a>, ProjectAuthorizationError> {
        Ok(SqliteLocalProjectAuthorizer {
            owner: self,
            verifier: self.local_bearer_verifier(audience, identity_json_bytes)?,
            grants: self.resource_grants(grants_json_bytes)?,
        })
    }
}
impl SqliteLocalProjectAuthorizer<'_> {
    /// Verify the raw local bearer and current whole policy for this exact project/action.
    /// Write and read are independent logical capabilities; storage permissions are separate.
    pub async fn authorize(
        &self,
        raw: &str,
        required_scopes: &[String],
        module: ProjectResourceModule,
        action: ProjectResourceAction,
        project_id: &str,
        original: Instant,
    ) -> Result<AuthorizedLocalProjectAccess, ProjectAuthorizationError> {
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(crate::ControlError::from)?;
        let capability = module
            .capability(action)
            .ok_or(ProjectAuthorizationError::InvalidOperation)?;
        if !canonical_project_id(project_id) {
            return Err(ProjectAuthorizationError::InvalidProject);
        }
        let mut principal = self.verifier.verify(raw, required_scopes, end).await?;
        // The SQL producer owns COMMIT classification; do not enclose it in another timeout.
        let snapshot = self.grants.read(end).await?;
        let policy = ResourcePolicy::compile(&snapshot, end)?;
        let allowed = policy.allows(principal.current_local_user(), capability, project_id, end)?;
        principal.finish(now_micros()?)?;
        check_deadline(end)?;
        if !allowed {
            return Err(ProjectAuthorizationError::Forbidden);
        }
        Ok(AuthorizedLocalProjectAccess::new(
            principal,
            project_id,
            module,
            action,
            snapshot.revision(),
            capability,
        ))
    }
}
