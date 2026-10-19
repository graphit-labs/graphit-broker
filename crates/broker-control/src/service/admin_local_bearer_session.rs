use super::admin_broker_session::{LocalAdminProof, read_local_session};
use super::{PostgresControlStore, bounded_deadline};
use crate::{
    AdminBrokerSessionError as Error, AdminBrokerSessionLimits, AdminLocalBearerSession,
    ControlError, admin_local_bearer_session::verification_error,
};
use std::{fmt, num::NonZeroUsize, time::Instant};

pub struct PostgresAdminLocalBearerSessions<'a> {
    store: &'a PostgresControlStore,
    audience: &'a str,
    identity_json_bytes: NonZeroUsize,
    limits: AdminBrokerSessionLimits,
}
impl fmt::Debug for PostgresAdminLocalBearerSessions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresAdminLocalBearerSessions([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn admin_local_bearer_sessions<'a>(
        &'a self,
        audience: &'a str,
        identity_json_bytes: NonZeroUsize,
        limits: AdminBrokerSessionLimits,
    ) -> Result<PostgresAdminLocalBearerSessions<'a>, ControlError> {
        limits.validate()?;
        if audience.trim().is_empty() {
            return Err(ControlError::Configuration);
        }
        self.local_bearer_verifier(audience, identity_json_bytes)
            .map_err(verification_error)
            .map_err(|error| match error {
                Error::Control(control) => control,
                _ => ControlError::Configuration,
            })?;
        Ok(PostgresAdminLocalBearerSessions {
            store: self,
            audience,
            identity_json_bytes,
            limits,
        })
    }
}
impl PostgresAdminLocalBearerSessions<'_> {
    /// Authentication originates here from raw possession; no metadata proof input.
    pub async fn read(
        &self,
        raw: &str,
        required_scopes: &[String],
        original: Instant,
    ) -> Result<AdminLocalBearerSession, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let proof = self
            .store
            .local_bearer_verifier(self.audience, self.identity_json_bytes)
            .map_err(verification_error)?
            .verify(raw, required_scopes, end)
            .await
            .map_err(verification_error)?;
        let (profile, principal, roles, permissions) = read_local_session(
            self.store,
            LocalAdminProof::Opaque(&proof),
            self.limits,
            end,
        )
        .await?;
        let result = AdminLocalBearerSession {
            proof,
            original: end,
            profile,
            principal,
            roles,
            permissions,
        };
        result.check()?;
        Ok(result)
    }
}
