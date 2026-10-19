use super::{PostgresControlStore, PostgresLocalBearerStates, bounded_deadline};
use crate::{
    ControlError, LocalBearerVerificationError, VerifiedLocalBearer,
    flow::now_micros,
    local_bearer_verifier::{bearer_kind, validate_state},
};
use std::{fmt, num::NonZeroUsize, time::Instant};

pub struct PostgresLocalBearerVerifier<'a> {
    owner: &'a PostgresControlStore,
    states: PostgresLocalBearerStates<'a>,
    audience: &'a str,
}
impl fmt::Debug for PostgresLocalBearerVerifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresLocalBearerVerifier([REDACTED])")
    }
}
impl PostgresControlStore {
    /// Explicit audience and JSON cap; no policy defaults or public digest input.
    pub fn local_bearer_verifier<'a>(
        &'a self,
        audience: &'a str,
        json_bytes: NonZeroUsize,
    ) -> Result<PostgresLocalBearerVerifier<'a>, LocalBearerVerificationError> {
        Ok(PostgresLocalBearerVerifier {
            owner: self,
            states: self.local_bearer_states(json_bytes)?,
            audience,
        })
    }
}
impl PostgresLocalBearerVerifier<'_> {
    /// Authenticate the exact raw bearer against current local SQL state.
    /// Internal errors are finite diagnostics; HTTP mapping belongs to the server.
    pub async fn verify(
        &self,
        raw: &str,
        required_scopes: &[String],
        caller: Instant,
    ) -> Result<VerifiedLocalBearer, LocalBearerVerificationError> {
        let end = bounded_deadline(caller, self.owner.budgets.operation_timeout)?;
        tokio::time::timeout_at(end.into(), async {
            let kind = bearer_kind(raw).ok_or(LocalBearerVerificationError::Unauthenticated)?;
            let digest = self
                .owner
                .digester
                .token(kind.token_kind(), raw.as_bytes())
                .map_err(|_| LocalBearerVerificationError::Unauthenticated)?;
            let state = self
                .states
                .read(&digest, kind, end)
                .await?
                .ok_or(LocalBearerVerificationError::Unauthenticated)?;
            let now = now_micros()?;
            validate_state(&state, self.audience, required_scopes, now)?;
            // Pair the final UTC observation with its immediately preceding mono
            // sample, after all SQL waits. An anchor before verify discounts SQL twice.
            let anchor = Instant::now();
            let mut verified = VerifiedLocalBearer::new(state, now_micros()?, anchor)?;
            verified.finish(now_micros()?)?;
            if Instant::now() >= end {
                return Err(ControlError::Deadline.into());
            }
            Ok(verified)
        })
        .await
        .map_err(|_| LocalBearerVerificationError::Control(ControlError::Deadline))?
    }
}
