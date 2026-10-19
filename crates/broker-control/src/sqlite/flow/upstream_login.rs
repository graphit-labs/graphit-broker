//! H1 over the physical SQLite flow producer and the existing OIDC SDK owner.
use super::SqliteControlStore;
use crate::{
    ControlError, FlowContinuation, IssuedUpstreamAuthorization, OidcFlow, UpstreamBearerVerifier,
    UpstreamLoginCallback, UpstreamLoginError, UpstreamLoginFailure, VerifiedUpstreamLogin,
    service::upstream_login::{ConsumedUpstreamFlow, entropy, gate},
    upstream_oidc::browser::{copy_continuation, temporal_gate},
};
use std::{
    fmt,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;

/// Borrows the actual store and verifier; no proof can be constructed from flow DATA.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore, verifier: &broker_control::UpstreamBearerVerifier)
///     -> broker_control::SqliteUpstreamLogins<'static> { store.upstream_logins(verifier) }
/// ```
pub struct SqliteUpstreamLogins<'a> {
    store: &'a SqliteControlStore,
    verifier: &'a UpstreamBearerVerifier,
}
impl fmt::Debug for SqliteUpstreamLogins<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteUpstreamLogins([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn upstream_logins<'a>(
        &'a self,
        verifier: &'a UpstreamBearerVerifier,
    ) -> SqliteUpstreamLogins<'a> {
        SqliteUpstreamLogins {
            store: self,
            verifier,
        }
    }
}
impl SqliteUpstreamLogins<'_> {
    pub async fn begin(
        &self,
        continuation: FlowContinuation,
        original: Instant,
    ) -> Result<IssuedUpstreamAuthorization, UpstreamLoginError> {
        let result = self.begin_inner(continuation, original).await;
        if matches!(
            result,
            Err(UpstreamLoginFailure::Control(
                ControlError::OutcomeUncertain
            ))
        ) {
            return result.map_err(|failure| UpstreamLoginError::new(failure, None));
        }
        gate(original).map_err(|e| UpstreamLoginError::new(e.into(), None))?;
        result.map_err(|failure| UpstreamLoginError::new(failure, None))
    }
    async fn begin_inner(
        &self,
        continuation: FlowContinuation,
        original: Instant,
    ) -> Result<IssuedUpstreamAuthorization, UpstreamLoginFailure> {
        gate(original)?;
        let mono = Instant::now();
        let wall = SystemTime::now();
        let ttl = Duration::from_micros(crate::flow::FLOW_TTL_MICROS as u64);
        let expires_at = wall.checked_add(ttl).ok_or(ControlError::Clock)?;
        let expires_mono = mono.checked_add(ttl).ok_or(ControlError::Clock)?;
        continuation.to_json(self.store.limits)?;
        let random = entropy::<32>()?;
        let state = Zeroizing::new(format!(
            "{}.{}",
            continuation.purpose().as_str(),
            random.as_str()
        ));
        let nonce = entropy::<32>()?;
        let binding = entropy::<32>()?;
        let verifier = entropy::<48>()?;
        let location = self
            .verifier
            .browser_authorization(&continuation, &state, &nonce, &verifier, original)
            .await?;
        temporal_gate(original, expires_at, expires_mono)?;
        let flow = OidcFlow::new(
            nonce.to_string(),
            verifier.to_string(),
            continuation,
            expires_at,
            self.store.limits,
        )?;
        self.store
            .save_flow(state.as_bytes(), binding.as_bytes(), flow, original)
            .await
            .map_err(ControlError::from)?;
        temporal_gate(original, expires_at, expires_mono)?;
        Ok(IssuedUpstreamAuthorization::committed(
            location,
            state,
            binding,
            expires_at,
            expires_mono,
            original,
        )?)
    }
    pub async fn complete(
        &self,
        state: &str,
        binding: &str,
        callback: UpstreamLoginCallback<'_>,
        original: Instant,
    ) -> Result<VerifiedUpstreamLogin, UpstreamLoginError> {
        let consumed =
            ConsumedUpstreamFlow::consume_sqlite(self.store, state, binding, original).await?;
        let continuation = copy_continuation(consumed.flow().continuation());
        let result = match callback {
            UpstreamLoginCallback::ProviderError => Err(UpstreamLoginFailure::ProviderError),
            UpstreamLoginCallback::Code(code) => {
                self.verifier.authenticate_browser(consumed, code).await
            }
        };
        gate(original).map_err(|e| {
            UpstreamLoginError::new(e.into(), Some(copy_continuation(&continuation)))
        })?;
        let proof =
            result.map_err(|failure| UpstreamLoginError::new(failure, Some(continuation)))?;
        proof.check(self.verifier).map_err(|e| {
            UpstreamLoginError::new(e.into(), Some(copy_continuation(proof.continuation())))
        })?;
        Ok(proof)
    }
}
