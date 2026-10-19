use super::PostgresControlStore;
use crate::upstream_oidc::browser::{copy_continuation, temporal_gate};
use crate::{
    ControlError, FlowContinuation, FlowPurpose, IssuedUpstreamAuthorization, OidcFlow,
    UpstreamBearerVerifier, UpstreamLoginCallback, UpstreamLoginError, UpstreamLoginFailure,
    VerifiedUpstreamLogin,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    fmt,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;

/// Borrows the existing SQL store and configured trust owner.
pub struct PostgresUpstreamLogins<'a> {
    store: &'a PostgresControlStore,
    verifier: &'a UpstreamBearerVerifier,
}
impl fmt::Debug for PostgresUpstreamLogins<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresUpstreamLogins([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn upstream_logins<'a>(
        &'a self,
        verifier: &'a UpstreamBearerVerifier,
    ) -> PostgresUpstreamLogins<'a> {
        PostgresUpstreamLogins {
            store: self,
            verifier,
        }
    }
}

/// This marker has no constructor outside the matched SQL consumption producer.
pub(crate) struct ConsumedUpstreamFlow {
    flow: OidcFlow,
    original: Instant,
    binding: Zeroizing<String>,
    expires_mono: Instant,
}
impl ConsumedUpstreamFlow {
    /// Construct only after the real SQLite owner confirms matching consumption.
    pub(crate) async fn consume_sqlite(
        store: &crate::SqliteControlStore,
        state: &str,
        binding: &str,
        original: Instant,
    ) -> Result<Self, UpstreamLoginError> {
        gate(original).map_err(|e| UpstreamLoginError::new(e.into(), None))?;
        let purpose_hint = upstream_login_purpose_hint(state);
        if purpose_hint.is_none() || !canonical_binding(binding) {
            gate(original).map_err(|e| UpstreamLoginError::new(e.into(), None))?;
            return Err(UpstreamLoginError::new(
                UpstreamLoginFailure::InvalidState,
                None,
            ));
        }
        let mono = Instant::now();
        let wall = SystemTime::now();
        let outcome = store
            .consume_flow(state.as_bytes(), binding.as_bytes(), original)
            .await
            .map_err(ControlError::from);
        if matches!(outcome, Err(ControlError::OutcomeUncertain)) {
            return Err(UpstreamLoginError::new(
                ControlError::OutcomeUncertain.into(),
                None,
            ));
        }
        gate(original).map_err(|e| UpstreamLoginError::new(e.into(), None))?;
        let flow = outcome.map_err(|e| {
            UpstreamLoginError::new(
                match e {
                    ControlError::Unavailable
                    | ControlError::Expired
                    | ControlError::InvalidFlow => UpstreamLoginFailure::InvalidState,
                    _ => e.into(),
                },
                None,
            )
        })?;
        // The hint chooses a budget, never the continuation or exchange authority.
        if purpose_hint != Some(flow.continuation().purpose()) {
            return Err(UpstreamLoginError::new(
                UpstreamLoginFailure::InvalidState,
                None,
            ));
        }
        let continuation = copy_continuation(flow.continuation());
        let delta = flow.expires_at().duration_since(wall).map_err(|_| {
            UpstreamLoginError::new(
                ControlError::Expired.into(),
                Some(copy_continuation(&continuation)),
            )
        })?;
        let expires_mono = mono.checked_add(delta).ok_or_else(|| {
            UpstreamLoginError::new(
                ControlError::Clock.into(),
                Some(copy_continuation(&continuation)),
            )
        })?;
        Ok(Self {
            flow,
            original,
            binding: Zeroizing::new(binding.to_owned()),
            expires_mono,
        })
    }
    pub(crate) fn flow(&self) -> &OidcFlow {
        &self.flow
    }
    pub(crate) fn original(&self) -> Instant {
        self.original
    }
    pub(crate) fn expires_mono(&self) -> Instant {
        self.expires_mono
    }
    pub(crate) fn check(&self) -> Result<(), ControlError> {
        temporal_gate(self.original, self.flow.expires_at(), self.expires_mono)
    }
    pub(crate) fn into_binding(self) -> Zeroizing<String> {
        self.binding
    }
}
pub(crate) fn entropy<const N: usize>() -> Result<Zeroizing<String>, ControlError> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::fill(bytes.as_mut()).map_err(|_| ControlError::Unavailable)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}
fn canonical_binding(raw: &str) -> bool {
    if raw.len() != 43 {
        return false;
    }
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(raw) else {
        return false;
    };
    bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == raw
}
/// Full state size: a purpose hint plus 32 unpredictable bytes encoded without padding.
pub const UPSTREAM_LOGIN_STATE_BYTES: usize = 49;

/// Parse an unauthenticated budget hint. Only matching SQL consumption proves purpose.
pub fn upstream_login_purpose_hint(state: &str) -> Option<FlowPurpose> {
    if state.len() != UPSTREAM_LOGIN_STATE_BYTES {
        return None;
    }
    let (prefix, random) = state.split_once('.')?;
    if !canonical_binding(random) {
        return None;
    }
    match prefix {
        "admin" => Some(FlowPurpose::Admin),
        "oauth" => Some(FlowPurpose::OAuth),
        _ => None,
    }
}

pub(crate) fn gate(original: Instant) -> Result<(), ControlError> {
    if Instant::now() >= original {
        Err(ControlError::Deadline)
    } else {
        Ok(())
    }
}
impl PostgresUpstreamLogins<'_> {
    pub async fn begin(
        &self,
        continuation: FlowContinuation,
        original: Instant,
    ) -> Result<IssuedUpstreamAuthorization, UpstreamLoginError> {
        let result = self.begin_inner(continuation, original).await;
        // An unknown COMMIT retains priority even when the caller cutoff crossed.
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
        let state = Zeroizing::new(format!("{}.{}", continuation.purpose().as_str(), *random));
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
            .await?;
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
        gate(original).map_err(|e| UpstreamLoginError::new(e.into(), None))?;
        let purpose_hint = upstream_login_purpose_hint(state);
        if purpose_hint.is_none() || !canonical_binding(binding) {
            gate(original).map_err(|e| UpstreamLoginError::new(e.into(), None))?;
            return Err(UpstreamLoginError::new(
                UpstreamLoginFailure::InvalidState,
                None,
            ));
        }
        let mono = Instant::now();
        let wall = SystemTime::now();
        let outcome = self
            .store
            .consume_flow(state.as_bytes(), binding.as_bytes(), original)
            .await;
        if matches!(outcome, Err(ControlError::OutcomeUncertain)) {
            return Err(UpstreamLoginError::new(
                ControlError::OutcomeUncertain.into(),
                None,
            ));
        }
        gate(original).map_err(|e| UpstreamLoginError::new(e.into(), None))?;
        let flow = outcome.map_err(|e| {
            UpstreamLoginError::new(
                match e {
                    ControlError::Unavailable
                    | ControlError::Expired
                    | ControlError::InvalidFlow => UpstreamLoginFailure::InvalidState,
                    _ => e.into(),
                },
                None,
            )
        })?;
        // The hint chooses a budget, never the continuation or exchange authority.
        if purpose_hint != Some(flow.continuation().purpose()) {
            return Err(UpstreamLoginError::new(
                UpstreamLoginFailure::InvalidState,
                None,
            ));
        }
        let continuation = copy_continuation(flow.continuation());
        let delta = flow.expires_at().duration_since(wall).map_err(|_| {
            UpstreamLoginError::new(
                ControlError::Expired.into(),
                Some(copy_continuation(&continuation)),
            )
        })?;
        let expires_mono = mono.checked_add(delta).ok_or_else(|| {
            UpstreamLoginError::new(
                ControlError::Clock.into(),
                Some(copy_continuation(&continuation)),
            )
        })?;
        let consumed = ConsumedUpstreamFlow {
            flow,
            original,
            binding: Zeroizing::new(binding.to_owned()),
            expires_mono,
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn purpose_hint_accepts_only_exact_prefix_and_canonical_entropy() {
        let random = URL_SAFE_NO_PAD.encode([0u8; 32]);
        for (prefix, purpose) in [("admin", FlowPurpose::Admin), ("oauth", FlowPurpose::OAuth)] {
            assert_eq!(
                upstream_login_purpose_hint(&format!("{prefix}.{random}")),
                Some(purpose)
            );
        }
        for invalid in [
            random.clone(),
            format!("other.{random}"),
            format!("Admin.{random}"),
            format!("admin.{random}="),
            format!("admin.{}", "A".repeat(42)),
            format!("admin.{}B", "A".repeat(42)),
        ] {
            assert_eq!(upstream_login_purpose_hint(&invalid), None);
        }
        assert!(canonical_binding(&random));
        assert!(!canonical_binding(&format!("admin.{random}")));
    }
}
