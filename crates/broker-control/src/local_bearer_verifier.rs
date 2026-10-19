//! Authentication results can only come from the server's raw-bearer verifier.
use crate::local_bearer::normalize;
use crate::{
    ControlError, LocalBearerKind, LocalBearerState, LocalBearerStateError, LocalBearerUser,
};
use broker_store::time::TimestampMicros;
use std::{
    fmt,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalBearerVerificationError {
    Unauthenticated,
    State(LocalBearerStateError),
    Control(ControlError),
}
impl From<ControlError> for LocalBearerVerificationError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<LocalBearerStateError> for LocalBearerVerificationError {
    fn from(value: LocalBearerStateError) -> Self {
        match value {
            LocalBearerStateError::Control(error) => Self::Control(error),
            other => Self::State(other),
        }
    }
}
impl fmt::Display for LocalBearerVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("local bearer authentication failed"),
            Self::State(error) => fmt::Display::fmt(error, f),
            Self::Control(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for LocalBearerVerificationError {}

/// A successful local credential observation, never a resource grant or lease.
/// Verify again for each consequential operation, then consult its current ACL.
/// Raw bearers and digests are not retained in this result.
///
/// SQL metadata cannot construct an authenticated result externally:
/// ```compile_fail
/// fn forge(state: broker_control::LocalBearerState) -> broker_control::VerifiedLocalBearer {
///     broker_control::VerifiedLocalBearer::new(state, 0, std::time::Instant::now())
/// }
/// ```
/// ```compile_fail
/// fn forge(value: &broker_control::VerifiedLocalBearer) { let _ = value.user; }
/// ```
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::VerifiedLocalBearer>();
/// ```
/// ```compile_fail
/// fn require_wire<T: serde::de::DeserializeOwned>() {}
/// require_wire::<broker_control::VerifiedLocalBearer>();
/// ```
pub struct VerifiedLocalBearer {
    user: LocalBearerUser,
    kind: LocalBearerKind,
    audience: String,
    scopes: Vec<String>,
    expires_at: TimestampMicros,
    verified_at: TimestampMicros,
    expires_utc: SystemTime,
    expires_mono: Instant,
}
impl fmt::Debug for VerifiedLocalBearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedLocalBearer([REDACTED])")
    }
}
impl VerifiedLocalBearer {
    pub fn current_local_user(&self) -> &LocalBearerUser {
        &self.user
    }
    pub fn kind(&self) -> LocalBearerKind {
        self.kind
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    pub fn expires_at(&self) -> TimestampMicros {
        self.expires_at
    }
    pub fn verified_at(&self) -> TimestampMicros {
        self.verified_at
    }
    /// Original authentication expiry, captured after SQL at the producer.
    /// This observer does not renew authentication or authorize a later effect.
    /// Keep the operation's Original deadline and obtain fresh SQL observations.
    /// ~~~
    /// fn expiry(proof: &broker_control::VerifiedLocalBearer)
    ///     -> (std::time::SystemTime, std::time::Instant) {
    ///     proof.authentication_expiry()
    /// }
    /// ~~~
    pub fn authentication_expiry(&self) -> (SystemTime, Instant) {
        (self.expires_utc, self.expires_mono)
    }
    pub fn auth_method(&self) -> &'static str {
        match self.kind {
            LocalBearerKind::Access => "local-token",
            LocalBearerKind::ServiceCredential => "service-credential",
        }
    }
    pub(crate) fn new(
        mut state: LocalBearerState,
        now: i64,
        anchor: Instant,
    ) -> Result<Self, LocalBearerVerificationError> {
        let remaining = state
            .expires_at
            .as_i64()
            .checked_sub(now)
            .and_then(|v| u64::try_from(v).ok())
            .filter(|v| *v > 0)
            .ok_or(LocalBearerVerificationError::Unauthenticated)?;
        let exp = u64::try_from(state.expires_at.as_i64()).map_err(|_| ControlError::Clock)?;
        let expires_utc = UNIX_EPOCH
            .checked_add(Duration::from_micros(exp))
            .ok_or(ControlError::Clock)?;
        let expires_mono = anchor
            .checked_add(Duration::from_micros(remaining))
            .ok_or(ControlError::Clock)?;
        normalize(&mut state.raw_scopes);
        Ok(Self {
            user: state.user,
            kind: state.kind,
            audience: state.audience,
            scopes: state.raw_scopes,
            expires_at: state.expires_at,
            verified_at: TimestampMicros::new(now).map_err(|_| ControlError::Clock)?,
            expires_utc,
            expires_mono,
        })
    }
    fn expired_at(&self, utc_micros: i64, mono: Instant) -> bool {
        utc_micros >= self.expires_at.as_i64() || mono >= self.expires_mono
    }
    pub(crate) fn finish(&mut self, now: i64) -> Result<(), LocalBearerVerificationError> {
        if self.expired_at(now, Instant::now()) {
            return Err(LocalBearerVerificationError::Unauthenticated);
        }
        // Metadata may observe a later finish; the original clock pair never renews.
        self.verified_at = TimestampMicros::new(now).map_err(|_| ControlError::Clock)?;
        Ok(())
    }
}
pub(crate) fn bearer_kind(raw: &str) -> Option<LocalBearerKind> {
    if raw.starts_with("gb_at_") {
        Some(LocalBearerKind::Access)
    } else if raw.starts_with("gb_sc_") {
        Some(LocalBearerKind::ServiceCredential)
    } else {
        None
    }
}
pub(crate) fn validate_state(
    state: &LocalBearerState,
    audience: &str,
    required: &[String],
    now: i64,
) -> Result<(), LocalBearerVerificationError> {
    if state.audience != audience.trim()
        || state.revoked_at.is_some()
        || state.expires_at.as_i64() <= now
        || required
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .any(|required| !state.raw_scopes.iter().any(|stored| stored == required))
    {
        return Err(LocalBearerVerificationError::Unauthenticated);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalIdentityKind;
    fn state() -> LocalBearerState {
        LocalBearerState {
            kind: LocalBearerKind::Access,
            audience: "aud".into(),
            raw_scopes: vec![
                " padded ".into(),
                "exact".into(),
                "a,b".into(),
                "exact".into(),
                "".into(),
            ],
            expires_at: TimestampMicros::new(100).unwrap(),
            revoked_at: None,
            user: LocalBearerUser {
                username: "u".into(),
                subject: "s".into(),
                kind: LocalIdentityKind::Human,
                name: "".into(),
                email: "".into(),
                organization: "".into(),
                teams: vec![],
                revision: 1,
            },
        }
    }
    #[test]
    fn clock_pair_is_immutable_through_finish_and_rollback() {
        let mut value = state();
        value.expires_at = TimestampMicros::new(2_000_000).unwrap();
        let anchor = Instant::now();
        let mut proof = VerifiedLocalBearer::new(value, 1_000_000, anchor).unwrap();
        let pair = proof.authentication_expiry();
        assert_eq!(pair.0, UNIX_EPOCH + Duration::from_secs(2));
        assert_eq!(pair.1, anchor + Duration::from_secs(1));
        proof.finish(1_500_000).unwrap();
        proof.finish(500_000).unwrap();
        assert_eq!(proof.verified_at().as_i64(), 500_000);
        assert_eq!(proof.authentication_expiry(), pair);
        assert!(!proof.expired_at(0, pair.1 - Duration::from_nanos(1)));
        assert!(proof.expired_at(0, pair.1));
        assert!(proof.expired_at(2_000_000, anchor));
    }
    #[test]
    fn raw_prefix_is_case_exact_and_never_trimmed_or_refresh() {
        assert_eq!(bearer_kind("gb_at_x"), Some(LocalBearerKind::Access));
        assert_eq!(
            bearer_kind("gb_sc_x"),
            Some(LocalBearerKind::ServiceCredential)
        );
        for raw in [
            "",
            "gb_rt_x",
            "GB_AT_x",
            " gb_at_x",
            "opaque",
            "eyJ.jwt.token",
        ] {
            assert_eq!(bearer_kind(raw), None);
        }
    }
    #[test]
    fn raw_membership_precedes_clean_output_and_exact_expiry_denies() {
        let mut value = state();
        validate_state(
            &value,
            " aud ",
            &[" exact ".into(), "exact".into(), "".into(), "a,b".into()],
            99,
        )
        .unwrap();
        for required in ["padded", "a", "EXACT"] {
            assert_eq!(
                validate_state(&value, "aud", &[required.into()], 99),
                Err(LocalBearerVerificationError::Unauthenticated)
            );
        }
        for now in [100, 101] {
            assert_eq!(
                validate_state(&value, "aud", &[], now),
                Err(LocalBearerVerificationError::Unauthenticated)
            );
        }
        assert_eq!(
            validate_state(&value, "AUD", &[], 99),
            Err(LocalBearerVerificationError::Unauthenticated)
        );
        value.revoked_at = Some(TimestampMicros::new(0).unwrap());
        assert_eq!(
            validate_state(&value, "aud", &[], 99),
            Err(LocalBearerVerificationError::Unauthenticated)
        );
        let mut verified = VerifiedLocalBearer::new(state(), 99, Instant::now()).unwrap();
        assert_eq!(verified.scopes(), ["a,b", "exact", "padded"]);
        assert_eq!(verified.auth_method(), "local-token");
        assert_eq!(verified.current_local_user().issuer(), "local");
        assert_eq!(format!("{verified:?}"), "VerifiedLocalBearer([REDACTED])");
        assert_eq!(
            verified.finish(100),
            Err(LocalBearerVerificationError::Unauthenticated)
        );
        assert_eq!(
            LocalBearerVerificationError::from(LocalBearerStateError::Control(
                ControlError::Storage
            )),
            LocalBearerVerificationError::Control(ControlError::Storage)
        );
        assert_eq!(
            LocalBearerVerificationError::Unauthenticated.to_string(),
            "local bearer authentication failed"
        );
    }
}
