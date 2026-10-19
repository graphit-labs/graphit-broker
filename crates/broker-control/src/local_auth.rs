//! Current LOCAL login stages. These values do not issue sessions or consent.
use crate::{ControlError, LocalPasswordVerificationError};
use broker_security::{
    CredentialDigest, CredentialDigester, CredentialError, LocalAuthBinding, LocalAuthPurpose,
    LocalMfaEnrollment, LocalMfaError, LocalPasswordError, LocalRecoveryCodes,
};
use broker_store::time::TimestampMicros;
use std::{
    collections::HashMap,
    fmt,
    num::{NonZeroU32, NonZeroUsize},
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Debug, Eq, PartialEq)]
pub enum LocalAuthError {
    Unauthenticated,
    InvalidChallenge,
    InvalidPolicy,
    PasswordUnchanged,
    InvalidMfaCode,
    MfaRateLimited(Duration),
    MfaBusy,
    MfaCapacity,
    MfaUnavailable,
    Password(LocalPasswordError),
    Credential(CredentialError),
    Mfa(LocalMfaError),
    Control(ControlError),
}
impl From<ControlError> for LocalAuthError {
    fn from(e: ControlError) -> Self {
        Self::Control(e)
    }
}
impl From<CredentialError> for LocalAuthError {
    fn from(e: CredentialError) -> Self {
        Self::Credential(e)
    }
}
impl From<LocalMfaError> for LocalAuthError {
    fn from(e: LocalMfaError) -> Self {
        Self::Mfa(e)
    }
}
impl From<LocalPasswordVerificationError> for LocalAuthError {
    fn from(error: LocalPasswordVerificationError) -> Self {
        match error {
            LocalPasswordVerificationError::Unauthenticated => Self::Unauthenticated,
            LocalPasswordVerificationError::Control(error) => Self::Control(error),
            LocalPasswordVerificationError::Password(error) => Self::Password(error),
        }
    }
}
impl fmt::Display for LocalAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("LOCAL login authentication failed"),
            Self::InvalidChallenge => f.write_str("invalid LOCAL login challenge"),
            Self::InvalidPolicy => f.write_str("invalid explicit LOCAL authentication policy"),
            Self::PasswordUnchanged => {
                f.write_str("new LOCAL password must differ from current password")
            }
            Self::InvalidMfaCode => f.write_str("invalid LOCAL MFA input size"),
            Self::MfaRateLimited(_) => f.write_str("LOCAL MFA attempts temporarily blocked"),
            Self::MfaBusy => f.write_str("LOCAL MFA attempt already in progress"),
            Self::MfaCapacity => f.write_str("LOCAL MFA attempt protection is full"),
            Self::MfaUnavailable => f.write_str("LOCAL MFA attempt protection unavailable"),
            Self::Password(e) => e.fmt(f),
            Self::Credential(e) => e.fmt(f),
            Self::Mfa(e) => e.fmt(f),
            Self::Control(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for LocalAuthError {}
/// Explicit bounded protection against guesses; shared by all MFA callers in one process.
/// ```compile_fail
/// fn defaulted<T: Default>() {} defaulted::<broker_control::LocalMfaAttemptPolicy>();
/// ```
#[derive(Debug)]
pub struct LocalMfaAttemptPolicy {
    max_failures: NonZeroU32,
    window: Duration,
    lockout: Duration,
    max_tracked: NonZeroUsize,
    stale_after: Duration,
}
impl LocalMfaAttemptPolicy {
    pub fn new(
        max_failures: NonZeroU32,
        window: Duration,
        lockout: Duration,
        max_tracked: NonZeroUsize,
    ) -> Result<Self, LocalAuthError> {
        let stale_after = window
            .checked_add(lockout)
            .ok_or(LocalAuthError::InvalidPolicy)?;
        if window.is_zero()
            || lockout.is_zero()
            || Instant::now().checked_add(stale_after).is_none()
        {
            return Err(LocalAuthError::InvalidPolicy);
        }
        Ok(Self {
            max_failures,
            window,
            lockout,
            max_tracked,
            stale_after,
        })
    }
}
struct MfaRateEntry {
    window_start: Instant,
    failures: u32,
    block_until: Option<Instant>,
    last_seen: Instant,
    in_flight: bool,
}
pub struct LocalMfaAttemptLimiter {
    policy: LocalMfaAttemptPolicy,
    entries: Mutex<HashMap<String, MfaRateEntry>>,
}
impl fmt::Debug for LocalMfaAttemptLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalMfaAttemptLimiter")
    }
}
impl LocalMfaAttemptLimiter {
    pub fn new(policy: LocalMfaAttemptPolicy) -> Self {
        Self {
            policy,
            entries: Mutex::new(HashMap::new()),
        }
    }
    pub(crate) fn admit<'a>(
        &'a self,
        subject: &'a str,
    ) -> Result<LocalMfaAttempt<'a>, LocalAuthError> {
        self.admit_at(subject, Instant::now())
    }
    fn admit_at<'a>(
        &'a self,
        subject: &'a str,
        now: Instant,
    ) -> Result<LocalMfaAttempt<'a>, LocalAuthError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| LocalAuthError::MfaUnavailable)?;
        if !entries.contains_key(subject) {
            if entries.len() >= self.policy.max_tracked.get() {
                entries.retain(|_, entry| {
                    entry.in_flight
                        || entry.block_until.is_some_and(|until| until > now)
                        || now.saturating_duration_since(entry.last_seen) <= self.policy.stale_after
                });
            }
            if entries.len() >= self.policy.max_tracked.get() {
                return Err(LocalAuthError::MfaCapacity);
            }
            entries.insert(
                subject.to_owned(),
                MfaRateEntry {
                    window_start: now,
                    failures: 0,
                    block_until: None,
                    last_seen: now,
                    in_flight: false,
                },
            );
        }
        let entry = entries
            .get_mut(subject)
            .ok_or(LocalAuthError::MfaUnavailable)?;
        if entry.in_flight {
            return Err(LocalAuthError::MfaBusy);
        }
        if let Some(until) = entry.block_until.filter(|until| *until > now) {
            return Err(LocalAuthError::MfaRateLimited(until.duration_since(now)));
        }
        entry.in_flight = true;
        entry.last_seen = now;
        Ok(LocalMfaAttempt {
            limiter: self,
            subject,
            finished: false,
        })
    }
}
/// Holds admission across verification and known COMMIT until failure/success is recorded.
pub(crate) struct LocalMfaAttempt<'a> {
    limiter: &'a LocalMfaAttemptLimiter,
    subject: &'a str,
    finished: bool,
}
impl LocalMfaAttempt<'_> {
    pub(crate) fn failure(&mut self) -> Result<(), LocalAuthError> {
        self.failure_at(Instant::now())
    }
    fn failure_at(&mut self, now: Instant) -> Result<(), LocalAuthError> {
        let mut entries = self
            .limiter
            .entries
            .lock()
            .map_err(|_| LocalAuthError::MfaUnavailable)?;
        let entry = entries
            .get_mut(self.subject)
            .ok_or(LocalAuthError::MfaUnavailable)?;
        if entry.failures == 0
            || now.saturating_duration_since(entry.window_start) >= self.limiter.policy.window
        {
            entry.window_start = now;
            entry.failures = 0;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= self.limiter.policy.max_failures.get() {
            entry.block_until = Some(
                now.checked_add(self.limiter.policy.lockout)
                    .ok_or(LocalAuthError::MfaUnavailable)?,
            );
        }
        entry.last_seen = now;
        Ok(())
    }
    pub(crate) fn success(mut self) -> Result<(), LocalAuthError> {
        self.limiter
            .entries
            .lock()
            .map_err(|_| LocalAuthError::MfaUnavailable)?
            .remove(self.subject);
        self.finished = true;
        Ok(())
    }
}
impl Drop for LocalMfaAttempt<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let mut entries = self
                .limiter
                .entries
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if entries
                .get(self.subject)
                .is_some_and(|entry| entry.failures == 0)
            {
                entries.remove(self.subject);
            } else if let Some(entry) = entries.get_mut(self.subject) {
                entry.in_flight = false;
            }
        }
    }
}
/// Explicit policy; MFA exemption never bypasses mandatory password change.
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::LocalAuthPolicy>();
/// ```
#[derive(Debug)]
pub struct LocalAuthPolicy {
    pub(crate) required: bool,
    pub(crate) issuer_label: String,
    pub(crate) challenge_ttl: Duration,
}
impl LocalAuthPolicy {
    pub fn new(
        required: bool,
        issuer_label: String,
        challenge_ttl: Duration,
    ) -> Result<Self, LocalAuthError> {
        let issuer_label = issuer_label.trim().to_owned();
        if issuer_label.is_empty()
            || !(Duration::from_secs(120)..=Duration::from_secs(1800)).contains(&challenge_ttl)
        {
            return Err(LocalAuthError::InvalidPolicy);
        }
        Ok(Self {
            required,
            issuer_label,
            challenge_ttl,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAuthStage {
    PasswordChange,
    Mfa,
    Enrollment,
}
impl LocalAuthStage {
    pub(crate) fn sql(self) -> &'static str {
        match self {
            Self::PasswordChange => "password-change",
            Self::Mfa => "mfa",
            Self::Enrollment => "mfa-enrollment",
        }
    }
    pub(crate) fn parse(value: &str) -> Result<Self, LocalAuthError> {
        match value {
            "password-change" => Ok(Self::PasswordChange),
            "mfa" => Ok(Self::Mfa),
            "mfa-enrollment" => Ok(Self::Enrollment),
            _ => Err(LocalAuthError::InvalidChallenge),
        }
    }
}
pub(crate) fn purpose_sql(purpose: LocalAuthPurpose) -> &'static str {
    match purpose {
        LocalAuthPurpose::AdminLogin => "admin-login",
        LocalAuthPurpose::OauthAuthorize => "oauth-authorize",
        LocalAuthPurpose::DeviceApprove => "device-approve",
    }
}
/// ```compile_fail
/// fn decoded<T: for<'a> serde::Deserialize<'a>>() {} decoded::<broker_security::LocalRecoveryCodes>();
/// ```
/// Produced only after known commit. It still needs current authorization and
/// the intended session/consent journey; it is not an OAuth grant.
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::CompletedLocalLogin>();
/// ```
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::CompletedLocalLogin>();
/// ```
/// ```compile_fail
/// fn require_deserialize<T: for<'a> serde::Deserialize<'a>>() {}
/// require_deserialize::<broker_control::CompletedLocalLogin>();
/// ```
/// ```compile_fail
/// fn expose(value: broker_control::CompletedLocalLogin) { let _=value.subject; }
/// ```
pub struct CompletedLocalLogin {
    pub(crate) username: String,
    pub(crate) subject: String,
    pub(crate) revision: i64,
    pub(crate) observed_at: TimestampMicros,
    pub(crate) purpose: LocalAuthPurpose,
    pub(crate) binding: CredentialDigest,
    pub(crate) factor_verified: bool,
    pub(crate) recovery_codes: Option<LocalRecoveryCodes>,
}
impl fmt::Debug for CompletedLocalLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompletedLocalLogin([REDACTED])")
    }
}
impl CompletedLocalLogin {
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn revision(&self) -> i64 {
        self.revision
    }
    pub fn observed_at(&self) -> TimestampMicros {
        self.observed_at
    }
    pub fn auth_method(&self) -> &'static str {
        if self.factor_verified {
            "local-password+totp"
        } else {
            "local-password"
        }
    }
    /// Removes the protected enrollment codes once. No persisted code can be re-exported.
    pub fn take_recovery_codes(&mut self) -> Option<LocalRecoveryCodes> {
        self.recovery_codes.take()
    }
    pub fn purpose(&self) -> LocalAuthPurpose {
        self.purpose
    }
    pub fn verify_binding(
        &self,
        digester: &CredentialDigester,
        context: LocalAuthBinding<'_>,
    ) -> Result<(), LocalAuthError> {
        if self.purpose as u8 != context.purpose() as u8 {
            return Err(LocalAuthError::InvalidChallenge);
        }
        digester
            .verify_local_auth_binding(context, &self.binding)
            .map_err(|_| LocalAuthError::InvalidChallenge)
    }
}
/// Synchronous ownership transfer before entering asynchronous OIDC completion.
/// Enrollment codes must first be taken and retained by the caller; their absence
/// does not prove presentation to the person.
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::PreparedOidcLogin>();
/// ```
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::PreparedOidcLogin>();
/// ```
/// ```compile_fail
/// fn require_deserialize<T: for<'a> serde::Deserialize<'a>>() {}
/// require_deserialize::<broker_control::PreparedOidcLogin>();
/// ```
/// ```compile_fail
/// fn forge(login: broker_control::CompletedLocalLogin) {
///     let _ = broker_control::PreparedOidcLogin { login };
/// }
/// ```
pub struct PreparedOidcLogin {
    pub(crate) login: CompletedLocalLogin,
}
impl fmt::Debug for PreparedOidcLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedOidcLogin([REDACTED])")
    }
}
impl TryFrom<CompletedLocalLogin> for PreparedOidcLogin {
    type Error = OidcLoginPreparationError;
    fn try_from(login: CompletedLocalLogin) -> Result<Self, Self::Error> {
        if !matches!(login.purpose, LocalAuthPurpose::OauthAuthorize) {
            return Err(OidcLoginPreparationError::InvalidPurpose(login));
        }
        if login.recovery_codes.is_some() {
            return Err(OidcLoginPreparationError::RecoveryCodesPending(login));
        }
        Ok(Self { login })
    }
}
/// A failed preparation returns the entire protected login instead of discarding
/// its one-time enrollment output. Diagnostics never expose the payload.
pub enum OidcLoginPreparationError {
    InvalidPurpose(CompletedLocalLogin),
    RecoveryCodesPending(CompletedLocalLogin),
}
impl OidcLoginPreparationError {
    pub fn into_login(self) -> CompletedLocalLogin {
        match self {
            Self::InvalidPurpose(login) | Self::RecoveryCodesPending(login) => login,
        }
    }
}
impl fmt::Debug for OidcLoginPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPurpose(_) => "OidcLoginPreparationError::InvalidPurpose([REDACTED])",
            Self::RecoveryCodesPending(_) => {
                "OidcLoginPreparationError::RecoveryCodesPending([REDACTED])"
            }
        })
    }
}
impl fmt::Display for OidcLoginPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPurpose(_) => "OIDC completion requires an OAuth authorization login",
            Self::RecoveryCodesPending(_) => "OIDC login still owns enrollment recovery codes",
        })
    }
}
impl std::error::Error for OidcLoginPreparationError {}

/// Non-consuming observation. Factor completion must revalidate SQL in its own transaction.
pub struct PendingLocalAuth {
    pub(crate) stage: LocalAuthStage,
    pub(crate) challenge: Zeroizing<String>,
    pub(crate) enrollment: Option<LocalMfaEnrollment>,
}
impl fmt::Debug for PendingLocalAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingLocalAuth([REDACTED])")
    }
}
impl PendingLocalAuth {
    pub fn stage(&self) -> LocalAuthStage {
        self.stage
    }
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
    pub fn enrollment(&self) -> Option<&LocalMfaEnrollment> {
        self.enrollment.as_ref()
    }
}
#[derive(Debug)]
pub enum LocalAuthStep {
    Complete(CompletedLocalLogin),
    Pending(PendingLocalAuth),
}
pub(crate) fn ensure_time(original: Instant) -> Result<(), LocalAuthError> {
    if Instant::now() >= original {
        Err(ControlError::Deadline.into())
    } else {
        Ok(())
    }
}
pub(crate) fn ensure_expiry(expires: i64, now: i64) -> Result<(), LocalAuthError> {
    if expires <= now {
        Err(LocalAuthError::InvalidChallenge)
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_policy_and_strict_expiry_boundaries() {
        for seconds in [120, 1800] {
            assert!(
                LocalAuthPolicy::new(
                    false,
                    " Graphit Broker ".into(),
                    Duration::from_secs(seconds)
                )
                .is_ok()
            );
        }
        for seconds in [119, 1801] {
            assert_eq!(
                LocalAuthPolicy::new(true, "label".into(), Duration::from_secs(seconds))
                    .unwrap_err(),
                LocalAuthError::InvalidPolicy
            );
        }
        assert_eq!(
            LocalAuthPolicy::new(true, " \t ".into(), Duration::from_secs(600)).unwrap_err(),
            LocalAuthError::InvalidPolicy
        );
        assert!(ensure_expiry(101, 100).is_ok());
        assert_eq!(
            ensure_expiry(100, 100),
            Err(LocalAuthError::InvalidChallenge)
        );
        assert_eq!(
            ensure_expiry(99, 100),
            Err(LocalAuthError::InvalidChallenge)
        );
        assert!(ensure_expiry(101, 100).is_ok());
        assert_eq!(
            ensure_expiry(101, 101),
            Err(LocalAuthError::InvalidChallenge)
        );
    }
    fn limiter(max: u32, capacity: usize) -> LocalMfaAttemptLimiter {
        LocalMfaAttemptLimiter::new(
            LocalMfaAttemptPolicy::new(
                NonZeroU32::new(max).unwrap(),
                Duration::from_secs(10),
                Duration::from_secs(20),
                NonZeroUsize::new(capacity).unwrap(),
            )
            .unwrap(),
        )
    }
    #[test]
    fn mfa_protection_blocks_guesses_preserves_admission_and_releases_cancellation() {
        let limiter = limiter(2, 1);
        let now = Instant::now();
        let held = limiter.admit_at("subject", now).unwrap();
        assert!(matches!(
            limiter.admit_at("subject", now),
            Err(LocalAuthError::MfaBusy)
        ));
        assert!(matches!(
            limiter.admit_at("other", now + Duration::from_secs(100)),
            Err(LocalAuthError::MfaCapacity)
        ));
        drop(held);
        // Cancelled/crypto/storage attempts have no guess count and do not occupy capacity.
        let mut held = limiter.admit_at("other", now).unwrap();
        held.failure_at(now).unwrap();
        drop(held);
        limiter
            .admit_at("other", now + Duration::from_secs(1))
            .unwrap()
            .failure_at(now + Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            limiter.admit_at("other", now + Duration::from_secs(20)),
            Err(LocalAuthError::MfaRateLimited(_))
        ));
        assert!(matches!(
            limiter.admit_at("subject", now + Duration::from_secs(20)),
            Err(LocalAuthError::MfaCapacity)
        ));
        let held = limiter
            .admit_at("other", now + Duration::from_secs(21))
            .unwrap();
        assert!(matches!(
            limiter.admit_at("other", now + Duration::from_secs(21)),
            Err(LocalAuthError::MfaBusy)
        ));
        held.success().unwrap();
        limiter
            .admit_at("subject", now + Duration::from_secs(21))
            .unwrap()
            .failure_at(now + Duration::from_secs(21))
            .unwrap();
        assert!(matches!(
            limiter.admit_at("other", now + Duration::from_secs(51)),
            Err(LocalAuthError::MfaCapacity)
        ));
        drop(
            limiter
                .admit_at("other", now + Duration::from_secs(52))
                .unwrap(),
        );
    }
    #[test]
    fn mfa_failure_window_resets_and_guard_keeps_post_commit_gap_closed() {
        let limiter = limiter(2, 2);
        let now = Instant::now();
        limiter
            .admit_at("subject", now)
            .unwrap()
            .failure_at(now)
            .unwrap();
        limiter
            .admit_at("subject", now + Duration::from_secs(10))
            .unwrap()
            .failure_at(now + Duration::from_secs(10))
            .unwrap();
        let mut held = limiter
            .admit_at("subject", now + Duration::from_secs(11))
            .unwrap();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(matches!(
                        limiter.admit_at("subject", now + Duration::from_secs(11)),
                        Err(LocalAuthError::MfaBusy)
                    ))
                })
                .join()
                .unwrap();
        });
        held.failure_at(now + Duration::from_secs(11)).unwrap();
        drop(held);
        assert!(matches!(
            limiter.admit_at("subject", now + Duration::from_secs(12)),
            Err(LocalAuthError::MfaRateLimited(_))
        ));
        assert!(
            LocalMfaAttemptPolicy::new(
                NonZeroU32::new(1).unwrap(),
                Duration::ZERO,
                Duration::from_secs(1),
                NonZeroUsize::new(1).unwrap()
            )
            .is_err()
        );
        assert!(
            LocalMfaAttemptPolicy::new(
                NonZeroU32::new(1).unwrap(),
                Duration::MAX,
                Duration::MAX,
                NonZeroUsize::new(1).unwrap()
            )
            .is_err()
        );
    }
}
