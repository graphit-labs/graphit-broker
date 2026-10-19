//! Shared LOCAL password work and bounded ephemeral attempt state.
use crate::{
    ControlError, LocalAuthError, LocalAuthStep, LocalPasswordEngine,
    LocalPasswordVerificationError, PostgresLocalAuthService, VerifiedLocalPassword,
    local_captcha::{LocalCaptcha, LocalCaptchaChallenge},
    local_password::{LocalPasswordWorkers, WrongPasswordEvidence},
};
use broker_security::{LocalAuthBinding, LocalAuthPurpose, LocalPasswordError};
use std::{
    collections::HashMap,
    fmt,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const TRACKED_USERNAMES: usize = 4096;
#[cfg(test)]
#[path = "../tests/support/local_password_policy.rs"]
mod tests;
#[derive(Clone, Copy, Debug)]
pub struct LocalPasswordAdmissionPolicy {
    pub max_failures: NonZeroUsize,
    pub window: Duration,
    pub lockout: Duration,
    pub workers: NonZeroUsize,
    pub saturation_multiplier: NonZeroUsize,
    pub max_tracked: NonZeroUsize,
}
impl LocalPasswordAdmissionPolicy {
    pub fn validate(&self) -> Result<(), ControlError> {
        let now = Instant::now();
        let capacity = self
            .workers
            .get()
            .checked_mul(self.saturation_multiplier.get())
            .ok_or(ControlError::Configuration)?;
        if capacity > tokio::sync::Semaphore::MAX_PERMITS
            || self.window.is_zero()
            || self.lockout.is_zero()
            || self.max_tracked.get() != TRACKED_USERNAMES
            || now.checked_add(self.window).is_none()
            || now.checked_add(self.lockout).is_none()
            || self.window.checked_add(self.lockout).is_none()
        {
            return Err(ControlError::Configuration);
        }
        Ok(())
    }
}
#[derive(Debug)]
pub enum LocalPasswordAdmissionError {
    Unauthenticated,
    RateLimited(Duration),
    CaptchaRequired(LocalCaptchaChallenge),
    Capacity,
    Control(ControlError),
    Password(LocalPasswordError),
    LocalAuth(LocalAuthError),
}
impl fmt::Display for LocalPasswordAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("LOCAL password authentication failed"),
            Self::RateLimited(_) => f.write_str("LOCAL password admission is rate limited"),
            Self::CaptchaRequired(_) => f.write_str("LOCAL password admission requires CAPTCHA"),
            Self::Capacity => f.write_str("LOCAL authentication is unavailable"),
            Self::Control(error) => error.fmt(f),
            Self::Password(error) => error.fmt(f),
            Self::LocalAuth(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for LocalPasswordAdmissionError {}
impl From<ControlError> for LocalPasswordAdmissionError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<LocalPasswordVerificationError> for LocalPasswordAdmissionError {
    fn from(value: LocalPasswordVerificationError) -> Self {
        match value {
            LocalPasswordVerificationError::Unauthenticated => Self::Unauthenticated,
            LocalPasswordVerificationError::Control(error) => Self::Control(error),
            LocalPasswordVerificationError::Password(error) => Self::Password(error),
        }
    }
}
struct Attempt {
    window_start: Instant,
    failures: usize,
    blocked_until: Option<Instant>,
    last_seen: Instant,
    active: usize,
}
impl Attempt {
    fn refresh_window(&mut self, now: Instant, window: Duration) {
        if now.saturating_duration_since(self.window_start) >= window {
            self.window_start = now;
            self.failures = 0;
            // A concurrent result may cross the window after another worker
            // starts a lockout. Its independent expiry remains authoritative.
            self.blocked_until = self.blocked_until.filter(|until| *until > now);
        }
    }
}
struct State {
    closed: bool,
    occupied: usize,
    attempts: HashMap<String, Attempt>,
}
struct AdmissionState {
    policy: LocalPasswordAdmissionPolicy,
    capacity: usize,
    state: Mutex<State>,
}
/// One trusted startup owner, shared across initial password and password changes.
/// This owner creates no SQL identity, factor, session or OAuth authority.
pub struct LocalPasswordAdmission {
    state: Arc<AdmissionState>,
    worker_owner: Arc<LocalPasswordWorkers>,
    pub(crate) captcha: LocalCaptcha,
}
impl fmt::Debug for LocalPasswordAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalPasswordAdmission([REDACTED])")
    }
}
impl LocalPasswordAdmission {
    pub fn new(
        policy: LocalPasswordAdmissionPolicy,
        engine: &LocalPasswordEngine,
        captcha: LocalCaptcha,
    ) -> Result<Self, ControlError> {
        policy.validate()?;
        if engine.physical_workers() != policy.workers.get()
            || !captcha.compatible(policy.workers, policy.saturation_multiplier)
        {
            return Err(ControlError::Configuration);
        }
        Ok(Self {
            worker_owner: Arc::clone(engine.worker_owner()),
            state: Arc::new(AdmissionState {
                policy,
                capacity: policy.workers.get() * policy.saturation_multiplier.get(),
                state: Mutex::new(State {
                    closed: false,
                    occupied: 0,
                    attempts: HashMap::new(),
                }),
            }),
            captcha,
        })
    }
    pub fn challenge(&self, purpose: LocalAuthPurpose) -> Option<LocalCaptchaChallenge> {
        self.captcha.challenge(purpose)
    }
    /// Public options observe the existing occupancy without reserving work.
    /// Authentication still captures and checks its own admitted occupancy.
    pub fn next_password_challenge(
        &self,
        purpose: LocalAuthPurpose,
    ) -> Result<Option<LocalCaptchaChallenge>, ControlError> {
        let state = self.state.state.lock().map_err(|_| ControlError::Closed)?;
        if state.closed {
            return Err(ControlError::Closed);
        }
        let next = state
            .occupied
            .checked_add(1)
            .ok_or(ControlError::Configuration)?;
        Ok(if self.captcha.required(next) {
            self.captcha.challenge(purpose)
        } else {
            None
        })
    }
    /// Close logical admission, then await `engine.close()` before SQL shutdown.
    pub fn close(&self) {
        self.state
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed = true;
    }
    pub(crate) fn admit(
        &self,
        username: Option<&str>,
        original: Instant,
    ) -> Result<(Arc<PasswordWorkLease>, usize), LocalPasswordAdmissionError> {
        if Instant::now() >= original {
            return Err(ControlError::Deadline.into());
        }
        let mut state = self.state.state.lock().map_err(|_| ControlError::Closed)?;
        let now = Instant::now();
        if now >= original {
            return Err(ControlError::Deadline.into());
        }
        if state.closed {
            return Err(ControlError::Closed.into());
        }
        if state.occupied == self.state.capacity {
            return Err(LocalPasswordAdmissionError::RateLimited(
                Duration::from_secs(1),
            ));
        }
        if let Some(username) = username {
            let stale = self
                .state
                .policy
                .window
                .checked_add(self.state.policy.lockout)
                .ok_or(ControlError::Configuration)?;
            state.attempts.retain(|_, entry| {
                entry.active != 0
                    || entry.blocked_until.is_some_and(|until| until > now)
                    || now.saturating_duration_since(entry.last_seen) <= stale
            });
            if !state.attempts.contains_key(username) && state.attempts.len() == TRACKED_USERNAMES {
                return Err(LocalPasswordAdmissionError::Capacity);
            }
            let entry = state
                .attempts
                .entry(username.to_owned())
                .or_insert(Attempt {
                    window_start: now,
                    failures: 0,
                    blocked_until: None,
                    last_seen: now,
                    active: 0,
                });
            if let Some(until) = entry.blocked_until.filter(|until| *until > now) {
                return Err(LocalPasswordAdmissionError::RateLimited(
                    until.duration_since(now),
                ));
            }
            entry.refresh_window(now, self.state.policy.window);
            entry.active = entry
                .active
                .checked_add(1)
                .ok_or(ControlError::Configuration)?;
            entry.last_seen = now;
        }
        state.occupied += 1;
        let occupancy = state.occupied;
        Ok((
            Arc::new(PasswordWorkLease {
                owner: Arc::clone(&self.state),
                username: username.map(str::to_owned),
            }),
            occupancy,
        ))
    }
    /// Reserve shared work for the genuine mandatory-change procedure. No CAPTCHA
    /// or initial-password failure/success accounting applies to this typed guard.
    pub fn admit_password_change<'a>(
        &self,
        engine: &'a LocalPasswordEngine,
        original: Instant,
    ) -> Result<AdmittedLocalPasswordChange<'a>, LocalPasswordAdmissionError> {
        if !self.matches_engine(engine) {
            return Err(ControlError::Configuration.into());
        }
        let (lease, _) = self.admit(None, original)?;
        Ok(AdmittedLocalPasswordChange {
            engine,
            lease,
            original,
        })
    }
    pub(crate) fn matches_engine(&self, engine: &LocalPasswordEngine) -> bool {
        Arc::ptr_eq(&self.worker_owner, engine.worker_owner())
    }
}
pub(crate) struct PasswordWorkLease {
    owner: Arc<AdmissionState>,
    username: Option<String>,
}
impl PasswordWorkLease {
    pub(crate) fn check_work(&self, original: Instant) -> Result<(), ControlError> {
        let state = self.owner.state.lock().map_err(|_| ControlError::Closed)?;
        if Instant::now() >= original {
            return Err(ControlError::Deadline);
        }
        if state.closed {
            return Err(ControlError::Closed);
        }
        Ok(())
    }
    pub(crate) fn recheck_attempt(
        &self,
        original: Instant,
    ) -> Result<(), LocalPasswordAdmissionError> {
        let state = self.owner.state.lock().map_err(|_| ControlError::Closed)?;
        let now = Instant::now();
        if now >= original {
            return Err(ControlError::Deadline.into());
        }
        if state.closed {
            return Err(ControlError::Closed.into());
        }
        if let Some(until) = self
            .username
            .as_ref()
            .and_then(|name| state.attempts.get(name))
            .and_then(|entry| entry.blocked_until)
            .filter(|until| *until > now)
        {
            return Err(LocalPasswordAdmissionError::RateLimited(
                until.duration_since(now),
            ));
        }
        Ok(())
    }
    pub(crate) fn incorrect(
        &self,
        _evidence: WrongPasswordEvidence,
        original: Instant,
    ) -> Result<(), LocalPasswordAdmissionError> {
        let mut state = self.owner.state.lock().map_err(|_| ControlError::Closed)?;
        let now = Instant::now();
        if now >= original {
            return Err(ControlError::Deadline.into());
        }
        if state.closed {
            return Err(ControlError::Closed.into());
        }
        let name = self.username.as_ref().ok_or(ControlError::Configuration)?;
        let entry = state
            .attempts
            .get_mut(name)
            .ok_or(ControlError::Configuration)?;
        entry.refresh_window(now, self.owner.policy.window);
        entry.failures = entry.failures.saturating_add(1);
        entry.last_seen = now;
        if entry.failures >= self.owner.policy.max_failures.get() {
            entry.blocked_until = Some(
                now.checked_add(self.owner.policy.lockout)
                    .ok_or(ControlError::Configuration)?,
            );
        }
        Ok(())
    }
    pub(crate) fn succeeded(
        &self,
        proof: &VerifiedLocalPassword,
        original: Instant,
    ) -> Result<(), LocalPasswordAdmissionError> {
        let mut state = self.owner.state.lock().map_err(|_| ControlError::Closed)?;
        let now = Instant::now();
        if now >= original {
            return Err(ControlError::Deadline.into());
        }
        if state.closed {
            return Err(ControlError::Closed.into());
        }
        let name = self
            .username
            .as_ref()
            .filter(|name| name.as_str() == proof.username())
            .ok_or(ControlError::Configuration)?;
        let entry = state
            .attempts
            .get_mut(name)
            .ok_or(ControlError::Configuration)?;
        // Keep the entry until all concurrent same-username leases finish. Removing
        // it here would let an old lease decrement a newly created entry's count.
        entry.failures = 0;
        entry.blocked_until = None;
        entry.window_start = now;
        entry.last_seen = now;
        Ok(())
    }
}
impl Drop for PasswordWorkLease {
    fn drop(&mut self) {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.occupied -= 1;
        if let Some(name) = &self.username {
            let remove = state.attempts.get_mut(name).is_some_and(|entry| {
                entry.active -= 1;
                entry.active == 0 && entry.failures == 0 && entry.blocked_until.is_none()
            });
            if remove {
                state.attempts.remove(name);
            }
        }
    }
}
/// Admission only: the guarded current SQL procedure still authenticates the
/// challenge, binding and revision. No Clone/Default/Serde or free constructor.
///
/// ```compile_fail
/// use broker_control::AdmittedLocalPasswordChange;
/// let _: AdmittedLocalPasswordChange<'static> = Default::default();
/// ```
/// ```compile_fail
/// use broker_control::AdmittedLocalPasswordChange;
/// fn duplicate(value: &AdmittedLocalPasswordChange<'_>) {
///     let _ = Clone::clone(value);
/// }
/// ```
/// ```compile_fail
/// use broker_control::AdmittedLocalPasswordChange;
/// fn deserialize<T: serde::de::DeserializeOwned>() {}
/// deserialize::<AdmittedLocalPasswordChange<'static>>();
/// ```
pub struct AdmittedLocalPasswordChange<'a> {
    engine: &'a LocalPasswordEngine,
    lease: Arc<PasswordWorkLease>,
    original: Instant,
}
impl fmt::Debug for AdmittedLocalPasswordChange<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdmittedLocalPasswordChange([REDACTED])")
    }
}
impl AdmittedLocalPasswordChange<'_> {
    pub async fn complete(
        self,
        auth: &PostgresLocalAuthService<'_>,
        raw: &str,
        context: LocalAuthBinding<'_>,
        new_password: &str,
    ) -> Result<LocalAuthStep, LocalPasswordAdmissionError> {
        self.lease.check_work(self.original)?;
        auth.complete_password_change_admitted(
            self.engine,
            raw,
            context,
            new_password,
            self.original,
            Arc::clone(&self.lease),
        )
        .await
        .map_err(LocalPasswordAdmissionError::LocalAuth)
    }
    /// Consume the same protected engine/lease for the SQLite continuation.
    pub async fn complete_sqlite(
        self,
        auth: &crate::SqliteLocalAuthService<'_>,
        raw: &str,
        context: LocalAuthBinding<'_>,
        new_password: &str,
    ) -> Result<LocalAuthStep, LocalPasswordAdmissionError> {
        self.lease.check_work(self.original)?;
        auth.complete_password_change_admitted(
            self.engine,
            raw,
            context,
            new_password,
            self.original,
            Arc::clone(&self.lease),
        )
        .await
        .map_err(LocalPasswordAdmissionError::LocalAuth)
    }
}
