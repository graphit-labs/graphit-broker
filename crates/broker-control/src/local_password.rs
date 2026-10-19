//! Password verification is an intermediate login step, never MFA or OAuth consent.
use crate::ControlError;
use crate::local_password_admission::{LocalPasswordAdmissionError, PasswordWorkLease};
use broker_security::{LOCAL_PASSWORD_MAX_BYTES, LocalPasswordError, LocalPasswordHasher};
use broker_store::time::TimestampMicros;
use std::{
    fmt,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;
use zeroize::Zeroizing;

#[derive(Debug, Eq, PartialEq)]
pub enum LocalPasswordVerificationError {
    Unauthenticated,
    Control(ControlError),
    Password(LocalPasswordError),
}
impl From<ControlError> for LocalPasswordVerificationError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<LocalPasswordError> for LocalPasswordVerificationError {
    fn from(value: LocalPasswordError) -> Self {
        Self::Password(value)
    }
}
impl fmt::Display for LocalPasswordVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("LOCAL password authentication failed"),
            Self::Control(error) => error.fmt(f),
            Self::Password(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for LocalPasswordVerificationError {}

/// A shared physical KDF concurrency bound. Running SDK work owns its permit,
/// secret inputs and pepper owner until it finishes, including after caller drop.
pub struct LocalPasswordEngine {
    hasher: Arc<LocalPasswordHasher>,
    slots: Arc<Semaphore>,
    dummy: Arc<Zeroizing<String>>,
    workers: Arc<LocalPasswordWorkers>,
}
pub(crate) struct LocalPasswordWorkers {
    slots: Arc<Semaphore>,
    limit: NonZeroUsize,
    tasks: TaskTracker,
    // TaskTracker::close permits later spawns. Serialize registration with close
    // so wait cannot finish before a previously admitted worker is registered.
    closed: Mutex<bool>,
}
impl LocalPasswordWorkers {
    fn new(workers: NonZeroUsize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(workers.get())),
            limit: workers,
            tasks: TaskTracker::new(),
            closed: Mutex::new(false),
        }
    }
    fn spawn<T: Send + 'static>(
        &self,
        original: Instant,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> Result<tokio::task::JoinHandle<T>, LocalPasswordVerificationError> {
        let closed = self.closed.lock().map_err(|_| ControlError::Closed)?;
        ensure_time(original)?;
        if *closed {
            return Err(ControlError::Closed.into());
        }
        Ok(self.tasks.spawn_blocking(operation))
    }
    async fn close(&self) {
        {
            let mut closed = self
                .closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *closed = true;
            self.slots.close();
            self.tasks.close();
        }
        self.tasks.wait().await;
    }
}
impl fmt::Debug for LocalPasswordEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalPasswordEngine([REDACTED])")
    }
}
impl LocalPasswordEngine {
    pub async fn new(
        hasher: LocalPasswordHasher,
        workers: NonZeroUsize,
        original: Instant,
    ) -> Result<Self, LocalPasswordVerificationError> {
        if workers.get() > Semaphore::MAX_PERMITS {
            return Err(ControlError::Configuration.into());
        }
        ensure_time(original)?;
        let hasher = Arc::new(hasher);
        let workers = Arc::new(LocalPasswordWorkers::new(workers));
        let dummy = initialize_dummy(&hasher, &workers, original).await?;
        Ok(Self {
            hasher,
            slots: Arc::clone(&workers.slots),
            dummy: Arc::new(dummy),
            workers,
        })
    }
    /// Closes physical admission and awaits real SDK worker exit. Call before SQL
    /// shutdown; caller cancellation or deadline alone does not join a KDF.
    pub async fn close(&self) {
        self.workers.close().await;
    }
    pub(crate) fn physical_workers(&self) -> usize {
        self.workers.limit.get()
    }
    pub(crate) fn worker_owner(&self) -> &Arc<LocalPasswordWorkers> {
        &self.workers
    }
    #[cfg(test)]
    pub(crate) fn physical_available_permits(&self) -> usize {
        self.slots.available_permits()
    }
    /// Hash creation for native password writes. SQL mutations remain separate.
    pub async fn hash(
        &self,
        password: &str,
        original: Instant,
    ) -> Result<Zeroizing<String>, LocalPasswordVerificationError> {
        if password.len() > LOCAL_PASSWORD_MAX_BYTES || password.chars().count() < 15 {
            return Err(LocalPasswordError::InvalidPassword.into());
        }
        let password = Zeroizing::new(password.to_owned());
        self.work(original, None, move |hasher| {
            hasher.hash(&password).map_err(Into::into)
        })
        .await
    }
    /// Cryptographic DATA check; only the SQL verifier produces password evidence.
    /// Missing/invalid PHC uses a real native dummy KDF and always returns false.
    pub async fn verify(
        &self,
        password: &str,
        phc: Option<&str>,
        original: Instant,
    ) -> Result<bool, LocalPasswordVerificationError> {
        if password.len() > LOCAL_PASSWORD_MAX_BYTES {
            return Err(LocalPasswordError::InvalidPassword.into());
        }
        let candidate = phc.filter(|value| LocalPasswordHasher::validate_hash(value).is_ok());
        let eligible = candidate.is_some();
        let hash = candidate.map_or_else(
            || Arc::clone(&self.dummy),
            |value| Arc::new(Zeroizing::new(value.to_owned())),
        );
        let password = Zeroizing::new(password.to_owned());
        self.work(original, None, move |hasher| {
            let matched = hasher.verify(&password, &hash)?;
            Ok(eligible && matched)
        })
        .await
    }
    pub(crate) async fn verify_admitted(
        &self,
        password: &str,
        phc: Option<&str>,
        lease: Arc<PasswordWorkLease>,
        original: Instant,
    ) -> Result<AdmittedPasswordCheck, LocalPasswordAdmissionError> {
        if password.len() > LOCAL_PASSWORD_MAX_BYTES {
            return Err(LocalPasswordAdmissionError::Password(
                LocalPasswordError::InvalidPassword,
            ));
        }
        let candidate = phc.filter(|value| LocalPasswordHasher::validate_hash(value).is_ok());
        let eligible = candidate.is_some();
        let hash = candidate.map_or_else(
            || Arc::clone(&self.dummy),
            |value| Arc::new(Zeroizing::new(value.to_owned())),
        );
        let password = Zeroizing::new(password.to_owned());
        self.work(original, Some(Arc::clone(&lease)), move |hasher| {
            let _lease = lease;
            // Recheck after both the physical semaphore and the blocking scheduler
            // queue. Only the actual SDK result creates incorrect-password evidence.
            _lease.recheck_attempt(original)?;
            let matched = hasher
                .verify(&password, &hash)
                .map_err(LocalPasswordVerificationError::from)?;
            Ok(AdmittedPasswordCheck {
                matched: eligible && matched,
                incorrect: if matched {
                    None
                } else {
                    Some(WrongPasswordEvidence { _private: () })
                },
            })
        })
        .await
    }
    pub(crate) async fn verify_for_change(
        &self,
        password: &str,
        phc: Option<&str>,
        lease: Arc<PasswordWorkLease>,
        original: Instant,
    ) -> Result<bool, LocalPasswordVerificationError> {
        if password.len() > LOCAL_PASSWORD_MAX_BYTES {
            return Err(LocalPasswordError::InvalidPassword.into());
        }
        let candidate = phc.filter(|value| LocalPasswordHasher::validate_hash(value).is_ok());
        let eligible = candidate.is_some();
        let hash = candidate.map_or_else(
            || Arc::clone(&self.dummy),
            |value| Arc::new(Zeroizing::new(value.to_owned())),
        );
        let password = Zeroizing::new(password.to_owned());
        self.work(original, Some(Arc::clone(&lease)), move |hasher| {
            let _lease = lease;
            _lease.check_work(original)?;
            Ok(eligible && hasher.verify(&password, &hash)?)
        })
        .await
    }
    pub(crate) async fn hash_for_change(
        &self,
        password: &str,
        lease: Arc<PasswordWorkLease>,
        original: Instant,
    ) -> Result<Zeroizing<String>, LocalPasswordVerificationError> {
        if password.len() > LOCAL_PASSWORD_MAX_BYTES || password.chars().count() < 15 {
            return Err(LocalPasswordError::InvalidPassword.into());
        }
        let password = Zeroizing::new(password.to_owned());
        self.work(original, Some(Arc::clone(&lease)), move |hasher| {
            let _lease = lease;
            _lease.check_work(original)?;
            hasher.hash(&password).map_err(Into::into)
        })
        .await
    }
    async fn work<
        T: Send + 'static,
        E: From<LocalPasswordVerificationError> + From<ControlError> + Send + 'static,
    >(
        &self,
        original: Instant,
        logical: Option<Arc<PasswordWorkLease>>,
        operation: impl FnOnce(&LocalPasswordHasher) -> Result<T, E> + Send + 'static,
    ) -> Result<T, E> {
        ensure_time(original).map_err(E::from)?;
        let permit =
            tokio::time::timeout_at(original.into(), Arc::clone(&self.slots).acquire_owned())
                .await
                .map_err(|_| E::from(ControlError::Deadline))?
                .map_err(|_| E::from(ControlError::Closed))?;
        ensure_time(original).map_err(E::from)?;
        let hasher = Arc::clone(&self.hasher);
        let worker = self
            .workers
            .spawn(original, move || {
                // Binding owns admission throughout actual work; never return a permit
                // merely because an async waiter has been cancelled or timed out.
                let _permit = permit;
                let _logical = logical;
                ensure_time(original).map_err(E::from)?;
                let result = operation(&hasher)?;
                ensure_time(original).map_err(E::from)?;
                Ok::<T, E>(result)
            })
            .map_err(E::from)?;
        join(worker, original).await
    }
}
async fn initialize_dummy(
    hasher: &Arc<LocalPasswordHasher>,
    workers: &LocalPasswordWorkers,
    original: Instant,
) -> Result<Zeroizing<String>, LocalPasswordVerificationError> {
    let worker_hasher = Arc::clone(hasher);
    let worker = match workers.spawn(original, move || {
        ensure_time(original)?;
        let result = worker_hasher.hash("native dummy LOCAL password verification")?;
        ensure_time(original)?;
        Ok::<_, LocalPasswordVerificationError>(result)
    }) {
        Ok(worker) => worker,
        Err(error) => {
            workers.close().await;
            return Err(error);
        }
    };
    let dummy = match join(worker, original).await {
        Ok(dummy) => dummy,
        Err(error) => {
            workers.close().await;
            return Err(error);
        }
    };
    Ok(dummy)
}
async fn join<T: Send + 'static, E: From<LocalPasswordVerificationError> + From<ControlError>>(
    worker: tokio::task::JoinHandle<Result<T, E>>,
    original: Instant,
) -> Result<T, E> {
    let result = tokio::time::timeout_at(original.into(), worker)
        .await
        .map_err(|_| E::from(ControlError::Deadline))?
        .map_err(|_| {
            E::from(LocalPasswordVerificationError::Password(
                LocalPasswordError::Hashing,
            ))
        })??;
    ensure_time(original).map_err(E::from)?;
    Ok(result)
}
pub(crate) struct WrongPasswordEvidence {
    _private: (),
}
pub(crate) struct AdmittedPasswordCheck {
    matched: bool,
    incorrect: Option<WrongPasswordEvidence>,
}
impl AdmittedPasswordCheck {
    pub(crate) fn matched(&self) -> bool {
        self.matched
    }
    pub(crate) fn into_incorrect(self) -> Option<WrongPasswordEvidence> {
        self.incorrect
    }
}
pub(crate) fn ensure_time(original: Instant) -> Result<(), LocalPasswordVerificationError> {
    if Instant::now() >= original {
        Err(ControlError::Deadline.into())
    } else {
        Ok(())
    }
}

/// An observed successful password step with current SQL identity.
///
/// Password change and MFA must be completed by the login flow before issuing
/// a session or OAuth grant. Consumers must revalidate current revision.
///
/// No free constructor, cloning, deserialization or defaults are available.
/// ```compile_fail
/// let proof = broker_control::VerifiedLocalPassword::default();
/// ```
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::VerifiedLocalPassword>();
/// ```
/// ```compile_fail
/// fn require_deserialize<T: for<'a> serde::Deserialize<'a>>() {}
/// require_deserialize::<broker_control::VerifiedLocalPassword>();
/// ```
/// ```compile_fail
/// fn construct() { let _ = broker_control::VerifiedLocalPassword {
///     username: "forged".into(), subject: "forged".into(), revision: 1,
///     password_change_required: false, verified_at: Default::default()
/// }; }
/// ```
pub struct VerifiedLocalPassword {
    pub(crate) username: String,
    pub(crate) subject: String,
    pub(crate) revision: i64,
    pub(crate) password_change_required: bool,
    pub(crate) verified_at: TimestampMicros,
}
impl fmt::Debug for VerifiedLocalPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedLocalPassword([REDACTED])")
    }
}
impl VerifiedLocalPassword {
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn revision(&self) -> i64 {
        self.revision
    }
    pub fn password_change_required(&self) -> bool {
        self.password_change_required
    }
    pub fn verified_at(&self) -> TimestampMicros {
        self.verified_at
    }
    pub fn auth_method(&self) -> &'static str {
        "local-password"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn end() -> Instant {
        Instant::now() + Duration::from_secs(20)
    }
    async fn engine() -> Arc<LocalPasswordEngine> {
        let hasher =
            LocalPasswordHasher::new(Zeroizing::new(vec![23; 32].into_boxed_slice())).unwrap();
        Arc::new(
            LocalPasswordEngine::new(hasher, NonZeroUsize::new(1).unwrap(), end())
                .await
                .unwrap(),
        )
    }
    async fn occupied(engine: &LocalPasswordEngine) {
        let deadline = end();
        while engine.slots.available_permits() != 0 {
            assert!(
                Instant::now() < deadline,
                "real KDF did not acquire admission"
            );
            tokio::task::yield_now().await;
        }
    }
    async fn recovered(engine: &LocalPasswordEngine) {
        tokio::time::timeout_at(end().into(), async {
            while engine.slots.available_permits() == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn running_kdf_retains_permit_after_caller_abort_and_queue_deadline() {
        let owner = engine().await;
        let worker_owner = Arc::clone(&owner);
        let caller = tokio::spawn(async move {
            worker_owner
                .hash("a genuine sufficiently long native password", end())
                .await
        });
        occupied(&owner).await;
        caller.abort();
        let _ = caller.await;
        assert_eq!(owner.slots.available_permits(), 0);
        let expired = owner
            .hash("another genuine sufficiently long password", Instant::now())
            .await;
        assert!(matches!(
            expired,
            Err(LocalPasswordVerificationError::Control(
                ControlError::Deadline
            ))
        ));
        recovered(&owner).await;
        let hash = owner
            .hash("another genuine sufficiently long password", end())
            .await
            .unwrap();
        assert!(
            owner
                .verify(
                    "another genuine sufficiently long password",
                    Some(&hash),
                    end()
                )
                .await
                .unwrap()
        );
        assert!(
            !owner
                .verify("another genuine sufficiently long password", None, end())
                .await
                .unwrap()
        );
        assert_eq!(format!("{owner:?}"), "LocalPasswordEngine([REDACTED])");
    }
    #[tokio::test]
    async fn timed_out_waiter_cannot_release_running_kdf_admission() {
        let owner = engine().await;
        let worker_owner = Arc::clone(&owner);
        let caller = tokio::spawn(async move {
            worker_owner
                .hash(
                    "a genuine sufficiently long native password",
                    Instant::now() + Duration::from_millis(100),
                )
                .await
        });
        occupied(&owner).await;
        let queued = owner
            .hash(
                "another genuine sufficiently long password",
                Instant::now() + Duration::from_millis(1),
            )
            .await;
        assert!(matches!(
            queued,
            Err(LocalPasswordVerificationError::Control(
                ControlError::Deadline
            ))
        ));
        assert_eq!(owner.slots.available_permits(), 0);
        assert!(matches!(
            caller.await.unwrap(),
            Err(LocalPasswordVerificationError::Control(
                ControlError::Deadline
            ))
        ));
        assert_eq!(owner.slots.available_permits(), 0);
        recovered(&owner).await;
        assert_eq!(owner.slots.available_permits(), 1);
    }
    #[tokio::test]
    async fn close_joins_cancelled_real_sdk_worker_and_rejects_new_work() {
        let owner = engine().await;
        let worker_owner = Arc::clone(&owner);
        let caller = tokio::spawn(async move {
            worker_owner
                .hash("a genuine sufficiently long native password", end())
                .await
        });
        occupied(&owner).await;
        caller.abort();
        let _ = caller.await;
        assert_eq!(owner.slots.available_permits(), 0);
        owner.close().await;
        assert!(owner.workers.tasks.is_empty());
        assert!(owner.slots.is_closed());
        assert_eq!(owner.slots.available_permits(), 1);
        assert!(matches!(
            owner
                .hash("another genuine sufficiently long password", end())
                .await,
            Err(LocalPasswordVerificationError::Control(
                ControlError::Closed
            ))
        ));
    }
    #[tokio::test]
    async fn startup_dummy_failure_drains_the_actual_worker_owner() {
        let hasher = Arc::new(
            LocalPasswordHasher::new(Zeroizing::new(vec![23; 32].into_boxed_slice())).unwrap(),
        );
        let workers = LocalPasswordWorkers::new(NonZeroUsize::new(1).unwrap());
        let result = initialize_dummy(
            &hasher,
            &workers,
            Instant::now() + Duration::from_millis(50),
        )
        .await;
        assert!(matches!(
            result,
            Err(LocalPasswordVerificationError::Control(
                ControlError::Deadline
            ))
        ));
        assert!(workers.tasks.is_empty());
        assert!(workers.tasks.is_closed());
        assert!(workers.slots.is_closed());
        assert_eq!(Arc::strong_count(&hasher), 1);
    }
}
