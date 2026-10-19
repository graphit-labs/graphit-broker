use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    ControlError, LocalPasswordEngine, LocalPasswordVerificationError, VerifiedLocalPassword,
    flow::now_micros,
    identity::{safe_identity_segment, valid_identity_subject},
    local_captcha::CaptchaFailure,
    local_password::ensure_time,
    local_password_admission::{LocalPasswordAdmission, LocalPasswordAdmissionError},
};
use broker_security::{LOCAL_PASSWORD_MAX_BYTES, LocalAuthPurpose};
use broker_store::time::TimestampMicros;
use sqlx_core::connection::Connection;
use std::{
    fmt,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

const INITIAL_SELECT: &str = "SELECT CASE WHEN octet_length(username)<=128 THEN username END,CASE WHEN octet_length(subject)<=512 THEN subject END,CASE WHEN octet_length(identity_kind)<=16 THEN identity_kind END,CASE WHEN octet_length(password_hash)<=512 THEN password_hash END,enabled::bigint,password_change_required::bigint,revision FROM public.local_users WHERE username=$1";
const FINAL_SELECT: &str = "SELECT CASE WHEN octet_length(username)<=128 THEN username END,CASE WHEN octet_length(subject)<=512 THEN subject END,CASE WHEN octet_length(identity_kind)<=16 THEN identity_kind END,CASE WHEN octet_length(password_hash)<=512 THEN password_hash END,enabled::bigint,password_change_required::bigint,revision FROM public.local_users WHERE subject=$1 FOR SHARE";
type Row = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    i64,
    i64,
);
struct CurrentPassword {
    username: String,
    subject: String,
    hash: Zeroizing<String>,
    revision: i64,
    change_required: bool,
}
impl CurrentPassword {
    fn from_row(row: Row) -> Option<Self> {
        let (username, subject, kind, hash, enabled, change, revision) = row;
        // Consume a fetched PHC immediately into a zeroizing owner, even if other
        // stored fields subsequently make this identity ineligible.
        let hash = Zeroizing::new(hash?);
        let username = username?;
        let subject = subject?;
        if !safe_identity_segment(&username, 128)
            || !valid_identity_subject(&subject, 512)
            || kind.as_deref() != Some("human")
            || enabled != 1
            || !matches!(change, 0 | 1)
            || revision < 1
        {
            return None;
        }
        Some(Self {
            username,
            subject,
            hash,
            revision,
            change_required: change == 1,
        })
    }
    fn matches(&self, other: &Self) -> bool {
        self.username == other.username
            && self.subject == other.subject
            && self.hash == other.hash
            && self.revision == other.revision
            && self.change_required == other.change_required
    }
}
/// Borrowed native password verifier. It does not complete password-change/MFA,
/// create a session or grant OAuth consent.
pub struct PostgresLocalPasswordVerifier<'a> {
    owner: &'a PostgresControlStore,
    engine: &'a LocalPasswordEngine,
}
impl fmt::Debug for PostgresLocalPasswordVerifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresLocalPasswordVerifier([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn local_password_verifier<'a>(
        &'a self,
        engine: &'a LocalPasswordEngine,
    ) -> PostgresLocalPasswordVerifier<'a> {
        PostgresLocalPasswordVerifier {
            owner: self,
            engine,
        }
    }
}
impl PostgresLocalPasswordVerifier<'_> {
    async fn load_current(
        &self,
        username: &str,
    ) -> Result<Option<CurrentPassword>, LocalPasswordVerificationError> {
        let mut guard = ConnectionGuard(Some(
            self.owner.pool.acquire().await.map_err(storage_error)?,
        ));
        let row = sqlx_core::query_as::query_as::<_, Row>(INITIAL_SELECT)
            .bind(username)
            .fetch_optional(guard.connection()?)
            .await
            .map_err(storage_error)?;
        guard.confirmed();
        Ok(row.and_then(CurrentPassword::from_row))
    }
    async fn finish_current(
        &self,
        initial: &CurrentPassword,
        end: Instant,
        commit_started: &AtomicBool,
    ) -> Result<VerifiedLocalPassword, LocalPasswordVerificationError> {
        let mut guard = ConnectionGuard(Some(
            self.owner.pool.acquire().await.map_err(storage_error)?,
        ));
        let mut tx = guard
            .connection()?
            .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
            .await
            .map_err(storage_error)?;
        let current = sqlx_core::query_as::query_as::<_, Row>(FINAL_SELECT)
            .bind(&initial.subject)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage_error)?
            .and_then(CurrentPassword::from_row)
            .ok_or(LocalPasswordVerificationError::Unauthenticated)?;
        if !initial.matches(&current) {
            return Err(LocalPasswordVerificationError::Unauthenticated);
        }
        ensure_time(end)?;
        let verified_at = TimestampMicros::new(now_micros()?).map_err(|_| ControlError::Clock)?;
        commit_started.store(true, Ordering::Relaxed);
        tx.commit()
            .await
            .map_err(|_| ControlError::OutcomeUncertain)?;
        guard.confirmed();
        ensure_time(end)?;
        Ok(VerifiedLocalPassword {
            username: current.username,
            subject: current.subject,
            revision: current.revision,
            password_change_required: current.change_required,
            verified_at,
        })
    }
    pub async fn verify(
        &self,
        username: &str,
        password: &str,
        original: Instant,
    ) -> Result<VerifiedLocalPassword, LocalPasswordVerificationError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        // Login input removes surrounding whitespace; stored identity and password
        // remain exact, and case is preserved.
        let username = username.trim();
        if !safe_identity_segment(username, 128) || password.len() > LOCAL_PASSWORD_MAX_BYTES {
            return Err(LocalPasswordVerificationError::Unauthenticated);
        }
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let initial = self.load_current(username).await?;
            let matched = self
                .engine
                .verify(password, initial.as_ref().map(|row| row.hash.as_str()), end)
                .await?;
            if !matched {
                return Err(LocalPasswordVerificationError::Unauthenticated);
            }
            let initial = initial.ok_or(LocalPasswordVerificationError::Unauthenticated)?;
            self.finish_current(&initial, end, &commit_started).await
        })
        .await
        .map_err(|_| timeout_error(&commit_started))?
    }
}
/// Borrows one shared admission owner and the same physical engine. Only current
/// PostgreSQL/SDK verification returns genuine password evidence.
pub struct PostgresAdmittedLocalPasswords<'a> {
    verifier: PostgresLocalPasswordVerifier<'a>,
    admission: &'a LocalPasswordAdmission,
    purpose: LocalAuthPurpose,
}
impl fmt::Debug for PostgresAdmittedLocalPasswords<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresAdmittedLocalPasswords([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn admitted_local_passwords<'a>(
        &'a self,
        engine: &'a LocalPasswordEngine,
        admission: &'a LocalPasswordAdmission,
        purpose: LocalAuthPurpose,
    ) -> Result<PostgresAdmittedLocalPasswords<'a>, ControlError> {
        if !admission.matches_engine(engine) {
            return Err(ControlError::Configuration);
        }
        Ok(PostgresAdmittedLocalPasswords {
            verifier: self.local_password_verifier(engine),
            admission,
            purpose,
        })
    }
}
impl PostgresAdmittedLocalPasswords<'_> {
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        captcha_proof: Option<&str>,
        original: Instant,
    ) -> Result<VerifiedLocalPassword, LocalPasswordAdmissionError> {
        let end = bounded_deadline(original, self.verifier.owner.budgets.operation_timeout)?;
        let username = username.trim();
        if !safe_identity_segment(username, 128)
            || password.is_empty()
            || password.len() > LOCAL_PASSWORD_MAX_BYTES
        {
            return Err(LocalPasswordAdmissionError::Unauthenticated);
        }
        let (lease, occupancy) = self.admission.admit(Some(username), end)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            if self.admission.captcha.required(occupancy) {
                self.admission
                    .captcha
                    .verify(self.purpose, captcha_proof, end)
                    .await
                    .map_err(|error| match error {
                        CaptchaFailure::Control(error) => {
                            LocalPasswordAdmissionError::Control(error)
                        }
                        CaptchaFailure::Required => self
                            .admission
                            .challenge(self.purpose)
                            .map(LocalPasswordAdmissionError::CaptchaRequired)
                            .unwrap_or(LocalPasswordAdmissionError::Control(
                                ControlError::Configuration,
                            )),
                    })?;
            }
            let initial = self.verifier.load_current(username).await?;
            let checked = self
                .verifier
                .engine
                .verify_admitted(
                    password,
                    initial.as_ref().map(|value| value.hash.as_str()),
                    Arc::clone(&lease),
                    end,
                )
                .await?;
            if !checked.matched() {
                if let Some(incorrect) = checked.into_incorrect() {
                    lease.incorrect(incorrect, end)?;
                }
                return Err(LocalPasswordAdmissionError::Unauthenticated);
            }
            let initial = initial.ok_or(LocalPasswordAdmissionError::Unauthenticated)?;
            let proof = self
                .verifier
                .finish_current(&initial, end, &commit_started)
                .await?;
            lease.succeeded(&proof, end)?;
            Ok(proof)
        })
        .await
        .map_err(|_| LocalPasswordAdmissionError::Control(timeout_error(&commit_started)))?
    }
}
