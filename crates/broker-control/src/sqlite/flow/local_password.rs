use super::SqliteControlStore;
use crate::{
    ControlError, LocalPasswordAdmission, LocalPasswordAdmissionError, LocalPasswordEngine,
    LocalPasswordVerificationError as Error, VerifiedLocalPassword,
    identity::{safe_identity_segment, valid_identity_subject},
    local_captcha::CaptchaFailure,
    local_password::ensure_time,
    local_password_admission::PasswordWorkLease,
};
use broker_security::{LOCAL_PASSWORD_MAX_BYTES, LocalAuthPurpose};
use broker_store::time::TimestampMicros;
use rusqlite::{OptionalExtension, Row, params};
use std::{fmt, sync::Arc, time::Instant};
use zeroize::Zeroizing;

pub(super) const PROJECTION: &str = "CASE WHEN length(CAST(username AS BLOB))<=128 THEN username END,CASE WHEN length(CAST(subject AS BLOB))<=512 THEN subject END,CASE WHEN length(CAST(identity_kind AS BLOB))<=16 THEN identity_kind END,CASE WHEN length(CAST(password_hash AS BLOB))<=512 THEN password_hash END,enabled,password_change_required,revision";

#[derive(PartialEq, Eq)]
pub(super) struct CurrentPassword {
    pub username: String,
    pub subject: String,
    pub hash: Zeroizing<String>,
    pub revision: i64,
    pub change_required: bool,
}
impl CurrentPassword {
    pub(super) fn decode(row: &Row<'_>) -> Option<Self> {
        let hash = Zeroizing::new(row.get::<_, Option<String>>(3).ok()??);
        let username = row.get::<_, Option<String>>(0).ok()??;
        let subject = row.get::<_, Option<String>>(1).ok()??;
        let kind = row.get::<_, Option<String>>(2).ok()??;
        let enabled: i64 = row.get(4).ok()?;
        let change: i64 = row.get(5).ok()?;
        let revision: i64 = row.get(6).ok()?;
        if !safe_identity_segment(&username, 128)
            || !valid_identity_subject(&subject, 512)
            || kind != "human"
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
}

/// Genuine SDK password evidence revalidated against current SQLite state.
pub struct SqliteLocalPasswordVerifier<'a> {
    owner: &'a SqliteControlStore,
    engine: &'a LocalPasswordEngine,
}
impl fmt::Debug for SqliteLocalPasswordVerifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalPasswordVerifier([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn local_password_verifier<'a>(
        &'a self,
        engine: &'a LocalPasswordEngine,
    ) -> SqliteLocalPasswordVerifier<'a> {
        SqliteLocalPasswordVerifier {
            owner: self,
            engine,
        }
    }
    pub fn admitted_local_passwords<'a>(
        &'a self,
        engine: &'a LocalPasswordEngine,
        admission: &'a LocalPasswordAdmission,
        purpose: LocalAuthPurpose,
    ) -> Result<SqliteAdmittedLocalPasswords<'a>, ControlError> {
        if !admission.matches_engine(engine) {
            return Err(ControlError::Configuration);
        }
        Ok(SqliteAdmittedLocalPasswords {
            verifier: self.local_password_verifier(engine),
            admission,
            purpose,
        })
    }
}
impl SqliteLocalPasswordVerifier<'_> {
    async fn load_current(
        &self,
        username: &str,
        end: Instant,
        lease: Option<Arc<PasswordWorkLease>>,
    ) -> Result<Option<CurrentPassword>, Error> {
        let username = username.to_owned();
        let dispatcher = tracing::dispatcher::get_default(Clone::clone);
        self.owner
            .executor
            .execute(end, move |owner, work| {
                // Native SQL work keeps admission after its async caller is dropped.
                let _dispatch = tracing::dispatcher::set_default(&dispatcher);
                let _lease = lease;
                tracing::trace!(target: "broker_control::sqlite::password_read_started", "SQLite password read started");
                let tx = owner.begin(work)?;
                let sql = format!("SELECT {PROJECTION} FROM local_users WHERE username=?1");
                let current = tx
                    .query_row(&sql, [&username], |r| Ok(CurrentPassword::decode(r)))
                    .optional()
                    .map_err(|e| work.sql(e))?
                    .flatten();
                work.commit(tx)?;
                Ok(current)
            })
            .await
            .map_err(ControlError::from)
            .map_err(Into::into)
    }
    async fn finish_current(
        &self,
        initial: CurrentPassword,
        end: Instant,
        lease: Option<Arc<PasswordWorkLease>>,
    ) -> Result<VerifiedLocalPassword, Error> {
        let result = self
            .owner
            .executor
            .execute(end, move |owner, work| {
                // Native SQL work keeps admission after its async caller is dropped.
                let _lease = lease;
                let tx = owner.begin(work)?;
                let sql = format!("SELECT {PROJECTION} FROM local_users WHERE subject=?1");
                let current = tx
                    .query_row(&sql, params![&initial.subject], |r| {
                        Ok(CurrentPassword::decode(r))
                    })
                    .optional()
                    .map_err(|e| work.sql(e))?
                    .flatten();
                let Some(current) = current.filter(|current| current == &initial) else {
                    return Ok(Err(Error::Unauthenticated));
                };
                work.commit(tx)?;
                let verified_at = TimestampMicros::new(super::clock()?)
                    .map_err(|_| super::SqliteControlError::Clock)?;
                Ok(Ok(VerifiedLocalPassword {
                    username: current.username,
                    subject: current.subject,
                    revision: current.revision,
                    password_change_required: current.change_required,
                    verified_at,
                }))
            })
            .await
            .map_err(ControlError::from)??;
        ensure_time(end)?;
        Ok(result)
    }
    pub async fn verify(
        &self,
        username: &str,
        password: &str,
        original: Instant,
    ) -> Result<VerifiedLocalPassword, Error> {
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let username = username.trim();
        if !safe_identity_segment(username, 128) || password.len() > LOCAL_PASSWORD_MAX_BYTES {
            return Err(Error::Unauthenticated);
        }
        let initial = self.load_current(username, end, None).await?;
        tracing::trace!(target: "broker_control::sqlite::password_snapshot", "SQLite password snapshot ready");
        if !self
            .engine
            .verify(password, initial.as_ref().map(|r| r.hash.as_str()), end)
            .await?
        {
            return Err(Error::Unauthenticated);
        }
        self.finish_current(initial.ok_or(Error::Unauthenticated)?, end, None)
            .await
    }
}

/// Uses the exact shared physical engine and logical admission owner.
pub struct SqliteAdmittedLocalPasswords<'a> {
    verifier: SqliteLocalPasswordVerifier<'a>,
    admission: &'a LocalPasswordAdmission,
    purpose: LocalAuthPurpose,
}
impl fmt::Debug for SqliteAdmittedLocalPasswords<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteAdmittedLocalPasswords([REDACTED])")
    }
}
impl SqliteAdmittedLocalPasswords<'_> {
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        captcha_proof: Option<&str>,
        original: Instant,
    ) -> Result<VerifiedLocalPassword, LocalPasswordAdmissionError> {
        let end = self
            .verifier
            .owner
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let username = username.trim();
        if !safe_identity_segment(username, 128)
            || password.is_empty()
            || password.len() > LOCAL_PASSWORD_MAX_BYTES
        {
            return Err(LocalPasswordAdmissionError::Unauthenticated);
        }
        let (lease, occupancy) = self.admission.admit(Some(username), end)?;
        if self.admission.captcha.required(occupancy) {
            self.admission
                .captcha
                .verify(self.purpose, captcha_proof, end)
                .await
                .map_err(|e| match e {
                    CaptchaFailure::Control(e) => LocalPasswordAdmissionError::Control(e),
                    CaptchaFailure::Required => self
                        .admission
                        .challenge(self.purpose)
                        .map(LocalPasswordAdmissionError::CaptchaRequired)
                        .unwrap_or(LocalPasswordAdmissionError::Control(
                            ControlError::Configuration,
                        )),
                })?;
        }
        let initial = self
            .verifier
            .load_current(username, end, Some(Arc::clone(&lease)))
            .await?;
        let checked = self
            .verifier
            .engine
            .verify_admitted(
                password,
                initial.as_ref().map(|r| r.hash.as_str()),
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
        let proof = self
            .verifier
            .finish_current(
                initial.ok_or(LocalPasswordAdmissionError::Unauthenticated)?,
                end,
                Some(Arc::clone(&lease)),
            )
            .await?;
        lease.succeeded(&proof, end)?;
        Ok(proof)
    }
}
