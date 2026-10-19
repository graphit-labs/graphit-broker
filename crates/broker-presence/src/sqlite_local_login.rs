//! Trusted SQLite LOCAL startup owners shared by HTTP password/factor consumers.
use broker_control::{
    AdmittedLocalPasswordChange, ControlError, LocalAuthPolicy, LocalCaptchaChallenge,
    LocalMfaAttemptLimiter, LocalPasswordAdmission, LocalPasswordAdmissionError,
    LocalPasswordEngine, SqliteAdmittedLocalPasswords, SqliteControlStore, SqliteLocalAuthService,
};
use broker_security::{CredentialDigester, LocalAuthPurpose, LocalMfaProtector};
use std::{fmt, sync::Arc, time::Instant};

/// Shares the genuine engine, admission, digester, factor policy and limiter.
/// Requests never construct owners or select the authentication purpose.
pub struct SqliteLocalLoginRuntime {
    engine: Arc<LocalPasswordEngine>,
    admission: Arc<LocalPasswordAdmission>,
    digester: Arc<CredentialDigester>,
    mfa: Arc<LocalMfaProtector>,
    policy: Arc<LocalAuthPolicy>,
    limiter: Arc<LocalMfaAttemptLimiter>,
}
impl fmt::Debug for SqliteLocalLoginRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalLoginRuntime([REDACTED])")
    }
}
impl SqliteLocalLoginRuntime {
    pub fn new(
        engine: Arc<LocalPasswordEngine>,
        admission: Arc<LocalPasswordAdmission>,
        digester: Arc<CredentialDigester>,
        mfa: Arc<LocalMfaProtector>,
        policy: Arc<LocalAuthPolicy>,
        limiter: Arc<LocalMfaAttemptLimiter>,
    ) -> Self {
        Self {
            engine,
            admission,
            digester,
            mfa,
            policy,
            limiter,
        }
    }
    pub fn passwords<'a>(
        &'a self,
        store: &'a SqliteControlStore,
        purpose: LocalAuthPurpose,
    ) -> Result<SqliteAdmittedLocalPasswords<'a>, ControlError> {
        store.admitted_local_passwords(&self.engine, &self.admission, purpose)
    }
    pub fn authentication<'a>(
        &'a self,
        store: &'a SqliteControlStore,
    ) -> SqliteLocalAuthService<'a> {
        store.local_auth_service(self.digester.clone(), self.mfa.clone(), self.policy.clone())
    }
    pub fn admit_password_change(
        &self,
        original: Instant,
    ) -> Result<AdmittedLocalPasswordChange<'_>, LocalPasswordAdmissionError> {
        self.admission.admit_password_change(&self.engine, original)
    }
    pub fn limiter(&self) -> Arc<LocalMfaAttemptLimiter> {
        self.limiter.clone()
    }
    pub fn policy(&self) -> &LocalAuthPolicy {
        &self.policy
    }
    pub fn challenge(&self, purpose: LocalAuthPurpose) -> Option<LocalCaptchaChallenge> {
        self.admission.challenge(purpose)
    }
    pub fn next_password_challenge(
        &self,
        purpose: LocalAuthPurpose,
    ) -> Result<Option<LocalCaptchaChallenge>, ControlError> {
        self.admission.next_password_challenge(purpose)
    }
    pub fn stop_admission(&self) {
        self.admission.close();
    }
    /// Join native SDK workers before the server closes SQL.
    pub async fn close(&self) {
        self.stop_admission();
        self.engine.close().await;
    }
}
