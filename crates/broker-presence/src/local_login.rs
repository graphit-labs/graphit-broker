//! Shared trusted LOCAL startup owner; HTTP purpose is explicit in each consumer.
use broker_control::{
    AdmittedLocalPasswordChange, ControlError, LocalAuthPolicy, LocalCaptchaChallenge,
    LocalMfaAttemptLimiter, LocalPasswordAdmission, LocalPasswordAdmissionError,
    LocalPasswordEngine, PostgresAdmittedLocalPasswords, PostgresControlStore,
    PostgresLocalAuthService,
};
use broker_security::{CredentialDigester, LocalAuthPurpose, LocalMfaProtector};
use std::{fmt, sync::Arc, time::Instant};

/// One engine/admission/factor owner shared by genuine Admin and OAuth consumers.
/// Requests supply credentials and a protected binding, never startup policy.
pub struct LocalLoginRuntime {
    engine: Arc<LocalPasswordEngine>,
    admission: Arc<LocalPasswordAdmission>,
    digester: CredentialDigester,
    mfa: LocalMfaProtector,
    policy: LocalAuthPolicy,
    limiter: LocalMfaAttemptLimiter,
}
impl fmt::Debug for LocalLoginRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalLoginRuntime([REDACTED])")
    }
}
impl LocalLoginRuntime {
    pub fn new(
        engine: Arc<LocalPasswordEngine>,
        admission: Arc<LocalPasswordAdmission>,
        digester: CredentialDigester,
        mfa: LocalMfaProtector,
        policy: LocalAuthPolicy,
        limiter: LocalMfaAttemptLimiter,
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
        store: &'a PostgresControlStore,
        purpose: LocalAuthPurpose,
    ) -> Result<PostgresAdmittedLocalPasswords<'a>, ControlError> {
        store.admitted_local_passwords(&self.engine, &self.admission, purpose)
    }
    pub fn authentication<'a>(
        &'a self,
        store: &'a PostgresControlStore,
    ) -> PostgresLocalAuthService<'a> {
        store.local_auth_service(&self.digester, &self.mfa, &self.policy)
    }
    pub fn admit_password_change(
        &self,
        original: Instant,
    ) -> Result<AdmittedLocalPasswordChange<'_>, LocalPasswordAdmissionError> {
        self.admission.admit_password_change(&self.engine, original)
    }
    pub fn limiter(&self) -> &LocalMfaAttemptLimiter {
        &self.limiter
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
    /// Join uncancellable SDK workers before the server closes SQL.
    pub async fn close(&self) {
        self.stop_admission();
        self.engine.close().await;
    }
}
