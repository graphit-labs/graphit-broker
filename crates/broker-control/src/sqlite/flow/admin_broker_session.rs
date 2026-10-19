use super::{
    SqliteControlStore,
    admin_local_observer::{self, LocalProof},
};
use crate::{
    AdminBrokerSession, AdminBrokerSessionError as Error, AdminBrokerSessionLimits,
    BrokerAccessError, BrokerAccessVerifier, ControlError, SystemAction, VerifiedBrokerAccess,
    identity::safe_identity_segment,
};
use std::{
    fmt,
    sync::Arc,
    time::{Instant, SystemTime},
};

/// A session view borrowing both its private SQLite owner and trusted verifier.
/// ```compile_fail
/// fn escape<'v>(s: &broker_control::SqliteControlStore, v: &'v broker_control::BrokerAccessVerifier, l: broker_control::AdminBrokerSessionLimits) -> broker_control::SqliteAdminBrokerSessions<'static,'v> {
///     s.admin_broker_sessions(v,l).unwrap()
/// }
/// ```
pub struct SqliteAdminBrokerSessions<'s, 'v> {
    store: &'s SqliteControlStore,
    verifier: &'v BrokerAccessVerifier,
    limits: AdminBrokerSessionLimits,
}
impl fmt::Debug for SqliteAdminBrokerSessions<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteAdminBrokerSessions([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn admin_broker_sessions<'s, 'v>(
        &'s self,
        verifier: &'v BrokerAccessVerifier,
        limits: AdminBrokerSessionLimits,
    ) -> Result<SqliteAdminBrokerSessions<'s, 'v>, ControlError> {
        limits.validate()?;
        Ok(SqliteAdminBrokerSessions {
            store: self,
            verifier,
            limits,
        })
    }
}
impl<'v> SqliteAdminBrokerSessions<'_, 'v> {
    pub async fn read(
        &self,
        proof: VerifiedBrokerAccess<'v>,
        original: Instant,
    ) -> Result<AdminBrokerSession<'v>, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        proof.check()?;
        if !proof.owned_by(self.verifier) {
            return Err(BrokerAccessError::InvalidToken.into());
        }
        let username = proof
            .username()
            .filter(|u| safe_identity_segment(u, self.limits.identity.username_bytes.get()))
            .ok_or(Error::Forbidden)?
            .to_owned();
        // These are bounded SQL parameters; the genuine proof stays alive in this caller.
        let subject = proof.subject().to_owned();
        let expiry = proof.authentication_expiry();
        let limits = self.limits;
        let digester = Arc::clone(&self.store.digester);
        let observed = self
            .store
            .executor
            .execute(end.min(expiry.1), move |owner, work| {
                Ok((|| -> Result<_, Error> {
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let data = admin_local_observer::observe(
                        &tx,
                        work,
                        LocalProof::Broker {
                            username: &username,
                            subject: &subject,
                            digester: &digester,
                            expiry,
                        },
                        limits,
                        SystemAction::SessionRead,
                        end,
                    )?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok(data)
                })())
            })
            .await;
        if matches!(
            &observed,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok(Err(Error::Control(ControlError::OutcomeUncertain)))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        if Instant::now() >= expiry.1 || SystemTime::now() >= expiry.0 {
            return Err(BrokerAccessError::Expired.into());
        }
        proof.check()?;
        let (profile, principal, roles, permissions) = observed.map_err(ControlError::from)??;
        let result = AdminBrokerSession {
            proof,
            original: end,
            profile,
            principal,
            roles,
            permissions,
        };
        result.check()?;
        Ok(result)
    }
}
