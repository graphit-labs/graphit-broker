use super::{
    SqliteControlStore,
    admin_local_observer::{self, LocalProof},
};
use crate::{
    AdminBrokerSessionError as Error, AdminBrokerSessionLimits, AdminLocalBearerSession,
    BrokerAccessError, ControlError, SystemAction, VerifiedLocalBearer,
    admin_local_bearer_session::{check_authentication, verification_error},
};
use std::{
    fmt,
    num::NonZeroUsize,
    time::{Instant, SystemTime},
};

/// Administrative session.read from genuine LOCAL access/service possession.
/// The view borrows the actual private SQLite owner.
/// ~~~compile_fail
/// fn escape(s: &broker_control::SqliteControlStore) -> broker_control::SqliteAdminLocalBearerSessions<'static> {
///     let n=std::num::NonZeroUsize::new(4096).unwrap();
///     let l=broker_control::AdminBrokerSessionLimits { identity: broker_control::IdentityReadLimits {username_bytes:n,subject_bytes:n,role_bytes:n,roles:n,rows:n}, profile_json_bytes:n };
///     s.admin_local_bearer_sessions("aud",n,l).unwrap()
/// }
/// ~~~
pub struct SqliteAdminLocalBearerSessions<'a> {
    store: &'a SqliteControlStore,
    audience: &'a str,
    identity_json_bytes: NonZeroUsize,
    limits: AdminBrokerSessionLimits,
}
impl fmt::Debug for SqliteAdminLocalBearerSessions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteAdminLocalBearerSessions([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn admin_local_bearer_sessions<'a>(
        &'a self,
        audience: &'a str,
        identity_json_bytes: NonZeroUsize,
        limits: AdminBrokerSessionLimits,
    ) -> Result<SqliteAdminLocalBearerSessions<'a>, ControlError> {
        limits.validate()?;
        if audience.trim().is_empty() {
            return Err(ControlError::Configuration);
        }
        self.local_bearer_verifier(audience, identity_json_bytes)
            .map_err(verification_error)
            .map_err(|e| match e {
                Error::Control(e) => e,
                _ => ControlError::Configuration,
            })?;
        Ok(SqliteAdminLocalBearerSessions {
            store: self,
            audience,
            identity_json_bytes,
            limits,
        })
    }
}
impl SqliteAdminLocalBearerSessions<'_> {
    pub async fn read(
        &self,
        raw: &str,
        required_scopes: &[String],
        original: Instant,
    ) -> Result<AdminLocalBearerSession, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let proof = self
            .store
            .local_bearer_verifier(self.audience, self.identity_json_bytes)
            .map_err(verification_error)?
            .verify(raw, required_scopes, end)
            .await
            .map_err(verification_error)?;
        self.read_current(proof, end).await
    }
    async fn read_current(
        &self,
        proof: VerifiedLocalBearer,
        end: Instant,
    ) -> Result<AdminLocalBearerSession, Error> {
        let expiry = proof.authentication_expiry();
        let wait_end = end.min(expiry.1);
        let limits = self.limits;
        let observed = self
            .store
            .executor
            .execute(wait_end, move |owner, work| {
                let outcome = (|| {
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let data = admin_local_observer::observe(
                        &tx,
                        work,
                        LocalProof::Opaque(&proof),
                        limits,
                        SystemAction::SessionRead,
                        end,
                    )?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok::<_, Error>(data)
                })();
                Ok((proof, outcome))
            })
            .await;
        // A missing COMMIT acknowledgement precedes expiry and any final gate.
        if matches!(
            &observed,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok((_, Err(Error::Control(ControlError::OutcomeUncertain))))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        // Captured cutoffs classify denial even when the native worker returned a
        // wait error; they never produce authority or replace the owned proof.
        if Instant::now() >= expiry.1 || SystemTime::now() >= expiry.0 {
            return Err(BrokerAccessError::Expired.into());
        }
        let (proof, outcome) = observed.map_err(ControlError::from)?;
        check_authentication(&proof)?;
        let (profile, principal, roles, permissions) = outcome?;
        let result = AdminLocalBearerSession {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlowLimits, IdentityReadLimits, SqliteControlConfig};
    use broker_security::{CredentialDigester, DigestLimits, TokenKind};
    use rusqlite::{Connection, params};
    use std::time::Duration;
    use zeroize::Zeroizing;
    fn n(v: usize) -> NonZeroUsize {
        NonZeroUsize::new(v).unwrap()
    }
    #[tokio::test]
    async fn authenticated_bearer_expiry_cuts_off_a_real_locked_admin_observation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private/db");
        let digester = CredentialDigester::new(
            Zeroizing::new(vec![53; 32].into_boxed_slice()),
            DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
        )
        .unwrap();
        let raw = "gb_at_expiry-physical";
        let hash = digester
            .token(TokenKind::LocalAccess, raw.as_bytes())
            .unwrap()
            .to_sql_hex();
        let end = || Instant::now() + Duration::from_secs(5);
        let store = SqliteControlStore::open(
            SqliteControlConfig::new(
                path.clone(),
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
                FlowLimits {
                    provider_bytes: n(128),
                    request_bytes: n(256),
                    continuation_bytes: n(1024),
                },
            )
            .unwrap(),
            digester,
            end(),
        )
        .await
        .unwrap();
        let db = Connection::open(path).unwrap();
        db.execute_batch("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at)VALUES('alice','alice-subject','human','','','','','[]',1,1,1,0,0)").unwrap();
        let principal=serde_json::json!({"issuer":"local","subject":"alice-subject","username":"alice","auth_method":"local-token","name":"stale","roles":["admin"],"teams":[],"local_user_revision":1}).to_string();
        let expires = crate::flow::now_micros().unwrap() + 30_000_000;
        db.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at)VALUES(?1,'expiry','access','alice-subject','pseudo',?2,'client','aud','','[]',1,'',0,?3,0)",params![hash,principal,expires]).unwrap();
        let limits = AdminBrokerSessionLimits {
            identity: IdentityReadLimits {
                username_bytes: n(128),
                subject_bytes: n(512),
                role_bytes: n(128),
                roles: n(16),
                rows: n(128),
            },
            profile_json_bytes: n(8192),
        };
        let proof = store
            .local_bearer_verifier("aud", n(8192))
            .unwrap()
            .verify(raw, &[], end())
            .await
            .unwrap();
        db.execute(
            "UPDATE local_users SET revision=2 WHERE username='alice'",
            [],
        )
        .unwrap();
        assert_eq!(
            store
                .admin_local_bearer_sessions("aud", n(8192), limits)
                .unwrap()
                .read_current(proof, end())
                .await
                .unwrap_err(),
            Error::Authentication(BrokerAccessError::InvalidToken)
        );
        db.execute(
            "UPDATE local_users SET revision=1 WHERE username='alice'",
            [],
        )
        .unwrap();
        db.execute(
            "UPDATE local_tokens SET expires_at=?1",
            [crate::flow::now_micros().unwrap() + 300_000],
        )
        .unwrap();
        let proof = store
            .local_bearer_verifier("aud", n(8192))
            .unwrap()
            .verify(raw, &[], end())
            .await
            .unwrap();
        let expected = proof.authentication_expiry().1;
        // Possession is already verified before this physical writer takes its lock.
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let result = store
            .admin_local_bearer_sessions("aud", n(8192), limits)
            .unwrap()
            .read_current(proof, end())
            .await;
        assert_eq!(
            result.unwrap_err(),
            Error::Authentication(BrokerAccessError::Expired)
        );
        assert!(Instant::now() >= expected);
        assert!(Instant::now().duration_since(expected) < Duration::from_secs(2));
        db.execute_batch("ROLLBACK").unwrap();
        store.shutdown(end()).await.unwrap();
    }
}
