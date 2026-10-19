use super::super::{
    admin_local_observer::{self, LocalProof},
    admin_upstream_session,
};
use super::{OwnedRequest, SqliteControlStore, projection};
use crate::{
    AdminBrokerSessionError as AuthenticationError, AdminReadAuthentication,
    AdminReadError as Error, AdminReadLimits, AdminReadRequest, AdminReadResult, BrokerAccessError,
    BrokerAccessVerifier, ControlError, SessionPrincipal, VerifiedBrokerAccess,
    admin_read::ReadWitness, service::admin_upstream_session::validate_profile,
    sqlite::executor::Work,
};
use std::{
    fmt,
    sync::Arc,
    time::{Instant, SystemTime},
};

/// Per-action projections from genuine configured credentials and one SQLite snapshot.
/// A completed session.read is neither an input nor a permission for this view.
/// ```compile_fail
/// fn escape(s: &broker_control::SqliteControlStore,l:broker_control::AdminReadLimits)
///     -> broker_control::SqliteAdminReads<'static> { s.admin_reads(l).unwrap() }
/// ```
pub struct SqliteAdminReads<'s> {
    store: &'s SqliteControlStore,
    limits: AdminReadLimits,
}
impl fmt::Debug for SqliteAdminReads<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteAdminReads([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn admin_reads(
        &self,
        limits: AdminReadLimits,
    ) -> Result<SqliteAdminReads<'_>, ControlError> {
        limits.validate()?;
        Ok(SqliteAdminReads {
            store: self,
            limits,
        })
    }
}
fn broker_gate(work: &Work, end: Instant, expiry: (SystemTime, Instant)) -> Result<(), Error> {
    work.check().map_err(ControlError::from)?;
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    if Instant::now() >= expiry.1 || SystemTime::now() >= expiry.0 {
        return Err(AuthenticationError::from(BrokerAccessError::Expired).into());
    }
    Ok(())
}
impl SqliteAdminReads<'_> {
    pub async fn read<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminReadRequest<'_>,
        original: Instant,
    ) -> Result<AdminReadResult<'a>, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        match authentication {
            AdminReadAuthentication::Broker { verifier, proof } => {
                self.broker(verifier, proof, request, end).await
            }
            AdminReadAuthentication::Opaque {
                raw,
                audience,
                identity_json_bytes,
                required_scopes,
            } => {
                self.store
                    .local_admin_reads(self.limits)?
                    .read_opaque(
                        raw,
                        audience,
                        identity_json_bytes,
                        required_scopes,
                        request,
                        end,
                    )
                    .await
            }
            AdminReadAuthentication::Upstream { raw, verifier } => {
                let proof = verifier.verify(raw, end).await?;
                validate_profile(&proof, self.limits.authorization, end)?;
                let expiry = proof.expires_mono();
                let wait = end.min(expiry);
                let request = OwnedRequest::capture(request, self.limits)?;
                let limits = self.limits;
                let observed = self
                    .store
                    .executor
                    .execute(wait, move |owner, work| {
                        let outcome = (|| -> Result<_, Error> {
                            proof.check()?;
                            work.check().map_err(ControlError::from)?;
                            let tx = owner.begin(work).map_err(ControlError::from)?;
                            let request = request.borrow();
                            let subject = format!("{}|{}", proof.issuer(), proof.profile().subject);
                            admin_upstream_session::observe_roles(
                                &tx,
                                work,
                                &subject,
                                proof.claim_roles(),
                                limits.authorization,
                                request.kind().action(),
                                || {
                                    if Instant::now() >= end {
                                        return Err(ControlError::Deadline.into());
                                    }
                                    proof.check()
                                },
                            )?;
                            let principal = SessionPrincipal {
                                issuer: proof.issuer().to_owned(),
                                username: proof.username().to_owned(),
                                organization: proof.organization().to_owned(),
                                teams: proof.teams().to_vec(),
                                local_user_revision: 0,
                            };
                            let payload = projection(
                                &tx,
                                work,
                                &request,
                                limits,
                                proof.profile(),
                                &principal,
                                wait,
                            )?;
                            proof.check()?;
                            work.check().map_err(ControlError::from)?;
                            work.commit(tx).map_err(ControlError::from)?;
                            Ok(payload)
                        })();
                        Ok((proof, outcome))
                    })
                    .await;
                if matches!(
                    &observed,
                    Err(crate::SqliteControlError::OutcomeUncertain)
                        | Ok((
                            _,
                            Err(Error::Authorization(AuthenticationError::Control(
                                ControlError::OutcomeUncertain
                            )))
                        ))
                ) {
                    return Err(ControlError::OutcomeUncertain.into());
                }
                if Instant::now() >= end {
                    return Err(ControlError::Deadline.into());
                }
                if Instant::now() >= expiry {
                    return Err(AuthenticationError::from(BrokerAccessError::Expired).into());
                }
                let (proof, outcome) = observed.map_err(ControlError::from)?;
                proof.check()?;
                let payload = outcome?;
                let result = AdminReadResult {
                    witness: ReadWitness::Upstream(proof),
                    original: end,
                    body: payload.body,
                    revision: payload.revision,
                };
                result.check()?;
                Ok(result)
            }
            AdminReadAuthentication::Cookie {
                raw,
                limits,
                policy,
                upstream,
            } => {
                let a = limits.authorization;
                let b = self.limits.authorization;
                if a.profile_json_bytes != b.profile_json_bytes
                    || [
                        a.identity.username_bytes,
                        a.identity.subject_bytes,
                        a.identity.role_bytes,
                        a.identity.roles,
                        a.identity.rows,
                    ] != [
                        b.identity.username_bytes,
                        b.identity.subject_bytes,
                        b.identity.role_bytes,
                        b.identity.roles,
                        b.identity.rows,
                    ]
                {
                    return Err(ControlError::Configuration.into());
                }
                self.store
                    .admin_cookie_sessions(limits, policy, upstream)?
                    .read_admin(raw, request, self.limits, end)
                    .await
            }
        }
    }
    async fn broker<'a>(
        &self,
        verifier: &'a BrokerAccessVerifier,
        proof: VerifiedBrokerAccess<'a>,
        request: AdminReadRequest<'_>,
        end: Instant,
    ) -> Result<AdminReadResult<'a>, Error> {
        proof.check().map_err(AuthenticationError::from)?;
        if !proof.owned_by(verifier) {
            return Err(AuthenticationError::from(BrokerAccessError::InvalidToken).into());
        }
        let username = proof
            .username()
            .filter(|u| {
                crate::identity::safe_identity_segment(
                    u,
                    self.limits.authorization.identity.username_bytes.get(),
                )
            })
            .ok_or(AuthenticationError::Forbidden)?
            .to_owned();
        // Bounded SQL data follows the native job. The genuine borrowed factor stays here.
        let subject = proof.subject().to_owned();
        let expiry = proof.authentication_expiry();
        let wait = end.min(expiry.1);
        let digester = Arc::clone(&self.store.digester);
        let limits = self.limits;
        let request = OwnedRequest::capture(request, limits)?;
        let observed = self
            .store
            .executor
            .execute(wait, move |owner, work| {
                Ok((|| -> Result<_, Error> {
                    broker_gate(work, end, expiry)?;
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let request = request.borrow();
                    let (profile, principal, _, _) = admin_local_observer::observe(
                        &tx,
                        work,
                        LocalProof::Broker {
                            username: &username,
                            subject: &subject,
                            digester: &digester,
                            expiry,
                        },
                        limits.authorization,
                        request.kind().action(),
                        end,
                    )?;
                    let payload =
                        projection(&tx, work, &request, limits, &profile, &principal, wait)?;
                    broker_gate(work, end, expiry)?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok(payload)
                })())
            })
            .await;
        if matches!(
            &observed,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok(Err(Error::Authorization(AuthenticationError::Control(
                    ControlError::OutcomeUncertain
                ))))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        proof.check().map_err(AuthenticationError::from)?;
        let payload = observed.map_err(ControlError::from)??;
        let result = AdminReadResult {
            witness: ReadWitness::Broker(proof),
            original: end,
            body: payload.body,
            revision: payload.revision,
        };
        result.check()?;
        Ok(result)
    }
}
