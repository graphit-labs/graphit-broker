//! Current SQLite administrative RBAC writes in the caller's authorized transaction.
use super::admin_cookie_session::{CookieObserver, ObservedAdminCookie, cookie_hash};
use super::{
    SqliteControlStore,
    admin_local_observer::{self, LocalProof},
    admin_upstream_session,
    roles::replace_role,
};
use crate::{
    AdminBrokerSessionError as AuthError, AdminBrokerSessionLimits, AdminCookieSessionError,
    AdminRbacError as Error, AdminRbacRequest, AdminRbacResult, AdminReadAuthentication,
    BrokerAccessError, BrokerAccessVerifier, ControlError, SystemAction, SystemPermission,
    VerifiedBrokerAccess, VerifiedLocalBearer,
    admin_cookie_session::CookieClock,
    admin_local_bearer_session::{check_authentication, verification_error},
    admin_rbac::assignment_values,
    admin_read::{ReadWitness, cookie_authorization},
    identity::{safe_identity_segment, valid_identity_subject},
    service::{admin_upstream_session::validate_profile, role_values},
    sqlite::executor::Work,
    upstream_oidc::VerifiedUpstreamBearer,
};
use rusqlite::{OptionalExtension, Transaction, params};
use std::{
    fmt,
    time::{Instant, SystemTime},
};
use zeroize::Zeroizing;

/// An administrative view borrowed from the actual SQLite owner.
/// ~~~compile_fail
/// fn escape(s: &broker_control::SqliteControlStore, l: broker_control::AdminBrokerSessionLimits)
///     -> broker_control::SqliteAdminRbac<'static> { s.admin_rbac(l).unwrap() }
/// ~~~
pub struct SqliteAdminRbac<'s> {
    store: &'s SqliteControlStore,
    limits: AdminBrokerSessionLimits,
}
impl fmt::Debug for SqliteAdminRbac<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteAdminRbac([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn admin_rbac(
        &self,
        limits: AdminBrokerSessionLimits,
    ) -> Result<SqliteAdminRbac<'_>, ControlError> {
        limits.validate()?;
        Ok(SqliteAdminRbac {
            store: self,
            limits,
        })
    }
}
enum OwnedMutation {
    SetRole {
        name: String,
        permissions: Vec<String>,
    },
    DeleteRole {
        name: String,
    },
    Assign {
        subject: String,
        role: String,
    },
    Revoke {
        subject: String,
        role: String,
    },
}
impl OwnedMutation {
    fn capture(request: AdminRbacRequest<'_>) -> Self {
        match request {
            AdminRbacRequest::SetRole { name, permissions } => Self::SetRole {
                name: name.to_owned(),
                permissions: permissions.to_vec(),
            },
            AdminRbacRequest::DeleteRole { name } => Self::DeleteRole {
                name: name.to_owned(),
            },
            AdminRbacRequest::Assign { subject, role } => Self::Assign {
                subject: subject.to_owned(),
                role: role.to_owned(),
            },
            AdminRbacRequest::Revoke { subject, role } => Self::Revoke {
                subject: subject.to_owned(),
                role: role.to_owned(),
            },
        }
    }
    fn borrow(&self) -> AdminRbacRequest<'_> {
        match self {
            Self::SetRole { name, permissions } => AdminRbacRequest::SetRole { name, permissions },
            Self::DeleteRole { name } => AdminRbacRequest::DeleteRole { name },
            Self::Assign { subject, role } => AdminRbacRequest::Assign { subject, role },
            Self::Revoke { subject, role } => AdminRbacRequest::Revoke { subject, role },
        }
    }
}
fn check(end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    Ok(())
}
fn critical(error: ControlError, fallback: Error) -> Error {
    match error {
        ControlError::Deadline | ControlError::Closed | ControlError::OutcomeUncertain => {
            error.into()
        }
        _ => fallback,
    }
}
fn mutation_sql(work: &Work, error: rusqlite::Error, fallback: Error) -> Error {
    critical(ControlError::from(work.sql(error)), fallback)
}
pub(super) fn parent(tx: &Transaction<'_>, work: &Work) -> Result<(), Error> {
    let exists = tx
        .query_row("SELECT name FROM roles WHERE name='admin'", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(|e| ControlError::from(work.sql(e)))?;
    work.check().map_err(ControlError::from)?;
    if exists.is_none() {
        return Err(ControlError::CorruptRbac.into());
    }
    Ok(())
}
pub(super) fn another_admin(tx: &Transaction<'_>, work: &Work, target: &str) -> Result<(), Error> {
    work.check().map_err(ControlError::from)?;
    let external: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM role_assignments WHERE role='admin' AND subject<>?1 AND typeof(subject)='text' AND substr(subject,1,6)<>'local|')",
        [target], |row| row.get(0),
    ).map_err(|e| mutation_sql(work, e, Error::AssignmentFailed))?;
    work.check().map_err(ControlError::from)?;
    if external {
        return Ok(());
    }
    let mut statement = tx.prepare(
        "SELECT CASE WHEN typeof(u.username)='text' AND length(CAST(u.username AS BLOB))<=128 THEN u.username END,
                CASE WHEN typeof(u.subject)='text' AND length(CAST(u.subject AS BLOB))<=512 THEN u.subject END,
                CASE WHEN typeof(u.identity_kind)='text' AND length(CAST(u.identity_kind AS BLOB))<=16 THEN u.identity_kind END,
                u.enabled,u.revision,
                CASE WHEN typeof(a.subject)='text' AND length(CAST(a.subject AS BLOB))<=518 THEN a.subject END
         FROM role_assignments a JOIN local_users u ON a.subject='local|'||u.subject
         WHERE a.role='admin' AND a.subject<>?1 AND substr(a.subject,1,6)='local|' AND u.enabled=1 LIMIT 1"
    ).map_err(|e| mutation_sql(work, e, Error::AssignmentFailed))?;
    let mut rows = statement
        .query([target])
        .map_err(|e| mutation_sql(work, e, Error::AssignmentFailed))?;
    let candidate = rows
        .next()
        .map_err(|e| mutation_sql(work, e, Error::AssignmentFailed))?
        .ok_or(Error::AssignmentFailed)?;
    let text = |i| -> Result<&str, ControlError> {
        candidate
            .get_ref(i)
            .map_err(|_| ControlError::CorruptIdentity)?
            .as_str()
            .map_err(|_| ControlError::CorruptIdentity)
    };
    let username = text(0)?;
    let subject = text(1)?;
    let kind = text(2)?;
    let enabled: i64 = candidate
        .get(3)
        .map_err(|_| ControlError::CorruptIdentity)?;
    let revision: i64 = candidate
        .get(4)
        .map_err(|_| ControlError::CorruptIdentity)?;
    let assigned = text(5)?;
    work.check().map_err(ControlError::from)?;
    if !safe_identity_segment(username, 128)
        || !valid_identity_subject(subject, 512)
        || !matches!(kind, "human" | "service")
        || enabled != 1
        || revision < 1
        || assigned.strip_prefix("local|") != Some(subject)
    {
        return Err(ControlError::CorruptIdentity.into());
    }
    Ok(())
}
fn mutate(
    tx: &Transaction<'_>,
    work: &Work,
    request: AdminRbacRequest<'_>,
    end: Instant,
) -> Result<(), Error> {
    check(end)?;
    work.check().map_err(ControlError::from)?;
    match request {
        AdminRbacRequest::SetRole { name, permissions } => {
            let name = name.trim();
            if matches!(name, "admin" | "user") {
                return Err(Error::InvalidRole);
            }
            let permissions = permissions
                .iter()
                .map(|p| SystemPermission::stored(p).ok_or(Error::InvalidRole))
                .collect::<Result<Vec<_>, _>>()?;
            let (name, actions) =
                role_values(name, &permissions).map_err(|e| critical(e, Error::InvalidRole))?;
            check(end)?;
            replace_role(tx, work, name, &actions).map_err(|e| critical(e, Error::InvalidRole))?;
        }
        AdminRbacRequest::DeleteRole { name } => {
            let name = name.trim();
            if !safe_identity_segment(name, 128) || matches!(name, "admin" | "user") {
                return Err(Error::RoleDeleteFailed);
            }
            if tx
                .execute("DELETE FROM roles WHERE name=?1", [name])
                .map_err(|e| mutation_sql(work, e, Error::RoleDeleteFailed))?
                != 1
            {
                return Err(Error::RoleDeleteFailed);
            }
        }
        AdminRbacRequest::Assign { subject, role } => {
            let (subject, role) = assignment_values(subject, role)?;
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM roles WHERE name=?1)",
                    [role],
                    |row| row.get(0),
                )
                .map_err(|e| mutation_sql(work, e, Error::AssignmentFailed))?;
            if !exists {
                return Err(Error::AssignmentFailed);
            }
            tx.execute("INSERT INTO role_assignments(subject,role,created_at) VALUES(?1,?2,?3) ON CONFLICT(subject,role) DO NOTHING",params![subject,role,crate::flow::now_micros()?]).map_err(|e| mutation_sql(work,e,Error::AssignmentFailed))?;
        }
        AdminRbacRequest::Revoke { subject, role } => {
            let (subject, role) = assignment_values(subject, role)?;
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM role_assignments WHERE subject=?1 AND role=?2)",
                    params![subject, role],
                    |row| row.get(0),
                )
                .map_err(|e| mutation_sql(work, e, Error::AssignmentFailed))?;
            if !exists {
                return Ok(());
            }
            if role == "admin" {
                another_admin(tx, work, subject)?;
            }
            tx.execute(
                "DELETE FROM role_assignments WHERE subject=?1 AND role=?2",
                params![subject, role],
            )
            .map_err(|e| mutation_sql(work, e, Error::AssignmentFailed))?;
        }
    }
    check(end)?;
    work.check().map_err(ControlError::from)?;
    Ok(())
}
fn finish(witness: ReadWitness<'_>, end: Instant) -> Result<AdminRbacResult<'_>, Error> {
    let result = AdminRbacResult {
        witness,
        original: end,
    };
    result.check()?;
    Ok(result)
}

fn authentication_gate(
    work: &Work,
    end: Instant,
    expiry: (SystemTime, Instant),
) -> Result<(), Error> {
    work.check().map_err(ControlError::from)?;
    check(end)?;
    if Instant::now() >= expiry.1 || SystemTime::now() >= expiry.0 {
        return Err(AuthError::from(BrokerAccessError::Expired).into());
    }
    Ok(())
}
impl SqliteAdminRbac<'_> {
    async fn broker<'a>(
        &self,
        verifier: &'a BrokerAccessVerifier,
        proof: VerifiedBrokerAccess<'a>,
        request: OwnedMutation,
        end: Instant,
    ) -> Result<AdminRbacResult<'a>, Error> {
        proof.check().map_err(AuthError::from)?;
        if !proof.owned_by(verifier) {
            return Err(AuthError::from(BrokerAccessError::InvalidToken).into());
        }
        let username = proof
            .username()
            .filter(|u| {
                crate::identity::safe_identity_segment(u, self.limits.identity.username_bytes.get())
            })
            .ok_or(AuthError::Forbidden)?
            .to_owned();
        let subject = proof.subject().to_owned();
        let expiry = proof.authentication_expiry();
        let limits = self.limits;
        let digester = self.store.digester.clone();
        let observed = self
            .store
            .executor
            .execute(end.min(expiry.1), move |owner, work| {
                Ok((|| -> Result<(), Error> {
                    authentication_gate(work, end, expiry)?;
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    parent(&tx, work)?;
                    admin_local_observer::observe(
                        &tx,
                        work,
                        LocalProof::Broker {
                            username: &username,
                            subject: &subject,
                            digester: &digester,
                            expiry,
                        },
                        limits,
                        SystemAction::RolesWrite,
                        end,
                    )?;
                    authentication_gate(work, end, expiry)?;
                    let applied = mutate(&tx, work, request.borrow(), end.min(expiry.1));
                    if matches!(
                        &applied,
                        Err(Error::Authorization(AuthError::Control(
                            ControlError::OutcomeUncertain
                        )))
                    ) {
                        return Err(ControlError::OutcomeUncertain.into());
                    }
                    authentication_gate(work, end, expiry)?;
                    applied?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok(())
                })())
            })
            .await;
        if matches!(
            &observed,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok(Err(Error::Authorization(AuthError::Control(
                    ControlError::OutcomeUncertain
                ))))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        check(end)?;
        proof.check().map_err(AuthError::from)?;
        observed.map_err(ControlError::from)??;
        finish(ReadWitness::Broker(proof), end)
    }
    async fn opaque(
        &self,
        proof: VerifiedLocalBearer,
        request: OwnedMutation,
        end: Instant,
    ) -> Result<AdminRbacResult<'static>, Error> {
        let expiry = proof.authentication_expiry();
        let limits = self.limits;
        let observed = self
            .store
            .executor
            .execute(end.min(expiry.1), move |owner, work| {
                let outcome = (|| -> Result<(), Error> {
                    authentication_gate(work, end, expiry)?;
                    check_authentication(&proof)?;
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    parent(&tx, work)?;
                    admin_local_observer::observe(
                        &tx,
                        work,
                        LocalProof::Opaque(&proof),
                        limits,
                        SystemAction::RolesWrite,
                        end,
                    )?;
                    authentication_gate(work, end, expiry)?;
                    check_authentication(&proof)?;
                    let applied = mutate(&tx, work, request.borrow(), end.min(expiry.1));
                    if matches!(
                        &applied,
                        Err(Error::Authorization(AuthError::Control(
                            ControlError::OutcomeUncertain
                        )))
                    ) {
                        return Err(ControlError::OutcomeUncertain.into());
                    }
                    authentication_gate(work, end, expiry)?;
                    check_authentication(&proof)?;
                    applied?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok(())
                })();
                Ok((proof, outcome))
            })
            .await;
        if matches!(
            &observed,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok((
                    _,
                    Err(Error::Authorization(AuthError::Control(
                        ControlError::OutcomeUncertain
                    )))
                ))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        check(end)?;
        if Instant::now() >= expiry.1 || SystemTime::now() >= expiry.0 {
            return Err(AuthError::from(BrokerAccessError::Expired).into());
        }
        let (proof, outcome) = observed.map_err(ControlError::from)?;
        check_authentication(&proof)?;
        outcome?;
        finish(ReadWitness::Opaque(proof), end)
    }
    async fn upstream(
        &self,
        proof: VerifiedUpstreamBearer,
        request: OwnedMutation,
        end: Instant,
    ) -> Result<AdminRbacResult<'static>, Error> {
        let expiry = proof.expires_mono();
        let limits = self.limits;
        let observed = self
            .store
            .executor
            .execute(end.min(expiry), move |owner, work| {
                let outcome = (|| -> Result<(), Error> {
                    proof.check()?;
                    check(end)?;
                    work.check().map_err(ControlError::from)?;
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    parent(&tx, work)?;
                    let subject = format!("{}|{}", proof.issuer(), proof.profile().subject);
                    admin_upstream_session::observe_roles(
                        &tx,
                        work,
                        &subject,
                        proof.claim_roles(),
                        limits,
                        SystemAction::RolesWrite,
                        || {
                            if Instant::now() >= end {
                                return Err(ControlError::Deadline.into());
                            }
                            proof.check()
                        },
                    )?;
                    let applied = mutate(&tx, work, request.borrow(), end.min(expiry));
                    if matches!(
                        &applied,
                        Err(Error::Authorization(AuthError::Control(
                            ControlError::OutcomeUncertain
                        )))
                    ) {
                        return Err(ControlError::OutcomeUncertain.into());
                    }
                    check(end)?;
                    proof.check()?;
                    work.check().map_err(ControlError::from)?;
                    applied?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok(())
                })();
                Ok((proof, outcome))
            })
            .await;
        if matches!(
            &observed,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok((
                    _,
                    Err(Error::Authorization(AuthError::Control(
                        ControlError::OutcomeUncertain
                    )))
                ))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        check(end)?;
        if Instant::now() >= expiry {
            return Err(AuthError::from(BrokerAccessError::Expired).into());
        }
        let (proof, outcome) = observed.map_err(ControlError::from)?;
        proof.check()?;
        outcome?;
        finish(ReadWitness::Upstream(proof), end)
    }
}

impl SqliteAdminRbac<'_> {
    pub async fn write<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminRbacRequest<'_>,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminRbacResult<'a>, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let request = OwnedMutation::capture(request);
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
                let proof = self
                    .store
                    .local_bearer_verifier(audience, identity_json_bytes)
                    .map_err(verification_error)?
                    .verify(raw, required_scopes, end)
                    .await
                    .map_err(verification_error)?;
                self.opaque(proof, request, end).await
            }
            AdminReadAuthentication::Upstream { raw, verifier } => {
                let proof = verifier.verify(raw, end).await?;
                validate_profile(&proof, self.limits, end)?;
                self.upstream(proof, request, end).await
            }
            AdminReadAuthentication::Cookie {
                raw,
                limits,
                policy,
                upstream,
            } => {
                let a = limits.authorization;
                let b = self.limits;
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
                    .admin_cookie_sessions(limits, policy, upstream.clone())?;
                let hash = cookie_hash(self.store, raw).map_err(cookie_authorization)?;
                let clock = CookieClock::capture();
                // Noncanonical sizes are represented as absent, with no error before current Auth.
                let supplied = csrf
                    .filter(|value| value.len() == 43)
                    .map(|value| Zeroizing::new(value.to_owned()));
                let observed = self
                    .store
                    .executor
                    .execute(end, move |owner, work| {
                        let mut cutoff = None;
                        let outcome = (|| -> Result<ReadWitness<'static>, Error> {
                            work.check().map_err(ControlError::from)?;
                            check(end)?;
                            let tx = owner.begin(work).map_err(ControlError::from)?;
                            parent(&tx, work)?;
                            let observation = match CookieObserver::new(
                                limits,
                                upstream.as_deref(),
                                SystemAction::RolesWrite,
                                &clock,
                                end,
                            )
                            .observe(&tx, work, &hash, &mut cutoff)?
                            {
                                ObservedAdminCookie::Active(observation) => observation,
                                ObservedAdminCookie::Expired(_) => {
                                    return Err(cookie_authorization(
                                        AdminCookieSessionError::Control(
                                            ControlError::SessionExpired,
                                        ),
                                    )
                                    .into());
                                }
                            };
                            let wait = end.min(observation.window().expiry().1);
                            let gate = || -> Result<(), Error> {
                                work.check().map_err(ControlError::from)?;
                                check(end)?;
                                observation.window().check().map_err(|error| {
                                    cookie_authorization(AdminCookieSessionError::Control(error))
                                })?;
                                Ok(())
                            };
                            gate()?;
                            let csrf_valid = observation
                                .csrf_matches(supplied.as_ref().map(|value| value.as_str()))?;
                            gate()?;
                            if !csrf_valid {
                                return Err(Error::CsrfFailed);
                            }
                            let applied = mutate(&tx, work, request.borrow(), wait);
                            if matches!(
                                &applied,
                                Err(Error::Authorization(AuthError::Control(
                                    ControlError::OutcomeUncertain
                                )))
                            ) {
                                return Err(ControlError::OutcomeUncertain.into());
                            }
                            gate()?;
                            applied?;
                            work.commit(tx).map_err(ControlError::from)?;
                            Ok(observation.into_witness())
                        })();
                        Ok((cutoff, outcome))
                    })
                    .await;
                if matches!(
                    &observed,
                    Err(crate::SqliteControlError::OutcomeUncertain)
                        | Ok((
                            _,
                            Err(Error::Authorization(AuthError::Control(
                                ControlError::OutcomeUncertain
                            )))
                        ))
                ) {
                    return Err(ControlError::OutcomeUncertain.into());
                }
                check(end)?;
                let (cutoff, outcome) = observed.map_err(ControlError::from)?;
                if cutoff
                    .is_some_and(|(utc, mono)| SystemTime::now() >= utc || Instant::now() >= mono)
                {
                    return Err(cookie_authorization(AdminCookieSessionError::Control(
                        ControlError::SessionExpired,
                    ))
                    .into());
                }
                let witness = outcome?;
                finish(witness, end)
            }
        }
    }
}
