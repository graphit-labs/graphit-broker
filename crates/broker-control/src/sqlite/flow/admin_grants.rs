//! Action-specific SQLite grant CAS; post-commit documents are DATA.
use super::admin_cookie_session::{CookieObserver, ObservedAdminCookie, cookie_hash};
use super::{
    SqliteControlStore,
    admin_local_observer::{self, LocalProof},
    admin_upstream_session, resource_grants,
};
use crate::{
    AdminBrokerSessionError as AuthError, AdminGrantError as Error, AdminGrantInput,
    AdminGrantRequest, AdminGrantResult, AdminGrantRoutes, AdminReadLimits, BrokerAccessError,
    BrokerAccessVerifier, ControlError, SystemAction, VerifiedBrokerAccess, VerifiedLocalBearer,
    admin_grants::validation::{check, normalized, validate_snapshot},
    admin_local_bearer_session::check_authentication,
    admin_read::ReadWitness,
    sqlite::executor::Work,
    upstream_oidc::VerifiedUpstreamBearer,
};
use crate::{
    AdminCookieSessionError, AdminReadAuthentication, admin_cookie_session::CookieClock,
    admin_local_bearer_session::verification_error, admin_read::cookie_authorization,
    service::admin_upstream_session::validate_profile,
};
use rusqlite::{OptionalExtension, Transaction, params};
use std::{
    fmt,
    sync::Arc,
    time::{Instant, SystemTime},
};
use zeroize::Zeroizing;

/// Borrowed SQLite writer with the actual configured public storage routes.
/// ~~~compile_fail
/// fn escape(s: &broker_control::SqliteControlStore, l: broker_control::AdminReadLimits,
///     r: std::sync::Arc<broker_control::AdminGrantRoutes>)
///     -> broker_control::SqliteAdminGrants<'static> { s.admin_grants(l,r).unwrap() }
/// ~~~
pub struct SqliteAdminGrants<'s> {
    store: &'s SqliteControlStore,
    limits: AdminReadLimits,
    routes: Arc<AdminGrantRoutes>,
}
impl fmt::Debug for SqliteAdminGrants<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteAdminGrants([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn admin_grants(
        &self,
        limits: AdminReadLimits,
        routes: Arc<AdminGrantRoutes>,
    ) -> Result<SqliteAdminGrants<'_>, ControlError> {
        limits.validate()?;
        Ok(SqliteAdminGrants {
            store: self,
            limits,
            routes,
        })
    }
}

// Capture raw DATA exactly once. Normalization stays after current Auth and CAS.
enum OwnedMutation {
    Create(AdminGrantInput),
    Update { id: String, grant: AdminGrantInput },
    Delete { id: String },
}
impl OwnedMutation {
    fn capture(request: AdminGrantRequest<'_>) -> Self {
        fn copy(input: &AdminGrantInput) -> AdminGrantInput {
            AdminGrantInput {
                id: input.id.clone(),
                name: input.name.clone(),
                access: input.access.clone(),
                principal: input.principal.clone(),
                capabilities: input.capabilities.clone(),
                projects: input.projects.clone(),
                s3_operations: input.s3_operations.clone(),
                s3_prefixes: input.s3_prefixes.clone(),
                s3_route: input.s3_route.clone(),
            }
        }
        match request {
            AdminGrantRequest::Create(input) => Self::Create(copy(input)),
            AdminGrantRequest::Update { id, grant } => Self::Update {
                id: id.to_owned(),
                grant: copy(grant),
            },
            AdminGrantRequest::Delete { id } => Self::Delete { id: id.to_owned() },
        }
    }
    fn borrow(&self) -> AdminGrantRequest<'_> {
        match self {
            Self::Create(input) => AdminGrantRequest::Create(input),
            Self::Update { id, grant } => AdminGrantRequest::Update { id, grant },
            Self::Delete { id } => AdminGrantRequest::Delete { id },
        }
    }
}
fn mutation_sql(work: &Work, error: rusqlite::Error) -> Error {
    let error = ControlError::from(work.sql(error));
    match error {
        ControlError::Deadline | ControlError::Closed | ControlError::OutcomeUncertain => {
            error.into()
        }
        _ => Error::WriteFailed,
    }
}
fn parent(tx: &Transaction<'_>, work: &Work) -> Result<(), Error> {
    let admin = tx
        .query_row("SELECT name FROM roles WHERE name='admin'", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(|e| ControlError::from(work.sql(e)))?;
    work.check().map_err(ControlError::from)?;
    if admin.is_none() {
        return Err(ControlError::CorruptRbac.into());
    }
    Ok(())
}
fn mutate(
    tx: &Transaction<'_>,
    work: &Work,
    request: AdminGrantRequest<'_>,
    expected: u64,
    limits: AdminReadLimits,
    routes: &AdminGrantRoutes,
    end: Instant,
) -> Result<(), Error> {
    check(end)?;
    work.check().map_err(ControlError::from)?;
    if expected == 0 {
        return Err(Error::PreconditionRequired);
    }
    let revision = tx
        .query_row(
            "SELECT revision FROM resource_acl_state WHERE id=1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|e| mutation_sql(work, e))?
        .ok_or(Error::WriteFailed)?;
    if revision <= 0 {
        return Err(Error::WriteFailed);
    }
    if u64::try_from(revision).ok() != Some(expected) {
        return Err(Error::RevisionConflict);
    }
    let next = revision.checked_add(1).ok_or(Error::WriteFailed)?;
    let now = crate::flow::now_micros()?;
    match request {
        AdminGrantRequest::Create(input) | AdminGrantRequest::Update { grant: input, .. } => {
            let id = match request {
                AdminGrantRequest::Update { id, .. } => id,
                _ => &input.id,
            };
            let grant = normalized(input, id)?;
            let query = if matches!(request, AdminGrantRequest::Create(_)) {
                "INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at)VALUES(?1,?2,?3,?4,?5,?6,?6)"
            } else {
                "UPDATE resource_grants SET name=?2,access_kind=?3,principal=?4,s3_route=?5,updated_at=?6 WHERE id=?1"
            };
            let changed = tx
                .execute(
                    query,
                    params![
                        grant.id,
                        grant.name,
                        grant.access,
                        grant.principal,
                        grant.s3_route,
                        now
                    ],
                )
                .map_err(|e| mutation_sql(work, e))?;
            if changed != 1 {
                return Err(Error::WriteFailed);
            }
            for (delete, insert, values) in [
                (
                    "DELETE FROM grant_capabilities WHERE grant_id=?1",
                    "INSERT INTO grant_capabilities(grant_id,value)VALUES(?1,?2)",
                    &grant.capabilities,
                ),
                (
                    "DELETE FROM grant_projects WHERE grant_id=?1",
                    "INSERT INTO grant_projects(grant_id,value)VALUES(?1,?2)",
                    &grant.projects,
                ),
                (
                    "DELETE FROM grant_s3_operations WHERE grant_id=?1",
                    "INSERT INTO grant_s3_operations(grant_id,value)VALUES(?1,?2)",
                    &grant.s3_operations,
                ),
                (
                    "DELETE FROM grant_s3_prefixes WHERE grant_id=?1",
                    "INSERT INTO grant_s3_prefixes(grant_id,value)VALUES(?1,?2)",
                    &grant.s3_prefixes,
                ),
            ] {
                check(end)?;
                work.check().map_err(ControlError::from)?;
                tx.execute(delete, [&grant.id])
                    .map_err(|e| mutation_sql(work, e))?;
                let mut statement = tx.prepare(insert).map_err(|e| mutation_sql(work, e))?;
                for value in values {
                    check(end)?;
                    work.check().map_err(ControlError::from)?;
                    statement
                        .execute(params![grant.id, value])
                        .map_err(|e| mutation_sql(work, e))?;
                }
            }
        }
        AdminGrantRequest::Delete { id } => {
            let id = id.trim();
            if !crate::identity::safe_identity_segment(id, 128) {
                return Err(Error::InvalidGrant);
            }
            if tx
                .execute("DELETE FROM resource_grants WHERE id=?1", [id])
                .map_err(|e| mutation_sql(work, e))?
                != 1
            {
                return Err(Error::WriteFailed);
            }
        }
    }
    if tx
        .execute(
            "UPDATE resource_acl_state SET revision=?1,updated_at=?2 WHERE id=1 AND revision=?3",
            params![next, now, revision],
        )
        .map_err(|e| mutation_sql(work, e))?
        != 1
    {
        return Err(Error::RevisionConflict);
    }
    let cap =
        i64::try_from(limits.grants_json_bytes.get()).map_err(|_| ControlError::Configuration)?;
    let snapshot = resource_grants::observe_snapshot(tx, work, cap)?;
    validate_snapshot(&snapshot, routes, end)?;
    work.check().map_err(ControlError::from)?;
    Ok(())
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
impl SqliteAdminGrants<'_> {
    async fn finish<'a>(
        &self,
        witness: ReadWitness<'a>,
        factor_expiry: Instant,
        end: Instant,
    ) -> Result<AdminGrantResult<'a>, Error> {
        witness.check()?;
        check(end)?;
        let snapshot = self
            .store
            .resource_grants(self.limits.grants_json_bytes)?
            .read(end.min(factor_expiry))
            .await;
        if matches!(
            &snapshot,
            Err(crate::ResourceGrantReadError::Control(
                ControlError::OutcomeUncertain
            ))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        witness.check()?;
        check(end)?;
        let snapshot = snapshot?;
        let payload = crate::admin_read::projection::grants_payload(
            &snapshot,
            self.limits.response_json_bytes.get(),
            end,
        );
        witness.check()?;
        check(end)?;
        let payload = payload?;
        let result = AdminGrantResult {
            revision: snapshot.revision(),
            body: payload.body,
            witness,
            original: end,
        };
        result.check()?;
        Ok(result)
    }
    async fn broker<'a>(
        &self,
        verifier: &'a BrokerAccessVerifier,
        proof: VerifiedBrokerAccess<'a>,
        request: OwnedMutation,
        expected: u64,
        end: Instant,
    ) -> Result<AdminGrantResult<'a>, Error> {
        proof.check().map_err(AuthError::from)?;
        if !proof.owned_by(verifier) {
            return Err(AuthError::from(BrokerAccessError::InvalidToken).into());
        }
        let username = proof
            .username()
            .filter(|u| {
                crate::identity::safe_identity_segment(
                    u,
                    self.limits.authorization.identity.username_bytes.get(),
                )
            })
            .ok_or(AuthError::Forbidden)?
            .to_owned();
        let subject = proof.subject().to_owned();
        let expiry = proof.authentication_expiry();
        let limits = self.limits;
        let routes = self.routes.clone();
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
                        limits.authorization,
                        SystemAction::GrantsWrite,
                        end,
                    )?;
                    authentication_gate(work, end, expiry)?;
                    let applied = mutate(
                        &tx,
                        work,
                        request.borrow(),
                        expected,
                        limits,
                        &routes,
                        end.min(expiry.1),
                    );
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
        self.finish(ReadWitness::Broker(proof), expiry.1, end).await
    }
    async fn opaque(
        &self,
        proof: VerifiedLocalBearer,
        request: OwnedMutation,
        expected: u64,
        end: Instant,
    ) -> Result<AdminGrantResult<'static>, Error> {
        let expiry = proof.authentication_expiry();
        let limits = self.limits;
        let routes = self.routes.clone();
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
                        limits.authorization,
                        SystemAction::GrantsWrite,
                        end,
                    )?;
                    authentication_gate(work, end, expiry)?;
                    check_authentication(&proof)?;
                    let applied = mutate(
                        &tx,
                        work,
                        request.borrow(),
                        expected,
                        limits,
                        &routes,
                        end.min(expiry.1),
                    );
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
        self.finish(ReadWitness::Opaque(proof), expiry.1, end).await
    }
    async fn upstream(
        &self,
        proof: VerifiedUpstreamBearer,
        request: OwnedMutation,
        expected: u64,
        end: Instant,
    ) -> Result<AdminGrantResult<'static>, Error> {
        let expiry = proof.expires_mono();
        let limits = self.limits;
        let routes = self.routes.clone();
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
                        limits.authorization,
                        SystemAction::GrantsWrite,
                        || {
                            if Instant::now() >= end {
                                return Err(ControlError::Deadline.into());
                            }
                            proof.check()
                        },
                    )?;
                    let applied = mutate(
                        &tx,
                        work,
                        request.borrow(),
                        expected,
                        limits,
                        &routes,
                        end.min(expiry),
                    );
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
        self.finish(ReadWitness::Upstream(proof), expiry, end).await
    }
}

impl SqliteAdminGrants<'_> {
    pub async fn write<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminGrantRequest<'_>,
        expected_revision: u64,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminGrantResult<'a>, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let request = OwnedMutation::capture(request);
        match authentication {
            AdminReadAuthentication::Broker { verifier, proof } => {
                self.broker(verifier, proof, request, expected_revision, end)
                    .await
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
                self.opaque(proof, request, expected_revision, end).await
            }
            AdminReadAuthentication::Upstream { raw, verifier } => {
                let proof = verifier.verify(raw, end).await?;
                validate_profile(&proof, self.limits.authorization, end)?;
                self.upstream(proof, request, expected_revision, end).await
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
                    .admin_cookie_sessions(limits, policy, upstream.clone())?;
                let hash = cookie_hash(self.store, raw).map_err(cookie_authorization)?;
                let clock = CookieClock::capture();
                // Noncanonical sizes are represented as absent, with no error before current Auth.
                let supplied = csrf
                    .filter(|value| value.len() == 43)
                    .map(|value| Zeroizing::new(value.to_owned()));
                let read_limits = self.limits;
                let routes = self.routes.clone();
                let observed = self
                    .store
                    .executor
                    .execute(end, move |owner, work| {
                        let mut cutoff = None;
                        let outcome = (|| -> Result<(ReadWitness<'static>, Instant), Error> {
                            work.check().map_err(ControlError::from)?;
                            check(end)?;
                            let tx = owner.begin(work).map_err(ControlError::from)?;
                            parent(&tx, work)?;
                            let observation = match CookieObserver::new(
                                limits,
                                upstream.as_deref(),
                                SystemAction::GrantsWrite,
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
                            let applied = mutate(
                                &tx,
                                work,
                                request.borrow(),
                                expected_revision,
                                read_limits,
                                &routes,
                                wait,
                            );
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
                            let expiry = observation.window().expiry().1;
                            Ok((observation.into_witness(), expiry))
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
                let (witness, expiry) = outcome?;
                self.finish(witness, expiry, end).await
            }
        }
    }
}
