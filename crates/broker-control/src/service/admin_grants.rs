use super::{
    ConnectionGuard, PostgresControlStore,
    admin_broker_session::{LocalAdminProof, observe_local_session},
    admin_upstream_session::observe_upstream_roles,
    bounded_deadline, storage_error, timeout_error,
};
use crate::admin_grants::validation::{check, normalized, validate_snapshot};
use crate::{
    AdminBrokerSessionError, AdminBrokerSessionLimits, AdminGrantError as Error, AdminGrantRequest,
    AdminGrantResult, AdminReadAuthentication, BrokerAccessError, ControlError, SystemAction,
    admin_cookie_session::{CookieClock, decode_secret},
    admin_read::{ReadWitness, cookie_authorization},
    upstream_oidc::VerifiedUpstreamBearer,
};
use sqlx_core::{connection::Connection, row::Row};
use sqlx_postgres::PgConnection;
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use subtle::ConstantTimeEq;

pub struct PostgresAdminGrants<'s> {
    store: &'s PostgresControlStore,
    limits: AdminBrokerSessionLimits,
    read_limits: crate::AdminReadLimits,
    routes: &'s crate::AdminGrantRoutes,
}
impl fmt::Debug for PostgresAdminGrants<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresAdminGrants([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn admin_grants<'s>(
        &'s self,
        limits: crate::AdminReadLimits,
        routes: &'s crate::AdminGrantRoutes,
    ) -> Result<PostgresAdminGrants<'s>, ControlError> {
        limits.validate()?;
        Ok(PostgresAdminGrants {
            store: self,
            limits: limits.authorization,
            read_limits: limits,
            routes,
        })
    }
}
fn gate(proof: &LocalAdminProof<'_, '_>, end: Instant) -> Result<(), Error> {
    check(end)?;
    proof.check()?;
    Ok(())
}
fn uncertain<T>(result: &Result<T, Error>) -> bool {
    matches!(
        result,
        Err(Error::Authorization(AdminBrokerSessionError::Control(
            ControlError::OutcomeUncertain
        )))
    )
}
use super::admin_rbac::lock_admin;
impl PostgresAdminGrants<'_> {
    pub async fn write<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminGrantRequest<'_>,
        expected_revision: u64,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminGrantResult<'a>, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let (witness, factor_expiry) = match authentication {
            AdminReadAuthentication::Broker { verifier, proof } => {
                gate(&LocalAdminProof::Broker(&proof), end)?;
                if !proof.owned_by(verifier) {
                    return Err(
                        AdminBrokerSessionError::from(BrokerAccessError::InvalidToken).into(),
                    );
                }
                self.local(
                    &LocalAdminProof::Broker(&proof),
                    &request,
                    expected_revision,
                    end,
                )
                .await?;
                let expiry = LocalAdminProof::Broker(&proof).authentication_expiry().1;
                (ReadWitness::Broker(proof), expiry)
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
                    .map_err(crate::admin_local_bearer_session::verification_error)?
                    .verify(raw, required_scopes, end)
                    .await
                    .map_err(crate::admin_local_bearer_session::verification_error)?;
                self.local(
                    &LocalAdminProof::Opaque(&proof),
                    &request,
                    expected_revision,
                    end,
                )
                .await?;
                let expiry = LocalAdminProof::Opaque(&proof).authentication_expiry().1;
                (ReadWitness::Opaque(proof), expiry)
            }
            AdminReadAuthentication::Upstream { raw, verifier } => {
                let proof = verifier.verify(raw, end).await?;
                self.upstream(&proof, &request, expected_revision, end)
                    .await?;
                let expiry = proof.expires_mono();
                (ReadWitness::Upstream(proof), expiry)
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
                let sessions =
                    self.store
                        .admin_cookie_sessions(limits, policy, upstream.as_deref())?;
                let clock = CookieClock::capture();
                let hash = sessions.hash(raw).map_err(cookie_authorization)?;
                let commit_started = AtomicBool::new(false);
                let outcome = tokio::time::timeout_at(end.into(), async {
                    let mut guard = ConnectionGuard(Some(
                        self.store.pool.acquire().await.map_err(storage_error)?,
                    ));
                    let mut tx = guard
                        .connection()?
                        .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                        .await
                        .map_err(storage_error)?;
                    lock_admin(&mut tx).await?;
                    let observation = sessions
                        .observe_cookie(&mut tx, &hash, &clock, SystemAction::GrantsWrite, end)
                        .await
                        .map_err(cookie_authorization)?;
                    let gate = || -> Result<(), Error> {
                        check(end)?;
                        observation.window.check()?;
                        Ok(())
                    };
                    gate()?;
                    let csrf_valid = (|| {
                        let stored = decode_secret(&observation.csrf)
                            .map_err(|_| ControlError::CorruptSession)?;
                        let supplied = decode_secret(csrf.ok_or(Error::CsrfFailed)?)
                            .map_err(|_| Error::CsrfFailed)?;
                        if !bool::from(stored.as_ref().ct_eq(supplied.as_ref())) {
                            return Err(Error::CsrfFailed);
                        }
                        Ok::<_, Error>(())
                    })();
                    gate()?;
                    csrf_valid?;
                    let wait = end.min(observation.window.expiry().1);
                    let applied = tokio::time::timeout_at(wait.into(), async {
                        let applied = self.mutate(&mut tx, &request, expected_revision, end).await;
                        gate()?;
                        applied?;
                        commit_started.store(true, Ordering::Relaxed);
                        tx.commit()
                            .await
                            .map_err(|_| ControlError::OutcomeUncertain)?;
                        Ok::<_, Error>(())
                    })
                    .await
                    .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
                    if uncertain(&applied) {
                        return Err(ControlError::OutcomeUncertain.into());
                    }
                    if applied.is_ok() {
                        guard.confirmed();
                    }
                    gate()?;
                    applied?;
                    let expiry = observation.window.expiry().1;
                    Ok::<_, Error>((
                        ReadWitness::Cookie {
                            _proof: observation.proof,
                            window: observation.window,
                        },
                        expiry,
                    ))
                })
                .await
                .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
                if uncertain(&outcome) {
                    return Err(ControlError::OutcomeUncertain.into());
                }
                check(end)?;
                outcome?
            }
        };
        witness.check()?;
        check(end)?;
        let snapshot = self
            .store
            .resource_grants(self.read_limits.grants_json_bytes)?
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
        let payload = super::admin_read::grants_payload(
            &snapshot,
            self.read_limits.response_json_bytes.get(),
            end,
        )?;
        let result = AdminGrantResult {
            revision: snapshot.revision(),
            body: payload.body,
            witness,
            original: end,
        };
        result.check()?;
        Ok(result)
    }
    async fn local(
        &self,
        proof: &LocalAdminProof<'_, '_>,
        request: &AdminGrantRequest<'_>,
        expected_revision: u64,
        end: Instant,
    ) -> Result<(), Error> {
        gate(proof, end)?;
        let wait = end.min(proof.authentication_expiry().1);
        let commit_started = AtomicBool::new(false);
        let outcome = tokio::time::timeout_at(wait.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            lock_admin(&mut tx).await?;
            let username = proof.username(self.limits)?;
            sqlx_core::query::query(
                "SELECT username FROM public.local_users WHERE username=$1 FOR SHARE",
            )
            .bind(&username)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage_error)?;
            observe_local_session(
                &mut tx,
                self.store,
                proof,
                self.limits,
                SystemAction::GrantsWrite,
                end,
            )
            .await?;
            gate(proof, end)?;
            let applied = self.mutate(&mut tx, request, expected_revision, end).await;
            gate(proof, end)?;
            applied?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok::<_, Error>(())
        })
        .await
        .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
        if uncertain(&outcome) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        gate(proof, end)?;
        outcome
    }
    async fn upstream(
        &self,
        proof: &VerifiedUpstreamBearer,
        request: &AdminGrantRequest<'_>,
        expected_revision: u64,
        end: Instant,
    ) -> Result<(), Error> {
        let gate = || -> Result<(), Error> {
            check(end)?;
            proof.check()?;
            Ok(())
        };
        gate()?;
        super::admin_upstream_session::validate_profile(proof, self.limits, end)?;
        let subject = format!("{}|{}", proof.issuer(), proof.profile().subject);
        let wait = end.min(proof.expires_mono());
        let commit_started = AtomicBool::new(false);
        let outcome = tokio::time::timeout_at(wait.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            lock_admin(&mut tx).await?;
            observe_upstream_roles(
                &mut tx,
                &subject,
                proof.claim_roles(),
                self.limits,
                SystemAction::GrantsWrite,
                || {
                    if Instant::now() >= end {
                        return Err(ControlError::Deadline.into());
                    }
                    proof.check()
                },
            )
            .await?;
            gate()?;
            let applied = self.mutate(&mut tx, request, expected_revision, end).await;
            gate()?;
            applied?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok::<_, Error>(())
        })
        .await
        .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()));
        if uncertain(&outcome) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        gate()?;
        outcome
    }
}

impl PostgresAdminGrants<'_> {
    async fn mutate(
        &self,
        connection: &mut PgConnection,
        request: &AdminGrantRequest<'_>,
        expected: u64,
        end: Instant,
    ) -> Result<(), Error> {
        if expected == 0 {
            return Err(Error::PreconditionRequired);
        }
        let row = sqlx_core::query::query(
            "SELECT revision FROM public.resource_acl_state WHERE id=1 FOR UPDATE",
        )
        .fetch_optional(&mut *connection)
        .await
        .map_err(storage_error)?
        .ok_or(Error::WriteFailed)?;
        let revision: i64 = row.try_get("revision").map_err(|_| Error::WriteFailed)?;
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
                    AdminGrantRequest::Update { id, .. } => *id,
                    _ => &input.id,
                };
                let grant = normalized(input, id)?;
                let query = if matches!(request, AdminGrantRequest::Create(_)) {
                    "INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$6)"
                } else {
                    "UPDATE public.resource_grants SET name=$2,access_kind=$3,principal=$4,s3_route=$5,updated_at=$6 WHERE id=$1"
                };
                let affected = sqlx_core::query::query(query)
                    .bind(&grant.id)
                    .bind(&grant.name)
                    .bind(&grant.access)
                    .bind(&grant.principal)
                    .bind(&grant.s3_route)
                    .bind(now)
                    .execute(&mut *connection)
                    .await
                    .map_err(|_| Error::WriteFailed)?;
                if affected.rows_affected() != 1 {
                    return Err(Error::WriteFailed);
                }
                for (delete, insert, values) in [
                    (
                        "DELETE FROM public.grant_capabilities WHERE grant_id=$1",
                        "INSERT INTO public.grant_capabilities(grant_id,value) SELECT $1,value FROM unnest($2::text[]) AS child(value)",
                        &grant.capabilities,
                    ),
                    (
                        "DELETE FROM public.grant_projects WHERE grant_id=$1",
                        "INSERT INTO public.grant_projects(grant_id,value) SELECT $1,value FROM unnest($2::text[]) AS child(value)",
                        &grant.projects,
                    ),
                    (
                        "DELETE FROM public.grant_s3_operations WHERE grant_id=$1",
                        "INSERT INTO public.grant_s3_operations(grant_id,value) SELECT $1,value FROM unnest($2::text[]) AS child(value)",
                        &grant.s3_operations,
                    ),
                    (
                        "DELETE FROM public.grant_s3_prefixes WHERE grant_id=$1",
                        "INSERT INTO public.grant_s3_prefixes(grant_id,value) SELECT $1,value FROM unnest($2::text[]) AS child(value)",
                        &grant.s3_prefixes,
                    ),
                ] {
                    check(end)?;
                    sqlx_core::query::query(delete)
                        .bind(&grant.id)
                        .execute(&mut *connection)
                        .await
                        .map_err(|_| Error::WriteFailed)?;
                    sqlx_core::query::query(insert)
                        .bind(&grant.id)
                        .bind(values.as_slice())
                        .execute(&mut *connection)
                        .await
                        .map_err(|_| Error::WriteFailed)?;
                }
            }
            AdminGrantRequest::Delete { id } => {
                let id = id.trim();
                if !crate::identity::safe_identity_segment(id, 128) {
                    return Err(Error::InvalidGrant);
                }
                let affected =
                    sqlx_core::query::query("DELETE FROM public.resource_grants WHERE id=$1")
                        .bind(id)
                        .execute(&mut *connection)
                        .await
                        .map_err(|_| Error::WriteFailed)?;
                if affected.rows_affected() != 1 {
                    return Err(Error::WriteFailed);
                }
            }
        }
        let updated = sqlx_core::query::query(
            "UPDATE public.resource_acl_state SET revision=$1,updated_at=$2 WHERE id=1",
        )
        .bind(next)
        .bind(now)
        .execute(&mut *connection)
        .await
        .map_err(|_| Error::WriteFailed)?;
        if updated.rows_affected() != 1 {
            return Err(Error::WriteFailed);
        }
        let snapshot = super::resource_grants::observe_snapshot(
            connection,
            self.read_limits.grants_json_bytes.get() as i64,
        )
        .await?;
        validate_snapshot(&snapshot, self.routes, end)
    }
}
