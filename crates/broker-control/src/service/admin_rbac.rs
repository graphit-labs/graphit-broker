use super::{
    ConnectionGuard, PostgresControlStore,
    admin_broker_session::{LocalAdminProof, observe_local_session},
    admin_upstream_session::observe_upstream_roles,
    bounded_deadline, storage_error, timeout_error,
};
use crate::admin_rbac::assignment_values;
use crate::{
    AdminBrokerSessionError, AdminBrokerSessionLimits, AdminRbacError as Error, AdminRbacRequest,
    AdminRbacResult, AdminReadAuthentication, BrokerAccessError, ControlError, SystemAction,
    SystemPermission,
    admin_cookie_session::{CookieClock, decode_secret},
    admin_read::{ReadWitness, cookie_authorization},
    identity::{safe_identity_segment, valid_identity_subject},
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

pub struct PostgresAdminRbac<'s> {
    store: &'s PostgresControlStore,
    limits: AdminBrokerSessionLimits,
}
impl fmt::Debug for PostgresAdminRbac<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresAdminRbac([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn admin_rbac(
        &self,
        limits: AdminBrokerSessionLimits,
    ) -> Result<PostgresAdminRbac<'_>, ControlError> {
        limits.validate()?;
        Ok(PostgresAdminRbac {
            store: self,
            limits,
        })
    }
}
fn check(end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    Ok(())
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
// All participating administrative writers lock this parent before actor/cookie/target.
pub(super) async fn lock_admin(connection: &mut PgConnection) -> Result<(), ControlError> {
    let exists =
        sqlx_core::query::query("SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
            .fetch_optional(connection)
            .await
            .map_err(storage_error)?;
    if exists.is_none() {
        return Err(ControlError::CorruptRbac);
    }
    Ok(())
}
impl PostgresAdminRbac<'_> {
    pub async fn write<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminRbacRequest<'_>,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminRbacResult<'a>, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let witness = match authentication {
            AdminReadAuthentication::Broker { verifier, proof } => {
                gate(&LocalAdminProof::Broker(&proof), end)?;
                if !proof.owned_by(verifier) {
                    return Err(
                        AdminBrokerSessionError::from(BrokerAccessError::InvalidToken).into(),
                    );
                }
                self.local(&LocalAdminProof::Broker(&proof), &request, end)
                    .await?;
                ReadWitness::Broker(proof)
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
                self.local(&LocalAdminProof::Opaque(&proof), &request, end)
                    .await?;
                ReadWitness::Opaque(proof)
            }
            AdminReadAuthentication::Upstream { raw, verifier } => {
                let proof = verifier.verify(raw, end).await?;
                self.upstream(&proof, &request, end).await?;
                ReadWitness::Upstream(proof)
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
                        .observe_cookie(&mut tx, &hash, &clock, SystemAction::RolesWrite, end)
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
                        let applied = mutate(&mut tx, &request).await;
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
                    Ok::<_, Error>(ReadWitness::Cookie {
                        _proof: observation.proof,
                        window: observation.window,
                    })
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
        let result = AdminRbacResult {
            witness,
            original: end,
        };
        result.check()?;
        Ok(result)
    }
    async fn local(
        &self,
        proof: &LocalAdminProof<'_, '_>,
        request: &AdminRbacRequest<'_>,
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
                SystemAction::RolesWrite,
                end,
            )
            .await?;
            gate(proof, end)?;
            let applied = mutate(&mut tx, request).await;
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
        request: &AdminRbacRequest<'_>,
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
                SystemAction::RolesWrite,
                || {
                    if Instant::now() >= end {
                        return Err(ControlError::Deadline.into());
                    }
                    proof.check()
                },
            )
            .await?;
            gate()?;
            let applied = mutate(&mut tx, request).await;
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

async fn mutate(
    connection: &mut PgConnection,
    request: &AdminRbacRequest<'_>,
) -> Result<(), Error> {
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
                super::roles::role_values(name, &permissions).map_err(|_| Error::InvalidRole)?;
            super::roles::replace_role(connection, name, &actions)
                .await
                .map_err(|_| Error::InvalidRole)
        }
        AdminRbacRequest::DeleteRole { name } => {
            let name = name.trim();
            if !safe_identity_segment(name, 128) || matches!(name, "admin" | "user") {
                return Err(Error::RoleDeleteFailed);
            }
            let result = sqlx_core::query::query("DELETE FROM public.roles WHERE name=$1")
                .bind(name)
                .execute(connection)
                .await
                .map_err(|_| Error::RoleDeleteFailed)?;
            if result.rows_affected() != 1 {
                return Err(Error::RoleDeleteFailed);
            }
            Ok(())
        }
        AdminRbacRequest::Assign { subject, role } => {
            let (subject, role) = assignment_values(subject, role)?;
            let exists =
                sqlx_core::query::query("SELECT name FROM public.roles WHERE name=$1 FOR SHARE")
                    .bind(role)
                    .fetch_optional(&mut *connection)
                    .await
                    .map_err(|_| Error::AssignmentFailed)?;
            if exists.is_none() {
                return Err(Error::AssignmentFailed);
            }
            sqlx_core::query::query("INSERT INTO public.role_assignments(subject,role,created_at) VALUES($1,$2,$3) ON CONFLICT(subject,role) DO NOTHING").bind(subject).bind(role).bind(crate::flow::now_micros()?).execute(connection).await.map_err(|_| Error::AssignmentFailed)?;
            Ok(())
        }
        AdminRbacRequest::Revoke { subject, role } => {
            let (subject, role) = assignment_values(subject, role)?;
            let exists = sqlx_core::query::query(
                "SELECT 1 FROM public.role_assignments WHERE subject=$1 AND role=$2 FOR UPDATE",
            )
            .bind(subject)
            .bind(role)
            .fetch_optional(&mut *connection)
            .await
            .map_err(|_| Error::AssignmentFailed)?;
            if exists.is_none() {
                return Ok(());
            }
            if role == "admin" {
                another_admin(connection, subject).await?;
            }
            sqlx_core::query::query(
                "DELETE FROM public.role_assignments WHERE subject=$1 AND role=$2",
            )
            .bind(subject)
            .bind(role)
            .execute(connection)
            .await
            .map_err(|_| Error::AssignmentFailed)?;
            Ok(())
        }
    }
}
pub(super) async fn another_admin(
    connection: &mut PgConnection,
    target: &str,
) -> Result<(), Error> {
    let external: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM public.role_assignments WHERE role='admin' AND subject<>$1 AND left(subject,6)<>'local|')").bind(target).fetch_one(&mut *connection).await.map_err(|_| Error::AssignmentFailed)?;
    if external {
        return Ok(());
    }
    let candidate = sqlx_core::query::query("SELECT CASE WHEN octet_length(u.username)<=128 THEN u.username END,CASE WHEN octet_length(u.subject)<=512 THEN u.subject END,CASE WHEN octet_length(u.identity_kind)<=16 THEN u.identity_kind END,u.enabled::bigint,u.revision,a.subject FROM public.role_assignments a JOIN public.local_users u ON a.subject='local|'||u.subject WHERE a.role='admin' AND a.subject<>$1 AND left(a.subject,6)='local|' AND u.enabled=1 LIMIT 1 FOR SHARE OF u").bind(target).fetch_optional(connection).await.map_err(|_| Error::AssignmentFailed)?.ok_or(Error::AssignmentFailed)?;
    let text = |i| -> Result<&str, ControlError> {
        candidate
            .try_get::<Option<&str>, _>(i)
            .map_err(|_| ControlError::CorruptIdentity)?
            .ok_or(ControlError::CorruptIdentity)
    };
    let username = text(0)?;
    let subject = text(1)?;
    let kind = text(2)?;
    let enabled: i64 = candidate
        .try_get(3)
        .map_err(|_| ControlError::CorruptIdentity)?;
    let revision: i64 = candidate
        .try_get(4)
        .map_err(|_| ControlError::CorruptIdentity)?;
    let assigned: &str = candidate
        .try_get(5)
        .map_err(|_| ControlError::CorruptIdentity)?;
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
