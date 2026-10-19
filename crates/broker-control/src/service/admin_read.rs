use super::admin_broker_session::{LocalAdminProof, observe_local_session};
use super::admin_upstream_session::observe_upstream_roles;
use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    AdminBrokerSessionError, AdminReadAuthentication, AdminReadError as Error, AdminReadKind,
    AdminReadLimits, AdminReadRequest, AdminReadResult, BrokerAccessError, ControlError,
    ResourceGrantReadError, SessionPrincipal, SessionProfile,
    admin_read::{
        ReadWitness,
        projection::{self as payload, check, encode},
    },
    identity::safe_identity_segment,
    upstream_oidc::VerifiedUpstreamBearer,
};
use sqlx_core::{connection::Connection, row::Row};
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

pub struct PostgresAdminReads<'s> {
    store: &'s PostgresControlStore,
    limits: AdminReadLimits,
}
impl fmt::Debug for PostgresAdminReads<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresAdminReads([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn admin_reads(
        &self,
        limits: AdminReadLimits,
    ) -> Result<PostgresAdminReads<'_>, ControlError> {
        limits.validate()?;
        Ok(PostgresAdminReads {
            store: self,
            limits,
        })
    }
}
pub(super) use crate::admin_read::projection::{Payload, grants_payload};
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
fn projection_error(kind: AdminReadKind, error: ControlError) -> Error {
    match error {
        ControlError::Deadline | ControlError::Closed | ControlError::OutcomeUncertain => {
            error.into()
        }
        _ => Error::Projection(kind),
    }
}
impl PostgresAdminReads<'_> {
    pub async fn read<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminReadRequest<'_>,
        original: Instant,
    ) -> Result<AdminReadResult<'a>, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        let (witness, payload) = match authentication {
            AdminReadAuthentication::Broker { verifier, proof } => {
                gate(&LocalAdminProof::Broker(&proof), end)?;
                if !proof.owned_by(verifier) {
                    return Err(
                        AdminBrokerSessionError::from(BrokerAccessError::InvalidToken).into(),
                    );
                }
                let payload = self
                    .local(&LocalAdminProof::Broker(&proof), &request, end)
                    .await?;
                (ReadWitness::Broker(proof), payload)
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
                let payload = self
                    .local(&LocalAdminProof::Opaque(&proof), &request, end)
                    .await?;
                (ReadWitness::Opaque(proof), payload)
            }
            AdminReadAuthentication::Upstream { raw, verifier } => {
                let proof = verifier.verify(raw, end).await?;
                let payload = self.upstream(&proof, &request, end).await?;
                (ReadWitness::Upstream(proof), payload)
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
                return self
                    .store
                    .admin_cookie_sessions(limits, policy, upstream.as_deref())?
                    .read_admin(raw, request, self.limits, end)
                    .await;
            }
        };
        let result = AdminReadResult {
            witness,
            original: end,
            body: payload.body,
            revision: payload.revision,
        };
        result.check()?;
        Ok(result)
    }
    async fn local(
        &self,
        proof: &LocalAdminProof<'_, '_>,
        request: &AdminReadRequest<'_>,
        end: Instant,
    ) -> Result<Payload, Error> {
        gate(proof, end)?;
        let wait = end.min(proof.authentication_expiry().1);
        let commit_started = AtomicBool::new(false);
        let outcome = tokio::time::timeout_at(wait.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
                .await
                .map_err(storage_error)?;
            let (profile, principal, _, _) = observe_local_session(
                &mut tx,
                self.store,
                proof,
                self.limits.authorization,
                request.kind().action(),
                end,
            )
            .await?;
            gate(proof, end)?;
            let payload =
                projection(&mut tx, request, self.limits, &profile, &principal, wait).await?;
            gate(proof, end)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok::<_, Error>(payload)
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
        request: &AdminReadRequest<'_>,
        end: Instant,
    ) -> Result<Payload, Error> {
        let gate = || {
            check(end)?;
            proof.check()?;
            Ok::<_, Error>(())
        };
        gate()?;
        // The protected profile comes from the common issuer, never an input DTO.
        let profile = proof.profile();
        let principal = SessionPrincipal {
            issuer: proof.issuer().to_owned(),
            username: proof.username().to_owned(),
            organization: proof.organization().to_owned(),
            teams: proof.teams().to_vec(),
            local_user_revision: 0,
        };
        let limits = self.limits.authorization;
        if profile.subject.len() > limits.identity.subject_bytes.get()
            || principal.username.len() > limits.identity.username_bytes.get()
            || proof.claim_roles().is_some_and(|roles| {
                roles.len() > limits.identity.roles.get()
                    || roles
                        .iter()
                        .any(|r| !safe_identity_segment(r, limits.identity.role_bytes.get()))
            })
        {
            gate()?;
            return Err(AdminBrokerSessionError::from(BrokerAccessError::InvalidToken).into());
        }
        let profile_projection = encode(
            &serde_json::json!({"subject":profile.subject,"issuer":principal.issuer,"username":principal.username,"name":profile.name,"email":profile.email,"organization":principal.organization,"teams":principal.teams}),
            limits.profile_json_bytes.get(),
            request.kind(),
        );
        gate()?;
        profile_projection
            .map_err(|_| Error::Authorization(ControlError::IdentityLimitExceeded.into()))?;
        let subject = format!("{}|{}", principal.issuer, profile.subject);
        let wait = end.min(proof.expires_mono());
        let commit_started = AtomicBool::new(false);
        let outcome = tokio::time::timeout_at(wait.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.store.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
                .await
                .map_err(storage_error)?;
            observe_upstream_roles(
                &mut tx,
                &subject,
                proof.claim_roles(),
                limits,
                request.kind().action(),
                || {
                    if Instant::now() >= end {
                        return Err(ControlError::Deadline.into());
                    }
                    proof.check()
                },
            )
            .await?;
            gate()?;
            let payload =
                projection(&mut tx, request, self.limits, profile, &principal, wait).await?;
            gate()?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok::<_, Error>(payload)
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

async fn limited_json(
    connection: &mut sqlx_postgres::PgConnection,
    select: &'static str,
    limit: usize,
    kind: AdminReadKind,
) -> Result<String, Error> {
    let row = sqlx_core::query::query(select)
        .bind(limit as i64)
        .fetch_one(connection)
        .await
        .map_err(|e| projection_error(kind, storage_error(e)))?;
    let size: i64 = row.try_get(0).map_err(|_| Error::Projection(kind))?;
    if size < 0 || size as u64 > limit as u64 {
        return Err(Error::Projection(kind));
    }
    row.try_get::<Option<String>, _>(1)
        .map_err(|_| Error::Projection(kind))?
        .ok_or(Error::Projection(kind))
}
const ROLES: &str = r#"WITH data AS MATERIALIZED (SELECT COALESCE(json_agg(json_build_object('name',r.name,'permissions',COALESCE((SELECT json_agg(p.action ORDER BY p.action COLLATE "C") FROM public.role_permissions p WHERE p.role=r.name),'[]'::json)) ORDER BY r.name COLLATE "C")::text,'[]') payload FROM public.roles r) SELECT octet_length(payload)::bigint,CASE WHEN octet_length(payload)::bigint<=$1 THEN payload END FROM data"#;
const ASSIGNMENTS: &str = r#"WITH data AS MATERIALIZED (SELECT COALESCE(json_agg(json_build_object('subject',subject,'role',role,'created_at',created_at) ORDER BY subject COLLATE "C",role COLLATE "C")::text,'[]') payload FROM public.role_assignments) SELECT octet_length(payload)::bigint,CASE WHEN octet_length(payload)::bigint<=$1 THEN payload END FROM data"#;
const USERS: &str = r#"WITH data AS MATERIALIZED (SELECT COALESCE(json_agg(json_build_object('username',u.username,'subject',u.subject,'kind',u.identity_kind,'name',u.name,'email',u.email,'organization',u.organization,'teams',u.teams_json::json,'enabled',u.enabled,'password_change_required',u.password_change_required,'mfa_enabled',EXISTS(SELECT 1 FROM public.local_mfa m WHERE m.subject=u.subject),'revision',u.revision,'created_at',u.created_at,'updated_at',u.updated_at,'roles',(SELECT json_agg(a.role ORDER BY a.role COLLATE "C") FROM (SELECT role FROM public.role_assignments WHERE subject='local|'||u.subject UNION SELECT 'user') a)) ORDER BY u.username COLLATE "C")::text,'[]') payload FROM public.local_users u) SELECT octet_length(payload)::bigint,CASE WHEN octet_length(payload)::bigint<=$1 THEN payload END FROM data"#;

pub(super) async fn projection(
    connection: &mut sqlx_postgres::PgConnection,
    request: &AdminReadRequest<'_>,
    limits: AdminReadLimits,
    profile: &SessionProfile,
    principal: &SessionPrincipal,
    end: Instant,
) -> Result<Payload, Error> {
    let kind = request.kind();
    check(end)?;
    let bytes = limits.response_json_bytes.get();
    match request {
        AdminReadRequest::Configuration { yaml } => {
            payload::configuration_payload(yaml, bytes, end)
        }
        AdminReadRequest::Projects { .. } | AdminReadRequest::Grants => {
            let snapshot = super::resource_grants::observe_snapshot(
                connection,
                limits.grants_json_bytes.get() as i64,
            )
            .await
            .map_err(|e| match e {
                ResourceGrantReadError::Control(e) => projection_error(kind, e),
                _ => Error::Projection(kind),
            })?;
            check(end)?;
            match request {
                AdminReadRequest::Projects { provider_command } => payload::projects_payload(
                    &snapshot,
                    provider_command,
                    profile,
                    principal,
                    bytes,
                    end,
                ),
                _ => grants_payload(&snapshot, bytes, end),
            }
        }
        AdminReadRequest::Roles
        | AdminReadRequest::Assignments
        | AdminReadRequest::Users
        | AdminReadRequest::Principals => {
            let select = match request {
                AdminReadRequest::Roles => ROLES,
                AdminReadRequest::Assignments => ASSIGNMENTS,
                _ => USERS,
            };
            let json = limited_json(connection, select, bytes, kind).await?;
            payload::rows_payload(&json, kind, bytes, end)
        }
    }
}
