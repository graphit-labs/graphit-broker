mod full;
pub use full::SqliteAdminReads;
mod rows;
#[cfg(test)]
mod tests;

use super::{
    SqliteControlStore,
    admin_local_observer::{self, LocalProof},
};
use crate::{
    AdminBrokerSessionError, AdminCookieSessionLimits, AdminCookieSessionPolicy,
    AdminReadError as Error, AdminReadKind, AdminReadLimits, AdminReadRequest, AdminReadResult,
    BrokerAccessError, ControlError, SessionPrincipal, SessionProfile, VerifiedLocalBearer,
    admin_local_bearer_session::{check_authentication, verification_error},
    admin_read::{
        ReadWitness,
        projection::{self as payload, Payload},
    },
    sqlite::executor::Work,
};
use rusqlite::Transaction;
use std::{
    fmt,
    num::NonZeroUsize,
    time::{Instant, SystemTime},
};

/// LOCAL administrative reads borrow the physical store and authorize each action.
/// A returned body is data from that read, never permission for a subsequent read.
/// ```compile_fail
/// fn escape(s: &broker_control::SqliteControlStore, l: broker_control::AdminReadLimits)
///     -> broker_control::SqliteLocalAdminReads<'static> { s.local_admin_reads(l).unwrap() }
/// ```
pub struct SqliteLocalAdminReads<'s> {
    store: &'s SqliteControlStore,
    limits: AdminReadLimits,
}
impl fmt::Debug for SqliteLocalAdminReads<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalAdminReads([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn local_admin_reads(
        &self,
        limits: AdminReadLimits,
    ) -> Result<SqliteLocalAdminReads<'_>, ControlError> {
        limits.validate()?;
        Ok(SqliteLocalAdminReads {
            store: self,
            limits,
        })
    }
}

// The worker owns only bounded request data. It receives the actual factor
// separately, so neither a request nor a projection can manufacture authority.
pub(super) enum OwnedRequest {
    Projects(String),
    Roles,
    Assignments,
    Users,
    Principals,
    Grants,
    Configuration(String),
}
impl OwnedRequest {
    pub(super) fn capture(
        request: AdminReadRequest<'_>,
        limits: AdminReadLimits,
    ) -> Result<Self, Error> {
        let copy = |value: &str, kind| {
            if value.len() > limits.response_json_bytes.get() {
                return Err(Error::Projection(kind));
            }
            Ok(value.to_owned())
        };
        Ok(match request {
            AdminReadRequest::Projects { provider_command } => {
                Self::Projects(copy(provider_command, AdminReadKind::Projects)?)
            }
            AdminReadRequest::Roles => Self::Roles,
            AdminReadRequest::Assignments => Self::Assignments,
            AdminReadRequest::Users => Self::Users,
            AdminReadRequest::Principals => Self::Principals,
            AdminReadRequest::Grants => Self::Grants,
            AdminReadRequest::Configuration { yaml } => {
                Self::Configuration(copy(yaml, AdminReadKind::Configuration)?)
            }
        })
    }
    pub(super) fn borrow(&self) -> AdminReadRequest<'_> {
        match self {
            Self::Projects(provider_command) => AdminReadRequest::Projects { provider_command },
            Self::Roles => AdminReadRequest::Roles,
            Self::Assignments => AdminReadRequest::Assignments,
            Self::Users => AdminReadRequest::Users,
            Self::Principals => AdminReadRequest::Principals,
            Self::Grants => AdminReadRequest::Grants,
            Self::Configuration(yaml) => AdminReadRequest::Configuration { yaml },
        }
    }
}

impl SqliteLocalAdminReads<'_> {
    pub async fn read_opaque(
        &self,
        raw: &str,
        audience: &str,
        identity_json_bytes: NonZeroUsize,
        required_scopes: &[String],
        request: AdminReadRequest<'_>,
        original: Instant,
    ) -> Result<AdminReadResult<'static>, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let proof = self
            .store
            .local_bearer_verifier(audience, identity_json_bytes)
            .map_err(verification_error)?
            .verify(raw, required_scopes, end)
            .await
            .map_err(verification_error)?;
        let request = OwnedRequest::capture(request, self.limits)?;
        self.read_current(proof, request, end).await
    }
    async fn read_current(
        &self,
        proof: VerifiedLocalBearer,
        request: OwnedRequest,
        end: Instant,
    ) -> Result<AdminReadResult<'static>, Error> {
        let expiry = proof.authentication_expiry();
        let wait = end.min(expiry.1);
        let limits = self.limits;
        let observed = self
            .store
            .executor
            .execute(wait, move |owner, work| {
                let outcome = (|| {
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let request = request.borrow();
                    let (profile, principal, _, _) = admin_local_observer::observe(
                        &tx,
                        work,
                        LocalProof::Opaque(&proof),
                        limits.authorization,
                        request.kind().action(),
                        end,
                    )?;
                    let payload =
                        projection(&tx, work, &request, limits, &profile, &principal, wait)?;
                    check_authentication(&proof)?;
                    work.commit(tx).map_err(ControlError::from)?;
                    Ok::<_, Error>(payload)
                })();
                Ok((proof, outcome))
            })
            .await;
        if matches!(
            &observed,
            Err(crate::SqliteControlError::OutcomeUncertain)
                | Ok((
                    _,
                    Err(Error::Authorization(AdminBrokerSessionError::Control(
                        ControlError::OutcomeUncertain
                    )))
                ))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        if Instant::now() >= expiry.1 || SystemTime::now() >= expiry.0 {
            return Err(AdminBrokerSessionError::from(BrokerAccessError::Expired).into());
        }
        let (proof, outcome) = observed.map_err(ControlError::from)?;
        check_authentication(&proof)?;
        let payload = outcome?;
        let result = AdminReadResult {
            witness: ReadWitness::Opaque(proof),
            original: end,
            body: payload.body,
            revision: payload.revision,
        };
        result.check()?;
        Ok(result)
    }
    pub async fn read_cookie(
        &self,
        raw: &str,
        limits: AdminCookieSessionLimits,
        policy: AdminCookieSessionPolicy,
        request: AdminReadRequest<'_>,
        original: Instant,
    ) -> Result<AdminReadResult<'static>, Error> {
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
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        self.store
            .local_admin_cookie_sessions(limits, policy)?
            .read_admin(raw, request, self.limits, end)
            .await
    }
}

fn projection_error(kind: AdminReadKind, error: ControlError) -> Error {
    match error {
        ControlError::Deadline | ControlError::Closed | ControlError::OutcomeUncertain => {
            error.into()
        }
        _ => Error::Projection(kind),
    }
}
pub(super) fn projection(
    tx: &Transaction<'_>,
    work: &Work,
    request: &AdminReadRequest<'_>,
    limits: AdminReadLimits,
    profile: &SessionProfile,
    principal: &SessionPrincipal,
    end: Instant,
) -> Result<Payload, Error> {
    work.check().map_err(ControlError::from)?;
    let kind = request.kind();
    let bytes = limits.response_json_bytes.get();
    let result = match request {
        AdminReadRequest::Projects { .. } | AdminReadRequest::Grants => {
            let snapshot = super::resource_grants::observe_snapshot(
                tx,
                work,
                limits.grants_json_bytes.get() as i64,
            )
            .map_err(|e| match e {
                crate::ResourceGrantReadError::Control(e) => projection_error(kind, e),
                _ => Error::Projection(kind),
            })?;
            match request {
                AdminReadRequest::Projects { provider_command } => payload::projects_payload(
                    &snapshot,
                    provider_command,
                    profile,
                    principal,
                    bytes,
                    end,
                ),
                _ => payload::grants_payload(&snapshot, bytes, end),
            }
        }
        AdminReadRequest::Configuration { yaml } => {
            payload::configuration_payload(yaml, bytes, end)
        }
        _ => {
            let json = rows::read(tx, work, kind, bytes)?;
            payload::rows_payload(&json, kind, bytes, end)
        }
    };
    work.check().map_err(ControlError::from)?;
    result
}
