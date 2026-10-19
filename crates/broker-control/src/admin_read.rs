//! Request-scoped administrative projections, authenticated independently per action.
pub(crate) mod projection;

use crate::{
    AdminBrokerSessionError, AdminBrokerSessionLimits, AdminCookieSessionError,
    AdminCookieSessionLimits, AdminCookieSessionPolicy, BrokerAccessError, BrokerAccessVerifier,
    ControlError, SystemAction, UpstreamBearerVerifier, VerifiedBrokerAccess, VerifiedLocalBearer,
    admin_cookie_session::CookieWindow, upstream_oidc::VerifiedUpstreamBearer,
};
use std::{fmt, num::NonZeroUsize, sync::Arc, time::Instant};

#[derive(Clone, Copy, Debug)]
pub struct AdminReadLimits {
    pub authorization: AdminBrokerSessionLimits,
    pub grants_json_bytes: NonZeroUsize,
    pub response_json_bytes: NonZeroUsize,
}
impl AdminReadLimits {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.authorization.validate()?;
        for value in [self.grants_json_bytes, self.response_json_bytes] {
            i64::try_from(value.get()).map_err(|_| ControlError::Configuration)?;
            value
                .get()
                .checked_add(1)
                .and_then(|v| isize::try_from(v).ok())
                .ok_or(ControlError::Configuration)?;
        }
        Ok(())
    }
}

/// Configured authentication inputs. Raw possession is verified by the SQL producer.
pub enum AdminReadAuthentication<'a, 'raw> {
    Broker {
        verifier: &'a BrokerAccessVerifier,
        proof: VerifiedBrokerAccess<'a>,
    },
    Opaque {
        raw: &'raw str,
        audience: &'raw str,
        identity_json_bytes: NonZeroUsize,
        required_scopes: &'raw [String],
    },
    Upstream {
        raw: &'raw str,
        verifier: &'a UpstreamBearerVerifier,
    },
    Cookie {
        raw: &'raw str,
        limits: AdminCookieSessionLimits,
        policy: AdminCookieSessionPolicy,
        // Cookie trust is observed inside the SQLite worker; retain its configured owner.
        upstream: Option<Arc<UpstreamBearerVerifier>>,
    },
}
impl fmt::Debug for AdminReadAuthentication<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminReadAuthentication([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminReadKind {
    Projects,
    Roles,
    Assignments,
    Users,
    Principals,
    Grants,
    Configuration,
}
impl AdminReadKind {
    pub(crate) const fn action(self) -> SystemAction {
        match self {
            Self::Projects => SystemAction::ProjectsRead,
            Self::Roles | Self::Assignments => SystemAction::RolesRead,
            Self::Users => SystemAction::UsersRead,
            Self::Principals | Self::Grants => SystemAction::GrantsRead,
            Self::Configuration => SystemAction::ConfigurationRead,
        }
    }
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::Projects => "projects_read_failed",
            Self::Roles => "roles_read_failed",
            Self::Assignments => "assignments_read_failed",
            Self::Users => "users_read_failed",
            Self::Principals => "principals_read_failed",
            Self::Grants => "grants_read_failed",
            Self::Configuration => "configuration_encode_failed",
        }
    }
}
/// Public deployment text is data, never a permission or a principal.
pub enum AdminReadRequest<'a> {
    Projects { provider_command: &'a str },
    Roles,
    Assignments,
    Users,
    Principals,
    Grants,
    Configuration { yaml: &'a str },
}
impl AdminReadRequest<'_> {
    pub(crate) const fn kind(&self) -> AdminReadKind {
        match self {
            Self::Projects { .. } => AdminReadKind::Projects,
            Self::Roles => AdminReadKind::Roles,
            Self::Assignments => AdminReadKind::Assignments,
            Self::Users => AdminReadKind::Users,
            Self::Principals => AdminReadKind::Principals,
            Self::Grants => AdminReadKind::Grants,
            Self::Configuration { .. } => AdminReadKind::Configuration,
        }
    }
}
impl fmt::Debug for AdminReadRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminReadRequest([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminReadError {
    Authorization(AdminBrokerSessionError),
    Projection(AdminReadKind),
}
impl From<AdminBrokerSessionError> for AdminReadError {
    fn from(value: AdminBrokerSessionError) -> Self {
        Self::Authorization(value)
    }
}
impl From<ControlError> for AdminReadError {
    fn from(value: ControlError) -> Self {
        Self::Authorization(value.into())
    }
}
impl fmt::Display for AdminReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(e) => e.fmt(f),
            Self::Projection(_) => f.write_str("administrative projection unavailable"),
        }
    }
}
impl std::error::Error for AdminReadError {}
pub(crate) fn cookie_authorization(error: AdminCookieSessionError) -> AdminBrokerSessionError {
    match error {
        AdminCookieSessionError::Control(e)
            if !matches!(
                e,
                ControlError::SessionExpired | ControlError::SessionUnavailable
            ) =>
        {
            e.into()
        }
        AdminCookieSessionError::Forbidden | AdminCookieSessionError::CsrfFailed => {
            AdminBrokerSessionError::Forbidden
        }
        AdminCookieSessionError::Entropy => AdminBrokerSessionError::Entropy,
        _ => BrokerAccessError::InvalidToken.into(),
    }
}
pub(crate) enum ReadWitness<'a> {
    Broker(VerifiedBrokerAccess<'a>),
    Opaque(VerifiedLocalBearer),
    Upstream(VerifiedUpstreamBearer),
    Cookie {
        _proof: crate::service::CookieReadProof,
        window: CookieWindow,
    },
}
impl ReadWitness<'_> {
    pub(crate) fn check(&self) -> Result<(), AdminBrokerSessionError> {
        match self {
            Self::Broker(p) => p.check().map_err(Into::into),
            Self::Opaque(p) => crate::admin_local_bearer_session::check_authentication(p),
            Self::Upstream(p) => p.check(),
            Self::Cookie { window, .. } => {
                window.check().map_err(|e| cookie_authorization(e.into()))
            }
        }
    }
}
/// The body is DATA for this completed read, never authority for another operation.
/// The HTTP consumer checks the retained factor before and after preparing headers.
/// ```compile_fail
/// fn clone<T: Clone>() {} clone::<broker_control::AdminReadResult<'static>>();
/// ```
/// ```compile_fail
/// fn default<T: Default>() {} default::<broker_control::AdminReadResult<'static>>();
/// ```
/// ```compile_fail
/// fn decode<T: serde::de::DeserializeOwned>() {} decode::<broker_control::AdminReadResult<'static>>();
/// ```
pub struct AdminReadResult<'a> {
    pub(crate) witness: ReadWitness<'a>,
    pub(crate) original: Instant,
    pub(crate) body: Vec<u8>,
    pub(crate) revision: Option<i64>,
}
impl AdminReadResult<'_> {
    pub fn check(&self) -> Result<(), AdminReadError> {
        if Instant::now() >= self.original {
            return Err(ControlError::Deadline.into());
        }
        self.witness.check()?;
        Ok(())
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn revision(&self) -> Option<i64> {
        self.revision
    }
}
impl fmt::Debug for AdminReadResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminReadResult([REDACTED])")
    }
}
