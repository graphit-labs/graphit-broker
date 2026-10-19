//! Request-scoped administrative admission from a genuine LOCAL opaque bearer.
use crate::{
    AdminBrokerSessionError as Error, BrokerAccessError, ControlError, LocalBearerStateError,
    LocalBearerVerificationError, SessionPrincipal, SessionProfile, SystemPermission,
    VerifiedLocalBearer,
};
use std::{
    fmt,
    time::{Instant, SystemTime},
};

/// Only the server's raw-bearer consumer can produce this session.read result.
/// Its observations do not authorize another action or a later request.
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::AdminLocalBearerSession>();
/// ```
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::AdminLocalBearerSession>();
/// ```
/// ```compile_fail
/// fn require_wire<T: serde::de::DeserializeOwned>() {}
/// require_wire::<broker_control::AdminLocalBearerSession>();
/// ```
pub struct AdminLocalBearerSession {
    pub(crate) proof: VerifiedLocalBearer,
    pub(crate) original: Instant,
    pub(crate) profile: SessionProfile,
    pub(crate) principal: SessionPrincipal,
    pub(crate) roles: Vec<String>,
    pub(crate) permissions: Vec<SystemPermission>,
}
impl fmt::Debug for AdminLocalBearerSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminLocalBearerSession([REDACTED])")
    }
}
pub(crate) fn check_authentication(proof: &VerifiedLocalBearer) -> Result<(), Error> {
    let (utc, mono) = proof.authentication_expiry();
    if SystemTime::now() >= utc || Instant::now() >= mono {
        return Err(BrokerAccessError::Expired.into());
    }
    Ok(())
}
impl AdminLocalBearerSession {
    pub fn check(&self) -> Result<(), Error> {
        if Instant::now() >= self.original {
            return Err(ControlError::Deadline.into());
        }
        check_authentication(&self.proof)
    }
    pub fn profile(&self) -> &SessionProfile {
        &self.profile
    }
    pub fn principal(&self) -> &SessionPrincipal {
        &self.principal
    }
    pub fn roles(&self) -> &[String] {
        &self.roles
    }
    pub fn permissions(&self) -> &[SystemPermission] {
        &self.permissions
    }
}

pub(crate) fn verification_error(error: LocalBearerVerificationError) -> Error {
    match error {
        LocalBearerVerificationError::Unauthenticated => BrokerAccessError::InvalidToken.into(),
        LocalBearerVerificationError::Control(error)
        | LocalBearerVerificationError::State(LocalBearerStateError::Control(error)) => {
            error.into()
        }
        LocalBearerVerificationError::State(LocalBearerStateError::InvalidLimits) => {
            ControlError::Configuration.into()
        }
        LocalBearerVerificationError::State(LocalBearerStateError::ReadLimitExceeded) => {
            ControlError::IdentityLimitExceeded.into()
        }
        LocalBearerVerificationError::State(LocalBearerStateError::MalformedStored) => {
            ControlError::CorruptIdentity.into()
        }
    }
}
