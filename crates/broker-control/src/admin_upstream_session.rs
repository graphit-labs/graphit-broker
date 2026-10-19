//! Request-scoped federated session.read, with its genuine private proof retained.
use crate::{
    AdminBrokerSessionError, SessionProfile, SystemPermission,
    upstream_oidc::VerifiedUpstreamBearer,
};
use std::{fmt, time::Instant};
/// Verified bearer plus current SQL permissions; getters expose only data.
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<broker_control::AdminUpstreamSession>();
/// ```
/// ```compile_fail
/// fn requires_default<T: Default>() {}
/// requires_default::<broker_control::AdminUpstreamSession>();
/// ```
/// ```compile_fail
/// fn requires_deserialize<T: serde::de::DeserializeOwned>() {}
/// requires_deserialize::<broker_control::AdminUpstreamSession>();
/// ```
pub struct AdminUpstreamSession {
    pub(crate) proof: VerifiedUpstreamBearer,
    pub(crate) original: Instant,
    pub(crate) roles: Vec<String>,
    pub(crate) permissions: Vec<SystemPermission>,
}
impl fmt::Debug for AdminUpstreamSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminUpstreamSession([REDACTED])")
    }
}
impl AdminUpstreamSession {
    pub fn check(&self) -> Result<(), AdminBrokerSessionError> {
        if Instant::now() >= self.original {
            return Err(crate::ControlError::Deadline.into());
        }
        self.proof.check()
    }
    pub fn profile(&self) -> &SessionProfile {
        self.proof.profile()
    }
    pub fn issuer(&self) -> &str {
        self.proof.issuer()
    }
    pub fn username(&self) -> &str {
        self.proof.username()
    }
    pub fn organization(&self) -> &str {
        self.proof.organization()
    }
    pub fn teams(&self) -> &[String] {
        self.proof.teams()
    }
    pub fn roles(&self) -> &[String] {
        &self.roles
    }
    pub fn permissions(&self) -> &[SystemPermission] {
        &self.permissions
    }
    pub fn role_source(&self) -> &'static str {
        if self.proof.claim_roles().is_some() {
            "claims"
        } else {
            "database"
        }
    }
}
