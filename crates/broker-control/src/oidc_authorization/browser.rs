//! Initial browser admission; no identity or grant authority.
use super::{
    ClientData, Error, OidcAuthorizationInput, OidcAuthorizationResponseMode,
    OidcAuthorizationResponseTarget, PendingOidcAuthorization, guard_original,
};
use std::{fmt, time::Instant};

/// Closed protocol errors supported by the existing authorization policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcAuthorizationRejectionCode {
    InvalidRequest,
    InvalidScope,
    LoginRequired,
    InvalidTarget,
}
impl OidcAuthorizationRejectionCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::LoginRequired => "login_required",
            Self::InvalidTarget => "invalid_target",
        }
    }
    pub(crate) fn from_error(error: Error) -> Result<Self, Error> {
        match error {
            Error::InvalidRequest => Ok(Self::InvalidRequest),
            Error::InvalidScope => Ok(Self::InvalidScope),
            Error::LoginRequired => Ok(Self::LoginRequired),
            Error::InvalidTarget => Ok(Self::InvalidTarget),
            other => Err(other),
        }
    }
}
/// A confirmed rejection with a destination admitted against the current client.
/// It is neither a pending request nor resource-owner authority.
/// ```compile_fail
/// fn forge(r: broker_control::RejectedOidcAuthorization<'_>) { let _ = r.target; }
/// ```
/// ```compile_fail
/// fn serialize(r: broker_control::RejectedOidcAuthorization<'_>) { let _ = serde_json::to_string(&r); }
/// ```
/// ```compile_fail
/// fn clone(r: broker_control::RejectedOidcAuthorization<'_>) { let _ = r.clone(); }
/// ```
pub struct RejectedOidcAuthorization<'a> {
    code: OidcAuthorizationRejectionCode,
    target: OidcAuthorizationResponseTarget<'a>,
}
impl fmt::Debug for RejectedOidcAuthorization<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RejectedOidcAuthorization([REDACTED])")
    }
}
impl<'a> RejectedOidcAuthorization<'a> {
    pub(crate) fn confirmed(
        code: OidcAuthorizationRejectionCode,
        input: &OidcAuthorizationInput<'a>,
        client: &ClientData,
        original: Instant,
    ) -> Result<Self, Error> {
        guard_original(original)?;
        if input.client_id != client.id {
            return Err(Error::InvalidClient);
        }
        client.admit_redirect(input.redirect_uri)?;
        Ok(Self {
            code,
            target: OidcAuthorizationResponseTarget::initial(
                input.redirect_uri,
                input.state,
                OidcAuthorizationResponseMode::from_parameter(input.response_mode),
                original,
            )?,
        })
    }
    pub const fn code(&self) -> OidcAuthorizationRejectionCode {
        self.code
    }
    /// Empty state denotes an omitted parameter in the eventual protocol response.
    pub fn into_target(self) -> OidcAuthorizationResponseTarget<'a> {
        self.target
    }
}
/// Only a successful pending admission or a confirmed, protected protocol rejection.
#[derive(Debug)]
pub enum BrowserOidcAuthorization<'a> {
    Pending(Box<PendingOidcAuthorization>),
    Rejected(RejectedOidcAuthorization<'a>),
}
