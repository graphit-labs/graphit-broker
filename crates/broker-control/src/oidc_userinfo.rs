//! Explicit OP profile results are data, never resource or administrator authority.
use crate::ControlError;
use serde::Serialize;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcUserInfoError {
    InvalidToken,
    InvalidConfiguration,
    MalformedStored,
    ReadLimitExceeded,
    Credential,
    Control(ControlError),
}
impl fmt::Display for OidcUserInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidToken => "invalid UserInfo access token",
            Self::InvalidConfiguration => "invalid UserInfo configuration",
            Self::MalformedStored => "malformed UserInfo grant",
            Self::ReadLimitExceeded => "UserInfo grant read limit exceeded",
            Self::Credential => "UserInfo credential operation failed",
            Self::Control(_) => "UserInfo storage operation failed",
        })
    }
}
impl std::error::Error for OidcUserInfoError {}
impl From<ControlError> for OidcUserInfoError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}
#[derive(Serialize)]
pub struct OidcUserInfo {
    pub(crate) sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) organization: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) groups: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) roles: Vec<String>,
}
impl fmt::Debug for OidcUserInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcUserInfo([REDACTED])")
    }
}
