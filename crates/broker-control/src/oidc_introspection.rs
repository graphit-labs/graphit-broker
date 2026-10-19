//! Explicit token inspection; no request-path dependency for local JWT consumers.
use crate::ControlError;
use serde::Serialize;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcIntrospectionError {
    InvalidAuthority,
    InvalidConfiguration,
    MalformedStored,
    ReadLimitExceeded,
    Credential,
    Control(ControlError),
}
impl fmt::Display for OidcIntrospectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidAuthority => "invalid introspection authority",
            Self::InvalidConfiguration => "invalid introspection configuration",
            Self::MalformedStored => "malformed introspection grant",
            Self::ReadLimitExceeded => "introspection grant read limit exceeded",
            Self::Credential => "introspection credential operation failed",
            Self::Control(_) => "introspection storage operation failed",
        })
    }
}
impl std::error::Error for OidcIntrospectionError {}
impl From<ControlError> for OidcIntrospectionError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}
#[derive(Serialize)]
pub struct OidcIntrospection {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
}
impl OidcIntrospection {
    pub(crate) fn inactive() -> Self {
        Self {
            active: false,
            client_id: None,
            scope: None,
            exp: None,
        }
    }
    pub(crate) fn active(client: String, scopes: &[String], expiry_micros: i64) -> Self {
        Self {
            active: true,
            client_id: Some(client),
            scope: (!scopes.is_empty()).then(|| scopes.join(" ")),
            exp: Some(expiry_micros / 1_000_000),
        }
    }
}
impl fmt::Debug for OidcIntrospection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcIntrospection([REDACTED])")
    }
}
