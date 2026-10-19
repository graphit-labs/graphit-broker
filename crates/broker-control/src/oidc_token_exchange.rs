//! Native OIDC token exchange. Only the SQL producers can construct a token result.
use crate::{ControlError, OidcAuthorizationError, flow::now_micros};
use oxide_auth::code_grant::accesstoken::{Authorization, Request};
use std::{
    borrow::Cow,
    fmt,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcTokenExchangeError {
    InvalidConfiguration,
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    InvalidTarget,
    InvalidScope,
    UnsupportedGrantType,
    MalformedStored,
    ReadLimitExceeded,
    Credential,
    Random,
    Signing,
    Control(ControlError),
}
impl fmt::Display for OidcTokenExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(e) => e.fmt(f),
            _ => write!(f, "OIDC token exchange {self:?}"),
        }
    }
}
impl std::error::Error for OidcTokenExchangeError {}
impl From<ControlError> for OidcTokenExchangeError {
    fn from(e: ControlError) -> Self {
        Self::Control(e)
    }
}
impl From<OidcAuthorizationError> for OidcTokenExchangeError {
    fn from(e: OidcAuthorizationError) -> Self {
        match e {
            OidcAuthorizationError::Control(e) => Self::Control(e),
            OidcAuthorizationError::InvalidClient => Self::InvalidClient,
            OidcAuthorizationError::InvalidLogin => Self::InvalidGrant,
            OidcAuthorizationError::ReadLimitExceeded => Self::ReadLimitExceeded,
            OidcAuthorizationError::Credential => Self::Credential,
            _ => Self::MalformedStored,
        }
    }
}

/// Explicit protocol lifetimes. Startup supplies the confirmed defaults, not this primitive.
pub struct OidcTokenExchangePolicy {
    pub(crate) access_micros: i64,
    pub(crate) refresh_micros: i64,
}
impl fmt::Debug for OidcTokenExchangePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcTokenExchangePolicy([REDACTED])")
    }
}
impl OidcTokenExchangePolicy {
    pub fn new(
        access_ttl: Duration,
        refresh_ttl: Duration,
    ) -> Result<Self, OidcTokenExchangeError> {
        if !(Duration::from_secs(60)..=Duration::from_secs(3600)).contains(&access_ttl)
            || refresh_ttl < access_ttl
            || refresh_ttl > Duration::from_secs(90 * 86400)
        {
            return Err(OidcTokenExchangeError::InvalidConfiguration);
        }
        Ok(Self {
            access_micros: i64::try_from(access_ttl.as_micros())
                .map_err(|_| OidcTokenExchangeError::InvalidConfiguration)?,
            refresh_micros: i64::try_from(refresh_ttl.as_micros())
                .map_err(|_| OidcTokenExchangeError::InvalidConfiguration)?,
        })
    }
}

/// Borrowed form parameters after scalar-duplicate and transport validation.
pub struct OidcTokenExchangeInput<'a> {
    pub grant_type: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub code: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub code_verifier: Option<&'a str>,
    pub resource: Option<&'a str>,
    pub authorization: Option<(&'a str, &'a [u8])>,
}
impl fmt::Debug for OidcTokenExchangeInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcTokenExchangeInput([REDACTED])")
    }
}
impl Request for OidcTokenExchangeInput<'_> {
    fn valid(&self) -> bool {
        true
    }
    fn code(&self) -> Option<Cow<'_, str>> {
        self.code.map(Cow::Borrowed)
    }
    fn authorization(&self) -> Authorization<'_> {
        match self.authorization {
            None => Authorization::None,
            Some((user, pass)) => {
                Authorization::UsernamePassword(Cow::Borrowed(user), Cow::Borrowed(pass))
            }
        }
    }
    fn client_id(&self) -> Option<Cow<'_, str>> {
        self.client_id.map(Cow::Borrowed)
    }
    fn redirect_uri(&self) -> Option<Cow<'_, str>> {
        self.redirect_uri.map(Cow::Borrowed)
    }
    fn grant_type(&self) -> Option<Cow<'_, str>> {
        self.grant_type.map(Cow::Borrowed)
    }
    fn extension(&self, key: &str) -> Option<Cow<'_, str>> {
        match key {
            "code_verifier" => self.code_verifier.map(Cow::Borrowed),
            "resource" => self.resource.map(Cow::Borrowed),
            _ => None,
        }
    }
}

/// Committed owned secrets. Not Clone/Serialize/Default; transport borrows them briefly.
/// ```compile_fail
/// fn copy<T: Clone>() {}
/// copy::<broker_control::OidcTokenExchangeResult>();
/// ```
/// ```compile_fail
/// fn serialize<T: serde::Serialize>() {}
/// serialize::<broker_control::OidcTokenExchangeResult>();
/// ```
/// ```compile_fail
/// fn forge(value: broker_control::OidcTokenExchangeResult) { let _ = value.access; }
/// ```
pub struct OidcTokenExchangeResult {
    pub(crate) access: Zeroizing<String>,
    pub(crate) id: Zeroizing<String>,
    pub(crate) refresh: Option<Zeroizing<String>>,
    pub(crate) scope: String,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) grant_expires_at: Option<i64>,
}
impl fmt::Debug for OidcTokenExchangeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcTokenExchangeResult([REDACTED])")
    }
}
impl OidcTokenExchangeResult {
    pub fn access_token(&self) -> &str {
        &self.access
    }
    pub fn id_token(&self) -> &str {
        &self.id
    }
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh.as_deref().map(String::as_str)
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn expires_in(&self, original: Instant) -> Result<u64, OidcTokenExchangeError> {
        if Instant::now() >= original {
            return Err(ControlError::Deadline.into());
        }
        remaining_with_grant(
            self.issued_at,
            self.expires_at,
            self.grant_expires_at,
            now_micros()?,
        )
    }
}
fn remaining_with_grant(
    issued_at: i64,
    expires_at: i64,
    grant_expires_at: Option<i64>,
    now: i64,
) -> Result<u64, OidcTokenExchangeError> {
    if grant_expires_at.is_some_and(|expiry| expiry <= issued_at || now >= expiry) {
        return Err(OidcTokenExchangeError::InvalidGrant);
    }
    remaining_seconds(issued_at, expires_at, now)
}
fn remaining_seconds(
    issued_at: i64,
    expires_at: i64,
    now: i64,
) -> Result<u64, OidcTokenExchangeError> {
    if issued_at <= 0 || expires_at <= issued_at || now < issued_at {
        return Err(ControlError::Clock.into());
    }
    if now >= expires_at {
        return Err(OidcTokenExchangeError::InvalidGrant);
    }
    let remaining = expires_at.checked_sub(now).ok_or(ControlError::Clock)?;
    let seconds = u64::try_from(remaining / 1_000_000).map_err(|_| ControlError::Clock)?;
    if seconds == 0 {
        return Err(OidcTokenExchangeError::InvalidGrant);
    }
    Ok(seconds)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_refresh_cutoff_survives_the_sql_return_until_http_output() {
        let issued = 1_000_000_000;
        let access = issued + 600_000_000;
        let refresh = issued + 2_000_000;
        assert_eq!(
            remaining_with_grant(issued, access, Some(refresh), issued),
            Ok(600)
        );
        assert_eq!(
            remaining_with_grant(issued, access, Some(refresh), refresh),
            Err(OidcTokenExchangeError::InvalidGrant)
        );
        assert_eq!(remaining_with_grant(issued, access, None, refresh), Ok(598));
    }
    #[test]
    fn remaining_lifetime_denies_a_clock_rewind_instead_of_extending_the_minted_interval() {
        let issued = 1_000_000_000;
        let expires = issued + 600_000_000;
        assert_eq!(remaining_seconds(issued, expires, issued), Ok(600));
        assert_eq!(
            remaining_seconds(issued, expires, issued + 1_000_000),
            Ok(599)
        );
        assert_eq!(
            remaining_seconds(issued, expires, issued - 1),
            Err(ControlError::Clock.into())
        );
        assert_eq!(
            remaining_seconds(issued, expires, i64::MIN),
            Err(ControlError::Clock.into())
        );
        assert_eq!(
            remaining_seconds(issued, expires, expires),
            Err(OidcTokenExchangeError::InvalidGrant)
        );
        assert_eq!(
            remaining_seconds(issued, expires, expires - 1),
            Err(OidcTokenExchangeError::InvalidGrant)
        );
        assert_eq!(
            remaining_seconds(issued, issued, issued),
            Err(ControlError::Clock.into())
        );
    }
}
