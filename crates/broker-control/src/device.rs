//! Native Device grant values. Only the SQL producer constructs committed outputs.
use crate::{ControlError, OidcTokenExchangeError, flow::now_micros};
use broker_security::LocalRecoveryCodes;
use std::{
    fmt,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceError {
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    ExpiredToken,
    Protocol(OidcTokenExchangeError),
}
impl From<ControlError> for DeviceError {
    fn from(e: ControlError) -> Self {
        Self::Protocol(e.into())
    }
}
impl From<OidcTokenExchangeError> for DeviceError {
    fn from(e: OidcTokenExchangeError) -> Self {
        Self::Protocol(e)
    }
}
impl From<crate::OidcAuthorizationError> for DeviceError {
    fn from(e: crate::OidcAuthorizationError) -> Self {
        Self::Protocol(e.into())
    }
}
impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Device authorization {self:?}")
    }
}
impl std::error::Error for DeviceError {}

/// Startup supplies lifetimes. This value has no inferred defaults.
#[derive(Debug)]
pub struct DeviceAuthorizationPolicy {
    pub(crate) ttl_micros: i64,
    pub(crate) interval_seconds: i64,
    pub(crate) access_micros: i64,
}
impl DeviceAuthorizationPolicy {
    pub fn new(
        code_ttl: Duration,
        poll_interval: Duration,
        access_ttl: Duration,
    ) -> Result<Self, DeviceError> {
        if !(Duration::from_secs(300)..=Duration::from_secs(1800)).contains(&code_ttl)
            || !(Duration::from_secs(1)..=Duration::from_secs(30)).contains(&poll_interval)
            || !(Duration::from_secs(60)..=Duration::from_secs(3600)).contains(&access_ttl)
            || code_ttl.subsec_nanos() != 0
            || poll_interval.subsec_nanos() != 0
        {
            return Err(OidcTokenExchangeError::InvalidConfiguration.into());
        }
        Ok(Self {
            ttl_micros: code_ttl.as_micros() as i64,
            interval_seconds: poll_interval.as_secs() as i64,
            access_micros: access_ttl.as_micros() as i64,
        })
    }
}
/// Canonical data for binding a LOCAL challenge; it proves no authentication.
pub fn normalize_device_user_code(raw: &str) -> Option<String> {
    let mut value = String::with_capacity(8);
    for byte in raw.trim().bytes().filter(|b| *b != b'-') {
        let byte = byte.to_ascii_uppercase();
        if value.len() == 8 || !b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(&byte) {
            return None;
        }
        value.push(byte as char);
    }
    (value.len() == 8).then_some(value)
}
pub(crate) fn check(original: Instant, expiry: i64) -> Result<(), DeviceError> {
    if Instant::now() >= original {
        return Err(ControlError::Deadline.into());
    }
    if now_micros()? >= expiry {
        return Err(DeviceError::ExpiredToken);
    }
    Ok(())
}
fn remaining(original: Instant, expiry: i64) -> Result<u64, DeviceError> {
    check(original, expiry)?;
    u64::try_from((expiry - now_micros()?) / 1_000_000).map_err(|_| ControlError::Clock.into())
}

/// Committed secrets. No wire serializer or externally constructible authority.
/// ```compile_fail
/// fn clone<T: Clone>() {} clone::<broker_control::DeviceAuthorizationCodes>();
/// ```
pub struct DeviceAuthorizationCodes {
    pub(crate) device: Zeroizing<String>,
    pub(crate) user: String,
    pub(crate) expires_at: i64,
    pub(crate) interval: u64,
}
impl fmt::Debug for DeviceAuthorizationCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceAuthorizationCodes([REDACTED])")
    }
}
impl DeviceAuthorizationCodes {
    pub fn device_code(&self) -> &str {
        &self.device
    }
    pub fn user_code(&self) -> &str {
        &self.user
    }
    pub fn expires_in(&self, original: Instant) -> Result<u64, DeviceError> {
        remaining(original, self.expires_at)
    }
    pub fn interval_seconds(&self) -> u64 {
        self.interval
    }
}
/// A genuine LOCAL login prepared for one explicit consent decision. Not approval.
/// ```compile_fail
/// fn wire<T: serde::Serialize>() {} wire::<broker_control::DeviceConsent>();
/// ```
/// ```compile_fail
/// fn forge(v: broker_control::DeviceConsent) { let _ = v.secret; }
/// ```
pub struct DeviceConsent {
    pub(crate) secret: Zeroizing<String>,
    pub(crate) recovery: Option<LocalRecoveryCodes>,
    pub(crate) user_code: String,
    pub(crate) client: String,
    pub(crate) scope: String,
    pub(crate) expires_at: i64,
}
impl fmt::Debug for DeviceConsent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceConsent([REDACTED])")
    }
}
impl DeviceConsent {
    pub fn secret(&self, original: Instant) -> Result<&str, DeviceError> {
        check(original, self.expires_at)?;
        if self.recovery.is_some() {
            return Err(OidcTokenExchangeError::InvalidGrant.into());
        }
        Ok(&self.secret)
    }
    pub fn take_recovery_codes(&mut self) -> Option<LocalRecoveryCodes> {
        self.recovery.take()
    }
    pub fn user_code(&self) -> &str {
        &self.user_code
    }
    pub fn client_id(&self) -> &str {
        &self.client
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
}
/// One committed JWT access bearer; this grant produces neither ID nor refresh token.
/// ```compile_fail
/// fn forge(v: broker_control::DeviceAccessToken) { let _ = v.access; }
/// ```
pub struct DeviceAccessToken {
    pub(crate) access: Zeroizing<String>,
    pub(crate) scope: String,
    pub(crate) expires_at: i64,
}
impl fmt::Debug for DeviceAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceAccessToken([REDACTED])")
    }
}
impl DeviceAccessToken {
    pub fn access_token(&self) -> &str {
        &self.access
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn expires_in(&self, original: Instant) -> Result<u64, DeviceError> {
        remaining(original, self.expires_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_and_canonical_user_code() {
        assert!(
            DeviceAuthorizationPolicy::new(
                Duration::from_secs(600),
                Duration::from_secs(5),
                Duration::from_secs(600)
            )
            .is_ok()
        );
        for (ttl, poll, access) in [
            (299, 5, 600),
            (1801, 5, 600),
            (600, 0, 600),
            (600, 31, 600),
            (600, 5, 59),
            (600, 5, 3601),
        ] {
            assert!(
                DeviceAuthorizationPolicy::new(
                    Duration::from_secs(ttl),
                    Duration::from_secs(poll),
                    Duration::from_secs(access)
                )
                .is_err()
            );
        }
        assert!(
            DeviceAuthorizationPolicy::new(
                Duration::from_secs(600),
                Duration::from_millis(1500),
                Duration::from_secs(600)
            )
            .is_err()
        );
        assert_eq!(
            normalize_device_user_code(" abcd-2345 ").as_deref(),
            Some("ABCD2345")
        );
        for raw in [
            "",
            "ABCD1234",
            "ABCD234I",
            "ABCD234O",
            "ABCD23456",
            "ABCD 2345",
            "ＡBCD2345",
        ] {
            assert!(normalize_device_user_code(raw).is_none());
        }
    }
}
