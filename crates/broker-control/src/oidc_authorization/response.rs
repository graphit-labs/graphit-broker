//! Response projection from current, sealed authorization observations.
use super::{
    OidcAuthorizationError as Error, OidcAuthorizationRequestInfo, OidcAuthorizationResponseMode,
    guard_original,
};
use crate::ControlError;
use std::{
    fmt,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// A transport destination, never login or grant authority. Fields cannot be supplied by DTOs.
/// ```compile_fail
/// fn forge(target: broker_control::OidcAuthorizationResponseTarget<'_>) { let _ = target.redirect; }
/// ```
/// ```compile_fail
/// fn serialize(target: broker_control::OidcAuthorizationResponseTarget<'_>) { let _ = serde_json::to_string(&target); }
/// ```
pub struct OidcAuthorizationResponseTarget<'a> {
    redirect: &'a str,
    state: &'a str,
    mode: OidcAuthorizationResponseMode,
    origin: String,
    original: Instant,
    pending_expiry: Option<PendingExpiry>,
}
struct PendingExpiry {
    utc: SystemTime,
    monotonic: Instant,
}
impl fmt::Debug for OidcAuthorizationResponseTarget<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcAuthorizationResponseTarget([REDACTED])")
    }
}
impl OidcAuthorizationRequestInfo {
    /// Borrow the already revalidated destination; callers must retain the request Original.
    pub fn response_target(
        &self,
        original: Instant,
    ) -> Result<OidcAuthorizationResponseTarget<'_>, Error> {
        guard_original(original)?;
        let observed = Instant::now();
        let micros = u64::try_from(self.expires_at).map_err(|_| Error::MalformedStored)?;
        let expires_at = UNIX_EPOCH
            .checked_add(Duration::from_micros(micros))
            .ok_or(ControlError::Clock)?;
        let remaining = expires_at
            .duration_since(SystemTime::now())
            .map_err(|_| ControlError::Expired)?;
        let expires_mono = observed.checked_add(remaining).ok_or(ControlError::Clock)?;
        let url = url::Url::parse(self.redirect_uri()).map_err(|_| Error::InvalidRedirect)?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(Error::InvalidRedirect);
        }
        let target = OidcAuthorizationResponseTarget {
            redirect: self.redirect_uri(),
            state: self.state(),
            mode: self.response_mode(),
            origin: url.origin().ascii_serialization(),
            original,
            pending_expiry: Some(PendingExpiry {
                utc: expires_at,
                monotonic: expires_mono,
            }),
        };
        target.check()?;
        Ok(target)
    }
}
impl<'a> OidcAuthorizationResponseTarget<'a> {
    pub(super) fn initial(
        redirect: &'a str,
        state: &'a str,
        mode: OidcAuthorizationResponseMode,
        original: Instant,
    ) -> Result<Self, Error> {
        guard_original(original)?;
        let url = url::Url::parse(redirect).map_err(|_| Error::InvalidRedirect)?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(Error::InvalidRedirect);
        }
        let target = Self {
            redirect,
            state,
            mode,
            origin: url.origin().ascii_serialization(),
            original,
            pending_expiry: None,
        };
        target.check()?;
        Ok(target)
    }
    pub fn redirect_uri(&self) -> &str {
        self.redirect
    }
    pub fn state(&self) -> &str {
        self.state
    }
    pub const fn response_mode(&self) -> OidcAuthorizationResponseMode {
        self.mode
    }
    /// A parsed HTTP origin for CSP and destination context; never the redirect replacement.
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn check(&self) -> Result<(), Error> {
        guard_original(self.original)?;
        if self.pending_expiry.as_ref().is_some_and(|expiry| {
            SystemTime::now() >= expiry.utc || Instant::now() >= expiry.monotonic
        }) {
            return Err(ControlError::Expired.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initial_original_and_pending_utc_monotonic_gates_remain_independent() {
        let mut target = OidcAuthorizationResponseTarget::initial(
            "https://rp.example/%2f",
            "",
            OidcAuthorizationResponseMode::Query,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        target.check().unwrap();
        assert!(target.pending_expiry.is_none());
        target.pending_expiry = Some(PendingExpiry {
            utc: SystemTime::now() - Duration::from_secs(1),
            monotonic: Instant::now() + Duration::from_secs(10),
        });
        assert_eq!(
            target.check().unwrap_err(),
            Error::Control(ControlError::Expired)
        );
        target.pending_expiry = Some(PendingExpiry {
            utc: SystemTime::now() + Duration::from_secs(10),
            monotonic: Instant::now() - Duration::from_secs(1),
        });
        assert_eq!(
            target.check().unwrap_err(),
            Error::Control(ControlError::Expired)
        );
        target.pending_expiry = None;
        target.original = Instant::now();
        assert_eq!(
            target.check().unwrap_err(),
            Error::Control(ControlError::Deadline)
        );
    }
}
