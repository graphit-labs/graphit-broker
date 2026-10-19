//! Genuine login issuance and request-scoped current cookie authorization.
use crate::{
    AdminBrokerSessionError, AdminBrokerSessionLimits, CompletedLocalLogin, ControlError,
    SessionLimits, SessionPrincipal, SessionProfile, SystemPermission,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_security::LocalAuthPurpose;
use std::{
    fmt,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;

pub const ADMIN_COOKIE_MAX_LIFETIME: Duration = Duration::from_secs(168 * 3600);
// Resolved headers 0.4.2 delegates to httpdate 1.0.3, which rejects year 10000.
const HTTP_DATE_EXCLUSIVE_SECONDS: u64 = 253_402_300_800;
fn validate_http_expiry(expiry: SystemTime) -> Result<(), ControlError> {
    let elapsed = expiry
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| ControlError::Clock)?;
    if elapsed.as_secs() >= HTTP_DATE_EXCLUSIVE_SECONDS {
        return Err(ControlError::Clock);
    }
    Ok(())
}
#[derive(Clone, Copy, Debug)]
pub struct AdminCookieSessionLimits {
    pub metadata: SessionLimits,
    pub authorization: AdminBrokerSessionLimits,
}
impl AdminCookieSessionLimits {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.metadata.validate()?;
        self.authorization.validate()?;
        if self.metadata.csrf_bytes.get() < 43
            || self.metadata.max_lifetime > ADMIN_COOKIE_MAX_LIFETIME
        {
            return Err(ControlError::Configuration);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub struct AdminCookieSessionPolicy {
    pub session_ttl: Duration,
}
impl AdminCookieSessionPolicy {
    pub fn validate(&self) -> Result<(), ControlError> {
        if !(Duration::from_secs(300)..=ADMIN_COOKIE_MAX_LIFETIME).contains(&self.session_ttl)
            || Instant::now().checked_add(self.session_ttl).is_none()
        {
            return Err(ControlError::Configuration);
        }
        Ok(())
    }
}
/// Owns the genuine completed login. Recovery codes must be taken before async issuance.
/// ```compile_fail
/// fn clone<T: Clone>() {} clone::<broker_control::PreparedAdminLogin>();
/// ```
/// ```compile_fail
/// fn default<T: Default>() {} default::<broker_control::PreparedAdminLogin>();
/// ```
/// ```compile_fail
/// fn decode<T: serde::de::DeserializeOwned>() {} decode::<broker_control::PreparedAdminLogin>();
/// ```
pub struct PreparedAdminLogin {
    pub(crate) login: CompletedLocalLogin,
}
pub enum AdminLoginPreparationError {
    InvalidPurpose(CompletedLocalLogin),
    RecoveryCodesPending(CompletedLocalLogin),
}
impl AdminLoginPreparationError {
    pub fn into_login(self) -> CompletedLocalLogin {
        match self {
            Self::InvalidPurpose(v) | Self::RecoveryCodesPending(v) => v,
        }
    }
}
impl TryFrom<CompletedLocalLogin> for PreparedAdminLogin {
    type Error = AdminLoginPreparationError;
    fn try_from(login: CompletedLocalLogin) -> Result<Self, Self::Error> {
        if !matches!(login.purpose(), LocalAuthPurpose::AdminLogin) {
            return Err(AdminLoginPreparationError::InvalidPurpose(login));
        }
        if login.recovery_codes.is_some() {
            return Err(AdminLoginPreparationError::RecoveryCodesPending(login));
        }
        Ok(Self { login })
    }
}
impl fmt::Debug for PreparedAdminLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedAdminLogin([REDACTED])")
    }
}
impl fmt::Debug for AdminLoginPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPurpose(_) => "AdminLoginPreparationError::InvalidPurpose([REDACTED])",
            Self::RecoveryCodesPending(_) => {
                "AdminLoginPreparationError::RecoveryCodesPending([REDACTED])"
            }
        })
    }
}
impl fmt::Display for AdminLoginPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPurpose(_) => "administrative issuance requires an Admin login",
            Self::RecoveryCodesPending(_) => "administrative login still owns recovery codes",
        })
    }
}
impl std::error::Error for AdminLoginPreparationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminCookieSessionError {
    MalformedCookie,
    Unauthorized,
    Forbidden,
    CsrfFailed,
    Entropy,
    Control(ControlError),
}
impl From<ControlError> for AdminCookieSessionError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl From<AdminBrokerSessionError> for AdminCookieSessionError {
    fn from(value: AdminBrokerSessionError) -> Self {
        match value {
            AdminBrokerSessionError::Control(e) => Self::Control(e),
            AdminBrokerSessionError::Forbidden => Self::Forbidden,
            AdminBrokerSessionError::Entropy => Self::Entropy,
            AdminBrokerSessionError::Authentication(crate::BrokerAccessError::Deadline) => {
                Self::Control(ControlError::Deadline)
            }
            AdminBrokerSessionError::Authentication(_) => Self::Unauthorized,
        }
    }
}
impl fmt::Display for AdminCookieSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedCookie => f.write_str("invalid administrative cookie format"),
            Self::Unauthorized => f.write_str("administrative cookie authentication failed"),
            Self::Forbidden => f.write_str("administrative access denied"),
            Self::CsrfFailed => f.write_str("administrative CSRF verification failed"),
            Self::Entropy => f.write_str("administrative credential entropy unavailable"),
            Self::Control(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for AdminCookieSessionError {}

pub(crate) struct CookieClock {
    mono: Instant,
    utc: SystemTime,
}
impl CookieClock {
    pub(crate) fn capture() -> Self {
        let mono = Instant::now();
        Self {
            mono,
            utc: SystemTime::now(),
        }
    }
    pub(crate) fn utc(&self) -> SystemTime {
        self.utc
    }
    pub(crate) fn window(&self, expiry: SystemTime) -> Result<CookieWindow, ControlError> {
        // Validate before SQL issuance and before the SDK's infallible HTTP-date conversion.
        validate_http_expiry(expiry)?;
        let remaining = expiry.duration_since(self.utc).unwrap_or(Duration::ZERO);
        Ok(CookieWindow {
            expiry,
            mono: self
                .mono
                .checked_add(remaining)
                .ok_or(ControlError::Clock)?,
        })
    }
}
pub(crate) struct CookieWindow {
    expiry: SystemTime,
    mono: Instant,
}
impl CookieWindow {
    pub(crate) fn check(&self) -> Result<(), ControlError> {
        if Instant::now() >= self.mono || SystemTime::now() >= self.expiry {
            return Err(ControlError::SessionExpired);
        }
        Ok(())
    }
    pub(crate) fn expiry(&self) -> (SystemTime, Instant) {
        (self.expiry, self.mono)
    }
}
pub(crate) fn decode_secret(raw: &str) -> Result<Zeroizing<[u8; 32]>, AdminCookieSessionError> {
    if raw.len() != 43 {
        return Err(AdminCookieSessionError::Unauthorized);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    let size = URL_SAFE_NO_PAD
        .decode_slice(raw, bytes.as_mut())
        .map_err(|_| AdminCookieSessionError::Unauthorized)?;
    if size != 32 || URL_SAFE_NO_PAD.encode(bytes.as_ref()) != raw {
        return Err(AdminCookieSessionError::Unauthorized);
    }
    Ok(bytes)
}
pub(crate) fn new_secret() -> Result<Zeroizing<String>, AdminCookieSessionError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| AdminCookieSessionError::Entropy)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}
/// Can be emitted only after current authorization and known SQL COMMIT.
/// ```compile_fail
/// fn clone<T: Clone>() {} clone::<broker_control::IssuedAdminCookie>();
/// ```
/// ```compile_fail
/// fn default<T: Default>() {} default::<broker_control::IssuedAdminCookie>();
/// ```
/// ```compile_fail
/// fn decode<T: serde::de::DeserializeOwned>() {} decode::<broker_control::IssuedAdminCookie>();
/// ```
pub struct IssuedAdminCookie {
    pub(crate) raw: Zeroizing<String>,
    pub(crate) window: CookieWindow,
    pub(crate) original: Instant,
}
impl IssuedAdminCookie {
    pub fn check(&self) -> Result<(), AdminCookieSessionError> {
        check(self.original, &self.window)?;
        validate_http_expiry(self.window.expiry)?;
        Ok(())
    }
    pub fn secret(&self) -> &str {
        &self.raw
    }
    pub fn authentication_expiry(&self) -> (SystemTime, Instant) {
        self.window.expiry()
    }
}
/// Current session.read observation; never a lease for an administrative write.
/// ```compile_fail
/// fn clone<T: Clone>() {} clone::<broker_control::AdminCookieReadSession>();
/// ```
/// ```compile_fail
/// fn default<T: Default>() {} default::<broker_control::AdminCookieReadSession>();
/// ```
/// ```compile_fail
/// fn decode<T: serde::de::DeserializeOwned>() {} decode::<broker_control::AdminCookieReadSession>();
/// ```
pub struct AdminCookieReadSession {
    pub(crate) proof: crate::service::CookieReadProof,
    pub(crate) csrf: Zeroizing<String>,
    pub(crate) window: CookieWindow,
    pub(crate) original: Instant,
}
impl AdminCookieReadSession {
    pub fn check(&self) -> Result<(), AdminCookieSessionError> {
        check(self.original, &self.window)
    }
    pub fn profile(&self) -> &SessionProfile {
        self.proof.profile()
    }
    pub fn principal(&self) -> &SessionPrincipal {
        self.proof.principal()
    }
    pub fn roles(&self) -> &[String] {
        self.proof.roles()
    }
    pub fn permissions(&self) -> &[SystemPermission] {
        self.proof.permissions()
    }
    pub fn role_source(&self) -> &'static str {
        self.proof.role_source()
    }
    pub fn csrf_token(&self) -> &str {
        &self.csrf
    }
    pub fn authentication_expiry(&self) -> (SystemTime, Instant) {
        self.window.expiry()
    }
}
fn check(original: Instant, window: &CookieWindow) -> Result<(), AdminCookieSessionError> {
    if Instant::now() >= original {
        return Err(ControlError::Deadline.into());
    }
    window.check()?;
    Ok(())
}
/// Known commit observation. The browser clear operation never substitutes for this result.
pub struct AdminCookieLogout {
    pub(crate) original: Instant,
    pub(crate) disposition: AdminCookieLogoutDisposition,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminCookieLogoutDisposition {
    Revoked,
    Absent,
    Expired,
}
impl AdminCookieLogout {
    pub fn check(&self) -> Result<(), AdminCookieSessionError> {
        if Instant::now() >= self.original {
            return Err(ControlError::Deadline.into());
        }
        Ok(())
    }
    pub fn disposition(&self) -> AdminCookieLogoutDisposition {
        self.disposition
    }
}
macro_rules! redacted {
    ($($ty:ty),+) => {$(impl fmt::Debug for $ty {
        fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.write_str(concat!(stringify!($ty),"([REDACTED])")) }
    })+};
}
redacted!(IssuedAdminCookie, AdminCookieReadSession, AdminCookieLogout);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expiry_must_fit_the_resolved_http_date_sdk_before_issuance() {
        let upper = SystemTime::UNIX_EPOCH + Duration::from_secs(HTTP_DATE_EXCLUSIVE_SECONDS);
        let clock = CookieClock {
            mono: Instant::now(),
            utc: upper - Duration::from_secs(10),
        };
        assert!(clock.window(upper - Duration::from_micros(1)).is_ok());
        assert!(matches!(clock.window(upper), Err(ControlError::Clock)));
        assert!(matches!(
            clock.window(SystemTime::UNIX_EPOCH - Duration::from_secs(1)),
            Err(ControlError::Clock)
        ));
    }
    #[test]
    fn native_secret_codec_rejects_noncanonical_size_and_trailing_bits() {
        let raw = URL_SAFE_NO_PAD.encode([0u8; 32]);
        assert!(decode_secret(&raw).is_ok());
        for invalid in [
            format!("{raw}="),
            raw[..42].to_owned(),
            format!("{}B", &raw[..42]),
        ] {
            assert_eq!(
                decode_secret(&invalid).unwrap_err(),
                AdminCookieSessionError::Unauthorized
            );
        }
    }
}
