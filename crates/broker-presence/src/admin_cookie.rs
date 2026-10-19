//! Header emission consumes only a genuine committed administrative cookie proof.
use axum::http::HeaderValue;
use broker_control::{
    AdminCookieSessionError, AdminCookieSessionLimits, AdminCookieSessionPolicy, ControlError,
    IssuedAdminCookie,
};
use headers::{Expires, Header};
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Copy, Debug)]
pub struct AdminCookieHttpConfig {
    pub limits: AdminCookieSessionLimits,
    pub policy: AdminCookieSessionPolicy,
    pub secure: bool,
}
impl AdminCookieHttpConfig {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.limits.validate()?;
        self.policy.validate()?;
        if self.limits.metadata.max_lifetime < self.policy.session_ttl {
            return Err(ControlError::Configuration);
        }
        Ok(())
    }
}
pub fn admin_cookie_header(
    cookie: &IssuedAdminCookie,
    secure: bool,
) -> Result<HeaderValue, AdminCookieSessionError> {
    cookie.check()?;
    let (utc, mono) = cookie.authentication_expiry();
    let remaining = utc
        .duration_since(SystemTime::now())
        .map_err(|_| ControlError::SessionExpired)?
        .min(mono.saturating_duration_since(Instant::now()))
        .as_secs();
    let header = header(cookie.secret(), utc, remaining, secure)?;
    cookie.check()?;
    Ok(header)
}
pub(super) fn clear_cookie_header(secure: bool) -> Result<HeaderValue, ControlError> {
    header(
        "",
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        0,
        secure,
    )
}
fn header(
    raw: &str,
    expiry: SystemTime,
    seconds: u64,
    secure: bool,
) -> Result<HeaderValue, ControlError> {
    let mut values = Vec::new();
    Expires::from(expiry).encode(&mut values);
    let date = values
        .first()
        .and_then(|v| v.to_str().ok())
        .ok_or(ControlError::Clock)?;
    let mut value=HeaderValue::from_str(&format!("graphit_admin_session={raw}; Path=/; HttpOnly; SameSite=Lax; Expires={date}; Max-Age={seconds}{}",if secure { "; Secure" } else { "" }))
        .map_err(|_|ControlError::InvalidSession)?;
    value.set_sensitive(true);
    Ok(value)
}
