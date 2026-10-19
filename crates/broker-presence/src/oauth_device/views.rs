use super::{Error, browser_url, gate};
use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use broker_control::{
    ControlError, DeviceConsent, DeviceError, LocalAuthError, LocalAuthStage,
    LocalCaptchaChallenge, LocalCaptchaProvider, LocalPasswordAdmissionError,
    OidcTokenExchangeError as Protocol, PendingLocalAuth,
};
use broker_security::LocalPasswordError;
use minijinja::{AutoEscape, Environment, context};
use std::time::{Duration, Instant};
const DEVICE: &str = concat!(
    include_str!("../templates/oauth/head.html"),
    include_str!("../templates/oauth/device.html"),
    include_str!("../templates/oauth/browser.html"),
    "{% endif %}",
    include_str!("../templates/oauth/foot.html")
);
pub(super) struct PasswordPresentation {
    pub challenge: Option<LocalCaptchaChallenge>,
}
pub(super) struct Views {
    env: Environment<'static>,
}
impl Views {
    pub fn new() -> Result<Self, ControlError> {
        let mut env = Environment::new();
        env.set_auto_escape_callback(|_| AutoEscape::Html);
        env.add_template("device.html", DEVICE)
            .map_err(|_| ControlError::Configuration)?;
        Ok(Self { env })
    }
    fn render(
        &self,
        value: minijinja::Value,
        error: Option<&Error>,
        provider: Option<LocalCaptchaProvider>,
        end: Instant,
    ) -> Result<Response, Error> {
        gate(end)?;
        let html = self
            .env
            .get_template("device.html")
            .and_then(|t| t.render(value))
            .map_err(|_| ControlError::Configuration)?;
        let mut response = crate::oauth_browser::views::html_response(html, "'self'", provider)?;
        if let Some(e) = error {
            apply_error(&mut response, e);
        }
        gate(end)?;
        Ok(response)
    }
    pub fn entry(&self, error: Option<&Error>, end: Instant) -> Result<Response, Error> {
        self.render(context! {title=>"Sign in on your device", stage=>"entry", error=>error.map(|e|detail(e).1)}, error, None, end)
    }
    pub fn login(
        &self,
        code: &str,
        presentation: PasswordPresentation,
        feedback: Option<(&Error, &str)>,
        end: Instant,
    ) -> Result<Response, Error> {
        let error = feedback.map(|(e, _)| e);
        let username = feedback.map_or("", |(_, u)| if u.len() <= 128 { u } else { "" });
        let captcha = presentation.challenge;
        self.render(context! {title=>"Sign in to your device", stage=>"password", user_code=>display(code),
            action=>browser_url(code), local=>true, username=>username, captcha=>captcha.as_ref(), error=>error.map(|e|detail(e).1)},
            error, captcha.as_ref().map(|c| c.provider()), end)
    }
    pub fn pending(
        &self,
        code: &str,
        pending: &PendingLocalAuth,
        error: Option<&Error>,
        end: Instant,
    ) -> Result<Response, Error> {
        let (title, stage) = match pending.stage() {
            LocalAuthStage::PasswordChange => ("Choose a new password", "password-change"),
            LocalAuthStage::Mfa => ("Verify your sign-in", "mfa"),
            LocalAuthStage::Enrollment => ("Set up two-step verification", "enrollment"),
        };
        let enrollment = pending.enrollment();
        self.render(context! {title=>title, stage=>stage, user_code=>display(code), action=>browser_url(code),
            challenge=>pending.challenge(), error=>error.map(|e|detail(e).1),
            secret=>enrollment.map(|e|e.secret()), qr=>enrollment.map(|e|e.qr_data_url()), otpauth=>enrollment.map(|e|e.otpauth_uri())},
            error, None, end)
    }
    pub fn consent(&self, mut consent: DeviceConsent, end: Instant) -> Result<Response, Error> {
        let recovery = consent.take_recovery_codes();
        let codes: Vec<_> = recovery
            .as_ref()
            .map(|r| r.iter().collect())
            .unwrap_or_default();
        let secret = consent.secret(end)?;
        let response = self.render(
            context! {title=>"Review device sign-in", stage=>"consent",
            user_code=>display(consent.user_code()), client=>consent.client_id(), codes=>codes,
            action=>browser_url(consent.user_code()), consent_secret=>secret},
            None,
            None,
            end,
        )?;
        consent.secret(end)?;
        Ok(response)
    }
    pub fn decided(&self, allow: bool, end: Instant) -> Result<Response, Error> {
        self.render(
            context! {title=>if allow {"Device sign-in allowed"} else {"Device sign-in denied"},
            stage=>"decided", allowed=>allow},
            None,
            None,
            end,
        )
    }
    pub fn failure(&self, error: &Error) -> Response {
        let html = self.env.get_template("device.html").and_then(|t| {
            t.render(context! {
                title=>"Device sign-in could not continue", stage=>"error", error=>detail(error).1
            })
        });
        let mut response = html
            .ok()
            .and_then(|h| crate::oauth_browser::views::html_response(h, "'self'", None).ok())
            .unwrap_or_else(|| {
                let mut r = Response::new(Body::from(
                    "Device sign-in is unavailable. Restart from your device.",
                ));
                crate::oauth_response::privacy_headers(&mut r);
                r
            });
        apply_error(&mut response, error);
        response
    }
}
fn display(code: &str) -> String {
    if code.len() == 8 && code.is_ascii() {
        format!("{}-{}", &code[..4], &code[4..])
    } else {
        code.to_owned()
    }
}
fn control(c: ControlError) -> (StatusCode, &'static str, Option<Duration>) {
    match c {
        ControlError::Deadline => (
            StatusCode::GATEWAY_TIMEOUT,
            "Sign-in took too long. Start again from your device.",
            None,
        ),
        ControlError::OutcomeUncertain => (
            StatusCode::SERVICE_UNAVAILABLE,
            "The result could not be confirmed. Start again from your device.",
            None,
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Device sign-in is unavailable. Try again from your device.",
            None,
        ),
    }
}
fn limited(d: Duration) -> (StatusCode, &'static str, Option<Duration>) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        "Too many sign-in attempts. Wait before trying again.",
        Some(d),
    )
}
fn detail(e: &Error) -> (StatusCode, &'static str, Option<Duration>) {
    match e {
        Error::Input(s) => (
            *s,
            "Check the device code and sign-in fields, then try again.",
            None,
        ),
        Error::Control(c)
        | Error::Auth(LocalAuthError::Control(c))
        | Error::Admission(LocalPasswordAdmissionError::Control(c))
        | Error::Device(DeviceError::Protocol(Protocol::Control(c))) => control(*c),
        Error::Admission(LocalPasswordAdmissionError::RateLimited(d))
        | Error::Auth(LocalAuthError::MfaRateLimited(d)) => limited(*d),
        Error::Auth(LocalAuthError::MfaBusy) => limited(Duration::from_secs(1)),
        Error::Admission(LocalPasswordAdmissionError::CaptchaRequired(_)) => (
            StatusCode::FORBIDDEN,
            "Complete the verification below and try signing in again.",
            None,
        ),
        Error::Auth(
            LocalAuthError::Unauthenticated
            | LocalAuthError::InvalidChallenge
            | LocalAuthError::InvalidMfaCode,
        )
        | Error::Admission(LocalPasswordAdmissionError::Unauthenticated) => (
            StatusCode::UNAUTHORIZED,
            "The credentials or verification code are invalid. Try again or restart sign-in.",
            None,
        ),
        Error::Auth(
            LocalAuthError::PasswordUnchanged
            | LocalAuthError::Password(LocalPasswordError::InvalidPassword),
        ) => (
            StatusCode::BAD_REQUEST,
            "Choose a different password with at least 15 characters and confirm it exactly.",
            None,
        ),
        Error::Admission(LocalPasswordAdmissionError::LocalAuth(e)) => auth_detail(e),
        Error::Device(DeviceError::Protocol(Protocol::InvalidClient)) => (
            StatusCode::UNAUTHORIZED,
            "This device request does not match the application. Start again from your device.",
            None,
        ),
        Error::Device(
            DeviceError::ExpiredToken
            | DeviceError::AccessDenied
            | DeviceError::Protocol(
                Protocol::InvalidRequest | Protocol::InvalidGrant | Protocol::InvalidScope,
            ),
        ) => (
            StatusCode::BAD_REQUEST,
            "This device request is invalid or expired. Start again from your device.",
            None,
        ),
        Error::Device(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Device sign-in could not continue. Start again from your device.",
            None,
        ),
        _ => control(ControlError::Unavailable),
    }
}
fn apply_error(r: &mut Response, e: &Error) {
    let (status, _, retry) = detail(e);
    *r.status_mut() = status;
    if let Some(d) = retry {
        let s = d
            .as_secs()
            .saturating_add(u64::from(d.subsec_nanos() != 0))
            .max(1);
        if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
            r.headers_mut().insert(header::RETRY_AFTER, v);
        }
    }
}

fn auth_detail(e: &LocalAuthError) -> (StatusCode, &'static str, Option<Duration>) {
    match e {
        LocalAuthError::Control(c) => control(*c),
        LocalAuthError::MfaRateLimited(d) => limited(*d),
        LocalAuthError::MfaBusy => limited(Duration::from_secs(1)),
        LocalAuthError::Unauthenticated
        | LocalAuthError::InvalidChallenge
        | LocalAuthError::InvalidMfaCode => (
            StatusCode::UNAUTHORIZED,
            "The credentials or verification code are invalid. Try again or restart sign-in.",
            None,
        ),
        LocalAuthError::PasswordUnchanged
        | LocalAuthError::Password(LocalPasswordError::InvalidPassword) => (
            StatusCode::BAD_REQUEST,
            "Choose a different password with at least 15 characters and confirm it exactly.",
            None,
        ),
        _ => control(ControlError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn native_device_template_compiles_without_optional_include_feature() {
        let v = Views::new().unwrap();
        let r = v
            .entry(None, Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let b = axum::body::to_bytes(r.into_body(), 32768).await.unwrap();
        let h = std::str::from_utf8(&b).unwrap();
        assert!(h.contains("name=\"user_code\"") && h.contains("data-ui=\"graphit-auth\""));
    }
}
