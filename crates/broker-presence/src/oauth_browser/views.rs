use super::{Error, gate, login_url};
use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use broker_control::{
    ControlError, LocalAuthError, LocalAuthStage, LocalCaptchaChallenge, LocalCaptchaProvider,
    LocalPasswordAdmissionError, PendingLocalAuth, UpstreamBrowserOption, UpstreamLoginFailure,
};
use broker_security::LocalPasswordError;
use minijinja::{AutoEscape, Environment, context};
use std::time::{Duration, Instant};

const BROWSER: &str = concat!(
    include_str!("../templates/oauth/head.html"),
    include_str!("../templates/oauth/browser.html"),
    include_str!("../templates/oauth/foot.html")
);
pub(crate) const RECOVERY: &str = concat!(
    include_str!("../templates/oauth/head.html"),
    include_str!("../templates/oauth/recovery.html"),
    include_str!("../templates/oauth/foot.html")
);
// Display-only data obtained from the current concrete LOCAL startup owner.
pub(super) struct PasswordPresentation {
    pub(super) challenge: Option<LocalCaptchaChallenge>,
}
pub(super) struct Views {
    environment: Environment<'static>,
}
impl Views {
    pub fn new() -> Result<Self, ControlError> {
        let mut environment = Environment::new();
        environment.set_auto_escape_callback(|_| AutoEscape::Html);
        environment
            .add_template("browser.html", BROWSER)
            .map_err(|_| ControlError::Configuration)?;
        Ok(Self { environment })
    }
    fn render(
        &self,
        values: minijinja::Value,
        error: Option<&Error>,
        provider: Option<LocalCaptchaProvider>,
        origin: &str,
        end: Instant,
    ) -> Result<Response, Error> {
        gate(end)?;
        let html = self
            .environment
            .get_template("browser.html")
            .and_then(|t| t.render(values))
            .map_err(|_| ControlError::Configuration)?;
        let mut response = html_response(html, &format!("'self' {origin}"), provider)?;
        if let Some(error) = error {
            apply_error(&mut response, error);
        }
        gate(end)?;
        Ok(response)
    }
    pub fn login(
        &self,
        id: &str,
        origin: &str,
        local: Option<PasswordPresentation>,
        options: &[UpstreamBrowserOption],
        feedback: Option<(&Error, &str)>,
        end: Instant,
    ) -> Result<Response, Error> {
        let error = feedback.map(|(error, _)| error);
        let username = feedback.map_or(
            "",
            |(_, username)| if username.len() <= 128 { username } else { "" },
        );
        if local.is_none() && options.is_empty() {
            return Err(ControlError::Unavailable.into());
        }
        let local_available = local.is_some();
        let challenge = local.and_then(|p| p.challenge);
        let providers: Vec<_> = options
            .iter()
            .map(|p| {
                let query = form_urlencoded::Serializer::new(String::new())
                    .append_pair("id", id)
                    .append_pair("login_method", "oidc")
                    .append_pair("provider", &p.id)
                    .finish();
                context! {name => &p.name, url => format!("/oauth/login?{query}")}
            })
            .collect();
        self.render(
            context! {
                title => "Sign in to your application", stage => "password", origin => origin,
                action => login_url(id), local => local_available, providers => providers, username => username,
                error => error.map(message), captcha => challenge.as_ref(),
            },
            error,
            challenge.as_ref().map(|c| c.provider()),
            origin,
            end,
        )
    }
    pub fn pending(
        &self,
        id: &str,
        origin: &str,
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
        self.render(
            context! {
                title => title, stage => stage, origin => origin, action => login_url(id),
                challenge => pending.challenge(), error => error.map(message),
                secret => enrollment.map(|e| e.secret()), qr => enrollment.map(|e| e.qr_data_url()),
                otpauth => enrollment.map(|e| e.otpauth_uri()),
            },
            error,
            None,
            origin,
            end,
        )
    }
    pub fn failure(&self, error: &Error, id: Option<&str>) -> Response {
        // An expired request may still receive a finite local error, never an OAuth result.
        let values = context! {title => "Sign-in could not continue", stage => "error", error => message(error), restart => id.map(login_url)};
        let result = self
            .environment
            .get_template("browser.html")
            .and_then(|t| t.render(values));
        let mut response = result
            .ok()
            .and_then(|html| html_response(html, "'self'", None).ok())
            .unwrap_or_else(unavailable);
        apply_error(&mut response, error);
        response
    }
}
pub(super) fn unavailable() -> Response {
    let mut response = Response::new(Body::from(
        "Sign-in is unavailable. Restart sign-in from your application.",
    ));
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    super::super::oauth_response::privacy_headers(&mut response);
    response
}
pub(crate) fn html_response(
    html: String,
    form_origin: &str,
    provider: Option<LocalCaptchaProvider>,
) -> Result<Response, ControlError> {
    let (scripts, frames, connect) = match provider {
        None => ("'none'", "'none'", "'none'"),
        Some(LocalCaptchaProvider::Turnstile) => (
            "https://challenges.cloudflare.com",
            "https://challenges.cloudflare.com",
            "'none'",
        ),
        Some(LocalCaptchaProvider::Recaptcha) => (
            "https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/",
            "https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/",
            "https://www.google.com/recaptcha/",
        ),
    };
    let csp = format!(
        "default-src 'none'; script-src {scripts}; style-src 'unsafe-inline'; img-src data:; connect-src {connect}; frame-src {frames}; form-action {form_origin}; frame-ancestors 'none'; base-uri 'none'"
    );
    let mut response = Response::new(Body::from(html));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_str(&csp).map_err(|_| ControlError::Configuration)?,
    );
    super::super::oauth_response::privacy_headers(&mut response);
    Ok(response)
}
fn control(error: ControlError) -> (StatusCode, &'static str, Option<Duration>) {
    match error {
        ControlError::Deadline => (
            StatusCode::GATEWAY_TIMEOUT,
            "Sign-in took too long. Restart sign-in from your application.",
            None,
        ),
        ControlError::OutcomeUncertain => (
            StatusCode::SERVICE_UNAVAILABLE,
            "The sign-in result could not be confirmed. Restart sign-in from your application.",
            None,
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Sign-in is unavailable. Try again from your application.",
            None,
        ),
    }
}
fn auth(error: &LocalAuthError) -> (StatusCode, &'static str, Option<Duration>) {
    match error {
        LocalAuthError::Control(e) => control(*e),
        LocalAuthError::Unauthenticated
        | LocalAuthError::InvalidChallenge
        | LocalAuthError::InvalidMfaCode => (
            StatusCode::UNAUTHORIZED,
            "The credentials or sign-in challenge are invalid. Try again or restart sign-in.",
            None,
        ),
        LocalAuthError::PasswordUnchanged
        | LocalAuthError::Password(LocalPasswordError::InvalidPassword) => (
            StatusCode::BAD_REQUEST,
            "Choose a different password with at least 15 characters and confirm it exactly.",
            None,
        ),
        LocalAuthError::MfaRateLimited(d) => limited(*d),
        LocalAuthError::MfaBusy => limited(Duration::from_secs(1)),
        _ => control(ControlError::Unavailable),
    }
}
fn limited(duration: Duration) -> (StatusCode, &'static str, Option<Duration>) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        "Too many sign-in attempts. Wait before trying again.",
        Some(duration),
    )
}
fn detail(error: &Error) -> (StatusCode, &'static str, Option<Duration>) {
    match error {
        Error::Input(status) => (
            *status,
            "The sign-in form is invalid. Check the fields or restart sign-in from your application.",
            None,
        ),
        Error::Control(e)
        | Error::Authorization(broker_control::OidcAuthorizationError::Control(e))
        | Error::Admission(LocalPasswordAdmissionError::Control(e)) => control(*e),
        Error::Auth(e) | Error::Admission(LocalPasswordAdmissionError::LocalAuth(e)) => auth(e),
        Error::Admission(LocalPasswordAdmissionError::Unauthenticated) => {
            auth(&LocalAuthError::Unauthenticated)
        }
        Error::Admission(LocalPasswordAdmissionError::CaptchaRequired(_)) => (
            StatusCode::FORBIDDEN,
            "Complete the verification below and try signing in again.",
            None,
        ),
        Error::Admission(LocalPasswordAdmissionError::RateLimited(d)) => limited(*d),
        Error::Authorization(
            broker_control::OidcAuthorizationError::InvalidRequest
            | broker_control::OidcAuthorizationError::InvalidClient
            | broker_control::OidcAuthorizationError::InvalidRedirect
            | broker_control::OidcAuthorizationError::InvalidScope
            | broker_control::OidcAuthorizationError::InvalidTarget
            | broker_control::OidcAuthorizationError::LoginRequired,
        ) => (
            StatusCode::BAD_REQUEST,
            "This sign-in request is invalid or expired. Restart sign-in from your application.",
            None,
        ),
        Error::Upstream(e) => match e.failure() {
            UpstreamLoginFailure::Control(c) => control(c),
            _ => control(ControlError::Unavailable),
        },
        _ => control(ControlError::Unavailable),
    }
}
fn message(error: &Error) -> &'static str {
    detail(error).1
}
fn apply_error(response: &mut Response, error: &Error) {
    let (status, _, retry) = detail(error);
    *response.status_mut() = status;
    if let Some(d) = retry {
        let seconds = d
            .as_secs()
            .saturating_add(u64::from(d.subsec_nanos() != 0))
            .max(1);
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn canonical_browser_templates_compile() {
        let views = Views::new().unwrap();
        let response = views.failure(&Error::Input(StatusCode::BAD_REQUEST), None);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.starts_with("<!doctype html>")
                && html.contains("<h1>Sign-in could not continue</h1>")
        );
        super::super::super::oauth_response::OAuthResponseRenderer::new().unwrap();
    }
}
