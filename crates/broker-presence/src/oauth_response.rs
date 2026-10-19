use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use broker_control::{
    AuthorizedOidcAuthorization, ControlError, OidcAuthorizationError as Error,
    OidcAuthorizationResponseMode as Mode, OidcAuthorizationResponseTarget,
    RejectedOidcAuthorization,
};
use broker_security::LocalRecoveryCodes;
use minijinja::{AutoEscape, Environment, context};
use std::time::Instant;

const FORM_POST: &str = include_str!("templates/oauth/form_post.html");
const SCRIPT_HASH: &str = "sha256-cXWgDurDk3e3+yXIIbDNyS1KkGGxuTkkAzw1U31Ay94=";

pub(crate) struct OAuthResponseRenderer {
    environment: Environment<'static>,
}
impl OAuthResponseRenderer {
    pub(crate) fn new() -> Result<Self, Error> {
        let mut environment = Environment::new();
        environment.set_auto_escape_callback(|_| AutoEscape::Html);
        environment
            .add_template("form-post.html", FORM_POST)
            .map_err(|_| Error::InvalidConfiguration)?;
        environment
            .add_template("recovery.html", super::oauth_browser::views::RECOVERY)
            .map_err(|_| Error::InvalidConfiguration)?;
        Ok(Self { environment })
    }
    pub(crate) fn authorized(
        &self,
        authorized: AuthorizedOidcAuthorization,
        original: Instant,
    ) -> Result<Response, Error> {
        let target = authorized.info().response_target(original)?;
        self.respond(&target, "code", authorized.code())
    }
    pub(crate) fn denied(
        &self,
        target: OidcAuthorizationResponseTarget<'_>,
    ) -> Result<Response, Error> {
        self.respond(&target, "error", "access_denied")
    }
    pub(crate) fn rejected(
        &self,
        rejected: RejectedOidcAuthorization<'_>,
    ) -> Result<Response, Error> {
        let code = rejected.code().as_str();
        self.respond(&rejected.into_target(), "error", code)
    }
    pub(crate) fn recovery(
        &self,
        authorized: AuthorizedOidcAuthorization,
        codes: LocalRecoveryCodes,
        original: Instant,
    ) -> Result<Response, Error> {
        let target = authorized.info().response_target(original)?;
        if target.response_mode() == Mode::FormPost && target.state().contains(['\0', '\r', '\n']) {
            return Err(Error::InvalidRequest);
        }
        let fields = [("code", authorized.code()), ("state", target.state())];
        target.check()?;
        let location = if target.response_mode() == Mode::FormPost {
            None
        } else {
            Some(response_location(
                target.redirect_uri(),
                target.response_mode(),
                &fields,
            ))
        };
        let values: Vec<_> = codes.iter().collect();
        let html = self.environment.get_template("recovery.html")
            .and_then(|t| t.render(context! {title => "Save your recovery codes", origin => target.origin(), codes => values, location => location, redirect => target.redirect_uri(), fields => fields}))
            .map_err(|_| ControlError::Configuration)?;
        let response = super::oauth_browser::views::html_response(html, target.origin(), None)?;
        target.check()?;
        Ok(response)
    }
    fn respond(
        &self,
        target: &OidcAuthorizationResponseTarget<'_>,
        field: &str,
        value: &str,
    ) -> Result<Response, Error> {
        target.check()?;
        let mut fields = vec![(field, value)];
        if !target.state().is_empty() {
            fields.push(("state", target.state()));
        }
        let mut response = match target.response_mode() {
            Mode::Query | Mode::Fragment => {
                let location =
                    response_location(target.redirect_uri(), target.response_mode(), &fields);
                let location =
                    HeaderValue::from_str(&location).map_err(|_| Error::InvalidRedirect)?;
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::SEE_OTHER;
                response.headers_mut().insert(header::LOCATION, location);
                response
            }
            Mode::FormPost => {
                if target.state().contains(['\0', '\r', '\n']) {
                    return Err(Error::InvalidRequest);
                }
                let html = self.render_form(target.redirect_uri(), target.origin(), &fields)?;
                let mut response = Response::new(Body::from(html));
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                );
                let policy = format!(
                    "default-src 'none'; script-src '{SCRIPT_HASH}'; style-src 'unsafe-inline'; form-action {}; frame-ancestors 'none'; base-uri 'none'",
                    target.origin()
                );
                response.headers_mut().insert(
                    "content-security-policy",
                    HeaderValue::from_str(&policy).map_err(|_| Error::InvalidRedirect)?,
                );
                response
            }
        };
        privacy_headers(&mut response);
        target.check()?;
        Ok(response)
    }
    fn render_form(
        &self,
        redirect: &str,
        origin: &str,
        fields: &[(&str, &str)],
    ) -> Result<String, Error> {
        self.environment
            .get_template("form-post.html")
            .and_then(|template| {
                template.render(context! {redirect => redirect, origin => origin, fields => fields})
            })
            .map_err(|_| ControlError::Configuration.into())
    }
}
fn response_location(redirect: &str, mode: Mode, fields: &[(&str, &str)]) -> String {
    let fields = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish();
    let delimiter = if mode == Mode::Fragment {
        "#"
    } else if redirect.contains('?') {
        if redirect.ends_with(['?', '&']) {
            ""
        } else {
            "&"
        }
    } else {
        "?"
    };
    format!("{redirect}{delimiter}{fields}")
}
pub(crate) fn privacy_headers(response: &mut Response) {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    #[test]
    fn redirects_preserve_literal_target_and_state() {
        let state = " state\0\r\n café%<& ";
        for (redirect, mode, expected) in [
            (
                "https://rp.example/%2f?kept=%2F",
                Mode::Query,
                "https://rp.example/%2f?kept=%2F&",
            ),
            (
                "https://rp.example/%2f?kept=%2F",
                Mode::Fragment,
                "https://rp.example/%2f?kept=%2F#",
            ),
            (
                "https://rp.example/cb?",
                Mode::Query,
                "https://rp.example/cb?",
            ),
        ] {
            let location =
                response_location(redirect, mode, &[("code", "value"), ("state", state)]);
            assert!(location.starts_with(expected));
            let values: Vec<_> =
                form_urlencoded::parse(location.strip_prefix(expected).unwrap().as_bytes())
                    .collect();
            assert_eq!(values[1].1, state);
        }
    }
    #[test]
    fn form_post_escapes_values_and_script_hash_matches_static_source() {
        let renderer = OAuthResponseRenderer::new().unwrap();
        let malicious = "\"><script>window.pwned=1</script>&' café";
        let html = renderer
            .render_form(
                "https://rp.example/cb?x=\"&q='",
                "https://rp.example",
                &[("code", "opaque"), ("state", malicious)],
            )
            .unwrap();
        assert!(!html.contains(malicious));
        assert!(!html.contains("<script>window.pwned"));
        assert!(html.contains("&lt;script&gt;"));
        assert_eq!(html.matches("<script>").count(), 1);
        let script = FORM_POST
            .split_once("<script>")
            .unwrap()
            .1
            .split_once("</script>")
            .unwrap()
            .0;
        assert_eq!(
            format!(
                "sha256-{}",
                STANDARD.encode(Sha256::digest(script.as_bytes()))
            ),
            SCRIPT_HASH
        );
        assert!(!html.contains("javascript:"));
    }
}
