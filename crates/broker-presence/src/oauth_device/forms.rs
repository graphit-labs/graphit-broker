use super::{Error, gate};
use axum::{
    body::to_bytes,
    extract::Request,
    http::{Method, StatusCode, header},
};
use headers::{ContentType, Header};
use std::{collections::BTreeMap, time::Instant};
use zeroize::Zeroizing;

pub(super) const API: &[&str] = &[
    "client_id",
    "scope",
    "client_secret",
    "client_assertion",
    "client_assertion_type",
    "resource",
    "redirect_uri",
    "grant_type",
    "device_code",
    "user_code",
    "code",
    "refresh_token",
    "code_verifier",
    "response_type",
];
const LOGIN: &[&str] = &[
    "username",
    "password",
    "login_method",
    "challenge_token",
    "new_password",
    "confirm_password",
    "code",
    "cf-turnstile-response",
    "g-recaptcha-response",
];
const DECISION: &[&str] = &["client_id", "consent_secret", "decision"];
const FOREIGN: &[&str] = &[
    "id",
    "provider",
    "resource",
    "scope",
    "login_token",
    "access_token",
    "client_secret",
    "client_assertion",
    "client_assertion_type",
    "redirect_uri",
    "device_code",
    "grant_type",
    "response_type",
    "code_verifier",
    "refresh_token",
];
#[derive(Default)]
pub(super) struct Fields {
    values: BTreeMap<String, Zeroizing<String>>,
}
impl Fields {
    pub fn get(&self, k: &str) -> &str {
        self.optional(k).unwrap_or("")
    }
    pub fn optional(&self, k: &str) -> Option<&str> {
        self.values.get(k).map(|v| v.as_str())
    }
    pub fn has_login_fields(&self) -> bool {
        LOGIN.iter().any(|k| self.optional(k).is_some())
    }
    fn append(&mut self, raw: &[u8], query: bool, post: bool) -> Result<(), Error> {
        let text = std::str::from_utf8(raw).map_err(|_| Error::Input(StatusCode::BAD_REQUEST))?;
        percent_encoding::percent_decode_str(text)
            .decode_utf8()
            .map_err(|_| Error::Input(StatusCode::BAD_REQUEST))?;
        for (k, v) in form_urlencoded::parse(raw) {
            let known = k == "user_code"
                || LOGIN.contains(&k.as_ref())
                || DECISION.contains(&k.as_ref())
                || FOREIGN.contains(&k.as_ref());
            if !known {
                continue;
            }
            let allowed = if query {
                k == "user_code"
            } else {
                post && k != "user_code"
                    && (LOGIN.contains(&k.as_ref()) || DECISION.contains(&k.as_ref()))
            };
            if !allowed
                || self
                    .values
                    .insert(k.into_owned(), Zeroizing::new(v.into_owned()))
                    .is_some()
            {
                return Err(Error::Input(StatusCode::BAD_REQUEST));
            }
        }
        Ok(())
    }
}
pub(super) async fn read(request: Request, cap: usize, end: Instant) -> Result<Fields, Error> {
    gate(end)?;
    let (parts, body) = request.into_parts();
    if parts.headers.contains_key(header::AUTHORIZATION) {
        return Err(Error::Input(StatusCode::BAD_REQUEST));
    }
    let query = parts.uri.query().unwrap_or("");
    if query.len() > cap {
        return Err(Error::Input(StatusCode::BAD_REQUEST));
    }
    let post = parts.method == Method::POST;
    let mut fields = Fields::default();
    fields.append(query.as_bytes(), true, post)?;
    let body = tokio::time::timeout_at(end.into(), to_bytes(body, cap - query.len()))
        .await
        .map_err(|_| broker_control::ControlError::Deadline)?
        .map_err(|_| Error::Input(StatusCode::BAD_REQUEST))?;
    let body = Zeroizing::new(body.to_vec());
    if !body.is_empty() {
        if !post {
            return Err(Error::Input(StatusCode::BAD_REQUEST));
        }
        let mut types = parts.headers.get_all(header::CONTENT_TYPE).iter();
        let first = types
            .next()
            .ok_or(Error::Input(StatusCode::UNSUPPORTED_MEDIA_TYPE))?;
        if types.next().is_some() {
            return Err(Error::Input(StatusCode::UNSUPPORTED_MEDIA_TYPE));
        }
        let content = ContentType::decode(&mut std::iter::once(first))
            .map_err(|_| Error::Input(StatusCode::UNSUPPORTED_MEDIA_TYPE))?;
        if content.to_string().split(';').next() != Some("application/x-www-form-urlencoded") {
            return Err(Error::Input(StatusCode::UNSUPPORTED_MEDIA_TYPE));
        }
        fields.append(&body, false, true)?;
    }
    gate(end)?;
    Ok(fields)
}
