use super::Error;
use axum::{
    body::to_bytes,
    extract::Request,
    http::{Method, StatusCode, header},
};
use headers::{ContentType, Header};
use std::{collections::BTreeMap, time::Instant};
use zeroize::Zeroizing;

const AUTHORIZE: &[&str] = &[
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "response_mode",
    "prompt",
    "resource",
];
const LOGIN: &[&str] = &[
    "id",
    "login_method",
    "provider",
    "username",
    "password",
    "challenge_token",
    "new_password",
    "confirm_password",
    "code",
    "cf-turnstile-response",
    "g-recaptcha-response",
];

#[derive(Default)]
pub(super) struct Fields {
    values: BTreeMap<String, Zeroizing<String>>,
    pub resources: Vec<Zeroizing<String>>,
}
impl Fields {
    pub fn get(&self, name: &str) -> &str {
        self.optional(name).unwrap_or("")
    }
    pub fn optional(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(|s| s.as_str())
    }
    fn append(
        &mut self,
        raw: &[u8],
        known: &[&str],
        allowed: &[&str],
        resource: bool,
    ) -> Result<(), Error> {
        let utf8 = std::str::from_utf8(raw).map_err(|_| Error::Input(StatusCode::BAD_REQUEST))?;
        percent_encoding::percent_decode_str(utf8)
            .decode_utf8()
            .map_err(|_| Error::Input(StatusCode::BAD_REQUEST))?;
        for (key, value) in form_urlencoded::parse(raw) {
            if !known.contains(&key.as_ref()) {
                continue;
            }
            if !allowed.contains(&key.as_ref()) {
                return Err(Error::Input(StatusCode::BAD_REQUEST));
            }
            if resource && key == "resource" {
                self.resources.push(Zeroizing::new(value.into_owned()));
            } else if self
                .values
                .insert(key.into_owned(), Zeroizing::new(value.into_owned()))
                .is_some()
            {
                return Err(Error::Input(StatusCode::BAD_REQUEST));
            }
        }
        Ok(())
    }
}
pub(super) async fn read(
    request: Request,
    authorize: bool,
    cap: usize,
    original: Instant,
) -> Result<Fields, Error> {
    super::gate(original)?;
    let (parts, body) = request.into_parts();
    let query = parts.uri.query().unwrap_or("");
    if query.len() > cap {
        return Err(Error::Input(StatusCode::BAD_REQUEST));
    }
    let post = parts.method == Method::POST;
    let known = if authorize { AUTHORIZE } else { LOGIN };
    let query_allowed: &[&str] = if authorize {
        AUTHORIZE
    } else if post {
        &["id"]
    } else {
        &["id", "login_method", "provider"]
    };
    let mut fields = Fields::default();
    fields.append(query.as_bytes(), known, query_allowed, authorize)?;
    let bytes = tokio::time::timeout_at(original.into(), to_bytes(body, cap - query.len()))
        .await
        .map_err(|_| broker_control::ControlError::Deadline)?
        .map_err(|_| Error::Input(StatusCode::BAD_REQUEST))?;
    let bytes = Zeroizing::new(bytes.to_vec());
    if post && !bytes.is_empty() {
        let mut types = parts.headers.get_all(header::CONTENT_TYPE).iter();
        let content = ContentType::decode(&mut types)
            .map_err(|_| Error::Input(StatusCode::UNSUPPORTED_MEDIA_TYPE))?;
        if types.next().is_some()
            || content.to_string().split(';').next() != Some("application/x-www-form-urlencoded")
        {
            return Err(Error::Input(StatusCode::UNSUPPORTED_MEDIA_TYPE));
        }
        let allowed: Vec<_> = known
            .iter()
            .copied()
            .filter(|key| authorize || *key != "id")
            .collect();
        fields.append(&bytes, known, &allowed, authorize)?;
    }
    super::gate(original)?;
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use std::time::Duration;
    async fn parse(
        uri: &str,
        body: &str,
        content: Option<&str>,
        authorize: bool,
    ) -> Result<Fields, Error> {
        let mut builder = Request::builder().method("POST").uri(uri);
        if let Some(content) = content {
            builder = builder.header(header::CONTENT_TYPE, content);
        }
        read(
            builder.body(Body::from(body.to_owned())).unwrap(),
            authorize,
            16384,
            Instant::now() + Duration::from_secs(1),
        )
        .await
    }
    #[tokio::test]
    async fn authorize_merges_origins_but_never_scalar_authority() {
        let f = parse(
            "/?client_id=cli&resource=a",
            "scope=openid&resource=b&unknown=x",
            Some("application/x-www-form-urlencoded"),
            true,
        )
        .await
        .unwrap();
        assert_eq!(f.get("client_id"), "cli");
        assert_eq!(
            f.resources.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        for (uri, body) in [
            ("/?state=a", "state=b"),
            ("/", "nonce=a&nonce=b"),
            ("/", "scope=%FF"),
        ] {
            assert!(
                parse(uri, body, Some("application/x-www-form-urlencoded"), true)
                    .await
                    .is_err()
            );
        }
        assert!(parse("/?client_id=cli", "", None, true).await.is_ok());
        assert!(matches!(
            parse("/", "state=a", Some("application/json"), true).await,
            Err(Error::Input(StatusCode::UNSUPPORTED_MEDIA_TYPE))
        ));
    }
    #[tokio::test]
    async fn login_id_only_in_query_and_credentials_only_in_body() {
        assert!(
            parse(
                "/?id=request",
                "username=alex&password=literal%20password",
                Some("application/x-www-form-urlencoded"),
                false
            )
            .await
            .is_ok()
        );
        for (uri, body) in [
            ("/?id=request", "id=other"),
            ("/?id=request&password=secret", ""),
            ("/?id=a&id=b", ""),
            ("/?id=request", "code=a&code=b"),
        ] {
            assert!(
                parse(uri, body, Some("application/x-www-form-urlencoded"), false)
                    .await
                    .is_err()
            );
        }
        let r = Request::builder()
            .uri("/?id=a&challenge_token=secret")
            .body(Body::empty())
            .unwrap();
        assert!(
            read(r, false, 16384, Instant::now() + Duration::from_secs(1))
                .await
                .is_err()
        );
    }
}
