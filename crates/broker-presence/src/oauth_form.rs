//! Shared bounded transport for native OAuth credential forms.
use axum::{body::to_bytes, extract::Request, http::header};
use broker_control::{ControlError, OidcTokenExchangeError as Error};
use headers::{Authorization, ContentType, Header, authorization::Basic};
use std::{collections::BTreeMap, time::Instant};
use zeroize::Zeroizing;

pub(super) struct CredentialForm {
    pub fields: BTreeMap<String, Zeroizing<String>>,
    pub authorization: Option<(Zeroizing<String>, Zeroizing<String>)>,
}

pub(super) fn form(
    raw: &[u8],
    parameters: &[&str],
) -> Result<BTreeMap<String, Zeroizing<String>>, Error> {
    let utf8 = std::str::from_utf8(raw).map_err(|_| Error::InvalidRequest)?;
    percent_encoding::percent_decode_str(utf8)
        .decode_utf8()
        .map_err(|_| Error::InvalidRequest)?;
    let mut fields = BTreeMap::new();
    for (key, value) in form_urlencoded::parse(raw) {
        if parameters.contains(&key.as_ref())
            && fields
                .insert(key.into_owned(), Zeroizing::new(value.into_owned()))
                .is_some()
        {
            return Err(Error::InvalidRequest);
        }
    }
    Ok(fields)
}

pub(super) async fn read(
    mut request: Request,
    parameters: &[&str],
    end: Instant,
    body_bytes: usize,
) -> Result<CredentialForm, Error> {
    for (name, value) in request.headers_mut().iter_mut() {
        if name == header::AUTHORIZATION {
            value.set_sensitive(true);
        }
    }
    let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
    let value = types.next().ok_or(Error::InvalidRequest)?;
    if types.next().is_some() {
        return Err(Error::InvalidRequest);
    }
    let content =
        ContentType::decode(&mut std::iter::once(value)).map_err(|_| Error::InvalidRequest)?;
    if content.to_string().split(';').next() != Some("application/x-www-form-urlencoded") {
        return Err(Error::InvalidRequest);
    }
    if request.uri().query().is_some_and(|q| {
        form_urlencoded::parse(q.as_bytes()).any(|(k, _)| parameters.contains(&k.as_ref()))
    }) {
        return Err(Error::InvalidRequest);
    }
    let authorization = {
        let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
        let first = values.next();
        if values.next().is_some() {
            return Err(Error::InvalidRequest);
        }
        match first {
            None => None,
            Some(value) => {
                let basic = Authorization::<Basic>::decode(&mut std::iter::once(value))
                    .map_err(|_| Error::InvalidClient)?;
                Some((
                    Zeroizing::new(basic.username().to_owned()),
                    Zeroizing::new(basic.password().to_owned()),
                ))
            }
        }
    };
    let body = tokio::time::timeout_at(end.into(), to_bytes(request.into_body(), body_bytes))
        .await
        .map_err(|_| Error::Control(ControlError::Deadline))?
        .map_err(|_| Error::InvalidRequest)?;
    let fields = form(&body, parameters)?;
    if fields.contains_key("client_assertion")
        || fields.contains_key("client_assertion_type")
        || (authorization.is_some() && fields.contains_key("client_secret"))
    {
        return Err(Error::InvalidRequest);
    }
    Ok(CredentialForm {
        fields,
        authorization,
    })
}
