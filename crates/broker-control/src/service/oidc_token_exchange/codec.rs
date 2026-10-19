use crate::service::oidc_principal::OidcPrincipal;
use crate::{OidcTokenExchangeError as Error, oidc_authorization::PendingFields};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{fmt, marker::PhantomData};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizedFields {
    format: String,
    phase: String,
    client_id: String,
    api_audience: String,
    #[serde(deserialize_with = "resource")]
    resource: Option<String>,
    redirect_uri: String,
    state: String,
    scopes: Vec<String>,
    response_mode: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(deserialize_with = "map_only")]
    pub(crate) principal: OidcPrincipal,
    pub(crate) oidc_subject: String,
    pub(crate) amr: Vec<String>,
    pub(crate) auth_time: i64,
}
impl AuthorizedFields {
    pub(crate) fn request_fields(&self) -> PendingFields {
        PendingFields {
            format: self.format.clone(),
            phase: self.phase.clone(),
            client_id: self.client_id.clone(),
            api_audience: self.api_audience.clone(),
            resource: self.resource.clone(),
            redirect_uri: self.redirect_uri.clone(),
            state: self.state.clone(),
            scopes: self.scopes.clone(),
            response_mode: self.response_mode.clone(),
            nonce: self.nonce.clone(),
            code_challenge: self.code_challenge.clone(),
            code_challenge_method: self.code_challenge_method.clone(),
        }
    }
    pub(crate) fn validate(&self, created_at: i64, now: i64) -> Result<(), Error> {
        if self.format != "rust-broker-authorization-v1"
            || self.phase != "authorized"
            || !self.principal.valid()
            || !self.principal.initial_amr(&self.amr)
            || self.auth_time < created_at
            || self.auth_time <= 0
            || self.auth_time > now
        {
            return Err(Error::MalformedStored);
        }
        Ok(())
    }
}
struct Object<T>(PhantomData<T>);
impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
    type Value = T;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a native authorization object")
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
        T::deserialize(MapAccessDeserializer::new(map))
    }
}
fn map_only<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    d.deserialize_map(Object(PhantomData))
}
fn resource<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
pub(crate) fn parse(raw: &str) -> Result<AuthorizedFields, Error> {
    let mut d = serde_json::Deserializer::from_str(raw);
    let result = map_only(&mut d).map_err(|_| Error::MalformedStored)?;
    d.end().map_err(|_| Error::MalformedStored)?;
    Ok(result)
}
