//! SDK metadata admission for public dynamic OAuth clients.
use crate::{ControlError, OidcAuthorizationPolicy, oidc_authorization::ClientData};
use openidconnect::{
    ClientId, ClientName, LocalizedClaim, RedirectUrl, ResponseTypes,
    core::{
        CoreApplicationType, CoreClientAuthMethod, CoreClientMetadata,
        CoreClientRegistrationResponse, CoreGrantType, CoreResponseType,
    },
    registration::{EmptyAdditionalClientMetadata, EmptyAdditionalClientRegistrationResponse},
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const OIDC_REGISTRATION_BODY_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcRegistrationError {
    Disabled,
    InvalidMetadata,
    Random,
    Control(ControlError),
}
impl fmt::Display for OidcRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(e) => e.fmt(f),
            _ => write!(f, "OIDC registration {self:?}"),
        }
    }
}
impl std::error::Error for OidcRegistrationError {}
impl From<ControlError> for OidcRegistrationError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}
type Error = OidcRegistrationError;
#[derive(Deserialize)]
struct Input {
    #[serde(flatten)]
    metadata: CoreClientMetadata,
    scope: Option<String>,
}
pub(crate) struct Registration {
    pub name: String,
    pub redirects: Vec<String>,
    pub scopes: Vec<String>,
    pub native: bool,
}
impl Registration {
    pub fn parse(raw: &[u8], policy: &OidcAuthorizationPolicy) -> Result<Self, Error> {
        if raw.len() > OIDC_REGISTRATION_BODY_BYTES {
            return Err(Error::InvalidMetadata);
        }
        let input: Input = serde_json::from_slice(raw).map_err(|_| Error::InvalidMetadata)?;
        let metadata = input.metadata;
        if metadata
            .token_endpoint_auth_method()
            .as_ref()
            .is_some_and(|m| !matches!(m.as_ref().trim(), "" | "none"))
            || metadata.grant_types().as_ref().is_some_and(|g| {
                g.iter().any(|v| {
                    !matches!(
                        v,
                        CoreGrantType::AuthorizationCode | CoreGrantType::RefreshToken
                    )
                })
            })
            || metadata.response_types().as_ref().is_some_and(|types| {
                types
                    .iter()
                    .any(|v| v.len() != 1 || v[0] != CoreResponseType::Code)
            })
        {
            return Err(Error::InvalidMetadata);
        }
        let bound = policy.limits.parameter_bytes();
        let mut redirects = Vec::new();
        for redirect in metadata.redirect_uris() {
            if redirect.as_str().len() > bound {
                return Err(Error::InvalidMetadata);
            }
            let raw = redirect.as_str().trim();
            if !redirects.iter().any(|v| v == raw) {
                redirects.push(raw.to_owned());
            }
        }
        let native = !redirects
            .iter()
            .any(|r| r.get(..6).is_some_and(|s| s.eq_ignore_ascii_case("https:")));
        ClientData {
            id: "registration".into(),
            redirects: redirects.clone(),
            native,
        }
        .validate_registration()
        .map_err(|_| Error::InvalidMetadata)?;
        let name = metadata
            .client_name()
            .as_ref()
            .and_then(|v| v.get(None))
            .map_or("", |n| n.as_str())
            .trim()
            .to_owned();
        if name.contains('\0')
            || name.len() > 1024
            || name.chars().count() > 256
            || name.len() > bound
        {
            return Err(Error::InvalidMetadata);
        }
        let raw_scope = input.scope.as_deref().unwrap_or("");
        if raw_scope.len() > bound {
            return Err(Error::InvalidMetadata);
        }
        let raw_scope = raw_scope.trim();
        let mut scopes = Vec::new();
        for scope in if raw_scope.is_empty() {
            "openid profile email offline_access"
        } else {
            raw_scope
        }
        .split_whitespace()
        {
            if !matches!(scope, "openid" | "profile" | "email" | "offline_access") {
                return Err(Error::InvalidMetadata);
            }
            if !scopes.iter().any(|v| v == scope) {
                scopes.push(scope.to_owned());
            }
        }
        let admitted = Self {
            name,
            redirects,
            scopes,
            native,
        };
        admitted.columns(policy)?;
        Ok(admitted)
    }
    pub fn columns(&self, policy: &OidcAuthorizationPolicy) -> Result<(String, String), Error> {
        let redirects =
            serde_json::to_string(&self.redirects).map_err(|_| Error::InvalidMetadata)?;
        let scopes = serde_json::to_string(&self.scopes).map_err(|_| Error::InvalidMetadata)?;
        if [redirects.len(), scopes.len()]
            .into_iter()
            .any(|n| i64::try_from(n).map_or(true, |n| n > policy.limits.json_bytes))
        {
            return Err(Error::InvalidMetadata);
        }
        Ok((redirects, scopes))
    }
    pub fn response(&self, id: String, created_at: i64) -> Result<RegisteredOidcClient, Error> {
        let issued =
            chrono::DateTime::from_timestamp_micros(created_at).ok_or(ControlError::Clock)?;
        let redirects = self
            .redirects
            .iter()
            .map(|r| RedirectUrl::new(r.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::InvalidMetadata)?;
        let response = CoreClientRegistrationResponse::new(
            ClientId::new(id),
            redirects,
            EmptyAdditionalClientMetadata {},
            EmptyAdditionalClientRegistrationResponse {},
        )
        .set_client_id_issued_at(Some(issued))
        .set_application_type(Some(if self.native {
            CoreApplicationType::Native
        } else {
            CoreApplicationType::Web
        }))
        .set_client_name(Some(LocalizedClaim::from(ClientName::new(
            self.name.clone(),
        ))))
        .set_token_endpoint_auth_method(Some(CoreClientAuthMethod::None))
        .set_grant_types(Some(vec![
            CoreGrantType::AuthorizationCode,
            CoreGrantType::RefreshToken,
        ]))
        .set_response_types(Some(vec![ResponseTypes::new(vec![CoreResponseType::Code])]));
        Ok(RegisteredOidcClient {
            response,
            scope: self.scopes.join(" "),
        })
    }
}
/// Public metadata released only after a confirmed SQL COMMIT.
#[derive(Serialize)]
pub struct RegisteredOidcClient {
    #[serde(flatten)]
    response: CoreClientRegistrationResponse,
    scope: String,
}
impl fmt::Debug for RegisteredOidcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegisteredOidcClient([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OidcAuthorizationConfiguration, OidcAuthorizationLimits};
    use serde_json::{Value, json};
    use std::{num::NonZeroUsize, time::Duration};
    fn policy(json: usize, parameter: usize) -> OidcAuthorizationPolicy {
        OidcAuthorizationPolicy::new(
            OidcAuthorizationConfiguration {
                cli_client_id: "graphit-cli".into(),
                cli_redirect_path: "/oauth/callback".into(),
                api_audience: "graphit-broker".into(),
                accepted_resources: vec![],
                dynamic_registration: true,
                authorization_ttl: Duration::from_secs(60),
            },
            OidcAuthorizationLimits::new(
                NonZeroUsize::new(json).unwrap(),
                NonZeroUsize::new(parameter).unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn parse(value: Value) -> Result<Registration, Error> {
        Registration::parse(&serde_json::to_vec(&value).unwrap(), &policy(8192, 8192))
    }
    #[test]
    fn sdk_public_metadata_preserves_literals_and_committed_response() {
        let r = parse(json!({
            "redirect_uris": [" HTTPS://Client.example:443/cb?q=%2F ", "http://localhost:8123/cb", "http://localhost:8123/cb"],
            "application_type": "native", "client_name": "  Cliente é  ",
            "token_endpoint_auth_method": " none ", "grant_types": [], "response_types": [],
            "scope": " profile openid profile email offline_access ", "extension": {"ignored": true}
        })).unwrap();
        assert!(!r.native);
        assert_eq!(r.name, "Cliente é");
        assert_eq!(
            r.redirects,
            [
                "HTTPS://Client.example:443/cb?q=%2F",
                "http://localhost:8123/cb"
            ]
        );
        assert_eq!(r.scopes, ["profile", "openid", "email", "offline_access"]);
        let response = r
            .response("opaque-public-id".into(), 1_700_000_000_123_456)
            .unwrap();
        let wire = serde_json::to_value(&response).unwrap();
        assert_eq!(wire["client_id"], "opaque-public-id");
        assert_eq!(wire["client_id_issued_at"], 1_700_000_000);
        assert_eq!(wire["application_type"], "web");
        assert_eq!(wire["client_name"], "Cliente é");
        assert_eq!(wire["scope"], "profile openid email offline_access");
        assert_eq!(
            wire["grant_types"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(wire["response_types"], json!(["code"]));
        assert_eq!(wire["token_endpoint_auth_method"], "none");
        assert_eq!(wire["redirect_uris"], json!(r.redirects));
        for field in [
            "client_secret",
            "client_secret_expires_at",
            "registration_access_token",
            "registration_client_uri",
        ] {
            assert!(wire.get(field).is_none(), "{field}");
        }
        let _: CoreClientRegistrationResponse = serde_json::from_value(wire).unwrap();
        for scope in [Value::Null, json!(""), json!(" \t ")] {
            let r = parse(json!({"redirect_uris":["http://[::1]/cb"],"scope":scope})).unwrap();
            assert!(r.native);
            assert_eq!(r.scopes, ["openid", "profile", "email", "offline_access"]);
        }
        assert_eq!(
            parse(json!({"redirect_uris":["https://app.example/cb"],"scope":"profile"}))
                .unwrap()
                .scopes,
            ["profile"]
        );
    }
    #[test]
    fn sdk_invalid_metadata_and_original_authorities_are_rejected() {
        for uri in [
            "",
            "relative",
            "ftp://app.example/cb",
            "http://app.example/cb",
            "https://localhost/cb",
            "https://127.0.0.1/cb",
            "http://127.1/cb",
            "http://0177.0.0.1/cb",
            "http://0x7f000001/cb",
            "http://localhost:0/cb",
            "https://user@app.example/cb",
            "https://app.example/cb#x",
        ] {
            assert!(parse(json!({"redirect_uris":[uri]})).is_err(), "{uri}");
        }
        for metadata in [
            json!({}),
            json!({"redirect_uris":[]}),
            json!({"redirect_uris":"https://app.example/cb"}),
            json!({"redirect_uris":[null]}),
            json!({"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}),
            json!({"redirect_uris":["https://app.example/cb"],"grant_types":["client_credentials"]}),
            json!({"redirect_uris":["https://app.example/cb"],"response_types":["code token"]}),
            json!({"redirect_uris":["https://app.example/cb"],"scope":"phone"}),
            json!({"redirect_uris":["https://app.example/cb"],"scope":42}),
            json!({"redirect_uris":["https://app.example/cb"],"client_name":"nul\u{0}name"}),
            json!({"redirect_uris":["https://app.example/cb"],"client_name":"é".repeat(257)}),
            json!({"redirect_uris":["https://app.example/cb"],"client_name":-1}),
        ] {
            assert!(parse(metadata).is_err());
        }
        for raw in [
            r#"{"redirect_uris":["https://app.example/cb"],"redirect_uris":["https://app.example/other"]}"#,
            r#"{"redirect_uris":["https://app.example/cb"],"client_name":null,"client_name":"duplicate"}"#,
            r#"{"redirect_uris":["https://app.example/cb"],"scope":null,"scope":"openid"}"#,
            r#"{"redirect_uris":["https://app.example/cb"]} {}"#,
            "null",
            "[]",
        ] {
            assert!(
                Registration::parse(raw.as_bytes(), &policy(8192, 8192)).is_err(),
                "{raw}"
            );
        }
    }
    #[test]
    fn reader_limits_unicode_names_and_body_cap_are_enforced_before_sql() {
        let good =
            json!({"redirect_uris":["https://app.example/cb"],"client_name":"🙂".repeat(256)});
        assert_eq!(parse(good).unwrap().name.len(), 1024);
        let raw = serde_json::to_vec(&json!({"redirect_uris":["https://app.example/cb"]})).unwrap();
        assert!(Registration::parse(&raw, &policy(8, 8192)).is_err());
        let raw = serde_json::to_vec(
            &json!({"redirect_uris":[format!("https://app.example/{}", "a".repeat(100))]}),
        )
        .unwrap();
        assert!(Registration::parse(&raw, &policy(8192, 64)).is_err());
        let mut oversized = vec![b' '; OIDC_REGISTRATION_BODY_BYTES + 1];
        oversized[0] = b'{';
        assert!(Registration::parse(&oversized, &policy(8192, 8192)).is_err());
    }
}
