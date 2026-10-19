use crate::{
    ControlError, UpstreamBearerVerifier, VerifiedUpstreamLogin,
    identity::{safe_identity_segment, valid_identity_subject},
    oidc_access_grant::{canonical, literal_identity},
};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// Native stored attributes; callers establish current authority separately.
#[derive(Deserialize, Serialize)]
#[serde(tag = "auth_method")]
pub(crate) enum OidcPrincipal {
    #[serde(rename = "local-token")]
    Local(LocalPrincipal),
    #[serde(rename = "oidc")]
    Federated(FederatedPrincipal),
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalPrincipal {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) username: String,
    pub(crate) local_user_revision: i64,
    pub(crate) name: String,
    pub(crate) email: String,
    pub(crate) organization: String,
    pub(crate) teams: Vec<String>,
    pub(crate) roles: Vec<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FederatedPrincipal {
    issuer: String,
    subject: String,
    username: String,
    local_user_revision: i64,
    name: String,
    email: String,
    organization: String,
    teams: Vec<String>,
    roles: Vec<String>,
    roles_from_claim: bool,
    #[serde(deserialize_with = "present_selector")]
    role_claim_selector: Option<String>,
}
fn present_selector<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
impl fmt::Debug for OidcPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcPrincipal([REDACTED])")
    }
}
impl OidcPrincipal {
    pub(crate) fn from_upstream(
        proof: &VerifiedUpstreamLogin,
        verifier: &UpstreamBearerVerifier,
    ) -> Result<Self, ControlError> {
        proof.check(verifier)?;
        if proof.role_selector().is_some() != proof.claim_roles().is_some() {
            return Err(ControlError::InvalidFlow);
        }
        let mut roles = proof.claim_roles().unwrap_or_default().to_vec();
        if !roles.iter().any(|r| r == "user") {
            roles.push("user".into());
        }
        let p = Self::Federated(FederatedPrincipal {
            issuer: proof.issuer().to_owned(),
            subject: proof.profile().subject.clone(),
            username: proof.username().to_owned(),
            local_user_revision: 0,
            name: proof.profile().name.clone(),
            email: proof.profile().email.clone(),
            organization: proof.organization().to_owned(),
            teams: proof.teams().to_vec(),
            roles,
            roles_from_claim: proof.role_selector().is_some(),
            role_claim_selector: proof.role_selector().map(str::to_owned),
        });
        if !p.valid() || !p.current_trust(Some(verifier)) {
            return Err(ControlError::InvalidFlow);
        }
        Ok(p)
    }
    pub(crate) fn valid(&self) -> bool {
        let attributes = [self.name(), self.email(), self.organization()];
        match self {
            Self::Local(p) => {
                if p.issuer != "local"
                    || !valid_identity_subject(&p.subject, 512)
                    || p.local_user_revision < 1
                    || !safe_identity_segment(&p.username, 128)
                    || attributes.iter().any(|s| s.chars().count() > 512)
                {
                    return false;
                }
            }
            Self::Federated(p) => {
                if p.issuer == "local"
                    || !canonical(&p.issuer)
                    || p.local_user_revision != 0
                    || !literal_identity(&p.subject)
                    || !literal_identity(&p.username)
                    || attributes.iter().any(|s| s.contains('\0'))
                    || p.roles_from_claim != p.role_claim_selector.is_some()
                    || p.role_claim_selector
                        .as_ref()
                        .is_some_and(|s| s.is_empty() || s.contains('\0'))
                    || !p.roles.iter().any(|r| r == "user")
                    || (!p.roles_from_claim && p.roles != ["user"])
                    || p.roles.iter().any(|r| !safe_identity_segment(r, 128))
                {
                    return false;
                }
            }
        }
        for values in [self.teams(), self.roles()] {
            for (i, v) in values.iter().enumerate() {
                if v.is_empty() || v.trim() != v || values[..i].contains(v) {
                    return false;
                }
            }
        }
        !self
            .roles()
            .iter()
            .any(|r| r.contains('\0') || r.chars().count() > 128)
    }
    pub(crate) fn current_trust(&self, verifier: Option<&UpstreamBearerVerifier>) -> bool {
        match self {
            Self::Local(_) => true,
            Self::Federated(p) => verifier.is_some_and(|v| {
                v.oauth_role_selector(&p.issuer) == Some(p.role_claim_selector.as_deref())
            }),
        }
    }
    pub(crate) fn initial_amr(&self, amr: &[String]) -> bool {
        match self {
            Self::Local(_) => amr == ["pwd"] || amr == ["pwd", "otp"],
            Self::Federated(_) => amr == ["federated"],
        }
    }
    pub(crate) fn as_local(&self) -> Option<&LocalPrincipal> {
        match self {
            Self::Local(p) => Some(p),
            Self::Federated(_) => None,
        }
    }
    pub(crate) fn issuer(&self) -> &str {
        match self {
            Self::Local(p) => &p.issuer,
            Self::Federated(p) => &p.issuer,
        }
    }
    pub(crate) fn subject(&self) -> &str {
        match self {
            Self::Local(p) => &p.subject,
            Self::Federated(p) => &p.subject,
        }
    }
    pub(crate) fn username(&self) -> &str {
        match self {
            Self::Local(p) => &p.username,
            Self::Federated(p) => &p.username,
        }
    }
    pub(crate) fn revision(&self) -> i64 {
        match self {
            Self::Local(p) => p.local_user_revision,
            Self::Federated(p) => p.local_user_revision,
        }
    }
    pub(crate) fn auth_method(&self) -> &str {
        match self {
            Self::Local(_) => "local-token",
            Self::Federated(_) => "oidc",
        }
    }
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Local(p) => &p.name,
            Self::Federated(p) => &p.name,
        }
    }
    pub(crate) fn email(&self) -> &str {
        match self {
            Self::Local(p) => &p.email,
            Self::Federated(p) => &p.email,
        }
    }
    pub(crate) fn organization(&self) -> &str {
        match self {
            Self::Local(p) => &p.organization,
            Self::Federated(p) => &p.organization,
        }
    }
    pub(crate) fn teams(&self) -> &[String] {
        match self {
            Self::Local(p) => &p.teams,
            Self::Federated(p) => &p.teams,
        }
    }
    pub(crate) fn roles(&self) -> &[String] {
        match self {
            Self::Local(p) => &p.roles,
            Self::Federated(p) => &p.roles,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn local() -> serde_json::Value {
        serde_json::json!({"issuer":"local","subject":"same","username":"local-user","auth_method":"local-token","local_user_revision":1,"name":"","email":"","organization":"","teams":[],"roles":["user"]})
    }
    fn federated() -> serde_json::Value {
        serde_json::json!({"issuer":"https://upstream.test","subject":"same","username":"person@example.test","auth_method":"oidc","local_user_revision":0,"name":"","email":"","organization":"","teams":[],"roles":["user"],"roles_from_claim":false,"role_claim_selector":null})
    }
    #[test]
    fn native_principal_keeps_local_and_federated_discriminators_strict() {
        for data in [local(), federated()] {
            let p: OidcPrincipal = serde_json::from_value(data.clone()).unwrap();
            assert!(p.valid());
            assert_eq!(serde_json::to_value(&p).unwrap(), data);
            let json = serde_json::to_string(&data).unwrap();
            for raw in [
                format!("{json} trailing"),
                json.replacen("{", "{\"issuer\":\"duplicate\",", 1),
            ] {
                assert!(serde_json::from_str::<OidcPrincipal>(&raw).is_err());
            }
        }
        for (mut data, key, value) in [
            (local(), "local_user_revision", serde_json::json!(0)),
            (federated(), "local_user_revision", serde_json::json!(1)),
            (federated(), "issuer", serde_json::json!("local")),
            (federated(), "roles_from_claim", serde_json::json!(true)),
            (federated(), "roles", serde_json::json!(["admin", "user"])),
        ] {
            data[key] = value;
            assert!(
                !serde_json::from_value::<OidcPrincipal>(data)
                    .unwrap()
                    .valid()
            );
        }
        let mut data = local();
        data["roles_from_claim"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<OidcPrincipal>(data).is_err());
        for key in ["roles_from_claim", "role_claim_selector", "name"] {
            let mut data = federated();
            data.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<OidcPrincipal>(data).is_err());
        }
        let mut data = federated();
        data["roles_from_claim"] = true.into();
        data["role_claim_selector"] = "$.roles".into();
        assert!(
            serde_json::from_value::<OidcPrincipal>(data)
                .unwrap()
                .valid()
        );
    }
    #[test]
    fn federated_native_codec_keeps_literal_identity_and_h1_profile_extent() {
        let mut v = serde_json::json!({"auth_method":"oidc","issuer":"https://issuer.example","subject":"  usuário|联合  ","username":"  名称  ","local_user_revision":0,"name":"界".repeat(600),"email":"","organization":"","teams":[],"roles":["user"],"roles_from_claim":false,"role_claim_selector":null});
        let p: OidcPrincipal = serde_json::from_value(v.clone()).unwrap();
        assert!(p.valid());
        assert_eq!(p.subject(), "  usuário|联合  ");
        assert_eq!(p.username(), "  名称  ");
        assert_eq!(p.name().chars().count(), 600);
        for field in ["subject", "username"] {
            for raw in ["", " ", "with\0nul"] {
                let mut bad = v.clone();
                bad[field] = serde_json::json!(raw);
                assert!(
                    !serde_json::from_value::<OidcPrincipal>(bad)
                        .unwrap()
                        .valid()
                );
            }
        }
        v["auth_method"] = serde_json::json!("local-token");
        v["issuer"] = serde_json::json!("local");
        v["local_user_revision"] = serde_json::json!(1);
        v.as_object_mut().unwrap().remove("roles_from_claim");
        v.as_object_mut().unwrap().remove("role_claim_selector");
        assert!(!serde_json::from_value::<OidcPrincipal>(v).unwrap().valid());
    }
}

use crate::OidcTokenExchangeError as Error;
use serde::de::{MapAccess, Visitor, value::MapAccessDeserializer};
impl OidcPrincipal {
    pub(crate) fn parse(raw: &str) -> Result<OidcPrincipal, Error> {
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = OidcPrincipal;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a native OIDC principal object")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                OidcPrincipal::deserialize(MapAccessDeserializer::new(map))
            }
        }
        let mut decoder = serde_json::Deserializer::from_str(raw);
        let p = decoder
            .deserialize_map(Object)
            .map_err(|_| Error::MalformedStored)?;
        decoder.end().map_err(|_| Error::MalformedStored)?;
        if !p.valid() {
            return Err(Error::MalformedStored);
        }
        Ok(p)
    }
}
#[cfg(test)]
mod parse_tests {
    use super::*;
    #[test]
    fn native_principal_requires_an_exact_map_and_real_local_method_fields() {
        let good = r#"{"issuer":"local","subject":"subject","username":"user","auth_method":"local-token","local_user_revision":1,"name":"","email":"","organization":"","teams":[],"roles":["user"]}"#;
        assert!(OidcPrincipal::parse(good).is_ok());
        for raw in [
            "[]".to_owned(),
            format!("{good} trailing"),
            good.replace(
                "\"issuer\":\"local\"",
                "\"issuer\":\"local\",\"issuer\":\"local\"",
            ),
            good.replace(
                "\"issuer\":\"local\"",
                "\"issuer\":\"local\",\"extra\":true",
            ),
            good.replace("local-token", "service-credential"),
            good.replace("\"local_user_revision\":1", "\"local_user_revision\":0"),
            good.replace("\"teams\":[]", "\"teams\":[\"team\",\"team\"]"),
            good.replace("\"name\":\"\",", ""),
        ] {
            assert!(OidcPrincipal::parse(&raw).is_err());
        }
    }
}
