//! Stored OIDC grant metadata does not authenticate or authorize a caller.
//! JWT access authentication is local until expiry; this reader is not a per-request gate.
//!
//! The borrowed reader cannot escape its store:
//! ~~~compile_fail
//! fn escape(store: &broker_control::PostgresControlStore)
//!     -> broker_control::PostgresOidcAccessGrants<'static> {
//!     store.oidc_access_grants(std::num::NonZeroUsize::new(4096).unwrap()).unwrap()
//! }
//! ~~~
//! Metadata fields remain private:
//! ~~~compile_fail
//! fn expose(grant: broker_control::OidcAccessGrantSnapshot) { let _ = grant.token_id; }
//! ~~~
use crate::{ControlError, LocalIdentityKind, identity::valid_identity_subject};
use broker_store::time::TimestampMicros;
use serde::{
    Deserialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcAccessGrantReadError {
    InvalidLimits,
    ReadLimitExceeded,
    MalformedStored,
    Control(ControlError),
}
impl fmt::Display for OidcAccessGrantReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid explicit OIDC grant JSON limit"),
            Self::ReadLimitExceeded => f.write_str("OIDC grant JSON read limit exceeded"),
            Self::MalformedStored => f.write_str("malformed stored OIDC grant data"),
            Self::Control(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for OidcAccessGrantReadError {}
impl From<ControlError> for OidcAccessGrantReadError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcClientApplicationType {
    Native,
    Web,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalFields {
    issuer: String,
    subject: String,
    username: String,
    auth_method: String,
    local_user_revision: i64,
    name: Option<String>,
    email: Option<String>,
    organization: Option<String>,
    teams: Option<Vec<String>>,
    scopes: Option<Vec<String>>,
    roles: Option<Vec<String>>,
    roles_from_claim: Option<bool>,
    role_claim_selector: Option<String>,
}
/// Literal stored attributes, never a verified principal.
pub struct StoredOidcPrincipal(PrincipalFields);
impl StoredOidcPrincipal {
    pub fn issuer(&self) -> &str {
        &self.0.issuer
    }
    pub fn subject(&self) -> &str {
        &self.0.subject
    }
    pub fn username(&self) -> &str {
        &self.0.username
    }
    pub fn auth_method(&self) -> &str {
        &self.0.auth_method
    }
    pub const fn local_user_revision(&self) -> i64 {
        self.0.local_user_revision
    }
    pub fn name(&self) -> Option<&str> {
        self.0.name.as_deref()
    }
    pub fn email(&self) -> Option<&str> {
        self.0.email.as_deref()
    }
    pub fn organization(&self) -> Option<&str> {
        self.0.organization.as_deref()
    }
    pub fn teams(&self) -> Option<&[String]> {
        self.0.teams.as_deref()
    }
    pub fn scopes(&self) -> Option<&[String]> {
        self.0.scopes.as_deref()
    }
    pub fn roles(&self) -> Option<&[String]> {
        self.0.roles.as_deref()
    }
    pub const fn roles_from_claim(&self) -> Option<bool> {
        self.0.roles_from_claim
    }
    pub fn role_claim_selector(&self) -> Option<&str> {
        self.0.role_claim_selector.as_deref()
    }
}
pub(crate) fn canonical(value: &str) -> bool {
    !value.is_empty() && value.trim() == value && !value.contains('\0')
}
pub(crate) fn literal_identity(value: &str) -> bool {
    !value.trim().is_empty() && !value.contains('\0')
}
pub(crate) fn parse_principal(raw: &str) -> Result<StoredOidcPrincipal, OidcAccessGrantReadError> {
    use serde::Deserializer;
    struct Object;
    impl<'de> Visitor<'de> for Object {
        type Value = PrincipalFields;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a stored principal object")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            PrincipalFields::deserialize(MapAccessDeserializer::new(map))
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(raw);
    let fields = decoder
        .deserialize_map(Object)
        .map_err(|_| OidcAccessGrantReadError::MalformedStored)?;
    decoder
        .end()
        .map_err(|_| OidcAccessGrantReadError::MalformedStored)?;
    let local = fields.issuer == "local";
    if !canonical(&fields.issuer)
        || (local
            && (!canonical(&fields.username)
                || !valid_identity_subject(&fields.subject, 512)
                || fields.local_user_revision < 1
                || !matches!(
                    fields.auth_method.as_str(),
                    "local-token" | "service-credential"
                )))
        || (!local
            && (!literal_identity(&fields.subject)
                || !literal_identity(&fields.username)
                || fields.local_user_revision != 0
                || fields.auth_method != "oidc"))
    {
        return Err(OidcAccessGrantReadError::MalformedStored);
    }
    Ok(StoredOidcPrincipal(fields))
}
/// Current local SQL attributes, including unavailable states, with no authentication claim.
pub struct OidcCurrentLocalUser {
    pub(crate) username: String,
    pub(crate) subject: String,
    pub(crate) kind: LocalIdentityKind,
    pub(crate) enabled: bool,
    pub(crate) name: String,
    pub(crate) email: String,
    pub(crate) organization: String,
    pub(crate) teams: Vec<String>,
    pub(crate) revision: i64,
}
impl OidcCurrentLocalUser {
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub const fn kind(&self) -> LocalIdentityKind {
        self.kind
    }
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn email(&self) -> &str {
        &self.email
    }
    pub fn organization(&self) -> &str {
        &self.organization
    }
    pub fn teams(&self) -> &[String] {
        &self.teams
    }
    pub const fn revision(&self) -> i64 {
        self.revision
    }
}
/// One dynamic registration row; presence does not recognize an OAuth client.
pub struct OidcDynamicClientRegistration {
    pub(crate) client_id: String,
    pub(crate) client_name: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) application_type: OidcClientApplicationType,
    pub(crate) created_at: TimestampMicros,
}
impl OidcDynamicClientRegistration {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn client_name(&self) -> &str {
        &self.client_name
    }
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    pub const fn application_type(&self) -> OidcClientApplicationType {
        self.application_type
    }
    pub const fn created_at(&self) -> TimestampMicros {
        self.created_at
    }
}
/// A read-only observation, including expired/revoked grants. This is not a bearer proof.
pub struct OidcAccessGrantSnapshot {
    pub(crate) token_id: String,
    pub(crate) subject: String,
    pub(crate) oidc_subject: String,
    pub(crate) client_id: String,
    pub(crate) audience: String,
    pub(crate) resource: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) local_user_revision: i64,
    pub(crate) family_id: String,
    pub(crate) auth_time: TimestampMicros,
    pub(crate) expires_at: TimestampMicros,
    pub(crate) revoked_at: Option<TimestampMicros>,
    pub(crate) created_at: TimestampMicros,
    pub(crate) principal: StoredOidcPrincipal,
    pub(crate) current_local_user: Option<OidcCurrentLocalUser>,
    pub(crate) dynamic_registration: Option<OidcDynamicClientRegistration>,
}
impl OidcAccessGrantSnapshot {
    pub fn token_id(&self) -> &str {
        &self.token_id
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn oidc_subject(&self) -> &str {
        &self.oidc_subject
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    pub const fn local_user_revision(&self) -> i64 {
        self.local_user_revision
    }
    pub fn family_id(&self) -> &str {
        &self.family_id
    }
    pub const fn auth_time(&self) -> TimestampMicros {
        self.auth_time
    }
    pub const fn expires_at(&self) -> TimestampMicros {
        self.expires_at
    }
    pub const fn revoked_at(&self) -> Option<TimestampMicros> {
        self.revoked_at
    }
    pub const fn created_at(&self) -> TimestampMicros {
        self.created_at
    }
    pub fn stored_principal(&self) -> &StoredOidcPrincipal {
        &self.principal
    }
    pub fn current_local_user(&self) -> Option<&OidcCurrentLocalUser> {
        self.current_local_user.as_ref()
    }
    pub fn dynamic_registration(&self) -> Option<&OidcDynamicClientRegistration> {
        self.dynamic_registration.as_ref()
    }
}
macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($ty), "([REDACTED])"))
        }
    })+ };
}
redacted!(
    StoredOidcPrincipal,
    OidcCurrentLocalUser,
    OidcDynamicClientRegistration,
    OidcAccessGrantSnapshot
);

#[cfg(test)]
mod tests {
    use super::*;
    fn base() -> serde_json::Value {
        serde_json::json!({"issuer":"local","subject":"subject","username":"user",
            "auth_method":"local-token","local_user_revision":1})
    }
    #[test]
    fn principal_object_is_strict_and_preserves_optional_data() {
        let mut value = base();
        let p = parse_principal(&value.to_string()).unwrap();
        assert_eq!(p.name(), None);
        assert_eq!(p.roles_from_claim(), None);
        assert_eq!(format!("{p:?}"), "StoredOidcPrincipal([REDACTED])");
        value["name"] = serde_json::json!("");
        value["email"] = serde_json::Value::Null;
        value["teams"] = serde_json::json!([" z ", "", " z "]);
        value["roles"] = serde_json::json!([]);
        value["roles_from_claim"] = serde_json::json!(false);
        let p = parse_principal(&value.to_string()).unwrap();
        assert_eq!(p.name(), Some(""));
        assert_eq!(p.email(), None);
        assert_eq!(p.teams().unwrap(), [" z ", "", " z "]);
        assert!(p.roles().unwrap().is_empty());
        assert_eq!(p.roles_from_claim(), Some(false));
        for field in [
            "issuer",
            "subject",
            "username",
            "auth_method",
            "local_user_revision",
        ] {
            let mut v = base();
            v.as_object_mut().unwrap().remove(field);
            assert_eq!(
                parse_principal(&v.to_string()).unwrap_err(),
                OidcAccessGrantReadError::MalformedStored
            );
            let mut v = base();
            v[field] = serde_json::Value::Null;
            assert!(parse_principal(&v.to_string()).is_err());
        }
        for (field, bad) in [
            ("name", serde_json::json!(1)),
            ("teams", serde_json::json!([1])),
            ("roles", serde_json::json!("admin")),
            ("roles_from_claim", serde_json::json!("true")),
            ("local_user_revision", serde_json::json!(1.5)),
            ("extra", serde_json::json!(true)),
        ] {
            let mut v = base();
            v[field] = bad;
            assert!(parse_principal(&v.to_string()).is_err());
        }
        for raw in [
            format!("{} x", base()),
            "[]".into(),
            r#"["local","subject","user","local-token",1]"#.into(),
            base().to_string().replace(
                "\"issuer\":\"local\"",
                "\"issuer\":\"local\",\"issuer\":\"local\"",
            ),
            base().to_string().replace(
                "\"issuer\":\"local\"",
                "\"issuer\":\"local\",\"name\":null,\"name\":null",
            ),
        ] {
            assert!(parse_principal(&raw).is_err());
        }
    }
    #[test]
    fn principal_local_federated_revision_and_method_are_data_coherence() {
        for (issuer, method, revision, good) in [
            ("local", "local-token", 1, true),
            ("local", "service-credential", 2, true),
            ("local", "oidc", 1, false),
            ("local", "local-token", 0, false),
            ("https://issuer.example", "oidc", 0, true),
            ("https://issuer.example", "oidc", 1, false),
            ("https://issuer.example", "local-token", 0, false),
            (" issuer ", "oidc", 0, false),
        ] {
            let mut v = base();
            v["issuer"] = serde_json::json!(issuer);
            v["auth_method"] = serde_json::json!(method);
            v["local_user_revision"] = serde_json::json!(revision);
            assert_eq!(parse_principal(&v.to_string()).is_ok(), good);
        }
        for bad in ["", " subject", "subject ", "x\0"] {
            let mut v = base();
            v["subject"] = serde_json::json!(bad);
            assert!(parse_principal(&v.to_string()).is_err());
        }
        for e in [
            OidcAccessGrantReadError::InvalidLimits,
            OidcAccessGrantReadError::ReadLimitExceeded,
            OidcAccessGrantReadError::MalformedStored,
            OidcAccessGrantReadError::Control(ControlError::OutcomeUncertain),
        ] {
            assert!(!e.to_string().contains("subject"));
        }
    }
    #[test]
    fn federated_data_preserves_h1_identity_bytes_without_local_canonical_rules() {
        let mut v = base();
        v["issuer"] = serde_json::json!("https://issuer.example");
        v["auth_method"] = serde_json::json!("oidc");
        v["local_user_revision"] = serde_json::json!(0);
        v["subject"] = serde_json::json!("  usuário|联合  ");
        v["username"] = serde_json::json!("  名称  ");
        let p = parse_principal(&v.to_string()).unwrap();
        assert_eq!(p.subject(), "  usuário|联合  ");
        assert_eq!(p.username(), "  名称  ");
        v["subject"] = serde_json::json!("界".repeat(400));
        assert!(parse_principal(&v.to_string()).is_ok());
        for field in ["subject", "username"] {
            for raw in ["", " ", "with\0nul"] {
                let mut bad = v.clone();
                bad[field] = serde_json::json!(raw);
                assert!(parse_principal(&bad.to_string()).is_err());
            }
        }
        v["issuer"] = serde_json::json!("local");
        v["auth_method"] = serde_json::json!("local-token");
        v["local_user_revision"] = serde_json::json!(1);
        assert!(parse_principal(&v.to_string()).is_err());
    }
}
