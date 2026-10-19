//! SQL state is metadata; only a server verifier can authenticate a bearer.
use crate::{ControlError, LocalIdentityKind};
use broker_security::TokenKind;
use broker_store::time::TimestampMicros;
use serde::Deserialize;
use std::fmt;

pub(crate) const LOCAL_ISSUER: &str = "local";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalBearerKind {
    Access,
    ServiceCredential,
}
impl LocalBearerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::ServiceCredential => "service",
        }
    }
    pub const fn token_kind(self) -> TokenKind {
        match self {
            Self::Access => TokenKind::LocalAccess,
            Self::ServiceCredential => TokenKind::ServiceCredential,
        }
    }
    pub(crate) const fn identity_kind(self) -> LocalIdentityKind {
        match self {
            Self::Access => LocalIdentityKind::Human,
            Self::ServiceCredential => LocalIdentityKind::Service,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalBearerStateError {
    InvalidLimits,
    ReadLimitExceeded,
    MalformedStored,
    Control(ControlError),
}
impl From<ControlError> for LocalBearerStateError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl fmt::Display for LocalBearerStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid local bearer read limit"),
            Self::ReadLimitExceeded => f.write_str("local bearer JSON exceeds read limit"),
            Self::MalformedStored => f.write_str("malformed local bearer state"),
            Self::Control(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for LocalBearerStateError {}

/// Current local attributes, never a credential or an authorization lease.
pub struct LocalBearerUser {
    pub(crate) username: String,
    pub(crate) subject: String,
    pub(crate) kind: LocalIdentityKind,
    pub(crate) name: String,
    pub(crate) email: String,
    pub(crate) organization: String,
    pub(crate) teams: Vec<String>,
    pub(crate) revision: i64,
}
impl fmt::Debug for LocalBearerUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalBearerUser([REDACTED])")
    }
}
impl LocalBearerUser {
    pub fn issuer(&self) -> &'static str {
        LOCAL_ISSUER
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn kind(&self) -> LocalIdentityKind {
        self.kind
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
    pub fn revision(&self) -> i64 {
        self.revision
    }
}

/// Even a returned state can be expired or revoked. It does not prove possession
/// of a raw bearer: a caller can construct a CredentialDigest from SQL metadata.
pub struct LocalBearerState {
    pub(crate) kind: LocalBearerKind,
    pub(crate) audience: String,
    pub(crate) raw_scopes: Vec<String>,
    pub(crate) expires_at: TimestampMicros,
    pub(crate) revoked_at: Option<TimestampMicros>,
    pub(crate) user: LocalBearerUser,
}
impl fmt::Debug for LocalBearerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalBearerState([REDACTED])")
    }
}
impl LocalBearerState {
    pub fn kind(&self) -> LocalBearerKind {
        self.kind
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    /// Keep exact stored values until the verifier checks required scopes.
    pub fn raw_scopes(&self) -> &[String] {
        &self.raw_scopes
    }
    pub fn expires_at(&self) -> TimestampMicros {
        self.expires_at
    }
    pub fn revoked_at(&self) -> Option<TimestampMicros> {
        self.revoked_at
    }
    pub fn current_local_user(&self) -> &LocalBearerUser {
        &self.user
    }
}

// Fields with underscore names still enforce the complete stored JSON types.
// Their old attributes never replace the current local user's attributes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredPrincipal {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    #[serde(rename = "username")]
    _username: String,
    #[serde(rename = "auth_method")]
    _auth_method: String,
    #[serde(rename = "name")]
    _name: Option<String>,
    #[serde(rename = "email")]
    _email: Option<String>,
    #[serde(rename = "organization")]
    _organization: Option<String>,
    #[serde(rename = "teams")]
    _teams: Option<Vec<String>>,
    #[serde(rename = "scopes")]
    _scopes: Option<Vec<String>>,
    #[serde(rename = "roles")]
    _roles: Option<Vec<String>>,
    #[serde(rename = "roles_from_claim")]
    _roles_from_claim: Option<bool>,
    #[serde(rename = "role_claim_selector")]
    _role_claim_selector: Option<String>,
    pub(crate) local_user_revision: Option<i64>,
}
pub(crate) fn parse_principal(json: &str) -> Result<StoredPrincipal, LocalBearerStateError> {
    serde_json::from_str(json).map_err(|_| LocalBearerStateError::MalformedStored)
}
pub(crate) fn parse_array(json: &str) -> Result<Vec<String>, LocalBearerStateError> {
    serde_json::from_str(json).map_err(|_| LocalBearerStateError::MalformedStored)
}
pub(crate) fn normalize(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        if value.trim() != value.as_str() {
            *value = value.trim().to_owned();
        }
    }
    values.retain(|v| !v.is_empty());
    values.sort_unstable();
    values.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn principal_codec_rejects_malformed_types_without_policy_defaults() {
        let minimal =
            r#"{"issuer":"local","subject":"s","username":"u","auth_method":"local-token"}"#;
        assert!(
            parse_principal(minimal)
                .unwrap()
                .local_user_revision
                .is_none()
        );
        for bad in [
            r#"{"issuer":"local","subject":"s","username":"u"}"#,
            r#"{"issuer":"local","subject":"s","username":"u","auth_method":"x","name":5}"#,
            r#"{"issuer":"local","subject":"s","username":"u","auth_method":"x","teams":[3]}"#,
            r#"{"issuer":"local","subject":"s","username":"u","auth_method":"x","roles_from_claim":"yes"}"#,
            r#"{"issuer":"local","subject":"s","username":"u","auth_method":"x","local_user_revision":"1"}"#,
            r#"{"issuer":"local","issuer":"other","subject":"s","username":"u","auth_method":"x"}"#,
            r#"{"issuer":"local","subject":"s","username":"u","auth_method":"x","extra":true}"#,
        ] {
            assert!(matches!(
                parse_principal(bad),
                Err(LocalBearerStateError::MalformedStored)
            ));
        }
    }
    #[test]
    fn arrays_and_team_cleaning_do_not_clean_required_scope_inputs_or_split_csv() {
        let mut teams = parse_array(r#"[" team ","","team","a,b"," z "]"#).unwrap();
        normalize(&mut teams);
        assert_eq!(teams, ["a,b", "team", "z"]);
        let scopes = parse_array(r#"[" presence:read ","presence:publish"]"#).unwrap();
        assert!(!scopes.iter().any(|s| s == "presence:read"));
        assert_eq!(scopes[0], " presence:read ");
        for bad in ["null", "{}", r#"[1]"#, r#""a,b""#] {
            assert!(parse_array(bad).is_err());
        }
    }
    #[test]
    fn errors_and_kind_domains_are_finite_and_redacted() {
        assert!(matches!(
            LocalBearerKind::Access.token_kind(),
            TokenKind::LocalAccess
        ));
        assert!(matches!(
            LocalBearerKind::ServiceCredential.token_kind(),
            TokenKind::ServiceCredential
        ));
        assert_eq!(
            LocalBearerStateError::MalformedStored.to_string(),
            "malformed local bearer state"
        );
    }
}
