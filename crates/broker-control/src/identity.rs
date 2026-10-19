//! Local identity references and fetched SQL role data do not authenticate callers.
use broker_store::seeds::ADMIN_ACTIONS;
pub use broker_store::seeds::SystemAction;
use std::{fmt, num::NonZeroUsize};

#[derive(Clone, Copy, Debug)]
pub struct IdentityReadLimits {
    pub username_bytes: NonZeroUsize,
    pub subject_bytes: NonZeroUsize,
    pub role_bytes: NonZeroUsize,
    pub roles: NonZeroUsize,
    pub rows: NonZeroUsize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityInputError {
    InvalidLimits,
    InvalidReference,
}
impl fmt::Display for IdentityInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid explicit identity read limits",
            Self::InvalidReference => "invalid local identity reference",
        })
    }
}
impl std::error::Error for IdentityInputError {}
impl IdentityReadLimits {
    pub fn validate(&self) -> Result<(), IdentityInputError> {
        let values = [
            self.username_bytes,
            self.subject_bytes,
            self.role_bytes,
            self.roles,
            self.rows,
        ];
        if self.role_bytes.get() < 4
            || self.subject_bytes.get().checked_add(6).is_none()
            || self.roles.get().checked_add(1).is_none()
            || self.rows.get().checked_add(1).is_none()
            || values
                .iter()
                .any(|value| u64::try_from(value.get()).is_err())
        {
            return Err(IdentityInputError::InvalidLimits);
        }
        Ok(())
    }
}
/// A data-only reference supplied by a consumer that already authenticated a local caller.
/// Constructing this value does not verify credentials or confer any permission.
pub struct LocalIdentityReference<'a> {
    username: &'a str,
    subject: &'a str,
    revision: i64,
}
impl<'a> LocalIdentityReference<'a> {
    pub fn new(
        username: &'a str,
        subject: &'a str,
        revision: i64,
        limits: &IdentityReadLimits,
    ) -> Result<Self, IdentityInputError> {
        limits.validate()?;
        let value = Self {
            username,
            subject,
            revision,
        };
        value.validate(limits)?;
        Ok(value)
    }
    pub fn username(&self) -> &str {
        self.username
    }
    pub fn subject(&self) -> &str {
        self.subject
    }
    pub const fn revision(&self) -> i64 {
        self.revision
    }
    pub(crate) fn validate(&self, limits: &IdentityReadLimits) -> Result<(), IdentityInputError> {
        if !safe_identity_segment(self.username, limits.username_bytes.get().min(128))
            || !valid_identity_subject(self.subject, limits.subject_bytes.get().min(512))
            || self.revision < 1
        {
            return Err(IdentityInputError::InvalidReference);
        }
        Ok(())
    }
}
pub(crate) fn safe_identity_segment(value: &str, cap: usize) -> bool {
    !value.is_empty()
        && value.len() <= cap
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
pub(crate) fn valid_identity_subject(value: &str, cap: usize) -> bool {
    !value.is_empty()
        && value.len() <= cap
        && value.len() <= 512
        && value.trim() == value
        && !value.contains('\0')
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalIdentityKind {
    Human,
    Service,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalIdentityUnavailable {
    Missing,
    Disabled,
    SubjectChanged,
    RevisionChanged,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemPermission {
    Action(SystemAction),
    All,
}
impl SystemPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Action(action) => action.as_str(),
            Self::All => "*",
        }
    }
    pub(crate) fn stored(value: &str) -> Option<Self> {
        if value == "*" {
            Some(Self::All)
        } else {
            ADMIN_ACTIONS
                .iter()
                .copied()
                .find(|action| action.as_str() == value)
                .map(Self::Action)
        }
    }
}
/// An immutable fetched snapshot, never a credential or an authorization lease.
pub struct LocalIdentitySnapshot {
    pub(crate) username: String,
    pub(crate) subject: String,
    pub(crate) kind: LocalIdentityKind,
    pub(crate) revision: i64,
    pub(crate) roles: Vec<String>,
    pub(crate) permissions: Vec<SystemPermission>,
}
impl LocalIdentitySnapshot {
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub const fn kind(&self) -> LocalIdentityKind {
        self.kind
    }
    pub const fn revision(&self) -> i64 {
        self.revision
    }
    pub fn roles(&self) -> &[String] {
        &self.roles
    }
    pub fn permissions(&self) -> &[SystemPermission] {
        &self.permissions
    }
    /// Tests only this fetched SQL permission set; the caller must already be authenticated.
    pub fn allows(&self, action: SystemAction) -> bool {
        self.permissions.contains(&SystemPermission::All)
            || self.permissions.contains(&SystemPermission::Action(action))
    }
}
pub enum LocalIdentityRead {
    Current(LocalIdentitySnapshot),
    Unavailable(LocalIdentityUnavailable),
}
macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($ty), "([REDACTED])"))
        }
    })+ };
}
redacted!(
    LocalIdentityReference<'_>,
    LocalIdentitySnapshot,
    LocalIdentityRead
);

#[cfg(test)]
mod tests {
    use super::*;
    fn n(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).unwrap()
    }
    fn limits() -> IdentityReadLimits {
        IdentityReadLimits {
            username_bytes: n(128),
            subject_bytes: n(512),
            role_bytes: n(128),
            roles: n(32),
            rows: n(256),
        }
    }
    #[test]
    fn local_identity_reference_bounds_and_finite_errors() {
        let limits = limits();
        for username in ["", ".", "..", "bad/name", "x y", "_bad", "é", "x\0"] {
            assert_eq!(
                LocalIdentityReference::new(username, "subject", 1, &limits).unwrap_err(),
                IdentityInputError::InvalidReference
            );
        }
        for subject in ["", " x", "x ", "x\0"] {
            assert_eq!(
                LocalIdentityReference::new("user", subject, 1, &limits).unwrap_err(),
                IdentityInputError::InvalidReference
            );
        }
        assert!(
            LocalIdentityReference::new(&"x".repeat(128), &"s".repeat(512), 1, &limits).is_ok()
        );
        assert!(
            LocalIdentityReference::new("user", &format!("{}x", "s".repeat(512)), 1, &limits)
                .is_err()
        );
        assert!(LocalIdentityReference::new("user", "subject", 0, &limits).is_err());
        let reference =
            LocalIdentityReference::new("private-name", "private-subject", 1, &limits).unwrap();
        assert_eq!(
            format!("{reference:?}"),
            "LocalIdentityReference<'_>([REDACTED])"
        );
        assert_eq!(
            IdentityInputError::InvalidLimits.to_string(),
            "invalid explicit identity read limits"
        );
        assert_eq!(
            IdentityInputError::InvalidReference.to_string(),
            "invalid local identity reference"
        );
        let mut bad = limits;
        bad.role_bytes = n(3);
        assert_eq!(bad.validate(), Err(IdentityInputError::InvalidLimits));
        let mut bad = limits;
        bad.subject_bytes = n(usize::MAX);
        assert_eq!(bad.validate(), Err(IdentityInputError::InvalidLimits));
        let mut bad = limits;
        bad.rows = n(usize::MAX);
        assert_eq!(bad.validate(), Err(IdentityInputError::InvalidLimits));
    }
    #[test]
    fn sql_permissions_are_exact_or_literal_wildcard() {
        assert_eq!(SystemPermission::stored("*"), Some(SystemPermission::All));
        for action in ADMIN_ACTIONS {
            assert_eq!(
                SystemPermission::stored(action.as_str()),
                Some(SystemPermission::Action(*action))
            );
        }
        assert_eq!(SystemPermission::stored("unknown.read"), None);
        let mut snapshot = LocalIdentitySnapshot {
            username: "private-name".into(),
            subject: "private-subject".into(),
            kind: LocalIdentityKind::Human,
            revision: 1,
            roles: vec!["user".into()],
            permissions: vec![
                SystemPermission::Action(SystemAction::SessionRead),
                SystemPermission::Action(SystemAction::ProjectsRead),
            ],
        };
        assert!(snapshot.allows(SystemAction::SessionRead));
        assert!(snapshot.allows(SystemAction::ProjectsRead));
        assert!(!snapshot.allows(SystemAction::UsersWrite));
        snapshot.permissions = vec![SystemPermission::All];
        for action in ADMIN_ACTIONS {
            assert!(snapshot.allows(*action));
        }
        snapshot.permissions.clear();
        for action in ADMIN_ACTIONS {
            assert!(!snapshot.allows(*action));
        }
        assert_eq!(format!("{snapshot:?}"), "LocalIdentitySnapshot([REDACTED])");
    }
}
