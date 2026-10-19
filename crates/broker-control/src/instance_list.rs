//! One completed local-authenticated list projection, not a reusable authority lease.
use crate::{
    InstanceInventory, InstanceReadError, PresenceAuthorizationError,
    instance_registry::{canonical_instance_id, canonical_project_id, canonical_version},
};
use std::{fmt, num::NonZeroUsize};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceListError {
    InvalidQuery,
    Authorization(PresenceAuthorizationError),
    Inventory(InstanceReadError),
}
impl From<PresenceAuthorizationError> for InstanceListError {
    fn from(value: PresenceAuthorizationError) -> Self {
        Self::Authorization(value)
    }
}
impl From<InstanceReadError> for InstanceListError {
    fn from(value: InstanceReadError) -> Self {
        Self::Inventory(value)
    }
}
impl fmt::Display for InstanceListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQuery => f.write_str("invalid instance inventory list query"),
            Self::Authorization(error) => error.fmt(f),
            Self::Inventory(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for InstanceListError {}

/// Validated data filters; these do not grant authority and have no transport default.
pub struct InstanceListQuery {
    pub(crate) limit: NonZeroUsize,
    pub(crate) after: Option<String>,
    pub(crate) instance_id: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) version: Option<String>,
}
impl InstanceListQuery {
    pub const MAX_LIMIT: usize = 100;
    pub fn new(
        limit: NonZeroUsize,
        after: Option<String>,
        instance_id: Option<String>,
        project_id: Option<String>,
        version: Option<String>,
    ) -> Result<Self, InstanceListError> {
        if limit.get() > Self::MAX_LIMIT
            || after.as_deref().is_some_and(|v| !canonical_instance_id(v))
            || instance_id
                .as_deref()
                .is_some_and(|v| !canonical_instance_id(v))
            || project_id
                .as_deref()
                .is_some_and(|v| !canonical_project_id(v))
            || version.as_deref().is_some_and(|v| !canonical_version(v))
        {
            return Err(InstanceListError::InvalidQuery);
        }
        Ok(Self {
            limit,
            after,
            instance_id,
            project_id,
            version,
        })
    }
}
impl fmt::Debug for InstanceListQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceListQuery([REDACTED])")
    }
}

/// Only completed visible items and a cursor for the last item actually returned.
/// ~~~compile_fail
/// fn fabricate() { let _ = broker_control::AuthorizedInstanceList::new(); }
/// ~~~
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::AuthorizedInstanceList>();
/// ~~~
/// ~~~compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::AuthorizedInstanceList>();
/// ~~~
/// ~~~compile_fail
/// fn require_deserialize<'de, T: serde::Deserialize<'de>>() {}
/// require_deserialize::<broker_control::AuthorizedInstanceList>();
/// ~~~
pub struct AuthorizedInstanceList {
    pub(crate) items: Vec<AuthorizedInstanceListItem>,
    pub(crate) next_after: Option<String>,
}
impl AuthorizedInstanceList {
    pub fn items(&self) -> &[AuthorizedInstanceListItem] {
        &self.items
    }
    pub fn next_after(&self) -> Option<&str> {
        self.next_after.as_deref()
    }
}
impl fmt::Debug for AuthorizedInstanceList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedInstanceList([REDACTED])")
    }
}
/// A private authorized projection containing no stored owner or credential.
/// ~~~compile_fail
/// fn owner(item: &broker_control::AuthorizedInstanceListItem) { let _ = item.owner(); }
/// ~~~
/// ~~~compile_fail
/// fn fabricate() { let _ = broker_control::AuthorizedInstanceListItem::new(); }
/// ~~~
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::AuthorizedInstanceListItem>();
/// ~~~
/// ~~~compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::AuthorizedInstanceListItem>();
/// ~~~
/// ~~~compile_fail
/// fn require_deserialize<'de, T: serde::Deserialize<'de>>() {}
/// require_deserialize::<broker_control::AuthorizedInstanceListItem>();
/// ~~~
pub struct AuthorizedInstanceListItem {
    pub(crate) inventory: InstanceInventory,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}
impl AuthorizedInstanceListItem {
    pub fn inventory(&self) -> &InstanceInventory {
        &self.inventory
    }
    pub fn created_at_micros(&self) -> i64 {
        self.created_at
    }
    pub fn updated_at_micros(&self) -> i64 {
        self.updated_at
    }
}
impl fmt::Debug for AuthorizedInstanceListItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedInstanceListItem([REDACTED])")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlError;
    fn n(v: usize) -> NonZeroUsize {
        NonZeroUsize::new(v).unwrap()
    }
    const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
    #[test]
    fn query_rejects_invalid_optional_filters_without_normalizing() {
        assert!(InstanceListQuery::new(n(1), None, None, None, None).is_ok());
        assert!(
            InstanceListQuery::new(
                n(100),
                Some("A-0".into()),
                Some("station".into()),
                Some(A.into()),
                Some("界😀".into())
            )
            .is_ok()
        );
        assert!(InstanceListQuery::new(n(1), Some("z".repeat(128)), None, None, None).is_ok());
        assert_eq!(
            InstanceListQuery::new(n(101), None, None, None, None).unwrap_err(),
            InstanceListError::InvalidQuery
        );
        for id in ["", " station", "station-", "é", "x/1", &"z".repeat(129)] {
            assert!(InstanceListQuery::new(n(1), Some(id.into()), None, None, None).is_err());
            assert!(InstanceListQuery::new(n(1), None, Some(id.into()), None, None).is_err());
        }
        for project in [
            "",
            "friendly",
            "00000000000000000000000000",
            &A.to_ascii_lowercase(),
        ] {
            assert!(InstanceListQuery::new(n(1), None, None, Some(project.into()), None).is_err());
        }
        for version in ["", " main", "main ", "main\nnext", "main\0"] {
            assert!(InstanceListQuery::new(n(1), None, None, None, Some(version.into())).is_err());
        }
        let query = InstanceListQuery::new(n(1), None, None, None, Some("main".into())).unwrap();
        assert_eq!(format!("{query:?}"), "InstanceListQuery([REDACTED])");
    }
    #[test]
    fn finite_errors_preserve_inventory_and_authorization_uncertainty() {
        let error = ControlError::OutcomeUncertain;
        assert_eq!(
            InstanceListError::from(InstanceReadError::Control(error)),
            InstanceListError::Inventory(InstanceReadError::Control(error))
        );
        assert_eq!(
            InstanceListError::from(PresenceAuthorizationError::Control(error)),
            InstanceListError::Authorization(PresenceAuthorizationError::Control(error))
        );
        assert_eq!(
            InstanceListError::InvalidQuery.to_string(),
            "invalid instance inventory list query"
        );
    }
}
