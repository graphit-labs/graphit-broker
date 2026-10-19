//! Installation inventory data. Construction grants no authentication or authorization.
use crate::ControlError;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceRegistryError {
    InvalidOwner,
    InvalidInventory,
    OwnerConflict,
    MalformedStored,
    Control(ControlError),
}
impl From<ControlError> for InstanceRegistryError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl fmt::Display for InstanceRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOwner => f.write_str("invalid installation owner data"),
            Self::InvalidInventory => f.write_str("invalid installation inventory"),
            Self::OwnerConflict => f.write_str("installation belongs to another owner"),
            Self::MalformedStored => f.write_str("stored installation inventory is invalid"),
            Self::Control(value) => value.fmt(f),
        }
    }
}
impl std::error::Error for InstanceRegistryError {}

/// Literal principal identity data; the server must obtain it from verified authentication.
pub struct InstanceOwner {
    issuer: String,
    subject: String,
}
impl InstanceOwner {
    pub fn new(issuer: &str, subject: &str) -> Result<Self, InstanceRegistryError> {
        if !valid_owner_value(issuer, 1024) || !valid_owner_value(subject, 512) {
            return Err(InstanceRegistryError::InvalidOwner);
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
        })
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
}
impl fmt::Debug for InstanceOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceOwner([REDACTED])")
    }
}
pub(crate) fn valid_owner_value(value: &str, characters: usize) -> bool {
    !value.is_empty()
        && !value.contains('\0')
        && value.chars().take(characters + 1).count() <= characters
}
pub(crate) fn canonical_project_id(value: &str) -> bool {
    let Ok(id) = ulid::Ulid::from_string(value) else {
        return false;
    };
    let mut canonical = [0; 26];
    !id.is_nil() && id.array_to_str(&mut canonical) == value
}
pub(crate) fn canonical_version(value: &str) -> bool {
    !value.is_empty() && value.trim() == value && !value.chars().any(char::is_control)
}
pub(crate) fn canonical_instance_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
}

/// Available versions of one project. Values are sorted; duplicate inputs are rejected.
#[derive(Debug, Eq, PartialEq)]
pub struct InstanceProjectVersions {
    project_id: String,
    versions: Vec<String>,
}
impl InstanceProjectVersions {
    pub fn new(
        project_id: String,
        mut versions: Vec<String>,
    ) -> Result<Self, InstanceRegistryError> {
        if !canonical_project_id(&project_id)
            || versions.is_empty()
            || i64::try_from(versions.len()).is_err()
            || versions.iter().any(|value| !canonical_version(value))
        {
            return Err(InstanceRegistryError::InvalidInventory);
        }
        versions.sort();
        if versions.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(InstanceRegistryError::InvalidInventory);
        }
        Ok(Self {
            project_id,
            versions,
        })
    }
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
    pub fn versions(&self) -> &[String] {
        &self.versions
    }
}

/// Complete replacement data for one canonical installation ID; an empty inventory is valid.
#[derive(Debug, Eq, PartialEq)]
pub struct InstanceInventory {
    instance_id: String,
    projects: Vec<InstanceProjectVersions>,
}
impl InstanceInventory {
    pub fn new(
        instance_id: String,
        mut projects: Vec<InstanceProjectVersions>,
    ) -> Result<Self, InstanceRegistryError> {
        if !canonical_instance_id(&instance_id) {
            return Err(InstanceRegistryError::InvalidInventory);
        }
        projects.sort_by(|a, b| a.project_id.cmp(&b.project_id));
        if projects
            .windows(2)
            .any(|pair| pair[0].project_id == pair[1].project_id)
        {
            return Err(InstanceRegistryError::InvalidInventory);
        }
        Ok(Self {
            instance_id,
            projects,
        })
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    pub fn projects(&self) -> &[InstanceProjectVersions] {
        &self.projects
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationChange {
    Created,
    Updated,
    Unchanged,
}
/// Returned only after confirmed COMMIT. This result contains no owner or authority.
#[derive(Debug, Eq, PartialEq)]
pub struct RegistrationResult {
    pub(crate) change: RegistrationChange,
    pub(crate) instance_id: String,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}
impl RegistrationResult {
    pub fn change(&self) -> RegistrationChange {
        self.change
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    pub fn created_at_micros(&self) -> i64 {
        self.created_at
    }
    pub fn updated_at_micros(&self) -> i64 {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PROJECT: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
    #[test]
    fn owner_preserves_literal_values_and_column_character_limits() {
        let owner = InstanceOwner::new("Issuer ", "Subject ").unwrap();
        assert_eq!((owner.issuer(), owner.subject()), ("Issuer ", "Subject "));
        assert_eq!(format!("{owner:?}"), "InstanceOwner([REDACTED])");
        assert!(InstanceOwner::new(&"界".repeat(1024), &"😀".repeat(512)).is_ok());
        for (issuer, subject) in [
            ("".into(), "s".into()),
            ("i".into(), "".into()),
            ("界".repeat(1025), "s".into()),
            ("i".into(), "😀".repeat(513)),
            ("i\0".into(), "s".into()),
        ] {
            assert_eq!(
                InstanceOwner::new(&issuer, &subject).unwrap_err(),
                InstanceRegistryError::InvalidOwner
            );
        }
    }
    #[test]
    fn inventory_accepts_canonical_identity_and_empty_replacement() {
        assert!(InstanceInventory::new("Station._-1".into(), vec![]).is_ok());
        assert!(InstanceInventory::new("A".repeat(128), vec![]).is_ok());
        for id in ["", " x", "x ", "_x", "x-", "x/y", "é", &"A".repeat(129)] {
            assert_eq!(
                InstanceInventory::new(id.into(), vec![]).unwrap_err(),
                InstanceRegistryError::InvalidInventory
            );
        }
    }
    #[test]
    fn versions_require_canonical_project_and_meaningful_unique_values() {
        for id in [
            "00000000000000000000000000",
            "01d39zy06fgsctvn4t2v9pkhfz",
            "friendly",
            " 01D39ZY06FGSCTVN4T2V9PKHFZ",
        ] {
            assert_eq!(
                InstanceProjectVersions::new(id.into(), vec!["main".into()]).unwrap_err(),
                InstanceRegistryError::InvalidInventory
            );
        }
        for versions in [
            vec![],
            vec!["".into()],
            vec![" main".into()],
            vec!["main\n".into()],
            vec!["a\0b".into()],
            vec!["main".into(), "main".into()],
        ] {
            assert_eq!(
                InstanceProjectVersions::new(PROJECT.into(), versions).unwrap_err(),
                InstanceRegistryError::InvalidInventory
            );
        }
        let values = InstanceProjectVersions::new(
            PROJECT.into(),
            vec!["界😀".repeat(10000), "main".into(), "feature/topic".into()],
        )
        .unwrap();
        assert_eq!(values.versions()[0], "feature/topic");
        assert_eq!(values.versions()[2].len(), 70000);
    }
    #[test]
    fn duplicate_projects_are_not_merged_silently() {
        let project = || InstanceProjectVersions::new(PROJECT.into(), vec!["main".into()]).unwrap();
        assert_eq!(
            InstanceInventory::new("station".into(), vec![project(), project()]).unwrap_err(),
            InstanceRegistryError::InvalidInventory
        );
    }
}
