//! Durable SQL inventory data. This snapshot conveys no authentication or permission.
use crate::{ControlError, InstanceInventory, InstanceOwner, InstanceProjectVersions};
use broker_store::time::TimestampMicros;
use serde::Deserialize;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceReadError {
    InvalidLimits,
    InvalidInstanceId,
    ReadLimitExceeded,
    MalformedStored,
    Control(ControlError),
}
impl From<ControlError> for InstanceReadError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl fmt::Display for InstanceReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid instance inventory read limit"),
            Self::InvalidInstanceId => f.write_str("invalid instance identity"),
            Self::ReadLimitExceeded => f.write_str("instance inventory exceeds read limit"),
            Self::MalformedStored => f.write_str("malformed stored instance inventory"),
            Self::Control(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for InstanceReadError {}

/// One SQL statement's data, constructed only by the validated storage decoder.
/// No authentication or authorization is carried by this value.
/// ~~~compile_fail
/// fn fabricate() { let _ = broker_control::StoredInstanceInventory::new(); }
/// ~~~
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::StoredInstanceInventory>();
/// ~~~
pub struct StoredInstanceInventory {
    owner: InstanceOwner,
    inventory: InstanceInventory,
    created_at: i64,
    updated_at: i64,
}
impl StoredInstanceInventory {
    pub fn owner(&self) -> &InstanceOwner {
        &self.owner
    }
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
impl fmt::Debug for StoredInstanceInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredInstanceInventory([REDACTED])")
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredParent {
    instance_id: String,
    owner_issuer: String,
    owner_subject: String,
    created_at: i64,
    updated_at: i64,
    versions: Vec<StoredVersion>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredVersion {
    project_id: String,
    position: i64,
    version: String,
}
pub(crate) fn decode_inventory(
    expected: &str,
    json: &str,
) -> Result<StoredInstanceInventory, InstanceReadError> {
    let stored: StoredParent =
        serde_json::from_str(json).map_err(|_| InstanceReadError::MalformedStored)?;
    if stored.instance_id != expected {
        return Err(InstanceReadError::MalformedStored);
    }
    TimestampMicros::new(stored.created_at).map_err(|_| InstanceReadError::MalformedStored)?;
    TimestampMicros::new(stored.updated_at).map_err(|_| InstanceReadError::MalformedStored)?;
    let owner = InstanceOwner::new(&stored.owner_issuer, &stored.owner_subject)
        .map_err(|_| InstanceReadError::MalformedStored)?;
    let mut projects = Vec::new();
    let mut project = String::new();
    let mut versions: Vec<String> = Vec::new();
    for row in stored.versions {
        if !crate::instance_registry::canonical_project_id(&row.project_id) {
            return Err(InstanceReadError::MalformedStored);
        }
        if row.project_id != project {
            if !project.is_empty() {
                if row.project_id <= project {
                    return Err(InstanceReadError::MalformedStored);
                }
                projects.push(
                    InstanceProjectVersions::new(
                        std::mem::take(&mut project),
                        std::mem::take(&mut versions),
                    )
                    .map_err(|_| InstanceReadError::MalformedStored)?,
                );
            }
            project = row.project_id;
        }
        let expected_position = i64::try_from(versions.len())
            .ok()
            .and_then(|p| p.checked_add(1));
        if expected_position != Some(row.position)
            || versions.last().is_some_and(|v| v >= &row.version)
        {
            return Err(InstanceReadError::MalformedStored);
        }
        versions.push(row.version);
    }
    if !project.is_empty() {
        projects.push(
            InstanceProjectVersions::new(project, versions)
                .map_err(|_| InstanceReadError::MalformedStored)?,
        );
    } else if !versions.is_empty() {
        return Err(InstanceReadError::MalformedStored);
    }
    let inventory = InstanceInventory::new(stored.instance_id, projects)
        .map_err(|_| InstanceReadError::MalformedStored)?;
    Ok(StoredInstanceInventory {
        owner,
        inventory,
        created_at: stored.created_at,
        updated_at: stored.updated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
    const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
    fn parent(rows: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"instance_id":"station","owner_issuer":"Issuer ","owner_subject":"Subject ","created_at":0,"updated_at":1,"versions":rows})
    }
    fn row(project: &str, position: i64, version: &str) -> serde_json::Value {
        serde_json::json!({"project_id":project,"position":position,"version":version})
    }
    fn decode(value: serde_json::Value) -> Result<StoredInstanceInventory, InstanceReadError> {
        decode_inventory("station", &value.to_string())
    }
    #[test]
    fn validated_snapshot_preserves_empty_literal_owner_and_canonical_inventory() {
        let empty = decode(parent(serde_json::json!([]))).unwrap();
        assert!(empty.inventory().projects().is_empty());
        assert_eq!(
            (empty.owner().issuer(), empty.owner().subject()),
            ("Issuer ", "Subject ")
        );
        assert_eq!(
            (empty.created_at_micros(), empty.updated_at_micros()),
            (0, 1)
        );
        assert_eq!(format!("{empty:?}"), "StoredInstanceInventory([REDACTED])");
        let full = decode(parent(serde_json::json!([
            row(A, 1, "main"),
            row(A, 2, "release"),
            row(B, 1, "界😀")
        ])))
        .unwrap();
        assert_eq!(full.inventory().projects().len(), 2);
        assert_eq!(full.inventory().projects()[1].versions(), &["界😀"]);
        assert_eq!(
            decode_inventory("other", &parent(serde_json::json!([])).to_string()).unwrap_err(),
            InstanceReadError::MalformedStored
        );
    }
    #[test]
    fn malformed_storage_is_rejected_before_sorting_or_repair() {
        for rows in [
            vec![row(A, 0, "main")],
            vec![row(A, 2, "main")],
            vec![row(A, 1, "main"), row(A, 3, "release")],
            vec![row(A, 1, "release"), row(A, 2, "main")],
            vec![row(A, 1, "main"), row(A, 2, "main")],
            vec![row(B, 1, "main"), row(A, 1, "main")],
            vec![row(A, 1, "main"), row(B, 1, "main"), row(A, 1, "release")],
            vec![row("", 1, "main")],
            vec![row("", 1, "main"), row(A, 2, "release")],
            vec![row("friendly", 1, "main")],
            vec![row("00000000000000000000000000", 1, "main")],
            vec![row(&A.to_lowercase(), 1, "main")],
            vec![row(A, 1, " main")],
            vec![row(A, 1, "")],
            vec![row(A, 1, "x\n")],
        ] {
            assert_eq!(
                decode(parent(serde_json::json!(rows))).unwrap_err(),
                InstanceReadError::MalformedStored
            );
        }
        for (key, value) in [
            ("instance_id", serde_json::json!(" x")),
            ("created_at", serde_json::json!(-1)),
            ("updated_at", serde_json::json!(-1)),
            ("owner_issuer", serde_json::json!("")),
            ("owner_subject", serde_json::json!("\0")),
        ] {
            let mut p = parent(serde_json::json!([]));
            p[key] = value;
            assert_eq!(decode(p).unwrap_err(), InstanceReadError::MalformedStored);
        }
        let mut p = parent(serde_json::json!([]));
        p["owner_issuer"] = serde_json::json!("界".repeat(1024));
        p["owner_subject"] = serde_json::json!("😀".repeat(512));
        assert!(decode(p.clone()).is_ok());
        p["owner_subject"] = serde_json::json!("😀".repeat(513));
        assert_eq!(decode(p).unwrap_err(), InstanceReadError::MalformedStored);
    }
    #[test]
    fn private_json_schema_is_strict_and_errors_redact_data() {
        let json = parent(serde_json::json!([row(A, 1, "main")])).to_string();
        for invalid in [
            json.replace("\"created_at\":0,", ""),
            json.replace("\"created_at\":0", "\"created_at\":null"),
            json.replace("\"created_at\":0", "\"created_at\":\"0\""),
            json.replace("\"created_at\":0", "\"created_at\":0,\"created_at\":0"),
            json.replace("\"created_at\":0", "\"created_at\":0,\"extra\":\"secret\""),
            json.replace("\"position\":1", "\"position\":1,\"extra\":true"),
            json.replace("\"position\":1", "\"position\":1,\"position\":1"),
            format!("{json} true"),
        ] {
            assert_eq!(
                decode_inventory("station", &invalid).unwrap_err(),
                InstanceReadError::MalformedStored
            );
        }
        for err in [
            InstanceReadError::InvalidLimits,
            InstanceReadError::InvalidInstanceId,
            InstanceReadError::ReadLimitExceeded,
            InstanceReadError::MalformedStored,
            InstanceReadError::Control(ControlError::Storage),
        ] {
            assert!(!format!("{err:?} {err}").contains("secret"));
        }
    }
}
