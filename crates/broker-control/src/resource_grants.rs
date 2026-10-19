//! Fresh SQL grant metadata is not an authenticated principal or authorization lease.
use crate::ControlError;
use broker_store::time::TimestampMicros;
use serde::Deserialize;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceGrantReadError {
    InvalidLimits,
    ReadLimitExceeded,
    MalformedStored,
    Control(ControlError),
}
impl From<ControlError> for ResourceGrantReadError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}
impl fmt::Display for ResourceGrantReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid resource grant read limit"),
            Self::ReadLimitExceeded => f.write_str("resource grant JSON exceeds read limit"),
            Self::MalformedStored => f.write_str("malformed resource grant snapshot"),
            Self::Control(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ResourceGrantReadError {}

/// Data only. Raw selectors and capabilities require validated policy evaluation.
pub struct ResourceGrantRule {
    id: String,
    name: String,
    access_kind: String,
    principal: String,
    s3_route: String,
    capabilities: Vec<String>,
    projects: Vec<String>,
    s3_operations: Vec<String>,
    s3_prefixes: Vec<String>,
    created_at: TimestampMicros,
    updated_at: TimestampMicros,
}
impl ResourceGrantRule {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn access_kind(&self) -> &str {
        &self.access_kind
    }
    pub fn principal(&self) -> &str {
        &self.principal
    }
    pub fn s3_route(&self) -> &str {
        &self.s3_route
    }
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }
    pub fn projects(&self) -> &[String] {
        &self.projects
    }
    pub fn s3_operations(&self) -> &[String] {
        &self.s3_operations
    }
    pub fn s3_prefixes(&self) -> &[String] {
        &self.s3_prefixes
    }
    pub fn created_at(&self) -> TimestampMicros {
        self.created_at
    }
    pub fn updated_at(&self) -> TimestampMicros {
        self.updated_at
    }
}
impl fmt::Debug for ResourceGrantRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResourceGrantRule([REDACTED])")
    }
}
/// One statement's current policy data; no permission decision or ongoing lease.
pub struct ResourceGrantSnapshot {
    revision: i64,
    updated_at: TimestampMicros,
    rules: Vec<ResourceGrantRule>,
}
impl ResourceGrantSnapshot {
    pub fn revision(&self) -> i64 {
        self.revision
    }
    pub fn updated_at(&self) -> TimestampMicros {
        self.updated_at
    }
    pub fn rules(&self) -> &[ResourceGrantRule] {
        &self.rules
    }
}
impl fmt::Debug for ResourceGrantSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResourceGrantSnapshot([REDACTED])")
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRule {
    id: String,
    name: String,
    access_kind: String,
    principal: String,
    s3_route: String,
    capabilities: Vec<String>,
    projects: Vec<String>,
    s3_operations: Vec<String>,
    s3_prefixes: Vec<String>,
    created_at: i64,
    updated_at: i64,
}
fn ordered<'a>(values: impl IntoIterator<Item = &'a str>) -> Result<(), ResourceGrantReadError> {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|p| p >= value) {
            return Err(ResourceGrantReadError::MalformedStored);
        }
        previous = Some(value);
    }
    Ok(())
}
pub(crate) fn decode_snapshot(
    revision: i64,
    updated_at: i64,
    json: &str,
) -> Result<ResourceGrantSnapshot, ResourceGrantReadError> {
    if revision < 1 {
        return Err(ResourceGrantReadError::MalformedStored);
    }
    let updated_at =
        TimestampMicros::new(updated_at).map_err(|_| ResourceGrantReadError::MalformedStored)?;
    let stored: Vec<StoredRule> =
        serde_json::from_str(json).map_err(|_| ResourceGrantReadError::MalformedStored)?;
    ordered(stored.iter().map(|r| r.id.as_str()))?;
    let mut rules = Vec::with_capacity(stored.len());
    for r in stored {
        for values in [
            &r.capabilities,
            &r.projects,
            &r.s3_operations,
            &r.s3_prefixes,
        ] {
            ordered(values.iter().map(String::as_str))?;
        }
        rules.push(ResourceGrantRule {
            id: r.id,
            name: r.name,
            access_kind: r.access_kind,
            principal: r.principal,
            s3_route: r.s3_route,
            capabilities: r.capabilities,
            projects: r.projects,
            s3_operations: r.s3_operations,
            s3_prefixes: r.s3_prefixes,
            created_at: TimestampMicros::new(r.created_at)
                .map_err(|_| ResourceGrantReadError::MalformedStored)?,
            updated_at: TimestampMicros::new(r.updated_at)
                .map_err(|_| ResourceGrantReadError::MalformedStored)?,
        });
    }
    Ok(ResourceGrantSnapshot {
        revision,
        updated_at,
        rules,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_codec_preserves_raw_policy_without_inventing_authority() {
        let json = r#"[{"id":"rule","name":"raw","access_kind":" unknown ","principal":" team* ","s3_route":"","capabilities":[" a,b ","presence:read"],"projects":[],"s3_operations":[],"s3_prefixes":["v2/{project}"],"created_at":0,"updated_at":1}]"#;
        let snapshot = decode_snapshot(1, 2, json).unwrap();
        let rule = &snapshot.rules()[0];
        assert_eq!(rule.access_kind(), " unknown ");
        assert_eq!(rule.principal(), " team* ");
        assert_eq!(rule.capabilities(), [" a,b ", "presence:read"]);
        assert!(rule.projects().is_empty());
        assert_eq!(format!("{snapshot:?}"), "ResourceGrantSnapshot([REDACTED])");
        for broken in [
            json.replace("\"created_at\":0", "\"created_at\":-1"),
            json.replace("\"projects\":[]", "\"projects\":null"),
            json.replace("\"name\":\"raw\"", "\"name\":1"),
            json.replace(
                "\"name\":\"raw\"",
                "\"name\":\"raw\",\"name\":\"duplicate\"",
            ),
            json.replace("\"projects\":[]", "\"unknown\":[],\"projects\":[]"),
            json.replace("\"projects\":[]", "\"projects\":[\"z\",\"a\"]"),
            json.replace("\"projects\":[]", "\"projects\":[\"a\",\"a\"]"),
        ] {
            assert_eq!(
                decode_snapshot(1, 2, &broken).unwrap_err(),
                ResourceGrantReadError::MalformedStored
            );
        }
        assert!(decode_snapshot(1, 0, "[]").unwrap().rules().is_empty());
        assert_eq!(
            decode_snapshot(0, 0, "[]").unwrap_err(),
            ResourceGrantReadError::MalformedStored
        );
        assert_eq!(
            decode_snapshot(1, -1, "[]").unwrap_err(),
            ResourceGrantReadError::MalformedStored
        );
        assert_eq!(
            decode_snapshot(1, 0, "null").unwrap_err(),
            ResourceGrantReadError::MalformedStored
        );
        assert_eq!(
            ordered(["z", "a"]),
            Err(ResourceGrantReadError::MalformedStored)
        );
    }
}
