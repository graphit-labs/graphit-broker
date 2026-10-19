//! Administrative grant writes. A cursor or revision is never an authorization lease.
pub(crate) mod validation;
use crate::{
    AdminBrokerSessionError, AdminReadError, ControlError, ResourceGrantReadError,
    admin_read::ReadWitness,
};
use serde::Deserialize;
use std::{collections::BTreeSet, fmt, time::Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminGrantInput {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub access: String,
    #[serde(default)]
    pub principal: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub s3_operations: Vec<String>,
    #[serde(default)]
    pub s3_prefixes: Vec<String>,
    #[serde(default)]
    pub s3_route: String,
}
impl fmt::Debug for AdminGrantInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminGrantInput([REDACTED])")
    }
}
pub enum AdminGrantRequest<'a> {
    Create(&'a AdminGrantInput),
    Update {
        id: &'a str,
        grant: &'a AdminGrantInput,
    },
    Delete {
        id: &'a str,
    },
}
impl fmt::Debug for AdminGrantRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminGrantRequest([REDACTED])")
    }
}

/// Public route names from the actual server configuration; no storage credentials.
pub struct AdminGrantRoutes {
    pub(crate) names: BTreeSet<String>,
    pub(crate) default: String,
}
impl AdminGrantRoutes {
    pub fn new(
        names: impl IntoIterator<Item = String>,
        default: String,
    ) -> Result<Self, ControlError> {
        let names: BTreeSet<_> = names.into_iter().collect();
        if names
            .iter()
            .any(|name| !crate::identity::safe_identity_segment(name, 128))
            || (!default.is_empty() && !names.contains(&default))
        {
            return Err(ControlError::Configuration);
        }
        Ok(Self { names, default })
    }
}
impl fmt::Debug for AdminGrantRoutes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminGrantRoutes([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminGrantError {
    Authorization(AdminBrokerSessionError),
    CsrfFailed,
    PreconditionRequired,
    RevisionConflict,
    InvalidGrant,
    WriteFailed,
    ReadFailed,
}
impl From<AdminBrokerSessionError> for AdminGrantError {
    fn from(error: AdminBrokerSessionError) -> Self {
        Self::Authorization(error)
    }
}
impl From<ControlError> for AdminGrantError {
    fn from(error: ControlError) -> Self {
        Self::Authorization(error.into())
    }
}
impl From<AdminReadError> for AdminGrantError {
    fn from(error: AdminReadError) -> Self {
        match error {
            AdminReadError::Authorization(error) => Self::Authorization(error),
            AdminReadError::Projection(_) => Self::ReadFailed,
        }
    }
}
impl From<ResourceGrantReadError> for AdminGrantError {
    fn from(error: ResourceGrantReadError) -> Self {
        match error {
            ResourceGrantReadError::Control(
                error @ (ControlError::Deadline
                | ControlError::Closed
                | ControlError::OutcomeUncertain),
            ) => error.into(),
            _ => Self::ReadFailed,
        }
    }
}
impl fmt::Display for AdminGrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authorization(_) => "administrative authorization failed",
            Self::CsrfFailed => "administrative CSRF verification failed",
            Self::PreconditionRequired => "a positive policy revision is required",
            Self::RevisionConflict => "policy revision changed",
            Self::InvalidGrant => "invalid resource grant",
            Self::WriteFailed => "resource grant write failed",
            Self::ReadFailed => "current resource grants unavailable",
        })
    }
}
impl std::error::Error for AdminGrantError {}

pub fn parse_grant_if_match(value: Option<&str>) -> Result<u64, AdminGrantError> {
    let value = value.ok_or(AdminGrantError::PreconditionRequired)?.trim();
    let value = value.strip_prefix("W/").unwrap_or(value);
    let value = match value.strip_prefix('"') {
        Some(value) => value
            .strip_suffix('"')
            .ok_or(AdminGrantError::PreconditionRequired)?,
        None => value,
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AdminGrantError::PreconditionRequired);
    }
    value
        .parse()
        .ok()
        .filter(|revision| *revision > 0)
        .ok_or(AdminGrantError::PreconditionRequired)
}

/// Fresh DATA after a known write COMMIT, with the original authentication retained.
pub struct AdminGrantResult<'a> {
    pub(crate) witness: ReadWitness<'a>,
    pub(crate) original: Instant,
    pub(crate) body: Vec<u8>,
    pub(crate) revision: i64,
}
impl AdminGrantResult<'_> {
    pub fn check(&self) -> Result<(), AdminGrantError> {
        if Instant::now() >= self.original {
            return Err(ControlError::Deadline.into());
        }
        self.witness.check()?;
        Ok(())
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn take_body(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.body)
    }
    pub fn revision(&self) -> i64 {
        self.revision
    }
}
impl fmt::Debug for AdminGrantResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminGrantResult([REDACTED])")
    }
}
