//! Native LOCAL administration; request data never grants authority.

pub(crate) mod validation;
use crate::{
    AdminBrokerSessionError, AdminBrokerSessionLimits, ControlError, SystemAction,
    admin_read::ReadWitness,
};
use serde::Deserialize;
use std::{
    fmt,
    num::NonZeroUsize,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug)]
pub struct AdminUsersLimits {
    pub authorization: AdminBrokerSessionLimits,
    pub response_json_bytes: NonZeroUsize,
    pub service_credential_audience: String,
    pub service_credential_max_ttl: Duration,
}
impl AdminUsersLimits {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.authorization.validate()?;
        isize::try_from(self.response_json_bytes.get()).map_err(|_| ControlError::Configuration)?;
        i64::try_from(self.response_json_bytes.get()).map_err(|_| ControlError::Configuration)?;
        let audience = &self.service_credential_audience;
        if audience.is_empty()
            || audience.trim() != audience
            || audience.len() > 128
            || audience.chars().any(char::is_control)
            || self.service_credential_max_ttl < Duration::from_secs(3600)
            || self.service_credential_max_ttl > Duration::from_secs(5 * 365 * 86400)
            || self.service_credential_max_ttl.subsec_nanos() != 0
        {
            return Err(ControlError::Configuration);
        }
        Ok(())
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminUserInput {
    pub username: String,
    pub subject: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub teams: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub password_change_required: bool,
}
impl Drop for AdminUserInput {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
impl fmt::Debug for AdminUserInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminUserInput([REDACTED])")
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminServiceCredentialInput {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_in: i64,
}
pub enum AdminUsersRequest<'a> {
    Create(&'a AdminUserInput),
    Update {
        username: &'a str,
        user: &'a AdminUserInput,
    },
    Delete {
        username: &'a str,
    },
    ResetMfa {
        username: &'a str,
    },
    Credentials {
        username: &'a str,
    },
    IssueCredential {
        username: &'a str,
        input: &'a AdminServiceCredentialInput,
    },
    RevokeCredential {
        username: &'a str,
        id: &'a str,
    },
}
impl AdminUsersRequest<'_> {
    pub(crate) fn action(&self) -> SystemAction {
        if matches!(self, Self::Credentials { .. }) {
            SystemAction::UsersRead
        } else {
            SystemAction::UsersWrite
        }
    }
    pub(crate) fn password(&self) -> Option<&str> {
        match self {
            Self::Create(user) | Self::Update { user, .. } if !user.password.is_empty() => {
                Some(&user.password)
            }
            _ => None,
        }
    }
    pub(crate) fn error(&self) -> AdminUsersError {
        match self {
            Self::Create(_) => AdminUsersError::CreateFailed,
            Self::Update { .. } => AdminUsersError::UpdateFailed,
            Self::Delete { .. } => AdminUsersError::DeleteFailed,
            Self::ResetMfa { .. } => AdminUsersError::MfaResetFailed,
            Self::Credentials { .. } => AdminUsersError::CredentialsReadFailed,
            Self::IssueCredential { .. } => AdminUsersError::CredentialCreateFailed,
            Self::RevokeCredential { .. } => AdminUsersError::CredentialRevokeFailed,
        }
    }
}
impl fmt::Debug for AdminUsersRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminUsersRequest([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminUsersError {
    Authorization(AdminBrokerSessionError),
    CsrfFailed,
    CreateFailed,
    UpdateFailed,
    DeleteFailed,
    MfaResetFailed,
    ServiceIdentityNotFound,
    InvalidCredential,
    CredentialCreateFailed,
    CredentialGenerationFailed,
    CredentialRevokeFailed,
    CredentialsReadFailed,
}
impl From<AdminBrokerSessionError> for AdminUsersError {
    fn from(value: AdminBrokerSessionError) -> Self {
        Self::Authorization(value)
    }
}
impl From<ControlError> for AdminUsersError {
    fn from(value: ControlError) -> Self {
        Self::Authorization(value.into())
    }
}
impl fmt::Display for AdminUsersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("native user administration failed")
    }
}
impl std::error::Error for AdminUsersError {}

pub struct AdminUsersResult<'a> {
    pub(crate) witness: ReadWitness<'a>,
    pub(crate) original: Instant,
    pub(crate) status: u16,
    pub(crate) body: Zeroizing<Vec<u8>>,
}
impl AdminUsersResult<'_> {
    pub fn check(&self) -> Result<(), AdminUsersError> {
        if Instant::now() >= self.original {
            return Err(ControlError::Deadline.into());
        }
        self.witness.check()?;
        Ok(())
    }
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn take_body(&mut self) -> Vec<u8> {
        std::mem::take(&mut *self.body)
    }
}
impl fmt::Debug for AdminUsersResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminUsersResult([REDACTED])")
    }
}
