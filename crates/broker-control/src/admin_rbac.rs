//! Current administrative role writes; inputs are data, never an authorization lease.
use crate::{AdminBrokerSessionError, ControlError, admin_read::ReadWitness};
use std::{fmt, time::Instant};

pub enum AdminRbacRequest<'a> {
    SetRole {
        name: &'a str,
        permissions: &'a [String],
    },
    DeleteRole {
        name: &'a str,
    },
    Assign {
        subject: &'a str,
        role: &'a str,
    },
    Revoke {
        subject: &'a str,
        role: &'a str,
    },
}
impl fmt::Debug for AdminRbacRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminRbacRequest([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminRbacError {
    Authorization(AdminBrokerSessionError),
    CsrfFailed,
    InvalidRole,
    RoleDeleteFailed,
    AssignmentFailed,
}
impl From<AdminBrokerSessionError> for AdminRbacError {
    fn from(value: AdminBrokerSessionError) -> Self {
        Self::Authorization(value)
    }
}
impl From<ControlError> for AdminRbacError {
    fn from(value: ControlError) -> Self {
        Self::Authorization(value.into())
    }
}
impl fmt::Display for AdminRbacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authorization(_) => "administrative authorization failed",
            Self::CsrfFailed => "administrative CSRF verification failed",
            Self::InvalidRole => "invalid system role definition",
            Self::RoleDeleteFailed => "system role deletion failed",
            Self::AssignmentFailed => "system role assignment failed",
        })
    }
}
impl std::error::Error for AdminRbacError {}

/// A known committed mutation. Its final gates check time and the retained factor,
/// not the permissions that this very mutation may validly have removed.
pub struct AdminRbacResult<'a> {
    pub(crate) witness: ReadWitness<'a>,
    pub(crate) original: Instant,
}
impl AdminRbacResult<'_> {
    pub fn check(&self) -> Result<(), AdminRbacError> {
        if Instant::now() >= self.original {
            return Err(ControlError::Deadline.into());
        }
        self.witness.check()?;
        Ok(())
    }
}
impl fmt::Debug for AdminRbacResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminRbacResult([REDACTED])")
    }
}

pub(crate) fn assignment_values<'a>(
    subject: &'a str,
    role: &'a str,
) -> Result<(&'a str, &'a str), AdminRbacError> {
    let subject = subject.trim();
    let role = role.trim();
    if subject.is_empty()
        || subject.chars().count() > 512
        || subject.chars().any(char::is_control)
        || !crate::identity::safe_identity_segment(role, 128)
    {
        return Err(AdminRbacError::AssignmentFailed);
    }
    Ok((subject, role))
}
