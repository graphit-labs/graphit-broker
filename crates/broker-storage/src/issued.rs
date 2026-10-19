use broker_control::StorageAdmissionError;
use std::{fmt, time::SystemTime};
use zeroize::Zeroizing;

/// Mature SDK strategy for an atomic create-only object promotion.
/// This is backend data, independent of permissions and conditional DELETE.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageCopyIfNotExists {
    Multipart,
    IfNoneMatch,
}

/// Issued storage credentials are DATA, not reusable Broker admission.
/// ~~~compile_fail
/// fn clone<T: Clone>() {} clone::<broker_storage::IssuedStorageCredentials>();
/// ~~~
/// ~~~compile_fail
/// fn default<T: Default>() {} default::<broker_storage::IssuedStorageCredentials>();
/// ~~~
/// ~~~compile_fail
/// fn wire<T: serde::de::DeserializeOwned>() {} wire::<broker_storage::IssuedStorageCredentials>();
/// ~~~
pub struct IssuedStorageCredentials {
    pub(crate) key: Zeroizing<String>,
    pub(crate) secret: Zeroizing<String>,
    pub(crate) token: Zeroizing<String>,
    pub(crate) expires_at: String,
    pub(crate) expiry: SystemTime,
    pub(crate) bucket: String,
    pub(crate) region: String,
    pub(crate) endpoint: Option<String>,
    pub(crate) conditional_delete: bool,
    pub(crate) copy_if_not_exists: StorageCopyIfNotExists,
    pub(crate) base_prefix: String,
    pub(crate) project_id: String,
    pub(crate) revision: i64,
}
impl IssuedStorageCredentials {
    pub fn access_key_id(&self) -> &str {
        &self.key
    }
    pub fn secret_access_key(&self) -> &str {
        &self.secret
    }
    pub fn session_token(&self) -> &str {
        &self.token
    }
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }
    pub fn expiry(&self) -> SystemTime {
        self.expiry
    }
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
    pub fn region(&self) -> &str {
        &self.region
    }
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }
    /// Backend capability only; this does not grant permission to delete an object.
    pub fn supports_conditional_delete(&self) -> bool {
        self.conditional_delete
    }
    pub fn copy_if_not_exists(&self) -> StorageCopyIfNotExists {
        self.copy_if_not_exists
    }
    pub fn base_prefix(&self) -> &str {
        &self.base_prefix
    }
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
    pub fn authorization_revision(&self) -> i64 {
        self.revision
    }
}
impl fmt::Debug for IssuedStorageCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuedStorageCredentials([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageIssueError {
    Admission(StorageAdmissionError),
    InvalidConfiguration,
    RouteUnavailable,
    PolicyTooLarge,
    Forbidden,
    Deadline,
    Provider,
    Sdk,
    InvalidResponse,
}
impl From<StorageAdmissionError> for StorageIssueError {
    fn from(e: StorageAdmissionError) -> Self {
        Self::Admission(e)
    }
}
impl fmt::Display for StorageIssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Admission(_) => "storage admission failed",
            Self::InvalidConfiguration => "invalid storage configuration",
            Self::RouteUnavailable => "storage route unavailable",
            Self::PolicyTooLarge => "storage session credentials too large",
            Self::Forbidden => "storage credentials forbidden",
            Self::Deadline => "storage issuance deadline",
            Self::Provider => "storage credential provider unavailable",
            Self::Sdk => "AWS STS unavailable",
            Self::InvalidResponse => "invalid storage credentials",
        })
    }
}
impl std::error::Error for StorageIssueError {}
