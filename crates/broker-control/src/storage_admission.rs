//! Actual storage authentication and authorization; requested scopes remain DATA.
use crate::service::{PostgresBrokerStorageAuthorizer, PostgresLocalStorageAuthorizer};
use crate::{
    BrokerAccessError, ControlError, LocalBearerVerificationError, ResourceGrantReadError,
    VerifiedBrokerAccess, VerifiedLocalBearer, flow::now_micros,
    instance_registry::canonical_project_id, resource_policy::ResourcePolicyError,
};
use crate::{SqliteBrokerStorageAuthorizer, SqliteLocalStorageAuthorizer};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    time::{Instant, SystemTime},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageAdmissionError {
    Native(BrokerAccessError),
    Local(LocalBearerVerificationError),
    Grants(ResourceGrantReadError),
    Control(ControlError),
    InvalidConfiguration,
    InvalidScope,
    InvalidPolicy,
    ConflictingRoutes,
    Forbidden,
    Deadline,
}
impl fmt::Display for StorageAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Native(_) | Self::Local(_) => "Hub storage authentication failed",
            Self::Grants(_) | Self::Control(_) => "Hub storage authorization unavailable",
            Self::InvalidConfiguration => "invalid Hub storage configuration",
            Self::InvalidScope => "invalid storage scope",
            Self::InvalidPolicy => "invalid Hub storage policy",
            Self::ConflictingRoutes => "conflicting Hub storage routes",
            Self::Forbidden => "Hub storage access denied",
            Self::Deadline => "Hub storage deadline elapsed",
        })
    }
}
impl std::error::Error for StorageAdmissionError {}
impl From<BrokerAccessError> for StorageAdmissionError {
    fn from(e: BrokerAccessError) -> Self {
        Self::Native(e)
    }
}
impl From<LocalBearerVerificationError> for StorageAdmissionError {
    fn from(e: LocalBearerVerificationError) -> Self {
        Self::Local(e)
    }
}
impl From<ResourceGrantReadError> for StorageAdmissionError {
    fn from(e: ResourceGrantReadError) -> Self {
        Self::Grants(e)
    }
}
impl From<ControlError> for StorageAdmissionError {
    fn from(e: ControlError) -> Self {
        Self::Control(e)
    }
}
impl From<ResourcePolicyError> for StorageAdmissionError {
    fn from(e: ResourcePolicyError) -> Self {
        match e {
            ResourcePolicyError::InvalidPolicy => Self::InvalidPolicy,
            ResourcePolicyError::Deadline => Self::Deadline,
        }
    }
}

/// The requested module is DATA; only actual authentication and SQL grant authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageModule {
    Hub,
    Task,
    Memory,
    Knowledge,
    Ast,
}
impl StorageModule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hub => "hub",
            Self::Task => "task",
            Self::Memory => "memory",
            Self::Knowledge => "knowledge",
            Self::Ast => "ast",
        }
    }
}
/// A requested resource is DATA, not an identity, grant or permission.
#[derive(Clone, Eq, PartialEq)]
pub struct StorageScope {
    kind: StorageScopeKind,
}
#[derive(Clone, Eq, PartialEq)]
enum StorageScopeKind {
    Project {
        project_id: String,
        module: StorageModule,
    },
    UserMemory {
        installation_id: String,
    },
    GlobalHub,
}
impl StorageScope {
    pub fn project(project_id: &str, module: StorageModule) -> Result<Self, StorageAdmissionError> {
        if !canonical_project_id(project_id) {
            return Err(StorageAdmissionError::InvalidScope);
        }
        Ok(Self {
            kind: StorageScopeKind::Project {
                project_id: project_id.into(),
                module,
            },
        })
    }
    /// Select installation DATA. The authenticated caller exclusively determines the USER owner.
    pub fn user_memory(installation_id: &str) -> Result<Self, StorageAdmissionError> {
        let bytes = installation_id.as_bytes();
        if !(1..=128).contains(&bytes.len())
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
        {
            return Err(StorageAdmissionError::InvalidScope);
        }
        Ok(Self {
            kind: StorageScopeKind::UserMemory {
                installation_id: installation_id.into(),
            },
        })
    }
    /// Select global Hub DATA; actual nonPROJECT Hub and S3 authority is still required.
    pub fn global_hub() -> Self {
        Self {
            kind: StorageScopeKind::GlobalHub,
        }
    }
    pub(crate) fn is_global_hub(&self) -> bool {
        matches!(self.kind, StorageScopeKind::GlobalHub)
    }
    pub fn project_id(&self) -> Option<&str> {
        match &self.kind {
            StorageScopeKind::Project { project_id, .. } => Some(project_id),
            StorageScopeKind::UserMemory { .. } | StorageScopeKind::GlobalHub => None,
        }
    }
    pub fn installation_id(&self) -> Option<&str> {
        match &self.kind {
            StorageScopeKind::UserMemory { installation_id } => Some(installation_id),
            StorageScopeKind::Project { .. } | StorageScopeKind::GlobalHub => None,
        }
    }
    pub fn module(&self) -> StorageModule {
        match self.kind {
            StorageScopeKind::Project { module, .. } => module,
            StorageScopeKind::UserMemory { .. } => StorageModule::Memory,
            StorageScopeKind::GlobalHub => StorageModule::Hub,
        }
    }
    pub(crate) fn roots(&self, identity: &StorageIdentity<'_>) -> Vec<String> {
        match &self.kind {
            StorageScopeKind::GlobalHub => vec![
                "v1/hub/global/registry".into(),
                "v1/hub/global/rules".into(),
            ],
            StorageScopeKind::Project {
                project_id,
                module: StorageModule::Hub,
            } => vec![
                format!("v1/projects/{project_id}/registry"),
                format!("v1/projects/{project_id}/artifacts"),
                format!("v1/projects/{project_id}/hub/metadata"),
                format!("v1/projects/{project_id}/hub/events"),
            ],
            StorageScopeKind::Project { project_id, module } => vec![format!(
                "v1/projects/{project_id}/corpora/{}",
                module.as_str(),
            )],
            StorageScopeKind::UserMemory { installation_id } => {
                let (issuer, subject) = match identity {
                    StorageIdentity::Native(p) => (p.issuer(), p.subject()),
                    StorageIdentity::Local(p) => {
                        let u = p.current_local_user();
                        (u.issuer(), u.subject())
                    }
                };
                vec![format!(
                    "v1/installations/{installation_id}/users/{}/corpora/memory",
                    user_namespace(issuer, subject)
                )]
            }
        }
    }
}
fn user_namespace(issuer: &str, subject: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"graphit-user-namespace-v1\0");
    for part in [issuer, subject] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    let mut key = String::with_capacity(64);
    for byte in digest.finalize() {
        key.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        key.push(char::from(b"0123456789abcdef"[(byte & 15) as usize]));
    }
    key
}
impl fmt::Debug for StorageScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageScope([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageOperation {
    Read,
    Write,
    Publish,
    Delete,
}
impl StorageOperation {
    pub(crate) const ALL: [Self; 4] = [Self::Read, Self::Write, Self::Publish, Self::Delete];
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Publish => 2,
            Self::Delete => 3,
        }
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Publish => "publish",
            Self::Delete => "delete",
        }
    }
}
pub(crate) enum StorageIdentity<'a> {
    Native(VerifiedBrokerAccess<'a>),
    Local(VerifiedLocalBearer),
}
pub(crate) struct StorageAuthentication<'a> {
    pub(crate) identity: StorageIdentity<'a>,
    pub(crate) end: Instant,
    expires_at: SystemTime,
    expires_mono: Instant,
}
impl<'a> StorageAuthentication<'a> {
    pub(crate) fn new(
        mut identity: StorageIdentity<'a>,
        end: Instant,
    ) -> Result<Self, StorageAdmissionError> {
        let (expires_at, expires_mono) = match &mut identity {
            StorageIdentity::Native(p) => {
                p.check()?;
                p.authentication_expiry()
            }
            StorageIdentity::Local(p) => {
                p.finish(now_micros().map_err(|e| StorageAdmissionError::Local(e.into()))?)?;
                p.authentication_expiry()
            }
        };
        let auth = Self {
            identity,
            end,
            expires_at,
            expires_mono,
        };
        auth.check()?;
        Ok(auth)
    }
    pub(crate) fn check(&self) -> Result<(), StorageAdmissionError> {
        if Instant::now() >= self.end {
            return Err(StorageAdmissionError::Deadline);
        }
        if SystemTime::now() >= self.expires_at || Instant::now() >= self.expires_mono {
            return Err(match &self.identity {
                StorageIdentity::Native(_) => {
                    StorageAdmissionError::Native(BrokerAccessError::Expired)
                }
                StorageIdentity::Local(_) => {
                    StorageAdmissionError::Local(LocalBearerVerificationError::Unauthenticated)
                }
            });
        }
        if let StorageIdentity::Native(p) = &self.identity {
            p.check()?;
        }
        Ok(())
    }
    pub(crate) fn subject(&self) -> String {
        match &self.identity {
            StorageIdentity::Native(p) => format!("{}|{}", p.issuer(), p.subject()),
            StorageIdentity::Local(p) => {
                let u = p.current_local_user();
                format!("{}|{}", u.issuer(), u.subject())
            }
        }
    }
}
pub(crate) enum FactoryBinding<'a> {
    Broker(&'a PostgresBrokerStorageAuthorizer<'a>),
    Local(&'a PostgresLocalStorageAuthorizer<'a>),
    SqliteBroker(&'a SqliteBrokerStorageAuthorizer<'a>),
    SqliteLocal(&'a SqliteLocalStorageAuthorizer<'a>),
}
/// Authenticated by the actual configured factory before reading a request body.
/// The caller cannot escape the actual factory:
/// ~~~compile_fail
/// use broker_control::{AuthenticatedStorageCaller, BrokerAccessVerifier, PostgresControlStore};
/// fn escape(s: &'static PostgresControlStore, v: &'static BrokerAccessVerifier, raw: &str)
///     -> AuthenticatedStorageCaller<'static> {
///     let factory = s.broker_storage_authorizer(v, std::num::NonZeroUsize::new(8192).unwrap(), "configured").unwrap();
///     factory.authenticate(raw, &[], std::time::Instant::now()).unwrap()
/// }
/// ~~~
/// Nor can its Native factory escape the actual verifier:
/// ~~~compile_fail
/// use broker_control::{BrokerAccessVerifier, PostgresBrokerStorageAuthorizer, PostgresControlStore};
/// fn escape(s: &'static PostgresControlStore, v: &BrokerAccessVerifier)
///     -> PostgresBrokerStorageAuthorizer<'static> {
///     s.broker_storage_authorizer(v, std::num::NonZeroUsize::new(8192).unwrap(), "configured").unwrap()
/// }
/// ~~~
/// The factory and its verifier must remain alive through both phases.
/// ~~~compile_fail
/// fn require<T:Clone>(){} require::<broker_control::AuthenticatedStorageCaller<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require<T:Default>(){} require::<broker_control::AuthenticatedStorageCaller<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require<T:serde::Serialize>(){} require::<broker_control::AuthenticatedStorageCaller<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require<T:serde::de::DeserializeOwned>(){} require::<broker_control::AuthenticatedStorageCaller<'static>>();
/// ~~~
pub struct AuthenticatedStorageCaller<'a> {
    pub(crate) binding: FactoryBinding<'a>,
    pub(crate) auth: StorageAuthentication<'a>,
}
impl AuthenticatedStorageCaller<'_> {
    pub fn check(&self) -> Result<(), StorageAdmissionError> {
        self.auth.check()
    }
}
impl fmt::Debug for AuthenticatedStorageCaller<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedStorageCaller([REDACTED])")
    }
}
/// A current SQL decision retaining its actual authenticated caller.
/// Keep the factory alive through admission and credential issuance:
/// ~~~no_run
/// use broker_control::{BrokerAccessVerifier, StorageScope, StorageModule, PostgresControlStore, StorageAdmissionError};
/// async fn admit(s: &PostgresControlStore, v: &BrokerAccessVerifier, raw: &str)
///     -> Result<(), StorageAdmissionError> {
///     let factory = s.broker_storage_authorizer(v, std::num::NonZeroUsize::new(65536).unwrap(), "configured")?;
///     let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
///     let caller = factory.authenticate(raw, &[], end)?;
///     let scope = StorageScope::project("01D39ZY06FGSCTVN4T2V9PKHFZ", StorageModule::Hub)?;
///     let grant = factory.authorize_authenticated(caller, &scope).await?;
///     grant.check()?;
///     Ok(())
/// }
/// ~~~
/// A grant cannot escape its factory either:
/// ~~~compile_fail
/// use broker_control::{AuthorizedStorageGrant, BrokerAccessVerifier, StorageScope, StorageModule, PostgresControlStore};
/// async fn escape(s: &'static PostgresControlStore, v: &'static BrokerAccessVerifier,
///     raw: &str, scope: &StorageScope) -> AuthorizedStorageGrant<'static> {
///     let factory = s.broker_storage_authorizer(v, std::num::NonZeroUsize::new(8192).unwrap(), "configured").unwrap();
///     factory.authorize(raw, &[], scope, std::time::Instant::now()).await.unwrap()
/// }
/// ~~~
/// Observer getters do not construct authority or renew the deadline.
/// ~~~compile_fail
/// fn require<T:Clone>(){} require::<broker_control::AuthorizedStorageGrant<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require<T:Default>(){} require::<broker_control::AuthorizedStorageGrant<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require<T:serde::Serialize>(){} require::<broker_control::AuthorizedStorageGrant<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require<T:serde::de::DeserializeOwned>(){} require::<broker_control::AuthorizedStorageGrant<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn forge(g:&broker_control::AuthorizedStorageGrant<'_>){let _=g.auth;}
/// ~~~
pub struct AuthorizedStorageGrant<'a> {
    pub(crate) auth: StorageAuthentication<'a>,
    pub(crate) scope: StorageScope,
    pub(crate) route: String,
    pub(crate) revision: i64,
    pub(crate) access: [Vec<String>; 4],
}
impl AuthorizedStorageGrant<'_> {
    pub fn scope(&self) -> &StorageScope {
        &self.scope
    }
    pub fn route(&self) -> &str {
        &self.route
    }
    pub fn revision(&self) -> i64 {
        self.revision
    }
    pub fn prefixes(&self, op: StorageOperation) -> &[String] {
        &self.access[op.index()]
    }
    pub fn canonical_subject(&self) -> String {
        self.auth.subject()
    }
    pub fn request_deadline(&self) -> Instant {
        self.auth.end
    }
    pub fn check(&self) -> Result<(), StorageAdmissionError> {
        self.auth.check()
    }
}
impl fmt::Debug for AuthorizedStorageGrant<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedStorageGrant([REDACTED])")
    }
}
