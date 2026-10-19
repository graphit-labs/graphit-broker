use crate::{IssuedStorageCredentials, StorageIssueError};
use aws_sdk_sts::primitives::{DateTime, DateTimeFormat};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{AuthorizedStorageGrant, StorageModule, StorageOperation, StorageScope};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    num::NonZeroUsize,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::{Host, Url};
use zeroize::Zeroizing;

const TOKEN_PREFIX: &str = "rust-fs1";
const TOKEN_DOMAIN: &[u8] = b"graphit-broker/rust-filesystem-session/v1\0";
const SECRET_DOMAIN: &[u8] = b"graphit-broker/rust-filesystem-secret/v1\0";
const OPERATIONS: [StorageOperation; 4] = [
    StorageOperation::Read,
    StorageOperation::Write,
    StorageOperation::Publish,
    StorageOperation::Delete,
];

/// Explicit server configuration; defaults belong to the server compositor.
pub struct FilesystemStorageRouteConfig {
    pub name: String,
    pub bucket: String,
    pub region: String,
    pub base_prefix: String,
    pub endpoint: String,
    pub session_duration: Duration,
    /// Actual security-token header budget of the configured ingress.
    pub token_bytes: NonZeroUsize,
}
impl fmt::Debug for FilesystemStorageRouteConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FilesystemStorageRouteConfig([REDACTED])")
    }
}
pub struct FilesystemStorageRoute {
    config: FilesystemStorageRouteConfig,
}
impl fmt::Debug for FilesystemStorageRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FilesystemStorageRoute([REDACTED])")
    }
}
fn segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn bucket(s: &str) -> bool {
    (3..=63).contains(&s.len())
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        && ![
            "admin",
            "healthz",
            "readyz",
            "oauth",
            "v1",
            "favicon.svg",
            ".well-known",
            "metrics",
            "api",
        ]
        .contains(&s)
}
fn endpoint(s: &str) -> bool {
    let Ok(u) = Url::parse(s) else {
        return false;
    };
    u.username().is_empty()
        && u.password().is_none()
        && u.host().is_some()
        && u.query().is_none()
        && u.fragment().is_none()
        && u.path() == "/"
        && (u.scheme() == "https"
            || (u.scheme() == "http"
                && match u.host() {
                    Some(Host::Domain(h)) => h == "localhost",
                    Some(Host::Ipv4(ip)) => ip.is_loopback(),
                    Some(Host::Ipv6(ip)) => ip.is_loopback(),
                    None => false,
                }))
}
/// Canonical object keys are compared before any filesystem path construction.
pub(crate) fn key(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 1024
        && s.bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'\\' && b != b'"')
        && s.split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
impl FilesystemStorageRoute {
    pub fn new(config: FilesystemStorageRouteConfig) -> Result<Self, StorageIssueError> {
        if !segment(&config.name)
            || !bucket(&config.bucket)
            || !endpoint(&config.endpoint)
            || config.region.is_empty()
            || !config
                .region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !key(&config.base_prefix)
            || !config.base_prefix.split('/').all(segment)
            || !(900..=43200).contains(&config.session_duration.as_secs())
            || config.session_duration.subsec_nanos() != 0
        {
            return Err(StorageIssueError::InvalidConfiguration);
        }
        Ok(Self { config })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemSessionError {
    InvalidToken,
    RouteUnavailable,
    Expired,
    Deadline,
    Crypto,
}
impl fmt::Display for FilesystemSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidToken => "invalid filesystem session",
            Self::RouteUnavailable => "filesystem route unavailable",
            Self::Expired => "filesystem session expired",
            Self::Deadline => "filesystem request deadline",
            Self::Crypto => "filesystem session cryptography unavailable",
        })
    }
}
impl std::error::Error for FilesystemSessionError {}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SessionScope {
    Project { project_id: String },
    User { installation_id: String },
    Hub,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    access_key: String,
    route: String,
    bucket: String,
    region: String,
    subject: String,
    scope: SessionScope,
    module: String,
    revision: i64,
    issued_at: u64,
    expires_at: u64,
    access: [Vec<String>; 4],
}
impl Payload {
    fn validated_scope(&self) -> Result<StorageScope, FilesystemSessionError> {
        let module = match self.module.as_str() {
            "hub" => StorageModule::Hub,
            "task" => StorageModule::Task,
            "memory" => StorageModule::Memory,
            "knowledge" => StorageModule::Knowledge,
            "ast" => StorageModule::Ast,
            _ => return Err(FilesystemSessionError::InvalidToken),
        };
        let scope = match &self.scope {
            SessionScope::Project { project_id } => StorageScope::project(project_id, module),
            SessionScope::User { installation_id } if module == StorageModule::Memory => {
                StorageScope::user_memory(installation_id)
            }
            SessionScope::Hub if module == StorageModule::Hub => Ok(StorageScope::global_hub()),
            _ => return Err(FilesystemSessionError::InvalidToken),
        };
        scope.map_err(|_| FilesystemSessionError::InvalidToken)
    }
    fn validate(
        &self,
        cfg: &FilesystemStorageRouteConfig,
        now: u64,
    ) -> Result<StorageScope, FilesystemSessionError> {
        let scope = self.validated_scope()?;
        if self.route != cfg.name
            || self.bucket != cfg.bucket
            || self.region != cfg.region
            || self.subject.is_empty()
            || self.revision <= 0
            || self.issued_at > now
            || !self
                .expires_at
                .checked_sub(self.issued_at)
                .is_some_and(|n| (900..=43200).contains(&n))
            || URL_SAFE_NO_PAD.decode(&self.access_key).is_err()
            || self.access_key.len() != 43
            || self.access.iter().all(Vec::is_empty)
        {
            return Err(FilesystemSessionError::InvalidToken);
        }
        let base = format!("{}/", cfg.base_prefix);
        for roots in &self.access {
            let mut unique = BTreeSet::new();
            for root in roots {
                if !key(root)
                    || !root.starts_with(&base)
                    || root.len() <= base.len()
                    || !unique.insert(root)
                {
                    return Err(FilesystemSessionError::InvalidToken);
                }
            }
        }
        if now >= self.expires_at {
            return Err(FilesystemSessionError::Expired);
        }
        Ok(scope)
    }
}
fn seconds(now: SystemTime) -> Result<u64, FilesystemSessionError> {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| FilesystemSessionError::InvalidToken)
}
fn mac(
    pepper: &[u8],
    domain: &[u8],
    parts: &[&[u8]],
) -> Result<Hmac<Sha256>, FilesystemSessionError> {
    let mut m = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(pepper)
        .map_err(|_| FilesystemSessionError::Crypto)?;
    m.update(domain);
    for p in parts {
        m.update(&(p.len() as u64).to_be_bytes());
        m.update(p);
    }
    Ok(m)
}
fn secret(
    pepper: &[u8],
    access_key: &str,
    tag: &[u8],
) -> Result<Zeroizing<String>, FilesystemSessionError> {
    let digest = Zeroizing::new(<[u8; 32]>::from(
        mac(pepper, SECRET_DOMAIN, &[access_key.as_bytes(), tag])?
            .finalize()
            .into_bytes(),
    ));
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(digest.as_ref())))
}

/// Only the MAC verifier constructs this proof. It is not SQL admission or an S3 signature.
/// ~~~compile_fail
/// fn clone<T: Clone>() {} clone::<broker_storage::VerifiedFilesystemSession>();
/// ~~~
/// ~~~compile_fail
/// fn default<T: Default>() {} default::<broker_storage::VerifiedFilesystemSession>();
/// ~~~
/// ~~~compile_fail
/// fn wire<T: serde::de::DeserializeOwned>() {} wire::<broker_storage::VerifiedFilesystemSession>();
/// ~~~
/// ~~~compile_fail
/// fn forge(s: &broker_storage::VerifiedFilesystemSession) { let _ = &s.payload; }
/// ~~~
pub struct VerifiedFilesystemSession {
    payload: Payload,
    scope: StorageScope,
    secret: Zeroizing<String>,
    deadline: Instant,
}
impl fmt::Debug for VerifiedFilesystemSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedFilesystemSession([REDACTED])")
    }
}
impl VerifiedFilesystemSession {
    pub(crate) fn bounded_deadline(&self, original: Instant) -> Instant {
        self.deadline.min(original)
    }
    pub fn bucket(&self) -> &str {
        &self.payload.bucket
    }
    pub fn region(&self) -> &str {
        &self.payload.region
    }
    pub fn access_key_id(&self) -> &str {
        &self.payload.access_key
    }
    /// Used by the request-scoped S3Auth, which must still verify the actual SigV4 request.
    pub fn secret_access_key(&self) -> &str {
        &self.secret
    }
    pub fn scope(&self) -> &StorageScope {
        &self.scope
    }
    pub fn canonical_subject(&self) -> &str {
        &self.payload.subject
    }
    pub fn authorization_revision(&self) -> i64 {
        self.payload.revision
    }
    pub fn expiry(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.payload.expires_at)
    }
    pub fn check(&self, original_deadline: Instant) -> Result<(), FilesystemSessionError> {
        if Instant::now() >= self.deadline || seconds(SystemTime::now())? >= self.payload.expires_at
        {
            return Err(FilesystemSessionError::Expired);
        }
        if Instant::now() >= original_deadline {
            return Err(FilesystemSessionError::Deadline);
        }
        Ok(())
    }
    fn covered(&self, indices: &[usize], target: &str) -> bool {
        indices.iter().any(|i| {
            self.payload.access[*i].iter().any(|root| {
                target == root
                    || target
                        .strip_prefix(root)
                        .is_some_and(|s| s.starts_with('/'))
            })
        })
    }
    pub fn allows(&self, operation: StorageOperation, target: &str) -> bool {
        if !key(target) || self.check(self.deadline).is_err() {
            return false;
        }
        self.covered(
            match operation {
                StorageOperation::Read => &[0, 1, 2],
                StorageOperation::Write => &[1, 2],
                StorageOperation::Publish => &[2],
                StorageOperation::Delete => &[2, 3],
            },
            target,
        )
    }
    pub fn allows_list(&self, prefix: &str) -> bool {
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        self.allows(StorageOperation::Read, prefix)
    }
}

pub struct FilesystemStorageIssuer {
    routes: BTreeMap<String, FilesystemStorageRoute>,
    pepper: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for FilesystemStorageIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FilesystemStorageIssuer([REDACTED])")
    }
}
impl FilesystemStorageIssuer {
    pub(crate) fn gateway_routes(&self) -> impl Iterator<Item = &FilesystemStorageRouteConfig> {
        self.routes.values().map(|route| &route.config)
    }
    pub fn new(
        routes: Vec<FilesystemStorageRoute>,
        pepper: Zeroizing<Vec<u8>>,
    ) -> Result<Self, StorageIssueError> {
        if pepper.len() < 32 || routes.is_empty() {
            return Err(StorageIssueError::InvalidConfiguration);
        }
        let mut named = BTreeMap::new();
        let mut buckets = BTreeSet::new();
        for route in routes {
            if !buckets.insert(route.config.bucket.clone())
                || named.insert(route.config.name.clone(), route).is_some()
            {
                return Err(StorageIssueError::InvalidConfiguration);
            }
        }
        Ok(Self {
            routes: named,
            pepper,
        })
    }
    pub async fn issue(
        &self,
        grant: &AuthorizedStorageGrant<'_>,
    ) -> Result<IssuedStorageCredentials, StorageIssueError> {
        grant.check()?;
        let result = self.issue_current(grant);
        grant.check()?;
        result
    }
    fn issue_current(
        &self,
        grant: &AuthorizedStorageGrant<'_>,
    ) -> Result<IssuedStorageCredentials, StorageIssueError> {
        let cfg = &self
            .routes
            .get(grant.route())
            .ok_or(StorageIssueError::RouteUnavailable)?
            .config;
        let now = seconds(SystemTime::now()).map_err(|_| StorageIssueError::InvalidResponse)?;
        let expires_at = now
            .checked_add(cfg.session_duration.as_secs())
            .ok_or(StorageIssueError::InvalidConfiguration)?;
        let mut random = Zeroizing::new([0u8; 32]);
        getrandom::fill(random.as_mut()).map_err(|_| StorageIssueError::Provider)?;
        let payload = Payload {
            access_key: URL_SAFE_NO_PAD.encode(random.as_ref()),
            route: cfg.name.clone(),
            bucket: cfg.bucket.clone(),
            region: cfg.region.clone(),
            subject: grant.canonical_subject(),
            scope: match (grant.scope().project_id(), grant.scope().installation_id()) {
                (Some(id), None) => SessionScope::Project {
                    project_id: id.into(),
                },
                (None, Some(id)) => SessionScope::User {
                    installation_id: id.into(),
                },
                (None, None) => SessionScope::Hub,
                _ => return Err(StorageIssueError::InvalidConfiguration),
            },
            module: grant.scope().module().as_str().into(),
            revision: grant.revision(),
            issued_at: now,
            expires_at,
            access: std::array::from_fn(|i| {
                grant
                    .prefixes(OPERATIONS[i])
                    .iter()
                    .map(|p| format!("{}/{p}", cfg.base_prefix))
                    .collect()
            }),
        };
        payload
            .validate(cfg, now)
            .map_err(|_| StorageIssueError::InvalidConfiguration)?;
        let token = self
            .encode(&payload)
            .map_err(|_| StorageIssueError::InvalidResponse)?;
        if token.len() > cfg.token_bytes.get() {
            return Err(StorageIssueError::PolicyTooLarge);
        }
        let verified = self
            .verify_session(grant.route(), &payload.access_key, &token)
            .map_err(|_| StorageIssueError::InvalidResponse)?;
        let expiry = verified.expiry();
        let expires_at = DateTime::from_secs(
            i64::try_from(expires_at).map_err(|_| StorageIssueError::InvalidResponse)?,
        )
        .fmt(DateTimeFormat::DateTime)
        .map_err(|_| StorageIssueError::InvalidResponse)?;
        grant.check()?;
        verified
            .check(grant.request_deadline())
            .map_err(|_| StorageIssueError::Deadline)?;
        let issued = IssuedStorageCredentials {
            key: Zeroizing::new(payload.access_key),
            secret: verified.secret,
            token,
            expires_at,
            expiry,
            bucket: cfg.bucket.clone(),
            region: cfg.region.clone(),
            endpoint: Some(cfg.endpoint.clone()),
            conditional_delete: true,
            copy_if_not_exists: crate::StorageCopyIfNotExists::IfNoneMatch,
            base_prefix: cfg.base_prefix.clone(),
            project_id: grant.scope().project_id().unwrap_or_default().into(),
            revision: grant.revision(),
        };
        grant.check()?;
        if SystemTime::now() >= issued.expiry() {
            return Err(StorageIssueError::InvalidResponse);
        }
        Ok(issued)
    }
    fn encode(&self, payload: &Payload) -> Result<Zeroizing<String>, FilesystemSessionError> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(payload).map_err(|_| FilesystemSessionError::InvalidToken)?,
        );
        let tag = mac(&self.pepper, TOKEN_DOMAIN, &[bytes.as_ref()])?
            .finalize()
            .into_bytes();
        Ok(Zeroizing::new(format!(
            "{TOKEN_PREFIX}.{}.{}",
            URL_SAFE_NO_PAD.encode(bytes.as_slice()),
            URL_SAFE_NO_PAD.encode(tag)
        )))
    }
    pub fn verify_session(
        &self,
        route: &str,
        access_key: &str,
        token: &str,
    ) -> Result<VerifiedFilesystemSession, FilesystemSessionError> {
        let monotonic = Instant::now();
        let utc = SystemTime::now();
        self.verify_at(route, access_key, token, utc, monotonic)
    }
    fn verify_at(
        &self,
        route: &str,
        access_key: &str,
        token: &str,
        utc: SystemTime,
        monotonic: Instant,
    ) -> Result<VerifiedFilesystemSession, FilesystemSessionError> {
        let cfg = &self
            .routes
            .get(route)
            .ok_or(FilesystemSessionError::RouteUnavailable)?
            .config;
        if token.len() > cfg.token_bytes.get() {
            return Err(FilesystemSessionError::InvalidToken);
        }
        let mut fields = token.split('.');
        if fields.next() != Some(TOKEN_PREFIX) {
            return Err(FilesystemSessionError::InvalidToken);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(fields.next().ok_or(FilesystemSessionError::InvalidToken)?)
                .map_err(|_| FilesystemSessionError::InvalidToken)?,
        );
        let tag = URL_SAFE_NO_PAD
            .decode(fields.next().ok_or(FilesystemSessionError::InvalidToken)?)
            .map_err(|_| FilesystemSessionError::InvalidToken)?;
        if fields.next().is_some() {
            return Err(FilesystemSessionError::InvalidToken);
        }
        mac(&self.pepper, TOKEN_DOMAIN, &[bytes.as_ref()])?
            .verify_slice(&tag)
            .map_err(|_| FilesystemSessionError::InvalidToken)?;
        let payload: Payload =
            serde_json::from_slice(&bytes).map_err(|_| FilesystemSessionError::InvalidToken)?;
        let scope = payload.validate(cfg, seconds(utc)?)?;
        if payload.access_key != access_key {
            return Err(FilesystemSessionError::InvalidToken);
        }
        let expiry = UNIX_EPOCH
            .checked_add(Duration::from_secs(payload.expires_at))
            .ok_or(FilesystemSessionError::InvalidToken)?;
        let remaining = expiry
            .duration_since(utc)
            .map_err(|_| FilesystemSessionError::Expired)?;
        let deadline = monotonic
            .checked_add(remaining)
            .ok_or(FilesystemSessionError::InvalidToken)?;
        let secret = secret(&self.pepper, &payload.access_key, &tag)?;
        let verified = VerifiedFilesystemSession {
            payload,
            scope,
            secret,
            deadline,
        };
        verified.check(deadline)?;
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PROJECT: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
    fn config() -> FilesystemStorageRouteConfig {
        FilesystemStorageRouteConfig {
            name: "primary".into(),
            bucket: "graphit-local".into(),
            region: "us-east-1".into(),
            base_prefix: "tenant".into(),
            endpoint: "http://127.0.0.1:9000".into(),
            session_duration: Duration::from_secs(900),
            token_bytes: NonZeroUsize::new(65536).unwrap(),
        }
    }
    fn issuer(pepper: u8) -> FilesystemStorageIssuer {
        FilesystemStorageIssuer::new(
            vec![FilesystemStorageRoute::new(config()).unwrap()],
            Zeroizing::new(vec![pepper; 32]),
        )
        .unwrap()
    }
    fn payload() -> Payload {
        let now = seconds(SystemTime::now()).unwrap();
        Payload {
            access_key: URL_SAFE_NO_PAD.encode([0x51u8; 32]),
            route: "primary".into(),
            bucket: "graphit-local".into(),
            region: "us-east-1".into(),
            subject: "fixture|subject".into(),
            scope: SessionScope::Project {
                project_id: PROJECT.into(),
            },
            module: "hub".into(),
            revision: 7,
            issued_at: now,
            expires_at: now + 900,
            access: [
                vec![format!("tenant/v1/projects/{PROJECT}/artifacts")],
                vec![],
                vec![],
                vec![],
            ],
        }
    }
    #[test]
    fn explicit_configuration_and_key_bounds() {
        assert!(FilesystemStorageRoute::new(config()).is_ok());
        for endpoint in [
            "http://remote.example",
            "https://example/path",
            "https://user:pass@example",
            "https://example/?query=x",
            "https://example/#fragment",
            "file:///tmp",
        ] {
            let mut c = config();
            c.endpoint = endpoint.into();
            assert!(FilesystemStorageRoute::new(c).is_err());
        }
        for bucket in [
            "v1", "admin", "metrics", "a..b", "Abucket", "-bucket", "bucket-", "ab",
        ] {
            let mut c = config();
            c.bucket = bucket.into();
            assert!(FilesystemStorageRoute::new(c).is_err());
        }
        for duration in [
            Duration::from_secs(899),
            Duration::from_secs(43201),
            Duration::new(900, 1),
        ] {
            let mut c = config();
            c.session_duration = duration;
            assert!(FilesystemStorageRoute::new(c).is_err());
        }
        assert!(FilesystemStorageIssuer::new(vec![], Zeroizing::new(vec![1; 32])).is_err());
        assert!(
            FilesystemStorageIssuer::new(
                vec![FilesystemStorageRoute::new(config()).unwrap()],
                Zeroizing::new(vec![1; 31])
            )
            .is_err()
        );
        assert!(
            FilesystemStorageIssuer::new(
                vec![
                    FilesystemStorageRoute::new(config()).unwrap(),
                    FilesystemStorageRoute::new(config()).unwrap()
                ],
                Zeroizing::new(vec![1; 32])
            )
            .is_err()
        );
        for bad in [
            "",
            "/a",
            "a/",
            "a//b",
            "a/../b",
            "a/./b",
            "a\\b",
            "a\"b",
            "unicode-ç",
        ] {
            assert!(!key(bad));
        }
        assert!(key(&"k".repeat(1024)));
        assert!(!key(&"k".repeat(1025)));
        assert!(key("a/space key"));
    }
    #[test]
    fn native_mac_binding_rotation_and_deadlines() {
        let first = issuer(0x71);
        let p = payload();
        let token = first.encode(&p).unwrap();
        let proof = first
            .verify_session("primary", &p.access_key, &token)
            .unwrap();
        assert_eq!(
            proof.secret_access_key(),
            issuer(0x71)
                .verify_session("primary", &p.access_key, &token)
                .unwrap()
                .secret_access_key()
        );
        assert!(
            issuer(0x72)
                .verify_session("primary", &p.access_key, &token)
                .is_err()
        );
        assert!(
            first
                .verify_session("missing", &p.access_key, &token)
                .is_err()
        );
        assert!(
            first
                .verify_session("primary", &URL_SAFE_NO_PAD.encode([0x52u8; 32]), &token)
                .is_err()
        );
        for altered in [
            format!("{}.extra", token.as_str()),
            token.replacen("rust-fs1", "v2", 1),
            token.replacen("rust-fs1", "rust-fs2", 1),
            format!("{}=", token.as_str()),
            "rust-fs1..".into(),
        ] {
            assert!(
                first
                    .verify_session("primary", &p.access_key, &altered)
                    .is_err()
            );
        }
        let mut altered = token.as_bytes().to_vec();
        let i = altered.iter().position(|b| *b == b'.').unwrap() + 5;
        altered[i] = if altered[i] == b'A' { b'B' } else { b'A' };
        assert!(
            first
                .verify_session(
                    "primary",
                    &p.access_key,
                    std::str::from_utf8(&altered).unwrap()
                )
                .is_err()
        );
        assert_eq!(
            first
                .verify_at(
                    "primary",
                    &p.access_key,
                    &token,
                    UNIX_EPOCH + Duration::from_secs(p.expires_at),
                    Instant::now()
                )
                .err(),
            Some(FilesystemSessionError::Expired)
        );
        assert_eq!(
            first
                .verify_at(
                    "primary",
                    &p.access_key,
                    &token,
                    SystemTime::now(),
                    Instant::now() - Duration::from_secs(901)
                )
                .err(),
            Some(FilesystemSessionError::Expired)
        );
        assert_eq!(
            proof.check(Instant::now() - Duration::from_secs(1)),
            Err(FilesystemSessionError::Deadline)
        );
        let mut c = config();
        c.token_bytes = NonZeroUsize::new(token.len() - 1).unwrap();
        let tiny = FilesystemStorageIssuer::new(
            vec![FilesystemStorageRoute::new(c).unwrap()],
            Zeroizing::new(vec![0x71; 32]),
        )
        .unwrap();
        assert!(
            tiny.verify_session("primary", &p.access_key, &token)
                .is_err()
        );
        assert_eq!(
            format!("{proof:?}"),
            "VerifiedFilesystemSession([REDACTED])"
        );
        assert_eq!(format!("{first:?}"), "FilesystemStorageIssuer([REDACTED])");
    }
    #[test]
    fn operation_union_and_exact_prefix_boundaries() {
        let codec = issuer(0x71);
        for index in 0..4 {
            let mut p = payload();
            let root = p.access[0][0].clone();
            p.access = std::array::from_fn(|_| vec![]);
            p.access[index].push(root.clone());
            let token = codec.encode(&p).unwrap();
            let proof = codec
                .verify_session("primary", &p.access_key, &token)
                .unwrap();
            assert_eq!(proof.allows(StorageOperation::Read, &root), index != 3);
            assert_eq!(
                proof.allows(StorageOperation::Write, &format!("{root}/object")),
                index == 1 || index == 2
            );
            assert_eq!(
                proof.allows(StorageOperation::Delete, &root),
                index == 2 || index == 3
            );
            assert_eq!(proof.allows_list(&format!("{root}/")), index != 3);
            for bad in [
                "tenant".into(),
                format!("{root}2/escaped"),
                format!("{root}/../escaped"),
                format!("{root}/double//slash"),
            ] {
                assert!(!proof.allows(StorageOperation::Read, &bad));
                assert!(!proof.allows_list(&bad));
            }
        }
    }
    #[test]
    fn authenticated_payload_requires_closed_semantics() {
        let codec = issuer(0x71);
        for case in 0..9 {
            let mut p = payload();
            match case {
                0 => p.revision = 0,
                1 => p.subject.clear(),
                2 => p.module = "unsupported".into(),
                3 => {
                    p.scope = SessionScope::User {
                        installation_id: "Install-A".into(),
                    }
                }
                4 => p.access[0][0] = "outside/namespace".into(),
                5 => {
                    let root = p.access[0][0].clone();
                    p.access[0].push(root);
                }
                6 => p.bucket = "other-bucket".into(),
                7 => p.region = "other-region".into(),
                8 => p.issued_at = p.expires_at + 1,
                _ => unreachable!(),
            };
            let token = codec.encode(&p).unwrap();
            assert!(
                codec
                    .verify_session("primary", &p.access_key, &token)
                    .is_err()
            );
        }
        let p = payload();
        let mut json = serde_json::to_value(&p).unwrap();
        json["unknown"] = "forbidden".into();
        let bytes = serde_json::to_vec(&json).unwrap();
        let tag = mac(&codec.pepper, TOKEN_DOMAIN, &[&bytes])
            .unwrap()
            .finalize()
            .into_bytes();
        let token = format!(
            "{TOKEN_PREFIX}.{}.{}",
            URL_SAFE_NO_PAD.encode(bytes),
            URL_SAFE_NO_PAD.encode(tag)
        );
        assert!(
            codec
                .verify_session("primary", &p.access_key, &token)
                .is_err()
        );
    }
}
