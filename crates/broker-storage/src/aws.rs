use crate::issued::{IssuedStorageCredentials, StorageIssueError};
use aws_config::{retry::RetryConfig, timeout::TimeoutConfig};
use aws_sdk_sts::{
    Client,
    config::{BehaviorVersion, Credentials, ProvideCredentials, Region},
    error::ProvideErrorMetadata,
    primitives::DateTimeFormat,
};
use broker_control::{AuthorizedStorageGrant, StorageOperation};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::OnceCell;
use url::{Host, Url};
use zeroize::Zeroizing;
const OPERATIONS: [StorageOperation; 4] = [
    StorageOperation::Read,
    StorageOperation::Write,
    StorageOperation::Publish,
    StorageOperation::Delete,
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsEndpointTransport {
    HttpsOnly,
    LoopbackHttp,
}
/// An indivisible configured server pair, never a caller's bearer.
pub struct PrivateStaticCredentials {
    key: Zeroizing<String>,
    secret: Zeroizing<String>,
}
impl PrivateStaticCredentials {
    pub fn new(
        key: Zeroizing<String>,
        secret: Zeroizing<String>,
    ) -> Result<Self, StorageIssueError> {
        if key.is_empty() || secret.is_empty() {
            return Err(StorageIssueError::InvalidConfiguration);
        }
        Ok(Self { key, secret })
    }
}
impl fmt::Debug for PrivateStaticCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateStaticCredentials([REDACTED])")
    }
}
pub enum AwsCredentialSource {
    DefaultChain,
    StaticPair(PrivateStaticCredentials),
}
impl fmt::Debug for AwsCredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AwsCredentialSource([REDACTED])")
    }
}
/// Required server fields. Active defaults belong to the server compositor.
pub struct AwsStorageRouteConfig {
    pub name: String,
    pub region: String,
    pub bucket: String,
    pub base_prefix: String,
    /// Whether this configured backend atomically enforces If-Match on DELETE.
    pub conditional_delete: bool,
    pub s3_endpoint: Option<String>,
    pub sts_endpoint: Option<String>,
    pub role_arn: String,
    pub session_name: String,
    pub session_duration: Duration,
    pub credential_source: AwsCredentialSource,
    pub endpoint_transport: AwsEndpointTransport,
}
impl fmt::Debug for AwsStorageRouteConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AwsStorageRouteConfig([REDACTED])")
    }
}
pub struct AwsStorageRoute {
    config: AwsStorageRouteConfig,
    sdk: OnceCell<aws_config::SdkConfig>,
    catalog: OnceCell<object_store::aws::AmazonS3>,
}
impl fmt::Debug for AwsStorageRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AwsStorageRoute([REDACTED])")
    }
}
fn safe_segment(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c))
}
fn safe_prefix(s: &str) -> bool {
    !s.is_empty() && s.split('/').all(safe_segment)
}
fn endpoint(s: &str, transport: AwsEndpointTransport) -> bool {
    let Ok(url) = Url::parse(s) else {
        return false;
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    if url.scheme() == "https" {
        return true;
    }
    transport == AwsEndpointTransport::LoopbackHttp
        && url.scheme() == "http"
        && match url.host() {
            Some(Host::Domain(host)) => host == "localhost",
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        }
}
impl AwsStorageRoute {
    pub fn new(mut config: AwsStorageRouteConfig) -> Result<Self, StorageIssueError> {
        let seconds = config.session_duration.as_secs();
        config.base_prefix = config.base_prefix.trim().trim_matches('/').into();
        config.session_name = config.session_name.trim().into();
        if !safe_segment(&config.name)
            || !safe_segment(&config.bucket)
            || !safe_prefix(&config.base_prefix)
            || config.base_prefix.len() > 1024
            || config.region.is_empty()
            || !config
                .region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !(20..=2048).contains(&config.role_arn.len())
            || !config.role_arn.starts_with("arn:")
            || config
                .role_arn
                .bytes()
                .any(|b| !b.is_ascii() || b.is_ascii_whitespace())
            || !(2..=64).contains(&config.session_name.len())
            || !config
                .session_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
            || !(900..=43200).contains(&seconds)
            || config.session_duration.subsec_nanos() != 0
            || config
                .s3_endpoint
                .as_deref()
                .is_some_and(|s| !endpoint(s, config.endpoint_transport))
            || config
                .sts_endpoint
                .as_deref()
                .is_some_and(|s| !endpoint(s, config.endpoint_transport))
        {
            return Err(StorageIssueError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            sdk: OnceCell::new(),
            catalog: OnceCell::new(),
        })
    }
}
pub struct AwsStorageIssuer {
    routes: BTreeMap<String, AwsStorageRoute>,
    timeout: Duration,
}
impl fmt::Debug for AwsStorageIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AwsStorageIssuer([REDACTED])")
    }
}
impl AwsStorageIssuer {
    pub(crate) fn route_names(&self) -> impl Iterator<Item = &str> {
        self.routes.keys().map(String::as_str)
    }

    pub fn new(
        routes: Vec<AwsStorageRoute>,
        request_timeout: Duration,
    ) -> Result<Self, StorageIssueError> {
        if request_timeout.is_zero()
            || Instant::now().checked_add(request_timeout).is_none()
            || routes.is_empty()
        {
            return Err(StorageIssueError::InvalidConfiguration);
        }
        let mut named = BTreeMap::new();
        for route in routes {
            let name = route.config.name.clone();
            if named.insert(name, route).is_some() {
                return Err(StorageIssueError::InvalidConfiguration);
            }
        }
        Ok(Self {
            routes: named,
            timeout: request_timeout,
        })
    }
    /// Consume an actual current grant obtained from the SQL admission factory.
    /// ~~~no_run
    /// async fn issue(
    ///     issuer: &broker_storage::AwsStorageIssuer,
    ///     grant: &broker_control::AuthorizedStorageGrant<'_>,
    /// ) -> Result<(), broker_storage::StorageIssueError> {
    ///     grant.check()?;
    ///     let credentials = issuer.issue(grant).await?;
    ///     assert!(!credentials.session_token().is_empty());
    ///     Ok(())
    /// }
    /// ~~~
    pub async fn issue(
        &self,
        grant: &AuthorizedStorageGrant<'_>,
    ) -> Result<IssuedStorageCredentials, StorageIssueError> {
        grant.check()?;
        let end = grant.request_deadline().min(
            Instant::now()
                .checked_add(self.timeout)
                .ok_or(StorageIssueError::InvalidConfiguration)?,
        );
        let result = async {
            let route = self
                .routes
                .get(grant.route())
                .ok_or(StorageIssueError::RouteUnavailable)?;
            let access: [Vec<String>; 4] =
                std::array::from_fn(|i| grant.prefixes(OPERATIONS[i]).to_vec());
            let policy = policy(&route.config, &access)?;
            let name = session_name(&route.config.session_name, &grant.canonical_subject());
            grant.check()?;
            let network = tokio::time::timeout_at(end.into(), async {
                let cfg = &route.config;
                let mut builder = match &cfg.credential_source {
                    AwsCredentialSource::DefaultChain => {
                        let shared = route
                            .sdk
                            .get_or_try_init(|| async {
                                let value = aws_config::defaults(BehaviorVersion::v2026_01_12())
                                    .region(Region::new(cfg.region.clone()))
                                    .load()
                                    .await;
                                Ok::<_, StorageIssueError>(value)
                            })
                            .await?;
                        grant.check()?;
                        let provider = shared
                            .credentials_provider()
                            .ok_or(StorageIssueError::Provider)?;
                        let credentials = provider
                            .provide_credentials()
                            .await
                            .map_err(|_| StorageIssueError::Provider)?;
                        grant.check()?;
                        aws_sdk_sts::Config::from(shared)
                            .to_builder()
                            .credentials_provider(credentials)
                    }
                    AwsCredentialSource::StaticPair(pair) => aws_sdk_sts::Config::builder()
                        .behavior_version(BehaviorVersion::v2026_01_12())
                        .region(Region::new(cfg.region.clone()))
                        .credentials_provider(Credentials::new(
                            pair.key.as_str(),
                            pair.secret.as_str(),
                            None,
                            None,
                            "broker-static-pair",
                        ))
                        .retry_config(RetryConfig::standard()),
                };
                let remaining = end
                    .checked_duration_since(Instant::now())
                    .ok_or(StorageIssueError::Deadline)?;
                builder = builder.timeout_config(
                    TimeoutConfig::builder()
                        .operation_timeout(remaining)
                        .operation_attempt_timeout(remaining)
                        .connect_timeout(remaining)
                        .build(),
                );
                // Only server route fields select the actual Role STS endpoint.
                // The SDK credential chain and retry configuration remain separate.
                apply_route_endpoint(cfg, &mut builder);
                grant.check()?;
                let output = Client::from_conf(builder.build())
                    .assume_role()
                    .role_arn(&cfg.role_arn)
                    .role_session_name(name)
                    .duration_seconds(
                        i32::try_from(cfg.session_duration.as_secs())
                            .map_err(|_| StorageIssueError::InvalidConfiguration)?,
                    )
                    .policy(policy)
                    .send()
                    .await
                    .map_err(|e| {
                        if matches!(&e, aws_sdk_sts::error::SdkError::TimeoutError(_)) {
                            return StorageIssueError::Deadline;
                        }
                        if e.as_service_error()
                            .and_then(|s| s.code())
                            .is_some_and(|s| matches!(s, "AccessDenied" | "AccessDeniedException"))
                        {
                            StorageIssueError::Forbidden
                        } else {
                            StorageIssueError::Sdk
                        }
                    })?;
                grant.check()?;
                let credentials = output
                    .credentials()
                    .ok_or(StorageIssueError::InvalidResponse)?;
                issued(cfg, grant, credentials)
            })
            .await;
            network.map_err(|_| StorageIssueError::Deadline)?
        }
        .await;
        grant.check()?;
        if Instant::now() >= end {
            return Err(StorageIssueError::Deadline);
        }
        result
    }
}
fn apply_route_endpoint(cfg: &AwsStorageRouteConfig, builder: &mut aws_sdk_sts::config::Builder) {
    builder.set_endpoint_url(
        cfg.sts_endpoint
            .as_ref()
            .or(cfg.s3_endpoint.as_ref())
            .cloned(),
    );
}
fn session_name(base: &str, subject: &str) -> String {
    let hash = Sha256::digest(subject.as_bytes());
    let suffix: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
    let base = base.trim().trim_matches(['-', '_']);
    let base = &base[..base.len().min(47)];
    format!("{base}-{suffix}")
}
fn policy(
    cfg: &AwsStorageRouteConfig,
    access: &[Vec<String>; 4],
) -> Result<String, StorageIssueError> {
    let mut permissions: BTreeMap<String, (bool, BTreeSet<&str>)> = BTreeMap::new();
    for (operation, roots) in OPERATIONS.iter().zip(access) {
        for root in roots {
            if !safe_prefix(root) {
                return Err(StorageIssueError::InvalidConfiguration);
            }
            let prefix = format!("{}/{root}", cfg.base_prefix);
            if prefix.len() > 1024 {
                return Err(StorageIssueError::InvalidConfiguration);
            }
            let entry = permissions.entry(prefix).or_default();
            let actions: &[&str] = match operation {
                StorageOperation::Read => &["s3:GetObject"],
                StorageOperation::Write => &[
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts",
                ],
                StorageOperation::Publish => &[
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts",
                ],
                StorageOperation::Delete => &["s3:DeleteObject"],
            };
            entry.0 |= *operation != StorageOperation::Delete;
            entry.1.extend(actions.iter().copied());
        }
    }
    if permissions.is_empty() {
        return Err(StorageIssueError::Forbidden);
    }
    let bucket = format!("arn:aws:s3:::{}", cfg.bucket);
    let mut statements =
        vec![json!({"Effect":"Allow","Action":["s3:GetBucketLocation"],"Resource":[&bucket]})];
    let mut listing = BTreeSet::new();
    let mut objects: BTreeMap<Vec<&str>, BTreeSet<String>> = BTreeMap::new();
    for (prefix, (list, actions)) in &permissions {
        let mut list = *list;
        let mut actions = actions.clone();
        // An ancestor's exact root plus /* already covers this descendant.
        // Keep only additional actions here; never coalesce sibling prefixes.
        for (ancestor, (ancestor_list, ancestor_actions)) in &permissions {
            if ancestor == prefix {
                break;
            }
            if prefix
                .strip_prefix(ancestor.as_str())
                .is_some_and(|suffix| suffix.starts_with('/'))
            {
                list &= !*ancestor_list;
                actions.retain(|action| !ancestor_actions.contains(action));
            }
        }
        if list {
            listing.insert(prefix.clone());
            listing.insert(format!("{prefix}/*"));
        }
        if !actions.is_empty() {
            let resources = objects.entry(actions.into_iter().collect()).or_default();
            resources.insert(format!("{bucket}/{prefix}"));
            resources.insert(format!("{bucket}/{prefix}/*"));
        }
    }
    if !listing.is_empty() {
        statements.push(json!({"Effect":"Allow","Action":["s3:ListBucket"],"Resource":[&bucket],"Condition":{"StringLike":{"s3:prefix":listing}}}));
    }
    for (actions, resources) in objects {
        statements.push(json!({"Effect":"Allow","Action":actions,"Resource":resources}));
    }
    let bytes = serde_json::to_vec(&json!({"Version":"2012-10-17","Statement":statements}))
        .map_err(|_| StorageIssueError::InvalidConfiguration)?;
    if bytes.len() > 2048 {
        return Err(StorageIssueError::PolicyTooLarge);
    }
    String::from_utf8(bytes).map_err(|_| StorageIssueError::InvalidConfiguration)
}
fn issued(
    cfg: &AwsStorageRouteConfig,
    grant: &AuthorizedStorageGrant<'_>,
    credentials: &aws_sdk_sts::types::Credentials,
) -> Result<IssuedStorageCredentials, StorageIssueError> {
    grant.check()?;
    let key = credentials.access_key_id();
    let secret = credentials.secret_access_key();
    let token = credentials.session_token();
    let (expiry, expires_at) = validated_credentials_expiry(credentials)?;
    let result = IssuedStorageCredentials {
        key: Zeroizing::new(key.into()),
        secret: Zeroizing::new(secret.into()),
        token: Zeroizing::new(token.into()),
        expires_at,
        expiry,
        bucket: cfg.bucket.clone(),
        region: cfg.region.clone(),
        endpoint: cfg.s3_endpoint.clone(),
        conditional_delete: cfg.conditional_delete,
        copy_if_not_exists: crate::StorageCopyIfNotExists::Multipart,
        base_prefix: cfg.base_prefix.clone(),
        project_id: grant.scope().project_id().unwrap_or_default().into(),
        revision: grant.revision(),
    };
    grant.check()?;
    Ok(result)
}
fn validated_credentials_expiry(
    credentials: &aws_sdk_sts::types::Credentials,
) -> Result<(SystemTime, String), StorageIssueError> {
    let key = credentials.access_key_id();
    let secret = credentials.secret_access_key();
    let token = credentials.session_token();
    if key.is_empty() || secret.is_empty() || token.is_empty() {
        return Err(StorageIssueError::InvalidResponse);
    }
    let exp = credentials.expiration();
    let seconds = u64::try_from(exp.secs()).map_err(|_| StorageIssueError::InvalidResponse)?;
    let expiry = UNIX_EPOCH
        .checked_add(Duration::new(seconds, exp.subsec_nanos()))
        .ok_or(StorageIssueError::InvalidResponse)?;
    if expiry <= SystemTime::now() {
        return Err(StorageIssueError::InvalidResponse);
    }
    let expires_at = exp
        .fmt(DateTimeFormat::DateTime)
        .map_err(|_| StorageIssueError::InvalidResponse)?;
    Ok((expiry, expires_at))
}
impl AwsStorageIssuer {
    pub(crate) async fn catalog(
        &self,
        route: &str,
    ) -> Result<(&object_store::aws::AmazonS3, &str), StorageIssueError> {
        let route = self
            .routes
            .get(route)
            .ok_or(StorageIssueError::RouteUnavailable)?;
        let store = route
            .catalog
            .get_or_try_init(|| async {
                use object_store::aws::{AmazonS3Builder, AwsCredential};
                let cfg = &route.config;
                let provider: object_store::aws::AwsCredentialProvider =
                    match &cfg.credential_source {
                        AwsCredentialSource::StaticPair(pair) => std::sync::Arc::new(
                            object_store::StaticCredentialProvider::new(AwsCredential {
                                key_id: pair.key.to_string(),
                                secret_key: pair.secret.to_string(),
                                token: None,
                            }),
                        ),
                        AwsCredentialSource::DefaultChain => {
                            let sdk = route
                                .sdk
                                .get_or_try_init(|| async {
                                    Ok::<_, StorageIssueError>(
                                        aws_config::defaults(BehaviorVersion::v2026_01_12())
                                            .region(Region::new(cfg.region.clone()))
                                            .load()
                                            .await,
                                    )
                                })
                                .await?;
                            std::sync::Arc::new(CatalogCredentials(
                                sdk.credentials_provider()
                                    .ok_or(StorageIssueError::Provider)?,
                            ))
                        }
                    };
                let mut builder = AmazonS3Builder::new()
                    .with_bucket_name(&cfg.bucket)
                    .with_region(&cfg.region)
                    .with_credentials(provider);
                if let Some(endpoint) = &cfg.s3_endpoint {
                    builder = builder
                        .with_endpoint(endpoint)
                        .with_virtual_hosted_style_request(false);
                }
                builder
                    .with_allow_http(cfg.endpoint_transport == AwsEndpointTransport::LoopbackHttp)
                    .build()
                    .map_err(|_| StorageIssueError::InvalidConfiguration)
            })
            .await?;
        Ok((store, &route.config.base_prefix))
    }
}
struct CatalogCredentials(aws_sdk_sts::config::SharedCredentialsProvider);
impl fmt::Debug for CatalogCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CatalogCredentials([REDACTED])")
    }
}
#[async_trait::async_trait]
impl object_store::CredentialProvider for CatalogCredentials {
    type Credential = object_store::aws::AwsCredential;
    async fn get_credential(&self) -> object_store::Result<std::sync::Arc<Self::Credential>> {
        let credentials =
            self.0
                .provide_credentials()
                .await
                .map_err(|e| object_store::Error::Generic {
                    store: "Hub catalog credentials",
                    source: Box::new(e),
                })?;
        Ok(std::sync::Arc::new(object_store::aws::AwsCredential {
            key_id: credentials.access_key_id().to_owned(),
            secret_key: credentials.secret_access_key().to_owned(),
            token: credentials.session_token().map(str::to_owned),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> AwsStorageRouteConfig {
        AwsStorageRouteConfig {
            name: "primary".into(),
            region: "us-east-1".into(),
            bucket: "bucket".into(),
            base_prefix: "tenant".into(),
            conditional_delete: false,
            s3_endpoint: None,
            sts_endpoint: None,
            role_arn: "arn:aws:iam::123456789012:role/broker".into(),
            session_name: "graphit-broker".into(),
            session_duration: Duration::from_secs(3600),
            credential_source: AwsCredentialSource::DefaultChain,
            endpoint_transport: AwsEndpointTransport::HttpsOnly,
        }
    }
    #[test]
    fn explicit_transport_and_required_configuration() {
        assert!(AwsStorageRoute::new(config()).is_ok());
        let mut trimmed = config();
        trimmed.session_name = "  graphit-broker  ".into();
        let route = AwsStorageRoute::new(trimmed).unwrap();
        assert_eq!(route.config.session_name, "graphit-broker");
        for url in [
            "http://127.0.0.1:9000",
            "http://localhost:9000",
            "http://[::1]:9000",
        ] {
            assert!(!endpoint(url, AwsEndpointTransport::HttpsOnly));
            assert!(endpoint(url, AwsEndpointTransport::LoopbackHttp));
        }
        for url in [
            "http://remote.example",
            "https://user:password@remote.example",
            "ftp://127.0.0.1",
            "/relative",
            "http://127.0.0.1/?token=secret",
        ] {
            assert!(!endpoint(url, AwsEndpointTransport::LoopbackHttp));
        }
        for duration in [899, 43201] {
            let mut cfg = config();
            cfg.session_duration = Duration::from_secs(duration);
            assert!(AwsStorageRoute::new(cfg).is_err());
        }
        assert!(
            PrivateStaticCredentials::new(
                Zeroizing::new(String::new()),
                Zeroizing::new("secret".into())
            )
            .is_err()
        );
    }
    #[test]
    fn policy_is_literal_bounded_and_actions_follow_each_operation() {
        let cfg = config();
        let root = "v1/projects/01D39ZY06FGSCTVN4T2V9PKHFZ/artifacts".to_string();
        let mut access: [Vec<String>; 4] = std::array::from_fn(|_| vec![]);
        assert_eq!(
            policy(&cfg, &access).unwrap_err(),
            StorageIssueError::Forbidden
        );
        for (i, action) in [
            (0, "s3:GetObject"),
            (1, "s3:PutObject"),
            (2, "s3:DeleteObject"),
            (3, "s3:DeleteObject"),
        ] {
            access = std::array::from_fn(|_| vec![]);
            access[i] = vec![root.clone()];
            let value: serde_json::Value =
                serde_json::from_str(&policy(&cfg, &access).unwrap()).unwrap();
            assert!(
                value["Statement"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|s| s["Action"].as_array().unwrap().iter().any(|a| a == action))
            );
        }
        access[3] = vec![format!("{root}/*")];
        assert_eq!(
            policy(&cfg, &access).unwrap_err(),
            StorageIssueError::InvalidConfiguration
        );
        access[3] = (0..20).map(|i| format!("{root}/namespace-{i}")).collect();
        assert_eq!(
            policy(&cfg, &access).unwrap_err(),
            StorageIssueError::PolicyTooLarge
        );
        let name = session_name(&"x".repeat(64), "issuer|subject");
        assert_eq!(name.len(), 64);
        assert_eq!(name, session_name(&"x".repeat(64), "issuer|subject"));
    }
    #[test]
    fn hub_metadata_policy_omits_inherited_actions_without_widening_staging_delete() {
        let id = "01D39ZY06FGSCTVN4T2V9PKHFZ";
        let mut cfg = config();
        cfg.bucket = "graphit-sts-0123456789ab".into();
        cfg.base_prefix = format!("tenant/{id}");
        let roots: Vec<_> = ["registry", "artifacts", "hub/metadata"]
            .map(|suffix| format!("v1/projects/{id}/{suffix}"))
            .into();
        let staging = format!("{}/staging", roots[1]);
        let access = [
            roots.clone(),
            roots.iter().cloned().chain([staging.clone()]).collect(),
            vec![],
            vec![staging.clone()],
        ];
        let encoded = policy(&cfg, &access).expect("real Hub publication grants fit STS policy");
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        let statements = value["Statement"].as_array().unwrap();
        let object_prefix = format!("arn:aws:s3:::{}/{}", cfg.bucket, cfg.base_prefix);
        let deletes = statements
            .iter()
            .find(|s| {
                s["Action"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a == "s3:DeleteObject")
            })
            .unwrap();
        assert_eq!(deletes["Action"], json!(["s3:DeleteObject"]));
        assert_eq!(
            deletes["Resource"],
            json!([
                format!("{object_prefix}/{staging}"),
                format!("{object_prefix}/{staging}/*")
            ])
        );
        let writes = statements
            .iter()
            .find(|s| {
                s["Action"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a == "s3:PutObject")
            })
            .unwrap();
        let expected: BTreeSet<_> = roots
            .iter()
            .flat_map(|root| {
                [
                    format!("{object_prefix}/{root}"),
                    format!("{object_prefix}/{root}/*"),
                ]
            })
            .collect();
        let actual: BTreeSet<_> = writes["Resource"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(actual, expected);
        let listing = statements
            .iter()
            .find(|s| s["Condition"].is_object())
            .unwrap();
        assert_eq!(
            listing["Condition"]["StringLike"]["s3:prefix"]
                .as_array()
                .unwrap()
                .len(),
            6
        );
        // A lexical prefix is not a path ancestor: its sibling read survives.
        cfg.base_prefix = "t".into();
        let sibling = policy(
            &cfg,
            &[vec!["a".into(), "ab".into()], vec![], vec![], vec![]],
        )
        .unwrap();
        let sibling: serde_json::Value = serde_json::from_str(&sibling).unwrap();
        assert!(sibling["Statement"].as_array().unwrap().iter().any(|s| {
            s["Resource"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == &json!(format!("arn:aws:s3:::{}/t/ab/*", cfg.bucket)))
        }));
    }
    #[test]
    fn serialized_policy_exact_byte_boundary_and_full_prefix_limit() {
        let mut exact = None;
        for bucket_bytes in 1..=4 {
            let mut cfg = config();
            cfg.bucket = "b".repeat(bucket_bytes);
            for root_bytes in 1usize..=600 {
                let root = (0..root_bytes.div_ceil(100))
                    .map(|i| "r".repeat((root_bytes - i * 100).min(100)))
                    .collect::<Vec<_>>()
                    .join("/");
                let mut access: [Vec<String>; 4] = std::array::from_fn(|_| vec![]);
                access[0] = vec![root];
                if policy(&cfg, &access).is_ok_and(|p| p.len() == 2048) {
                    exact = Some((cfg, access));
                    break;
                }
            }
            if exact.is_some() {
                break;
            }
        }
        let (cfg, mut access) = exact.expect("valid policy at exactly 2048 bytes");
        assert_eq!(policy(&cfg, &access).unwrap().len(), 2048);
        access[0][0].push('r');
        assert_eq!(
            policy(&cfg, &access),
            Err(StorageIssueError::PolicyTooLarge)
        );
        access[0] = vec![vec!["r".repeat(128); 8].join("/")];
        assert_eq!(
            policy(&cfg, &access),
            Err(StorageIssueError::InvalidConfiguration)
        );
    }
    #[test]
    fn sdk_credential_data_requires_complete_fields_and_future_utc() {
        // SDK DATA validation only; this creates no Broker grant or network proof.
        let future = SystemTime::now() + Duration::from_secs(3600);
        let expiration = aws_sdk_sts::primitives::DateTime::from(future);
        let data = |fields: [&str; 3], exp| {
            aws_sdk_sts::types::Credentials::builder()
                .access_key_id(fields[0])
                .secret_access_key(fields[1])
                .session_token(fields[2])
                .expiration(exp)
                .build()
                .unwrap()
        };
        let (actual, text) =
            validated_credentials_expiry(&data(["key", "secret", "token"], expiration)).unwrap();
        assert_eq!(actual, future);
        assert!(text.ends_with('Z'));
        for fields in [
            ["", "secret", "token"],
            ["key", "", "token"],
            ["key", "secret", ""],
        ] {
            assert_eq!(
                validated_credentials_expiry(&data(fields, expiration)),
                Err(StorageIssueError::InvalidResponse)
            );
        }
        for seconds in [-1, 0, i64::MAX] {
            assert_eq!(
                validated_credentials_expiry(&data(
                    ["key", "secret", "token"],
                    aws_sdk_sts::primitives::DateTime::from_secs(seconds)
                )),
                Err(StorageIssueError::InvalidResponse)
            );
        }
    }
    #[tokio::test]
    async fn sdk_endpoint_environment_child() {
        if std::env::var("BROKER_STS_ENDPOINT_MODEL_CHILD").is_err() {
            return;
        }
        // SDK model/transport regression only: no Broker proof or STS response is fabricated.
        let shared = aws_config::defaults(BehaviorVersion::v2026_01_12())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new(
                "synthetic-model-key",
                "synthetic-model-secret",
                None,
                None,
                "fixture-model",
            ))
            .load()
            .await;
        let mut builder = aws_sdk_sts::Config::from(&shared).to_builder();
        apply_route_endpoint(&config(), &mut builder);
        let observed = std::sync::Arc::new(std::sync::Mutex::new(None));
        let capture = observed.clone();
        let result = Client::from_conf(builder.build())
            .assume_role()
            .role_arn("arn:aws:iam::123456789012:role/fixture")
            .role_session_name("fixture-model")
            .customize()
            .map_request(move |request| {
                *capture.lock().unwrap() = Some(request.uri().to_string());
                Err::<_, std::io::Error>(std::io::Error::other(
                    "model request captured before network",
                ))
            })
            .send()
            .await;
        assert!(result.is_err());
        let url = observed
            .lock()
            .unwrap()
            .clone()
            .expect("actual SDK endpoint resolution observed");
        assert!(
            url.starts_with("https://sts."),
            "server-only AWS endpoint expected"
        );
    }
    #[tokio::test]
    async fn environment_and_profile_cannot_select_role_http_transport() {
        let folder = tempfile::tempdir().unwrap();
        let profile = folder.path().join("config");
        std::fs::write(
            &profile,
            "[default]\nendpoint_url = http://198.51.100.9:9999\n",
        )
        .unwrap();
        for source in ["environment", "profile"] {
            let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
            // Set only the SDK inputs this case exercises, independently of
            // the developer's profiles, endpoint mode, or AWS credentials.
            for (name, _) in std::env::vars_os() {
                if name
                    .to_string_lossy()
                    .to_ascii_uppercase()
                    .starts_with("AWS_")
                {
                    command.env_remove(name);
                }
            }
            command
                .args([
                    "--exact",
                    "aws::tests::sdk_endpoint_environment_child",
                    "--test-threads=1",
                ])
                .env("BROKER_STS_ENDPOINT_MODEL_CHILD", source)
                .env("AWS_EC2_METADATA_DISABLED", "true")
                .env(
                    "AWS_CONFIG_FILE",
                    if source == "profile" {
                        profile.clone()
                    } else {
                        folder.path().join("absent-config")
                    },
                )
                .env(
                    "AWS_SHARED_CREDENTIALS_FILE",
                    folder.path().join("absent-credentials"),
                );
            if source == "environment" {
                command.env("AWS_ENDPOINT_URL_STS", "http://198.51.100.9:9999");
            }
            let mut child = command
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let status = match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
                Ok(status) => status.unwrap(),
                Err(_) => {
                    child.kill().await.unwrap();
                    panic!("isolated {source} endpoint regression child timed out");
                }
            };
            assert!(
                status.success(),
                "isolated {source} endpoint regression child failed"
            );
        }
    }
}
