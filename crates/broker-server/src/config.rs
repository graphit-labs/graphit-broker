use broker_control::{
    ADMIN_COOKIE_MAX_LIFETIME, AdminBrokerSessionLimits, AdminCookieSessionLimits,
    AdminCookieSessionPolicy, BrokerAccessIssuer, BrokerAccessVerifier, ConnectionLimits,
    DeviceAuthorizationPolicy, FlowLimits, IdentityReadLimits, LocalAuthPolicy, LocalCaptcha,
    LocalCaptchaConfiguration, LocalCaptchaProvider, LocalMfaAttemptLimiter, LocalMfaAttemptPolicy,
    LocalPasswordAdmission, LocalPasswordAdmissionPolicy, LocalPasswordEngine,
    OidcAuthorizationConfiguration, OidcAuthorizationLimits, OidcAuthorizationPolicy,
    OidcTokenExchangePolicy, PoolConfig, PostgresConfig, PostgresCredentials, PostgresEndpoint,
    SessionLimits, SqliteControlConfig,
};
use broker_presence::{
    AdminCookieHttpConfig, AdminLocalBearerHttpConfig, AdminSessionHttpConfig,
    BrokerOwnReadHttpConfig, BrokerProjectAuthorizationHttpConfig, BrokerPublishHttpConfig,
    InstanceInventoryListHttpConfig, LocalLoginRuntime, OidcRegistrationHttpConfig,
    OidcTokenHttpConfig, RealtimeHttpConfig, SqliteLocalLoginRuntime,
};
use broker_security::{CredentialDigester, DigestLimits, LocalMfaProtector, LocalPasswordHasher};
use broker_storage::{
    AwsCredentialSource, AwsEndpointTransport, AwsStorageIssuer, AwsStorageRoute,
    AwsStorageRouteConfig, FilesystemStorageIssuer, FilesystemStorageRoute,
    FilesystemStorageRouteConfig, FilesystemStoreConfig, PrivateStaticCredentials,
    StorageCredentialsService, StorageIssuer,
};
use regex::Regex;
use rustls_pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Deserializer};
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    io::Read,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use url::{Host, Url};
use zeroize::Zeroizing;

#[path = "admin_config_view.rs"]
mod admin_config_view;
#[path = "embeddings_config.rs"]
mod embeddings_config;
#[path = "local_model_bootstrap.rs"]
mod local_model_bootstrap;
#[path = "rerank_config.rs"]
mod rerank_config;

const CONFIG_BYTES: usize = 4 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerError {
    Configuration,
    ConfigurationIo,
    Key,
    Certificate,
    Database,
    SqliteDatabase(broker_control::SqliteControlError),
    Storage,
    StorageIo {
        kind: std::io::ErrorKind,
        code: Option<i32>,
    },
    Bind,
    Startup,
    Listener,
    Signal,
    Shutdown,
    AdministratorInput,
    AdministratorConfiguration,
    AdministratorExists,
    Administrator,
    AdministratorOutcomeUncertain,
    AdministratorShutdown,
}
impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid server configuration",
            Self::ConfigurationIo => "configuration file unavailable",
            Self::Key => "invalid configured signing key",
            Self::Certificate => "invalid configured PostgreSQL CA",
            Self::Database => "PostgreSQL startup failed",
            Self::SqliteDatabase(error) => return write!(f, "SQLite startup failed: {error}"),
            Self::Storage => "storage startup failed",
            Self::StorageIo { kind, code } => {
                write!(f, "storage startup failed: {kind:?}")?;
                if let Some(code) = code {
                    write!(f, " (OS error {code})")?;
                }
                return Ok(());
            }
            Self::Bind => "listener bind failed",
            Self::Startup => "server startup deadline",
            Self::Listener => "listener failed",
            Self::Signal => "signal handler failed",
            Self::Shutdown => "server shutdown deadline",
            Self::AdministratorInput => "invalid initial administrator password input",
            Self::AdministratorConfiguration => {
                "initial administrator requires LOCAL login and administrative cookie transport"
            }
            Self::AdministratorExists => "local user catalog is already initialized",
            Self::Administrator => "initial administrator creation failed",
            Self::AdministratorOutcomeUncertain => {
                "administrator transaction outcome uncertain; do not replay automatically"
            }
            Self::AdministratorShutdown => "administrator created; physical shutdown failed",
        })
    }
}
impl std::error::Error for ServerError {}
struct Secret(Zeroizing<String>);
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Self(Zeroizing::new(s)))
    }
}
#[derive(Clone, Copy)]
struct Budget(Duration);
impl<'de> Deserialize<'de> for Budget {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let duration = humantime::parse_duration(&s)
            .map_err(|_| serde::de::Error::custom("invalid duration"))?;
        if duration.is_zero() || Instant::now().checked_add(duration).is_none() {
            return Err(serde::de::Error::custom("invalid duration"));
        }
        Ok(Self(duration))
    }
}
fn read_timeout() -> Budget {
    Budget(Duration::from_secs(15))
}
fn write_timeout() -> Budget {
    Budget(Duration::from_secs(60))
}
fn idle_timeout() -> Budget {
    Budget(Duration::from_secs(120))
}
fn address() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8080))
}
fn body_bytes() -> NonZeroUsize {
    NonZeroUsize::new(CONFIG_BYTES).expect("constant")
}
fn hour() -> Budget {
    Budget(Duration::from_secs(3600))
}
fn object_bytes() -> NonZeroU64 {
    NonZeroU64::new(5 * 1024 * 1024 * 1024).expect("constant")
}
fn region() -> String {
    "us-east-1".into()
}
fn session_name() -> String {
    "graphit-broker".into()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    server: Server,
    database: Database,
    auth: Auth,
    storage: Storage,
    oidc: Option<Oidc>,
    administration: Option<Administration>,
    project_access: Option<ProjectAccess>,
    presence: Option<Presence>,
    services: Option<embeddings_config::Services>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Presence {
    enabled: bool,
    authentication: Option<PresenceAuthentication>,
    publish: Option<PresencePublish>,
    read: Option<PresenceRead>,
    realtime: Option<PresenceRealtime>,
    heartbeat_timeout: Option<Budget>,
    broadcast_capacity: Option<NonZeroUsize>,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum PresenceAuthentication {
    BrokerJwt {},
    LocalOpaque {
        audience: String,
        identity_json_bytes: NonZeroUsize,
        list: PresenceList,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresencePublish {
    required_scopes: Vec<String>,
    grants_json_bytes: NonZeroUsize,
    body_bytes: NonZeroUsize,
    request_timeout: Budget,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceRead {
    required_scopes: Vec<String>,
    grants_json_bytes: NonZeroUsize,
    inventory_json_bytes: NonZeroUsize,
    request_timeout: Budget,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceRealtime {
    required_scopes: Vec<String>,
    grants_json_bytes: NonZeroUsize,
    inventory_json_bytes: NonZeroUsize,
    command_bytes: NonZeroUsize,
    outbound_bytes: NonZeroUsize,
    operation_timeout: Budget,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceList {
    required_scopes: Vec<String>,
    grants_json_bytes: NonZeroUsize,
    inventory_json_bytes: NonZeroUsize,
    query_bytes: NonZeroUsize,
    request_timeout: Budget,
}
pub(crate) enum PreparedPresenceAuthentication {
    BrokerJwt,
    LocalOpaque {
        audience: String,
        identity_json_bytes: NonZeroUsize,
        list: InstanceInventoryListHttpConfig,
    },
}
pub(crate) struct PreparedPresence {
    pub authentication: PreparedPresenceAuthentication,
    pub publish: BrokerPublishHttpConfig,
    pub read: BrokerOwnReadHttpConfig,
    pub realtime: RealtimeHttpConfig,
    pub heartbeat_timeout: Duration,
    pub broadcast_capacity: NonZeroUsize,
}
fn presence_sql_cap(cap: NonZeroUsize) -> Result<(), ServerError> {
    isize::try_from(cap.get()).map_err(|_| ServerError::Configuration)?;
    i64::try_from(cap.get()).map_err(|_| ServerError::Configuration)?;
    Ok(())
}
fn presence_scopes(scopes: &[String], native: bool) -> Result<(), ServerError> {
    if scopes
        .iter()
        .any(|s| s.trim().is_empty() || (native && s.contains(' ')))
    {
        Err(ServerError::Configuration)
    } else {
        Ok(())
    }
}
impl Presence {
    fn prepare(self) -> Result<PreparedPresence, ServerError> {
        let required = || ServerError::Configuration;
        let authentication = self.authentication.ok_or_else(required)?;
        let native = matches!(authentication, PresenceAuthentication::BrokerJwt {});
        let publish = self.publish.ok_or_else(required)?;
        let read = self.read.ok_or_else(required)?;
        let realtime = self.realtime.ok_or_else(required)?;
        let heartbeat_timeout = self.heartbeat_timeout.ok_or_else(required)?.0;
        let broadcast_capacity = self.broadcast_capacity.ok_or_else(required)?;
        if SystemTime::now().checked_add(heartbeat_timeout).is_none()
            || broadcast_capacity.get() > usize::MAX >> 1
            || broadcast_capacity
                .get()
                .checked_next_power_of_two()
                .is_none()
        {
            return Err(ServerError::Configuration);
        }
        for scopes in [
            &publish.required_scopes,
            &read.required_scopes,
            &realtime.required_scopes,
        ] {
            presence_scopes(scopes, native)?;
        }
        for cap in [
            publish.grants_json_bytes,
            read.grants_json_bytes,
            read.inventory_json_bytes,
            realtime.grants_json_bytes,
            realtime.inventory_json_bytes,
        ] {
            presence_sql_cap(cap)?;
        }
        for cap in [
            publish.body_bytes,
            realtime.command_bytes,
            realtime.outbound_bytes,
        ] {
            isize::try_from(cap.get()).map_err(|_| ServerError::Configuration)?;
        }
        let authentication = match authentication {
            PresenceAuthentication::BrokerJwt {} => PreparedPresenceAuthentication::BrokerJwt,
            PresenceAuthentication::LocalOpaque {
                audience,
                identity_json_bytes,
                list,
            } => {
                if audience.trim().is_empty() {
                    return Err(ServerError::Configuration);
                }
                presence_sql_cap(identity_json_bytes)?;
                presence_sql_cap(list.grants_json_bytes)?;
                presence_sql_cap(list.inventory_json_bytes)?;
                presence_scopes(&list.required_scopes, false)?;
                isize::try_from(list.query_bytes.get()).map_err(|_| ServerError::Configuration)?;
                let list = InstanceInventoryListHttpConfig {
                    audience: audience.clone(),
                    identity_json_bytes,
                    required_scopes: list.required_scopes,
                    grants_json_bytes: list.grants_json_bytes,
                    inventory_json_bytes: list.inventory_json_bytes,
                    query_bytes: list.query_bytes,
                    request_timeout: list.request_timeout.0,
                };
                PreparedPresenceAuthentication::LocalOpaque {
                    audience,
                    identity_json_bytes,
                    list,
                }
            }
        };
        Ok(PreparedPresence {
            authentication,
            publish: BrokerPublishHttpConfig {
                required_scopes: publish.required_scopes,
                grants_json_bytes: publish.grants_json_bytes,
                body_bytes: publish.body_bytes,
                request_timeout: publish.request_timeout.0,
            },
            read: BrokerOwnReadHttpConfig {
                required_scopes: read.required_scopes,
                grants_json_bytes: read.grants_json_bytes,
                inventory_json_bytes: read.inventory_json_bytes,
                request_timeout: read.request_timeout.0,
            },
            realtime: RealtimeHttpConfig {
                required_scopes: realtime.required_scopes,
                grants_json_bytes: realtime.grants_json_bytes,
                inventory_json_bytes: realtime.inventory_json_bytes,
                command_bytes: realtime.command_bytes,
                outbound_bytes: realtime.outbound_bytes,
                operation_timeout: realtime.operation_timeout.0,
            },
            heartbeat_timeout,
            broadcast_capacity,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectAccess {
    enabled: bool,
    required_scopes: Option<Vec<String>>,
    grants_json_bytes: Option<NonZeroUsize>,
    body_bytes: Option<NonZeroUsize>,
    request_timeout: Option<Budget>,
}
impl ProjectAccess {
    fn prepare(self) -> Result<BrokerProjectAuthorizationHttpConfig, ServerError> {
        let required = || ServerError::Configuration;
        let config = BrokerProjectAuthorizationHttpConfig {
            required_scopes: self.required_scopes.ok_or_else(required)?,
            grants_json_bytes: self.grants_json_bytes.ok_or_else(required)?,
            body_bytes: self.body_bytes.ok_or_else(required)?,
            request_timeout: self.request_timeout.ok_or_else(required)?.0,
        };
        if config
            .required_scopes
            .iter()
            .any(|s| s.trim().is_empty() || s.contains(' '))
        {
            return Err(ServerError::Configuration);
        }
        isize::try_from(config.grants_json_bytes.get()).map_err(|_| ServerError::Configuration)?;
        i64::try_from(config.grants_json_bytes.get()).map_err(|_| ServerError::Configuration)?;
        isize::try_from(config.body_bytes.get()).map_err(|_| ServerError::Configuration)?;
        Ok(config)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Administration {
    enabled: bool,
    request_timeout: Option<Budget>,
    username_bytes: Option<NonZeroUsize>,
    subject_bytes: Option<NonZeroUsize>,
    role_bytes: Option<NonZeroUsize>,
    roles: Option<NonZeroUsize>,
    rows: Option<NonZeroUsize>,
    profile_json_bytes: Option<NonZeroUsize>,
    grants_json_bytes: Option<NonZeroUsize>,
    response_json_bytes: Option<NonZeroUsize>,
    cli: Option<AdminCli>,
    local_bearer: Option<AdminLocalBearer>,
    cookie: Option<AdminCookie>,
    session_ttl: Option<Budget>,
    cookie_secure: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminCli {
    provider_name: Option<String>,
    profile_name: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminCookie {
    enabled: bool,
    text_bytes: Option<NonZeroUsize>,
    csrf_bytes: Option<NonZeroUsize>,
    team_bytes: Option<NonZeroUsize>,
    max_teams: Option<NonZeroUsize>,
    teams_json_bytes: Option<NonZeroUsize>,
    roles_json_bytes: Option<NonZeroUsize>,
}
fn validate_cookie_secure(secure: bool, public_url: &str) -> Result<(), ServerError> {
    if !secure
        && !Url::parse(public_url)
            .is_ok_and(|url| url.scheme() == "http" && secure_origin(public_url))
    {
        return Err(ServerError::Configuration);
    }
    Ok(())
}
impl AdminCookie {
    fn prepare(
        self,
        authorization: AdminBrokerSessionLimits,
        ttl: Option<Budget>,
        secure: Option<bool>,
        public_url: &str,
    ) -> Result<AdminCookieHttpConfig, ServerError> {
        let required = || ServerError::Configuration;
        let secure = secure.unwrap_or(true);
        validate_cookie_secure(secure, public_url)?;
        let config = AdminCookieHttpConfig {
            limits: AdminCookieSessionLimits {
                authorization,
                metadata: SessionLimits {
                    text_bytes: self.text_bytes.ok_or_else(required)?,
                    csrf_bytes: self.csrf_bytes.ok_or_else(required)?,
                    team_bytes: self.team_bytes.ok_or_else(required)?,
                    role_bytes: authorization.identity.role_bytes,
                    max_teams: self.max_teams.ok_or_else(required)?,
                    max_roles: authorization.identity.roles,
                    teams_json_bytes: self.teams_json_bytes.ok_or_else(required)?,
                    roles_json_bytes: self.roles_json_bytes.ok_or_else(required)?,
                    max_lifetime: ADMIN_COOKIE_MAX_LIFETIME,
                },
            },
            policy: AdminCookieSessionPolicy {
                session_ttl: ttl.map(|v| v.0).unwrap_or(Duration::from_secs(8 * 3600)),
            },
            secure,
        };
        config.validate().map_err(|_| ServerError::Configuration)?;
        Ok(config)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminLocalBearer {
    enabled: bool,
    audience: Option<String>,
    identity_json_bytes: Option<NonZeroUsize>,
    required_scopes: Option<Vec<String>>,
}
pub(crate) struct PreparedAdministration {
    pub http: AdminSessionHttpConfig,
    pub local_bearer: Option<AdminLocalBearerHttpConfig>,
    pub cookie: Option<AdminCookieHttpConfig>,
    pub read_limits: broker_control::AdminReadLimits,
    pub provider_command: String,
    pub cli_provider: String,
    pub cli_profile: String,
}
impl AdminLocalBearer {
    fn prepare(self) -> Result<AdminLocalBearerHttpConfig, ServerError> {
        let required = || ServerError::Configuration;
        let config = AdminLocalBearerHttpConfig {
            audience: self.audience.ok_or_else(required)?,
            identity_json_bytes: self.identity_json_bytes.ok_or_else(required)?,
            required_scopes: self.required_scopes.ok_or_else(required)?,
        };
        config.validate().map_err(|_| ServerError::Configuration)?;
        Ok(config)
    }
}
impl Administration {
    fn prepare(self, public_url: &str) -> Result<PreparedAdministration, ServerError> {
        let required = || ServerError::Configuration;
        let config = AdminSessionHttpConfig {
            request_timeout: self.request_timeout.ok_or_else(required)?.0,
            limits: AdminBrokerSessionLimits {
                identity: IdentityReadLimits {
                    username_bytes: self.username_bytes.ok_or_else(required)?,
                    subject_bytes: self.subject_bytes.ok_or_else(required)?,
                    role_bytes: self.role_bytes.ok_or_else(required)?,
                    roles: self.roles.ok_or_else(required)?,
                    rows: self.rows.ok_or_else(required)?,
                },
                profile_json_bytes: self.profile_json_bytes.ok_or_else(required)?,
            },
        };
        config.validate().map_err(|_| ServerError::Configuration)?;
        let read_limits = broker_control::AdminReadLimits {
            authorization: config.limits,
            grants_json_bytes: self.grants_json_bytes.ok_or_else(required)?,
            response_json_bytes: self.response_json_bytes.ok_or_else(required)?,
        };
        read_limits
            .validate()
            .map_err(|_| ServerError::Configuration)?;
        let cli_provider = self
            .cli
            .as_ref()
            .and_then(|v| v.provider_name.as_deref())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or("organization-broker")
            .to_owned();
        let cli_profile = self
            .cli
            .as_ref()
            .and_then(|v| v.profile_name.as_deref())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or(&cli_provider)
            .to_owned();
        let provider_command =
            admin_config_view::provider_command(public_url, &cli_provider, &cli_profile);
        let local_bearer = self
            .local_bearer
            .filter(|local| local.enabled)
            .map(AdminLocalBearer::prepare)
            .transpose()?;
        let cookie = self
            .cookie
            .filter(|cookie| cookie.enabled)
            .map(|cookie| {
                cookie.prepare(
                    config.limits,
                    self.session_ttl,
                    self.cookie_secure,
                    public_url,
                )
            })
            .transpose()?;
        Ok(PreparedAdministration {
            http: config,
            local_bearer,
            cookie,
            read_limits,
            provider_command,
            cli_provider,
            cli_profile,
        })
    }
}
fn authorization_ttl() -> Budget {
    Budget(Duration::from_secs(60))
}
fn access_ttl() -> Budget {
    Budget(Duration::from_secs(600))
}
fn device_code_ttl() -> Budget {
    Budget(Duration::from_secs(600))
}
fn device_poll_interval() -> Budget {
    Budget(Duration::from_secs(5))
}
fn refresh_ttl() -> Budget {
    Budget(Duration::from_secs(30 * 86400))
}
fn token_body_bytes() -> NonZeroUsize {
    NonZeroUsize::new(32 * 1024).expect("constant")
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Oidc {
    enabled: bool,
    cli_client_id: Option<String>,
    cli_redirect_path: Option<String>,
    accepted_resources: Option<Vec<String>>,
    dynamic_registration: Option<bool>,
    #[serde(default = "authorization_ttl")]
    authorization_ttl: Budget,
    #[serde(default = "access_ttl")]
    access_ttl: Budget,
    #[serde(default = "device_code_ttl")]
    device_code_ttl: Budget,
    #[serde(default = "device_poll_interval")]
    device_poll_interval: Budget,
    #[serde(default = "refresh_ttl")]
    refresh_ttl: Budget,
    json_bytes: Option<NonZeroUsize>,
    parameter_bytes: Option<NonZeroUsize>,
    request_timeout: Option<Budget>,
    #[serde(default = "token_body_bytes")]
    body_bytes: NonZeroUsize,
    #[serde(default)]
    allowed_origins: Vec<String>,
}
pub(crate) struct PreparedOidc {
    pub request_timeout: Duration,
    pub body_bytes: NonZeroUsize,
    pub issuer: Arc<BrokerAccessIssuer>,
    pub authorization: Arc<OidcAuthorizationPolicy>,
    pub policy: Arc<OidcTokenExchangePolicy>,
    pub device: Arc<DeviceAuthorizationPolicy>,
    pub device_verification_uri: String,
    pub http: OidcTokenHttpConfig,
    pub registration_http: OidcRegistrationHttpConfig,
    pub cors: Option<CorsLayer>,
    pub discovery: crate::discovery::Discovery,
    view: admin_config_view::OidcView,
}
impl Oidc {
    fn prepare(
        self,
        issuer: BrokerAccessIssuer,
        audience: &str,
        public_url: &str,
    ) -> Result<PreparedOidc, ServerError> {
        let required = || ServerError::Configuration;
        let json_bytes = self.json_bytes.ok_or_else(required)?;
        let parameter_bytes = self.parameter_bytes.ok_or_else(required)?;
        let limits = OidcAuthorizationLimits::new(json_bytes, parameter_bytes)
            .map_err(|_| ServerError::Configuration)?;
        let configuration = OidcAuthorizationConfiguration {
            cli_client_id: self.cli_client_id.ok_or_else(required)?,
            cli_redirect_path: self.cli_redirect_path.ok_or_else(required)?,
            api_audience: audience.to_owned(),
            accepted_resources: self.accepted_resources.ok_or_else(required)?,
            dynamic_registration: self.dynamic_registration.ok_or_else(required)?,
            authorization_ttl: self.authorization_ttl.0,
        };
        if configuration
            .accepted_resources
            .iter()
            .enumerate()
            .any(|(i, resource)| {
                resource.is_empty()
                    || resource.trim() != resource
                    || configuration.accepted_resources[..i].contains(resource)
            })
        {
            eprintln!("oidc.accepted_resources requires nonempty, unpadded, unique resources");
            return Err(ServerError::Configuration);
        }
        let allowed_origins = self
            .allowed_origins
            .into_iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        let view = admin_config_view::OidcView {
            enabled: true,
            cli_client_id: configuration.cli_client_id.clone(),
            cli_redirect_path: configuration.cli_redirect_path.clone(),
            accepted_resources: configuration.accepted_resources.clone(),
            dynamic_registration: configuration.dynamic_registration,
            authorization_ttl: admin_config_view::Time(configuration.authorization_ttl),
            access_ttl: admin_config_view::Time(self.access_ttl.0),
            refresh_ttl: admin_config_view::Time(self.refresh_ttl.0),
            device_code_ttl: admin_config_view::Time(self.device_code_ttl.0),
            device_poll_interval: admin_config_view::Time(self.device_poll_interval.0),
            json_bytes,
            parameter_bytes,
            request_timeout: admin_config_view::Time(self.request_timeout.ok_or_else(required)?.0),
            body_bytes: self.body_bytes,
            allowed_origins,
        };
        let authorization = OidcAuthorizationPolicy::new(configuration, limits)
            .map_err(|_| ServerError::Configuration)?;
        let device = DeviceAuthorizationPolicy::new(
            self.device_code_ttl.0,
            self.device_poll_interval.0,
            self.access_ttl.0,
        )
        .map_err(|_| ServerError::Configuration)?;
        let device_verification_uri = format!("{}/oauth/device", public_url.trim_end_matches('/'));
        device_verification_uri
            .parse::<axum::http::Uri>()
            .map_err(|_| ServerError::Configuration)?;
        let policy = OidcTokenExchangePolicy::new(self.access_ttl.0, self.refresh_ttl.0)
            .map_err(|_| ServerError::Configuration)?;
        let http = OidcTokenHttpConfig::new(
            self.request_timeout.ok_or_else(required)?.0,
            self.body_bytes,
        )
        .map_err(|_| ServerError::Configuration)?;
        let registration_http =
            OidcRegistrationHttpConfig::new(self.request_timeout.ok_or_else(required)?.0)
                .map_err(|_| ServerError::Configuration)?;
        let patterns = view
            .allowed_origins
            .iter()
            .map(|origin| {
                let pattern = match origin.split_once('*') {
                    Some((before, after)) => {
                        format!("(?i)^{}.*{}$", regex::escape(before), regex::escape(after))
                    }
                    None => format!("(?i)^{}$", regex::escape(origin)),
                };
                Regex::new(&pattern).map_err(|_| ServerError::Configuration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let cors = if patterns.is_empty() {
            None
        } else {
            use axum::http::{Method, header};
            Some(
                CorsLayer::new()
                    .allow_origin(AllowOrigin::predicate(move |origin, _| {
                        origin
                            .to_str()
                            .is_ok_and(|v| patterns.iter().any(|p| p.is_match(v)))
                    }))
                    .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                    .allow_headers([
                        header::AUTHORIZATION,
                        header::CONTENT_TYPE,
                        header::ACCEPT,
                        header::ORIGIN,
                    ])
                    .expose_headers([header::WWW_AUTHENTICATE]),
            )
        };
        let discovery = crate::discovery::Discovery::new(
            public_url,
            audience,
            &view.cli_client_id,
            &view.cli_redirect_path,
            &view.accepted_resources,
            view.dynamic_registration,
        );
        Ok(PreparedOidc {
            request_timeout: self.request_timeout.ok_or_else(required)?.0,
            body_bytes: self.body_bytes,
            issuer: Arc::new(issuer),
            authorization: Arc::new(authorization),
            policy: Arc::new(policy),
            device: Arc::new(device),
            device_verification_uri,
            http,
            registration_http,
            cors,
            discovery,
            view,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Server {
    #[serde(default = "address")]
    pub address: SocketAddr,
    public_url: String,
    instruction_overrides_file: Option<PathBuf>,
    #[serde(default = "read_timeout")]
    read_timeout: Budget,
    #[serde(default = "write_timeout")]
    write_timeout: Budget,
    #[serde(default = "idle_timeout")]
    idle_timeout: Budget,
    #[serde(default = "read_timeout")]
    shutdown_timeout: Budget,
    #[serde(default = "body_bytes")]
    body_bytes: NonZeroUsize,
}
#[derive(Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase", deny_unknown_fields)]
enum Database {
    Postgres {
        host: String,
        port: NonZeroU16,
        database: String,
        username: String,
        password: Secret,
        ca_file: PathBuf,
        text_bytes: NonZeroUsize,
        ca_bytes: NonZeroUsize,
        pool: Box<Pool>,
        flows: Flows,
    },
    Sqlite {
        path: PathBuf,
        startup_timeout: Budget,
        operation_timeout: Budget,
        shutdown_timeout: Budget,
        flows: Flows,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pool {
    max_connections: NonZeroU32,
    min_connections: u32,
    statement_cache_capacity: usize,
    connect_timeout: Budget,
    acquire_timeout: Budget,
    operation_timeout: Budget,
    startup_timeout: Budget,
    shutdown_timeout: Budget,
    max_lifetime: Budget,
    idle_timeout: Budget,
    statement_timeout: Budget,
    lock_timeout: Budget,
    idle_transaction_timeout: Budget,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Flows {
    provider_bytes: NonZeroUsize,
    request_bytes: NonZeroUsize,
    continuation_bytes: NonZeroUsize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Auth {
    issuer: String,
    audience: String,
    #[serde(default = "service_credential_max_ttl")]
    service_credential_max_ttl: Budget,
    kid: String,
    resource: Option<String>,
    pkcs8_file: PathBuf,
    key_bytes: NonZeroUsize,
    pepper: Secret,
    digest: Digests,
    oidc: Option<Vec<UpstreamOidc>>,
    local: Option<LocalAuthentication>,
}
fn service_credential_max_ttl() -> Budget {
    Budget(Duration::from_secs(365 * 24 * 3600))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalAuthentication {
    login: Option<LocalLogin>,
    rate_limit: Option<LocalRateLimit>,
    captcha: Option<LocalCaptchaInput>,
    mfa: Option<LocalMfaInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalLogin {
    enabled: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalRateLimit {
    max_failures: Option<NonZeroU32>,
    window: Option<Budget>,
    lockout: Option<Budget>,
    max_concurrent: Option<NonZeroUsize>,
    saturation_multiplier: Option<NonZeroUsize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalCaptchaInput {
    enabled: bool,
    provider: Option<String>,
    site_key: Option<String>,
    secret_key: Option<Secret>,
    trigger_multiplier: Option<f64>,
    verification_timeout: Option<Budget>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalMfaInput {
    required: Option<bool>,
    issuer_label: Option<String>,
    challenge_ttl: Option<Budget>,
}
pub(crate) struct PreparedLocalPassword {
    hasher: LocalPasswordHasher,
    workers: NonZeroUsize,
}
impl PreparedLocalPassword {
    pub(crate) async fn start(
        self,
        original: Instant,
    ) -> Result<Arc<LocalPasswordEngine>, broker_control::LocalPasswordVerificationError> {
        LocalPasswordEngine::new(self.hasher, self.workers, original)
            .await
            .map(Arc::new)
    }
}
pub(crate) struct PreparedLocalLogin {
    admission: LocalPasswordAdmissionPolicy,
    captcha: LocalCaptcha,
    digester: CredentialDigester,
    mfa: LocalMfaProtector,
    policy: LocalAuthPolicy,
    limiter: LocalMfaAttemptLimiter,
    view: admin_config_view::LocalView,
}
pub(crate) enum OwnedLocalLogin {
    Postgres(Arc<LocalLoginRuntime>),
    Sqlite(Arc<SqliteLocalLoginRuntime>),
}
impl OwnedLocalLogin {
    pub(crate) fn stop_admission(&self) {
        match self {
            Self::Postgres(owner) => owner.stop_admission(),
            Self::Sqlite(owner) => owner.stop_admission(),
        }
    }
    pub(crate) async fn close(&self) {
        match self {
            Self::Postgres(owner) => owner.close().await,
            Self::Sqlite(owner) => owner.close().await,
        }
    }
}
impl PreparedLocalLogin {
    pub(crate) fn start(
        self,
        engine: Arc<LocalPasswordEngine>,
        database: &PreparedDatabase,
    ) -> Result<OwnedLocalLogin, ServerError> {
        let admission = Arc::new(
            LocalPasswordAdmission::new(self.admission, &engine, self.captcha)
                .map_err(|_| ServerError::Configuration)?,
        );
        Ok(match database {
            PreparedDatabase::Postgres(_) => {
                OwnedLocalLogin::Postgres(Arc::new(LocalLoginRuntime::new(
                    engine,
                    admission,
                    self.digester,
                    self.mfa,
                    self.policy,
                    self.limiter,
                )))
            }
            PreparedDatabase::Sqlite(_) => {
                OwnedLocalLogin::Sqlite(Arc::new(SqliteLocalLoginRuntime::new(
                    engine,
                    admission,
                    Arc::new(self.digester),
                    Arc::new(self.mfa),
                    Arc::new(self.policy),
                    Arc::new(self.limiter),
                )))
            }
        })
    }
}
impl LocalAuthentication {
    fn prepare(
        self,
        pepper: &Secret,
        digests: &Digests,
        public_url: &str,
    ) -> Result<PreparedLocalLogin, ServerError> {
        let rate = self.rate_limit;
        let max_failures = rate
            .as_ref()
            .and_then(|r| r.max_failures)
            .unwrap_or(NonZeroU32::new(5).expect("sourced positive constant"));
        let window = rate
            .as_ref()
            .and_then(|r| r.window)
            .map(|v| v.0)
            .unwrap_or(Duration::from_secs(60));
        let lockout = rate
            .as_ref()
            .and_then(|r| r.lockout)
            .map(|v| v.0)
            .unwrap_or(Duration::from_secs(300));
        let workers = rate
            .as_ref()
            .and_then(|r| r.max_concurrent)
            .unwrap_or(NonZeroUsize::new(2).expect("sourced positive constant"));
        let saturation = rate
            .as_ref()
            .and_then(|r| r.saturation_multiplier)
            .unwrap_or(NonZeroUsize::new(4).expect("sourced positive constant"));
        let capacity = NonZeroUsize::new(4096).expect("sourced positive constant");
        let policy = LocalPasswordAdmissionPolicy {
            max_failures: NonZeroUsize::new(
                usize::try_from(max_failures.get()).map_err(|_| ServerError::Configuration)?,
            )
            .ok_or(ServerError::Configuration)?,
            window,
            lockout,
            workers,
            saturation_multiplier: saturation,
            max_tracked: capacity,
        };
        policy.validate().map_err(|_| ServerError::Configuration)?;
        let captcha = match self.captcha.filter(|value| value.enabled) {
            None => LocalCaptchaConfiguration::Disabled,
            Some(value) => LocalCaptchaConfiguration::Enabled {
                provider: match value.provider.as_deref() {
                    Some("turnstile") => LocalCaptchaProvider::Turnstile,
                    Some("recaptcha") => LocalCaptchaProvider::Recaptcha,
                    _ => return Err(ServerError::Configuration),
                },
                site_key: value.site_key.ok_or(ServerError::Configuration)?,
                secret_key: value.secret_key.ok_or(ServerError::Configuration)?.0,
                public_url: Url::parse(public_url).map_err(|_| ServerError::Configuration)?,
                trigger_multiplier: value.trigger_multiplier.unwrap_or(1.5),
                verification_timeout: value
                    .verification_timeout
                    .map(|v| v.0)
                    .unwrap_or(Duration::from_secs(3)),
            },
        };
        let captcha_view = admin_config_view::CaptchaView::new(&captcha);
        let captcha = LocalCaptcha::new(captcha, workers, saturation)
            .map_err(|_| ServerError::Configuration)?;
        let required = self
            .mfa
            .as_ref()
            .and_then(|mfa| mfa.required)
            .unwrap_or(true);
        let label = self
            .mfa
            .as_ref()
            .and_then(|mfa| mfa.issuer_label.as_ref())
            .cloned()
            .unwrap_or_else(|| "Graphit Broker".into());
        let ttl = self
            .mfa
            .and_then(|mfa| mfa.challenge_ttl)
            .map(|v| v.0)
            .unwrap_or(Duration::from_secs(600));
        let view = admin_config_view::LocalView {
            login: admin_config_view::LoginView { enabled: true },
            rate_limit: admin_config_view::RateView {
                max_failures,
                window: admin_config_view::Time(window),
                lockout: admin_config_view::Time(lockout),
                max_concurrent: workers,
                saturation_multiplier: saturation,
            },
            mfa: admin_config_view::MfaView {
                required,
                issuer_label: label.trim().to_owned(),
                challenge_ttl: admin_config_view::Time(ttl),
            },
            captcha: captcha_view,
        };
        // Public placeholder DATA validates SDK presentation parameters only.
        // No OTP/URI/QR, randomness, real secret or authentication proof is made.
        totp_rs::Builder::new()
            .with_algorithm(totp_rs::Algorithm::SHA1)
            .with_digits(6)
            .with_step_duration(30)
            .with_skew(0)
            .with_secret(vec![0; 32])
            .with_issuer(Some(label.trim()))
            .with_account_name("native-config-validation")
            .build()
            .map_err(|_| ServerError::Configuration)?;
        let auth_policy =
            LocalAuthPolicy::new(required, label, ttl).map_err(|_| ServerError::Configuration)?;
        let limiter = LocalMfaAttemptLimiter::new(
            LocalMfaAttemptPolicy::new(max_failures, window, lockout, capacity)
                .map_err(|_| ServerError::Configuration)?,
        );
        let key = || Zeroizing::new(pepper.0.as_bytes().to_vec().into_boxed_slice());
        let mfa = LocalMfaProtector::new(key()).map_err(|_| ServerError::Configuration)?;
        let limits = DigestLimits::new(
            digests.pepper_bytes,
            digests.token_bytes,
            digests.binding_bytes,
            digests.subject_bytes,
            digests.recovery_bytes,
        )
        .map_err(|_| ServerError::Configuration)?;
        let digester =
            CredentialDigester::new(key(), limits).map_err(|_| ServerError::Configuration)?;
        Ok(PreparedLocalLogin {
            admission: policy,
            captcha,
            digester,
            mfa,
            policy: auth_policy,
            limiter,
            view,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamOidc {
    id: String,
    enabled: bool,
    issuer: Option<String>,
    audiences: Option<Vec<String>>,
    required_scopes: Option<Vec<String>>,
    allowed_algorithms: Option<Vec<broker_control::UpstreamSignatureAlgorithm>>,
    access_policy: Option<broker_control::UpstreamAccessPolicy>,
    predicates: Option<Vec<broker_control::UpstreamClaimPredicate>>,
    claims: Option<broker_control::UpstreamClaimSelectors>,
    limits: Option<broker_control::UpstreamReadLimits>,
    request_timeout: Option<Budget>,
    cache_max_age: Option<Budget>,
    min_refresh_interval: Option<Budget>,
    allow_loopback_http: Option<bool>,
    ca_file: Option<PathBuf>,
    ca_bytes: Option<NonZeroUsize>,
    #[serde(default, deserialize_with = "browser_clients")]
    browser_clients: Vec<broker_control::UpstreamBrowserClient>,
}
fn browser_clients<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<broker_control::UpstreamBrowserClient>, D::Error> {
    struct Clients;
    impl<'de> serde::de::Visitor<'de> for Clients {
        type Value = Vec<broker_control::UpstreamBrowserClient>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a browser client sequence")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            sequence: A,
        ) -> Result<Self::Value, A::Error> {
            Vec::deserialize(serde::de::value::SeqAccessDeserializer::new(sequence))
        }
    }
    // YAML's typed sequence coercion accepts null as empty; presence is stricter here.
    deserializer.deserialize_any(Clients)
}
impl UpstreamOidc {
    fn prepare(
        self,
        base: &Path,
    ) -> Result<Option<broker_control::UpstreamProviderConfig>, ServerError> {
        if !self.enabled {
            return Ok(None);
        }
        let trusted_ca_pem = match (self.ca_file, self.ca_bytes) {
            (None, None) => None,
            (Some(path), Some(cap)) => {
                isize::try_from(cap.get()).map_err(|_| ServerError::Configuration)?;
                Some(
                    read_bounded(&resolve(base, path)?, cap.get(), ServerError::Certificate)?
                        .to_vec(),
                )
            }
            _ => return Err(ServerError::Configuration),
        };
        Ok(Some(broker_control::UpstreamProviderConfig {
            id: self.id,
            issuer: self.issuer.ok_or(ServerError::Configuration)?,
            audiences: self.audiences.ok_or(ServerError::Configuration)?,
            required_scopes: self.required_scopes.ok_or(ServerError::Configuration)?,
            allowed_algorithms: self.allowed_algorithms.ok_or(ServerError::Configuration)?,
            access_policy: self.access_policy.ok_or(ServerError::Configuration)?,
            predicates: self.predicates.unwrap_or_default(),
            claims: self.claims.ok_or(ServerError::Configuration)?,
            limits: self.limits.ok_or(ServerError::Configuration)?,
            request_timeout: self.request_timeout.ok_or(ServerError::Configuration)?.0,
            cache_max_age: self.cache_max_age.ok_or(ServerError::Configuration)?.0,
            min_refresh_interval: self
                .min_refresh_interval
                .ok_or(ServerError::Configuration)?
                .0,
            allow_loopback_http: self.allow_loopback_http.ok_or(ServerError::Configuration)?,
            trusted_ca_pem,
            browser_clients: self.browser_clients,
        }))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Digests {
    pepper_bytes: NonZeroUsize,
    token_bytes: NonZeroUsize,
    binding_bytes: NonZeroUsize,
    subject_bytes: NonZeroUsize,
    recovery_bytes: NonZeroUsize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Storage {
    pub enabled: bool,
    default_route: Option<String>,
    routes: BTreeMap<String, Route>,
    required_scopes: Vec<String>,
    request_timeout: Budget,
    sts_timeout: Budget,
    pub identity_json_bytes: NonZeroUsize,
    pub grants_json_bytes: NonZeroUsize,
    pub head_bytes: NonZeroUsize,
    token_bytes: NonZeroUsize,
    metadata_bytes: NonZeroUsize,
}
#[derive(Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Driver {
    #[default]
    S3,
    Filesystem,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    #[serde(default)]
    driver: Driver,
    bucket: String,
    base_prefix: String,
    #[serde(default = "region")]
    region: String,
    endpoint: Option<String>,
    directory: Option<PathBuf>,
    role_arn: Option<String>,
    sts_endpoint: Option<String>,
    access_key_id: Option<Secret>,
    secret_access_key: Option<Secret>,
    #[serde(default = "hour")]
    session_duration: Budget,
    session_name: Option<String>,
    max_object_bytes: Option<NonZeroU64>,
    allow_loopback_http: Option<bool>,
    conditional_delete: Option<bool>,
}
pub(crate) enum PreparedDatabase {
    Postgres(Box<PostgresConfig>),
    Sqlite(SqliteControlConfig),
}
impl Database {
    fn prepare(self, base: &Path) -> Result<(PreparedDatabase, Duration), ServerError> {
        match self {
            Self::Postgres {
                host,
                port,
                database,
                username,
                password,
                ca_file,
                text_bytes,
                ca_bytes,
                pool,
                flows,
            } => {
                let ca = read_bounded(
                    &resolve(base, ca_file)?,
                    ca_bytes.get(),
                    ServerError::Certificate,
                )?;
                let mut roots = rustls::RootCertStore::empty();
                for certificate in CertificateDer::pem_slice_iter(&ca) {
                    roots
                        .add(certificate.map_err(|_| ServerError::Certificate)?)
                        .map_err(|_| ServerError::Certificate)?;
                }
                if roots.is_empty() {
                    return Err(ServerError::Certificate);
                }
                let p = pool;
                let startup_timeout = p.startup_timeout.0;
                let database = PostgresConfig::new(
                    PostgresEndpoint {
                        host,
                        port,
                        database,
                    },
                    PostgresCredentials::new(username, password.0),
                    ca.to_vec(),
                    ConnectionLimits {
                        text_bytes,
                        ca_bytes,
                    },
                    PoolConfig {
                        max_connections: p.max_connections,
                        min_connections: p.min_connections,
                        statement_cache_capacity: p.statement_cache_capacity,
                        connect_timeout: p.connect_timeout.0,
                        acquire_timeout: p.acquire_timeout.0,
                        operation_timeout: p.operation_timeout.0,
                        startup_timeout: p.startup_timeout.0,
                        shutdown_timeout: p.shutdown_timeout.0,
                        max_lifetime: p.max_lifetime.0,
                        idle_timeout: p.idle_timeout.0,
                        statement_timeout: p.statement_timeout.0,
                        lock_timeout: p.lock_timeout.0,
                        idle_transaction_timeout: p.idle_transaction_timeout.0,
                    },
                    FlowLimits {
                        provider_bytes: flows.provider_bytes,
                        request_bytes: flows.request_bytes,
                        continuation_bytes: flows.continuation_bytes,
                    },
                )
                .map_err(|_| ServerError::Configuration)?;
                Ok((
                    PreparedDatabase::Postgres(Box::new(database)),
                    startup_timeout,
                ))
            }
            Self::Sqlite {
                path,
                startup_timeout,
                operation_timeout,
                shutdown_timeout,
                flows,
            } => {
                // Validate the configured spelling before base-path resolution so URI
                // and in-memory forms cannot turn into ordinary relative filenames.
                let limits = FlowLimits {
                    provider_bytes: flows.provider_bytes,
                    request_bytes: flows.request_bytes,
                    continuation_bytes: flows.continuation_bytes,
                };
                SqliteControlConfig::new(
                    path.clone(),
                    startup_timeout.0,
                    operation_timeout.0,
                    shutdown_timeout.0,
                    limits,
                )
                .map_err(|_| ServerError::Configuration)?;
                let database = SqliteControlConfig::new(
                    resolve(base, path)?,
                    startup_timeout.0,
                    operation_timeout.0,
                    shutdown_timeout.0,
                    limits,
                )
                .map_err(|_| ServerError::Configuration)?;
                Ok((PreparedDatabase::Sqlite(database), startup_timeout.0))
            }
        }
    }
}

/// Prepared runtime owners are not a serializable deployment view. Only the
/// closed public-data projection can be returned by administrative reads.
///
/// ```compile_fail
/// fn serialize_runtime_owners(config: &broker_server::PreparedConfig) {
///     let _ = serde_json::to_string(config).unwrap();
/// }
/// ```
pub struct PreparedConfig {
    pub(crate) server: Server,
    pub(crate) database: PreparedDatabase,
    pub(crate) digester: CredentialDigester,
    pub(crate) verifier: Arc<BrokerAccessVerifier>,
    pub(crate) upstream: Option<Arc<broker_control::UpstreamBearerVerifier>>,
    pub(crate) jwks: serde_json::Value,
    pub(crate) credentials: Option<Arc<StorageCredentialsService>>,
    pub(crate) stores: Vec<FilesystemStoreConfig>,
    pub(crate) storage: Storage,
    pub(crate) default_route: String,
    pub(crate) grant_routes: Arc<broker_control::AdminGrantRoutes>,
    pub(crate) audience: String,
    pub(crate) startup_timeout: Duration,
    pub(crate) oidc: Option<PreparedOidc>,
    pub(crate) administration: Option<PreparedAdministration>,
    pub(crate) upstream_cookie_secure: bool,
    pub(crate) local_login: Option<PreparedLocalLogin>,
    pub(crate) local_password: Option<PreparedLocalPassword>,
    pub(crate) service_credential_max_ttl: Duration,
    pub(crate) project_access: Option<BrokerProjectAuthorizationHttpConfig>,
    pub(crate) presence: Option<PreparedPresence>,
    pub(crate) embeddings: Option<embeddings_config::PreparedEmbeddings>,
    pub(crate) rerank: Option<rerank_config::PreparedRerank>,
    pub(crate) configuration_yaml: Option<String>,
    pub(crate) instruction_overrides_file: PathBuf,
    pub(crate) native_sdk: Option<graphit_ai::native_embedding::NativeSdkRoot>,
}
impl PreparedConfig {
    /// Stop native admission and retain the SDK bootstrap until both workers have joined.
    pub async fn shutdown_models(&self) -> Result<(), ServerError> {
        let cancel = graphit_core::file_lock::Cancellation::default();
        let end = Instant::now()
            .checked_add(self.server.shutdown_timeout())
            .ok_or(ServerError::Configuration)?;
        let context = graphit_ai::context::InferenceContext::new(&cancel, end);
        let (embedding, rerank) = tokio::join!(
            async {
                match &self.embeddings {
                    Some(owner) => owner
                        .backend
                        .shutdown(context)
                        .await
                        .map_err(|_| ServerError::Shutdown),
                    None => Ok(()),
                }
            },
            async {
                match &self.rerank {
                    Some(owner) => owner
                        .backend
                        .shutdown(context)
                        .await
                        .map_err(|_| ServerError::Shutdown),
                    None => Ok(()),
                }
            },
        );
        embedding?;
        rerank
    }
}
impl Server {
    pub(crate) fn public_url(&self) -> &str {
        &self.public_url
    }

    pub(crate) fn read_timeout(&self) -> Duration {
        self.read_timeout.0
    }
    pub(crate) fn write_timeout(&self) -> Duration {
        self.write_timeout.0
    }
    pub(crate) fn idle_timeout(&self) -> Duration {
        self.idle_timeout.0
    }
    pub(crate) fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout.0
    }
    pub(crate) fn body_bytes(&self) -> NonZeroUsize {
        self.body_bytes
    }
}
impl Storage {
    pub(crate) fn request_timeout(&self) -> Duration {
        self.request_timeout.0
    }
    pub(crate) fn required_scopes(&self) -> Vec<String> {
        self.required_scopes.clone()
    }
}
pub fn default_config_path() -> Result<PathBuf, ServerError> {
    let base = match std::env::var_os("GRAPHIT_GLOBAL_DIR") {
        Some(s) if !s.is_empty() => PathBuf::from(s),
        Some(_) => return Err(ServerError::Configuration),
        None => dirs::home_dir()
            .ok_or(ServerError::Configuration)?
            .join(".graphit"),
    };
    Ok(base.join("broker/config.yaml"))
}
fn resolve(base: &Path, path: PathBuf) -> Result<PathBuf, ServerError> {
    if path.as_os_str().is_empty() {
        return Err(ServerError::Configuration);
    }
    if let Some(s) = path.to_str().and_then(|s| s.strip_prefix("~/")) {
        return Ok(dirs::home_dir().ok_or(ServerError::Configuration)?.join(s));
    }
    Ok(if path.is_absolute() {
        path
    } else {
        base.join(path)
    })
}
fn read_bounded(
    path: &Path,
    limit: usize,
    error: ServerError,
) -> Result<Zeroizing<Vec<u8>>, ServerError> {
    let mut bytes = Zeroizing::new(Vec::new());
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(error)?;
    File::open(path)
        .map_err(|_| error)?
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| error)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(error);
    }
    Ok(bytes)
}
fn expand(
    raw: &str,
    mut lookup: impl FnMut(&str) -> Option<Zeroizing<String>>,
) -> Result<Zeroizing<String>, ServerError> {
    let pattern = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:\?)([^}]*)|(:-)([^}]*))?\}")
        .map_err(|_| ServerError::Configuration)?;
    let mut value = Zeroizing::new(String::new());
    let mut previous = 0;
    for capture in pattern.captures_iter(raw) {
        let span = capture.get(0).expect("regex match");
        value.push_str(&raw[previous..span.start()]);
        let replacement = lookup(&capture[1]).filter(|s| !s.is_empty());
        match replacement {
            Some(replacement) => value.push_str(&replacement),
            None if capture.get(2).is_some() => return Err(ServerError::Configuration),
            None => value.push_str(capture.get(5).map_or("", |s| s.as_str())),
        }
        if value.len() > CONFIG_BYTES {
            return Err(ServerError::Configuration);
        }
        previous = span.end();
    }
    value.push_str(&raw[previous..]);
    if value.len() > CONFIG_BYTES {
        return Err(ServerError::Configuration);
    }
    Ok(value)
}
fn secure_origin(s: &str) -> bool {
    let Ok(u) = Url::parse(s) else {
        return false;
    };
    u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none()
        && u.path() == "/"
        && u.host().is_some()
        && (u.scheme() == "https"
            || (u.scheme() == "http"
                && match u.host() {
                    Some(Host::Domain(h)) => h == "localhost",
                    Some(Host::Ipv4(ip)) => ip.is_loopback(),
                    Some(Host::Ipv6(ip)) => ip.is_loopback(),
                    None => false,
                }))
}
pub async fn load_config(path: &Path) -> Result<PreparedConfig, ServerError> {
    let raw = read_bounded(path, CONFIG_BYTES, ServerError::ConfigurationIo)?;
    let raw = std::str::from_utf8(&raw).map_err(|_| ServerError::Configuration)?;
    let expanded = expand(raw, |name| std::env::var(name).ok().map(Zeroizing::new))?;
    let config: Config =
        serde_saphyr::from_str(&expanded).map_err(|_| ServerError::Configuration)?;
    prepare(config, path.parent().unwrap_or(Path::new("."))).await
}
async fn prepare(config: Config, base: &Path) -> Result<PreparedConfig, ServerError> {
    // Resolve infrastructure once, independently of the YAML and model bundle paths.
    let model_paths = config
        .services
        .as_ref()
        .filter(|services| services.needs_native_sdk())
        .map(|_| local_model_bootstrap::resolve())
        .transpose()?;
    let Config {
        server,
        database: db,
        auth,
        mut storage,
        oidc,
        administration,
        project_access,
        presence,
        services,
    } = config;
    if !secure_origin(&server.public_url)
        || auth.audience.trim().is_empty()
        || !(Duration::from_secs(3600)..=Duration::from_secs(5 * 365 * 24 * 3600))
            .contains(&auth.service_credential_max_ttl.0)
        || storage.required_scopes.iter().any(|s| s.trim().is_empty())
    {
        return Err(ServerError::Configuration);
    }
    if oidc.as_ref().is_some_and(|o| o.enabled) && auth.issuer != server.public_url {
        eprintln!("OIDC requires auth.issuer to equal server.public_url literally");
        return Err(ServerError::Configuration);
    }
    if storage.enabled {
        // Match the actual SQL readers' representability checks before opening SQL.
        for cap in [storage.identity_json_bytes, storage.grants_json_bytes] {
            isize::try_from(cap.get()).map_err(|_| ServerError::Configuration)?;
            i64::try_from(cap.get()).map_err(|_| ServerError::Configuration)?;
        }
        if storage
            .routes
            .values()
            .any(|route| route.driver == Driver::Filesystem)
        {
            u64::try_from(storage.metadata_bytes.get())
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(ServerError::Configuration)?;
        }
    }
    let mut configuration_view = administration
        .as_ref()
        .filter(|a| a.enabled)
        .map(|_| admin_config_view::Deployment::new(&server, &db, &auth, &storage, base))
        .transpose()?;
    let upstream_cookie_secure = administration
        .as_ref()
        .and_then(|admin| admin.cookie_secure)
        .unwrap_or(true);
    let administration = administration
        .filter(|a| a.enabled)
        .map(|a| a.prepare(&server.public_url))
        .transpose()?;
    let upstream = auth
        .oidc
        .map(|entries| {
            let mut ids = std::collections::BTreeSet::new();
            let mut issuers = std::collections::BTreeSet::new();
            let mut providers = Vec::new();
            for entry in entries {
                if entry.id.trim().is_empty()
                    || !ids.insert(entry.id.clone())
                    || entry
                        .issuer
                        .as_ref()
                        .is_some_and(|s| s == &auth.issuer || !issuers.insert(s.clone()))
                {
                    return Err(ServerError::Configuration);
                }
                let ca_file = if configuration_view.is_some() && entry.enabled {
                    entry
                        .ca_file
                        .as_ref()
                        .map(|p| resolve(base, p.clone()))
                        .transpose()?
                } else {
                    None
                };
                let ca_bytes = entry.ca_bytes;
                if let Some(provider) = entry.prepare(base)? {
                    if !provider.browser_clients.is_empty() {
                        validate_cookie_secure(upstream_cookie_secure, &server.public_url)?;
                        if auth.digest.token_bytes.get()
                            < broker_control::UPSTREAM_LOGIN_STATE_BYTES
                        {
                            return Err(ServerError::Configuration);
                        }
                    }
                    if !provider.browser_clients.is_empty()
                        && administration.as_ref().and_then(|a| a.cookie).is_none()
                        && !oidc.as_ref().is_some_and(|o| o.enabled)
                    {
                        return Err(ServerError::Configuration);
                    }
                    if let Some(view) = configuration_view.as_mut() {
                        view.upstream(&provider, ca_file, ca_bytes)?;
                    }
                    providers.push(provider);
                }
            }
            broker_control::UpstreamBearerVerifier::new(
                &auth.issuer,
                auth.digest.token_bytes,
                providers,
            )
            .map(Arc::new)
            .map_err(|_| ServerError::Configuration)
        })
        .transpose()?;
    let project_access = project_access
        .filter(|p| p.enabled)
        .map(ProjectAccess::prepare)
        .transpose()?;
    let presence = presence
        .filter(|p| p.enabled)
        .map(Presence::prepare)
        .transpose()?;
    let key = read_bounded(
        &resolve(base, auth.pkcs8_file)?,
        auth.key_bytes.get(),
        ServerError::Key,
    )?;
    let issuer = BrokerAccessIssuer::new(&auth.issuer, &auth.audience, &auth.kid, &key)
        .map_err(|_| ServerError::Key)?;
    let verifier = Arc::new(
        BrokerAccessVerifier::new(
            &auth.issuer,
            &auth.audience,
            auth.resource.as_deref(),
            issuer.jwks(),
            auth.digest.token_bytes,
        )
        .map_err(|_| ServerError::Key)?,
    );
    let jwks = serde_json::to_value(issuer.jwks()).map_err(|_| ServerError::Key)?;
    let oidc = match oidc.filter(|o| o.enabled) {
        Some(o) => Some(o.prepare(issuer, &auth.audience, &server.public_url)?),
        None => None,
    };
    drop(key);
    let (database, startup_timeout) = db.prepare(base)?;
    if administration.as_ref().is_some_and(|a| a.cookie.is_some())
        && auth.digest.token_bytes.get() < 43
    {
        return Err(ServerError::Configuration);
    }
    let d = auth.digest;
    let local_enabled = auth
        .local
        .as_ref()
        .is_some_and(|local| local.login.as_ref().is_some_and(|login| login.enabled));
    if local_enabled
        && (!(administration
            .as_ref()
            .is_some_and(|admin| admin.cookie.is_some())
            || oidc.is_some())
            || d.token_bytes.get() < 43
            || (oidc.is_some() && d.binding_bytes.get() < 43))
    {
        return Err(ServerError::Configuration);
    }
    let limits = DigestLimits::new(
        d.pepper_bytes,
        d.token_bytes,
        d.binding_bytes,
        d.subject_bytes,
        d.recovery_bytes,
    )
    .map_err(|_| ServerError::Configuration)?;
    let digester = CredentialDigester::new(
        Zeroizing::new(auth.pepper.0.as_bytes().to_vec().into_boxed_slice()),
        limits,
    )
    .map_err(|_| ServerError::Configuration)?;
    let local_password = if local_enabled || administration.is_some() {
        let workers = auth
            .local
            .as_ref()
            .and_then(|local| local.rate_limit.as_ref())
            .and_then(|rate| rate.max_concurrent)
            .unwrap_or(NonZeroUsize::new(2).expect("sourced positive constant"));
        Some(PreparedLocalPassword {
            hasher: LocalPasswordHasher::new(Zeroizing::new(
                auth.pepper.0.as_bytes().to_vec().into_boxed_slice(),
            ))
            .map_err(|_| ServerError::Configuration)?,
            workers,
        })
    } else {
        None
    };
    let local_login = auth
        .local
        .filter(|local| local.login.as_ref().is_some_and(|login| login.enabled))
        .map(|local| local.prepare(&auth.pepper, &d, &server.public_url))
        .transpose()?;
    let default_route = match storage.default_route.take() {
        Some(s) => s,
        None if storage.routes.len() == 1 => {
            storage.routes.keys().next().expect("one route").clone()
        }
        None if !storage.enabled => String::new(),
        None => return Err(ServerError::Configuration),
    };
    if storage.enabled && !storage.routes.contains_key(&default_route) {
        return Err(ServerError::Configuration);
    }
    let grant_routes = Arc::new(
        broker_control::AdminGrantRoutes::new(
            storage.routes.keys().cloned(),
            default_route.clone(),
        )
        .map_err(|_| ServerError::Configuration)?,
    );
    for route in storage.routes.values() {
        let incompatible = match route.driver {
            Driver::S3 => {
                route.directory.is_some()
                    || route.max_object_bytes.is_some()
                    || route.access_key_id.is_some() != route.secret_access_key.is_some()
            }
            Driver::Filesystem => {
                route.role_arn.is_some()
                    || route.sts_endpoint.is_some()
                    || route.access_key_id.is_some()
                    || route.secret_access_key.is_some()
                    || route.session_name.is_some()
                    || route.allow_loopback_http.is_some()
                    || route.conditional_delete.is_some()
            }
        };
        if incompatible {
            return Err(ServerError::Configuration);
        }
    }
    let mut aws = Vec::new();
    let mut fs = Vec::new();
    let mut stores = Vec::new();
    // Disabled capability validates the schema but does not construct credential chains or volumes.
    if storage.enabled {
        for (name, r) in std::mem::take(&mut storage.routes) {
            match r.driver {
                Driver::S3 => {
                    if r.directory.is_some() || r.max_object_bytes.is_some() {
                        return Err(ServerError::Configuration);
                    }
                    let session_name = r.session_name.unwrap_or_else(session_name);
                    let allow_loopback_http = r.allow_loopback_http.unwrap_or(false);
                    let conditional_delete = r.conditional_delete.unwrap_or(false);
                    let role_arn = r.role_arn.ok_or(ServerError::Configuration)?;
                    if let Some(view) = configuration_view.as_mut() {
                        view.route(
                            name.clone(),
                            admin_config_view::RouteView::S3 {
                                bucket: r.bucket.clone(),
                                base_prefix: r.base_prefix.clone(),
                                region: r.region.clone(),
                                endpoint: r.endpoint.clone(),
                                role_arn: role_arn.clone(),
                                sts_endpoint: r.sts_endpoint.clone(),
                                session_duration: admin_config_view::Time(r.session_duration.0),
                                session_name: session_name.clone(),
                                allow_loopback_http,
                                conditional_delete,
                                access_key_id: r
                                    .access_key_id
                                    .as_ref()
                                    .map(admin_config_view::secret_marker),
                                secret_access_key: r
                                    .secret_access_key
                                    .as_ref()
                                    .map(admin_config_view::secret_marker),
                            },
                        )?;
                    }
                    let source = match (r.access_key_id, r.secret_access_key) {
                        (None, None) => AwsCredentialSource::DefaultChain,
                        (Some(key), Some(secret)) => AwsCredentialSource::StaticPair(
                            PrivateStaticCredentials::new(key.0, secret.0)
                                .map_err(|_| ServerError::Configuration)?,
                        ),
                        _ => return Err(ServerError::Configuration),
                    };
                    aws.push(
                        AwsStorageRoute::new(AwsStorageRouteConfig {
                            name,
                            region: r.region,
                            bucket: r.bucket,
                            base_prefix: r.base_prefix,
                            s3_endpoint: r.endpoint,
                            conditional_delete,
                            sts_endpoint: r.sts_endpoint,
                            role_arn,
                            session_name,
                            session_duration: r.session_duration.0,
                            credential_source: source,
                            endpoint_transport: if allow_loopback_http {
                                AwsEndpointTransport::LoopbackHttp
                            } else {
                                AwsEndpointTransport::HttpsOnly
                            },
                        })
                        .map_err(|_| ServerError::Configuration)?,
                    );
                }
                Driver::Filesystem => {
                    if r.role_arn.is_some()
                        || r.sts_endpoint.is_some()
                        || r.access_key_id.is_some()
                        || r.secret_access_key.is_some()
                        || r.session_name.is_some()
                        || r.allow_loopback_http.is_some()
                        || r.conditional_delete.is_some()
                        || storage.token_bytes > storage.head_bytes
                    {
                        return Err(ServerError::Configuration);
                    }
                    let directory = resolve(base, r.directory.ok_or(ServerError::Configuration)?)?;
                    let max_object_bytes = r.max_object_bytes.unwrap_or_else(object_bytes);
                    let endpoint = r
                        .endpoint
                        .unwrap_or_else(|| server.public_url.trim_end_matches('/').into());
                    if let Some(view) = configuration_view.as_mut() {
                        view.route(
                            name.clone(),
                            admin_config_view::RouteView::Filesystem {
                                bucket: r.bucket.clone(),
                                base_prefix: r.base_prefix.clone(),
                                region: r.region.clone(),
                                endpoint: endpoint.clone(),
                                directory: directory.clone(),
                                session_duration: admin_config_view::Time(r.session_duration.0),
                                max_object_bytes,
                            },
                        )?;
                    }
                    stores.push(FilesystemStoreConfig {
                        directory,
                        bucket: r.bucket.clone(),
                        max_object_bytes,
                        metadata_bytes: storage.metadata_bytes,
                    });
                    fs.push(
                        FilesystemStorageRoute::new(FilesystemStorageRouteConfig {
                            name,
                            bucket: r.bucket,
                            region: r.region,
                            base_prefix: r.base_prefix,
                            endpoint,
                            session_duration: r.session_duration.0,
                            token_bytes: storage.token_bytes,
                        })
                        .map_err(|_| ServerError::Configuration)?,
                    );
                }
            }
        }
    }
    let credentials = if storage.enabled {
        let mut issuers = Vec::new();
        if !aws.is_empty() {
            issuers.push(StorageIssuer::Aws(
                AwsStorageIssuer::new(aws, storage.sts_timeout.0)
                    .map_err(|_| ServerError::Configuration)?,
            ));
        }
        if !fs.is_empty() {
            issuers.push(StorageIssuer::Filesystem(
                FilesystemStorageIssuer::new(fs, Zeroizing::new(auth.pepper.0.as_bytes().to_vec()))
                    .map_err(|_| ServerError::Configuration)?,
            ));
        }
        Some(Arc::new(
            StorageCredentialsService::new(issuers).map_err(|_| ServerError::Configuration)?,
        ))
    } else {
        None
    };
    let snapshot_parent = model_paths
        .as_ref()
        .map(|paths| local_model_bootstrap::prepare(paths, startup_timeout))
        .transpose()?;
    let native_sdk = if model_paths.is_some() {
        Some(
            graphit_ai::native_embedding::NativeSdkRoot::new()
                .map_err(|_| ServerError::Configuration)?,
        )
    } else {
        None
    };
    let (embeddings, rerank) = match services {
        Some(services) => {
            services
                .prepare_all(
                    snapshot_parent,
                    base,
                    &auth.audience,
                    startup_timeout,
                    server.shutdown_timeout(),
                )
                .await?
        }
        None => (None, None),
    };
    if let Some(view) = configuration_view.as_mut() {
        view.services =
            embeddings_config::ServicesView::combined(embeddings.as_ref(), rerank.as_ref());
    }
    let instruction_overrides_file = resolve(
        base,
        server
            .instruction_overrides_file
            .clone()
            .unwrap_or_else(|| "agent-instructions.json".into()),
    )?;
    let mut prepared = PreparedConfig {
        server,
        database,
        digester,
        verifier,
        upstream,
        jwks,
        credentials,
        stores,
        storage,
        default_route,
        grant_routes,
        audience: auth.audience,
        startup_timeout,
        oidc,
        administration,
        upstream_cookie_secure,
        local_login,
        local_password,
        service_credential_max_ttl: auth.service_credential_max_ttl.0,
        project_access,
        presence,
        embeddings,
        rerank,
        configuration_yaml: None,
        instruction_overrides_file,
        native_sdk,
    };
    if let Some(view) = configuration_view {
        let yaml = prepared
            .administration
            .as_ref()
            .ok_or(ServerError::Configuration)
            .and_then(|admin| {
                view.finish(
                    admin,
                    prepared.oidc.as_ref(),
                    prepared.local_login.as_ref(),
                    prepared.project_access.as_ref(),
                    prepared.presence.as_ref(),
                    &prepared.default_route,
                )
            });
        match yaml {
            Ok(yaml) => prepared.configuration_yaml = Some(yaml),
            Err(error) => {
                prepared.shutdown_models().await?;
                return Err(error);
            }
        }
    }
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn prepared_storage_config_controls_the_real_http_service_announcement() {
        use crate::discovery::{services_discovery_router, tests::http_document};
        use serde_json::{Value, json};
        use std::io::Write;
        for enabled in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let example = include_str!("../../../docs/rust-broker-server.md");
            let yaml = example
                .split_once("```yaml\n")
                .unwrap()
                .1
                .split_once("```")
                .unwrap()
                .0;
            let mut value: Value = serde_saphyr::from_str(yaml).unwrap();
            let sqlite = example
                .split_once("## Select private SQLite")
                .unwrap()
                .1
                .split_once("~~~yaml\n")
                .unwrap()
                .1
                .split_once("~~~")
                .unwrap()
                .0;
            value["database"] =
                serde_saphyr::from_str::<Value>(sqlite).unwrap()["database"].clone();
            value["auth"]["pepper"] = json!("ephemeral-discovery-fixture-pepper-32bytes");
            value["storage"]["enabled"] = json!(enabled);
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            for (path, bytes) in [
                (
                    root.path().join("signing.pk8"),
                    zeroize::Zeroizing::new(key.serialize_der()),
                ),
                (
                    root.path().join("broker.json"),
                    zeroize::Zeroizing::new(serde_json::to_vec(&value).unwrap()),
                ),
            ] {
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                options.open(path).unwrap().write_all(&bytes).unwrap();
            }
            let prepared = crate::load_config(&root.path().join("broker.json"))
                .await
                .unwrap();
            assert_eq!(prepared.storage.enabled, enabled);
            assert_eq!(prepared.credentials.is_some(), enabled);
            let (status, document) = http_document(services_discovery_router(
                prepared.server.public_url(),
                None,
                None,
                prepared.storage.enabled && prepared.credentials.is_some(),
            ))
            .await;
            if enabled {
                assert_eq!(status, reqwest::StatusCode::OK);
                let document = document.unwrap();
                assert_eq!(
                    document["services"]["s3_credentials"],
                    json!({"protocol":"graphit-s3-credentials-v3", "path":"/v1/s3/credentials"})
                );
                assert!(document.get("authentication").is_none());
            } else {
                assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
                assert!(document.is_none());
            }
            assert!(
                !root.path().join("volumes/native-storage").exists(),
                "discovery preparation must not open the filesystem volume"
            );
        }
    }

    #[test]
    fn expressions_and_secret_errors() {
        let lookup = |name: &str| (name == "VALUE").then(|| Zeroizing::new("assigned".into()));
        assert_eq!(
            &*expand("${VALUE}/${ABSENT}/${ABSENT:-literal}", lookup).unwrap(),
            "assigned//literal"
        );
        assert_eq!(
            expand("${ABSENT:?secret message}", lookup).err(),
            Some(ServerError::Configuration)
        );
        assert!(
            !ServerError::Configuration
                .to_string()
                .contains("secret message")
        );
        assert!(expand(&"x".repeat(CONFIG_BYTES + 1), |_| None).is_err());
    }
    #[test]
    fn strict_yaml_and_active_defaults() {
        for raw in [
            "address: '127.0.0.1:80'\npublic_url: https://example.test\nunknown: value",
            "public_url: https://one.test\npublic_url: https://two.test",
            "public_url: https://one.test\n---\npublic_url: https://two.test",
            "public_url: https://one.test\nread_timeout: 0s",
        ] {
            assert!(serde_saphyr::from_str::<Server>(raw).is_err());
        }
        let server: Server = serde_saphyr::from_str("public_url: https://example.test").unwrap();
        assert_eq!(server.address.port(), 8080);
        assert_eq!(server.read_timeout(), Duration::from_secs(15));
        assert_eq!(server.write_timeout(), Duration::from_secs(60));
        assert_eq!(server.idle_timeout(), Duration::from_secs(120));
        assert_eq!(server.shutdown_timeout(), Duration::from_secs(15));
        assert_eq!(server.body_bytes.get(), CONFIG_BYTES);
        assert!(secure_origin("http://127.0.0.1:8080"));
        assert!(secure_origin("https://broker.example"));
        for url in [
            "http://10.0.0.1",
            "https://u:p@broker.example",
            "https://broker.example/path",
            "https://broker.example?secret=1",
        ] {
            assert!(!secure_origin(url));
        }
    }
}

#[cfg(test)]
mod presence_config_tests {
    use super::PresenceAuthentication;
    #[test]
    fn native_presence_rejects_opaque_mode_fields() {
        assert!(
            serde_json::from_value::<PresenceAuthentication>(
                serde_json::json!({"type":"broker_jwt"})
            )
            .is_ok()
        );
        for field in ["audience", "identity_json_bytes", "list", "unexpected"] {
            let mut value = serde_json::json!({"type":"broker_jwt"});
            value[field] = serde_json::json!("extraneous");
            assert!(
                serde_json::from_value::<PresenceAuthentication>(value).is_err(),
                "Native selector accepted {field}"
            );
        }
    }
}

#[cfg(test)]
mod database_config_tests {
    use super::*;
    fn value() -> serde_json::Value {
        serde_json::json!({"backend":"sqlite","path":"private/broker.db","startup_timeout":"10s","operation_timeout":"4s","shutdown_timeout":"3s","flows":{"provider_bytes":128,"request_bytes":1024,"continuation_bytes":4096}})
    }
    #[test]
    fn sqlite_requires_its_own_explicit_shape_and_valid_path_budgets() {
        let good = value();
        let db: Database = serde_json::from_value(good.clone()).unwrap();
        assert!(matches!(
            db.prepare(Path::new(".")),
            Ok((PreparedDatabase::Sqlite(_), _))
        ));
        for field in [
            "path",
            "startup_timeout",
            "operation_timeout",
            "shutdown_timeout",
            "flows",
        ] {
            let mut v = good.clone();
            v.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<Database>(v).is_err(),
                "missing {field}"
            );
        }
        for field in [
            "host",
            "port",
            "database",
            "username",
            "password",
            "ca_file",
            "text_bytes",
            "ca_bytes",
            "pool",
            "unexpected",
        ] {
            let mut v = good.clone();
            v[field] = serde_json::json!("foreign");
            assert!(
                serde_json::from_value::<Database>(v).is_err(),
                "foreign {field}"
            );
        }
        for backend in ["SQLite", "postgresql", "mysql", "invented"] {
            let mut v = good.clone();
            v["backend"] = serde_json::json!(backend);
            assert!(serde_json::from_value::<Database>(v).is_err());
        }
        for field in ["startup_timeout", "operation_timeout", "shutdown_timeout"] {
            for budget in ["0s", "invalid", "18446744073709551615s"] {
                let mut v = good.clone();
                v[field] = serde_json::json!(budget);
                assert!(
                    serde_json::from_value::<Database>(v).is_err(),
                    "{field}={budget}"
                );
            }
        }
        for path in ["", ":memory:", "file:private.db", "/"] {
            let mut v = good.clone();
            v["path"] = serde_json::json!(path);
            let db: Database = serde_json::from_value(v).unwrap();
            assert!(
                db.prepare(Path::new("base")).is_err(),
                "invalid path {path}"
            );
        }
    }
}
