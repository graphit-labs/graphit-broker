//! Closed deployment projection. Config, secret wrappers and runtime owners are
//! deliberately not Serialize. Builders capture effective public values once.
use super::*;
use serde::{Serialize, Serializer};

#[derive(Clone, Copy)]
pub(super) struct Time(pub Duration);
impl Serialize for Time {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&humantime::format_duration(self.0))
    }
}
fn mark(secret: &Secret) -> &'static str {
    if secret.0.is_empty() {
        ""
    } else {
        "[configured-secret]"
    }
}

#[derive(Serialize)]
pub(super) struct Deployment {
    server: ServerView,
    database: DatabaseView,
    auth: AuthView,
    storage: StorageView,
    #[serde(skip_serializing_if = "Option::is_none")]
    administration: Option<AdminView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc: Option<OidcView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_access: Option<ProjectView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    presence: Option<PresenceView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) services: Option<embeddings_config::ServicesView>,
}
#[derive(Serialize)]
struct ServerView {
    address: SocketAddr,
    public_url: String,
    read_timeout: Time,
    write_timeout: Time,
    idle_timeout: Time,
    shutdown_timeout: Time,
    body_bytes: NonZeroUsize,
}
#[derive(Serialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
enum DatabaseView {
    Postgres {
        host: String,
        port: NonZeroU16,
        database: String,
        username: String,
        password: &'static str,
        ca_file: PathBuf,
        text_bytes: NonZeroUsize,
        ca_bytes: NonZeroUsize,
        pool: Box<PoolView>,
        flows: FlowsView,
    },
    Sqlite {
        path: PathBuf,
        startup_timeout: Time,
        operation_timeout: Time,
        shutdown_timeout: Time,
        flows: FlowsView,
    },
}
#[derive(Serialize)]
struct PoolView {
    max_connections: NonZeroU32,
    min_connections: u32,
    statement_cache_capacity: usize,
    connect_timeout: Time,
    acquire_timeout: Time,
    operation_timeout: Time,
    startup_timeout: Time,
    shutdown_timeout: Time,
    max_lifetime: Time,
    idle_timeout: Time,
    statement_timeout: Time,
    lock_timeout: Time,
    idle_transaction_timeout: Time,
}
#[derive(Serialize)]
struct FlowsView {
    provider_bytes: NonZeroUsize,
    request_bytes: NonZeroUsize,
    continuation_bytes: NonZeroUsize,
}
#[derive(Serialize)]
struct AuthView {
    issuer: String,
    audience: String,
    service_credential_max_ttl: Time,
    kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    pkcs8_file: PathBuf,
    key_bytes: NonZeroUsize,
    pepper: &'static str,
    digest: DigestView,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc: Option<Vec<UpstreamView>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<LocalView>,
}
#[derive(Serialize)]
struct DigestView {
    pepper_bytes: NonZeroUsize,
    token_bytes: NonZeroUsize,
    binding_bytes: NonZeroUsize,
    subject_bytes: NonZeroUsize,
    recovery_bytes: NonZeroUsize,
}
#[derive(Serialize)]
#[serde(untagged)]
enum StorageView {
    Disabled {
        enabled: bool,
    },
    Enabled {
        enabled: bool,
        default_route: Option<String>,
        required_scopes: Vec<String>,
        request_timeout: Time,
        sts_timeout: Time,
        identity_json_bytes: NonZeroUsize,
        grants_json_bytes: NonZeroUsize,
        head_bytes: NonZeroUsize,
        token_bytes: NonZeroUsize,
        metadata_bytes: NonZeroUsize,
        routes: BTreeMap<String, RouteView>,
    },
}
#[derive(Serialize)]
#[serde(tag = "driver", rename_all = "snake_case")]
pub(super) enum RouteView {
    S3 {
        bucket: String,
        base_prefix: String,
        region: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
        role_arn: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sts_endpoint: Option<String>,
        session_duration: Time,
        session_name: String,
        allow_loopback_http: bool,
        conditional_delete: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        access_key_id: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        secret_access_key: Option<&'static str>,
    },
    Filesystem {
        bucket: String,
        base_prefix: String,
        region: String,
        endpoint: String,
        directory: PathBuf,
        session_duration: Time,
        max_object_bytes: NonZeroU64,
    },
}
#[derive(Serialize)]
struct AdminView {
    enabled: bool,
    request_timeout: Time,
    username_bytes: NonZeroUsize,
    subject_bytes: NonZeroUsize,
    role_bytes: NonZeroUsize,
    roles: NonZeroUsize,
    rows: NonZeroUsize,
    profile_json_bytes: NonZeroUsize,
    grants_json_bytes: NonZeroUsize,
    response_json_bytes: NonZeroUsize,
    cli: CliView,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_bearer: Option<LocalBearerView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookie: Option<CookieView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_ttl: Option<Time>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookie_secure: Option<bool>,
}
#[derive(Serialize)]
struct CliView {
    provider_name: String,
    profile_name: String,
}
#[derive(Serialize)]
struct LocalBearerView {
    enabled: bool,
    audience: String,
    identity_json_bytes: NonZeroUsize,
    required_scopes: Vec<String>,
}
#[derive(Serialize)]
struct CookieView {
    enabled: bool,
    text_bytes: NonZeroUsize,
    csrf_bytes: NonZeroUsize,
    team_bytes: NonZeroUsize,
    max_teams: NonZeroUsize,
    teams_json_bytes: NonZeroUsize,
    roles_json_bytes: NonZeroUsize,
}
#[derive(Clone, Serialize)]
pub(super) struct OidcView {
    pub enabled: bool,
    pub cli_client_id: String,
    pub cli_redirect_path: String,
    pub accepted_resources: Vec<String>,
    pub dynamic_registration: bool,
    pub authorization_ttl: Time,
    pub access_ttl: Time,
    pub refresh_ttl: Time,
    pub device_code_ttl: Time,
    pub device_poll_interval: Time,
    pub json_bytes: NonZeroUsize,
    pub parameter_bytes: NonZeroUsize,
    pub request_timeout: Time,
    pub body_bytes: NonZeroUsize,
    pub allowed_origins: Vec<String>,
}
#[derive(Clone, Serialize)]
pub(super) struct LocalView {
    pub login: LoginView,
    pub rate_limit: RateView,
    pub mfa: MfaView,
    pub captcha: CaptchaView,
}
#[derive(Clone, Serialize)]
pub(super) struct LoginView {
    pub enabled: bool,
}
#[derive(Clone, Serialize)]
pub(super) struct RateView {
    pub max_failures: NonZeroU32,
    pub window: Time,
    pub lockout: Time,
    pub max_concurrent: NonZeroUsize,
    pub saturation_multiplier: NonZeroUsize,
}
#[derive(Clone, Serialize)]
pub(super) struct MfaView {
    pub required: bool,
    pub issuer_label: String,
    pub challenge_ttl: Time,
}
#[derive(Clone, Serialize)]
#[serde(untagged)]
pub(super) enum CaptchaView {
    Disabled {
        enabled: bool,
    },
    Enabled {
        enabled: bool,
        provider: &'static str,
        site_key: String,
        secret_key: &'static str,
        trigger_multiplier: f64,
        verification_timeout: Time,
    },
}
impl CaptchaView {
    pub(super) fn new(value: &LocalCaptchaConfiguration) -> Self {
        match value {
            LocalCaptchaConfiguration::Disabled => Self::Disabled { enabled: false },
            LocalCaptchaConfiguration::Enabled {
                provider,
                site_key,
                secret_key,
                trigger_multiplier,
                verification_timeout,
                ..
            } => Self::Enabled {
                enabled: true,
                provider: match provider {
                    LocalCaptchaProvider::Turnstile => "turnstile",
                    LocalCaptchaProvider::Recaptcha => "recaptcha",
                },
                site_key: site_key.clone(),
                secret_key: if secret_key.is_empty() {
                    ""
                } else {
                    "[configured-secret]"
                },
                trigger_multiplier: *trigger_multiplier,
                verification_timeout: Time(*verification_timeout),
            },
        }
    }
}
#[derive(Serialize)]
struct ProjectView {
    enabled: bool,
    required_scopes: Vec<String>,
    grants_json_bytes: NonZeroUsize,
    body_bytes: NonZeroUsize,
    request_timeout: Time,
}
#[derive(Serialize)]
struct PresenceView {
    enabled: bool,
    authentication: PresenceAuthenticationView,
    publish: PublishView,
    read: ReadView,
    realtime: RealtimeView,
    heartbeat_timeout: Time,
    broadcast_capacity: NonZeroUsize,
}
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PresenceAuthenticationView {
    BrokerJwt {},
    LocalOpaque {
        audience: String,
        identity_json_bytes: NonZeroUsize,
        list: ListView,
    },
}
#[derive(Serialize)]
struct PublishView {
    required_scopes: Vec<String>,
    grants_json_bytes: NonZeroUsize,
    body_bytes: NonZeroUsize,
    request_timeout: Time,
}
#[derive(Serialize)]
struct ReadView {
    required_scopes: Vec<String>,
    grants_json_bytes: NonZeroUsize,
    inventory_json_bytes: NonZeroUsize,
    request_timeout: Time,
}
#[derive(Serialize)]
struct ListView {
    required_scopes: Vec<String>,
    grants_json_bytes: NonZeroUsize,
    inventory_json_bytes: NonZeroUsize,
    query_bytes: NonZeroUsize,
    request_timeout: Time,
}
#[derive(Serialize)]
struct RealtimeView {
    required_scopes: Vec<String>,
    grants_json_bytes: NonZeroUsize,
    inventory_json_bytes: NonZeroUsize,
    command_bytes: NonZeroUsize,
    outbound_bytes: NonZeroUsize,
    operation_timeout: Time,
}
#[derive(Serialize)]
struct UpstreamView {
    id: String,
    enabled: bool,
    issuer: String,
    audiences: Vec<String>,
    required_scopes: Vec<String>,
    allowed_algorithms: Vec<broker_control::UpstreamSignatureAlgorithm>,
    access_policy: AccessView,
    predicates: Vec<PredicateView>,
    claims: ClaimsView,
    limits: UpstreamLimitsView,
    request_timeout: Time,
    cache_max_age: Time,
    min_refresh_interval: Time,
    allow_loopback_http: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_bytes: Option<NonZeroUsize>,
    browser_clients: Vec<BrowserView>,
}
#[derive(Serialize)]
struct BrowserView {
    display_name: String,
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'static str>,
    redirect_url: String,
    scopes: Vec<String>,
    require_nonce: bool,
    claims_source: &'static str,
    id_token_additional_audiences: Vec<String>,
}
impl From<&broker_control::UpstreamBrowserClient> for BrowserView {
    fn from(value: &broker_control::UpstreamBrowserClient) -> Self {
        Self {
            display_name: value.display_name.clone(),
            client_id: value.client_id.clone(),
            client_secret: value.client_secret.as_ref().map(|_| "[configured-secret]"),
            redirect_url: value.redirect_url.clone(),
            scopes: value.scopes.clone(),
            require_nonce: value.require_nonce,
            claims_source: match value.claims_source {
                broker_control::UpstreamBrowserClaimsSource::IdToken => "id_token",
                broker_control::UpstreamBrowserClaimsSource::AccessToken => "access_token",
                broker_control::UpstreamBrowserClaimsSource::Userinfo => "userinfo",
            },
            id_token_additional_audiences: value.id_token_additional_audiences.clone(),
        }
    }
}
#[derive(Serialize)]
struct PredicateView {
    selector: String,
    value: String,
}
impl From<&broker_control::UpstreamClaimPredicate> for PredicateView {
    fn from(value: &broker_control::UpstreamClaimPredicate) -> Self {
        Self {
            selector: value.selector.clone(),
            value: value.value.clone(),
        }
    }
}
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AccessView {
    ResourceAudience {
        id_token_audiences: Vec<String>,
    },
    SignedMarker {
        #[serde(skip_serializing_if = "Option::is_none")]
        typ: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        claim: Option<PredicateView>,
    },
}
#[derive(Serialize)]
struct ClaimsView {
    subject: String,
    username: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    teams: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    roles: Option<String>,
}
#[derive(Serialize)]
struct UpstreamLimitsView {
    token_bytes: NonZeroUsize,
    response_bytes: NonZeroUsize,
    keys: NonZeroUsize,
    selector_bytes: NonZeroUsize,
    claim_string_bytes: NonZeroUsize,
    profile_json_bytes: NonZeroUsize,
    teams: NonZeroUsize,
}
impl Deployment {
    pub(super) fn new(
        s: &Server,
        db: &Database,
        a: &Auth,
        storage: &Storage,
        base: &Path,
    ) -> Result<Self, ServerError> {
        let d = &a.digest;
        Ok(Self {
            server: ServerView {
                address: s.address,
                public_url: s.public_url.clone(),
                read_timeout: Time(s.read_timeout.0),
                write_timeout: Time(s.write_timeout.0),
                idle_timeout: Time(s.idle_timeout.0),
                shutdown_timeout: Time(s.shutdown_timeout.0),
                body_bytes: s.body_bytes,
            },
            database: match db {
                Database::Postgres {
                    host,
                    port,
                    database,
                    username,
                    password,
                    ca_file,
                    text_bytes,
                    ca_bytes,
                    pool: p,
                    flows,
                } => DatabaseView::Postgres {
                    host: host.clone(),
                    port: *port,
                    database: database.clone(),
                    username: username.clone(),
                    password: mark(password),
                    ca_file: resolve(base, ca_file.clone())?,
                    text_bytes: *text_bytes,
                    ca_bytes: *ca_bytes,
                    pool: Box::new(PoolView {
                        max_connections: p.max_connections,
                        min_connections: p.min_connections,
                        statement_cache_capacity: p.statement_cache_capacity,
                        connect_timeout: Time(p.connect_timeout.0),
                        acquire_timeout: Time(p.acquire_timeout.0),
                        operation_timeout: Time(p.operation_timeout.0),
                        startup_timeout: Time(p.startup_timeout.0),
                        shutdown_timeout: Time(p.shutdown_timeout.0),
                        max_lifetime: Time(p.max_lifetime.0),
                        idle_timeout: Time(p.idle_timeout.0),
                        statement_timeout: Time(p.statement_timeout.0),
                        lock_timeout: Time(p.lock_timeout.0),
                        idle_transaction_timeout: Time(p.idle_transaction_timeout.0),
                    }),
                    flows: FlowsView {
                        provider_bytes: flows.provider_bytes,
                        request_bytes: flows.request_bytes,
                        continuation_bytes: flows.continuation_bytes,
                    },
                },
                Database::Sqlite {
                    path,
                    startup_timeout,
                    operation_timeout,
                    shutdown_timeout,
                    flows,
                } => DatabaseView::Sqlite {
                    path: resolve(base, path.clone())?,
                    startup_timeout: Time(startup_timeout.0),
                    operation_timeout: Time(operation_timeout.0),
                    shutdown_timeout: Time(shutdown_timeout.0),
                    flows: FlowsView {
                        provider_bytes: flows.provider_bytes,
                        request_bytes: flows.request_bytes,
                        continuation_bytes: flows.continuation_bytes,
                    },
                },
            },
            auth: AuthView {
                issuer: a.issuer.clone(),
                audience: a.audience.clone(),
                service_credential_max_ttl: Time(a.service_credential_max_ttl.0),
                kid: a.kid.clone(),
                resource: a.resource.clone(),
                pkcs8_file: resolve(base, a.pkcs8_file.clone())?,
                key_bytes: a.key_bytes,
                pepper: mark(&a.pepper),
                digest: DigestView {
                    pepper_bytes: d.pepper_bytes,
                    token_bytes: d.token_bytes,
                    binding_bytes: d.binding_bytes,
                    subject_bytes: d.subject_bytes,
                    recovery_bytes: d.recovery_bytes,
                },
                oidc: a.oidc.as_ref().map(|_| Vec::new()),
                local: None,
            },
            storage: if storage.enabled {
                StorageView::Enabled {
                    enabled: true,
                    default_route: None,
                    required_scopes: storage.required_scopes.clone(),
                    request_timeout: Time(storage.request_timeout.0),
                    sts_timeout: Time(storage.sts_timeout.0),
                    identity_json_bytes: storage.identity_json_bytes,
                    grants_json_bytes: storage.grants_json_bytes,
                    head_bytes: storage.head_bytes,
                    token_bytes: storage.token_bytes,
                    metadata_bytes: storage.metadata_bytes,
                    routes: BTreeMap::new(),
                }
            } else {
                StorageView::Disabled { enabled: false }
            },
            administration: None,
            oidc: None,
            project_access: None,
            presence: None,
            services: None,
        })
    }
    pub(super) fn upstream(
        &mut self,
        p: &broker_control::UpstreamProviderConfig,
        ca_file: Option<PathBuf>,
        ca_bytes: Option<NonZeroUsize>,
    ) -> Result<(), ServerError> {
        use broker_control::UpstreamAccessPolicy;
        let claims = &p.claims;
        let limits = p.limits;
        let access_policy = match &p.access_policy {
            UpstreamAccessPolicy::ResourceAudience { id_token_audiences } => {
                AccessView::ResourceAudience {
                    id_token_audiences: id_token_audiences.clone(),
                }
            }
            UpstreamAccessPolicy::SignedMarker { typ, claim } => AccessView::SignedMarker {
                typ: typ.clone(),
                claim: claim.as_ref().map(Into::into),
            },
        };
        self.auth
            .oidc
            .as_mut()
            .ok_or(ServerError::Configuration)?
            .push(UpstreamView {
                id: p.id.clone(),
                enabled: true,
                issuer: p.issuer.clone(),
                audiences: p.audiences.clone(),
                required_scopes: p.required_scopes.clone(),
                allowed_algorithms: p.allowed_algorithms.clone(),
                access_policy,
                predicates: p.predicates.iter().map(Into::into).collect(),
                claims: ClaimsView {
                    subject: claims.subject.clone(),
                    username: claims.username.clone(),
                    scope: claims.scope.clone(),
                    name: claims.name.clone(),
                    email: claims.email.clone(),
                    organization: claims.organization.clone(),
                    teams: claims.teams.clone(),
                    roles: claims.roles.clone(),
                },
                limits: UpstreamLimitsView {
                    token_bytes: limits.token_bytes,
                    response_bytes: limits.response_bytes,
                    keys: limits.keys,
                    selector_bytes: limits.selector_bytes,
                    claim_string_bytes: limits.claim_string_bytes,
                    profile_json_bytes: limits.profile_json_bytes,
                    teams: limits.teams,
                },
                request_timeout: Time(p.request_timeout),
                cache_max_age: Time(p.cache_max_age),
                min_refresh_interval: Time(p.min_refresh_interval),
                allow_loopback_http: p.allow_loopback_http,
                ca_file,
                ca_bytes,
                browser_clients: p.browser_clients.iter().map(Into::into).collect(),
            });
        Ok(())
    }
    pub(super) fn route(&mut self, name: String, route: RouteView) -> Result<(), ServerError> {
        let StorageView::Enabled { routes, .. } = &mut self.storage else {
            return Err(ServerError::Configuration);
        };
        if routes.insert(name, route).is_some() {
            return Err(ServerError::Configuration);
        }
        Ok(())
    }
    pub(super) fn finish(
        mut self,
        admin: &PreparedAdministration,
        oidc: Option<&PreparedOidc>,
        local: Option<&PreparedLocalLogin>,
        project: Option<&BrokerProjectAuthorizationHttpConfig>,
        presence: Option<&PreparedPresence>,
        default_route: &str,
    ) -> Result<String, ServerError> {
        let a = admin.http.limits;
        let i = a.identity;
        self.administration = Some(AdminView {
            enabled: true,
            request_timeout: Time(admin.http.request_timeout),
            username_bytes: i.username_bytes,
            subject_bytes: i.subject_bytes,
            role_bytes: i.role_bytes,
            roles: i.roles,
            rows: i.rows,
            profile_json_bytes: a.profile_json_bytes,
            grants_json_bytes: admin.read_limits.grants_json_bytes,
            response_json_bytes: admin.read_limits.response_json_bytes,
            cli: CliView {
                provider_name: admin.cli_provider.clone(),
                profile_name: admin.cli_profile.clone(),
            },
            local_bearer: admin.local_bearer.as_ref().map(|v| LocalBearerView {
                enabled: true,
                audience: v.audience.clone(),
                identity_json_bytes: v.identity_json_bytes,
                required_scopes: v.required_scopes.clone(),
            }),
            cookie: admin.cookie.map(|v| {
                let m = v.limits.metadata;
                CookieView {
                    enabled: true,
                    text_bytes: m.text_bytes,
                    csrf_bytes: m.csrf_bytes,
                    team_bytes: m.team_bytes,
                    max_teams: m.max_teams,
                    teams_json_bytes: m.teams_json_bytes,
                    roles_json_bytes: m.roles_json_bytes,
                }
            }),
            session_ttl: admin.cookie.map(|v| Time(v.policy.session_ttl)),
            cookie_secure: admin.cookie.map(|v| v.secure),
        });
        self.oidc = oidc.map(|v| v.view.clone());
        self.auth.local = local.map(|v| v.view.clone());
        self.project_access = project.map(|p| ProjectView {
            enabled: true,
            required_scopes: p.required_scopes.clone(),
            grants_json_bytes: p.grants_json_bytes,
            body_bytes: p.body_bytes,
            request_timeout: Time(p.request_timeout),
        });
        self.presence = presence.map(|p| PresenceView {
            enabled: true,
            authentication: match &p.authentication {
                PreparedPresenceAuthentication::BrokerJwt => {
                    PresenceAuthenticationView::BrokerJwt {}
                }
                PreparedPresenceAuthentication::LocalOpaque {
                    audience,
                    identity_json_bytes,
                    list,
                } => PresenceAuthenticationView::LocalOpaque {
                    audience: audience.clone(),
                    identity_json_bytes: *identity_json_bytes,
                    list: ListView {
                        required_scopes: list.required_scopes.clone(),
                        grants_json_bytes: list.grants_json_bytes,
                        inventory_json_bytes: list.inventory_json_bytes,
                        query_bytes: list.query_bytes,
                        request_timeout: Time(list.request_timeout),
                    },
                },
            },
            publish: PublishView {
                required_scopes: p.publish.required_scopes.clone(),
                grants_json_bytes: p.publish.grants_json_bytes,
                body_bytes: p.publish.body_bytes,
                request_timeout: Time(p.publish.request_timeout),
            },
            read: ReadView {
                required_scopes: p.read.required_scopes.clone(),
                grants_json_bytes: p.read.grants_json_bytes,
                inventory_json_bytes: p.read.inventory_json_bytes,
                request_timeout: Time(p.read.request_timeout),
            },
            realtime: RealtimeView {
                required_scopes: p.realtime.required_scopes.clone(),
                grants_json_bytes: p.realtime.grants_json_bytes,
                inventory_json_bytes: p.realtime.inventory_json_bytes,
                command_bytes: p.realtime.command_bytes,
                outbound_bytes: p.realtime.outbound_bytes,
                operation_timeout: Time(p.realtime.operation_timeout),
            },
            heartbeat_timeout: Time(p.heartbeat_timeout),
            broadcast_capacity: p.broadcast_capacity,
        });
        if let StorageView::Enabled {
            default_route: current,
            ..
        } = &mut self.storage
        {
            *current = Some(default_route.to_owned());
        }
        struct Capped {
            text: String,
            maximum: usize,
        }
        impl fmt::Write for Capped {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                if text.len() > self.maximum.saturating_sub(self.text.len()) {
                    return Err(fmt::Error);
                }
                self.text.push_str(text);
                Ok(())
            }
        }
        let mut output = Capped {
            text: String::new(),
            maximum: admin.read_limits.response_json_bytes.get(),
        };
        serde_saphyr::to_fmt_writer(&mut output, &self).map_err(|_| ServerError::Configuration)?;
        // Check the actual enclosing JSON/escaping budget before SQL or listeners.
        broker_presence::AdminReadHttpConfig {
            limits: admin.read_limits,
            provider_command: admin.provider_command.clone(),
            configuration_yaml: output.text.clone(),
        }
        .validate()
        .map_err(|_| ServerError::Configuration)?;
        Ok(output.text)
    }
}
pub(super) fn secret_marker(secret: &Secret) -> &'static str {
    mark(secret)
}
pub(super) fn provider_command(public_url: &str, provider: &str, profile: &str) -> String {
    fn quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
    let provider = quote(provider);
    let profile = quote(profile);
    let url = quote(public_url.trim_end_matches('/'));
    format!(
        "graphit --non-interactive provider add {provider} --type broker --broker-endpoint {url}\n\ngraphit login --provider {provider} --profile {profile}"
    )
}
