//! Private Native and Web OAuth / SQL / STSv3 fixture for actual Hub consumers.
//! Web mode composes the productive LOCAL browser, token and discovery producers.
#[allow(
    dead_code,
    reason = "shared PostgreSQL support also serves other integration suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
#[allow(
    dead_code,
    reason = "shared MinIO support also serves other integration suites"
)]
#[path = "../../broker-storage/tests/support_aws/mod.rs"]
mod support_aws;
// Reuse the canonical Server metadata producer without a fixture-only public API.
#[allow(
    dead_code,
    reason = "productive Server discovery is reused; its embeddings routes are not fixture capabilities"
)]
#[path = "../../broker-server/src/discovery.rs"]
mod discovery;

use axum::{Json, routing::get};
use broker_control::{
    BrokerAccessIssuer, BrokerAccessTokenInput, BrokerAccessVerifier, PostgresConfig,
    PostgresControlStore, StorageModule, StorageScope,
};
use broker_presence::{
    BrokerOwnReadHttpConfig, BrokerProjectAuthorizationHttpConfig, BrokerPublishHttpConfig,
    BrokerStorageCredentialsHttpConfig, FilesystemStorageHttp, HubAccessHttpConfig,
    RealtimeHttpConfig, RealtimeServerRuntime, broker_hub_access_router,
    broker_instance_inventory_router, broker_project_authorization_router, broker_realtime_router,
    broker_storage_credentials_router,
};
use broker_storage::{
    AwsCredentialSource, AwsEndpointTransport, AwsStorageIssuer, AwsStorageRoute,
    AwsStorageRouteConfig, FilesystemGatewayConfig, FilesystemStorageIssuer,
    FilesystemStorageRoute, FilesystemStorageRouteConfig, FilesystemStore, FilesystemStoreConfig,
    PrivateStaticCredentials, StorageCredentialsService, StorageIssuer,
};
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    io::{BufRead, Write},
    panic::AssertUnwindSafe,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use support_aws::Minio;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use zeroize::Zeroizing;

const API_AUDIENCE: &str = "broker-api";
const CLIENT_ID: &str = "native-client";
const SUBJECT: &str = "native-subject";
const SCOPE: &str = "openid fixture";
const REDIRECT: &str = "/auth/callback";
const ACCESS_TTL_SECONDS: u64 = 600;
const REGION: &str = "us-east-1";
const ROUTE: &str = "primary";

fn present_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Start {
        project_id: String,
        #[serde(default, deserialize_with = "present_string")]
        second_project_id: Option<String>,
        #[serde(default)]
        standalone: bool,
        #[serde(default)]
        standalone_catalog: bool,
    },
    StartWeb {
        project_id: String,
        #[serde(default)]
        standalone_catalog: bool,
        #[serde(default)]
        hub_storage_write: bool,
        #[serde(default)]
        now_read: bool,
        #[serde(default, deserialize_with = "present_string")]
        second_project_id: Option<String>,
        authorization_ttl_seconds: u64,
        local_challenge_ttl_seconds: u64,
        access_ttl_seconds: u64,
        refresh_ttl_seconds: u64,
    },
    HoldSts {},
    AwaitSts {},
    ReleaseSts {},
    Shutdown {},
}
impl Command {
    fn setup(self) -> Result<Setup, Failure> {
        match self {
            Self::Start {
                project_id,
                second_project_id,
                standalone,
                standalone_catalog,
            } => {
                if standalone_catalog && !standalone {
                    return Err(Failure::InvalidCommand);
                }
                let mut setup = Setup::new(project_id, second_project_id)?;
                setup.standalone = standalone;
                setup.standalone_catalog = standalone_catalog;
                Ok(setup)
            }
            Self::StartWeb {
                project_id,
                standalone_catalog,
                hub_storage_write,
                now_read,
                second_project_id,
                authorization_ttl_seconds,
                local_challenge_ttl_seconds,
                access_ttl_seconds,
                refresh_ttl_seconds,
            } => {
                let mut settings = WebSettings::new(
                    authorization_ttl_seconds,
                    local_challenge_ttl_seconds,
                    access_ttl_seconds,
                    refresh_ttl_seconds,
                )?;
                let mut setup = Setup::new(project_id, second_project_id)?;
                settings.now_read = now_read;
                settings.hub_storage_write = hub_storage_write;
                setup.standalone = standalone_catalog;
                setup.standalone_catalog = standalone_catalog;
                setup.web = Some(settings);
                Ok(setup)
            }
            Self::HoldSts {} | Self::AwaitSts {} | Self::ReleaseSts {} | Self::Shutdown {} => {
                Err(Failure::InvalidCommand)
            }
        }
    }
}
#[derive(Clone, Copy)]
struct WebSettings {
    now_read: bool,
    hub_storage_write: bool,
    authorization_ttl: Duration,
    local_challenge_ttl: Duration,
    access_ttl: Duration,
    refresh_ttl: Duration,
}
impl WebSettings {
    fn new(
        authorization: u64,
        local_challenge: u64,
        access: u64,
        refresh: u64,
    ) -> Result<Self, Failure> {
        let settings = Self {
            now_read: false,
            hub_storage_write: false,
            authorization_ttl: Duration::from_secs(authorization),
            local_challenge_ttl: Duration::from_secs(local_challenge),
            access_ttl: Duration::from_secs(access),
            refresh_ttl: Duration::from_secs(refresh),
        };
        for ttl in [
            settings.authorization_ttl,
            settings.local_challenge_ttl,
            settings.access_ttl,
            settings.refresh_ttl,
        ] {
            if ttl.is_zero() || std::time::Instant::now().checked_add(ttl).is_none() {
                return Err(Failure::InvalidCommand);
            }
        }
        broker_control::OidcTokenExchangePolicy::new(settings.access_ttl, settings.refresh_ttl)
            .map_err(|_| Failure::InvalidCommand)?;
        settings.authorization(&[])?;
        broker_control::LocalAuthPolicy::new(
            false,
            "Graphit Broker".into(),
            settings.local_challenge_ttl,
        )
        .map_err(|_| Failure::InvalidCommand)?;
        Ok(settings)
    }
    fn authorization(
        &self,
        resources: &[String],
    ) -> Result<Arc<broker_control::OidcAuthorizationPolicy>, Failure> {
        use broker_control::{
            OidcAuthorizationConfiguration, OidcAuthorizationLimits, OidcAuthorizationPolicy,
        };
        Ok(Arc::new(
            OidcAuthorizationPolicy::new(
                OidcAuthorizationConfiguration {
                    cli_client_id: CLIENT_ID.into(),
                    cli_redirect_path: REDIRECT.into(),
                    api_audience: API_AUDIENCE.into(),
                    accepted_resources: resources.to_vec(),
                    dynamic_registration: true,
                    authorization_ttl: self.authorization_ttl,
                },
                OidcAuthorizationLimits::new(n(65536), n(8192))
                    .map_err(|_| Failure::InvalidCommand)?,
            )
            .map_err(|_| Failure::InvalidCommand)?,
        ))
    }
}
struct Setup {
    project_id: String,
    second_project_id: Option<String>,
    web: Option<WebSettings>,
    standalone: bool,
    standalone_catalog: bool,
}
impl Setup {
    fn new(project_id: String, second_project_id: Option<String>) -> Result<Self, Failure> {
        StorageScope::project(&project_id, StorageModule::Hub)
            .map_err(|_| Failure::InvalidCommand)?;
        if let Some(second) = &second_project_id {
            StorageScope::project(second, StorageModule::Hub)
                .map_err(|_| Failure::InvalidCommand)?;
            if second == &project_id {
                return Err(Failure::InvalidCommand);
            }
        }
        Ok(Self {
            project_id,
            second_project_id,
            web: None,
            standalone: false,
            standalone_catalog: false,
        })
    }
}
#[derive(Debug)]
enum Failure {
    InvalidCommand,
    Input,
    Output,
    Setup,
    Server,
    Shutdown,
}
impl Failure {
    fn message(&self) -> &'static str {
        match self {
            Self::InvalidCommand => "invalid Hub storage fixture command",
            Self::Input => "Hub storage fixture input failed",
            Self::Output => "Hub storage fixture output failed",
            Self::Setup => "Hub storage fixture setup failed",
            Self::Server => "Hub storage fixture server failed",
            Self::Shutdown => "Hub storage fixture shutdown failed",
        }
    }
}
fn read_command(input: &mut impl BufRead) -> Result<Option<Command>, Failure> {
    let mut line = String::new();
    if input.read_line(&mut line).map_err(|_| Failure::Input)? == 0 {
        return Ok(None);
    }
    serde_json::from_str(&line)
        .map(Some)
        .map_err(|_| Failure::InvalidCommand)
}
fn emit(output: &mut impl Write, value: &impl Serialize) -> Result<(), Failure> {
    serde_json::to_writer(&mut *output, value).map_err(|_| Failure::Output)?;
    output.write_all(b"\n").map_err(|_| Failure::Output)?;
    output.flush().map_err(|_| Failure::Output)
}
fn config(pg: &Fixture) -> Result<PostgresConfig, Failure> {
    PostgresConfig::new(
        broker_control::PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: std::num::NonZeroU16::new(pg.port).ok_or(Failure::Setup)?,
            database: "postgres".into(),
        },
        broker_control::PostgresCredentials::new(
            "hub_storage_owner".into(),
            Zeroizing::new("fixture-owner".into()),
        ),
        pg.ca.clone(),
        broker_control::ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .map_err(|_| Failure::Setup)
}
const UNPUBLISH_CATALOG_IDS: [&str; 2] = ["fixture/web-file-reader", "fixture/web-publication"];
fn unpublish_catalog_prefixes() -> [String; 2] {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    UNPUBLISH_CATALOG_IDS.map(|id| {
        format!(
            "v1/projects/{{project}}/registry/skill/{}.json",
            URL_SAFE_NO_PAD.encode(id.as_bytes())
        )
    })
}
async fn grants(control: &mut PgConnection, setup: &Setup, origin: &str) -> Result<(), Failure> {
    let project = &setup.project_id;
    let catalog_prefixes = unpublish_catalog_prefixes();
    let catalog_roots: Vec<_> = catalog_prefixes.iter().map(String::as_str).collect();
    let mut tx = control.begin().await.map_err(|_| Failure::Setup)?;
    let mut publication_grants = vec![
        ("hub-resolve", project, "hub", "", &[][..], &[][..]),
        (
            "hub-objects",
            project,
            "s3",
            ROUTE,
            &["read", "write"][..],
            &[
                "v1/projects/{project}/registry",
                "v1/projects/{project}/artifacts",
                "v1/projects/{project}/hub/metadata",
            ][..],
        ),
        (
            "hub-staging",
            project,
            "s3",
            ROUTE,
            &["write", "delete"][..],
            &["v1/projects/{project}/artifacts/staging"][..],
        ),
    ];
    if setup.web.is_none_or(|web| web.hub_storage_write) {
        publication_grants.push((
            "hub-catalog-delete",
            project,
            "s3",
            ROUTE,
            &["delete"][..],
            catalog_roots.as_slice(),
        ));
    }
    if let Some(second) = setup
        .second_project_id
        .as_ref()
        .filter(|_| setup.web.is_some())
    {
        publication_grants.extend([
            (
                "hub-second-objects",
                second,
                "s3",
                ROUTE,
                &["read", "write"][..],
                &[
                    "v1/projects/{project}/registry",
                    "v1/projects/{project}/artifacts",
                ][..],
            ),
            (
                "hub-second-metadata",
                second,
                "s3",
                ROUTE,
                &["write"][..],
                &["v1/projects/{project}/hub/metadata/project.json"][..],
            ),
            (
                "hub-second-staging",
                second,
                "s3",
                ROUTE,
                &["write", "delete"][..],
                &["v1/projects/{project}/artifacts/staging"][..],
            ),
        ]);
    }
    for (id, project, cap, route, operations, prefixes) in publication_grants {
        sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'Hub process fixture','subject',$2,$3,0,0)")
            .bind(id).bind(format!("{origin}|{SUBJECT}")).bind(route)
            .execute(&mut *tx).await.map_err(|_| Failure::Setup)?;
        sqlx_core::query::query(
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
        )
        .bind(id)
        .bind(cap)
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::Setup)?;
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(project)
            .execute(&mut *tx)
            .await
            .map_err(|_| Failure::Setup)?;
        for (statement, values) in [
            (
                "INSERT INTO public.grant_s3_operations(grant_id,value) VALUES($1,$2)",
                operations,
            ),
            (
                "INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES($1,$2)",
                prefixes,
            ),
        ] {
            for value in values {
                sqlx_core::query::query(statement)
                    .bind(id)
                    .bind(*value)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| Failure::Setup)?;
            }
        }
    }
    for (id, capability) in [
        ("inventory-read", "presence:read"),
        ("inventory-publish", "presence:publish"),
    ] {
        sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'Hub process inventory','subject',$2,'',0,0)")
            .bind(id).bind(format!("{origin}|{SUBJECT}"))
            .execute(&mut *tx).await.map_err(|_| Failure::Setup)?;
        sqlx_core::query::query(
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
        )
        .bind(id)
        .bind(capability)
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::Setup)?;
        for inventory_project in std::iter::once(project).chain(setup.second_project_id.iter()) {
            sqlx_core::query::query(
                "INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)",
            )
            .bind(id)
            .bind(inventory_project)
            .execute(&mut *tx)
            .await
            .map_err(|_| Failure::Setup)?;
        }
    }
    tx.execute("UPDATE public.resource_acl_state SET revision=revision+1,updated_at=0 WHERE id=1")
        .await
        .map_err(|_| Failure::Setup)?;
    tx.commit().await.map_err(|_| Failure::Setup)
}

const WEB_USERNAME: &str = "hub-storage-web";
const WEB_RAW_SUBJECT: &str = "hub-storage-web-human";
const WEB_SCOPE: &str = "openid profile email offline_access";
#[derive(Serialize)]
struct WebReady<'a> {
    subject: &'a str,
    username: &'static str,
    password: &'a str,
    scope: &'static str,
}
struct WebRuntime {
    local: Arc<broker_presence::LocalLoginRuntime>,
    first: WebIdentity,
    second: Option<WebIdentity>,
}
struct WebIdentity {
    username: &'static str,
    subject: String,
    password: Zeroizing<String>,
}
impl WebIdentity {
    async fn prepare(
        engine: &broker_control::LocalPasswordEngine,
        control: &mut PgConnection,
        username: &'static str,
        raw_subject: &str,
    ) -> Result<Self, Failure> {
        let password = private_random()?;
        let hash = engine
            .hash(&password, deadline())
            .await
            .map_err(|_| Failure::Setup)?;
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Failure::Setup)?
                .as_micros(),
        )
        .map_err(|_| Failure::Setup)?;
        sqlx_core::query::query("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES($1,$2,'human',$3,'','','','[]',1,0,1,$4,$4)")
            .bind(username).bind(raw_subject).bind(hash.as_str()).bind(now)
            .execute(&mut *control).await.map_err(|_| Failure::Setup)?;
        let subject = support::digester()
            .oidc_subject(b"local", raw_subject.as_bytes())
            .map_err(|_| Failure::Setup)?
            .as_str()
            .to_owned();
        Ok(Self {
            username,
            subject,
            password,
        })
    }
    fn ready(&self) -> WebReady<'_> {
        WebReady {
            subject: &self.subject,
            username: self.username,
            password: &self.password,
            scope: WEB_SCOPE,
        }
    }
}
fn private_random() -> Result<Zeroizing<String>, Failure> {
    use base64::Engine;
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| Failure::Setup)?;
    Ok(Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_ref()),
    ))
}
async fn web_grants(
    control: &mut PgConnection,
    project: &str,
    origin: &str,
    subject: &str,
    grant_ids: (&str, &str),
    now_read: bool,
    hub_storage_write: bool,
) -> Result<(), Failure> {
    let mut tx = control.begin().await.map_err(|_| Failure::Setup)?;
    let staging_grant = format!("{}-staging", grant_ids.1);
    let catalog_grant = format!("{}-catalog-delete", grant_ids.1);
    let mut grants = vec![
        (grant_ids.0, "hub", "", subject),
        (grant_ids.1, "s3", ROUTE, subject),
    ];
    if hub_storage_write {
        grants.push((staging_grant.as_str(), "s3", ROUTE, subject));
        grants.push((catalog_grant.as_str(), "s3", ROUTE, subject));
    }
    if now_read {
        grants.extend([
            ("web-now-read", "presence:read", "", subject),
            ("web-task-read", "task:read", "", subject),
            ("now-publisher-task-read", "task:read", "", SUBJECT),
        ]);
    }
    for (id, capability, route, principal) in grants {
        sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'Web Hub fixture','subject',$2,$3,0,0)")
            .bind(id).bind(format!("{origin}|{principal}")).bind(route)
            .execute(&mut *tx).await.map_err(|_| Failure::Setup)?;
        sqlx_core::query::query(
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
        )
        .bind(id)
        .bind(capability)
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::Setup)?;
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(project)
            .execute(&mut *tx)
            .await
            .map_err(|_| Failure::Setup)?;
    }
    let operations: &[&str] = if hub_storage_write {
        &["read", "write"]
    } else {
        &["read"]
    };
    for operation in operations {
        sqlx_core::query::query(
            "INSERT INTO public.grant_s3_operations(grant_id,value) VALUES($1,$2)",
        )
        .bind(grant_ids.1)
        .bind(operation)
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::Setup)?;
    }
    let mut prefixes = vec![
        "v1/projects/{project}/registry",
        "v1/projects/{project}/artifacts",
    ];
    if hub_storage_write {
        prefixes.push("v1/projects/{project}/hub/metadata/project.json");
    }
    for prefix in prefixes {
        sqlx_core::query::query(
            "INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES($1,$2)",
        )
        .bind(grant_ids.1)
        .bind(prefix)
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::Setup)?;
    }
    if hub_storage_write {
        sqlx_core::query::query(
            "INSERT INTO public.grant_s3_operations(grant_id,value) VALUES($1,'delete')",
        )
        .bind(&staging_grant)
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::Setup)?;
        sqlx_core::query::query("INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES($1,'v1/projects/{project}/artifacts/staging')")
            .bind(&staging_grant).execute(&mut *tx).await.map_err(|_| Failure::Setup)?;
        sqlx_core::query::query(
            "INSERT INTO public.grant_s3_operations(grant_id,value) VALUES($1,'delete')",
        )
        .bind(&catalog_grant)
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::Setup)?;
        for prefix in unpublish_catalog_prefixes() {
            sqlx_core::query::query(
                "INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES($1,$2)",
            )
            .bind(&catalog_grant)
            .bind(prefix)
            .execute(&mut *tx)
            .await
            .map_err(|_| Failure::Setup)?;
        }
    }
    tx.execute("UPDATE public.resource_acl_state SET revision=revision+1,updated_at=0 WHERE id=1")
        .await
        .map_err(|_| Failure::Setup)?;
    tx.commit().await.map_err(|_| Failure::Setup)
}
impl WebRuntime {
    async fn prepare(
        store: Arc<PostgresControlStore>,
        control: &mut PgConnection,
        issuer: Arc<BrokerAccessIssuer>,
        verifier: Arc<BrokerAccessVerifier>,
        origin: &str,
        resource: &str,
        setup: &Setup,
    ) -> Result<(axum::Router, Self), Failure> {
        let settings = setup.web.ok_or(Failure::Setup)?;
        use broker_control::{
            LocalAuthPolicy, LocalCaptcha, LocalCaptchaConfiguration, LocalMfaAttemptLimiter,
            LocalMfaAttemptPolicy, LocalPasswordAdmission, LocalPasswordAdmissionPolicy,
            LocalPasswordEngine, OidcTokenExchangePolicy,
        };
        use broker_presence::{
            LocalLoginRuntime, OidcBrowserHttpConfig, OidcRegistrationHttpConfig,
            OidcTokenHttpConfig, oidc_browser_router, oidc_registration_router, oidc_token_router,
        };
        use broker_security::{LocalMfaProtector, LocalPasswordHasher};
        let resources = [resource.to_owned()];
        let authorization = settings.authorization(&resources)?;
        let token_policy = Arc::new(
            OidcTokenExchangePolicy::new(settings.access_ttl, settings.refresh_ttl)
                .map_err(|_| Failure::Setup)?,
        );
        let mut pepper = Zeroizing::new(vec![0u8; 32].into_boxed_slice());
        getrandom::fill(pepper.as_mut()).map_err(|_| Failure::Setup)?;
        let hasher = LocalPasswordHasher::new(pepper.clone()).map_err(|_| Failure::Setup)?;
        let mfa = LocalMfaProtector::new(pepper).map_err(|_| Failure::Setup)?;
        let policy =
            LocalAuthPolicy::new(false, "Graphit Broker".into(), settings.local_challenge_ttl)
                .map_err(|_| Failure::Setup)?;
        let limiter = LocalMfaAttemptLimiter::new(
            LocalMfaAttemptPolicy::new(
                std::num::NonZeroU32::new(5).ok_or(Failure::Setup)?,
                Duration::from_secs(60),
                Duration::from_secs(300),
                n(4096),
            )
            .map_err(|_| Failure::Setup)?,
        );
        let captcha = LocalCaptcha::new(LocalCaptchaConfiguration::Disabled, n(1), n(2))
            .map_err(|_| Failure::Setup)?;
        let engine = Arc::new(
            LocalPasswordEngine::new(hasher, n(1), deadline())
                .await
                .map_err(|_| Failure::Setup)?,
        );
        let prepared = async {
            let admission = Arc::new(
                LocalPasswordAdmission::new(
                    LocalPasswordAdmissionPolicy {
                        max_failures: n(5),
                        window: Duration::from_secs(60),
                        lockout: Duration::from_secs(300),
                        workers: n(1),
                        saturation_multiplier: n(2),
                        max_tracked: n(4096),
                    },
                    &engine,
                    captcha,
                )
                .map_err(|_| Failure::Setup)?,
            );
            let local = Arc::new(LocalLoginRuntime::new(
                engine.clone(),
                admission,
                support::digester(),
                mfa,
                policy,
                limiter,
            ));
            let first =
                WebIdentity::prepare(&engine, control, WEB_USERNAME, WEB_RAW_SUBJECT).await?;
            web_grants(
                control,
                &setup.project_id,
                origin,
                &first.subject,
                ("web-hub-resolve", "web-hub-objects"),
                settings.now_read,
                settings.hub_storage_write,
            )
            .await?;
            let second = if let Some(project) = setup.second_project_id.as_deref() {
                let identity = WebIdentity::prepare(
                    &engine,
                    control,
                    "hub-storage-web-second",
                    "hub-storage-web-human-second",
                )
                .await?;
                web_grants(
                    control,
                    project,
                    origin,
                    &identity.subject,
                    ("web-second-hub-resolve", "web-second-hub-objects"),
                    false,
                    false,
                )
                .await?;
                Some(identity)
            } else {
                None
            };
            let browser = oidc_browser_router(
                store.clone(),
                OidcBrowserHttpConfig {
                    authorization: authorization.clone(),
                    body_bytes: n(65536),
                    request_timeout: Duration::from_secs(10),
                    cookie_secure: false,
                },
                Some(local.clone()),
                None,
            )
            .map_err(|_| Failure::Setup)?;
            let registration = oidc_registration_router(
                store.clone(),
                authorization.clone(),
                OidcRegistrationHttpConfig::new(Duration::from_secs(10))
                    .map_err(|_| Failure::Setup)?,
            );
            let introspection = broker_presence::oidc_introspection_router(
                store.clone(),
                verifier.clone(),
                authorization.clone(),
                broker_presence::OidcIntrospectionHttpConfig {
                    request_timeout: Duration::from_secs(10),
                    body_bytes: n(65536),
                },
            )
            .map_err(|_| Failure::Setup)?;
            let userinfo = broker_presence::oidc_userinfo_router(
                store.clone(),
                verifier.clone(),
                authorization.clone(),
                None,
                broker_presence::OidcUserInfoHttpConfig {
                    request_timeout: Duration::from_secs(10),
                    body_bytes: n(65536),
                },
            )
            .map_err(|_| Failure::Setup)?;
            let end_session = broker_presence::oidc_end_session_router(
                store.clone(),
                verifier.clone(),
                authorization.clone(),
                broker_presence::OidcEndSessionHttpConfig {
                    request_timeout: Duration::from_secs(10),
                    body_bytes: n(65536),
                },
            )
            .map_err(|_| Failure::Setup)?;
            let revocation = broker_presence::oidc_revocation_router(
                store.clone(),
                verifier,
                authorization.clone(),
                broker_presence::OidcRevocationHttpConfig {
                    request_timeout: Duration::from_secs(10),
                    body_bytes: n(65536),
                },
            )
            .map_err(|_| Failure::Setup)?;
            let tokens = oidc_token_router(
                store,
                issuer.clone(),
                authorization,
                token_policy,
                OidcTokenHttpConfig::new(Duration::from_secs(10), n(65536))
                    .map_err(|_| Failure::Setup)?,
            )
            .map_err(|_| Failure::Setup)?;
            let keys = serde_json::to_value(issuer.jwks()).map_err(|_| Failure::Setup)?;
            let router = browser
                .merge(registration)
                .merge(tokens)
                .merge(introspection)
                .merge(userinfo)
                .merge(revocation)
                .merge(end_session)
                .merge(
                    discovery::Discovery::new(
                        origin,
                        API_AUDIENCE,
                        CLIENT_ID,
                        REDIRECT,
                        &resources,
                        true,
                    )
                    .router(),
                )
                .route(
                    "/v1/oidc/keys",
                    get(move || {
                        let value = keys.clone();
                        async move { Json(value) }
                    }),
                );
            Ok((
                router,
                Self {
                    local,
                    first,
                    second,
                },
            ))
        }
        .await;
        if prepared.is_err() {
            engine.close().await;
        }
        prepared
    }
    fn ready(&self) -> WebReady<'_> {
        self.first.ready()
    }
}

// Setup-only LocalS3 capability. It is independent of Broker STS grants and JWT identity.
struct StandaloneStorage {
    prefix: String,
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    expires_at: i64,
}
#[derive(Serialize)]
struct StandaloneStorageReady<'a> {
    bucket: &'a str,
    region: &'static str,
    endpoint: &'a str,
    prefix: &'a str,
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: Option<&'a str>,
    expires_at: i64,
}
impl StandaloneStorage {
    fn create(
        minio: &Minio,
        project: &str,
        catalog: bool,
        publisher: bool,
    ) -> Result<Self, Failure> {
        let prefix = format!("standalone/{project}");
        let mut access_key_id = private_random()?;
        // MinIO service-account keys admit 3..=20 characters. Keep 120 random bits.
        access_key_id.truncate(20);
        let mut secret_access_key = private_random()?;
        // The service-account API admits 8..=40 secret characters.
        secret_access_key.truncate(40);
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Failure::Setup)?
                .as_secs(),
        )
        .map_err(|_| Failure::Setup)?;
        let expires_at = now.checked_add(1800).ok_or(Failure::Setup)?;
        let expiry = chrono::DateTime::<chrono::Utc>::from_timestamp(expires_at, 0)
            .ok_or(Failure::Setup)?
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let mut statements = vec![json!({
            "Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],
            "Resource":[format!("arn:aws:s3:::{}/{prefix}/*", minio.bucket)]
        })];
        if catalog {
            statements.push(json!({
                "Effect":"Allow","Action":["s3:ListBucket"],
                "Resource":[format!("arn:aws:s3:::{}", minio.bucket)],
                "Condition":{"StringLike":{"s3:prefix":[prefix,format!("{prefix}/*")]}}
            }));
        }
        if publisher {
            // SDK producer IDs vary within this already admitted setup namespace.
            statements.push(json!({
                "Effect":"Allow","Action":["s3:DeleteObject"],
                "Resource":[format!("arn:aws:s3:::{}/{prefix}/v1/projects/*/artifacts/staging/native-upload-*", minio.bucket)]
            }));
        }
        let policy = json!({"Version":"2012-10-17","Statement":statements});
        let mut file = tempfile::NamedTempFile::new().map_err(|_| Failure::Setup)?;
        serde_json::to_writer(&mut file, &policy).map_err(|_| Failure::Setup)?;
        file.flush().map_err(|_| Failure::Setup)?;
        minio.admin(&[
            "admin",
            "accesskey",
            "create",
            "fixture",
            minio.caller_key.as_str(),
            "--access-key",
            access_key_id.as_str(),
            "--secret-key",
            secret_access_key.as_str(),
            "--policy",
            file.path().to_str().ok_or(Failure::Setup)?,
            "--expiry",
            &expiry,
        ]);
        Ok(Self {
            prefix,
            access_key_id,
            secret_access_key,
            expires_at,
        })
    }
    fn ready<'a>(&'a self, minio: &'a Minio) -> StandaloneStorageReady<'a> {
        StandaloneStorageReady {
            bucket: &minio.bucket,
            region: REGION,
            endpoint: &minio.endpoint,
            prefix: &self.prefix,
            access_key_id: &self.access_key_id,
            secret_access_key: &self.secret_access_key,
            session_token: None,
            expires_at: self.expires_at,
        }
    }
}

#[derive(Serialize)]
struct Ready<'a> {
    event: &'static str,
    endpoint: &'a str,
    issuer: &'a str,
    api_audience: &'static str,
    resource: &'a str,
    client_id: &'static str,
    subject: &'static str,
    scope: &'static str,
    redirect_uri_path: &'static str,
    expires_at: u64,
    access_bearer: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    web: Option<WebReady<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    web_second: Option<WebReady<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    standalone_storage: Option<StandaloneStorageReady<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    standalone_publisher_storage: Option<StandaloneStorageReady<'a>>,
    project_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    second_project_id: Option<&'a str>,
    bucket: &'a str,
    region: &'static str,
    storage_endpoint: &'a str,
    prefix: &'a str,
}
/// One private observation/release pair per completed productive STSv3 response.
#[derive(Default)]
struct StsBarrier {
    gate: tokio::sync::Mutex<Option<StsGate>>,
}
struct StsGate {
    entered: Option<oneshot::Sender<()>>,
    observed: Option<oneshot::Receiver<()>>,
    release: Option<oneshot::Sender<()>>,
    response: Option<oneshot::Receiver<()>>,
    finish: Option<oneshot::Sender<()>>,
    done: oneshot::Receiver<()>,
}
impl StsBarrier {
    async fn hold(&self) -> Result<(), Failure> {
        let mut gate = self.gate.lock().await;
        if gate.as_mut().is_some_and(|gate| {
            matches!(
                gate.done.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            )
        }) {
            return Err(Failure::InvalidCommand);
        }
        let (entered, observed) = oneshot::channel();
        let (release, response) = oneshot::channel();
        let (finish, done) = oneshot::channel();
        *gate = Some(StsGate {
            entered: Some(entered),
            observed: Some(observed),
            release: Some(release),
            response: Some(response),
            finish: Some(finish),
            done,
        });
        Ok(())
    }
    async fn retain(&self) {
        let waiting = {
            let mut gate = self.gate.lock().await;
            gate.as_mut().and_then(|gate| {
                Some((
                    gate.response.take()?,
                    gate.entered.take()?,
                    gate.finish.take()?,
                ))
            })
        };
        if let Some((response, entered, finish)) = waiting {
            let _ = entered.send(());
            let _ = response.await;
            let _ = finish.send(());
        }
    }
    async fn await_entered(&self) -> Result<(), Failure> {
        let observed = self
            .gate
            .lock()
            .await
            .as_mut()
            .and_then(|gate| gate.observed.take())
            .ok_or(Failure::InvalidCommand)?;
        tokio::time::timeout(Duration::from_secs(30), observed)
            .await
            .map_err(|_| Failure::Server)?
            .map_err(|_| Failure::Server)
    }
    async fn release(&self) {
        let mut slot = self.gate.lock().await;
        if let Some(gate) = slot.as_mut() {
            if let Some(release) = gate.release.take() {
                let _ = release.send(());
            }
            if gate.response.is_some() {
                *slot = None;
            }
        }
    }
}
async fn retain_sts_response(
    axum::extract::State(barrier): axum::extract::State<Arc<StsBarrier>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let selected = request.method() == axum::http::Method::POST
        && request.uri().path() == "/v1/s3/credentials";
    let response = next.run(request).await;
    if selected && response.status().is_success() {
        barrier.retain().await;
    }
    response
}

struct LiveFixture {
    postgres: Fixture,
    control: PgConnection,
    store: Arc<PostgresControlStore>,
    minio: Option<Minio>,
    filesystem_directory: Option<tempfile::TempDir>,
    filesystem_http: Option<FilesystemStorageHttp>,
    storage_bucket: String,
    storage_endpoint: String,
    standalone_storage: Option<StandaloneStorage>,
    standalone_publisher_storage: Option<StandaloneStorage>,
    setup: Setup,
    origin: String,
    resource: String,
    prefix: String,
    bearer: Zeroizing<String>,
    expires_at: u64,
    verifier: Arc<BrokerAccessVerifier>,
    realtime: RealtimeServerRuntime,
    web: Option<WebRuntime>,
    stop: oneshot::Sender<()>,
    server: JoinHandle<Result<(), std::io::Error>>,
    sts_barrier: Arc<StsBarrier>,
}
fn phase(name: &'static str) {
    if std::env::var_os("GRAPHIT_BROKER_FIXTURE_DIAGNOSTICS").is_some_and(|value| value == "1") {
        eprintln!("broker-hub-storage-fixture phase={name}");
    }
}
impl LiveFixture {
    async fn start(setup: Setup) -> Result<Self, Failure> {
        // An explicit alternative uses the same Broker SQL/JWT/HTTP owners and wire protocol.
        let filesystem = match std::env::var_os("GRAPHIT_BROKER_HUB_STORAGE_FIXTURE_BACKEND") {
            None => false,
            Some(value) if value == "minio" => false,
            Some(value) if value == "filesystem" => true,
            Some(_) => return Err(Failure::InvalidCommand),
        };
        if filesystem && setup.standalone {
            return Err(Failure::InvalidCommand);
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| Failure::Server)?;
        let origin = format!(
            "http://{}",
            listener.local_addr().map_err(|_| Failure::Server)?
        );
        let resource = format!("{origin}/v1");
        let prefix = "t".to_owned();
        phase("postgres-begin");
        let postgres = Fixture::new(true).await;
        phase("postgres-end-sql-begin");
        let mut control = postgres.connection().await;
        control.execute("CREATE ROLE hub_storage_owner LOGIN NOSUPERUSER PASSWORD 'fixture-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION hub_storage_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO hub_storage_owner")
            .await.map_err(|_| Failure::Setup)?;
        let store = Arc::new(
            PostgresControlStore::open(config(&postgres)?, support::digester(), deadline())
                .await
                .map_err(|_| Failure::Setup)?,
        );
        grants(&mut control, &setup, &origin).await?;
        phase("sql-end-minio-begin");
        let minio = if filesystem {
            None
        } else {
            let mut minio = Minio::start().await;
            // Each fixture owns its MinIO process and private volume. Short names
            // leave room for the unchanged scoped policy under the real STS limit.
            let bucket = "hub";
            minio.admin(&["mb", &format!("fixture/{bucket}")]);
            let parent = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":[format!("arn:aws:s3:::{bucket}"),format!("arn:aws:s3:::{bucket}/*")]}]});
            let mut policy = tempfile::NamedTempFile::new().map_err(|_| Failure::Setup)?;
            serde_json::to_writer(&mut policy, &parent).map_err(|_| Failure::Setup)?;
            policy.flush().map_err(|_| Failure::Setup)?;
            minio.admin(&[
                "admin",
                "policy",
                "create",
                "fixture",
                "fixture-parent",
                policy.path().to_str().ok_or(Failure::Setup)?,
            ]);
            minio.admin(&["rb", &format!("fixture/{}", minio.bucket)]);
            minio.bucket = bucket.into();
            Some(minio)
        };
        let storage_bucket = minio
            .as_ref()
            .map_or_else(|| "hub".to_owned(), |s| s.bucket.clone());
        let storage_endpoint = minio
            .as_ref()
            .map_or_else(|| origin.clone(), |s| s.endpoint.clone());
        phase("minio-end-standalone-begin");
        let standalone_storage = if setup.standalone {
            Some(StandaloneStorage::create(
                minio.as_ref().ok_or(Failure::Setup)?,
                &setup.project_id,
                setup.standalone_catalog,
                false,
            )?)
        } else {
            None
        };
        let standalone_publisher_storage = if setup.standalone_catalog {
            Some(StandaloneStorage::create(
                minio.as_ref().ok_or(Failure::Setup)?,
                &setup.project_id,
                true,
                true,
            )?)
        } else {
            None
        };
        phase("minio-end-auth-begin");
        let mut filesystem_directory = None;
        let mut filesystem_http = None;
        let storage = if filesystem {
            let directory = tempfile::tempdir().map_err(|_| Failure::Setup)?;
            let mut pepper = Zeroizing::new(vec![0u8; 32]);
            getrandom::fill(pepper.as_mut()).map_err(|_| Failure::Setup)?;
            let issuer = FilesystemStorageIssuer::new(
                vec![
                    FilesystemStorageRoute::new(FilesystemStorageRouteConfig {
                        name: ROUTE.into(),
                        bucket: storage_bucket.clone(),
                        region: REGION.into(),
                        base_prefix: prefix.clone(),
                        endpoint: origin.clone(),
                        session_duration: Duration::from_secs(900),
                        token_bytes: n(65536),
                    })
                    .map_err(|_| Failure::Setup)?,
                ],
                pepper,
            )
            .map_err(|_| Failure::Setup)?;
            let service = Arc::new(
                StorageCredentialsService::new(vec![StorageIssuer::Filesystem(issuer)])
                    .map_err(|_| Failure::Setup)?,
            );
            let volume = Arc::new(
                FilesystemStore::open(FilesystemStoreConfig {
                    directory: directory.path().join("volume"),
                    bucket: storage_bucket.clone(),
                    max_object_bytes: std::num::NonZeroU64::new(1024 * 1024)
                        .ok_or(Failure::Setup)?,
                    metadata_bytes: n(8192),
                })
                .map_err(|_| Failure::Setup)?,
            );
            let gateways = service
                .filesystem_gateways(
                    vec![volume],
                    FilesystemGatewayConfig {
                        request_timeout: Duration::from_secs(10),
                        request_head_bytes: n(70000),
                    },
                )
                .map_err(|_| Failure::Setup)?;
            filesystem_http = Some(
                FilesystemStorageHttp::new(
                    gateways.into_iter().map(Arc::new).collect(),
                    Duration::from_secs(10),
                )
                .map_err(|_| Failure::Setup)?,
            );
            filesystem_directory = Some(directory);
            service
        } else {
            let minio = minio.as_ref().ok_or(Failure::Setup)?;
            let route = AwsStorageRoute::new(AwsStorageRouteConfig {
                name: ROUTE.into(),
                conditional_delete: false,
                region: REGION.into(),
                bucket: minio.bucket.clone(),
                base_prefix: prefix.clone(),
                s3_endpoint: Some(minio.endpoint.clone()),
                sts_endpoint: None,
                role_arn: "arn:aws:iam::123456789012:role/fixture".into(),
                session_name: "graphit-broker".into(),
                session_duration: Duration::from_secs(900),
                credential_source: AwsCredentialSource::StaticPair(
                    PrivateStaticCredentials::new(
                        minio.caller_key.clone(),
                        minio.caller_secret.clone(),
                    )
                    .map_err(|_| Failure::Setup)?,
                ),
                endpoint_transport: AwsEndpointTransport::LoopbackHttp,
            })
            .map_err(|_| Failure::Setup)?;
            Arc::new(
                StorageCredentialsService::new(vec![StorageIssuer::Aws(
                    AwsStorageIssuer::new(vec![route], Duration::from_secs(5))
                        .map_err(|_| Failure::Setup)?,
                )])
                .map_err(|_| Failure::Setup)?,
            )
        };
        let pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|_| Failure::Setup)?;
        let key = Zeroizing::new(pair.serialize_der());
        let issuer = Arc::new(
            BrokerAccessIssuer::new(&origin, API_AUDIENCE, "hub-storage-fixture", &key)
                .map_err(|_| Failure::Setup)?,
        );
        let verifier = Arc::new(
            BrokerAccessVerifier::new(
                &origin,
                API_AUDIENCE,
                Some(&resource),
                issuer.jwks(),
                n(8192),
            )
            .map_err(|_| Failure::Setup)?,
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Failure::Setup)?
            .as_secs();
        let expires_at = now.checked_add(ACCESS_TTL_SECONDS).ok_or(Failure::Setup)?;
        let bearer = Zeroizing::new(
            issuer
                .sign_access(
                    BrokerAccessTokenInput {
                        subject: SUBJECT,
                        client_id: CLIENT_ID,
                        resource: Some(&resource),
                        scope: SCOPE,
                        jti: "hub-storage-fixture-access",
                        issued_at: now,
                        expires_at,
                        preferred_username: None,
                        name: None,
                        email: None,
                        organization: None,
                        groups: &[],
                        roles: &[],
                    },
                    deadline(),
                )
                .map_err(|_| Failure::Setup)?,
        );
        verifier
            .verify(&bearer, &["fixture".into()], deadline())
            .map_err(|_| Failure::Setup)?;
        let required_scope = if setup.web.is_some() {
            "openid"
        } else {
            "fixture"
        };
        let inventory = broker_instance_inventory_router(
            store.clone(),
            verifier.clone(),
            BrokerPublishHttpConfig {
                required_scopes: vec![required_scope.into()],
                grants_json_bytes: n(65536),
                body_bytes: n(65536),
                request_timeout: Duration::from_secs(10),
            },
            BrokerOwnReadHttpConfig {
                required_scopes: vec![required_scope.into()],
                grants_json_bytes: n(65536),
                inventory_json_bytes: n(65536),
                request_timeout: Duration::from_secs(10),
            },
        )
        .map_err(|_| Failure::Setup)?;
        let hub = broker_hub_access_router(
            store.clone(),
            verifier.clone(),
            HubAccessHttpConfig {
                grants_json_bytes: n(65536),
                request_timeout: Duration::from_secs(10),
            },
        )
        .map_err(|_| Failure::Setup)?;
        let catalog = broker_presence::hub_catalog_router(
            store.clone(),
            verifier.clone(),
            Arc::new(broker_storage::HubCatalogReader::new(
                storage.clone(),
                Vec::new(),
                n(65536),
            )),
            broker_presence::HubCatalogHttpConfig {
                audience: API_AUDIENCE.into(),
                identity_json_bytes: n(65536),
                grants_json_bytes: n(65536),
                default_route: ROUTE.into(),
                query_bytes: n(8192),
                request_timeout: Duration::from_secs(10),
            },
        )
        .map_err(|_| Failure::Setup)?;
        let credentials = broker_storage_credentials_router(
            store.clone(),
            verifier.clone(),
            Some(storage),
            BrokerStorageCredentialsHttpConfig {
                required_scopes: vec![required_scope.into()],
                grants_json_bytes: n(65536),
                default_route: ROUTE.into(),
                body_bytes: n(8192),
                request_timeout: Duration::from_secs(10),
                enabled: true,
            },
        )
        .map_err(|_| Failure::Setup)?;
        let realtime = RealtimeServerRuntime::new(Duration::from_secs(30), n(32))
            .map_err(|_| Failure::Setup)?;
        let realtime_router = broker_realtime_router(
            store.clone(),
            verifier.clone(),
            RealtimeHttpConfig {
                required_scopes: vec![required_scope.into()],
                grants_json_bytes: n(65536),
                inventory_json_bytes: n(65536),
                command_bytes: n(65536),
                outbound_bytes: n(65536),
                operation_timeout: Duration::from_secs(10),
            },
            &realtime,
        )
        .map_err(|_| Failure::Setup)?;
        let project_access = broker_project_authorization_router(
            store.clone(),
            verifier.clone(),
            BrokerProjectAuthorizationHttpConfig {
                required_scopes: vec![required_scope.into()],
                grants_json_bytes: n(65536),
                body_bytes: n(8192),
                request_timeout: Duration::from_secs(10),
            },
        )
        .map_err(|_| Failure::Setup)?;
        let (authentication, web) = match setup.web {
            Some(_) => {
                let (router, runtime) = WebRuntime::prepare(
                    store.clone(),
                    &mut control,
                    issuer,
                    verifier.clone(),
                    &origin,
                    &resource,
                    &setup,
                )
                .await?;
                (router, Some(runtime))
            }
            None => {
                let broker = json!({"version":"1","issuer":origin,"authentication":{"type":"oidc","issuer":origin,
            "client_id":CLIENT_ID,"scopes":SCOPE.split(' ').collect::<Vec<_>>(),"audiences":[API_AUDIENCE],
            "mcp_resources":[resource],"access_token_audience":API_AUDIENCE,"redirect_uri_path":REDIRECT}});
                // The existing Native warm-verification shape, with no login/refresh route implementation.
                let oidc = json!({"issuer":origin,"authorization_endpoint":format!("{origin}/authorize"),
            "token_endpoint":format!("{origin}/token"),"jwks_uri":format!("{origin}/jwks"),
            "grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],
            "token_endpoint_auth_methods_supported":["none"],"id_token_signing_alg_values_supported":["EdDSA"]});
                let keys = serde_json::to_value(issuer.jwks()).map_err(|_| Failure::Setup)?;
                let router = axum::Router::new()
                    .route(
                        "/.well-known/graphit-broker",
                        get(move || {
                            let v = broker.clone();
                            async move { Json(v) }
                        }),
                    )
                    .route(
                        "/.well-known/openid-configuration",
                        get(move || {
                            let v = oidc.clone();
                            async move { Json(v) }
                        }),
                    )
                    .route(
                        "/jwks",
                        get(move || {
                            let v = keys.clone();
                            async move { Json(v) }
                        }),
                    );
                (router, None)
            }
        };
        let sts_barrier = Arc::new(StsBarrier::default());
        let router = inventory
            .reset_fallback()
            .merge(hub)
            .reset_fallback()
            .merge(credentials)
            .reset_fallback()
            .merge(catalog)
            .merge(realtime_router)
            .reset_fallback()
            .merge(project_access)
            .merge(authentication)
            .merge(
                filesystem_http
                    .as_ref()
                    .map_or_else(axum::Router::new, FilesystemStorageHttp::router),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&sts_barrier),
                retain_sts_response,
            ));
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        phase("auth-end-ready");
        Ok(Self {
            postgres,
            control,
            store,
            minio,
            filesystem_directory,
            filesystem_http,
            storage_bucket,
            storage_endpoint,
            standalone_storage,
            standalone_publisher_storage,
            setup,
            origin,
            resource,
            prefix,
            bearer,
            expires_at,
            verifier,
            realtime,
            web,
            stop,
            server,
            sts_barrier,
        })
    }
    fn emit_ready(&self, output: &mut impl Write) -> Result<(), Failure> {
        self.verifier
            .verify(&self.bearer, &["fixture".into()], deadline())
            .map_err(|_| Failure::Setup)?;
        emit(
            output,
            &Ready {
                event: "ready",
                endpoint: &self.origin,
                issuer: &self.origin,
                api_audience: API_AUDIENCE,
                resource: &self.resource,
                client_id: CLIENT_ID,
                subject: SUBJECT,
                scope: SCOPE,
                redirect_uri_path: REDIRECT,
                expires_at: self.expires_at,
                access_bearer: &self.bearer,
                web: self.web.as_ref().map(WebRuntime::ready),
                web_second: self
                    .web
                    .as_ref()
                    .and_then(|web| web.second.as_ref())
                    .map(WebIdentity::ready),
                standalone_storage: self
                    .standalone_storage
                    .as_ref()
                    .zip(self.minio.as_ref())
                    .map(|(s, minio)| s.ready(minio)),
                standalone_publisher_storage: self
                    .standalone_publisher_storage
                    .as_ref()
                    .zip(self.minio.as_ref())
                    .map(|(s, minio)| s.ready(minio)),
                project_id: &self.setup.project_id,
                second_project_id: self.setup.second_project_id.as_deref(),
                bucket: &self.storage_bucket,
                region: REGION,
                storage_endpoint: &self.storage_endpoint,
                prefix: &self.prefix,
            },
        )
    }
    async fn shutdown(self) -> Result<(), Failure> {
        let Self {
            postgres,
            control,
            store,
            mut minio,
            filesystem_directory,
            filesystem_http,
            realtime,
            web,
            stop,
            mut server,
            sts_barrier,
            ..
        } = self;
        if let Some(web) = &web {
            web.local.stop_admission();
        }
        sts_barrier.release().await;
        let filesystem_closed = match &filesystem_http {
            Some(http) => http
                .shutdown(deadline())
                .await
                .map_err(|_| Failure::Shutdown),
            None => Ok(()),
        };
        let _ = stop.send(());
        phase("shutdown-now-begin");
        let realtime = realtime.shutdown().await.map_err(|_| Failure::Shutdown);
        phase("shutdown-now-end-http-begin");
        let served = match tokio::time::timeout(Duration::from_secs(3), &mut server).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(_) => Err(Failure::Shutdown),
            Err(_) => {
                server.abort();
                let _ = server.await;
                Err(Failure::Shutdown)
            }
        };
        let filesystem_joined = match &filesystem_http {
            Some(http) => http.join_closed().await.map_err(|_| Failure::Shutdown),
            None => Ok(()),
        };
        drop(filesystem_http);
        drop(filesystem_directory);
        if let Some(web) = &web {
            web.local.close().await;
        }
        phase("shutdown-http-end-sql-begin");
        let sql = store
            .shutdown(deadline())
            .await
            .map_err(|_| Failure::Shutdown);
        let connection = control.close().await.map_err(|_| Failure::Shutdown);
        drop(store);
        phase("shutdown-sql-end-postgres-begin");
        let pg = postgres.shutdown().map_err(|_| Failure::Shutdown);
        phase("shutdown-postgres-end-minio-begin");
        let s3 = match &mut minio {
            Some(minio) => minio.shutdown().map_err(|_| Failure::Shutdown),
            None => Ok(()),
        };
        phase("shutdown-minio-end");
        realtime
            .and(served)
            .and(sql)
            .and(connection)
            .and(pg)
            .and(s3)
            .and(filesystem_closed)
            .and(filesystem_joined)
    }
}
async fn run(input: &mut impl BufRead, output: &mut impl Write) -> Result<(), Failure> {
    let Some(command) = read_command(input)? else {
        return Ok(());
    };
    let setup = command.setup()?;
    let fixture = LiveFixture::start(setup).await?;
    let mut explicit_shutdown = false;
    let result = async {
        fixture.emit_ready(output)?;
        loop {
            let command = match read_command(input)? {
                Some(Command::HoldSts {}) => {
                    fixture.sts_barrier.hold().await?;
                    "hold_sts"
                }
                Some(Command::AwaitSts {}) => {
                    fixture.sts_barrier.await_entered().await?;
                    "await_sts"
                }
                Some(Command::ReleaseSts {}) => {
                    fixture.sts_barrier.release().await;
                    "release_sts"
                }
                Some(Command::Shutdown {}) => {
                    explicit_shutdown = true;
                    break;
                }
                Some(Command::Start { .. } | Command::StartWeb { .. }) => {
                    return Err(Failure::InvalidCommand);
                }
                None => break,
            };
            emit(output, &json!({"event":"ack","command":command,"ok":true}))?;
        }
        Ok(())
    }
    .await;
    let stopped = fixture.shutdown().await;
    result.and(stopped)?;
    if explicit_shutdown {
        emit(
            output,
            &json!({"event":"ack","command":"shutdown","ok":true}),
        )?;
    }
    Ok(())
}
#[tokio::main(worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    std::panic::set_hook(Box::new(|panic| {
        if !std::env::var_os("GRAPHIT_BROKER_FIXTURE_DIAGNOSTICS").is_some_and(|value| value == "1")
        {
            return;
        }
        if let Some(location) = panic.location() {
            let source = if location
                .file()
                .ends_with("broker-control/tests/support/mod.rs")
            {
                "crates/broker-control/tests/support/mod.rs"
            } else if location
                .file()
                .ends_with("broker-storage/tests/support_aws/mod.rs")
            {
                "crates/broker-storage/tests/support_aws/mod.rs"
            } else if location.file().ends_with("hub_storage_fixture.rs") {
                "crates/broker-presence/examples/hub_storage_fixture.rs"
            } else {
                "external-fixture-dependency"
            };
            eprintln!(
                "broker-hub-storage-fixture panic_source={source} line={} column={}",
                location.line(),
                location.column()
            );
        }
    }));
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    match AssertUnwindSafe(run(&mut input, &mut output))
        .catch_unwind()
        .await
    {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        Ok(Err(error)) => {
            eprintln!("{}", error.message());
            std::process::ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("Hub storage fixture failed");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use object_store::{
        ClientOptions, CopyMode, CopyOptions, ObjectStore, ObjectStoreExt, PutMode, PutOptions,
        aws::{AmazonS3, AmazonS3Builder, S3ConditionalPut, S3CopyIfNotExists},
        path::Path,
    };
    use serde_json::Value;
    use std::{io::Cursor, process::Stdio};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_tungstenite::{
        MaybeTlsStream, WebSocketStream, connect_async,
        tungstenite::{Error as WsError, Message, client::IntoClientRequest},
    };
    #[test]
    fn fixture_refinement_catalog_keys_match_sdk_full_id_layout() {
        assert_eq!(
            unpublish_catalog_prefixes(),
            [
                "v1/projects/{project}/registry/skill/Zml4dHVyZS93ZWItZmlsZS1yZWFkZXI.json",
                "v1/projects/{project}/registry/skill/Zml4dHVyZS93ZWItcHVibGljYXRpb24.json",
            ]
        );
    }
    #[tokio::test]
    async fn fixture_refinement_sts_rearms_without_overlapping_response_ownership() {
        let barrier = Arc::new(StsBarrier::default());
        for _ in 0..3 {
            assert!(barrier.hold().await.is_ok());
            assert!(matches!(barrier.hold().await, Err(Failure::InvalidCommand)));
            let owner = barrier.clone();
            let retained = tokio::spawn(async move { owner.retain().await });
            assert!(barrier.await_entered().await.is_ok());
            assert!(matches!(barrier.hold().await, Err(Failure::InvalidCommand)));
            barrier.release().await;
            assert!(matches!(barrier.hold().await, Err(Failure::InvalidCommand)));
            tokio::time::timeout(Duration::from_secs(5), retained)
                .await
                .unwrap()
                .unwrap();
        }
        assert!(barrier.hold().await.is_ok());
        barrier.release().await;
        assert!(barrier.hold().await.is_ok());
        let owner = barrier.clone();
        let cancelled = tokio::spawn(async move { owner.retain().await });
        assert!(barrier.await_entered().await.is_ok());
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert!(barrier.hold().await.is_ok());
        barrier.release().await;
        barrier.retain().await;
        assert!(barrier.hold().await.is_ok());
        barrier.release().await;
    }
    type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NowFrame {
        r#type: String,
        project_id: String,
        instances: Vec<NowInstance>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NowInstance {
        instance_id: String,
        version: String,
        now: broker_now_wire::NowSnapshotData,
    }
    const PROJECT: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
    const SECOND: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
    fn ok<T, E>(value: Result<T, E>, label: &str) -> T {
        match value {
            Ok(value) => value,
            Err(_) => panic!("{label}"),
        }
    }
    fn text<'a>(v: &'a Value, key: &str) -> &'a str {
        v[key].as_str().expect("required private wire string")
    }
    #[test]
    fn closed_commands_validate_canonical_distinct_projects_before_effects() {
        for value in [
            json!({"command":"start","project_id":PROJECT}),
            json!({"command":"start","project_id":PROJECT,"second_project_id":SECOND}),
        ] {
            let Some(Command::Start {
                project_id,
                second_project_id,
                ..
            }) = ok(
                read_command(&mut Cursor::new(value.to_string())),
                "start decode",
            )
            else {
                panic!("start required");
            };
            assert!(Setup::new(project_id, second_project_id).is_ok());
        }
        for raw in [
            "null".to_owned(),
            "[]".to_owned(),
            "[\"start\"]".to_owned(),
            json!({"command":"start"}).to_string(),
            json!({"command":"start","project_id":null}).to_string(),
            json!({"command":"start","project_id":PROJECT,"second_project_id":null}).to_string(),
            json!({"command":"start","project_id":PROJECT,"unknown":true}).to_string(),
            json!({"command":"shutdown","project_id":PROJECT}).to_string(),
            format!(r#"{{"command":"start","project_id":"{PROJECT}","project_id":"{SECOND}"}}"#),
            format!(r#"{{"command":"start","command":"shutdown","project_id":"{PROJECT}"}}"#),
        ] {
            assert!(
                read_command(&mut Cursor::new(raw)).is_err(),
                "closed JSON object command required"
            );
        }
        for id in [
            "",
            "project",
            " 01D39ZY06FGSCTVN4T2V9PKHFZ",
            "01d39zy06fgsctvn4t2v9pkhfz",
        ] {
            assert!(Setup::new(id.into(), None).is_err());
            assert!(Setup::new(PROJECT.into(), Some(id.into())).is_err());
        }
        assert!(Setup::new(PROJECT.into(), Some(PROJECT.into())).is_err());
    }
    #[tokio::test]
    async fn eof_is_silent_and_shutdown_cannot_precede_start() {
        let mut out = Vec::new();
        assert!(run(&mut Cursor::new(""), &mut out).await.is_ok());
        assert!(out.is_empty());
        assert!(
            run(&mut Cursor::new("{\"command\":\"shutdown\"}\n"), &mut out)
                .await
                .is_err()
        );
        assert!(out.is_empty());
    }
    fn objects(keys: &Value) -> AmazonS3 {
        let builder = AmazonS3Builder::new()
            .with_bucket_name(text(keys, "bucket"))
            .with_region(text(keys, "region"))
            .with_endpoint(text(keys, "endpoint"))
            .with_virtual_hosted_style_request(false)
            .with_access_key_id(text(keys, "access_key_id"))
            .with_secret_access_key(text(keys, "secret_access_key"));
        let builder = match keys["session_token"].as_str() {
            Some(token) => builder.with_token(token),
            None => builder,
        };
        ok(
            builder
                .with_conditional_put(S3ConditionalPut::ETagMatch)
                .with_copy_if_not_exists(S3CopyIfNotExists::Multipart)
                .with_client_options(
                    ClientOptions::new()
                        .with_allow_http(true)
                        .with_timeout(Duration::from_secs(5))
                        .with_connect_timeout(Duration::from_secs(2)),
                )
                .with_retry(object_store::RetryConfig {
                    max_retries: 0,
                    retry_timeout: Duration::from_secs(5),
                    ..Default::default()
                })
                .build(),
            "real HTTP-issued S3 client",
        )
    }
    fn denied<T>(value: object_store::Result<T>) {
        match value {
            Err(object_store::Error::PermissionDenied { .. }) => {}
            Err(object_store::Error::Generic { source, .. }) => {
                let reason = Zeroizing::new(source.to_string());
                assert!(
                    reason.contains("403 Forbidden") || reason.ends_with("(code: AccessDenied)"),
                    "actual S3 authorization denial required"
                );
            }
            _ => panic!("actual S3 authorization denial required"),
        }
    }
    async fn http(
        ready: &Value,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (hyper::StatusCode, hyper::HeaderMap, Value) {
        use http_body_util::{BodyExt, Full};
        use hyper_util::rt::TokioIo;
        let address: std::net::SocketAddr = ok(
            text(ready, "endpoint")
                .strip_prefix("http://")
                .expect("owned loopback origin")
                .parse(),
            "owned address",
        );
        let stream = ok(tokio::net::TcpStream::connect(address).await, "owned TCP");
        let (mut sender, connection) = ok(
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await,
            "HTTP handshake",
        );
        let worker = tokio::spawn(connection);
        let bearer = Zeroizing::new(format!("Bearer {}", text(ready, "access_bearer")));
        let mut authorization = ok(
            hyper::header::HeaderValue::from_str(&bearer),
            "private Authorization header",
        );
        authorization.set_sensitive(true);
        let body = body.map(|value| value.to_string()).unwrap_or_default();
        let request = ok(
            hyper::Request::builder()
                .method(method)
                .uri(path)
                .header("host", address.to_string())
                .header("authorization", authorization)
                .header("content-type", "application/json")
                .body(Full::new(axum::body::Bytes::from(body))),
            "HTTP request",
        );
        let response = ok(
            ok(
                tokio::time::timeout(Duration::from_secs(12), sender.send_request(request)).await,
                "HTTP response guard",
            ),
            "HTTP response",
        );
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = ok(response.into_body().collect().await, "HTTP body").to_bytes();
        let value = ok(serde_json::from_slice(&bytes), "private response JSON");
        drop(sender);
        ok(
            ok(
                ok(
                    tokio::time::timeout(Duration::from_secs(3), worker).await,
                    "HTTP driver guard",
                ),
                "HTTP driver join",
            ),
            "HTTP driver result",
        );
        (status, headers, value)
    }
    async fn exercise_inventory(ready: &Value) {
        let mut projects = vec![json!({"project_id":PROJECT,"versions":["feature","main"]})];
        let has_second = ready.get("second_project_id").is_some();
        if has_second {
            projects.push(json!({"project_id":SECOND,"versions":["sibling"]}));
        }
        let path = "/v1/instances/hub-station/inventory";
        let payload = json!({"projects":projects});
        let (status, _, published) = http(ready, "PUT", path, Some(payload.clone())).await;
        assert_eq!(status, 201);
        assert_eq!(published["change"], "created");
        let (status, _, inventory) = http(ready, "GET", path, None).await;
        assert_eq!(status, 200);
        assert_eq!(inventory["instance_id"], "hub-station");
        assert_eq!(inventory["projects"], json!(projects));
        let (status, _, repeated) = http(ready, "PUT", path, Some(payload)).await;
        assert_eq!(status, 200);
        assert_eq!(repeated["change"], "unchanged");
        let denied_project = if has_second {
            "01D39ZY06FGSCTVN4T2V9PKHG1"
        } else {
            SECOND
        };
        let (status, _, _) = http(
            ready,
            "PUT",
            path,
            Some(json!({"projects":[{"project_id":denied_project,"versions":["main"]}]})),
        )
        .await;
        assert_eq!(status, 403, "ungranted inventory project is denied");
        let (status, _, inventory) = http(ready, "GET", path, None).await;
        assert_eq!(status, 200);
        assert_eq!(
            inventory["projects"],
            json!(projects),
            "denied publication preserves inventory"
        );
    }
    async fn websocket(ready: &Value, authenticated: bool) -> Result<Socket, WsError> {
        let endpoint = text(ready, "endpoint").replacen("http://", "ws://", 1);
        let mut request = ok(
            format!("{endpoint}/v1/realtime").into_client_request(),
            "Now WebSocket request",
        );
        if authenticated {
            let mut authorization = ok(
                format!("Bearer {}", text(ready, "access_bearer"))
                    .parse::<axum::http::HeaderValue>(),
                "private Now bearer",
            );
            authorization.set_sensitive(true);
            request.headers_mut().insert("authorization", authorization);
        }
        let (socket, response) = ok(
            tokio::time::timeout(Duration::from_secs(10), connect_async(request)).await,
            "Now upgrade guard",
        )?;
        assert_eq!(response.status().as_u16(), 101);
        Ok(socket)
    }
    async fn now_send(socket: &mut Socket, value: Value) {
        ok(
            socket.send(Message::Text(value.to_string().into())).await,
            "Now command",
        );
    }
    async fn now_receive(socket: &mut Socket) -> Value {
        ok(
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match socket.next().await {
                        Some(Ok(Message::Text(text))) => {
                            return ok(serde_json::from_str(&text), "Now JSON frame");
                        }
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                        _ => panic!("Now connection closed before frame"),
                    }
                }
            })
            .await,
            "Now frame guard",
        )
    }
    fn now_data(project: &str, generated_at: &str) -> Value {
        let actor = "a".repeat(64);
        let available = |items: Value| json!({"availability":"available","total":items.as_array().unwrap().len(),"items":items,"has_more":false,"error":null});
        let wire = json!({"project_id":project,"generated_at":generated_at,"sections":{
            "tasks":available(json!([{"id":PROJECT,"session_id":SECOND,"title":"Task","owner":actor,"lease_expires_at":"2000000","updated_at":"1000000"}])),
            "sessions":available(json!([{"id":SECOND,"title":"Session","owner":actor,"lease_expires_at":"2000000","updated_at":"1000000","completed_tasks":1,"total_tasks":2}])),
            "memories":available(json!([{"id":PROJECT,"title":"Memory","updated_by":actor,"updated_at":"1000000"}])),
            "knowledge":available(json!([{"slug":"known","title":"Knowledge","updated_at":null}]))
        }});
        let bytes = ok(serde_json::to_vec(&wire), "Now DATA bytes");
        let data = ok(
            broker_now_wire::NowSnapshotData::decode(&bytes, n(bytes.len())),
            "actual Now DATA contract",
        );
        ok(serde_json::to_value(data), "Now DATA serialization")
    }
    #[test]
    fn fixture_update_marker_must_precede_active_leases() {
        for marker in ["1000000", "1000001"] {
            let data: broker_now_wire::NowSnapshotData = ok(
                serde_json::from_value(now_data(PROJECT, marker)),
                "valid fixture update DATA",
            );
            assert_eq!(data.generated_at(), marker);
        }
        let mut expired = now_data(PROJECT, "1000000");
        expired["generated_at"] = json!("2000000");
        assert!(serde_json::from_value::<broker_now_wire::NowSnapshotData>(expired).is_err());
    }
    async fn exercise_now(ready: &Value) -> Vec<Socket> {
        match websocket(ready, false).await {
            Err(WsError::Http(response)) => assert_eq!(response.status().as_u16(), 401),
            _ => panic!("Now upgrade without bearer must be unauthorized"),
        }
        let mut sockets = Vec::new();
        for (project, version) in [(PROJECT, "main"), (SECOND, "sibling")] {
            if project == SECOND && ready.get("second_project_id").is_none() {
                continue;
            }
            let mut publisher = ok(websocket(ready, true).await, "real Now publisher upgrade");
            now_send(&mut publisher, json!({"op":"publish","instance_id":"hub-station","project_id":project,"version":version,"snapshot":now_data(project, "1000000")})).await;
            let welcome = now_receive(&mut publisher).await;
            assert_eq!(welcome["type"], "welcome");
            assert_eq!(welcome.as_object().unwrap().len(), 2);
            let mut subscriber = ok(websocket(ready, true).await, "real Now subscriber upgrade");
            now_send(
                &mut subscriber,
                json!({"op":"subscribe","project_id":project}),
            )
            .await;
            assert_eq!(now_receive(&mut subscriber).await["type"], "welcome");
            let snapshot = now_receive(&mut subscriber).await;
            assert_eq!(snapshot["type"], "snapshot");
            assert_eq!(snapshot["project_id"], project);
            let instances = snapshot["instances"].as_array().unwrap();
            assert_eq!(instances.len(), 1);
            assert_eq!(instances[0]["instance_id"], "hub-station");
            assert_eq!(instances[0]["version"], version);
            assert_eq!(instances[0]["now"]["project_id"], project);
            for name in ["tasks", "sessions", "memories", "knowledge"] {
                assert_eq!(
                    instances[0]["now"]["sections"][name],
                    json!({"availability":"failed","items":[],"total":null,"has_more":null,"error":"forbidden"}),
                    "Presence grants do not grant domain reads"
                );
            }
            sockets.push(publisher);
            sockets.push(subscriber);
        }
        let mut denied = ok(websocket(ready, true).await, "Now denied-project upgrade");
        now_send(
            &mut denied,
            json!({"op":"subscribe","project_id":"01D39ZY06FGSCTVN4T2V9PKHG1"}),
        )
        .await;
        assert_eq!(
            now_receive(&mut denied).await,
            json!({"type":"error","code":"forbidden"})
        );
        ok(denied.close(None).await, "denied Now socket close");
        sockets
    }
    async fn now_stopped(socket: &mut Socket) {
        ok(
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match socket.next().await {
                        None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                        Some(Ok(_)) => {}
                    }
                }
            })
            .await,
            "Now connection joined before Shutdown Ack",
        );
    }
    async fn exercise_invalid_now_update(ready: &Value) {
        let mut publisher = ok(
            websocket(ready, true).await,
            "invalid DATA publisher upgrade",
        );
        now_send(&mut publisher, json!({"op":"publish","instance_id":"hub-station","project_id":PROJECT,"version":"feature","snapshot":now_data(PROJECT, "1000000")})).await;
        assert_eq!(now_receive(&mut publisher).await["type"], "welcome");
        let mut subscriber = ok(
            websocket(ready, true).await,
            "invalid DATA observer upgrade",
        );
        now_send(&mut subscriber, json!({"op":"subscribe","project_id":PROJECT,"instance_id":"hub-station","version":"feature"})).await;
        assert_eq!(now_receive(&mut subscriber).await["type"], "welcome");
        let initial: NowFrame = ok(
            serde_json::from_value(now_receive(&mut subscriber).await),
            "typed initial feature frame",
        );
        assert_eq!(initial.instances.len(), 1);
        assert_eq!(initial.instances[0].version, "feature");
        let mut expired = now_data(PROJECT, "1000000");
        expired["generated_at"] = json!("2000000");
        assert!(
            serde_json::from_value::<broker_now_wire::NowSnapshotData>(expired.clone()).is_err()
        );
        now_send(&mut publisher, json!({"op":"publish","instance_id":"hub-station","project_id":PROJECT,"version":"feature","snapshot":expired})).await;
        assert_eq!(
            now_receive(&mut publisher).await,
            json!({"type":"error","code":"invalid_data"})
        );
        ok(
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match publisher.next().await {
                        Some(Ok(Message::Close(Some(frame)))) => {
                            assert_eq!(u16::from(frame.code), 1008);
                            break;
                        }
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                        _ => panic!("invalid DATA publisher must close with 1008"),
                    }
                }
            })
            .await,
            "invalid DATA close guard",
        );
        ok(
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let frame: NowFrame = ok(
                        serde_json::from_value(now_receive(&mut subscriber).await),
                        "typed withdrawn feature frame",
                    );
                    assert_eq!(frame.r#type, "snapshot");
                    assert_eq!(frame.project_id, PROJECT);
                    if frame.instances.is_empty() {
                        break;
                    }
                }
            })
            .await,
            "invalid DATA removes its slot",
        );
        ok(subscriber.close(None).await, "invalid DATA observer close");
        eprintln!(
            "broker-hub-storage-contract invalid generated_at=lease rejected by SDK and WS invalid_data/1008; feature slot withdrawn"
        );
    }
    async fn now_updated(sockets: &mut [Socket]) {
        assert!(matches!(sockets.len(), 2 | 4));
        for (index, pair) in sockets.chunks_exact_mut(2).enumerate() {
            let (project, version) = if index == 0 {
                (PROJECT, "main")
            } else {
                (SECOND, "sibling")
            };
            let (publisher, subscriber) = pair.split_at_mut(1);
            let snapshot = now_data(project, "1000001");
            now_send(&mut publisher[0], json!({"op":"publish","instance_id":"hub-station","project_id":project,"version":version,"snapshot":snapshot})).await;
            let mut observed = Vec::new();
            let update = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let frame: NowFrame = ok(
                        serde_json::from_value(now_receive(&mut subscriber[0]).await),
                        "typed Now update frame",
                    );
                    assert_eq!(frame.r#type, "snapshot");
                    assert_eq!(frame.project_id, project);
                    let marker = frame
                        .instances
                        .iter()
                        .find(|instance| {
                            instance.instance_id == "hub-station" && instance.version == version
                        })
                        .map(|instance| {
                            assert_eq!(instance.now.project_id(), project);
                            instance.now.generated_at().to_owned()
                        });
                    let updated = marker.as_deref() == Some("1000001");
                    observed.push((frame.instances.len(), marker));
                    if updated {
                        break;
                    }
                }
            })
            .await;
            // Only generated fixture DTO counts/timestamps, never Ready or headers.
            eprintln!(
                "broker-hub-storage-contract Now update project-index={index} observed={observed:?}"
            );
            ok(update, "Now update marker guard");
        }
    }
    async fn now_active(sockets: &mut [Socket]) {
        assert!(matches!(sockets.len(), 2 | 4));
        for (index, socket) in sockets.iter_mut().enumerate() {
            let marker = format!("fixture-shutdown-{index}").into_bytes();
            ok(
                socket.send(Message::Ping(marker.clone().into())).await,
                "live Now control Ping",
            );
            ok(
                tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        match socket.next().await {
                            Some(Ok(Message::Pong(payload))) if payload.as_ref() == marker => break,
                            Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_))) => {}
                            _ => panic!("Now connection closed before control Pong"),
                        }
                    }
                })
                .await,
                "live Now control Pong guard",
            );
        }
    }
    async fn credentials(ready: &Value) -> Value {
        let keys_path = if ready.get("web").is_some() {
            "/v1/oidc/keys"
        } else {
            "/jwks"
        };
        for endpoint in [
            "/.well-known/graphit-broker",
            "/.well-known/openid-configuration",
            keys_path,
        ] {
            assert_eq!(http(ready, "GET", endpoint, None).await.0, 200);
        }
        let (status, _, resolved) = http(ready, "POST", "/v1/hub/access/resolve", None).await;
        assert_eq!(status, 200);
        let resolved = resolved.to_string();
        assert!(
            resolved.contains(PROJECT) && !resolved.contains(SECOND),
            "only granted producer is visible"
        );
        let (status, headers, keys) = http(
            ready,
            "POST",
            "/v1/s3/credentials",
            Some(json!({"scope":"project","project_id":PROJECT,"module":"hub"})),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(keys["scope"], "project");
        assert_eq!(keys["project_id"], PROJECT);
        assert_eq!(keys["module"], "hub");
        assert_eq!(keys["prefixes"], json!([text(ready, "prefix")]));
        assert!(
            text(&keys, "authorization_revision")
                .parse::<u64>()
                .is_ok_and(|v| v > 0)
        );
        assert!(chrono::DateTime::parse_from_rfc3339(text(&keys, "expires_at")).is_ok());
        let (denied_status, _, _) = http(
            ready,
            "POST",
            "/v1/s3/credentials",
            Some(json!({"scope":"project","project_id":SECOND,"module":"hub"})),
        )
        .await;
        assert_eq!(
            denied_status, 403,
            "wrong producer is denied before S3 issuance"
        );
        keys
    }
    async fn exercise(ready: &Value) {
        let keys = credentials(ready).await;
        let s3 = objects(&keys);
        let base = text(ready, "prefix");
        let registry = Path::from(format!(
            "{base}/v1/projects/{PROJECT}/registry/ast/fixture.json"
        ));
        let first = ok(
            s3.put_opts(
                &registry,
                "first".into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await,
            "catalog Create",
        );
        assert!(matches!(
            s3.put_opts(
                &registry,
                "duplicate".into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                }
            )
            .await,
            Err(object_store::Error::AlreadyExists { .. })
        ));
        let version = object_store::UpdateVersion::from(first);
        ok(
            s3.put_opts(
                &registry,
                "updated".into(),
                PutOptions {
                    mode: PutMode::Update(version.clone()),
                    ..Default::default()
                },
            )
            .await,
            "catalog CAS",
        );
        assert!(matches!(
            s3.put_opts(
                &registry,
                "stale".into(),
                PutOptions {
                    mode: PutMode::Update(version),
                    ..Default::default()
                }
            )
            .await,
            Err(object_store::Error::Precondition { .. })
        ));
        let stage = Path::from(format!(
            "{base}/v1/projects/{PROJECT}/artifacts/staging/native-upload-fixture"
        ));
        let final_path = Path::from(format!(
            "{base}/v1/projects/{PROJECT}/artifacts/ast/id/version/digest/payload"
        ));
        let mut multipart = ok(s3.put_multipart(&stage).await, "staging multipart initiate");
        ok(
            multipart.put_part(vec![42u8; 5 * 1024 * 1024].into()).await,
            "multipart part one",
        );
        ok(
            multipart.put_part(vec![43u8; 1024].into()).await,
            "multipart part two",
        );
        ok(multipart.complete().await, "multipart complete");
        ok(
            s3.copy_opts(
                &stage,
                &final_path,
                CopyOptions {
                    mode: CopyMode::Create,
                    ..Default::default()
                },
            )
            .await,
            "conditional multipart-copy Create",
        );
        assert!(matches!(
            s3.copy_opts(
                &stage,
                &final_path,
                CopyOptions {
                    mode: CopyMode::Create,
                    ..Default::default()
                }
            )
            .await,
            Err(object_store::Error::AlreadyExists { .. })
        ));
        assert_eq!(
            ok(s3.head(&final_path).await, "reader HEAD").size,
            5 * 1024 * 1024 + 1024
        );
        assert_eq!(
            ok(s3.get_range(&final_path, 0..4).await, "reader range").as_ref(),
            &[42u8; 4]
        );
        let payload = ok(
            ok(s3.get(&final_path).await, "reader GET").bytes().await,
            "reader body",
        );
        assert_eq!(payload.len(), 5 * 1024 * 1024 + 1024);
        let empty = Path::from(format!(
            "{base}/v1/projects/{PROJECT}/artifacts/knowledge/id/version/digest/empty"
        ));
        ok(
            s3.put_opts(
                &empty,
                Vec::new().into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await,
            "empty immutable file Create",
        );
        denied(s3.delete(&final_path).await);
        denied(s3.delete(&registry).await);
        ok(s3.delete(&stage).await, "delete only owned staging");
        assert!(matches!(
            s3.head(&stage).await,
            Err(object_store::Error::NotFound { .. })
        ));
        let aborted = Path::from(format!(
            "{base}/v1/projects/{PROJECT}/artifacts/staging/native-upload-abort"
        ));
        let mut multipart = ok(s3.put_multipart(&aborted).await, "abort initiate");
        ok(
            multipart.put_part(vec![44u8; 5 * 1024 * 1024].into()).await,
            "abort part",
        );
        ok(multipart.abort().await, "actual multipart abort");
        denied(
            s3.put(
                &Path::from(format!("{base}/v1/projects/{SECOND}/artifacts/escape")),
                "denied".into(),
            )
            .await,
        );
        // This consumer never invokes LIST. The unchanged 6488 policy includes scoped ListBucket.
    }

    #[test]
    fn closed_web_commands_require_explicit_product_validated_lifetimes() {
        let valid = json!({"command":"start_web","project_id":PROJECT,
            "authorization_ttl_seconds":60,"local_challenge_ttl_seconds":600,"access_ttl_seconds":600,"refresh_ttl_seconds":3600});
        assert!(
            ok(
                read_command(&mut Cursor::new(valid.to_string())),
                "Web command"
            )
            .unwrap()
            .setup()
            .is_ok()
        );
        let omitted: Command = ok(serde_json::from_value(valid.clone()), "Web write omitted");
        assert!(
            !ok(omitted.setup(), "Web write default")
                .web
                .unwrap()
                .hub_storage_write
        );
        for enabled in [false, true] {
            let mut value = valid.clone();
            value["hub_storage_write"] = json!(enabled);
            let command: Command = ok(serde_json::from_value(value), "closed Web storage write");
            assert_eq!(
                ok(command.setup(), "Web storage write setup")
                    .web
                    .unwrap()
                    .hub_storage_write,
                enabled
            );
        }
        for invalid in [Value::Null, json!("true"), json!(1), json!({})] {
            let mut value = valid.clone();
            value["hub_storage_write"] = invalid;
            assert!(serde_json::from_value::<Command>(value).is_err());
        }
        assert!(
            serde_json::from_value::<Command>(
                json!({"command":"start", "project_id":PROJECT, "hub_storage_write":true})
            )
            .is_err()
        );
        assert!(serde_json::from_str::<Command>(r#"{"command":"start_web","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","hub_storage_write":true,"hub_storage_write":false,"authorization_ttl_seconds":60,"local_challenge_ttl_seconds":600,"access_ttl_seconds":600,"refresh_ttl_seconds":3600}"#).is_err());
        for field in [
            "authorization_ttl_seconds",
            "local_challenge_ttl_seconds",
            "access_ttl_seconds",
            "refresh_ttl_seconds",
        ] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(read_command(&mut Cursor::new(missing.to_string())).is_err());
            let mut null = valid.clone();
            null[field] = Value::Null;
            assert!(read_command(&mut Cursor::new(null.to_string())).is_err());
            let mut zero = valid.clone();
            zero[field] = json!(0);
            assert!(
                ok(
                    read_command(&mut Cursor::new(zero.to_string())),
                    "decode zero"
                )
                .unwrap()
                .setup()
                .is_err()
            );
        }
        for (field, number) in [
            ("authorization_ttl_seconds", 29),
            ("authorization_ttl_seconds", 601),
            ("local_challenge_ttl_seconds", 119),
            ("local_challenge_ttl_seconds", 1801),
            ("access_ttl_seconds", 59),
            ("access_ttl_seconds", 3601),
            ("refresh_ttl_seconds", 599),
            ("refresh_ttl_seconds", 90 * 86400 + 1),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = json!(number);
            assert!(
                ok(
                    read_command(&mut Cursor::new(invalid.to_string())),
                    "decode invalid lifetime"
                )
                .unwrap()
                .setup()
                .is_err()
            );
        }
        for (field, value) in [("second_project_id", Value::Null), ("unknown", json!(true))] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(read_command(&mut Cursor::new(invalid.to_string())).is_err());
        }
    }
    fn form(fields: &[(&str, &str)]) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish()
    }
    async fn web_http(
        ready: &Value,
        method: &str,
        path: &str,
        content_type: &str,
        body: &str,
    ) -> (hyper::StatusCode, hyper::HeaderMap, Zeroizing<String>) {
        use http_body_util::{BodyExt, Full};
        use hyper_util::rt::TokioIo;
        let address: std::net::SocketAddr = ok(
            text(ready, "endpoint")
                .strip_prefix("http://")
                .unwrap()
                .parse(),
            "owned Web address",
        );
        let stream = ok(tokio::net::TcpStream::connect(address).await, "Web TCP");
        let (mut sender, connection) = ok(
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await,
            "Web handshake",
        );
        let worker = tokio::spawn(connection);
        let request = ok(
            hyper::Request::builder()
                .method(method)
                .uri(path)
                .header("host", address.to_string())
                .header("content-type", content_type)
                .body(Full::new(axum::body::Bytes::copy_from_slice(
                    body.as_bytes(),
                ))),
            "Web request",
        );
        let response = ok(
            ok(
                tokio::time::timeout(Duration::from_secs(12), sender.send_request(request)).await,
                "Web response guard",
            ),
            "Web response",
        );
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = ok(response.into_body().collect().await, "Web body").to_bytes();
        let body = Zeroizing::new(ok(String::from_utf8(bytes.to_vec()), "Web UTF8"));
        drop(sender);
        ok(
            ok(
                ok(
                    tokio::time::timeout(Duration::from_secs(3), worker).await,
                    "Web driver guard",
                ),
                "Web driver join",
            ),
            "Web driver",
        );
        (status, headers, body)
    }
    fn json_body(body: &str) -> Value {
        ok(serde_json::from_str(body), "private Web JSON")
    }
    async fn token_form(ready: &Value, fields: &[(&str, &str)]) -> (hyper::StatusCode, Value) {
        let encoded = Zeroizing::new(form(fields));
        let (status, headers, body) = web_http(
            ready,
            "POST",
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &encoded,
        )
        .await;
        assert_eq!(headers["cache-control"], "no-store");
        (status, json_body(&body))
    }
    fn verify_web_jwt(
        keys: &jsonwebtoken::jwk::JwkSet,
        raw: &str,
        issuer: &str,
        audience: &str,
    ) -> Value {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
        let header = ok(decode_header(raw), "Web JWT header");
        assert_eq!(header.alg, Algorithm::EdDSA);
        let key = keys
            .find(header.kid.as_deref().expect("Web key ID"))
            .expect("actual advertised Web signing key");
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        ok(
            decode::<Value>(
                raw,
                &ok(DecodingKey::from_jwk(key), "Web decoding key"),
                &validation,
            ),
            "verified real Web JWT",
        )
        .claims
    }
    async fn exercise_web(ready: &Value) {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let (status, _, body) = web_http(
            ready,
            "GET",
            "/.well-known/graphit-broker",
            "application/json",
            "",
        )
        .await;
        assert_eq!(status, 200);
        let graphit = json_body(&body);
        assert_eq!(graphit["issuer"], ready["issuer"]);
        assert_eq!(
            graphit["authentication"]["mcp_resources"],
            json!([text(ready, "resource")])
        );
        assert_eq!(
            graphit["authentication"]["scopes"],
            json!(["openid", "profile", "email", "offline_access"])
        );
        let (status, _, body) = web_http(
            ready,
            "GET",
            "/.well-known/openid-configuration",
            "application/json",
            "",
        )
        .await;
        assert_eq!(status, 200);
        let discovery = json_body(&body);
        for (field, path) in [
            ("authorization_endpoint", "/oauth/authorize"),
            ("token_endpoint", "/oauth/token"),
            ("registration_endpoint", "/oauth/register"),
            ("jwks_uri", "/v1/oidc/keys"),
        ] {
            assert!(
                text(&discovery, field) == format!("{}{path}", text(ready, "issuer")),
                "canonical discovery endpoint"
            );
        }
        let (status, _, body) =
            web_http(ready, "GET", "/v1/oidc/keys", "application/json", "").await;
        assert_eq!(status, 200);
        let keys: jsonwebtoken::jwk::JwkSet = ok(serde_json::from_str(&body), "real Web JWKS");
        let redirect = "http://127.0.0.1:49158/web-callback";
        let registration = json!({"redirect_uris":[redirect],"token_endpoint_auth_method":"none","client_name":"Hub Web reader"});
        let (status, _, body) = web_http(
            ready,
            "POST",
            "/oauth/register",
            "application/json",
            &registration.to_string(),
        )
        .await;
        assert_eq!(status, 201);
        let registered = json_body(&body);
        let client = text(&registered, "client_id");
        let verifier = private_random().expect("private PKCE entropy");
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let state = "fixture Web state café +%";
        let nonce = "fixture Web nonce";
        let fields = [
            ("client_id", client),
            ("redirect_uri", redirect),
            ("response_type", "code"),
            ("scope", WEB_SCOPE),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("resource", text(ready, "resource")),
        ];
        let path = format!("/oauth/authorize?{}", form(&fields));
        let (status, headers, _) =
            web_http(ready, "GET", &path, "application/x-www-form-urlencoded", "").await;
        assert_eq!(status, 303);
        let login = headers["location"].to_str().unwrap().to_owned();
        let (status, _, body) = web_http(
            ready,
            "GET",
            &login,
            "application/x-www-form-urlencoded",
            "",
        )
        .await;
        assert_eq!(status, 200);
        assert!(
            body.contains("<form"),
            "productive browser login representation"
        );
        let request_id = form_urlencoded::parse(login.split_once('?').unwrap().1.as_bytes())
            .find(|(name, _)| name == "id")
            .unwrap()
            .1
            .into_owned();
        let web_identity = &ready["web"];
        let login_form = Zeroizing::new(form(&[
            ("login_method", "local"),
            ("username", text(web_identity, "username")),
            ("password", text(web_identity, "password")),
        ]));
        let (status, headers, _) = web_http(
            ready,
            "POST",
            &format!("/oauth/login?{}", form(&[("id", &request_id)])),
            "application/x-www-form-urlencoded",
            &login_form,
        )
        .await;
        assert_eq!(status, 303);
        let callback = headers["location"].to_str().unwrap();
        assert!(
            callback.starts_with(redirect),
            "registered callback literal"
        );
        let params: std::collections::BTreeMap<_, _> =
            form_urlencoded::parse(callback.split_once('?').unwrap().1.as_bytes())
                .into_owned()
                .collect();
        assert!(
            params.get("state").is_some_and(|v| v == state),
            "preserved actual state"
        );
        let code = Zeroizing::new(params.get("code").expect("actual authorized code").clone());
        let (status, tokens) = token_form(
            ready,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", client),
                ("code", &code),
                ("redirect_uri", redirect),
                ("code_verifier", &verifier),
                ("resource", text(ready, "resource")),
            ],
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(tokens["scope"], WEB_SCOPE);
        let access = verify_web_jwt(
            &keys,
            text(&tokens, "access_token"),
            text(ready, "issuer"),
            API_AUDIENCE,
        );
        assert!(
            access["sub"] == web_identity["subject"] && access["sub"] != SUBJECT,
            "distinct canonical LOCAL subject"
        );
        assert_eq!(access["client_id"], client);
        let audiences = access["aud"].as_array().expect("explicit access audiences");
        assert!(audiences.contains(&json!(API_AUDIENCE)) && audiences.contains(&ready["resource"]));
        let id = verify_web_jwt(
            &keys,
            text(&tokens, "id_token"),
            text(ready, "issuer"),
            client,
        );
        assert_eq!(id["nonce"], nonce);
        assert!(id["sub"] == web_identity["subject"]);
        let (status, refreshed) = token_form(
            ready,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", client),
                ("refresh_token", text(&tokens, "refresh_token")),
                ("resource", text(ready, "resource")),
            ],
        )
        .await;
        assert_eq!(status, 200);
        assert!(
            refreshed["refresh_token"] != tokens["refresh_token"],
            "opaque refresh rotated"
        );
        let access = verify_web_jwt(
            &keys,
            text(&refreshed, "access_token"),
            text(ready, "issuer"),
            API_AUDIENCE,
        );
        assert!(access["sub"] == web_identity["subject"]);
        let id = verify_web_jwt(
            &keys,
            text(&refreshed, "id_token"),
            text(ready, "issuer"),
            client,
        );
        assert!(id["sub"] == web_identity["subject"]);
        let (status, replay) = token_form(
            ready,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", client),
                ("refresh_token", text(&tokens, "refresh_token")),
                ("resource", text(ready, "resource")),
            ],
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(replay["error"], "invalid_grant");
        // Reuse the real STSv3 transport helper with the refreshed Web access token.
        let mut web = ready.clone();
        web["access_bearer"] = refreshed["access_token"].clone();
        let native_keys = credentials(ready).await;
        let native = objects(&native_keys);
        let path = Path::from(format!(
            "{}/v1/projects/{PROJECT}/artifacts/ast/web-reader/payload",
            text(ready, "prefix")
        ));
        ok(
            native
                .put(&path, "actual Native publisher bytes".into())
                .await,
            "Native publish for distinct Web reader",
        );
        let web_keys = credentials(&web).await;
        let reader = objects(&web_keys);
        let bytes = ok(
            ok(reader.get(&path).await, "Web S3 read").bytes().await,
            "Web S3 body",
        );
        assert_eq!(bytes.as_ref(), b"actual Native publisher bytes");
        denied(reader.put(&path, "denied Web write".into()).await);
        denied(reader.delete(&path).await);
        // Own-GET returns NotFound before capability checks when no inventory exists.
        // Use actual protected publication/subscription to prove the missing grants.
        assert_eq!(
            http(
                &web,
                "PUT",
                "/v1/instances/web-reader/inventory",
                Some(json!({"projects":[{"project_id":PROJECT,"versions":["main"]}]}))
            )
            .await
            .0,
            403,
            "HubRead does not grant Presence publication"
        );
        let mut denied_presence = ok(websocket(&web, true).await, "real Web Now upgrade");
        now_send(
            &mut denied_presence,
            json!({"op":"subscribe","project_id":PROJECT}),
        )
        .await;
        assert_eq!(
            now_receive(&mut denied_presence).await,
            json!({"type":"error","code":"forbidden"}),
            "HubRead does not grant Presence subscription"
        );
        ok(
            denied_presence.close(None).await,
            "denied Web Now socket close",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "normal process IPC, real PostgreSQL TLS, Native JWT and upstream MinIO STSv3/S3"]
    async fn hub_storage_fixture_native_sts_contract() {
        process_contract(true, false).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "causal Native inventory composition, real PostgreSQL TLS and STSv3 admission"]
    async fn hub_storage_fixture_native_inventory_contract() {
        process_contract(false, false).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "normal process, TLS PostgreSQL, genuine LOCAL/DCR/OAuth refresh, separate Native/Web Hub grants and MinIO STSv3/S3"]
    async fn hub_storage_fixture_web_oidc_contract() {
        process_contract(false, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "owned MinIO accesskey setup and expiry; no PostgreSQL required"]
    async fn standalone_minio_accesskey_setup() {
        let mut minio = Minio::start().await;
        let observed = AssertUnwindSafe(async {
            let storage = ok(
                StandaloneStorage::create(&minio, PROJECT, false, false),
                "restricted Standalone accesskey setup",
            );
            assert_eq!(storage.prefix, format!("standalone/{PROJECT}"));
            let wire = ok(
                serde_json::to_value(storage.ready(&minio)),
                "private Standalone capability",
            );
            let store = objects(&wire);
            let path = Path::from(format!("{}/v1/global.json", storage.prefix));
            ok(
                store.put(&path, "actual Standalone setup".into()).await,
                "restricted Standalone Put",
            );
            ok(store.head(&path).await, "restricted Standalone Head");
            assert!(
                ok(
                    ok(store.get(&path).await, "restricted Standalone Get")
                        .bytes()
                        .await,
                    "complete restricted Standalone bytes"
                ) == "actual Standalone setup"
            );
            denied(
                store
                    .put(&Path::from("outside-standalone"), "denied".into())
                    .await,
            );
        })
        .catch_unwind()
        .await;
        let closed = minio.shutdown();
        if let Err(failure) = observed {
            std::panic::resume_unwind(failure);
        }
        ok(closed, "owned MinIO shutdown");
    }
    async fn exercise_standalone(ready: &Value) {
        use futures_util::TryStreamExt as _;
        let keys = &ready["standalone_storage"];
        assert!(keys.is_object(), "opt-in private Standalone capability");
        assert!(
            keys["session_token"].is_null(),
            "MinIO child accesskey has no STS token"
        );
        assert!(
            keys["bucket"] == ready["bucket"]
                && keys["region"] == ready["region"]
                && keys["endpoint"] == ready["storage_endpoint"],
            "owned storage topology"
        );
        let prefix = format!("standalone/{PROJECT}");
        assert!(keys["prefix"] == prefix, "dedicated Standalone prefix");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry = keys["expires_at"]
            .as_u64()
            .expect("actual Unix-second expiry");
        assert!(
            expiry > now && expiry <= now + 1800,
            "finite real accesskey expiry"
        );
        let store = objects(keys);
        for relative in [
            "v1/global.json".to_owned(),
            "v1/anonymous.json".into(),
            "v1/authenticated.json".into(),
            format!("v1/users/{SUBJECT}.json"),
            "v1/teams/fixture.json".into(),
            format!("v1/projects/{PROJECT}/hub/metadata/project.json"),
        ] {
            let path = Path::from(format!("{prefix}/{relative}"));
            ok(
                store.put(&path, "owned Standalone data".into()).await,
                "Standalone scoped Put",
            );
            ok(store.head(&path).await, "Standalone scoped Head");
            let data = ok(
                ok(store.get(&path).await, "Standalone scoped Get")
                    .bytes()
                    .await,
                "Standalone complete data",
            );
            assert!(data == "owned Standalone data", "actual Standalone bytes");
        }
        let native = objects(&credentials(ready).await);
        let outside = Path::from(format!(
            "{}/v1/projects/{PROJECT}/artifacts/standalone-outside",
            text(ready, "prefix")
        ));
        ok(
            native.put(&outside, "owned Hub object".into()).await,
            "actual independent Hub object",
        );
        denied(store.get(&outside).await);
        denied(store.put(&outside, "denied".into()).await);
        denied(
            store
                .put(
                    &Path::from(format!("standalone/{SECOND}/v1/global.json")),
                    "denied".into(),
                )
                .await,
        );
        denied(
            store
                .put(
                    &Path::from(format!("{prefix}-sibling/v1/global.json")),
                    "denied".into(),
                )
                .await,
        );
        denied(
            store
                .delete(&Path::from(format!("{prefix}/v1/global.json")))
                .await,
        );
        denied(
            store
                .list(Some(&Path::from(prefix)))
                .try_collect::<Vec<_>>()
                .await,
        );
        assert!(
            ok(
                ok(native.get(&outside).await, "Native Hub remains readable")
                    .bytes()
                    .await,
                "Native Hub complete data"
            ) == "owned Hub object",
            "independent Native capability preserved"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "normal process, owned PostgreSQL/MinIO and expiring scoped Standalone accesskey"]
    async fn hub_storage_fixture_standalone_scope_contract() {
        process_profile_contract(false, false, true, false).await;
    }
    async fn exercise_standalone_publisher(ready: &Value) {
        use futures_util::{StreamExt as _, TryStreamExt as _};
        let reader_keys = &ready["standalone_storage"];
        let publisher_keys = &ready["standalone_publisher_storage"];
        assert!(
            reader_keys.is_object() && publisher_keys.is_object(),
            "separate private catalog capabilities"
        );
        for field in ["bucket", "region", "endpoint", "prefix"] {
            assert!(
                reader_keys[field] == publisher_keys[field],
                "same owned storage namespace"
            );
        }
        assert!(
            reader_keys["access_key_id"] != publisher_keys["access_key_id"],
            "independent publisher account"
        );
        assert!(
            reader_keys["secret_access_key"] != publisher_keys["secret_access_key"],
            "independent publisher credential"
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            publisher_keys["expires_at"]
                .as_u64()
                .is_some_and(|v| v > now && v <= now + 1800),
            "finite actual publisher expiry"
        );
        let prefix = text(reader_keys, "prefix");
        assert!(
            prefix == format!("standalone/{PROJECT}"),
            "dedicated seed namespace"
        );
        let reader = objects(reader_keys);
        let publisher = objects(publisher_keys);
        // Artifact producer differs from the fixture/consumer project inside this seed namespace.
        let stage = Path::from(format!(
            "{prefix}/v1/projects/{SECOND}/artifacts/staging/native-upload-fixture"
        ));
        let final_path = Path::from(format!(
            "{prefix}/v1/projects/{SECOND}/artifacts/ast/fixture/v1/data"
        ));
        let registry = Path::from(format!(
            "{prefix}/v1/projects/{SECOND}/registry/ast/fixture.json"
        ));
        ok(
            publisher.put(&stage, "actual seed payload".into()).await,
            "publisher staging upload",
        );
        ok(
            publisher.copy_if_not_exists(&stage, &final_path).await,
            "publisher immutable copy",
        );
        denied(
            reader
                .delete_stream(futures_util::stream::iter([Ok(stage.clone())]).boxed())
                .try_collect::<Vec<_>>()
                .await,
        );
        ok(
            reader.head(&stage).await,
            "reader bulk denial preserves staging",
        );
        let removed = ok(
            publisher
                .delete_stream(futures_util::stream::iter([Ok(stage.clone())]).boxed())
                .try_collect::<Vec<_>>()
                .await,
            "publisher actual bulk cleanup",
        );
        assert!(
            removed == [stage.clone()],
            "bulk response confirms its object result"
        );
        assert!(
            matches!(
                publisher.head(&stage).await,
                Err(object_store::Error::NotFound { .. })
            ),
            "staging actually removed"
        );
        ok(
            publisher
                .put_opts(
                    &registry,
                    "actual registry marker".into(),
                    PutOptions {
                        mode: PutMode::Create,
                        ..Default::default()
                    },
                )
                .await,
            "registry conditional publication after cleanup",
        );
        assert!(
            ok(
                ok(reader.get(&final_path).await, "reader payload get")
                    .bytes()
                    .await,
                "reader payload bytes"
            ) == "actual seed payload",
            "reader remains usable"
        );
        let metadata = Path::from(format!(
            "{prefix}/v1/projects/{SECOND}/hub/metadata/project.json"
        ));
        let acl = Path::from(format!("{prefix}/v1/global.json"));
        let foreign_stage = Path::from(format!(
            "{prefix}/v1/projects/{SECOND}/artifacts/staging/foreign-upload"
        ));
        for key in [&metadata, &acl, &foreign_stage] {
            ok(
                reader.put(key, "preserved".into()).await,
                "existing setup write",
            );
        }
        for key in [&final_path, &registry, &metadata, &acl, &foreign_stage] {
            denied(publisher.delete(key).await);
            ok(
                reader.head(key).await,
                "denied publisher delete preserves object",
            );
        }
        denied(
            publisher
                .delete_stream(futures_util::stream::iter([Ok(final_path.clone())]).boxed())
                .try_collect::<Vec<_>>()
                .await,
        );
        ok(
            reader.head(&final_path).await,
            "bulk item denial preserves immutable payload",
        );
        let outside = Path::from(format!(
            "standalone/{SECOND}/v1/projects/{SECOND}/artifacts/staging/native-upload-fixture"
        ));
        denied(publisher.put(&outside, "denied".into()).await);
        denied(publisher.delete(&outside).await);
        denied(reader.put(&outside, "denied".into()).await);
        ok(
            reader
                .list(Some(&Path::from(prefix)))
                .try_collect::<Vec<_>>()
                .await,
            "catalog reader listing unchanged",
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "normal Web/catalog process and actual separate MinIO publisher bulk cleanup with reader denials"]
    async fn hub_storage_fixture_standalone_publisher_contract() {
        process_profile_contract(false, true, true, true).await;
    }
    #[test]
    fn standalone_is_explicit_optional_closed_boolean() {
        for enabled in [false, true] {
            let command: Command = ok(
                serde_json::from_value(json!({"command":"start",
                "project_id":PROJECT,"standalone":enabled})),
                "closed Standalone opt-in",
            );
            assert_eq!(ok(command.setup(), "Standalone setup").standalone, enabled);
        }
        let command: Command = ok(
            serde_json::from_value(json!({"command":"start","project_id":PROJECT})),
            "unchanged Native start",
        );
        let setup = ok(command.setup(), "unchanged Native setup");
        assert!(!setup.standalone);
        assert!(!setup.standalone_catalog);
        for standalone in [false, true] {
            let command: Command = ok(
                serde_json::from_value(json!({"command":"start","project_id":PROJECT,
                    "standalone":standalone,"standalone_catalog":true})),
                "closed catalog opt-in",
            );
            match command.setup() {
                Ok(setup) => assert!(standalone && setup.standalone_catalog),
                Err(_) => assert!(!standalone),
            }
        }
        for invalid in [Value::Null, json!("true"), json!(1), json!({})] {
            assert!(
                serde_json::from_value::<Command>(json!({"command":"start",
                "project_id":PROJECT,"standalone":invalid}))
                .is_err()
            );
        }
        for enabled in [false, true] {
            let command: Command = ok(
                serde_json::from_value(json!({"command":"start_web",
                "project_id":PROJECT,"second_project_id":SECOND,"standalone_catalog":enabled,
                "authorization_ttl_seconds":60,"local_challenge_ttl_seconds":600,
                "access_ttl_seconds":600,"refresh_ttl_seconds":3600})),
                "Web catalog opt-in",
            );
            let setup = ok(command.setup(), "Web catalog setup");
            assert!(setup.web.is_some());
            assert_eq!(setup.standalone, enabled);
            assert_eq!(setup.standalone_catalog, enabled);
            assert_eq!(setup.second_project_id.as_deref(), Some(SECOND));
        }
        let omitted: Command = ok(
            serde_json::from_value(json!({"command":"start_web",
            "project_id":PROJECT,"authorization_ttl_seconds":60,"local_challenge_ttl_seconds":600,
            "access_ttl_seconds":600,"refresh_ttl_seconds":3600})),
            "Web catalog omitted",
        );
        let omitted = ok(omitted.setup(), "Web catalog absent setup");
        assert!(!omitted.standalone && !omitted.standalone_catalog);
        for invalid in [Value::Null, json!("true"), json!(1), json!({})] {
            assert!(
                serde_json::from_value::<Command>(json!({"command":"start_web",
                "project_id":PROJECT,"standalone_catalog":invalid,
                "authorization_ttl_seconds":60,"local_challenge_ttl_seconds":600,
                "access_ttl_seconds":600,"refresh_ttl_seconds":3600}))
                .is_err()
            );
        }
        assert!(serde_json::from_str::<Command>(r#"{"command":"start_web","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","standalone_catalog":true,"standalone_catalog":false,"authorization_ttl_seconds":60,"local_challenge_ttl_seconds":600,"access_ttl_seconds":600,"refresh_ttl_seconds":3600}"#).is_err());
        assert!(
            serde_json::from_value::<Command>(json!({"command":"start_web","project_id":PROJECT,
            "authorization_ttl_seconds":60,"local_challenge_ttl_seconds":600,
            "access_ttl_seconds":600,"refresh_ttl_seconds":3600,"standalone":true}))
            .is_err()
        );
    }
    async fn process_contract(full_s3: bool, web: bool) {
        process_profile_contract(full_s3, web, false, false).await;
    }
    async fn process_profile_contract(full_s3: bool, web: bool, standalone: bool, catalog: bool) {
        let executable = ok(std::env::current_exe(), "test executable")
            .parent()
            .unwrap()
            .join(format!(
                "hub_storage_fixture{}",
                std::env::consts::EXE_SUFFIX
            ));
        assert!(
            executable.is_file(),
            "build the normal hub_storage_fixture example before this contract"
        );
        let mut child = ok(
            tokio::process::Command::new(&executable)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(
                    if std::env::var_os("GRAPHIT_BROKER_FIXTURE_DIAGNOSTICS")
                        .is_some_and(|value| value == "1")
                    {
                        Stdio::inherit()
                    } else {
                        Stdio::null()
                    },
                )
                .kill_on_drop(true)
                .spawn(),
            "normal process spawn",
        );
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut start = if standalone && !web {
            json!({"command":"start","project_id":PROJECT,"second_project_id":SECOND,"standalone":true})
        } else if web {
            json!({"command":"start_web","project_id":PROJECT,"second_project_id":SECOND,
                "authorization_ttl_seconds":60,"local_challenge_ttl_seconds":600,"access_ttl_seconds":600,"refresh_ttl_seconds":3600})
        } else {
            json!({"command":"start","project_id":PROJECT,"second_project_id":SECOND})
        };
        if catalog {
            start["standalone_catalog"] = json!(true);
        }
        let observed = AssertUnwindSafe(async {
            ok(
                input.write_all(format!("{start}\n").as_bytes()).await,
                "private Start",
            );
            ok(input.flush().await, "Start flush");
            let ready = ok(
                ok(
                    tokio::time::timeout(Duration::from_secs(300), output.next_line()).await,
                    "Ready guard",
                )
                .map_err(|_| ()),
                "Ready read",
            )
            .expect("Ready line");
            let ready = Zeroizing::new(ready);
            let ready: Value = ok(serde_json::from_str(&ready), "private Ready decode");
            assert_eq!(ready["event"], "ready");
            assert!(ready["expires_at"].as_u64().is_some_and(|v| {
                v > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            }));
            let mut now_sockets = Vec::new();
            let exercised = AssertUnwindSafe(async {
                if catalog {
                    exercise_standalone_publisher(&ready).await;
                    return;
                }
                assert!(
                    ready.get("standalone_publisher_storage").is_none(),
                    "publisher absent without catalog opt-in"
                );
                if standalone {
                    exercise_standalone(&ready).await;
                    return;
                }
                assert!(
                    ready.get("standalone_storage").is_none(),
                    "ordinary Native/Web capability unchanged"
                );
                if web {
                    exercise_web(&ready).await;
                }
                exercise_inventory(&ready).await;
                if full_s3 {
                    exercise(&ready).await;
                } else {
                    let _ = credentials(&ready).await;
                }
                exercise_invalid_now_update(&ready).await;
                now_sockets = exercise_now(&ready).await;
                now_updated(&mut now_sockets).await;
                // Control Ping/Pong proves each connection is live immediately
                // before Shutdown, independently of domain payload read masks.
                now_active(&mut now_sockets).await;
            })
            .catch_unwind()
            .await;
            ok(
                input.write_all(b"{\"command\":\"shutdown\"}\n").await,
                "private Shutdown",
            );
            ok(input.flush().await, "Shutdown flush");
            let ack = ok(
                ok(
                    tokio::time::timeout(Duration::from_secs(300), output.next_line()).await,
                    "Shutdown guard",
                )
                .map_err(|_| ()),
                "Ack read",
            )
            .expect("Ack line");
            let ack: Value = ok(serde_json::from_str(&ack), "Ack decode");
            assert_eq!(ack, json!({"event":"ack","command":"shutdown","ok":true}));
            for socket in &mut now_sockets {
                now_stopped(socket).await;
            }
            if let Err(panic) = exercised {
                std::panic::resume_unwind(panic);
            }
        })
        .catch_unwind()
        .await;
        // EOF allows the normal child to finish setup and clean up even when Ready failed.
        drop(input);
        let joined = tokio::time::timeout(Duration::from_secs(300), child.wait()).await;
        let success = match joined {
            Ok(Ok(status)) => status.success(),
            _ => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                false
            }
        };
        if let Err(panic) = observed {
            std::panic::resume_unwind(panic);
        }
        assert!(success, "normal process join");
    }
}
