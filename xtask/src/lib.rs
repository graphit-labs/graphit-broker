pub mod build;
pub mod package;

use std::{
    io,
    process::{Command, ExitStatus},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    PreCommit,
    PrePush,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Check {
    pub program: &'static str,
    pub args: &'static [&'static str],
}

const FMT: Check = Check {
    program: "cargo",
    args: &["fmt", "--all", "--check"],
};
const CLIPPY: Check = Check {
    program: "cargo",
    args: &[
        "clippy",
        "--locked",
        "--offline",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ],
};
const AWS_HUB_STORAGE: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "-p",
        "broker-storage",
        "--test",
        "aws_hub_storage",
        "--",
        "--ignored",
        "--exact",
        "aws_hub_storage_sts_s3_contract",
        "--test-threads=1",
    ],
};
const PROJECT_CORPUS_HTTP_STS: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "-p",
        "broker-presence",
        "--test",
        "project_corpus_storage_credentials_http",
        "--",
        "--ignored",
        "--exact",
        "project_corpus_storage_credentials_http_contract",
        "--test-threads=1",
    ],
};
const USER_MEMORY_HTTP_STS: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "-p",
        "broker-presence",
        "--test",
        "user_memory_storage_credentials_http",
        "--",
        "--ignored",
        "--exact",
        "user_memory_storage_credentials_http_contract",
        "--test-threads=1",
    ],
};
const GLOBAL_HUB_HTTP_STS: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "-p",
        "broker-presence",
        "--test",
        "global_hub_storage_credentials_http",
        "--",
        "--ignored",
        "--exact",
        "global_hub_storage_credentials_http_contract",
        "--test-threads=1",
    ],
};
const PROJECT_HUB_METADATA_EVENTS_STS: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "-p",
        "broker-presence",
        "--test",
        "project_hub_metadata_events_storage",
        "--",
        "--ignored",
        "--exact",
        "project_hub_metadata_events_storage_contract",
        "--test-threads=1",
    ],
};
const POSTGRES: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "-p",
        "broker-control",
        "-p",
        "broker-server",
        "--test",
        "postgres",
        "--test",
        "local_admin_bootstrap",
        "--test",
        "postgres_identity",
        "--test",
        "postgres_roles",
        "--test",
        "storage_admission",
        "--test",
        "project_corpus_storage_admission",
        "--test",
        "user_memory_storage_admission",
        "--test",
        "global_hub_storage_admission",
        "--test",
        "postgres_oidc_token_exchange",
        "--test",
        "postgres_oidc_refresh",
        "--test",
        "postgres_admin_broker_session",
        "--test",
        "postgres_admin_local_bearer_session",
        "--test",
        "embedding_cache",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const POSTGRES_SESSIONS: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "-p",
        "broker-control",
        "--test",
        "postgres_sessions",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const DOC: Check = Check {
    program: "cargo",
    args: &["test", "--locked", "--offline", "--workspace", "--doc"],
};
const TEST: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "--workspace",
        "--all-targets",
        "--no-fail-fast",
    ],
};
const FILESYSTEM_SESSION: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "-p",
        "broker-storage",
        "--test",
        "filesystem_sessions",
        "--",
        "--ignored",
        "--exact",
        "filesystem_sessions_postgres_contract",
        "--test-threads=1",
    ],
};
const FILESYSTEM_OBJECTS: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-storage",
        "--test",
        "filesystem_objects",
        "--",
        "--ignored",
        "--exact",
        "filesystem_objects_postgres_contract",
        "--test-threads=1",
    ],
};
const FILESYSTEM_LISTING: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-storage",
        "--test",
        "filesystem_listing",
        "--",
        "--ignored",
        "--exact",
        "filesystem_listing_postgres_contract",
        "--test-threads=1",
    ],
};
const FILESYSTEM_MULTIPART: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-storage",
        "--test",
        "filesystem_multipart",
        "--",
        "--ignored",
        "--exact",
        "filesystem_multipart_postgres_contract",
        "--test-threads=1",
    ],
};
const FILESYSTEM_S3_GATEWAY: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-storage",
        "--test",
        "filesystem_s3_gateway",
        "--",
        "--ignored",
        "--exact",
        "filesystem_s3_gateway_postgres_contract",
        "--test-threads=1",
    ],
};
const MIXED_STORAGE_HTTP_STS: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-presence",
        "--test",
        "mixed_storage_credentials_http",
        "--",
        "--ignored",
        "--exact",
        "mixed_storage_credentials_http_contract",
        "--test-threads=1",
    ],
};
const BROKER_STORAGE_SERVER_STARTUP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "startup",
        "--",
        "--ignored",
        "--exact",
        "broker_storage_server_startup_contract",
        "--test-threads=1",
    ],
};

const OIDC_REGISTRATION_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "oauth_token",
        "--",
        "--ignored",
        "--exact",
        "broker_oidc_registration_http_contract",
        "--test-threads=1",
    ],
};
const OIDC_REGISTRATION_UNCERTAINTY: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "oauth_token",
        "--",
        "--ignored",
        "--exact",
        "broker_oidc_registration_uncertainty_contract",
        "--test-threads=1",
    ],
};
const OIDC_BROWSER_CALLBACK_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "oidc_browser_callback",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const OIDC_FEDERATED_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_oidc_federated",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const OIDC_FEDERATED_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "oidc_federated",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const LOCAL_FEDERATED_ISOLATION_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_local_auth",
        "--",
        "--ignored",
        "--exact",
        "postgres_local_invalidation_preserves_federated_grants",
        "--test-threads=1",
    ],
};
const OIDC_CODE_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "oauth_token",
        "--",
        "--ignored",
        "--exact",
        "broker_oidc_authorization_code_http_contract",
        "--test-threads=1",
    ],
};
const OIDC_REFRESH_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "oauth_token",
        "--",
        "--ignored",
        "--exact",
        "broker_oidc_refresh_http_contract",
        "--test-threads=1",
    ],
};

const OIDC_REVOCATION_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_oidc_revocation",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const OIDC_REVOCATION_FEDERATED_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_oidc_federated",
        "--",
        "--ignored",
        "--exact",
        "postgres_oidc_federated_revocation_contract",
        "--test-threads=1",
    ],
};
const OIDC_REVOCATION_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "oauth_revocation",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};

const OIDC_USERINFO_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "oauth_userinfo",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};

const OIDC_INTROSPECTION_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "oauth_introspection",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};

const OIDC_END_SESSION_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "oauth_end_session",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};

const DEVICE_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_device",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};

const ADMIN_SESSION_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "admin_session",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_session_http_contract",
        "--test-threads=1",
    ],
};
const ADMIN_LOCAL_BEARER_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "admin_session",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_local_bearer_http_contract",
        "--test-threads=1",
    ],
};
const ADMIN_UPSTREAM_BEARER_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "admin_session",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_upstream_bearer_http_contract",
        "--test-threads=1",
    ],
};
const ADMIN_COOKIE_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-control",
        "--test",
        "postgres_admin_cookie",
        "--",
        "--ignored",
        "--exact",
        "postgres_admin_cookie_contract",
        "--test-threads=1",
    ],
};
const ADMIN_COOKIE_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "admin_cookie",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_cookie_http_contract",
        "--test-threads=1",
    ],
};
const LOCAL_PASSWORD_ADMISSION_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-control",
        "--test",
        "local_password_admission",
        "--",
        "--ignored",
        "--exact",
        "postgres_local_password_admission_contract",
        "--test-threads=1",
    ],
};
const LOCAL_PASSWORD_ADMISSION_UNCERTAIN: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-control",
        "--test",
        "local_password_admission",
        "--",
        "--ignored",
        "--exact",
        "postgres_admission_commit_uncertainty_contract",
        "--test-threads=1",
    ],
};
const LOCAL_PASSWORD_CAPTCHA_SQL: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-control",
        "--lib",
        "--",
        "--ignored",
        "_https_local_password_admission_contract",
        "--test-threads=1",
    ],
};
const LOCAL_PASSWORD_CAPACITY_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-control",
        "--lib",
        "--",
        "--ignored",
        "--exact",
        "local_password_admission::tests::postgres_admission_capacity_preserves_active_entries",
        "--test-threads=1",
    ],
};
const OIDC_BROWSER_ADMISSION_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_oidc_authorization",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const OIDC_BROWSER_AUTHORIZATION_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "oidc_browser_authorization",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const OIDC_DISCOVERY_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "oidc_discovery",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const SERVER_EMBEDDINGS_HTTP_SQL: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "embeddings",
        "--",
        "--ignored",
        "--exact",
        "compiled_server_embeddings_authorizes_batches_persists_and_reopens",
        "--test-threads=1",
    ],
};
const RERANK_ADMISSION_SQL: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "rerank_admission",
        "--",
        "--include-ignored",
        "--test-threads=1",
    ],
};
const SERVER_RERANK_HTTP_SQL: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "rerank",
        "--",
        "--ignored",
        "--exact",
        "compiled_rerank_postgres_discovery_private_cache_sdk_and_shutdown",
        "--test-threads=1",
    ],
};
const LOCAL_LOGIN_RUNTIME_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "local_login_runtime",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const ADMIN_LOCAL_LOGIN_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "admin_local_login",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_local_login_http_contract",
        "--test-threads=1",
    ],
};
const ADMIN_LOCAL_LOGIN_FAILURE_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "admin_local_login",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_local_login_failure_contract",
        "--test-threads=1",
    ],
};
const ADMIN_LOCAL_LOGIN_UNCERTAINTY_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "admin_local_login",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_local_login_uncertainty_contract",
        "--test-threads=1",
    ],
};
const ADMIN_LOCAL_LOGIN_CONFIG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "admin_local_login",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_local_login_configuration_contract",
        "--test-threads=1",
    ],
};
const UPSTREAM_BROWSER_LOGIN_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_upstream_login",
        "--",
        "--ignored",
        "--exact",
        "postgres_upstream_login_contract",
        "--test-threads=1",
    ],
};
const UPSTREAM_BROWSER_UNCERTAINTY_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_upstream_login",
        "--",
        "--ignored",
        "--exact",
        "postgres_upstream_login_uncertainty_contract",
        "--test-threads=1",
    ],
};
const ADMIN_FEDERATED_COOKIE_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_admin_federated_cookie",
        "--",
        "--ignored",
        "--exact",
        "postgres_admin_federated_cookie_contract",
        "--test-threads=1",
    ],
};
const ADMIN_FEDERATED_COOKIE_UNCERTAINTY_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_admin_federated_cookie",
        "--",
        "--ignored",
        "--exact",
        "postgres_admin_federated_cookie_uncertainty_contract",
        "--test-threads=1",
    ],
};
const ADMIN_READ_PG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-control",
        "--test",
        "postgres_admin_read",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const ADMIN_READ_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "admin_read",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const ADMIN_UPSTREAM_LOGIN_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "admin_upstream_login",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_upstream_login_http_contract",
        "--test-threads=1",
    ],
};
const ADMIN_UPSTREAM_LOGIN_UNCERTAINTY: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "admin_upstream_login",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_upstream_login_uncertainty_contract",
        "--test-threads=1",
    ],
};
const ADMIN_UPSTREAM_LOGIN_CONFIG: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "admin_upstream_login",
        "--",
        "--ignored",
        "--exact",
        "broker_admin_upstream_login_configuration_contract",
        "--test-threads=1",
    ],
};
const HUB_STORAGE_FIXTURE_BUILD: Check = Check {
    program: "cargo",
    args: &[
        "build",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-presence",
        "--example",
        "hub_storage_fixture",
    ],
};
const HUB_STORAGE_FIXTURE_CONTRACT: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-presence",
        "--example",
        "hub_storage_fixture",
        "--",
        "--ignored",
        "--exact",
        "tests::hub_storage_fixture_native_sts_contract",
        "--test-threads=1",
    ],
};
const PROJECT_ACCESS_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "project_access",
        "--",
        "--ignored",
        "--exact",
        "broker_project_access_http_contract",
        "--test-threads=1",
    ],
};
const PRESENCE_SERVER_HTTP: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "presence",
        "--",
        "--ignored",
        "--exact",
        "broker_presence_server_http_ws_contract",
        "--test-threads=1",
    ],
};
const SQLITE_LOCAL_AUTH: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-control",
        "-p",
        "broker-presence",
        "-p",
        "broker-server",
        "--test",
        "sqlite_local_auth",
        "--test",
        "sqlite_admin_cookie",
        "--test",
        "sqlite_admin_local_http",
        "--test",
        "sqlite_oidc_grants",
        "--test",
        "sqlite_oidc_browser_http",
        "--test",
        "sqlite_device_http",
        "--test",
        "sqlite_oidc_lifecycle",
        "--test",
        "sqlite_oidc_lifecycle_http",
        "--test",
        "sqlite_admin_reads",
        "--test",
        "sqlite_admin_read_http",
        "--test",
        "sqlite_oidc_federated",
        "--test",
        "sqlite_oidc_federated_http",
        "--test",
        "sqlite_admin_ingress",
        "--test",
        "sqlite_admin_session_http",
        "--test",
        "sqlite_admin_upstream_login",
        "--test",
        "sqlite_admin_grants",
        "--test",
        "sqlite_admin_grants_http",
        "--test",
        "sqlite_admin_rbac_write",
        "--test",
        "sqlite_admin_rbac_write_http",
        "--test",
        "sqlite_hub_access_http",
        "--test",
        "sqlite_storage_admission",
        "--test",
        "sqlite_storage_credentials_http",
        "--test",
        "sqlite_admin_users",
        "--test",
        "sqlite_admin_users_http",
        "--test",
        "sqlite_local_presence_now",
        "--test",
        "sqlite_local_presence_now_http",
        "--test",
        "sqlite_server",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const AUDIT: Check = Check {
    program: "cargo",
    args: &["audit", "--file", "Cargo.lock", "--json"],
};
const SQL_SERVERS: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "-p",
        "broker-store",
        "--test",
        "sql_servers",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const MYSQL_CONTROL: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "-p",
        "broker-control",
        "--test",
        "mysql_control",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const DIFF: Check = Check {
    program: "git",
    args: &["diff", "--cached", "--check"],
};
const BUILD: Check = Check {
    program: "cargo",
    args: &[
        "run", "--locked", "--quiet", "-p", "xtask", "--", "build", "--debug",
    ],
};
const SHELL: Check = Check {
    program: "sh",
    args: &["-n", "docker-entrypoint.sh"],
};
const UI: Check = Check {
    program: "node",
    args: &["scripts/check-admin-ui.cjs"],
};
const UNIX_INSTALLER: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "broker-server",
        "--test",
        "server_assets",
        "--",
        "--ignored",
        "--exact",
        "unix_installer_checks_real_archive_and_preserves_previous_binary",
    ],
};
const NATIVE_PACKAGE: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-p",
        "xtask",
        "--test",
        "native_package",
        "--",
        "--ignored",
        "--test-threads=1",
    ],
};
const DOCKER: Check = Check {
    program: "cargo",
    args: &[
        "test",
        "--locked",
        "--offline",
        "-j4",
        "-p",
        "broker-server",
        "--test",
        "container",
        "--",
        "--ignored",
        "--exact",
        "broker_native_container_contract",
        "--test-threads=1",
    ],
};

pub fn qualification_checks() -> Vec<Check> {
    vec![
        AWS_HUB_STORAGE,
        PROJECT_CORPUS_HTTP_STS,
        USER_MEMORY_HTTP_STS,
        GLOBAL_HUB_HTTP_STS,
        PROJECT_HUB_METADATA_EVENTS_STS,
        FILESYSTEM_SESSION,
        FILESYSTEM_OBJECTS,
        FILESYSTEM_LISTING,
        FILESYSTEM_MULTIPART,
        FILESYSTEM_S3_GATEWAY,
        MIXED_STORAGE_HTTP_STS,
        BROKER_STORAGE_SERVER_STARTUP,
        OIDC_CODE_HTTP,
        OIDC_REFRESH_HTTP,
        OIDC_FEDERATED_PG,
        OIDC_FEDERATED_HTTP,
        LOCAL_FEDERATED_ISOLATION_PG,
        ADMIN_SESSION_HTTP,
        ADMIN_LOCAL_BEARER_HTTP,
        ADMIN_UPSTREAM_BEARER_HTTP,
        ADMIN_COOKIE_PG,
        ADMIN_COOKIE_HTTP,
        LOCAL_PASSWORD_ADMISSION_PG,
        LOCAL_PASSWORD_ADMISSION_UNCERTAIN,
        LOCAL_PASSWORD_CAPTCHA_SQL,
        LOCAL_PASSWORD_CAPACITY_PG,
        ADMIN_LOCAL_LOGIN_HTTP,
        ADMIN_LOCAL_LOGIN_FAILURE_HTTP,
        ADMIN_LOCAL_LOGIN_UNCERTAINTY_HTTP,
        ADMIN_LOCAL_LOGIN_CONFIG,
        UPSTREAM_BROWSER_LOGIN_PG,
        UPSTREAM_BROWSER_UNCERTAINTY_PG,
        ADMIN_FEDERATED_COOKIE_PG,
        ADMIN_FEDERATED_COOKIE_UNCERTAINTY_PG,
        ADMIN_READ_PG,
        ADMIN_READ_HTTP,
        PROJECT_ACCESS_HTTP,
        PRESENCE_SERVER_HTTP,
        ADMIN_UPSTREAM_LOGIN_HTTP,
        ADMIN_UPSTREAM_LOGIN_UNCERTAINTY,
        ADMIN_UPSTREAM_LOGIN_CONFIG,
        HUB_STORAGE_FIXTURE_BUILD,
        HUB_STORAGE_FIXTURE_CONTRACT,
        OIDC_REGISTRATION_HTTP,
        OIDC_REGISTRATION_UNCERTAINTY,
        OIDC_BROWSER_CALLBACK_HTTP,
        LOCAL_LOGIN_RUNTIME_HTTP,
        OIDC_BROWSER_ADMISSION_PG,
        OIDC_BROWSER_AUTHORIZATION_HTTP,
        OIDC_DISCOVERY_HTTP,
        SERVER_EMBEDDINGS_HTTP_SQL,
        OIDC_REVOCATION_PG,
        OIDC_REVOCATION_FEDERATED_PG,
        OIDC_REVOCATION_HTTP,
        OIDC_USERINFO_HTTP,
        OIDC_INTROSPECTION_HTTP,
        OIDC_END_SESSION_HTTP,
        DEVICE_PG,
        SQLITE_LOCAL_AUTH,
        AUDIT,
        POSTGRES,
        POSTGRES_SESSIONS,
        SQL_SERVERS,
        MYSQL_CONTROL,
        RERANK_ADMISSION_SQL,
        SERVER_RERANK_HTTP_SQL,
        UNIX_INSTALLER,
        NATIVE_PACKAGE,
        BUILD,
        DOCKER,
    ]
}

/// Classify raw NUL-separated Git paths without lossy UTF-8 conversion.
pub fn checks(event: Event, staged: &[u8]) -> Vec<Check> {
    if event == Event::PrePush {
        return vec![FMT, CLIPPY, DOC, TEST];
    }
    let mut selected = vec![DIFF, FMT];
    let mut shell = false;
    let mut ui = false;
    for path in staged
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        shell |= path == b"docker-entrypoint.sh"
            || path == b"Dockerfile"
            || path.starts_with(b"docker-compose")
            || path.starts_with(b"compose.")
            || path.starts_with(b"scripts/");
        ui |= path.starts_with(b"crates/broker-presence/assets/admin/")
            || path == b"scripts/check-admin-ui.cjs";
    }
    if shell {
        selected.push(SHELL);
    }
    if ui {
        selected.push(UI);
    }
    selected
}

pub fn staged_paths() -> io::Result<Vec<u8>> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "-z"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("cannot inspect staged paths"));
    }
    Ok(output.stdout)
}

pub fn execute(check: Check) -> io::Result<ExitStatus> {
    eprintln!("broker check: {} {:?}", check.program, check.args);
    let package = if check == DOCKER
        && std::env::var_os("GRAPHIT_BROKER_CONTAINER_IMAGE").is_none()
        && std::env::var_os("GRAPHIT_BROKER_CONTAINER_PACKAGE").is_none()
    {
        let temporary = tempfile::tempdir()?;
        package::package(
            false,
            &temporary.path().join("package"),
            Some(std::path::Path::new("graphit-broker")),
            None,
        )?;
        Some(temporary)
    } else {
        None
    };
    let mut command = Command::new(check.program);
    command.args(check.args);
    if let Some(package) = &package {
        command.env(
            "GRAPHIT_BROKER_CONTAINER_PACKAGE",
            package
                .path()
                .join("package/graphit-broker-linux-amd64.tar.gz"),
        );
    }
    command.status()
}

pub fn parse_event(value: &str) -> Option<Event> {
    match value {
        "pre-commit" => Some(Event::PreCommit),
        "pre-push" => Some(Event::PrePush),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pre_commit_keeps_static_checks_and_pre_push_covers_workspace_tests() {
        let paths = b"Cargo.toml\0crates/broker-store/src/schema.rs\0xtask/src/lib.rs\0docs/rust-sql-schema.md\0";
        assert_eq!(checks(Event::PreCommit, paths), vec![DIFF, FMT]);
        let push = checks(Event::PrePush, paths);
        assert_eq!(push, vec![FMT, CLIPPY, DOC, TEST]);
        assert_eq!(
            TEST.args,
            &[
                "test",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--no-fail-fast"
            ]
        );
    }
    #[test]
    fn qualification_keeps_real_postgres_rerank_consumers() {
        let phases = qualification_checks();
        for phase in [RERANK_ADMISSION_SQL, SERVER_RERANK_HTTP_SQL] {
            assert!(phases.contains(&phase));
            assert!(phase.args.contains(&"--offline"));
            assert!(phase.args.contains(&"--test-threads=1"));
        }
        assert!(RERANK_ADMISSION_SQL.args.contains(&"--include-ignored"));
        assert!(SERVER_RERANK_HTTP_SQL.args.contains(&"--ignored"));
        assert!(
            SERVER_RERANK_HTTP_SQL
                .args
                .contains(&"compiled_rerank_postgres_discovery_private_cache_sdk_and_shutdown")
        );
    }
    #[test]
    fn commit_keeps_static_checks_and_qualification_preserves_build_check() {
        assert_eq!(checks(Event::PreCommit, b"Makefile\0"), vec![DIFF, FMT]);
        assert_eq!(
            checks(
                Event::PreCommit,
                b"crates/broker-presence/assets/admin/index.html\0"
            ),
            vec![DIFF, FMT, UI]
        );
        assert_eq!(
            checks(Event::PreCommit, b"docker-entrypoint.sh\0"),
            vec![DIFF, FMT, SHELL]
        );
        assert_eq!(
            checks(Event::PreCommit, b"Makefile\0scripts/check-admin-ui.cjs\0"),
            vec![DIFF, FMT, SHELL, UI]
        );
        assert_eq!(
            qualification_checks(),
            vec![
                AWS_HUB_STORAGE,
                PROJECT_CORPUS_HTTP_STS,
                USER_MEMORY_HTTP_STS,
                GLOBAL_HUB_HTTP_STS,
                PROJECT_HUB_METADATA_EVENTS_STS,
                FILESYSTEM_SESSION,
                FILESYSTEM_OBJECTS,
                FILESYSTEM_LISTING,
                FILESYSTEM_MULTIPART,
                FILESYSTEM_S3_GATEWAY,
                MIXED_STORAGE_HTTP_STS,
                BROKER_STORAGE_SERVER_STARTUP,
                OIDC_CODE_HTTP,
                OIDC_REFRESH_HTTP,
                OIDC_FEDERATED_PG,
                OIDC_FEDERATED_HTTP,
                LOCAL_FEDERATED_ISOLATION_PG,
                ADMIN_SESSION_HTTP,
                ADMIN_LOCAL_BEARER_HTTP,
                ADMIN_UPSTREAM_BEARER_HTTP,
                ADMIN_COOKIE_PG,
                ADMIN_COOKIE_HTTP,
                LOCAL_PASSWORD_ADMISSION_PG,
                LOCAL_PASSWORD_ADMISSION_UNCERTAIN,
                LOCAL_PASSWORD_CAPTCHA_SQL,
                LOCAL_PASSWORD_CAPACITY_PG,
                ADMIN_LOCAL_LOGIN_HTTP,
                ADMIN_LOCAL_LOGIN_FAILURE_HTTP,
                ADMIN_LOCAL_LOGIN_UNCERTAINTY_HTTP,
                ADMIN_LOCAL_LOGIN_CONFIG,
                UPSTREAM_BROWSER_LOGIN_PG,
                UPSTREAM_BROWSER_UNCERTAINTY_PG,
                ADMIN_FEDERATED_COOKIE_PG,
                ADMIN_FEDERATED_COOKIE_UNCERTAINTY_PG,
                ADMIN_READ_PG,
                ADMIN_READ_HTTP,
                PROJECT_ACCESS_HTTP,
                PRESENCE_SERVER_HTTP,
                ADMIN_UPSTREAM_LOGIN_HTTP,
                ADMIN_UPSTREAM_LOGIN_UNCERTAINTY,
                ADMIN_UPSTREAM_LOGIN_CONFIG,
                HUB_STORAGE_FIXTURE_BUILD,
                HUB_STORAGE_FIXTURE_CONTRACT,
                OIDC_REGISTRATION_HTTP,
                OIDC_REGISTRATION_UNCERTAINTY,
                OIDC_BROWSER_CALLBACK_HTTP,
                LOCAL_LOGIN_RUNTIME_HTTP,
                OIDC_BROWSER_ADMISSION_PG,
                OIDC_BROWSER_AUTHORIZATION_HTTP,
                OIDC_DISCOVERY_HTTP,
                SERVER_EMBEDDINGS_HTTP_SQL,
                OIDC_REVOCATION_PG,
                OIDC_REVOCATION_FEDERATED_PG,
                OIDC_REVOCATION_HTTP,
                OIDC_USERINFO_HTTP,
                OIDC_INTROSPECTION_HTTP,
                OIDC_END_SESSION_HTTP,
                DEVICE_PG,
                SQLITE_LOCAL_AUTH,
                AUDIT,
                POSTGRES,
                POSTGRES_SESSIONS,
                SQL_SERVERS,
                MYSQL_CONTROL,
                RERANK_ADMISSION_SQL,
                SERVER_RERANK_HTTP_SQL,
                UNIX_INSTALLER,
                NATIVE_PACKAGE,
                BUILD,
                DOCKER
            ]
        );
    }
    #[test]
    fn sql_schema_fast_and_serial_sql_server_targets_are_exact() {
        assert_eq!(
            POSTGRES.args,
            &[
                "test",
                "--locked",
                "-p",
                "broker-control",
                "-p",
                "broker-server",
                "--test",
                "postgres",
                "--test",
                "local_admin_bootstrap",
                "--test",
                "postgres_identity",
                "--test",
                "postgres_roles",
                "--test",
                "storage_admission",
                "--test",
                "project_corpus_storage_admission",
                "--test",
                "user_memory_storage_admission",
                "--test",
                "global_hub_storage_admission",
                "--test",
                "postgres_oidc_token_exchange",
                "--test",
                "postgres_oidc_refresh",
                "--test",
                "postgres_admin_broker_session",
                "--test",
                "postgres_admin_local_bearer_session",
                "--test",
                "embedding_cache",
                "--",
                "--ignored",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            SQL_SERVERS.args,
            &[
                "test",
                "--locked",
                "-p",
                "broker-store",
                "--test",
                "sql_servers",
                "--",
                "--ignored",
                "--test-threads=1"
            ]
        );
    }
    #[test]
    fn upstream_browser_phases_preserve_exact_real_contracts() {
        let phases = qualification_checks();
        for (phase, name) in [
            (
                UPSTREAM_BROWSER_LOGIN_PG,
                "postgres_upstream_login_contract",
            ),
            (
                UPSTREAM_BROWSER_UNCERTAINTY_PG,
                "postgres_upstream_login_uncertainty_contract",
            ),
        ] {
            assert_eq!(phase.program, "cargo");
            assert_eq!(
                phase.args,
                &[
                    "test",
                    "--locked",
                    "--offline",
                    "-j4",
                    "-p",
                    "broker-control",
                    "--test",
                    "postgres_upstream_login",
                    "--",
                    "--ignored",
                    "--exact",
                    name,
                    "--test-threads=1"
                ]
            );
            let position = phases.iter().position(|p| *p == phase).unwrap();
            assert!(
                position
                    < phases
                        .iter()
                        .position(|p| *p == PROJECT_ACCESS_HTTP)
                        .unwrap()
            );
        }
    }
    #[test]
    fn federated_cookie_phases_preserve_exact_real_contracts() {
        let phases = qualification_checks();
        for (phase, name) in [
            (
                ADMIN_FEDERATED_COOKIE_PG,
                "postgres_admin_federated_cookie_contract",
            ),
            (
                ADMIN_FEDERATED_COOKIE_UNCERTAINTY_PG,
                "postgres_admin_federated_cookie_uncertainty_contract",
            ),
        ] {
            assert_eq!(phase.program, "cargo");
            assert_eq!(
                phase.args,
                &[
                    "test",
                    "--locked",
                    "--offline",
                    "-j4",
                    "-p",
                    "broker-control",
                    "--test",
                    "postgres_admin_federated_cookie",
                    "--",
                    "--ignored",
                    "--exact",
                    name,
                    "--test-threads=1"
                ]
            );
            let position = phases.iter().position(|p| *p == phase).unwrap();
            assert!(
                position
                    < phases
                        .iter()
                        .position(|p| *p == PROJECT_ACCESS_HTTP)
                        .unwrap()
            );
        }
    }
    #[test]
    fn mysql_control_phase_uses_exact_native_command_after_sql_servers() {
        assert_eq!(
            MYSQL_CONTROL.args,
            &[
                "test",
                "--locked",
                "-p",
                "broker-control",
                "--test",
                "mysql_control",
                "--",
                "--ignored",
                "--test-threads=1"
            ]
        );
        let plan = qualification_checks();
        let servers = plan.iter().position(|check| *check == SQL_SERVERS).unwrap();
        assert_eq!(plan[servers + 1], MYSQL_CONTROL);
        assert_eq!(plan[servers + 2], RERANK_ADMISSION_SQL);
        assert_eq!(plan[servers + 3], SERVER_RERANK_HTTP_SQL);
        assert_eq!(plan[servers + 4], UNIX_INSTALLER);
        assert_eq!(plan[servers + 5], NATIVE_PACKAGE);
        assert_eq!(plan[servers + 6], BUILD);
        assert_eq!(plan[servers + 7], DOCKER);
    }
    #[test]
    fn admin_read_phases_run_all_real_consumers_before_later_integration() {
        let phases = qualification_checks();
        for (phase, package, target) in [
            (ADMIN_READ_PG, "broker-control", "postgres_admin_read"),
            (ADMIN_READ_HTTP, "broker-server", "admin_read"),
        ] {
            assert_eq!(phase.program, "cargo");
            assert_eq!(
                phase.args,
                &[
                    "test",
                    "--locked",
                    "--offline",
                    "-j4",
                    "-p",
                    package,
                    "--test",
                    target,
                    "--",
                    "--ignored",
                    "--test-threads=1"
                ]
            );
            let position = phases.iter().position(|p| *p == phase).unwrap();
            assert!(
                position
                    > phases
                        .iter()
                        .position(|p| *p == ADMIN_FEDERATED_COOKIE_UNCERTAINTY_PG)
                        .unwrap()
            );
            assert!(
                position
                    < phases
                        .iter()
                        .position(|p| *p == PROJECT_ACCESS_HTTP)
                        .unwrap()
            );
        }
    }
    #[test]
    fn upstream_admin_browser_contracts_precede_audit_in_order() {
        let selected: Vec<_> = SQLITE_LOCAL_AUTH
            .args
            .windows(2)
            .filter(|arg| arg[0] == "--test")
            .map(|arg| arg[1])
            .collect();
        assert!(selected.ends_with(&[
            "sqlite_admin_users",
            "sqlite_admin_users_http",
            "sqlite_local_presence_now",
            "sqlite_local_presence_now_http",
            "sqlite_server"
        ]));
        for target in [
            "sqlite_admin_users",
            "sqlite_admin_users_http",
            "sqlite_local_presence_now",
            "sqlite_local_presence_now_http",
            "sqlite_server",
        ] {
            assert_eq!(selected.iter().filter(|name| **name == target).count(), 1);
        }
        assert!(SQLITE_LOCAL_AUTH.args.contains(&"--ignored"));
        assert!(SQLITE_LOCAL_AUTH.args.contains(&"--test-threads=1"));
        let server_args = SERVER_EMBEDDINGS_HTTP_SQL.args;
        let exact = server_args
            .iter()
            .position(|arg| *arg == "--exact")
            .unwrap();
        assert_eq!(
            &server_args[exact + 1..],
            &[
                "compiled_server_embeddings_authorizes_batches_persists_and_reopens",
                "--test-threads=1"
            ]
        );

        let phases = qualification_checks();
        let mut prior = phases
            .iter()
            .position(|p| *p == PRESENCE_SERVER_HTTP)
            .unwrap();
        let audit = phases.iter().position(|p| *p == AUDIT).unwrap();
        for (phase, contract) in [
            (
                ADMIN_UPSTREAM_LOGIN_HTTP,
                "broker_admin_upstream_login_http_contract",
            ),
            (
                ADMIN_UPSTREAM_LOGIN_UNCERTAINTY,
                "broker_admin_upstream_login_uncertainty_contract",
            ),
            (
                ADMIN_UPSTREAM_LOGIN_CONFIG,
                "broker_admin_upstream_login_configuration_contract",
            ),
        ] {
            assert_eq!(phase.program, "cargo");
            assert_eq!(
                phase.args,
                &[
                    "test",
                    "--locked",
                    "--offline",
                    "-j4",
                    "-p",
                    "broker-server",
                    "--test",
                    "admin_upstream_login",
                    "--",
                    "--ignored",
                    "--exact",
                    contract,
                    "--test-threads=1"
                ]
            );
            let position = phases.iter().position(|p| *p == phase).unwrap();
            assert!(prior < position && position < audit);
            prior = position;
        }
    }
    #[test]
    fn hub_storage_process_build_precedes_its_real_contract_and_audit() {
        let phases = qualification_checks();
        let position = |phase| phases.iter().position(|p| *p == phase).unwrap();
        assert!(position(ADMIN_UPSTREAM_LOGIN_CONFIG) < position(HUB_STORAGE_FIXTURE_BUILD));
        assert!(position(HUB_STORAGE_FIXTURE_BUILD) < position(HUB_STORAGE_FIXTURE_CONTRACT));
        assert!(position(HUB_STORAGE_FIXTURE_CONTRACT) < position(AUDIT));
        assert_eq!(HUB_STORAGE_FIXTURE_BUILD.program, "cargo");
        assert_eq!(
            HUB_STORAGE_FIXTURE_BUILD.args,
            &[
                "build",
                "--locked",
                "--offline",
                "-j4",
                "-p",
                "broker-presence",
                "--example",
                "hub_storage_fixture"
            ]
        );
        assert_eq!(HUB_STORAGE_FIXTURE_CONTRACT.program, "cargo");
        assert_eq!(
            HUB_STORAGE_FIXTURE_CONTRACT.args,
            &[
                "test",
                "--locked",
                "--offline",
                "-j4",
                "-p",
                "broker-presence",
                "--example",
                "hub_storage_fixture",
                "--",
                "--ignored",
                "--exact",
                "tests::hub_storage_fixture_native_sts_contract",
                "--test-threads=1"
            ]
        );
    }
    #[test]
    fn storage_contract_commands_are_in_the_saved_phases() {
        assert_eq!(
            PROJECT_CORPUS_HTTP_STS.args,
            &[
                "test",
                "--locked",
                "-p",
                "broker-presence",
                "--test",
                "project_corpus_storage_credentials_http",
                "--",
                "--ignored",
                "--exact",
                "project_corpus_storage_credentials_http_contract",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            USER_MEMORY_HTTP_STS.args,
            &[
                "test",
                "--locked",
                "-p",
                "broker-presence",
                "--test",
                "user_memory_storage_credentials_http",
                "--",
                "--ignored",
                "--exact",
                "user_memory_storage_credentials_http_contract",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            GLOBAL_HUB_HTTP_STS.args,
            &[
                "test",
                "--locked",
                "-p",
                "broker-presence",
                "--test",
                "global_hub_storage_credentials_http",
                "--",
                "--ignored",
                "--exact",
                "global_hub_storage_credentials_http_contract",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            PROJECT_HUB_METADATA_EVENTS_STS.args,
            &[
                "test",
                "--locked",
                "-p",
                "broker-presence",
                "--test",
                "project_hub_metadata_events_storage",
                "--",
                "--ignored",
                "--exact",
                "project_hub_metadata_events_storage_contract",
                "--test-threads=1",
            ]
        );
        let phases = qualification_checks();
        assert!(phases.contains(&AWS_HUB_STORAGE));
        assert_eq!(phases[1], PROJECT_CORPUS_HTTP_STS);
        assert_eq!(phases[2], USER_MEMORY_HTTP_STS);
        assert_eq!(phases[3], GLOBAL_HUB_HTTP_STS);
        assert_eq!(phases[4], PROJECT_HUB_METADATA_EVENTS_STS);
        assert_eq!(phases[5], FILESYSTEM_SESSION);
        assert_eq!(phases[6], FILESYSTEM_OBJECTS);
        assert_eq!(phases[7], FILESYSTEM_LISTING);
        assert_eq!(phases[8], FILESYSTEM_MULTIPART);
        assert_eq!(phases[9], FILESYSTEM_S3_GATEWAY);
        assert_eq!(phases[10], MIXED_STORAGE_HTTP_STS);
        assert_eq!(phases[11], BROKER_STORAGE_SERVER_STARTUP);
        assert_eq!(phases[12], OIDC_CODE_HTTP);
        assert_eq!(phases[13], OIDC_REFRESH_HTTP);
        assert_eq!(phases[14], OIDC_FEDERATED_PG);
        assert_eq!(phases[15], OIDC_FEDERATED_HTTP);
        assert_eq!(phases[16], LOCAL_FEDERATED_ISOLATION_PG);
        assert_eq!(phases[17], ADMIN_SESSION_HTTP);
        assert_eq!(phases[18], ADMIN_LOCAL_BEARER_HTTP);
        assert_eq!(phases[19], ADMIN_UPSTREAM_BEARER_HTTP);
        assert_eq!(phases[20], ADMIN_COOKIE_PG);
        assert_eq!(phases[21], ADMIN_COOKIE_HTTP);
        assert_eq!(phases[22], LOCAL_PASSWORD_ADMISSION_PG);
        assert_eq!(phases[23], LOCAL_PASSWORD_ADMISSION_UNCERTAIN);
        assert_eq!(phases[24], LOCAL_PASSWORD_CAPTCHA_SQL);
        assert_eq!(phases[25], LOCAL_PASSWORD_CAPACITY_PG);
        assert_eq!(phases[26], ADMIN_LOCAL_LOGIN_HTTP);
        assert_eq!(phases[27], ADMIN_LOCAL_LOGIN_FAILURE_HTTP);
        assert_eq!(phases[28], ADMIN_LOCAL_LOGIN_UNCERTAINTY_HTTP);
        assert_eq!(phases[29], ADMIN_LOCAL_LOGIN_CONFIG);
        assert_eq!(phases[30], UPSTREAM_BROWSER_LOGIN_PG);
        assert_eq!(phases[31], UPSTREAM_BROWSER_UNCERTAINTY_PG);
        assert_eq!(phases[32], ADMIN_FEDERATED_COOKIE_PG);
        assert_eq!(phases[33], ADMIN_FEDERATED_COOKIE_UNCERTAINTY_PG);
        assert_eq!(phases[34], ADMIN_READ_PG);
        assert_eq!(phases[35], ADMIN_READ_HTTP);
        assert_eq!(phases[36], PROJECT_ACCESS_HTTP);
        assert_eq!(phases[37], PRESENCE_SERVER_HTTP);
        assert_eq!(phases[38], ADMIN_UPSTREAM_LOGIN_HTTP);
        assert_eq!(phases[39], ADMIN_UPSTREAM_LOGIN_UNCERTAINTY);
        assert_eq!(phases[40], ADMIN_UPSTREAM_LOGIN_CONFIG);
        assert_eq!(phases[41], HUB_STORAGE_FIXTURE_BUILD);
        assert_eq!(phases[42], HUB_STORAGE_FIXTURE_CONTRACT);
        assert_eq!(phases[43], OIDC_REGISTRATION_HTTP);
        assert_eq!(phases[44], OIDC_REGISTRATION_UNCERTAINTY);
        assert_eq!(phases[45], OIDC_BROWSER_CALLBACK_HTTP);
        assert_eq!(phases[46], LOCAL_LOGIN_RUNTIME_HTTP);
        assert_eq!(phases[47], OIDC_BROWSER_ADMISSION_PG);
        assert_eq!(phases[48], OIDC_BROWSER_AUTHORIZATION_HTTP);
        assert_eq!(phases[49], OIDC_DISCOVERY_HTTP);
        assert_eq!(phases[50], SERVER_EMBEDDINGS_HTTP_SQL);
        assert_eq!(phases[51], OIDC_REVOCATION_PG);
        assert_eq!(phases[52], OIDC_REVOCATION_FEDERATED_PG);
        assert_eq!(phases[53], OIDC_REVOCATION_HTTP);
        assert_eq!(phases[54], OIDC_USERINFO_HTTP);
        assert_eq!(phases[55], OIDC_INTROSPECTION_HTTP);
        assert_eq!(phases[56], OIDC_END_SESSION_HTTP);
        assert_eq!(phases[57], DEVICE_PG);
        assert_eq!(phases[58], SQLITE_LOCAL_AUTH);
        assert_eq!(phases[59], AUDIT);
        for (phase, target) in [
            (
                ADMIN_LOCAL_LOGIN_HTTP,
                "broker_admin_local_login_http_contract",
            ),
            (
                ADMIN_LOCAL_LOGIN_FAILURE_HTTP,
                "broker_admin_local_login_failure_contract",
            ),
            (
                ADMIN_LOCAL_LOGIN_UNCERTAINTY_HTTP,
                "broker_admin_local_login_uncertainty_contract",
            ),
            (
                ADMIN_LOCAL_LOGIN_CONFIG,
                "broker_admin_local_login_configuration_contract",
            ),
        ] {
            assert_eq!(phase.program, "cargo");
            assert_eq!(
                phase.args,
                &[
                    "test",
                    "--locked",
                    "--offline",
                    "-p",
                    "broker-server",
                    "--test",
                    "admin_local_login",
                    "--",
                    "--ignored",
                    "--exact",
                    target,
                    "--test-threads=1",
                ]
            );
        }
        assert_eq!(
            ADMIN_SESSION_HTTP.args,
            &[
                "test",
                "--locked",
                "--offline",
                "-p",
                "broker-server",
                "--test",
                "admin_session",
                "--",
                "--ignored",
                "--exact",
                "broker_admin_session_http_contract",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            OIDC_CODE_HTTP.args,
            &[
                "test",
                "--locked",
                "--offline",
                "-p",
                "broker-server",
                "--test",
                "oauth_token",
                "--",
                "--ignored",
                "--exact",
                "broker_oidc_authorization_code_http_contract",
                "--test-threads=1"
            ]
        );
        assert_eq!(
            OIDC_REFRESH_HTTP.args,
            &[
                "test",
                "--locked",
                "--offline",
                "-p",
                "broker-server",
                "--test",
                "oauth_token",
                "--",
                "--ignored",
                "--exact",
                "broker_oidc_refresh_http_contract",
                "--test-threads=1"
            ]
        );
        assert_eq!(
            BROKER_STORAGE_SERVER_STARTUP.args,
            &[
                "test",
                "--locked",
                "--offline",
                "-p",
                "broker-server",
                "--test",
                "startup",
                "--",
                "--ignored",
                "--exact",
                "broker_storage_server_startup_contract",
                "--test-threads=1"
            ]
        );
        assert_eq!(
            MIXED_STORAGE_HTTP_STS.args,
            &[
                "test",
                "--locked",
                "--offline",
                "-p",
                "broker-presence",
                "--test",
                "mixed_storage_credentials_http",
                "--",
                "--ignored",
                "--exact",
                "mixed_storage_credentials_http_contract",
                "--test-threads=1"
            ]
        );
        assert_eq!(
            FILESYSTEM_S3_GATEWAY.args,
            &[
                "test",
                "--locked",
                "--offline",
                "-p",
                "broker-storage",
                "--test",
                "filesystem_s3_gateway",
                "--",
                "--ignored",
                "--exact",
                "filesystem_s3_gateway_postgres_contract",
                "--test-threads=1"
            ]
        );
        assert_eq!(
            FILESYSTEM_MULTIPART.args,
            &[
                "test",
                "--locked",
                "--offline",
                "-p",
                "broker-storage",
                "--test",
                "filesystem_multipart",
                "--",
                "--ignored",
                "--exact",
                "filesystem_multipart_postgres_contract",
                "--test-threads=1"
            ]
        );
        assert_eq!(
            FILESYSTEM_LISTING.args,
            &[
                "test",
                "--locked",
                "--offline",
                "-p",
                "broker-storage",
                "--test",
                "filesystem_listing",
                "--",
                "--ignored",
                "--exact",
                "filesystem_listing_postgres_contract",
                "--test-threads=1"
            ]
        );
        assert_eq!(
            FILESYSTEM_OBJECTS.args,
            &[
                "test",
                "--locked",
                "--offline",
                "-p",
                "broker-storage",
                "--test",
                "filesystem_objects",
                "--",
                "--ignored",
                "--exact",
                "filesystem_objects_postgres_contract",
                "--test-threads=1"
            ]
        );
        assert_eq!(
            FILESYSTEM_SESSION.args,
            &[
                "test",
                "--locked",
                "-p",
                "broker-storage",
                "--test",
                "filesystem_sessions",
                "--",
                "--ignored",
                "--exact",
                "filesystem_sessions_postgres_contract",
                "--test-threads=1"
            ]
        );
        assert!(qualification_checks().contains(&AWS_HUB_STORAGE));
        assert_eq!(
            AWS_HUB_STORAGE.args,
            &[
                "test",
                "--locked",
                "-p",
                "broker-storage",
                "--test",
                "aws_hub_storage",
                "--",
                "--ignored",
                "--exact",
                "aws_hub_storage_sts_s3_contract",
                "--test-threads=1",
            ]
        );
    }
    #[test]
    fn unknown_events_fail_closed() {
        for input in ["", "pre_commit", "post-commit", "PRE-COMMIT"] {
            assert!(parse_event(input).is_none());
        }
    }
    #[test]
    fn dynamic_registration_phases_preserve_exact_contracts_before_audit() {
        let phases = qualification_checks();
        let position = |phase| phases.iter().position(|p| *p == phase).unwrap();
        assert!(position(OIDC_REGISTRATION_HTTP) < position(OIDC_REGISTRATION_UNCERTAINTY));
        assert!(position(OIDC_REGISTRATION_UNCERTAINTY) < position(AUDIT));
        for (phase, name) in [
            (
                OIDC_REGISTRATION_HTTP,
                "broker_oidc_registration_http_contract",
            ),
            (
                OIDC_REGISTRATION_UNCERTAINTY,
                "broker_oidc_registration_uncertainty_contract",
            ),
        ] {
            assert_eq!(phase.program, "cargo");
            assert_eq!(
                phase.args,
                &[
                    "test",
                    "--locked",
                    "--offline",
                    "-p",
                    "broker-server",
                    "--test",
                    "oauth_token",
                    "--",
                    "--ignored",
                    "--exact",
                    name,
                    "--test-threads=1"
                ]
            );
        }
    }
}
