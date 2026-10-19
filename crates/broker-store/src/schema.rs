//! Closed SQL schema. This module performs no I/O or authorization.
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dialect {
    Sqlite,
    Postgres,
    Mysql,
}

/// Data describing the current format; successful validation grants no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaVersion;
impl SchemaVersion {
    pub const FORMAT: &'static str = "rust-broker-v1";
    pub const EPOCH: i64 = 2;
    pub fn validate(format: &str, epoch: i64) -> Result<Self, SchemaMismatch> {
        if format == Self::FORMAT && epoch == Self::EPOCH {
            Ok(Self)
        } else {
            Err(SchemaMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaMismatch;
impl fmt::Display for SchemaMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unsupported broker database schema; recreate the database")
    }
}
impl std::error::Error for SchemaMismatch {}

mod model;
mod mysql;
use CheckCondition::{EqualOne, Positive};
use ColumnType::{BigInt, LargeText, SmallInt, Text, Varchar};
pub use model::{
    CheckCondition, ColumnDefault, ColumnDefinition, ColumnType, ForeignKeyDefinition,
    PrimaryKeyDefinition, TableDefinition,
};
pub use mysql::{
    MysqlCheckShape, MysqlColumnShape, MysqlForeignKeyShape, MysqlIndexShape, MysqlTableShape,
};

const fn column(name: &'static str, kind: ColumnType, not_null: bool) -> ColumnDefinition {
    ColumnDefinition::new(name, kind, not_null)
}
const fn primary(columns: &'static [&'static str], inline: bool) -> PrimaryKeyDefinition {
    PrimaryKeyDefinition::new(columns, inline)
}
const fn foreign(
    column: &'static str,
    target: Table,
    target_column: &'static str,
) -> ForeignKeyDefinition {
    ForeignKeyDefinition::new(column, target, target_column)
}

macro_rules! tables {
    ($( $variant:ident => ($name:literal, [$($column:expr),+ $(,)?], $primary:expr, [$($foreign:expr),* $(,)?]) ),+ $(,)?) => {
        /// Fixed inventory. External identifiers cannot select or construct SQL.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum Table { $( $variant ),+ }
        pub const TABLES: &[Table] = &[$( Table::$variant ),+];
        impl Table {
            pub const fn definition(self) -> &'static TableDefinition {
                match self { $( Self::$variant => {
                    const DEFINITION: TableDefinition = TableDefinition::new($name, &[$($column),+], $primary, &[$($foreign),*]);
                    &DEFINITION
                } ),+ }
            }
            pub const fn name(self) -> &'static str { self.definition().name() }
            pub fn create_statement(self, dialect: Dialect) -> String { self.definition().render(dialect) }
            pub fn mysql_shape(self) -> MysqlTableShape { MysqlTableShape::derive(self.definition()) }
        }
    };
}

tables! {
    SchemaMeta => ("schema_meta", [
        column("id", SmallInt, false).with_check(EqualOne),
        column("format", Varchar(64), true),
        column("epoch", BigInt, true).with_check(Positive)
    ], primary(&["id"], true), []),
    Roles => ("roles", [column("name", Varchar(128), false), column("created_at", BigInt, true)], primary(&["name"], true), []),
    RolePermissions => ("role_permissions", [column("role", Varchar(128), true), column("action", Varchar(128), true)], primary(&["role", "action"], false), [foreign("role", Table::Roles, "name")]),
    RoleAssignments => ("role_assignments", [column("subject", Varchar(512), true), column("role", Varchar(128), true), column("created_at", BigInt, true)], primary(&["subject", "role"], false), [foreign("role", Table::Roles, "name")]),
    AdminSessions => ("admin_sessions", [
        column("token_hash", Varchar(64), false), column("subject", Varchar(512), true), column("name", Varchar(512), true), column("email", Varchar(512), true), column("csrf_token", Varchar(128), true), column("expires_at", BigInt, true), column("created_at", BigInt, true)
    ], primary(&["token_hash"], true), []),
    AdminSessionPrincipals => ("admin_session_principals", [
        column("token_hash", Varchar(64), false), column("issuer", Varchar(1024), true), column("username", Varchar(512), true), column("organization", Varchar(512), true), column("teams_json", Text, true), column("local_user_revision", BigInt, true)
    ], primary(&["token_hash"], true), [foreign("token_hash", Table::AdminSessions, "token_hash")]),
    AdminSessionClaimRoles => ("admin_session_claim_roles", [column("token_hash", Varchar(64), false), column("claim_selector", Varchar(4096), true), column("roles_json", Text, true)], primary(&["token_hash"], true), [foreign("token_hash", Table::AdminSessions, "token_hash")]),
    OidcFlows => ("oidc_flows", [
        column("state_hash", Varchar(64), false), column("browser_binding_hash", Varchar(64), true), column("nonce", Varchar(128), true), column("pkce_verifier", Varchar(256), true), column("purpose", Varchar(32), true), column("continuation_json", Text, true), column("expires_at", BigInt, true), column("created_at", BigInt, true)
    ], primary(&["state_hash"], true), []),
    LocalUsers => ("local_users", [
        column("username", Varchar(128), false), column("subject", Varchar(512), true).with_unique(), column("identity_kind", Varchar(16), true), column("password_hash", Varchar(512), true), column("name", Varchar(512), true), column("email", Varchar(512), true), column("organization", Varchar(512), true), column("teams_json", Text, true), column("enabled", SmallInt, true), column("password_change_required", SmallInt, true), column("revision", BigInt, true), column("created_at", BigInt, true), column("updated_at", BigInt, true)
    ], primary(&["username"], true), []),
    LocalMfa => ("local_mfa", [column("subject", Varchar(512), false), column("secret_ciphertext", Text, true), column("last_totp_step", BigInt, true), column("confirmed_at", BigInt, true)], primary(&["subject"], true), [foreign("subject", Table::LocalUsers, "subject")]),
    LocalMfaRecoveryCodes => ("local_mfa_recovery_codes", [column("subject", Varchar(512), true), column("code_hash", Varchar(64), true), column("created_at", BigInt, true)], primary(&["subject", "code_hash"], false), [foreign("subject", Table::LocalUsers, "subject")]),
    LocalAuthChallenges => ("local_auth_challenges", [
        column("challenge_hash", Varchar(64), false), column("subject", Varchar(512), true), column("local_user_revision", BigInt, true), column("purpose", Varchar(32), true), column("binding_hash", Varchar(64), true), column("stage", Varchar(32), true), column("secret_ciphertext", Text, true), column("expires_at", BigInt, true), column("created_at", BigInt, true)
    ], primary(&["challenge_hash"], true), [foreign("subject", Table::LocalUsers, "subject")]),
    LocalTokens => ("local_tokens", [
        column("token_hash", Varchar(64), false), column("token_id", Varchar(128), true).with_unique(), column("token_kind", Varchar(16), true), column("subject", Varchar(512), true), column("oidc_subject", Varchar(128), true), column("principal_json", Text, true), column("client_id", Varchar(128), true), column("audience", Varchar(128), true), column("resource", Varchar(512), true).with_empty_default(), column("scopes_json", Text, true), column("local_user_revision", BigInt, true), column("family_id", Varchar(128), true), column("auth_time", BigInt, true), column("expires_at", BigInt, true), column("revoked_at", BigInt, false), column("consumed_at", BigInt, false), column("last_used_at", BigInt, false), column("created_at", BigInt, true)
    ], primary(&["token_hash"], true), []),
    OidcAuthRequests => ("oidc_auth_requests", [column("request_hash", Varchar(64), false), column("identity_subject", Varchar(512), true), column("request_json", Text, true), column("code_hash", Varchar(64), false).with_unique(), column("expires_at", BigInt, true), column("created_at", BigInt, true)], primary(&["request_hash"], true), []),
    OauthDeviceCodes => ("oauth_device_codes", [
        column("device_hash", Varchar(64), false), column("user_hash", Varchar(64), true).with_unique(), column("client_id", Varchar(128), true), column("scopes_json", Text, true), column("subject", Varchar(512), true), column("local_user_revision", BigInt, true), column("status", Varchar(16), true), column("interval_seconds", BigInt, true), column("last_poll_at", BigInt, false), column("expires_at", BigInt, true), column("created_at", BigInt, true)
    ], primary(&["device_hash"], true), []),
    OauthDynamicClients => ("oauth_dynamic_clients", [column("client_id", Varchar(128), false), column("client_name", Varchar(256), true), column("redirect_uris_json", Text, true), column("scopes_json", Text, true), column("application_type", Varchar(16), true), column("created_at", BigInt, true)], primary(&["client_id"], true), []),
    ResourceAclState => ("resource_acl_state", [column("id", SmallInt, false), column("revision", BigInt, true), column("updated_at", BigInt, true)], primary(&["id"], true), []),
    ResourceGrants => ("resource_grants", [column("id", Varchar(128), false), column("name", Varchar(256), true), column("access_kind", Varchar(32), true), column("principal", Varchar(512), true), column("s3_route", Varchar(128), true), column("created_at", BigInt, true), column("updated_at", BigInt, true)], primary(&["id"], true), []),
    GrantCapabilities => ("grant_capabilities", [column("grant_id", Varchar(128), true), column("value", Varchar(128), true)], primary(&["grant_id", "value"], false), [foreign("grant_id", Table::ResourceGrants, "id")]),
    GrantProjects => ("grant_projects", [column("grant_id", Varchar(128), true), column("value", Varchar(256), true)], primary(&["grant_id", "value"], false), [foreign("grant_id", Table::ResourceGrants, "id")]),
    GrantS3Operations => ("grant_s3_operations", [column("grant_id", Varchar(128), true), column("value", Varchar(32), true)], primary(&["grant_id", "value"], false), [foreign("grant_id", Table::ResourceGrants, "id")]),
    GrantS3Prefixes => ("grant_s3_prefixes", [column("grant_id", Varchar(128), true), column("value", Varchar(512), true)], primary(&["grant_id", "value"], false), [foreign("grant_id", Table::ResourceGrants, "id")]),
    BrokerInstances => ("broker_instances", [column("instance_id", Varchar(128), true), column("owner_issuer", Varchar(1024), true), column("owner_subject", Varchar(512), true), column("created_at", BigInt, true), column("updated_at", BigInt, true)], primary(&["instance_id"], true), []),
    BrokerInstanceProjectVersions => ("broker_instance_project_versions", [column("instance_id", Varchar(128), true), column("project_id", Varchar(26), true), column("position", BigInt, true).with_check(Positive), column("version", LargeText, true)], primary(&["instance_id", "project_id", "position"], false), [foreign("instance_id", Table::BrokerInstances, "instance_id")]),
    EmbeddingCache => ("embedding_cache", [column("compatibility_hash", Varchar(64), true), column("input_hash", Varchar(64), true), column("provider", Text, true), column("revision", Text, true), column("model", Text, true), column("input_type", Varchar(16), true), column("embedding_json", LargeText, true)], primary(&["compatibility_hash", "input_hash"], false), []),
}

/// Generate the fixed schema in foreign-key creation order from its single declaration.
pub fn schema_statements(dialect: Dialect) -> impl ExactSizeIterator<Item = String> {
    TABLES
        .iter()
        .map(move |table| table.create_statement(dialect))
}
