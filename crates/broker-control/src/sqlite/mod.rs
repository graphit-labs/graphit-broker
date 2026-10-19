//! Private file-backed SQLite persistence. Metadata grants no authority.
mod config;
mod error;
mod executor;
mod files;
mod flow;
mod schema;

pub use config::SqliteControlConfig;
pub use error::SqliteControlError;
pub use flow::{
    SqliteAdminBrokerSessions, SqliteAdminCookieSessions, SqliteAdminGrants,
    SqliteAdminLocalBearerSessions, SqliteAdminRbac, SqliteAdminReads, SqliteAdminSessions,
    SqliteAdminUpstreamSessions, SqliteAdminUsers, SqliteAdmittedLocalPasswords,
    SqliteBrokerHubAccessResolver, SqliteBrokerInstanceInventoryReader,
    SqliteBrokerInstanceRegistrar, SqliteBrokerProjectAuthorizer, SqliteBrokerStorageAuthorizer,
    SqliteControlStore, SqliteDeviceAuthorizations, SqliteEmbeddingAdmissions,
    SqliteEmbeddingCache, SqliteInstanceInventories, SqliteInstanceInventoryCandidates,
    SqliteLocalAdminCookieSessions, SqliteLocalAdminReads, SqliteLocalAuthService,
    SqliteLocalBearerVerifier, SqliteLocalHubAccessResolver, SqliteLocalIdentities,
    SqliteLocalInstanceInventoryLister, SqliteLocalInstanceInventoryReader,
    SqliteLocalInstanceRegistrar, SqliteLocalPasswordVerifier, SqliteLocalProjectAuthorizer,
    SqliteLocalStorageAuthorizer, SqliteNowChannelAuthorizer, SqliteOidcAuthorizationService,
    SqliteOidcEndSession, SqliteOidcIntrospection, SqliteOidcRefresh,
    SqliteOidcRegistrationService, SqliteOidcRevocation, SqliteOidcTokenExchange,
    SqliteOidcUserInfo, SqliteRerankAdmissions, SqliteResourceGrants, SqliteUpstreamLogins,
};

type Result<T> = std::result::Result<T, SqliteControlError>;
