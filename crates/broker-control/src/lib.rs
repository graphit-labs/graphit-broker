//! PostgreSQL and MySQL login flows and administrative session metadata; current local identity, SQL role snapshots and atomic role definition replacement.
//! Both SQL backends provide role definition replacement with fixed built-ins and known commit outcomes.
//! Owns SQL persistence; callers must authenticate and authorize administrative writes. Fetched identity/role data is not authority.
//!
//! Creation input has no caller-supplied creation timestamp:
//! ```compile_fail
//! fn input_created(input: &broker_control::NewAdminSession) {
//!     let _ = input.created_at();
//! }
//! ```
//! Session creation inputs and stored results retain one owner:
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<broker_control::NewAdminSession>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<broker_control::AdminSession>();
//! ```
//! The borrowed view cannot outlive its store:
//! ```compile_fail
//! fn escape(store: &broker_control::PostgresControlStore, limits: broker_control::SessionLimits)
//!     -> broker_control::AdminSessions<'static> {
//!     store.admin_sessions(limits).unwrap()
//! }
//! ```
//! MySQL never exports its physical connection or native proof:
//! ```compile_fail
//! fn escape(value: &broker_control::MySqlControlStore) {
//!     let _ = &value.connection;
//! }
//! ```
//! ```compile_fail
//! use broker_control::mysql::executor::Lease;
//! ```

//! Local identity views cannot outlive their owner.
//! ```compile_fail
//! fn escape(store: &broker_control::MySqlControlStore, limits: broker_control::IdentityReadLimits)
//!     -> broker_control::MySqlLocalIdentities<'static> { store.local_identities(limits).unwrap() }
//! ```
//! PostgreSQL identity views also borrow their store.
//! ```compile_fail
//! fn escape(store: &broker_control::PostgresControlStore, limits: broker_control::IdentityReadLimits)
//!     -> broker_control::PostgresLocalIdentities<'static> { store.local_identities(limits).unwrap() }
//! ```
//! ```compile_fail
//! fn require_default<T: Default>() {}
//! require_default::<broker_control::IdentityReadLimits>();
//! ```
//! ```compile_fail
//! fn expose(value: broker_control::LocalIdentitySnapshot) { let _ = value.username; }
//! ```

#[cfg(test)]
extern crate self as broker_control;
#[cfg(test)]
#[path = "../tests/support/admin_cookie.rs"]
#[allow(
    dead_code,
    reason = "genuine shared LOCAL fixture also serves cookie and admission cases"
)]
mod admin_cookie_fixture;
mod admin_cookie_session;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "shared owned PostgreSQL fixture for private CAPTCHA protocol tests"
)]
mod support;
pub use admin_cookie_session::{
    ADMIN_COOKIE_MAX_LIFETIME, AdminCookieLogout, AdminCookieLogoutDisposition,
    AdminCookieReadSession, AdminCookieSessionError, AdminCookieSessionLimits,
    AdminCookieSessionPolicy, AdminLoginPreparationError, IssuedAdminCookie, PreparedAdminLogin,
};
pub use service::PostgresAdminCookieSessions;
mod embedding_admission;
mod rerank_admission;
pub use rerank_admission::{RerankAdmission, RerankAdmissionError, RerankAdmissionLimits};
mod embedding_cache;
pub use embedding_admission::{
    EmbeddingAdmission, EmbeddingAdmissionError, EmbeddingAdmissionLimits,
};
pub use embedding_cache::{
    EmbeddingCacheEntry, EmbeddingCacheError, EmbeddingCacheKey, EmbeddingCacheLimits,
    EmbeddingCacheProvenance, EmbeddingCacheWrite,
};
pub use service::PostgresEmbeddingCache;
pub use service::{PostgresEmbeddingAdmissions, PostgresRerankAdmissions};
mod admin_broker_session;
mod admin_grants;
mod admin_rbac;
mod admin_read;
mod admin_users;
pub use admin_grants::{
    AdminGrantError, AdminGrantInput, AdminGrantRequest, AdminGrantResult, AdminGrantRoutes,
    parse_grant_if_match,
};
pub use admin_rbac::{AdminRbacError, AdminRbacRequest, AdminRbacResult};
pub use admin_read::{
    AdminReadAuthentication, AdminReadError, AdminReadKind, AdminReadLimits, AdminReadRequest,
    AdminReadResult,
};
pub use admin_users::{
    AdminServiceCredentialInput, AdminUserInput, AdminUsersError, AdminUsersLimits,
    AdminUsersRequest, AdminUsersResult,
};
pub use service::PostgresAdminRbac;
pub use service::PostgresAdminReads;
pub use service::{PostgresAdminGrants, PostgresAdminUsers};
mod admin_local_bearer_session;
mod admin_upstream_session;
mod upstream_oidc;
pub use admin_broker_session::{
    AdminBrokerSession, AdminBrokerSessionError, AdminBrokerSessionLimits, new_admin_request_id,
};
pub use admin_local_bearer_session::AdminLocalBearerSession;
pub use admin_upstream_session::AdminUpstreamSession;
pub use jsonwebtoken::Algorithm as UpstreamSignatureAlgorithm;
pub use service::PostgresAdminBrokerSessions;
pub use service::PostgresAdminLocalBearerSessions;
pub use service::PostgresAdminUpstreamSessions;
pub use service::{
    PostgresUpstreamLogins, UPSTREAM_LOGIN_STATE_BYTES, upstream_login_purpose_hint,
};
pub use upstream_oidc::{
    IssuedUpstreamAuthorization, UpstreamAccessPolicy, UpstreamBearerVerifier,
    UpstreamBrowserClaimsSource, UpstreamBrowserClient, UpstreamBrowserOption,
    UpstreamClaimPredicate, UpstreamClaimSelectors, UpstreamLoginCallback, UpstreamLoginError,
    UpstreamLoginFailure, UpstreamProviderConfig, UpstreamReadLimits, VerifiedUpstreamLogin,
};
mod broker_instance_inventory_read;
mod broker_instance_registration;
mod config;
mod error;
mod flow;
mod hub_access;
mod identity;
mod instance_inventory_read;
mod instance_list;
mod instance_read;
mod instance_registration;
mod instance_registry;
mod local_bearer;
mod local_bearer_verifier;
mod mysql;
mod oidc_access_grant;
mod presence_authorization;
mod project_authorization;
mod resource_grants;
mod resource_policy;
mod storage_admission;
mod storage_policy;
pub use hub_access::{HubAccessError, HubAccessResolution, HubProjectSelector};
pub use service::{PostgresBrokerStorageAuthorizer, PostgresLocalStorageAuthorizer};
pub use storage_admission::{
    AuthenticatedStorageCaller, AuthorizedStorageGrant, StorageAdmissionError, StorageModule,
    StorageOperation, StorageScope,
};
mod schema;
mod service;
mod session;
pub use broker_instance_inventory_read::{
    AuthorizedBrokerInstanceInventory, BrokerInstanceInventoryReadError,
};
pub use broker_instance_registration::BrokerInstanceRegistrationError;
pub use config::{
    ConnectionLimits, PoolConfig, PostgresConfig, PostgresCredentials, PostgresEndpoint,
};
pub use error::ControlError;
pub use flow::{FlowContinuation, FlowLimits, FlowPurpose, OidcFlow};
pub use identity::{
    IdentityInputError, IdentityReadLimits, LocalIdentityKind, LocalIdentityRead,
    LocalIdentityReference, LocalIdentitySnapshot, LocalIdentityUnavailable, SystemAction,
    SystemPermission,
};
pub use instance_inventory_read::{AuthorizedInstanceInventory, InstanceInventoryReadError};
pub use instance_list::{
    AuthorizedInstanceList, AuthorizedInstanceListItem, InstanceListError, InstanceListQuery,
};
pub use instance_read::{InstanceReadError, StoredInstanceInventory};
pub use instance_registration::InstanceRegistrationError;
pub use instance_registry::{
    InstanceInventory, InstanceOwner, InstanceProjectVersions, InstanceRegistryError,
    RegistrationChange, RegistrationResult,
};
pub use local_bearer::{LocalBearerKind, LocalBearerState, LocalBearerStateError, LocalBearerUser};
pub use local_bearer_verifier::{LocalBearerVerificationError, VerifiedLocalBearer};
pub use oidc_access_grant::{
    OidcAccessGrantReadError, OidcAccessGrantSnapshot, OidcClientApplicationType,
    OidcCurrentLocalUser, OidcDynamicClientRegistration, StoredOidcPrincipal,
};
pub use presence_authorization::{
    AuthorizedLocalPresence, PresenceAuthorizationError, PresenceCapability,
};
pub use project_authorization::{
    AuthorizedLocalProjectAccess, ProjectAuthorizationError, ProjectResourceAction,
    ProjectResourceModule,
};
pub use resource_grants::{ResourceGrantReadError, ResourceGrantRule, ResourceGrantSnapshot};
pub use service::PostgresBrokerInstanceInventoryReader;
pub use service::PostgresBrokerInstanceRegistrar;
pub use service::{
    PostgresControlStore, PostgresInstanceInventories, PostgresInstanceInventoryCandidates,
    PostgresLocalBearerStates, PostgresLocalBearerVerifier, PostgresLocalIdentities,
    PostgresLocalInstanceInventoryLister, PostgresLocalInstanceInventoryReader,
    PostgresLocalInstanceRegistrar, PostgresLocalPresenceAuthorizer,
    PostgresLocalProjectAuthorizer, PostgresOidcAccessGrants, PostgresResourceGrants,
};

pub use session::{
    AdminSession, AdminSessions, NewAdminSession, SessionClaimRoles, SessionLimits,
    SessionPrincipal, SessionProfile, SessionRevocation,
};

pub use mysql::{
    CleanupReason, MySqlAdminSessions, MySqlControlConfig, MySqlControlError, MySqlControlStore,
    MySqlLocalIdentities, MysqlAdmissionLimits, MysqlBudgets, MysqlCatalogLimits,
    MysqlConnectionLimits, MysqlCredentials, MysqlEndpoint, RequiredCapability, SchemaReason,
    UnprovenReason,
};

mod broker_access;
pub use broker_access::{BrokerAccessError, BrokerAccessVerifier, VerifiedBrokerAccess};

mod broker_project_authorization;
pub use broker_project_authorization::{
    AuthorizedBrokerProjectAccess, BrokerProjectAuthorizationError,
};
pub use service::PostgresBrokerProjectAuthorizer;
mod broker_presence_authorization;
pub use broker_presence_authorization::{
    AuthorizedBrokerPresence, BrokerPresenceAuthorizationError,
};
pub use service::PostgresBrokerPresenceAuthorizer;
pub use service::{PostgresBrokerHubAccessResolver, PostgresLocalHubAccessResolver};

mod broker_access_issuer;
mod oidc_end_session;
mod oidc_introspection;
mod oidc_refresh;
mod oidc_revocation;
pub use oidc_end_session::OidcEndSessionInput;
pub use oidc_introspection::{OidcIntrospection, OidcIntrospectionError};
pub use service::PostgresOidcEndSession;
pub use service::PostgresOidcIntrospection;
mod oidc_userinfo;
pub use oidc_userinfo::{OidcUserInfo, OidcUserInfoError};
pub use service::PostgresOidcUserInfo;
mod oidc_token_exchange;
pub use broker_access_issuer::{
    BrokerAccessIssueError, BrokerAccessIssuer, BrokerAccessTokenInput, BrokerIdTokenInput,
};
pub use oidc_refresh::OidcRefreshInput;
pub use oidc_revocation::OidcRevocationInput;
pub use oidc_token_exchange::{
    OidcTokenExchangeError, OidcTokenExchangeInput, OidcTokenExchangePolicy,
    OidcTokenExchangeResult,
};
pub use service::PostgresOidcRefresh;
pub use service::PostgresOidcRevocation;
pub use service::PostgresOidcTokenExchange;

mod local_administrator;
mod local_captcha;
mod local_password;
pub use local_administrator::{
    LocalAdministratorBootstrapError, validate_initial_administrator_password,
};
pub use local_captcha::{
    LocalCaptcha, LocalCaptchaChallenge, LocalCaptchaConfiguration, LocalCaptchaProvider,
};
mod local_password_admission;
pub use local_password::{
    LocalPasswordEngine, LocalPasswordVerificationError, VerifiedLocalPassword,
};
pub use local_password_admission::{
    AdmittedLocalPasswordChange, LocalPasswordAdmission, LocalPasswordAdmissionError,
    LocalPasswordAdmissionPolicy,
};
pub use service::PostgresAdmittedLocalPasswords;
pub use service::PostgresLocalPasswordVerifier;

mod local_auth;
pub use local_auth::{
    CompletedLocalLogin, LocalAuthError, LocalAuthPolicy, LocalAuthStage, LocalAuthStep,
    LocalMfaAttemptLimiter, LocalMfaAttemptPolicy, OidcLoginPreparationError, PendingLocalAuth,
    PreparedOidcLogin,
};
pub use service::PostgresLocalAuthService;

mod oidc_registration;
pub use oidc_registration::{
    OIDC_REGISTRATION_BODY_BYTES, OidcRegistrationError, RegisteredOidcClient,
};
pub use service::PostgresOidcRegistrationService;

mod oidc_authorization;
pub use oidc_authorization::{
    AuthorizedOidcAuthorization, BrowserOidcAuthorization, OidcAuthorizationConfiguration,
    OidcAuthorizationError, OidcAuthorizationInput, OidcAuthorizationLimits,
    OidcAuthorizationPolicy, OidcAuthorizationRejectionCode, OidcAuthorizationRequestInfo,
    OidcAuthorizationResponseMode, OidcAuthorizationResponseTarget, PendingOidcAuthorization,
    RejectedOidcAuthorization,
};
pub use service::PostgresOidcAuthorizationService;

mod now_channel;
pub use now_channel::{
    AuthorizedNowProjectSubscriber, AuthorizedNowPublisher, AuthorizedNowSubscriber,
    NowChannelAuthorizationError, NowReadMask, PresenceChannel,
};
pub use service::PostgresNowChannelAuthorizer;

mod device;
pub use device::{
    DEVICE_GRANT_TYPE, DeviceAccessToken, DeviceAuthorizationCodes, DeviceAuthorizationPolicy,
    DeviceConsent, DeviceError, normalize_device_user_code,
};
pub use service::PostgresDeviceAuthorizations;

mod sqlite;
pub use sqlite::{
    SqliteAdminBrokerSessions, SqliteAdminCookieSessions, SqliteAdminGrants,
    SqliteAdminLocalBearerSessions, SqliteAdminRbac, SqliteAdminReads, SqliteAdminSessions,
    SqliteAdminUpstreamSessions, SqliteAdminUsers, SqliteAdmittedLocalPasswords,
    SqliteBrokerHubAccessResolver, SqliteBrokerInstanceInventoryReader,
    SqliteBrokerInstanceRegistrar, SqliteBrokerProjectAuthorizer, SqliteBrokerStorageAuthorizer,
    SqliteControlConfig, SqliteControlError, SqliteControlStore, SqliteDeviceAuthorizations,
    SqliteEmbeddingAdmissions, SqliteEmbeddingCache, SqliteInstanceInventories,
    SqliteInstanceInventoryCandidates, SqliteLocalAdminCookieSessions, SqliteLocalAdminReads,
    SqliteLocalAuthService, SqliteLocalBearerVerifier, SqliteLocalHubAccessResolver,
    SqliteLocalIdentities, SqliteLocalInstanceInventoryLister, SqliteLocalInstanceInventoryReader,
    SqliteLocalInstanceRegistrar, SqliteLocalPasswordVerifier, SqliteLocalProjectAuthorizer,
    SqliteLocalStorageAuthorizer, SqliteNowChannelAuthorizer, SqliteOidcAuthorizationService,
    SqliteOidcEndSession, SqliteOidcIntrospection, SqliteOidcRefresh,
    SqliteOidcRegistrationService, SqliteOidcRevocation, SqliteOidcTokenExchange,
    SqliteOidcUserInfo, SqliteRerankAdmissions, SqliteResourceGrants, SqliteUpstreamLogins,
};
