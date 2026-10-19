use super::{SqliteControlStore, SqliteLocalBearerVerifier, SqliteResourceGrants};
use crate::{
    AuthenticatedStorageCaller, AuthorizedStorageGrant, BrokerAccessVerifier,
    LocalBearerStateError, LocalBearerVerificationError, ResourceGrantReadError,
    StorageAdmissionError, StorageScope,
    storage_admission::{FactoryBinding, StorageAuthentication, StorageIdentity},
    storage_policy::StoragePolicy,
};
use std::{fmt, num::NonZeroUsize, time::Instant};
/// Native admission borrows both its store and its actual verifier.
/// ~~~compile_fail
/// fn escape(s: &'static broker_control::SqliteControlStore, v: &broker_control::BrokerAccessVerifier)
///     -> broker_control::SqliteBrokerStorageAuthorizer<'static> {
///     s.broker_storage_authorizer(v, std::num::NonZeroUsize::new(65536).unwrap(), "configured").unwrap()
/// }
/// ~~~
/// A caller cannot escape its actual factory.
/// ~~~compile_fail
/// fn escape(s: &'static broker_control::SqliteControlStore, v: &'static broker_control::BrokerAccessVerifier, raw: &str)
///     -> broker_control::AuthenticatedStorageCaller<'static> {
///     let factory = s.broker_storage_authorizer(v, std::num::NonZeroUsize::new(65536).unwrap(), "configured").unwrap();
///     factory.authenticate(raw, &[], std::time::Instant::now()).unwrap()
/// }
/// ~~~
pub struct SqliteBrokerStorageAuthorizer<'a> {
    owner: &'a SqliteControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants: SqliteResourceGrants<'a>,
    default_route: String,
}
/// Opaque admission borrows the configured audience and physical store.
/// ~~~compile_fail
/// fn escape(s: &'static broker_control::SqliteControlStore, audience: &str)
///     -> broker_control::SqliteLocalStorageAuthorizer<'static> {
///     let cap = std::num::NonZeroUsize::new(65536).unwrap();
///     s.local_storage_authorizer(audience, cap, cap, "configured").unwrap()
/// }
/// ~~~
pub struct SqliteLocalStorageAuthorizer<'a> {
    owner: &'a SqliteControlStore,
    verifier: SqliteLocalBearerVerifier<'a>,
    grants: SqliteResourceGrants<'a>,
    default_route: String,
}
fn route(value: &str) -> Result<String, StorageAdmissionError> {
    let value = value.trim();
    if value.is_empty() {
        Err(StorageAdmissionError::InvalidConfiguration)
    } else {
        Ok(value.into())
    }
}
impl fmt::Debug for SqliteBrokerStorageAuthorizer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteBrokerStorageAuthorizer([REDACTED])")
    }
}
impl fmt::Debug for SqliteLocalStorageAuthorizer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalStorageAuthorizer([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn broker_storage_authorizer<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
        default_route: &str,
    ) -> Result<SqliteBrokerStorageAuthorizer<'a>, StorageAdmissionError> {
        Ok(SqliteBrokerStorageAuthorizer {
            owner: self,
            verifier,
            grants: self
                .resource_grants(grants_json_bytes)
                .map_err(|e| match e {
                    ResourceGrantReadError::InvalidLimits => {
                        StorageAdmissionError::InvalidConfiguration
                    }
                    other => other.into(),
                })?,
            default_route: route(default_route)?,
        })
    }
    pub fn local_storage_authorizer<'a>(
        &'a self,
        audience: &'a str,
        identity_json_bytes: NonZeroUsize,
        grants_json_bytes: NonZeroUsize,
        default_route: &str,
    ) -> Result<SqliteLocalStorageAuthorizer<'a>, StorageAdmissionError> {
        Ok(SqliteLocalStorageAuthorizer {
            owner: self,
            verifier: self
                .local_bearer_verifier(audience, identity_json_bytes)
                .map_err(|e| match e {
                    LocalBearerVerificationError::State(LocalBearerStateError::InvalidLimits) => {
                        StorageAdmissionError::InvalidConfiguration
                    }
                    other => other.into(),
                })?,
            grants: self
                .resource_grants(grants_json_bytes)
                .map_err(|e| match e {
                    ResourceGrantReadError::InvalidLimits => {
                        StorageAdmissionError::InvalidConfiguration
                    }
                    other => other.into(),
                })?,
            default_route: route(default_route)?,
        })
    }
}
impl SqliteBrokerStorageAuthorizer<'_> {
    pub fn authenticate<'s>(
        &'s self,
        raw: &str,
        required_scopes: &[String],
        original: Instant,
    ) -> Result<AuthenticatedStorageCaller<'s>, StorageAdmissionError> {
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(crate::ControlError::from)?;
        let auth = StorageAuthentication::new(
            StorageIdentity::Native(self.verifier.verify(raw, required_scopes, end)?),
            end,
        )?;
        Ok(AuthenticatedStorageCaller {
            binding: FactoryBinding::SqliteBroker(self),
            auth,
        })
    }
    pub async fn authorize_authenticated<'s>(
        &'s self,
        caller: AuthenticatedStorageCaller<'s>,
        scope: &StorageScope,
    ) -> Result<AuthorizedStorageGrant<'s>, StorageAdmissionError> {
        if !matches!(&caller.binding,FactoryBinding::SqliteBroker(factory) if std::ptr::eq(*factory,self))
        {
            return Err(StorageAdmissionError::InvalidConfiguration);
        }
        authorize(&self.grants, &self.default_route, caller, scope).await
    }
    pub async fn authorize<'s>(
        &'s self,
        raw: &str,
        required_scopes: &[String],
        scope: &StorageScope,
        original: Instant,
    ) -> Result<AuthorizedStorageGrant<'s>, StorageAdmissionError> {
        let caller = self.authenticate(raw, required_scopes, original)?;
        self.authorize_authenticated(caller, scope).await
    }
}
impl SqliteLocalStorageAuthorizer<'_> {
    pub async fn authenticate<'s>(
        &'s self,
        raw: &str,
        required_scopes: &[String],
        original: Instant,
    ) -> Result<AuthenticatedStorageCaller<'s>, StorageAdmissionError> {
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(crate::ControlError::from)?;
        let proof = self.verifier.verify(raw, required_scopes, end).await?;
        let auth = StorageAuthentication::new(StorageIdentity::Local(proof), end)?;
        Ok(AuthenticatedStorageCaller {
            binding: FactoryBinding::SqliteLocal(self),
            auth,
        })
    }
    pub async fn authorize_authenticated<'s>(
        &'s self,
        caller: AuthenticatedStorageCaller<'s>,
        scope: &StorageScope,
    ) -> Result<AuthorizedStorageGrant<'s>, StorageAdmissionError> {
        if !matches!(&caller.binding,FactoryBinding::SqliteLocal(factory) if std::ptr::eq(*factory,self))
        {
            return Err(StorageAdmissionError::InvalidConfiguration);
        }
        authorize(&self.grants, &self.default_route, caller, scope).await
    }
    pub async fn authorize<'s>(
        &'s self,
        raw: &str,
        required_scopes: &[String],
        scope: &StorageScope,
        original: Instant,
    ) -> Result<AuthorizedStorageGrant<'s>, StorageAdmissionError> {
        let caller = self.authenticate(raw, required_scopes, original).await?;
        self.authorize_authenticated(caller, scope).await
    }
}
async fn authorize<'a>(
    grants: &SqliteResourceGrants<'_>,
    default_route: &str,
    caller: AuthenticatedStorageCaller<'a>,
    scope: &StorageScope,
) -> Result<AuthorizedStorageGrant<'a>, StorageAdmissionError> {
    caller.check()?;
    // SQL owns transaction/COMMIT uncertainty classification; no outer timer.
    let snapshot = grants.read(caller.auth.end).await;
    if matches!(
        &snapshot,
        Err(ResourceGrantReadError::Control(
            crate::ControlError::OutcomeUncertain
        ))
    ) {
        return Err(ResourceGrantReadError::Control(crate::ControlError::OutcomeUncertain).into());
    }
    caller.check()?;
    let snapshot = snapshot?;
    let policy = StoragePolicy::compile(&snapshot, caller.auth.end);
    caller.check()?;
    let decision = policy?.evaluate(&caller.auth.identity, scope, default_route, caller.auth.end);
    caller.check()?;
    let decision = decision?.ok_or(StorageAdmissionError::Forbidden)?;
    let result = AuthorizedStorageGrant {
        auth: caller.auth,
        scope: scope.clone(),
        route: decision.route,
        revision: snapshot.revision(),
        access: decision.access,
    };
    result.check()?;
    Ok(result)
}
