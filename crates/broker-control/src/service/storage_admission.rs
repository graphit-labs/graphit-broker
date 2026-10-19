use super::{
    PostgresControlStore, PostgresLocalBearerVerifier, PostgresResourceGrants, bounded_deadline,
};
use crate::{
    AuthenticatedStorageCaller, AuthorizedStorageGrant, BrokerAccessVerifier,
    LocalBearerStateError, LocalBearerVerificationError, ResourceGrantReadError,
    StorageAdmissionError, StorageScope,
    storage_admission::{FactoryBinding, StorageAuthentication, StorageIdentity},
    storage_policy::StoragePolicy,
};
use std::{fmt, num::NonZeroUsize, time::Instant};
pub struct PostgresBrokerStorageAuthorizer<'a> {
    owner: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants: PostgresResourceGrants<'a>,
    default_route: String,
}
pub struct PostgresLocalStorageAuthorizer<'a> {
    owner: &'a PostgresControlStore,
    verifier: PostgresLocalBearerVerifier<'a>,
    grants: PostgresResourceGrants<'a>,
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
impl fmt::Debug for PostgresBrokerStorageAuthorizer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresBrokerStorageAuthorizer([REDACTED])")
    }
}
impl fmt::Debug for PostgresLocalStorageAuthorizer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresLocalStorageAuthorizer([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn broker_storage_authorizer<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
        default_route: &str,
    ) -> Result<PostgresBrokerStorageAuthorizer<'a>, StorageAdmissionError> {
        Ok(PostgresBrokerStorageAuthorizer {
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
    ) -> Result<PostgresLocalStorageAuthorizer<'a>, StorageAdmissionError> {
        Ok(PostgresLocalStorageAuthorizer {
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
impl PostgresBrokerStorageAuthorizer<'_> {
    pub fn authenticate<'s>(
        &'s self,
        raw: &str,
        required_scopes: &[String],
        original: Instant,
    ) -> Result<AuthenticatedStorageCaller<'s>, StorageAdmissionError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        let auth = StorageAuthentication::new(
            StorageIdentity::Native(self.verifier.verify(raw, required_scopes, end)?),
            end,
        )?;
        Ok(AuthenticatedStorageCaller {
            binding: FactoryBinding::Broker(self),
            auth,
        })
    }
    pub async fn authorize_authenticated<'s>(
        &'s self,
        caller: AuthenticatedStorageCaller<'s>,
        scope: &StorageScope,
    ) -> Result<AuthorizedStorageGrant<'s>, StorageAdmissionError> {
        if !matches!(&caller.binding,FactoryBinding::Broker(factory) if std::ptr::eq(*factory,self))
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
impl PostgresLocalStorageAuthorizer<'_> {
    pub async fn authenticate<'s>(
        &'s self,
        raw: &str,
        required_scopes: &[String],
        original: Instant,
    ) -> Result<AuthenticatedStorageCaller<'s>, StorageAdmissionError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        let proof = self.verifier.verify(raw, required_scopes, end).await?;
        let auth = StorageAuthentication::new(StorageIdentity::Local(proof), end)?;
        Ok(AuthenticatedStorageCaller {
            binding: FactoryBinding::Local(self),
            auth,
        })
    }
    pub async fn authorize_authenticated<'s>(
        &'s self,
        caller: AuthenticatedStorageCaller<'s>,
        scope: &StorageScope,
    ) -> Result<AuthorizedStorageGrant<'s>, StorageAdmissionError> {
        if !matches!(&caller.binding,FactoryBinding::Local(factory) if std::ptr::eq(*factory,self))
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
    grants: &PostgresResourceGrants<'_>,
    default_route: &str,
    caller: AuthenticatedStorageCaller<'a>,
    scope: &StorageScope,
) -> Result<AuthorizedStorageGrant<'a>, StorageAdmissionError> {
    caller.check()?;
    // SQL owns transaction/COMMIT uncertainty classification; no outer timer.
    let snapshot = grants.read(caller.auth.end).await?;
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
