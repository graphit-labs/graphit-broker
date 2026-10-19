use super::{SqliteControlStore, SqliteLocalBearerVerifier, SqliteResourceGrants};
use crate::{
    BrokerAccessVerifier, RerankAdmission, RerankAdmissionError as Error, RerankAdmissionLimits,
    UpstreamBearerVerifier,
    embedding_admission::{EmbeddingIdentity, authenticate_nonlocal},
    local_bearer_verifier::bearer_kind,
    rerank_admission::admit,
};
use std::time::Instant;

/// Uses the SQLite store's existing physical verifier and snapshot executor.
pub struct SqliteRerankAdmissions<'a> {
    native: &'a BrokerAccessVerifier,
    upstream: Option<&'a UpstreamBearerVerifier>,
    local: SqliteLocalBearerVerifier<'a>,
    grants: SqliteResourceGrants<'a>,
    scopes: &'a [String],
}
impl SqliteControlStore {
    pub fn rerank_admissions<'a>(
        &'a self,
        native: &'a BrokerAccessVerifier,
        upstream: Option<&'a UpstreamBearerVerifier>,
        local_audience: &'a str,
        required_scopes: &'a [String],
        limits: RerankAdmissionLimits,
    ) -> Result<SqliteRerankAdmissions<'a>, Error> {
        limits.validate(local_audience, required_scopes)?;
        Ok(SqliteRerankAdmissions {
            native,
            upstream,
            local: self.local_bearer_verifier(local_audience, limits.identity_json_bytes)?,
            grants: self.resource_grants(limits.grants_json_bytes)?,
            scopes: required_scopes,
        })
    }
}
impl<'a> SqliteRerankAdmissions<'a> {
    pub async fn authorize(
        &self,
        raw: Option<&str>,
        original: Instant,
    ) -> Result<RerankAdmission<'a>, Error> {
        let identity = match raw {
            Some(raw) if bearer_kind(raw).is_some() => {
                EmbeddingIdentity::Local(self.local.verify(raw, self.scopes, original).await?)
            }
            other => {
                authenticate_nonlocal(self.native, self.upstream, other, self.scopes, original)
                    .await?
            }
        };
        // The physical executor owns deadlines, retained work and COMMIT acknowledgement.
        let wait = identity.deadline(original);
        let snapshot = self.grants.read(wait).await;
        admit(identity, snapshot, original)
    }
}
