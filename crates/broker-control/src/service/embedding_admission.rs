use crate::{
    BrokerAccessVerifier, EmbeddingAdmission, EmbeddingAdmissionError as Error,
    EmbeddingAdmissionLimits, PostgresControlStore, PostgresLocalBearerVerifier,
    PostgresResourceGrants, UpstreamBearerVerifier,
    embedding_admission::{EmbeddingIdentity, admit, authenticate_nonlocal},
    local_bearer_verifier::bearer_kind,
};
use std::time::Instant;

/// Borrows the configured verifier owners and the existing physical SQL readers.
pub struct PostgresEmbeddingAdmissions<'a> {
    native: &'a BrokerAccessVerifier,
    upstream: Option<&'a UpstreamBearerVerifier>,
    local: PostgresLocalBearerVerifier<'a>,
    grants: PostgresResourceGrants<'a>,
    scopes: &'a [String],
}
impl PostgresControlStore {
    pub fn embedding_admissions<'a>(
        &'a self,
        native: &'a BrokerAccessVerifier,
        upstream: Option<&'a UpstreamBearerVerifier>,
        local_audience: &'a str,
        required_scopes: &'a [String],
        limits: EmbeddingAdmissionLimits,
    ) -> Result<PostgresEmbeddingAdmissions<'a>, Error> {
        limits.validate(local_audience, required_scopes)?;
        Ok(PostgresEmbeddingAdmissions {
            native,
            upstream,
            local: self.local_bearer_verifier(local_audience, limits.identity_json_bytes)?,
            grants: self.resource_grants(limits.grants_json_bytes)?,
            scopes: required_scopes,
        })
    }
}
impl<'a> PostgresEmbeddingAdmissions<'a> {
    pub async fn authorize(
        &self,
        raw: Option<&str>,
        original: Instant,
    ) -> Result<EmbeddingAdmission<'a>, Error> {
        let identity = match raw {
            Some(raw) if bearer_kind(raw).is_some() => {
                EmbeddingIdentity::Local(self.local.verify(raw, self.scopes, original).await?)
            }
            other => {
                authenticate_nonlocal(self.native, self.upstream, other, self.scopes, original)
                    .await?
            }
        };
        // SQL readers retain their own bounded transaction and COMMIT classification.
        // A fresh snapshot is required even when every vector is already cached.
        let wait = identity.deadline(original);
        let snapshot = self.grants.read(wait).await;
        admit(identity, snapshot, original)
    }
}
