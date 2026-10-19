use super::{
    SqliteControlStore, SqliteInstanceInventories, SqliteLocalBearerVerifier, SqliteResourceGrants,
};
use crate::{
    AuthorizedNowProjectSubscriber, AuthorizedNowPublisher, AuthorizedNowSubscriber,
    BrokerAccessVerifier, BrokerPresenceAuthorizationError, ControlError,
    NowChannelAuthorizationError as Error, NowReadMask, PresenceAuthorizationError,
    PresenceCapability, PresenceChannel, ProjectResourceAction, ProjectResourceModule,
    instance_registry::canonical_project_id,
    now_channel::{AuthorizedChannel, ChannelPrincipal, NowAuthorization},
    resource_policy::ResourcePolicy,
};
use std::{fmt, num::NonZeroUsize, time::Instant};

enum Authentication<'a> {
    Native(&'a BrokerAccessVerifier),
    Local(SqliteLocalBearerVerifier<'a>),
}
impl Authentication<'_> {
    fn control(&self, error: ControlError) -> Error {
        match self {
            Self::Native(_) => Error::Native(error.into()),
            Self::Local(_) => Error::Local(error.into()),
        }
    }
}

/// Explicit Native or current LOCAL identity, ACL and SQLite registered context.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore,
///     verifier: &broker_control::BrokerAccessVerifier) -> broker_control::SqliteNowChannelAuthorizer<'static> {
///     let cap = std::num::NonZeroUsize::new(4096).unwrap();
///     store.broker_now_channel_authorizer(verifier, cap, cap).unwrap()
/// }
/// ```
pub struct SqliteNowChannelAuthorizer<'a> {
    owner: &'a SqliteControlStore,
    authentication: Authentication<'a>,
    grants: SqliteResourceGrants<'a>,
    inventories: SqliteInstanceInventories<'a>,
}
impl fmt::Debug for SqliteNowChannelAuthorizer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteNowChannelAuthorizer([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn broker_now_channel_authorizer<'a>(
        &'a self,
        verifier: &'a BrokerAccessVerifier,
        grants_json_bytes: NonZeroUsize,
        inventory_json_bytes: NonZeroUsize,
    ) -> Result<SqliteNowChannelAuthorizer<'a>, Error> {
        Ok(SqliteNowChannelAuthorizer {
            owner: self,
            authentication: Authentication::Native(verifier),
            grants: self
                .resource_grants(grants_json_bytes)
                .map_err(|e| Error::Native(BrokerPresenceAuthorizationError::from(e)))?,
            inventories: self.instance_inventories(inventory_json_bytes)?,
        })
    }
    pub fn local_now_channel_authorizer<'a>(
        &'a self,
        audience: &'a str,
        identity_json_bytes: NonZeroUsize,
        grants_json_bytes: NonZeroUsize,
        inventory_json_bytes: NonZeroUsize,
    ) -> Result<SqliteNowChannelAuthorizer<'a>, Error> {
        Ok(SqliteNowChannelAuthorizer {
            owner: self,
            authentication: Authentication::Local(
                self.local_bearer_verifier(audience, identity_json_bytes)
                    .map_err(|e| Error::Local(PresenceAuthorizationError::from(e)))?,
            ),
            grants: self
                .resource_grants(grants_json_bytes)
                .map_err(|e| Error::Local(PresenceAuthorizationError::from(e)))?,
            inventories: self.instance_inventories(inventory_json_bytes)?,
        })
    }
}
impl<'a> SqliteNowChannelAuthorizer<'a> {
    async fn authorize_project(
        &self,
        raw: &str,
        scopes: &[String],
        project_id: &str,
        cap: PresenceCapability,
        original: Instant,
    ) -> Result<NowAuthorization<'a>, Error> {
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(ControlError::from)
            .map_err(|e| self.authentication.control(e))?;
        if !canonical_project_id(project_id) {
            return Err(Error::InvalidProject);
        }
        let principal = match &self.authentication {
            Authentication::Native(verifier) => ChannelPrincipal::Native(
                verifier
                    .verify(raw, scopes, end)
                    .map_err(|e| Error::Native(e.into()))?,
            ),
            Authentication::Local(verifier) => ChannelPrincipal::Local(
                verifier
                    .verify(raw, scopes, end)
                    .await
                    .map_err(|e| Error::Local(e.into()))?,
            ),
        };
        let mut proof = NowAuthorization::new(principal, project_id, end)?;
        // The qualified SQL producers own timeout/COMMIT outcomes. Do not wrap
        // these reads in another timeout or replay an uncertain operation.
        let grants = self
            .grants
            .read(end)
            .await
            .map_err(|e| match &proof.principal {
                ChannelPrincipal::Native(_) => Error::Native(e.into()),
                ChannelPrincipal::Local(_) => Error::Local(e.into()),
            })?;
        let policy =
            ResourcePolicy::compile(&grants, end).map_err(|e| proof.principal.policy_error(e))?;
        let allowed = proof
            .principal
            .allows(&policy, cap.as_str(), project_id, end)?;
        proof.principal.finish()?;
        proof.check()?;
        if !allowed {
            return Err(proof.principal.forbidden());
        }
        let read = |module: ProjectResourceModule| {
            let capability = module
                .capability(ProjectResourceAction::Read)
                .ok_or_else(|| proof.principal.forbidden())?;
            proof.principal.allows(&policy, capability, project_id, end)
        };
        proof.mask = NowReadMask {
            task: read(ProjectResourceModule::Task)?,
            memory: read(ProjectResourceModule::Memory)?,
            knowledge: read(ProjectResourceModule::Knowledge)?,
        };
        proof.policy_revision = grants.revision();
        proof.principal.finish()?;
        proof.check()?;
        Ok(proof)
    }
    async fn authorize_channel(
        &self,
        raw: &str,
        scopes: &[String],
        channel: &PresenceChannel,
        cap: PresenceCapability,
        original: Instant,
    ) -> Result<AuthorizedChannel<'a>, Error> {
        let mut authorization = self
            .authorize_project(raw, scopes, channel.project_id(), cap, original)
            .await?;
        let snapshot = self
            .inventories
            .read(channel.instance_id(), authorization.end)
            .await?;
        let decision = if let Some(snapshot) = snapshot.as_ref() {
            if cap == PresenceCapability::Publish && !authorization.principal.owns(snapshot.owner())
            {
                Err(Error::OwnerConflict)
            } else if snapshot.inventory().projects().iter().any(|project| {
                project.project_id() == channel.project_id()
                    && project
                        .versions()
                        .iter()
                        .any(|version| version == channel.version())
            }) {
                Ok(())
            } else {
                Err(Error::NotRegistered)
            }
        } else {
            Err(Error::NotRegistered)
        };
        authorization.principal.finish()?;
        authorization.check()?;
        decision?;
        let snapshot = snapshot.ok_or(Error::NotRegistered)?;
        Ok(AuthorizedChannel {
            authorization,
            channel: channel.clone(),
            snapshot,
        })
    }
    pub async fn authorize_publish(
        &self,
        raw: &str,
        required_scopes: &[String],
        channel: &PresenceChannel,
        original: Instant,
    ) -> Result<AuthorizedNowPublisher<'a>, Error> {
        Ok(AuthorizedNowPublisher {
            inner: self
                .authorize_channel(
                    raw,
                    required_scopes,
                    channel,
                    PresenceCapability::Publish,
                    original,
                )
                .await?,
        })
    }
    pub async fn authorize_read(
        &self,
        raw: &str,
        required_scopes: &[String],
        channel: &PresenceChannel,
        original: Instant,
    ) -> Result<AuthorizedNowSubscriber<'a>, Error> {
        Ok(AuthorizedNowSubscriber {
            inner: self
                .authorize_channel(
                    raw,
                    required_scopes,
                    channel,
                    PresenceCapability::Read,
                    original,
                )
                .await?,
        })
    }
    pub async fn authorize_subscriber_project(
        &self,
        raw: &str,
        required_scopes: &[String],
        project_id: &str,
        original: Instant,
    ) -> Result<AuthorizedNowProjectSubscriber<'a>, Error> {
        Ok(AuthorizedNowProjectSubscriber {
            authorization: self
                .authorize_project(
                    raw,
                    required_scopes,
                    project_id,
                    PresenceCapability::Read,
                    original,
                )
                .await?,
        })
    }
}
