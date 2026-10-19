//! Current Auth/ACL and registry observations for one Now channel operation.
use crate::{
    BrokerAccessError, BrokerPresenceAuthorizationError, InstanceOwner, InstanceReadError,
    LocalBearerVerificationError, PresenceAuthorizationError, StoredInstanceInventory,
    VerifiedBrokerAccess, VerifiedLocalBearer,
    flow::now_micros,
    instance_registry::{canonical_instance_id, canonical_project_id, canonical_version},
    resource_policy::{ResourcePolicy, ResourcePolicyError},
};
use broker_now_wire::NowSnapshotData;
use std::{
    fmt,
    time::{Instant, SystemTime},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NowChannelAuthorizationError {
    Native(BrokerPresenceAuthorizationError),
    Local(PresenceAuthorizationError),
    Inventory(InstanceReadError),
    InvalidChannel,
    InvalidProject,
    NotRegistered,
    OwnerConflict,
    SnapshotProjectMismatch,
}
impl From<InstanceReadError> for NowChannelAuthorizationError {
    fn from(value: InstanceReadError) -> Self {
        Self::Inventory(value)
    }
}
impl fmt::Display for NowChannelAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(e) => e.fmt(f),
            Self::Local(e) => e.fmt(f),
            Self::Inventory(e) => e.fmt(f),
            Self::InvalidChannel => f.write_str("invalid Now channel"),
            Self::InvalidProject => f.write_str("invalid Now project"),
            Self::NotRegistered => f.write_str("Now channel not registered"),
            Self::OwnerConflict => f.write_str("Now channel belongs to another owner"),
            Self::SnapshotProjectMismatch => f.write_str("Now snapshot project mismatch"),
        }
    }
}
impl std::error::Error for NowChannelAuthorizationError {}

/// Canonical channel DATA. Construction is not authentication or admission.
#[derive(Clone, Eq, PartialEq)]
pub struct PresenceChannel {
    instance_id: String,
    project_id: String,
    version: String,
}
impl PresenceChannel {
    pub fn new(
        instance_id: &str,
        project_id: &str,
        version: &str,
    ) -> Result<Self, NowChannelAuthorizationError> {
        if !canonical_instance_id(instance_id)
            || !canonical_project_id(project_id)
            || !canonical_version(version)
        {
            return Err(NowChannelAuthorizationError::InvalidChannel);
        }
        Ok(Self {
            instance_id: instance_id.to_owned(),
            project_id: project_id.to_owned(),
            version: version.to_owned(),
        })
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
}
impl fmt::Debug for PresenceChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresenceChannel([REDACTED])")
    }
}

/// DATA selected by current policy. This mask alone is not an authorized proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NowReadMask {
    pub(crate) task: bool,
    pub(crate) memory: bool,
    pub(crate) knowledge: bool,
}
impl NowReadMask {
    pub fn task_read(self) -> bool {
        self.task
    }
    pub fn memory_read(self) -> bool {
        self.memory
    }
    pub fn knowledge_read(self) -> bool {
        self.knowledge
    }
}

pub(crate) enum ChannelPrincipal<'a> {
    Native(VerifiedBrokerAccess<'a>),
    Local(VerifiedLocalBearer),
}
impl ChannelPrincipal<'_> {
    pub(crate) fn policy_error(&self, e: ResourcePolicyError) -> NowChannelAuthorizationError {
        match self {
            Self::Native(_) => NowChannelAuthorizationError::Native(e.into()),
            Self::Local(_) => NowChannelAuthorizationError::Local(e.into()),
        }
    }
    pub(crate) fn forbidden(&self) -> NowChannelAuthorizationError {
        match self {
            Self::Native(_) => {
                NowChannelAuthorizationError::Native(BrokerPresenceAuthorizationError::Forbidden)
            }
            Self::Local(_) => {
                NowChannelAuthorizationError::Local(PresenceAuthorizationError::Forbidden)
            }
        }
    }
    pub(crate) fn allows(
        &self,
        policy: &ResourcePolicy,
        cap: &str,
        project: &str,
        end: Instant,
    ) -> Result<bool, NowChannelAuthorizationError> {
        let result = match self {
            Self::Native(p) => policy.allows_broker(p, cap, project, end),
            Self::Local(p) => policy.allows(p.current_local_user(), cap, project, end),
        };
        result.map_err(|e| self.policy_error(e))
    }
    pub(crate) fn owns(&self, owner: &InstanceOwner) -> bool {
        let (issuer, subject) = match self {
            Self::Native(p) => (p.issuer(), p.subject()),
            Self::Local(p) => (
                p.current_local_user().issuer(),
                p.current_local_user().subject(),
            ),
        };
        owner.issuer() == issuer && owner.subject() == subject
    }
    pub(crate) fn finish(&mut self) -> Result<(), NowChannelAuthorizationError> {
        match self {
            Self::Native(p) => p
                .check()
                .map_err(|e| NowChannelAuthorizationError::Native(e.into())),
            Self::Local(p) => p
                .finish(now_micros().map_err(|e| NowChannelAuthorizationError::Local(e.into()))?)
                .map_err(|e| NowChannelAuthorizationError::Local(e.into())),
        }
    }
    fn expired(&self) -> NowChannelAuthorizationError {
        match self {
            Self::Native(_) => {
                NowChannelAuthorizationError::Native(BrokerAccessError::Expired.into())
            }
            Self::Local(_) => NowChannelAuthorizationError::Local(
                LocalBearerVerificationError::Unauthenticated.into(),
            ),
        }
    }
}

pub(crate) struct NowAuthorization<'a> {
    pub(crate) principal: ChannelPrincipal<'a>,
    pub(crate) project_id: String,
    pub(crate) mask: NowReadMask,
    pub(crate) policy_revision: i64,
    pub(crate) end: Instant,
    expires_at: SystemTime,
    expires_mono: Instant,
}
impl<'a> NowAuthorization<'a> {
    pub(crate) fn new(
        mut principal: ChannelPrincipal<'a>,
        project_id: &str,
        end: Instant,
    ) -> Result<Self, NowChannelAuthorizationError> {
        principal.finish()?;
        let (expires_at, expires_mono) = match &principal {
            ChannelPrincipal::Native(p) => p.authentication_expiry(),
            ChannelPrincipal::Local(p) => p.authentication_expiry(),
        };
        let out = Self {
            principal,
            project_id: project_id.to_owned(),
            mask: NowReadMask {
                task: false,
                memory: false,
                knowledge: false,
            },
            policy_revision: 0,
            end,
            expires_at,
            expires_mono,
        };
        out.check()?;
        Ok(out)
    }
    fn expired_at(&self, utc: SystemTime, mono: Instant) -> bool {
        utc >= self.expires_at || mono >= self.expires_mono
    }
    pub(crate) fn check(&self) -> Result<(), NowChannelAuthorizationError> {
        crate::resource_policy::check_deadline(self.end)
            .map_err(|e| self.principal.policy_error(e))?;
        if self.expired_at(SystemTime::now(), Instant::now()) {
            return Err(self.principal.expired());
        }
        if let ChannelPrincipal::Native(p) = &self.principal {
            p.check()
                .map_err(|e| NowChannelAuthorizationError::Native(e.into()))?;
        }
        Ok(())
    }
    fn filter_snapshot(
        &self,
        snapshot: NowSnapshotData,
    ) -> Result<NowSnapshotData, NowChannelAuthorizationError> {
        self.check()?;
        if snapshot.project_id() != self.project_id {
            return Err(NowChannelAuthorizationError::SnapshotProjectMismatch);
        }
        let masked = snapshot.mask_sections(self.mask.task, self.mask.memory, self.mask.knowledge);
        self.check()?;
        Ok(masked)
    }
}

pub(crate) struct AuthorizedChannel<'a> {
    pub(crate) authorization: NowAuthorization<'a>,
    pub(crate) channel: PresenceChannel,
    pub(crate) snapshot: StoredInstanceInventory,
}

/// Actual Auth/ACL plus a literal owned registered publication context.
/// This is an operation observation; authenticate and load current grants again
/// before a subsequent consequential operation.
/// ```compile_fail
/// let _ = broker_control::AuthorizedNowPublisher::new();
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {} clone::<broker_control::AuthorizedNowPublisher<'static>>();
/// ```
/// ```compile_fail
/// fn default<T: Default>() {} default::<broker_control::AuthorizedNowPublisher<'static>>();
/// ```
/// ```compile_fail
/// fn wire<T: serde::de::DeserializeOwned>() {} wire::<broker_control::AuthorizedNowPublisher<'static>>();
/// ```
/// ```compile_fail
/// fn wire<T: serde::Serialize>() {} wire::<broker_control::AuthorizedNowPublisher<'static>>();
/// ```
pub struct AuthorizedNowPublisher<'a> {
    pub(crate) inner: AuthorizedChannel<'a>,
}
/// Actual Presence Read and a registered context; stored owner remains DATA.
/// ```compile_fail
/// fn clone<T: Clone>() {} clone::<broker_control::AuthorizedNowSubscriber<'static>>();
/// ```
/// ```compile_fail
/// let _ = broker_control::AuthorizedNowSubscriber::new();
/// ```
/// ```compile_fail
/// fn default<T: Default>() {} default::<broker_control::AuthorizedNowSubscriber<'static>>();
/// ```
/// ```compile_fail
/// fn wire<T: serde::de::DeserializeOwned>() {} wire::<broker_control::AuthorizedNowSubscriber<'static>>();
/// ```
/// ```compile_fail
/// fn wire<T: serde::Serialize>() {} wire::<broker_control::AuthorizedNowSubscriber<'static>>();
/// ```
pub struct AuthorizedNowSubscriber<'a> {
    pub(crate) inner: AuthorizedChannel<'a>,
}
/// Actual project Presence Read, including an empty online view. No registry
/// entry is fabricated to authorize a project subscription.
/// ```compile_fail
/// fn wire<T: serde::de::DeserializeOwned>() {} wire::<broker_control::AuthorizedNowProjectSubscriber<'static>>();
/// ```
/// ```compile_fail
/// let _ = broker_control::AuthorizedNowProjectSubscriber::new();
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {} clone::<broker_control::AuthorizedNowProjectSubscriber<'static>>();
/// ```
/// ```compile_fail
/// fn default<T: Default>() {} default::<broker_control::AuthorizedNowProjectSubscriber<'static>>();
/// ```
/// ```compile_fail
/// fn wire<T: serde::Serialize>() {} wire::<broker_control::AuthorizedNowProjectSubscriber<'static>>();
/// ```
pub struct AuthorizedNowProjectSubscriber<'a> {
    pub(crate) authorization: NowAuthorization<'a>,
}
macro_rules! proof_methods {
    ($name:ident,$($field:ident).+) => {
        impl $name<'_> {
            pub fn project_id(&self)->&str { &self.$($field).+.project_id }
            pub fn read_mask(&self)->NowReadMask { self.$($field).+.mask }
            pub fn policy_revision(&self)->i64 { self.$($field).+.policy_revision }
            pub fn authentication_expiry(&self)->(SystemTime,Instant) { (self.$($field).+.expires_at,self.$($field).+.expires_mono) }
            pub fn check(&self)->Result<(),NowChannelAuthorizationError> { self.$($field).+.check() }
            pub fn filter_snapshot(&self,snapshot:NowSnapshotData)->Result<NowSnapshotData,NowChannelAuthorizationError> { self.$($field).+.filter_snapshot(snapshot) }
        }
        impl fmt::Debug for $name<'_> {
            fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.write_str(concat!(stringify!($name),"([REDACTED])")) }
        }
    }
}
proof_methods!(AuthorizedNowPublisher, inner.authorization);
proof_methods!(AuthorizedNowSubscriber, inner.authorization);
proof_methods!(AuthorizedNowProjectSubscriber, authorization);
macro_rules! channel_methods {
    ($name:ident) => {
        impl $name<'_> {
            pub fn channel(&self) -> &PresenceChannel {
                &self.inner.channel
            }
            pub fn registered_owner(&self) -> &InstanceOwner {
                self.inner.snapshot.owner()
            }
        }
    };
}
channel_methods!(AuthorizedNowPublisher);
channel_methods!(AuthorizedNowSubscriber);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlError;
    use std::time::{Duration, UNIX_EPOCH};
    #[test]
    fn canonical_channel_and_finite_errors() {
        let a = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        assert!(PresenceChannel::new("Station._-1", a, "branch/ação").is_ok());
        for (instance, project, version) in [
            ("bad/instance", a, "main"),
            ("station", "friendly", "main"),
            ("station", a, " main "),
        ] {
            assert_eq!(
                PresenceChannel::new(instance, project, version).unwrap_err(),
                NowChannelAuthorizationError::InvalidChannel
            );
        }
        for e in [
            NowChannelAuthorizationError::NotRegistered,
            NowChannelAuthorizationError::OwnerConflict,
            NowChannelAuthorizationError::SnapshotProjectMismatch,
            NowChannelAuthorizationError::Inventory(InstanceReadError::Control(
                ControlError::OutcomeUncertain,
            )),
        ] {
            assert!(std::error::Error::source(&e).is_none());
            assert!(!e.to_string().is_empty());
        }
    }
    #[test]
    fn expiry_keeps_real_verifier_anchor_through_clock_reversal() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use serde_json::json;
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let keys=serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())}]})).unwrap();
        let verifier = crate::BrokerAccessVerifier::new(
            "https://broker.test",
            "api",
            None,
            &keys,
            std::num::NonZeroUsize::new(8192).unwrap(),
        )
        .unwrap();
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("test".into());
        let raw=encode(&header,&json!({"iss":"https://broker.test","sub":"subject","aud":"api","iat":seconds-1,"exp":seconds+60,"token_use":"access","client_id":"client","jti":"token","scope":""}),&EncodingKey::from_ed_der(&pair.serialize_der())).unwrap();
        let end = Instant::now() + Duration::from_secs(30);
        let principal = verifier.verify(&raw, &[], end).unwrap();
        let actual = principal.authentication_expiry();
        let proof = NowAuthorization::new(
            ChannelPrincipal::Native(principal),
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            end,
        )
        .unwrap();
        assert_eq!((proof.expires_at, proof.expires_mono), actual);
        assert!(!proof.expired_at(UNIX_EPOCH, actual.1 - Duration::from_nanos(1)));
        assert!(proof.expired_at(UNIX_EPOCH, actual.1));
        assert!(proof.expired_at(actual.0, actual.1 - Duration::from_secs(1)));
        proof.check().unwrap();
    }
}
