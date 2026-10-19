//! Authorized ephemeral Now publications, project invalidations and replay.
use broker_control::{
    AuthorizedNowProjectSubscriber, AuthorizedNowPublisher, AuthorizedNowSubscriber,
    NowChannelAuthorizationError, NowReadMask, PresenceChannel,
};
use broker_now_wire::{NowSectionAvailability, NowSectionErrorCode, NowSnapshotData};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    num::NonZeroUsize,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    sync::{Notify, broadcast, watch},
    task::JoinHandle,
};

type Key = (String, String, String);
fn key(c: &PresenceChannel) -> Key {
    (
        c.project_id().into(),
        c.instance_id().into(),
        c.version().into(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealtimeHubError {
    Authorization(NowChannelAuthorizationError),
    InvalidConfiguration,
    InvalidContext,
    OwnerConflict,
    AuthenticationExpired,
    Superseded,
    Closed,
    Unavailable,
}
impl From<NowChannelAuthorizationError> for RealtimeHubError {
    fn from(e: NowChannelAuthorizationError) -> Self {
        Self::Authorization(e)
    }
}
impl fmt::Display for RealtimeHubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authorization(_) => "Now authorization failed",
            Self::InvalidConfiguration => "invalid realtime Hub configuration",
            Self::InvalidContext => "invalid realtime context",
            Self::OwnerConflict => "realtime publisher owner conflict",
            Self::AuthenticationExpired => "realtime publication authentication expired",
            Self::Superseded => "realtime publication superseded",
            Self::Closed => "realtime Hub closed",
            Self::Unavailable => "realtime Hub unavailable",
        })
    }
}
impl std::error::Error for RealtimeHubError {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealtimeHubSignalError {
    Lagged,
    Closed,
}
impl fmt::Display for RealtimeHubSignalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Lagged => "realtime signals lagged",
            Self::Closed => "realtime signals closed",
        })
    }
}
impl std::error::Error for RealtimeHubSignalError {}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Dormant,
    Running,
    Closed,
}
struct PublicationIdentity {
    inactive: watch::Sender<Option<RealtimeHubError>>,
}
impl PublicationIdentity {
    fn end(&self, reason: RealtimeHubError) {
        let _ = self.inactive.send_replace(Some(reason));
    }
    fn end_reason(&self) -> Option<RealtimeHubError> {
        *self.inactive.borrow()
    }
}
#[derive(Clone, Copy)]
struct Window {
    utc: SystemTime,
    mono: Instant,
    heartbeat: Instant,
}
impl Window {
    fn active(self, utc: SystemTime, mono: Instant) -> bool {
        utc < self.utc && mono < self.mono && mono < self.heartbeat
    }
    fn next(self, utc: SystemTime, mono: Instant) -> Instant {
        let utc_end = self
            .utc
            .duration_since(utc)
            .ok()
            .and_then(|d| mono.checked_add(d))
            .unwrap_or(mono);
        utc_end.min(self.mono).min(self.heartbeat)
    }
}
struct Slot {
    channel: PresenceChannel,
    issuer: String,
    subject: String,
    identity: Arc<PublicationIdentity>,
    snapshot: Arc<NowSnapshotData>,
    window: Window,
}
struct StateData {
    phase: Phase,
    slots: BTreeMap<Key, Slot>,
    groups: BTreeMap<String, broadcast::Sender<()>>,
}
struct State {
    data: Mutex<StateData>,
    heartbeat: Duration,
    capacity: usize,
    changed: Notify,
}
impl State {
    fn lock(&self) -> Result<MutexGuard<'_, StateData>, RealtimeHubError> {
        self.data.lock().map_err(|_| RealtimeHubError::Unavailable)
    }
    fn running(d: &StateData) -> Result<(), RealtimeHubError> {
        match d.phase {
            Phase::Running => Ok(()),
            Phase::Closed => Err(RealtimeHubError::Closed),
            Phase::Dormant => Err(RealtimeHubError::Unavailable),
        }
    }
    fn signal(d: &StateData, project: &str) {
        if let Some(sender) = d.groups.get(project) {
            let _ = sender.send(());
        }
    }
    fn prune_groups(d: &mut StateData) {
        let slots = &d.slots;
        d.groups.retain(|project, sender| {
            sender.receiver_count() != 0 || slots.keys().any(|k| &k.0 == project)
        });
    }
    fn prune(d: &mut StateData, utc: SystemTime, mono: Instant) {
        let expired: Vec<_> = d
            .slots
            .iter()
            .filter(|(_, s)| !s.window.active(utc, mono))
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            if let Some(slot) = d.slots.remove(&k) {
                let reason = if utc >= slot.window.utc || mono >= slot.window.mono {
                    RealtimeHubError::AuthenticationExpired
                } else {
                    RealtimeHubError::Closed
                };
                slot.identity.end(reason);
                Self::signal(d, slot.channel.project_id());
            }
        }
        Self::prune_groups(d);
    }
    fn close(&self) {
        // Poisoned state is never admitted again; cleanup must still wake owners.
        let mut d = self.data.lock().unwrap_or_else(|p| p.into_inner());
        d.phase = Phase::Closed;
        for slot in d.slots.values() {
            slot.identity.end(RealtimeHubError::Closed);
        }
        d.slots.clear();
        d.groups.clear();
        drop(d);
        self.changed.notify_one();
    }
    fn remove(&self, channel: &PresenceChannel, identity: &Arc<PublicationIdentity>) {
        if let Ok(mut d) = self.lock() {
            let k = key(channel);
            if d.slots
                .get(&k)
                .is_some_and(|s| Arc::ptr_eq(&s.identity, identity))
            {
                d.slots.remove(&k);
                identity.end(RealtimeHubError::Closed);
                Self::signal(&d, channel.project_id());
                Self::prune_groups(&mut d);
                self.changed.notify_one();
            }
        } else {
            self.close();
        }
    }
}

pub(crate) struct RealtimeHubCandidate {
    channel: PresenceChannel,
}
impl RealtimeHubCandidate {
    pub(crate) fn channel(&self) -> &PresenceChannel {
        &self.channel
    }
}

/// State only. Start and retain its explicit maintenance owner before admission.
/// ~~~no_run
/// # async fn example() -> Result<(), broker_presence::RealtimeHubError> {
/// use broker_presence::RealtimeHub;
/// let hub = RealtimeHub::new(std::time::Duration::from_secs(30), std::num::NonZeroUsize::new(32).unwrap())?;
/// let maintenance = hub.run_maintenance()?;
/// maintenance.shutdown().await?;
/// # Ok(()) }
/// ~~~
pub struct RealtimeHub {
    state: Arc<State>,
}
impl RealtimeHub {
    pub fn new(
        heartbeat_timeout: Duration,
        broadcast_capacity: NonZeroUsize,
    ) -> Result<Arc<Self>, RealtimeHubError> {
        let capacity = broadcast_capacity.get();
        if heartbeat_timeout.is_zero()
            || Instant::now().checked_add(heartbeat_timeout).is_none()
            || SystemTime::now().checked_add(heartbeat_timeout).is_none()
            || capacity > usize::MAX >> 1
            || capacity.checked_next_power_of_two().is_none()
        {
            return Err(RealtimeHubError::InvalidConfiguration);
        }
        Ok(Arc::new(Self {
            state: Arc::new(State {
                data: Mutex::new(StateData {
                    phase: Phase::Dormant,
                    slots: BTreeMap::new(),
                    groups: BTreeMap::new(),
                }),
                heartbeat: heartbeat_timeout,
                capacity,
                changed: Notify::new(),
            }),
        }))
    }
    pub fn run_maintenance(self: &Arc<Self>) -> Result<RealtimeHubMaintenance, RealtimeHubError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| RealtimeHubError::InvalidConfiguration)?;
        let mut d = self.state.lock()?;
        match d.phase {
            Phase::Dormant => d.phase = Phase::Running,
            Phase::Running => return Err(RealtimeHubError::InvalidConfiguration),
            Phase::Closed => return Err(RealtimeHubError::Closed),
        }
        let state = self.state.clone();
        let task = runtime.spawn(async move {
            let _exit = MaintenanceExit(state.clone());
            maintenance_loop(&state).await;
        });
        Ok(RealtimeHubMaintenance {
            state: self.state.clone(),
            task: Some(task),
        })
    }
    pub fn open_publisher(
        self: &Arc<Self>,
        proof: AuthorizedNowPublisher<'_>,
        snapshot: NowSnapshotData,
    ) -> Result<RealtimePublisherHandle, RealtimeHubError> {
        proof.check()?;
        let channel = proof.channel().clone();
        let snapshot = Arc::new(proof.filter_snapshot(snapshot)?);
        let (utc, mono) = proof.authentication_expiry();
        let identity = Arc::new(PublicationIdentity {
            inactive: watch::channel(None).0,
        });
        let mut d = self.state.lock()?;
        State::running(&d)?;
        State::prune(&mut d, SystemTime::now(), Instant::now());
        let k = key(&channel);
        if let Some(old) = d.slots.get(&k)
            && (old.issuer != proof.registered_owner().issuer()
                || old.subject != proof.registered_owner().subject())
        {
            return Err(RealtimeHubError::OwnerConflict);
        }
        let heartbeat = Instant::now()
            .checked_add(self.state.heartbeat)
            .ok_or(RealtimeHubError::InvalidConfiguration)?;
        proof.check()?;
        let slot = Slot {
            channel: channel.clone(),
            issuer: proof.registered_owner().issuer().into(),
            subject: proof.registered_owner().subject().into(),
            identity: identity.clone(),
            snapshot,
            window: Window {
                utc,
                mono,
                heartbeat,
            },
        };
        proof.check()?;
        if let Some(old) = d.slots.insert(k, slot) {
            old.identity.end(RealtimeHubError::Superseded);
        }
        State::signal(&d, channel.project_id());
        drop(d);
        self.state.changed.notify_one();
        Ok(RealtimePublisherHandle {
            state: self.state.clone(),
            channel,
            identity,
        })
    }
    pub fn subscribe(
        &self,
        proof: &AuthorizedNowProjectSubscriber<'_>,
    ) -> Result<RealtimeProjectSubscription, RealtimeHubError> {
        proof.check()?;
        let mut d = self.state.lock()?;
        State::running(&d)?;
        State::prune(&mut d, SystemTime::now(), Instant::now());
        proof.check()?;
        let sender = d
            .groups
            .entry(proof.project_id().into())
            .or_insert_with(|| broadcast::channel(self.state.capacity).0);
        Ok(RealtimeProjectSubscription {
            state: self.state.clone(),
            project: proof.project_id().into(),
            receiver: Some(sender.subscribe()),
        })
    }
    /// Channel metadata is crate-private and project-authorized, never raw DATA.
    pub(crate) fn candidates(
        &self,
        proof: &AuthorizedNowProjectSubscriber<'_>,
    ) -> Result<Vec<RealtimeHubCandidate>, RealtimeHubError> {
        proof.check()?;
        let mut d = self.state.lock()?;
        State::running(&d)?;
        State::prune(&mut d, SystemTime::now(), Instant::now());
        let channels = d
            .slots
            .values()
            .filter(|s| s.channel.project_id() == proof.project_id())
            .map(|s| RealtimeHubCandidate {
                channel: s.channel.clone(),
            })
            .collect();
        proof.check()?;
        Ok(channels)
    }
    pub fn replay<'v>(
        &self,
        project: AuthorizedNowProjectSubscriber<'v>,
        channels: Vec<AuthorizedNowSubscriber<'v>>,
    ) -> Result<RealtimeHubReplay<'v>, RealtimeHubError> {
        let candidates: BTreeSet<_> = self
            .candidates(&project)?
            .iter()
            .map(|candidate| key(candidate.channel()))
            .collect();
        let mut unique = BTreeSet::new();
        for proof in &channels {
            proof.check()?;
            if proof.project_id() != project.project_id() || !unique.insert(key(proof.channel())) {
                return Err(RealtimeHubError::InvalidContext);
            }
        }
        let mut d = self.state.lock()?;
        State::running(&d)?;
        State::prune(&mut d, SystemTime::now(), Instant::now());
        let mut instances = Vec::new();
        for (index, proof) in channels.iter().enumerate() {
            let k = key(proof.channel());
            if !candidates.contains(&k) {
                continue;
            }
            if let Some(slot) = d.slots.get(&k) {
                if slot.issuer != proof.registered_owner().issuer()
                    || slot.subject != proof.registered_owner().subject()
                {
                    return Err(RealtimeHubError::OwnerConflict);
                }
                instances.push(RealtimeHubInstance {
                    channel: slot.channel.clone(),
                    snapshot: slot.snapshot.clone(),
                    proof_index: index,
                });
            }
        }
        project.check()?;
        for proof in &channels {
            proof.check()?;
        }
        drop(d);
        instances
            .sort_by(|a, b| (a.instance_id(), a.version()).cmp(&(b.instance_id(), b.version())));
        let replay = RealtimeHubReplay {
            project,
            channels,
            instances,
        };
        replay.check()?;
        Ok(replay)
    }
}

/// An owned maintenance task; dropping it closes the Hub and aborts the task.
/// ~~~compile_fail
/// fn clone<T: Clone>() {} clone::<broker_presence::RealtimeHubMaintenance>();
/// ~~~
pub struct RealtimeHubMaintenance {
    state: Arc<State>,
    task: Option<JoinHandle<()>>,
}
impl RealtimeHubMaintenance {
    pub async fn shutdown(mut self) -> Result<(), RealtimeHubError> {
        self.state.close();
        // Retain the handle during await: cancellation drops and aborts it.
        let result = if let Some(task) = self.task.as_mut() {
            task.await.map_err(|_| RealtimeHubError::Unavailable)
        } else {
            Ok(())
        };
        self.task.take();
        result
    }
}
impl Drop for RealtimeHubMaintenance {
    fn drop(&mut self) {
        self.state.close();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
struct MaintenanceExit(Arc<State>);
impl Drop for MaintenanceExit {
    fn drop(&mut self) {
        self.0.close();
    }
}
async fn maintenance_loop(state: &State) {
    loop {
        let next = {
            let Ok(mut d) = state.lock() else {
                state.close();
                return;
            };
            if d.phase != Phase::Running {
                return;
            }
            let utc = SystemTime::now();
            let mono = Instant::now();
            State::prune(&mut d, utc, mono);
            d.slots.values().map(|s| s.window.next(utc, mono)).min()
        };
        match next {
            Some(end) => {
                let _ = tokio::time::timeout_at(end.into(), state.changed.notified()).await;
            }
            None => state.changed.notified().await,
        }
    }
}

/// A publication identity, not permission for a later publication.
/// ~~~compile_fail
/// fn clone<T: Clone>() {} clone::<broker_presence::RealtimePublisherHandle>();
/// ~~~
/// ~~~compile_fail
/// fn default<T: Default>() {} default::<broker_presence::RealtimePublisherHandle>();
/// ~~~
/// ~~~compile_fail
/// fn wire<T: serde::de::DeserializeOwned>() {} wire::<broker_presence::RealtimePublisherHandle>();
/// ~~~
/// ~~~compile_fail
/// fn wire<T: serde::Serialize>() {} wire::<broker_presence::RealtimePublisherHandle>();
/// ~~~
pub struct RealtimePublisherHandle {
    state: Arc<State>,
    channel: PresenceChannel,
    identity: Arc<PublicationIdentity>,
}
impl RealtimePublisherHandle {
    pub fn publish(
        &self,
        proof: AuthorizedNowPublisher<'_>,
        snapshot: NowSnapshotData,
    ) -> Result<(), RealtimeHubError> {
        proof.check()?;
        if proof.channel() != &self.channel {
            return Err(RealtimeHubError::InvalidContext);
        }
        let snapshot = Arc::new(proof.filter_snapshot(snapshot)?);
        let (utc, mono) = proof.authentication_expiry();
        if let Some(reason) = self.identity.end_reason() {
            return Err(reason);
        }
        let mut d = self.state.lock()?;
        if let Some(reason) = self.identity.end_reason() {
            return Err(reason);
        }
        State::running(&d)?;
        State::prune(&mut d, SystemTime::now(), Instant::now());
        if let Some(reason) = self.identity.end_reason() {
            return Err(reason);
        }
        let slot = d
            .slots
            .get_mut(&key(&self.channel))
            .ok_or(RealtimeHubError::Superseded)?;
        if !Arc::ptr_eq(&slot.identity, &self.identity) {
            return Err(RealtimeHubError::Superseded);
        }
        if slot.issuer != proof.registered_owner().issuer()
            || slot.subject != proof.registered_owner().subject()
        {
            return Err(RealtimeHubError::OwnerConflict);
        }
        let heartbeat = Instant::now()
            .checked_add(self.state.heartbeat)
            .ok_or(RealtimeHubError::InvalidConfiguration)?;
        proof.check()?;
        slot.snapshot = snapshot;
        slot.window = Window {
            utc,
            mono,
            heartbeat,
        };
        State::signal(&d, self.channel.project_id());
        drop(d);
        self.state.changed.notify_one();
        Ok(())
    }
    pub fn check_active(&self) -> Result<(), RealtimeHubError> {
        if let Some(reason) = self.identity.end_reason() {
            return Err(reason);
        }
        let mut d = self.state.lock()?;
        if let Some(reason) = self.identity.end_reason() {
            return Err(reason);
        }
        State::running(&d)?;
        State::prune(&mut d, SystemTime::now(), Instant::now());
        if let Some(reason) = self.identity.end_reason() {
            return Err(reason);
        }
        if d.slots
            .get(&key(&self.channel))
            .is_some_and(|s| Arc::ptr_eq(&s.identity, &self.identity))
        {
            Ok(())
        } else {
            Err(RealtimeHubError::Superseded)
        }
    }
    pub async fn wait_inactive(&self) -> RealtimeHubError {
        let mut inactive = self.identity.inactive.subscribe();
        loop {
            if let Err(reason) = self.check_active() {
                return reason;
            }
            if inactive.changed().await.is_err() {
                return RealtimeHubError::Closed;
            }
        }
    }
}
impl Drop for RealtimePublisherHandle {
    fn drop(&mut self) {
        self.state.remove(&self.channel, &self.identity);
    }
}

/// Unit invalidations only. Every replay needs fresh actual authorization.
/// ~~~compile_fail
/// fn clone<T: Clone>() {} clone::<broker_presence::RealtimeProjectSubscription>();
/// ~~~
/// ~~~compile_fail
/// fn default<T: Default>() {} default::<broker_presence::RealtimeProjectSubscription>();
/// ~~~
pub struct RealtimeProjectSubscription {
    state: Arc<State>,
    project: String,
    receiver: Option<broadcast::Receiver<()>>,
}
impl RealtimeProjectSubscription {
    pub async fn recv(&mut self) -> Result<(), RealtimeHubSignalError> {
        let receiver = self
            .receiver
            .as_mut()
            .ok_or(RealtimeHubSignalError::Closed)?;
        receiver.recv().await.map_err(|e| match e {
            broadcast::error::RecvError::Lagged(_) => RealtimeHubSignalError::Lagged,
            broadcast::error::RecvError::Closed => RealtimeHubSignalError::Closed,
        })
    }
}
impl Drop for RealtimeProjectSubscription {
    fn drop(&mut self) {
        self.receiver.take();
        if let Ok(mut d) = self.state.lock() {
            if d.groups
                .get(&self.project)
                .is_some_and(|sender| sender.receiver_count() == 0)
                && !d.slots.keys().any(|k| k.0 == self.project)
            {
                d.groups.remove(&self.project);
            }
        } else {
            self.state.close();
        }
    }
}

/// Safe instance metadata; no raw snapshot getter or independently serializable view.
pub struct RealtimeHubInstance {
    channel: PresenceChannel,
    snapshot: Arc<NowSnapshotData>,
    proof_index: usize,
}
impl RealtimeHubInstance {
    pub fn instance_id(&self) -> &str {
        self.channel.instance_id()
    }
    pub fn version(&self) -> &str {
        self.channel.version()
    }
}
/// Retains both actual proof classes until the final serialization/send gate.
/// ~~~compile_fail
/// fn clone<T: Clone>() {} clone::<broker_presence::RealtimeHubReplay<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn default<T: Default>() {} default::<broker_presence::RealtimeHubReplay<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn wire<T: serde::de::DeserializeOwned>() {} wire::<broker_presence::RealtimeHubReplay<'static>>();
/// ~~~
pub struct RealtimeHubReplay<'v> {
    project: AuthorizedNowProjectSubscriber<'v>,
    channels: Vec<AuthorizedNowSubscriber<'v>>,
    instances: Vec<RealtimeHubInstance>,
}
impl RealtimeHubReplay<'_> {
    pub fn project_id(&self) -> &str {
        self.project.project_id()
    }
    pub fn instances(&self) -> &[RealtimeHubInstance] {
        &self.instances
    }
    pub fn check(&self) -> Result<(), RealtimeHubError> {
        self.project.check()?;
        for proof in &self.channels {
            proof.check()?;
        }
        Ok(())
    }
}
impl Serialize for RealtimeHubReplay<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.check().map_err(S::Error::custom)?;
        let mut view = serializer.serialize_struct("RealtimeHubReplay", 2)?;
        view.serialize_field("project_id", self.project_id())?;
        view.serialize_field("instances", &InstanceViews(self))?;
        self.check().map_err(S::Error::custom)?;
        view.end()
    }
}
struct InstanceViews<'a, 'v>(&'a RealtimeHubReplay<'v>);
impl Serialize for InstanceViews<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.0.instances.len()))?;
        for instance in &self.0.instances {
            seq.serialize_element(&InstanceView {
                instance,
                project: self.0.project.read_mask(),
                channel: self.0.channels[instance.proof_index].read_mask(),
            })?;
        }
        seq.end()
    }
}
struct InstanceView<'a> {
    instance: &'a RealtimeHubInstance,
    project: NowReadMask,
    channel: NowReadMask,
}
impl Serialize for InstanceView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut view = serializer.serialize_struct("RealtimeHubInstance", 3)?;
        view.serialize_field("instance_id", self.instance.instance_id())?;
        view.serialize_field("version", self.instance.version())?;
        view.serialize_field(
            "now",
            &SnapshotView {
                snapshot: &self.instance.snapshot,
                task: self.project.task_read() && self.channel.task_read(),
                memory: self.project.memory_read() && self.channel.memory_read(),
                knowledge: self.project.knowledge_read() && self.channel.knowledge_read(),
            },
        )?;
        view.end()
    }
}
struct SnapshotView<'a> {
    snapshot: &'a NowSnapshotData,
    task: bool,
    memory: bool,
    knowledge: bool,
}
impl Serialize for SnapshotView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut view = serializer.serialize_struct("NowSnapshotData", 3)?;
        view.serialize_field("project_id", self.snapshot.project_id())?;
        view.serialize_field("generated_at", self.snapshot.generated_at())?;
        view.serialize_field("sections", &SectionsView(self))?;
        view.end()
    }
}
struct SectionsView<'a, 'b>(&'a SnapshotView<'b>);
impl Serialize for SectionsView<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let sections = self.0.snapshot.sections();
        let mut view = serializer.serialize_struct("NowSectionsData", 4)?;
        view.serialize_field("tasks", &SectionView(sections.tasks(), self.0.task))?;
        view.serialize_field("sessions", &SectionView(sections.sessions(), self.0.task))?;
        view.serialize_field("memories", &SectionView(sections.memories(), self.0.memory))?;
        view.serialize_field(
            "knowledge",
            &SectionView(sections.knowledge(), self.0.knowledge),
        )?;
        view.end()
    }
}
struct SectionView<'a, T>(&'a T, bool);
impl<T: Serialize> Serialize for SectionView<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.1 {
            self.0.serialize(serializer)
        } else {
            let mut section = serializer.serialize_struct("NowSectionData", 5)?;
            section.serialize_field("availability", &NowSectionAvailability::Failed)?;
            section.serialize_field("items", &[] as &[u8])?;
            section.serialize_field("total", &Option::<u64>::None)?;
            section.serialize_field("has_more", &Option::<bool>::None)?;
            section.serialize_field("error", &Some(NowSectionErrorCode::Forbidden))?;
            section.end()
        }
    }
}
macro_rules! redacted {
    ($($name:ty),+ $(,)?) => { $(impl fmt::Debug for $name { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.write_str(concat!(stringify!($name),"([REDACTED])")) } })+ };
}
redacted!(
    RealtimeHub,
    RealtimeHubMaintenance,
    RealtimePublisherHandle,
    RealtimeProjectSubscription,
    RealtimeHubInstance,
    RealtimeHubReplay<'_>
);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_and_utc_mono_clock_bounds() {
        assert_eq!(
            RealtimeHub::new(Duration::ZERO, NonZeroUsize::new(1).unwrap()).unwrap_err(),
            RealtimeHubError::InvalidConfiguration
        );
        assert_eq!(
            RealtimeHub::new(Duration::MAX, NonZeroUsize::new(1).unwrap()).unwrap_err(),
            RealtimeHubError::InvalidConfiguration
        );
        assert_eq!(
            RealtimeHub::new(
                Duration::from_secs(1),
                NonZeroUsize::new(usize::MAX).unwrap()
            )
            .unwrap_err(),
            RealtimeHubError::InvalidConfiguration
        );
        let mono = Instant::now();
        let utc = SystemTime::now();
        let w = Window {
            utc: utc + Duration::from_secs(3),
            mono: mono + Duration::from_secs(3),
            heartbeat: mono + Duration::from_secs(2),
        };
        assert!(w.active(SystemTime::UNIX_EPOCH, mono));
        assert!(!w.active(SystemTime::UNIX_EPOCH, w.mono));
        assert!(!w.active(w.utc, mono));
        assert!(!w.active(utc, w.heartbeat));
        assert_eq!(w.next(SystemTime::UNIX_EPOCH, mono), w.heartbeat);
        let hub = RealtimeHub::new(Duration::from_secs(1), NonZeroUsize::new(1).unwrap()).unwrap();
        assert_eq!(
            hub.run_maintenance().unwrap_err(),
            RealtimeHubError::InvalidConfiguration
        );
    }
    #[tokio::test]
    async fn maintenance_owner_lifecycle_and_no_cycle() {
        let hub = RealtimeHub::new(Duration::from_secs(1), NonZeroUsize::new(1).unwrap()).unwrap();
        let weak = Arc::downgrade(&hub.state);
        let guard = hub.run_maintenance().unwrap();
        assert_eq!(
            hub.run_maintenance().unwrap_err(),
            RealtimeHubError::InvalidConfiguration
        );
        guard.shutdown().await.unwrap();
        assert_eq!(hub.run_maintenance().unwrap_err(), RealtimeHubError::Closed);
        drop(hub);
        assert!(weak.upgrade().is_none());
        let hub = RealtimeHub::new(Duration::from_secs(1), NonZeroUsize::new(1).unwrap()).unwrap();
        let guard = hub.run_maintenance().unwrap();
        let state = Arc::downgrade(&hub.state);
        drop(guard);
        assert_eq!(hub.run_maintenance().unwrap_err(), RealtimeHubError::Closed);
        drop(hub);
        tokio::task::yield_now().await;
        assert!(state.upgrade().is_none());
    }
}
