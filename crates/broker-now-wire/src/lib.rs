//! Strict, validated Now DATA. This codec does not authenticate a publisher or
//! attest local corpus scans, admissions, activity or a registered channel.
//!
//! ```compile_fail
//! let _ = broker_now_wire::NowSnapshotData::default();
//! ```
//! ```compile_fail
//! fn expose(value: broker_now_wire::NowSnapshotData) { let _ = value.project_id; }
//! ```

//! ```
//! use broker_now_wire::NowSnapshotData;
//! use std::num::NonZeroUsize;
//! let bytes = br#"{"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","generated_at":"0",
//! "sections":{"tasks":{"availability":"no_corpus","items":[],"total":0,"has_more":false,"error":null},
//! "sessions":{"availability":"no_corpus","items":[],"total":0,"has_more":false,"error":null},
//! "memories":{"availability":"no_corpus","items":[],"total":0,"has_more":false,"error":null},
//! "knowledge":{"availability":"no_corpus","items":[],"total":0,"has_more":false,"error":null}}}"#;
//! let data = NowSnapshotData::decode(bytes, NonZeroUsize::new(bytes.len()).unwrap()).unwrap();
//! assert_eq!(data.sections().tasks().total(), Some(0));
//! let masked = data.mask_sections(false, true, true);
//! assert_eq!(masked.sections().tasks().error(), Some(broker_now_wire::NowSectionErrorCode::Forbidden));
//! assert_eq!(masked.sections().sessions().total(), None);
//! assert_eq!(masked.sections().memories().total(), Some(0));
//! ```
//! ```compile_fail
//! fn require_decode<T: for<'de> serde::Deserialize<'de>>() {}
//! require_decode::<broker_now_wire::NowTaskData>();
//! ```
//! ```compile_fail
//! let _ = broker_now_wire::NowSnapshotData::new;
//! ```

use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::HashSet, error::Error, fmt, marker::PhantomData, num::NonZeroUsize};

const SAFE_COUNT_MAX: u64 = 9_007_199_254_740_991;
const MILLION: i128 = 1_000_000;
const MAX_MILLISECONDS_NS: i128 = u64::MAX as i128 * MILLION;

/// Finite errors; neither variant retains input or a Serde cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NowSnapshotDataError {
    InvalidData,
    ReadLimitExceeded,
}
impl fmt::Display for NowSnapshotDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidData => "invalid Now snapshot data",
            Self::ReadLimitExceeded => "Now snapshot read limit exceeded",
        })
    }
}
impl Error for NowSnapshotDataError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", try_from = "String")]
pub enum NowSectionAvailability {
    Available,
    NoCorpus,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", try_from = "String")]
pub enum NowSectionErrorCode {
    Forbidden,
    Unavailable,
    InvalidData,
    LimitExceeded,
    CountsUnavailable,
}

impl TryFrom<String> for NowSectionAvailability {
    type Error = NowSnapshotDataError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "available" => Ok(Self::Available),
            "no_corpus" => Ok(Self::NoCorpus),
            "failed" => Ok(Self::Failed),
            _ => Err(NowSnapshotDataError::InvalidData),
        }
    }
}
impl TryFrom<String> for NowSectionErrorCode {
    type Error = NowSnapshotDataError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "forbidden" => Ok(Self::Forbidden),
            "unavailable" => Ok(Self::Unavailable),
            "invalid_data" => Ok(Self::InvalidData),
            "limit_exceeded" => Ok(Self::LimitExceeded),
            "counts_unavailable" => Ok(Self::CountsUnavailable),
            _ => Err(NowSnapshotDataError::InvalidData),
        }
    }
}

// The public read models have no Deserialize/new/Default. Only the private wire
// models can be decoded; the complete envelope is validated before conversion.
macro_rules! data_row {
    ($name:ident, $raw:ident, { $($field:ident: $ty:ty),+ $(,)? }) => {
        #[derive(Serialize)]
        pub struct $name { $($field: $ty),+ }
        impl $name { $(pub fn $field(&self) -> &$ty { &self.$field })+ }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $raw { $($field: $ty),+ }
        impl From<$raw> for $name {
            fn from(raw: $raw) -> Self { Self { $($field: raw.$field),+ } }
        }
    };
}
data_row!(NowTaskData, RawTask, {
    id: String, session_id: String, title: String, owner: String,
    lease_expires_at: String, updated_at: String,
});
data_row!(NowSessionData, RawSession, {
    id: String, title: String, owner: String, lease_expires_at: String,
    updated_at: String, completed_tasks: u64, total_tasks: u64,
});
data_row!(NowMemoryData, RawMemory, {
    id: String, title: String, updated_by: String, updated_at: String,
});

#[derive(Serialize)]
pub struct NowKnowledgeData {
    slug: String,
    title: String,
    updated_at: Option<String>,
}
impl NowKnowledgeData {
    pub fn slug(&self) -> &str {
        &self.slug
    }
    pub fn title(&self) -> &str {
        &self.title
    }
    pub fn updated_at(&self) -> Option<&str> {
        self.updated_at.as_deref()
    }
}
impl fmt::Debug for NowKnowledgeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NowKnowledgeData").finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKnowledge {
    slug: String,
    title: String,
    #[serde(deserialize_with = "required_nullable")]
    updated_at: Option<String>,
}
impl From<RawKnowledge> for NowKnowledgeData {
    fn from(raw: RawKnowledge) -> Self {
        Self {
            slug: raw.slug,
            title: raw.title,
            updated_at: raw.updated_at,
        }
    }
}

#[derive(Serialize)]
pub struct NowSectionData<T> {
    availability: NowSectionAvailability,
    items: Vec<T>,
    total: Option<u64>,
    has_more: Option<bool>,
    error: Option<NowSectionErrorCode>,
}
impl<T> NowSectionData<T> {
    fn forbid(&mut self) {
        self.availability = NowSectionAvailability::Failed;
        self.items.clear();
        self.total = None;
        self.has_more = None;
        self.error = Some(NowSectionErrorCode::Forbidden);
    }

    pub fn availability(&self) -> NowSectionAvailability {
        self.availability
    }
    pub fn items(&self) -> &[T] {
        &self.items
    }
    pub fn total(&self) -> Option<u64> {
        self.total
    }
    pub fn has_more(&self) -> Option<bool> {
        self.has_more
    }
    pub fn error(&self) -> Option<NowSectionErrorCode> {
        self.error
    }
}
impl<T> fmt::Debug for NowSectionData<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NowSectionData").finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
struct RawSection<T> {
    availability: NowSectionAvailability,
    #[serde(deserialize_with = "object_items")]
    items: Vec<T>,
    #[serde(deserialize_with = "required_nullable")]
    total: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    has_more: Option<bool>,
    #[serde(deserialize_with = "required_nullable")]
    error: Option<NowSectionErrorCode>,
}
impl<T> RawSection<T> {
    fn validate(&self) -> bool {
        match self.availability {
            NowSectionAvailability::Available => self.total.is_some_and(|total| {
                total <= SAFE_COUNT_MAX
                    && self.items.len() as u128 == u128::from(total).min(20)
                    && self.has_more == Some(u128::from(total) > self.items.len() as u128)
                    && self.error.is_none()
            }),
            NowSectionAvailability::NoCorpus => {
                self.items.is_empty()
                    && self.total == Some(0)
                    && self.has_more == Some(false)
                    && self.error.is_none()
            }
            NowSectionAvailability::Failed => {
                self.items.is_empty()
                    && self.total.is_none()
                    && self.has_more.is_none()
                    && self.error.is_some()
            }
        }
    }
    fn into_data<U: From<T>>(self) -> NowSectionData<U> {
        NowSectionData {
            availability: self.availability,
            items: self.items.into_iter().map(U::from).collect(),
            total: self.total,
            has_more: self.has_more,
            error: self.error,
        }
    }
}

#[derive(Serialize)]
pub struct NowSectionsData {
    tasks: NowSectionData<NowTaskData>,
    sessions: NowSectionData<NowSessionData>,
    memories: NowSectionData<NowMemoryData>,
    knowledge: NowSectionData<NowKnowledgeData>,
}
impl NowSectionsData {
    pub fn tasks(&self) -> &NowSectionData<NowTaskData> {
        &self.tasks
    }
    pub fn sessions(&self) -> &NowSectionData<NowSessionData> {
        &self.sessions
    }
    pub fn memories(&self) -> &NowSectionData<NowMemoryData> {
        &self.memories
    }
    pub fn knowledge(&self) -> &NowSectionData<NowKnowledgeData> {
        &self.knowledge
    }
}
impl fmt::Debug for NowSectionsData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NowSectionsData").finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSections {
    #[serde(deserialize_with = "object")]
    tasks: RawSection<RawTask>,
    #[serde(deserialize_with = "object")]
    sessions: RawSection<RawSession>,
    #[serde(deserialize_with = "object")]
    memories: RawSection<RawMemory>,
    #[serde(deserialize_with = "object")]
    knowledge: RawSection<RawKnowledge>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSnapshot {
    project_id: String,
    generated_at: String,
    #[serde(deserialize_with = "object")]
    sections: RawSections,
}

/// Owned, validated DATA. Deserialize validates exactly as `decode`; a transport
/// must impose its own byte budget when decoding a containing command.
#[derive(Serialize)]
pub struct NowSnapshotData {
    project_id: String,
    generated_at: String,
    sections: NowSectionsData,
}
impl fmt::Debug for NowSnapshotData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NowSnapshotData").finish_non_exhaustive()
    }
}
impl<'de> Deserialize<'de> for NowSnapshotData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: RawSnapshot = object(deserializer)?;
        if !raw.validate() {
            return Err(serde::de::Error::custom("invalid Now snapshot data"));
        }
        Ok(Self {
            project_id: raw.project_id,
            generated_at: raw.generated_at,
            sections: NowSectionsData {
                tasks: raw.sections.tasks.into_data(),
                sessions: raw.sections.sessions.into_data(),
                memories: raw.sections.memories.into_data(),
                knowledge: raw.sections.knowledge.into_data(),
            },
        })
    }
}
impl NowSnapshotData {
    /// Consume validated DATA, removing sections that the caller selects out.
    /// Task selection covers both tasks and sessions. Headers and selected-in
    /// sections retain their values and allocations; removed rows are dropped.
    /// Reapplying `true` cannot restore a section that was already removed.
    ///
    /// These flags are DATA selection, not authentication or authorization.
    /// The caller must derive them from its current authorization proof.
    /// No parsing, cloning or whole-snapshot serialization occurs here.
    ///
    /// ```compile_fail
    /// fn consume(data: broker_now_wire::NowSnapshotData) {
    ///     let masked = data.mask_sections(false, false, false);
    ///     let _ = data.sections(); // the original value has been consumed
    /// }
    /// ```
    pub fn mask_sections(
        mut self,
        task_read: bool,
        memory_read: bool,
        knowledge_read: bool,
    ) -> Self {
        if !task_read {
            self.sections.tasks.forbid();
            self.sections.sessions.forbid();
        }
        if !memory_read {
            self.sections.memories.forbid();
        }
        if !knowledge_read {
            self.sections.knowledge.forbid();
        }
        self
    }

    pub fn decode(
        bytes: &[u8],
        snapshot_bytes: NonZeroUsize,
    ) -> Result<Self, NowSnapshotDataError> {
        if bytes.len() > snapshot_bytes.get() {
            return Err(NowSnapshotDataError::ReadLimitExceeded);
        }
        serde_json::from_slice(bytes).map_err(|_| NowSnapshotDataError::InvalidData)
    }
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
    pub fn generated_at(&self) -> &str {
        &self.generated_at
    }
    pub fn sections(&self) -> &NowSectionsData {
        &self.sections
    }
}

// Serde's derived struct decoder also accepts positional sequences. Use its
// map decoder explicitly at every object boundary, preserving duplicate checks.
fn object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectVisitor<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(ObjectVisitor(PhantomData))
}
fn object_items<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(T);
    impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            object(deserializer).map(Self)
        }
    }
    Vec::<Object<T>>::deserialize(deserializer)
        .map(|rows| rows.into_iter().map(|row| row.0).collect())
}

// Explicit deserialize_with makes even nullable fields mandatory: absence is a
// missing-field error, whereas JSON null is the contractual None.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl RawSnapshot {
    fn validate(&self) -> bool {
        let Some(generated) = decimal(&self.generated_at)
            .filter(|n| (0..=MAX_MILLISECONDS_NS + MILLION - 1).contains(n))
        else {
            return false;
        };
        let sections = &self.sections;
        canonical_id(&self.project_id)
            && sections.tasks.validate()
            && sections.sessions.validate()
            && sections.memories.validate()
            && sections.knowledge.validate()
            && ordered(
                &sections.tasks.items,
                |row| &row.id,
                |row| milliseconds(&row.updated_at).map(Some),
                |row| {
                    canonical_id(&row.id)
                        && canonical_id(&row.session_id)
                        && exact_title(&row.title)
                        && actor(&row.owner)
                        && milliseconds(&row.lease_expires_at).is_some_and(|n| n > generated)
                },
            )
            && ordered(
                &sections.sessions.items,
                |row| &row.id,
                |row| milliseconds(&row.updated_at).map(Some),
                |row| {
                    canonical_id(&row.id)
                        && exact_title(&row.title)
                        && actor(&row.owner)
                        && milliseconds(&row.lease_expires_at).is_some_and(|n| n > generated)
                        && row.total_tasks <= SAFE_COUNT_MAX
                        && row.completed_tasks <= row.total_tasks
                },
            )
            && ordered(
                &sections.memories.items,
                |row| &row.id,
                |row| milliseconds(&row.updated_at).map(Some),
                |row| {
                    canonical_id(&row.id) && !row.title.trim().is_empty() && actor(&row.updated_by)
                },
            )
            && ordered(
                &sections.knowledge.items,
                |row| &row.slug,
                |row| match &row.updated_at {
                    Some(value) => decimal(value)
                        .filter(|n| i64::try_from(*n).is_ok())
                        .map(Some),
                    None => Some(None),
                },
                |row| valid_slug(&row.slug),
            )
    }
}

// Unknown Knowledge times sort last; all numeric keys stay in i128.
fn ordered<T>(
    rows: &[T],
    id: impl Fn(&T) -> &str,
    timestamp: impl Fn(&T) -> Option<Option<i128>>,
    validate: impl Fn(&T) -> bool,
) -> bool {
    let mut ids = HashSet::with_capacity(rows.len());
    let mut previous: Option<(Option<i128>, &str)> = None;
    for row in rows {
        let Some(time) = timestamp(row) else {
            return false;
        };
        let current_id = id(row);
        if !validate(row) || !ids.insert(current_id) {
            return false;
        }
        if let Some((previous_time, previous_id)) = previous
            && (previous_time < time || (previous_time == time && previous_id >= current_id))
        {
            return false;
        }
        previous = Some((time, current_id));
    }
    true
}
fn canonical_id(value: &str) -> bool {
    ulid::Ulid::from_string(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
fn exact_title(value: &str) -> bool {
    !value.is_empty() && value.trim() == value
}
fn actor(value: &str) -> bool {
    value.len() == 26
        && ulid::Ulid::from_string(value).is_ok_and(|identifier| identifier.to_string() == value)
}
fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with("..")
        && !value.contains(['/', '\\'])
        && !value.chars().any(char::is_control)
}
fn decimal(value: &str) -> Option<i128> {
    let n: i128 = value.parse().ok()?;
    (n.to_string() == value).then_some(n)
}
fn milliseconds(value: &str) -> Option<i128> {
    decimal(value).filter(|n| (0..=MAX_MILLISECONDS_NS).contains(n) && n % MILLION == 0)
}
