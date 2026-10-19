use crate::{
    FilesystemSessionError, VerifiedFilesystemSession, filesystem_session::key as valid_key,
};
use broker_control::StorageOperation;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use cap_tempfile::TempDir;
use parking_lot::{Mutex, MutexGuard};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    fs::{File, TryLockError},
    io::{self, Read, Seek, SeekFrom, Write},
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
    path::PathBuf,
    time::{Duration, Instant, SystemTime},
};
use tokio_util::sync::CancellationToken;

pub struct FilesystemStoreConfig {
    pub directory: PathBuf,
    pub bucket: String,
    pub max_object_bytes: NonZeroU64,
    pub metadata_bytes: NonZeroUsize,
}
impl fmt::Debug for FilesystemStoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FilesystemStoreConfig([REDACTED])")
    }
}
pub struct FilesystemRequest {
    pub deadline: Instant,
    pub cancellation: CancellationToken,
}
impl FilesystemRequest {
    pub(crate) fn check(
        &self,
        session: &VerifiedFilesystemSession,
    ) -> Result<(), FilesystemStoreError> {
        session
            .check(self.deadline)
            .map_err(FilesystemStoreError::Session)?;
        if self.cancellation.is_cancelled() {
            return Err(FilesystemStoreError::Cancelled);
        }
        Ok(())
    }
}
#[derive(Default)]
pub struct FilesystemConditions {
    pub if_match: Option<String>,
    pub if_none_match: Option<String>,
}
pub struct FilesystemPutOptions<'a> {
    pub content_type: Option<&'a str>,
    pub expected_digest: Option<&'a str>,
    pub conditions: &'a FilesystemConditions,
}
#[derive(Clone, Debug)]
pub struct FilesystemObjectInfo {
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub modified: SystemTime,
}
pub struct FilesystemObjectRead {
    pub file: File,
    pub info: FilesystemObjectInfo,
    pub offset: u64,
    pub length: u64,
}

pub enum FilesystemStoreError {
    InvalidConfiguration,
    VolumeBusy,
    InvalidKey,
    Forbidden,
    NotFound,
    InvalidRange,
    InvalidArgument,
    NoSuchUpload,
    InvalidPart,
    InvalidPartOrder,
    Crypto,
    InvalidMetadata,
    Precondition,
    BadDigest,
    TooLarge,
    Cancelled,
    Session(FilesystemSessionError),
    Io(io::Error),
    CommitUncertain(Box<FilesystemStoreError>),
}
impl fmt::Debug for FilesystemStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl fmt::Display for FilesystemStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid filesystem storage configuration",
            Self::VolumeBusy => "filesystem volume is already owned",
            Self::InvalidKey => "invalid filesystem key",
            Self::Forbidden => "filesystem access denied",
            Self::NotFound => "filesystem object not found",
            Self::InvalidRange => "invalid filesystem range",
            Self::InvalidArgument => "invalid filesystem argument",
            Self::NoSuchUpload => "filesystem upload unavailable",
            Self::InvalidPart => "invalid filesystem part",
            Self::InvalidPartOrder => "invalid filesystem part order",
            Self::Crypto => "filesystem entropy unavailable",
            Self::InvalidMetadata => "invalid filesystem authored metadata",
            Self::Precondition => "filesystem precondition failed",
            Self::BadDigest => "filesystem payload digest mismatch",
            Self::TooLarge => "filesystem object exceeds configured limit",
            Self::Cancelled => "filesystem request cancelled",
            Self::Session(_) => "filesystem session unavailable",
            Self::Io(_) => "filesystem IO failed",
            Self::CommitUncertain(_) => "filesystem commit outcome uncertain",
        })
    }
}
impl Error for FilesystemStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Session(e) => Some(e),
            Self::CommitUncertain(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}
impl From<io::Error> for FilesystemStoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    content_type: Value,
    #[serde(default)]
    derived: Value,
}
pub(crate) struct PreparedObject {
    pub(crate) stage: TempDir,
    pub(crate) info: FilesystemObjectInfo,
}

pub struct FilesystemStore {
    pub(crate) config: FilesystemStoreConfig,
    pub(crate) data: Dir,
    pub(crate) meta: Dir,
    pub(crate) temporary: Dir,
    pub(crate) multipart: Dir,
    _volume_owner: File,
    pub(crate) metadata_read_limit: u64,
    pub(crate) shards: [Mutex<()>; 256],
}
impl fmt::Debug for FilesystemStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FilesystemStore([REDACTED])")
    }
}
pub(crate) fn options(read: bool, create: bool) -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(read)
        .write(create)
        .create_new(create)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}
pub(crate) fn owned_dir(parent: &Dir, name: &str) -> Result<Dir, FilesystemStoreError> {
    let mut builder = cap_std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match parent.create_dir_with(name, &builder) {
        Ok(()) => sync_dir(parent)?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    parent
        .open_dir_nofollow(name)
        .map_err(FilesystemStoreError::Io)
}
pub(crate) fn sync_dir(dir: &Dir) -> Result<(), FilesystemStoreError> {
    // Capability directory handles may be O_PATH: reopen this held directory for IO.
    dir.open_with(".", &options(true, false))?
        .sync_all()
        .map_err(FilesystemStoreError::Io)
}
pub(crate) fn header(s: &str) -> bool {
    !s.is_empty() && http::HeaderValue::from_str(s).is_ok()
}
pub(crate) fn etag(hash: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(66);
    out.push('"');
    for b in hash {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 15) as usize]));
    }
    out.push('"');
    out
}
pub(crate) fn valid_etag(s: &str) -> bool {
    s.len() == 66
        && s.starts_with('"')
        && s.ends_with('"')
        && s.as_bytes()[1..65].iter().all(u8::is_ascii_hexdigit)
}
fn condition(value: &str, current: Option<&str>) -> bool {
    value.split(',').map(str::trim).any(|v| {
        if v == "*" {
            current.is_some()
        } else {
            valid_etag(v) && current == Some(v)
        }
    })
}
impl FilesystemConditions {
    pub(crate) fn check(&self, current: Option<&str>) -> Result<(), FilesystemStoreError> {
        if self
            .if_match
            .as_deref()
            .is_some_and(|v| !condition(v, current))
            || self
                .if_none_match
                .as_deref()
                .is_some_and(|v| condition(v, current))
        {
            return Err(FilesystemStoreError::Precondition);
        }
        Ok(())
    }
}
impl FilesystemStore {
    pub fn open(config: FilesystemStoreConfig) -> Result<Self, FilesystemStoreError> {
        if config.directory.as_os_str().is_empty() || config.bucket.is_empty() {
            return Err(FilesystemStoreError::InvalidConfiguration);
        }
        let metadata_read_limit = u64::try_from(config.metadata_bytes.get())
            .ok()
            .and_then(|limit| limit.checked_add(1))
            .ok_or(FilesystemStoreError::InvalidConfiguration)?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&config.directory)?;
        let root = Dir::open_ambient_dir(&config.directory, ambient_authority())?;
        let mut o = OpenOptions::new();
        o.read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let owner = root.open_with("owner.lock", &o)?.into_std();
        match owner.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(FilesystemStoreError::VolumeBusy),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        let data = owned_dir(&root, "data")?;
        let meta = owned_dir(&root, "meta")?;
        let temporary = owned_dir(&root, "tmp")?;
        let multipart = owned_dir(&root, "multipart")?;
        // Startup owns this directory exclusively; no published data lives here.
        for entry in temporary.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                temporary.open_dir_nofollow(&name)?.remove_open_dir_all()?;
            } else {
                temporary.remove_file(&name)?;
            }
        }
        sync_dir(&root)?;
        let store = Self {
            config,
            data,
            meta,
            temporary,
            multipart,
            _volume_owner: owner,
            metadata_read_limit,
            shards: std::array::from_fn(|_| Mutex::new(())),
        };
        store.prune_multipart_startup()?;
        Ok(store)
    }
    pub(crate) fn shard(key: &str) -> usize {
        usize::from(Sha256::digest(key.as_bytes())[0])
    }
    pub(crate) fn lock<'a>(
        &'a self,
        key: &str,
        session: &VerifiedFilesystemSession,
        request: &FilesystemRequest,
    ) -> Result<MutexGuard<'a, ()>, FilesystemStoreError> {
        loop {
            request.check(session)?;
            if let Some(guard) =
                self.shards[Self::shard(key)].try_lock_for(Duration::from_millis(10))
            {
                request.check(session)?;
                return Ok(guard);
            }
        }
    }
    pub(crate) fn authorize(
        &self,
        session: &VerifiedFilesystemSession,
        request: &FilesystemRequest,
        operation: StorageOperation,
        key: &str,
    ) -> Result<(), FilesystemStoreError> {
        request.check(session)?;
        if session.bucket() != self.config.bucket {
            return Err(FilesystemStoreError::Forbidden);
        }
        if !valid_key(key) {
            return Err(FilesystemStoreError::InvalidKey);
        }
        if !session.allows(operation, key) {
            return Err(FilesystemStoreError::Forbidden);
        }
        Ok(())
    }
    pub(crate) fn parent(
        root: &Dir,
        key: &str,
        create: bool,
    ) -> Result<(Dir, String), FilesystemStoreError> {
        if !valid_key(key) {
            return Err(FilesystemStoreError::InvalidKey);
        }
        let mut parts = key.split('/').peekable();
        let mut dir = root.try_clone()?;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                return Ok((dir, part.into()));
            }
            dir = if create {
                owned_dir(&dir, part)?
            } else {
                dir.open_dir_nofollow(part).map_err(|e| {
                    if e.kind() == io::ErrorKind::NotFound {
                        FilesystemStoreError::NotFound
                    } else {
                        FilesystemStoreError::Io(e)
                    }
                })?
            };
        }
        Err(FilesystemStoreError::InvalidKey)
    }
    pub(crate) fn data_file(&self, key: &str) -> Result<File, FilesystemStoreError> {
        let (dir, name) = Self::parent(&self.data, key, false)?;
        let f = dir
            .open_with(&name, &options(true, false))
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    FilesystemStoreError::NotFound
                } else {
                    FilesystemStoreError::Io(e)
                }
            })?
            .into_std();
        if !f.metadata()?.is_file() {
            return Err(FilesystemStoreError::InvalidKey);
        }
        Ok(f)
    }
    fn metadata(&self, key: &str) -> Result<Option<Metadata>, FilesystemStoreError> {
        let (dir, name) = match Self::parent(&self.meta, key, false) {
            Ok(p) => p,
            Err(FilesystemStoreError::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut f = match dir.open_with(&name, &options(true, false)) {
            Ok(f) => f.into_std(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !f.metadata()?.is_file() {
            return Err(FilesystemStoreError::InvalidMetadata);
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut f)
            .take(self.metadata_read_limit)
            .read_to_end(&mut bytes)?;
        if bytes.len() > self.config.metadata_bytes.get() {
            return Err(FilesystemStoreError::InvalidMetadata);
        }
        let meta: Metadata =
            serde_json::from_slice(&bytes).map_err(|_| FilesystemStoreError::InvalidMetadata)?;
        if !meta.content_type.is_null() && !meta.content_type.as_str().is_some_and(header) {
            return Err(FilesystemStoreError::InvalidMetadata);
        }
        Ok(Some(meta))
    }
    pub(crate) fn describe(
        &self,
        key: &str,
        file: &mut File,
        session: &VerifiedFilesystemSession,
        request: &FilesystemRequest,
    ) -> Result<FilesystemObjectInfo, FilesystemStoreError> {
        request.check(session)?;
        let stat = file.metadata()?;
        let size = stat.len();
        let modified = stat.modified()?;
        let meta = self.metadata(key)?;
        let content_type = meta
            .as_ref()
            .and_then(|m| m.content_type.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| {
                mime_guess::from_path(key)
                    .first_or_octet_stream()
                    .to_string()
            });
        let expected_time = serde_json::to_value(modified).ok();
        let cached = expected_time.as_ref().and_then(|time| {
            meta.as_ref().and_then(|m| {
                let value = &m.derived;
                let e = value.get("etag")?.as_str()?;
                (valid_etag(e)
                    && value.get("size").and_then(Value::as_u64) == Some(size)
                    && value.get("modified") == Some(time))
                .then(|| e.to_owned())
            })
        });
        let etag = if let Some(e) = cached {
            e
        } else {
            file.seek(SeekFrom::Start(0))?;
            let mut digest = Sha256::new();
            let mut buf = [0u8; 16384];
            loop {
                request.check(session)?;
                let count = file.read(&mut buf)?;
                if count == 0 {
                    break;
                }
                digest.update(&buf[..count]);
            }
            etag(&digest.finalize())
        };
        file.seek(SeekFrom::Start(0))?;
        request.check(session)?;
        Ok(FilesystemObjectInfo {
            size,
            etag,
            content_type,
            modified,
        })
    }
    pub fn head(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        request: &FilesystemRequest,
    ) -> Result<FilesystemObjectInfo, FilesystemStoreError> {
        self.authorize(session, request, StorageOperation::Read, key)?;
        let result = (|| {
            let _guard = self.lock(key, session, request)?;
            let mut file = self.data_file(key)?;
            self.describe(key, &mut file, session, request)
        })();
        request.check(session)?;
        result
    }
    pub fn open_range(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        range: Option<Range<u64>>,
        request: &FilesystemRequest,
    ) -> Result<FilesystemObjectRead, FilesystemStoreError> {
        self.authorize(session, request, StorageOperation::Read, key)?;
        let result = (|| {
            let _guard = self.lock(key, session, request)?;
            let mut file = self.data_file(key)?;
            let info = self.describe(key, &mut file, session, request)?;
            let (offset, length) = match range {
                None => (0, info.size),
                Some(r) if r.start < info.size && r.end > r.start => {
                    (r.start, r.end.min(info.size) - r.start)
                }
                _ => return Err(FilesystemStoreError::InvalidRange),
            };
            file.seek(SeekFrom::Start(offset))?;
            Ok(FilesystemObjectRead {
                file,
                info,
                offset,
                length,
            })
        })();
        request.check(session)?;
        result
    }
    pub(crate) fn prepare<R: Read>(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        body: &mut R,
        content_type: Option<&str>,
        expected_digest: Option<&str>,
        request: &FilesystemRequest,
    ) -> Result<PreparedObject, FilesystemStoreError> {
        request.check(session)?;
        if content_type.is_some_and(|s| !header(s)) {
            return Err(FilesystemStoreError::InvalidMetadata);
        }
        if expected_digest
            .is_some_and(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(FilesystemStoreError::BadDigest);
        }
        let authored = content_type.map_or(Value::Null, |s| Value::String(s.into()));
        let author_bytes = serde_json::to_vec(&Metadata {
            content_type: authored.clone(),
            derived: Value::Null,
        })
        .map_err(|_| FilesystemStoreError::InvalidMetadata)?;
        if author_bytes.len() > self.config.metadata_bytes.get() {
            return Err(FilesystemStoreError::InvalidMetadata);
        }
        let stage = TempDir::new_in(&self.temporary)?;
        let mut file = stage
            .open_with("payload", &options(false, true))?
            .into_std();
        let mut digest = Sha256::new();
        let mut size = 0u64;
        let mut buf = [0u8; 16384];
        loop {
            request.check(session)?;
            let count = body.read(&mut buf)?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(count as u64)
                .ok_or(FilesystemStoreError::TooLarge)?;
            if size > self.config.max_object_bytes.get() {
                return Err(FilesystemStoreError::TooLarge);
            }
            digest.update(&buf[..count]);
            file.write_all(&buf[..count])?;
        }
        let hash = etag(&digest.finalize());
        if expected_digest.is_some_and(|d| !d.eq_ignore_ascii_case(&hash[1..65])) {
            return Err(FilesystemStoreError::BadDigest);
        }
        file.sync_all()?;
        let modified = file.metadata()?.modified()?;
        let metadata = Metadata {
            content_type: authored,
            derived: serde_json::to_value(modified).ok().map_or(
                Value::Null,
                |time| json!({"etag":hash,"size":size,"modified":time}),
            ),
        };
        let bytes =
            serde_json::to_vec(&metadata).map_err(|_| FilesystemStoreError::InvalidMetadata)?;
        if bytes.len() > self.config.metadata_bytes.get() {
            return Err(FilesystemStoreError::InvalidMetadata);
        }
        let mut author = stage
            .open_with("metadata", &options(false, true))?
            .into_std();
        author.write_all(&bytes)?;
        author.sync_all()?;
        request.check(session)?;
        let content_type = content_type.map(str::to_owned).unwrap_or_else(|| {
            mime_guess::from_path(key)
                .first_or_octet_stream()
                .to_string()
        });
        Ok(PreparedObject {
            stage,
            info: FilesystemObjectInfo {
                size,
                etag: hash,
                content_type,
                modified,
            },
        })
    }
    pub(crate) fn publish_locked(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        prepared: PreparedObject,
        conditions: &FilesystemConditions,
        request: &FilesystemRequest,
    ) -> Result<FilesystemObjectInfo, FilesystemStoreError> {
        request.check(session)?;
        if conditions.if_match.is_some() || conditions.if_none_match.is_some() {
            let current = match self.data_file(key) {
                Ok(mut f) => Some(self.describe(key, &mut f, session, request)?.etag),
                Err(FilesystemStoreError::NotFound) => None,
                Err(e) => return Err(e),
            };
            conditions.check(current.as_deref())?;
        }
        let (data, name) = Self::parent(&self.data, key, true)?;
        let (meta, metaname) = Self::parent(&self.meta, key, true)?;
        for (dir, filename) in [(&data, &name), (&meta, &metaname)] {
            match dir.symlink_metadata(filename) {
                Ok(m) if !m.is_file() => return Err(FilesystemStoreError::InvalidKey),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        request.check(session)?;
        prepared.stage.rename("payload", &data, &name)?;
        let after = (|| {
            prepared.stage.rename("metadata", &meta, &metaname)?;
            sync_dir(&data)?;
            sync_dir(&meta)?;
            request.check(session)?;
            prepared.stage.close()?;
            Ok(())
        })();
        after.map_err(|e| FilesystemStoreError::CommitUncertain(Box::new(e)))?;
        Ok(prepared.info)
    }
    pub fn put<R: Read>(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        mut body: R,
        options: FilesystemPutOptions<'_>,
        request: &FilesystemRequest,
    ) -> Result<FilesystemObjectInfo, FilesystemStoreError> {
        self.authorize(session, request, StorageOperation::Write, key)?;
        let result = (|| {
            let prepared = self.prepare(
                session,
                key,
                &mut body,
                options.content_type,
                options.expected_digest,
                request,
            )?;
            let _guard = self.lock(key, session, request)?;
            self.publish_locked(session, key, prepared, options.conditions, request)
        })();
        match result {
            Ok(info) => {
                request
                    .check(session)
                    .map_err(|e| FilesystemStoreError::CommitUncertain(Box::new(e)))?;
                Ok(info)
            }
            Err(e @ FilesystemStoreError::CommitUncertain(_)) => Err(e),
            Err(e) => {
                request.check(session)?;
                Err(e)
            }
        }
    }
    pub fn delete(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        request: &FilesystemRequest,
    ) -> Result<(), FilesystemStoreError> {
        self.delete_inner(session, key, None, request)
    }
    /// Compare the current native ETag and delete under the same key lock.
    /// The existence wildcard requires a current object; only Delete authority is required.
    pub fn delete_if_match(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        if_match: &str,
        request: &FilesystemRequest,
    ) -> Result<(), FilesystemStoreError> {
        self.delete_inner(session, key, Some(if_match), request)
    }
    fn delete_inner(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        if_match: Option<&str>,
        request: &FilesystemRequest,
    ) -> Result<(), FilesystemStoreError> {
        self.authorize(session, request, StorageOperation::Delete, key)?;
        let result = (|| {
            let _guard = self.lock(key, session, request)?;
            if let Some(if_match) = if_match {
                let current = match self.data_file(key) {
                    Ok(mut file) => Some(self.describe(key, &mut file, session, request)?.etag),
                    Err(FilesystemStoreError::NotFound) => None,
                    Err(error) => return Err(error),
                };
                FilesystemConditions {
                    if_match: Some(if_match.to_owned()),
                    if_none_match: None,
                }
                .check(current.as_deref())?;
            }
            let (data, name) = match Self::parent(&self.data, key, false) {
                Ok(p) => p,
                Err(FilesystemStoreError::NotFound) => return Ok(false),
                Err(e) => return Err(e),
            };
            match data.symlink_metadata(&name) {
                Ok(m) if !m.is_file() => return Err(FilesystemStoreError::InvalidKey),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(e) => return Err(e.into()),
            };
            request.check(session)?;
            data.remove_file(&name)?;
            let after = (|| {
                match Self::parent(&self.meta, key, false) {
                    Ok((meta, name)) => match meta.remove_file(name) {
                        Ok(()) => sync_dir(&meta)?,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    },
                    Err(FilesystemStoreError::NotFound) => {}
                    Err(e) => return Err(e),
                };
                sync_dir(&data)?;
                request.check(session)
            })();
            after.map_err(|e| FilesystemStoreError::CommitUncertain(Box::new(e)))?;
            Ok(true)
        })();
        match result {
            Ok(removed) => match request.check(session) {
                Ok(()) => Ok(()),
                Err(e) if removed => Err(FilesystemStoreError::CommitUncertain(Box::new(e))),
                Err(e) => Err(e),
            },
            Err(e @ FilesystemStoreError::CommitUncertain(_)) => Err(e),
            Err(e) => {
                request.check(session)?;
                Err(e)
            }
        }
    }
}
