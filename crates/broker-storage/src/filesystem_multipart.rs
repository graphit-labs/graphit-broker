use crate::{
    FilesystemConditions, FilesystemObjectInfo, FilesystemRequest, FilesystemStore,
    FilesystemStoreError, VerifiedFilesystemSession,
    filesystem_session::key as valid_key,
    filesystem_store::{create_store_dir, etag, header, options, owned_dir, sync_dir, valid_etag},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::StorageOperation;
use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use cap_tempfile::TempDir;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_PART: i32 = 10000;
const ABANDONED_SECONDS: u64 = 24 * 60 * 60;
#[derive(Clone, Debug)]
pub struct FilesystemPartInfo {
    pub number: i32,
    pub etag: String,
    pub size: u64,
    pub modified: SystemTime,
}
pub struct FilesystemPartsRequest<'a> {
    pub upload_id: &'a str,
    pub marker: Option<i32>,
    pub max_parts: Option<i32>,
}
pub struct FilesystemPartsPage {
    pub parts: Vec<FilesystemPartInfo>,
    pub is_truncated: bool,
    pub next_marker: Option<i32>,
}
pub struct FilesystemCompletedPart {
    pub number: i32,
    pub etag: String,
}
pub struct FilesystemCompleteUpload<'a> {
    pub upload_id: &'a str,
    pub parts: &'a [FilesystemCompletedPart],
    pub conditions: &'a FilesystemConditions,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    bucket: String,
    key: String,
    content_type: Value,
    created: u64,
    last_progress: u64,
}
fn seconds() -> Result<u64, FilesystemStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| FilesystemStoreError::InvalidMetadata)
}
fn upload_id(id: &str) -> bool {
    id.len() == 43
        && URL_SAFE_NO_PAD
            .decode(id)
            .is_ok_and(|bytes| bytes.len() == 32)
}
fn upload_lock(id: &str) -> String {
    format!("multipart:{id}")
}
fn uncertain(error: FilesystemStoreError) -> FilesystemStoreError {
    if matches!(error, FilesystemStoreError::CommitUncertain(_)) {
        error
    } else {
        FilesystemStoreError::CommitUncertain(Box::new(error))
    }
}
#[derive(Debug)]
struct InvalidPartBody;
impl fmt::Display for InvalidPartBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("multipart payload does not match its part")
    }
}
impl Error for InvalidPartBody {}
fn invalid_body() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, InvalidPartBody)
}

struct PartsReader<'a> {
    directory: Dir,
    parts: &'a [FilesystemCompletedPart],
    index: usize,
    file: Option<File>,
    digest: Sha256,
}
impl Read for PartsReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let Some(part) = self.parts.get(self.index) else {
                return Ok(0);
            };
            if self.file.is_none() {
                let file = self
                    .directory
                    .open_with(part.number.to_string(), &options(true, false))
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            invalid_body()
                        } else {
                            e
                        }
                    })?
                    .into_std();
                if !file.metadata()?.is_file() {
                    return Err(invalid_body());
                }
                self.file = Some(file);
                self.digest = Sha256::new();
            }
            let count = self.file.as_mut().ok_or_else(invalid_body)?.read(buf)?;
            if count != 0 {
                self.digest.update(&buf[..count]);
                return Ok(count);
            }
            if etag(&self.digest.finalize_reset()) != part.etag {
                return Err(invalid_body());
            }
            self.file = None;
            self.index += 1;
        }
    }
}
impl FilesystemStore {
    fn upload_directory(&self, id: &str) -> Result<Dir, FilesystemStoreError> {
        if !upload_id(id) {
            return Err(FilesystemStoreError::NoSuchUpload);
        }
        self.multipart.open_dir_nofollow(id).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                FilesystemStoreError::NoSuchUpload
            } else {
                e.into()
            }
        })
    }
    fn read_upload_manifest(&self, upload: &Dir) -> Result<Manifest, FilesystemStoreError> {
        let mut file = upload
            .open_with("manifest", &options(true, false))
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    FilesystemStoreError::NoSuchUpload
                } else {
                    e.into()
                }
            })?
            .into_std();
        if !file.metadata()?.is_file() {
            return Err(FilesystemStoreError::InvalidMetadata);
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(self.metadata_read_limit)
            .read_to_end(&mut bytes)?;
        if bytes.len() > self.config.metadata_bytes.get() {
            return Err(FilesystemStoreError::InvalidMetadata);
        }
        let state: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| FilesystemStoreError::InvalidMetadata)?;
        if state.bucket != self.config.bucket
            || !valid_key(&state.key)
            || state.last_progress < state.created
            || (!state.content_type.is_null() && !state.content_type.as_str().is_some_and(header))
        {
            return Err(FilesystemStoreError::InvalidMetadata);
        }
        Ok(state)
    }
    fn current_upload(&self, key: &str, id: &str) -> Result<(Dir, Manifest), FilesystemStoreError> {
        let dir = self.upload_directory(id)?;
        let manifest = self.read_upload_manifest(&dir)?;
        if manifest.key != key {
            return Err(FilesystemStoreError::NoSuchUpload);
        }
        Ok((dir, manifest))
    }
    fn manifest_bytes(&self, state: &Manifest) -> Result<Vec<u8>, FilesystemStoreError> {
        let bytes = serde_json::to_vec(state).map_err(|_| FilesystemStoreError::InvalidMetadata)?;
        if bytes.len() > self.config.metadata_bytes.get() {
            return Err(FilesystemStoreError::InvalidMetadata);
        }
        Ok(bytes)
    }
    fn write_upload_manifest(
        &self,
        upload: &Dir,
        state: &Manifest,
    ) -> Result<(), FilesystemStoreError> {
        let bytes = self.manifest_bytes(state)?;
        let stage = TempDir::new_in(&self.temporary)?;
        let mut file = stage
            .open_with("manifest", &options(false, true))?
            .into_std();
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        match upload.symlink_metadata("manifest") {
            Ok(m) if !m.is_file() => return Err(FilesystemStoreError::InvalidMetadata),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        stage.rename("manifest", upload, "manifest")?;
        let after = (|| {
            sync_dir(upload)?;
            stage.close()?;
            Ok(())
        })();
        after.map_err(uncertain)
    }
    fn remove_upload(&self, dir: Dir) -> Result<(), FilesystemStoreError> {
        dir.remove_open_dir_all()?;
        sync_dir(&self.multipart)
    }
    fn prune_upload(&self, id: &str, now: u64) -> Result<(), FilesystemStoreError> {
        let dir = match self.upload_directory(id) {
            Ok(dir) => dir,
            Err(FilesystemStoreError::NoSuchUpload) => return Ok(()),
            Err(error) => return Err(error),
        };
        match self.read_upload_manifest(&dir) {
            Ok(state) if now.saturating_sub(state.last_progress) >= ABANDONED_SECONDS => {
                self.remove_upload(dir)
            }
            Ok(_) => Ok(()),
            // No committed manifest means no active native upload state.
            Err(FilesystemStoreError::NoSuchUpload) => self.remove_upload(dir),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn prune_multipart_startup(&self) -> Result<(), FilesystemStoreError> {
        let now = seconds()?;
        for entry in self.multipart.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            let id = name.to_str().ok_or(FilesystemStoreError::InvalidMetadata)?;
            if !entry.file_type()?.is_dir() || !upload_id(id) {
                return Err(FilesystemStoreError::InvalidMetadata);
            }
            self.prune_upload(id, now)?;
        }
        Ok(())
    }
    fn prune_multipart_current(
        &self,
        session: &VerifiedFilesystemSession,
        request: &FilesystemRequest,
    ) -> Result<(), FilesystemStoreError> {
        let now = seconds()?;
        for entry in self.multipart.entries()? {
            request.check(session)?;
            let entry = entry?;
            let name = entry.file_name();
            let id = name.to_str().ok_or(FilesystemStoreError::InvalidMetadata)?;
            if !entry.file_type()?.is_dir() || !upload_id(id) {
                return Err(FilesystemStoreError::InvalidMetadata);
            }
            let _guard = self.lock(&upload_lock(id), session, request)?;
            self.prune_upload(id, now)?;
        }
        Ok(())
    }
    pub fn create_upload(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        content_type: Option<&str>,
        request: &FilesystemRequest,
    ) -> Result<String, FilesystemStoreError> {
        self.authorize(session, request, StorageOperation::Write, key)?;
        let result = (|| {
            if content_type.is_some_and(|s| !header(s)) {
                return Err(FilesystemStoreError::InvalidMetadata);
            }
            let now = seconds()?;
            let state = Manifest {
                bucket: self.config.bucket.clone(),
                key: key.into(),
                content_type: content_type.map_or(Value::Null, |v| Value::String(v.into())),
                created: now,
                last_progress: now,
            };
            self.manifest_bytes(&state)?;
            self.prune_multipart_current(session, request)?;
            let mut random = [0u8; 32];
            getrandom::fill(&mut random).map_err(|_| FilesystemStoreError::Crypto)?;
            let id = URL_SAFE_NO_PAD.encode(random);
            let _guard = self.lock(&upload_lock(&id), session, request)?;
            create_store_dir(&self.multipart, &id)?;
            let dir = self.upload_directory(&id)?;
            let publish = (|| {
                owned_dir(&dir, "parts")?;
                request.check(session)?;
                self.write_upload_manifest(&dir, &state)?;
                sync_dir(&self.multipart).map_err(uncertain)?;
                request.check(session).map_err(uncertain)?;
                Ok(())
            })();
            if let Err(error) = publish {
                if matches!(error, FilesystemStoreError::CommitUncertain(_)) {
                    return Err(error);
                }
                self.remove_upload(dir).map_err(uncertain)?;
                return Err(error);
            }
            Ok(id)
        })();
        match result {
            Ok(id) => {
                request.check(session).map_err(uncertain)?;
                Ok(id)
            }
            Err(e @ FilesystemStoreError::CommitUncertain(_)) => Err(e),
            Err(e) => {
                request.check(session)?;
                Err(e)
            }
        }
    }
    pub fn upload_part<R: Read>(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        id: &str,
        number: i32,
        mut body: R,
        request: &FilesystemRequest,
    ) -> Result<FilesystemPartInfo, FilesystemStoreError> {
        self.authorize(session, request, StorageOperation::Write, key)?;
        let result = (|| {
            if !(1..=MAX_PART).contains(&number) {
                return Err(FilesystemStoreError::InvalidArgument);
            }
            if !upload_id(id) {
                return Err(FilesystemStoreError::NoSuchUpload);
            }
            let (_, initial) = {
                let _guard = self.lock(&upload_lock(id), session, request)?;
                self.current_upload(key, id)?
            };
            let prepared = self.prepare(
                session,
                key,
                &mut body,
                initial.content_type.as_str(),
                None,
                request,
            )?;
            let _guard = self.lock(&upload_lock(id), session, request)?;
            let (upload, mut state) = self.current_upload(key, id)?;
            let parts = upload.open_dir_nofollow("parts")?;
            let part_name = number.to_string();
            match parts.symlink_metadata(&part_name) {
                Ok(m) if !m.is_file() => return Err(FilesystemStoreError::InvalidPart),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            request.check(session)?;
            prepared.stage.rename("payload", &parts, &part_name)?;
            let after = (|| {
                sync_dir(&parts)?;
                state.last_progress = seconds()?.max(state.created);
                self.write_upload_manifest(&upload, &state)?;
                request.check(session)?;
                prepared.stage.close()?;
                Ok(())
            })();
            after.map_err(uncertain)?;
            Ok(FilesystemPartInfo {
                number,
                etag: prepared.info.etag,
                size: prepared.info.size,
                modified: prepared.info.modified,
            })
        })();
        match result {
            Ok(info) => {
                request.check(session).map_err(uncertain)?;
                Ok(info)
            }
            Err(e @ FilesystemStoreError::CommitUncertain(_)) => Err(e),
            Err(e) => {
                request.check(session)?;
                Err(e)
            }
        }
    }
    fn describe_part(
        &self,
        directory: &Dir,
        number: i32,
        session: &VerifiedFilesystemSession,
        request: &FilesystemRequest,
    ) -> Result<FilesystemPartInfo, FilesystemStoreError> {
        let mut file = directory
            .open_with(number.to_string(), &options(true, false))?
            .into_std();
        let stat = file.metadata()?;
        if !stat.is_file() {
            return Err(FilesystemStoreError::InvalidPart);
        }
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
        Ok(FilesystemPartInfo {
            number,
            etag: etag(&digest.finalize()),
            size: stat.len(),
            modified: stat.modified()?,
        })
    }
    pub fn list_parts(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        input: FilesystemPartsRequest<'_>,
        request: &FilesystemRequest,
    ) -> Result<FilesystemPartsPage, FilesystemStoreError> {
        self.authorize(session, request, StorageOperation::Write, key)?;
        let result = (|| {
            if !upload_id(input.upload_id) {
                return Err(FilesystemStoreError::NoSuchUpload);
            }
            let marker = input.marker.unwrap_or(0);
            if !(0..=MAX_PART).contains(&marker) {
                return Err(FilesystemStoreError::InvalidArgument);
            }
            let max = match input.max_parts {
                None | Some(0) => 1000,
                Some(v @ 1..=1000) => v as usize,
                _ => return Err(FilesystemStoreError::InvalidArgument),
            };
            let _guard = self.lock(&upload_lock(input.upload_id), session, request)?;
            let (upload, _) = self.current_upload(key, input.upload_id)?;
            let directory = upload.open_dir_nofollow("parts")?;
            let mut numbers = BTreeSet::new();
            for entry in directory.entries()? {
                request.check(session)?;
                let entry = entry?;
                let name = entry.file_name();
                let raw = name.to_str().ok_or(FilesystemStoreError::InvalidPart)?;
                let number: i32 = raw.parse().map_err(|_| FilesystemStoreError::InvalidPart)?;
                if !(1..=MAX_PART).contains(&number)
                    || number.to_string() != raw
                    || !entry.file_type()?.is_file()
                {
                    return Err(FilesystemStoreError::InvalidPart);
                }
                if number <= marker {
                    continue;
                }
                numbers.insert(number);
                if numbers.len() > max + 1 {
                    numbers.pop_last();
                }
            }
            let is_truncated = numbers.len() > max;
            if is_truncated {
                numbers.pop_last();
            }
            let next_marker = if is_truncated {
                numbers.last().copied()
            } else {
                None
            };
            let mut parts = Vec::new();
            for number in numbers {
                parts.push(self.describe_part(&directory, number, session, request)?);
            }
            Ok(FilesystemPartsPage {
                parts,
                is_truncated,
                next_marker,
            })
        })();
        request.check(session)?;
        result
    }
    pub fn complete_upload(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        input: FilesystemCompleteUpload<'_>,
        request: &FilesystemRequest,
    ) -> Result<FilesystemObjectInfo, FilesystemStoreError> {
        self.authorize(session, request, StorageOperation::Write, key)?;
        let result = (|| {
            if !upload_id(input.upload_id) {
                return Err(FilesystemStoreError::NoSuchUpload);
            }
            if input.parts.is_empty() {
                return Err(FilesystemStoreError::InvalidPart);
            }
            let mut previous = 0;
            for part in input.parts {
                if !(1..=MAX_PART).contains(&part.number) || !valid_etag(&part.etag) {
                    return Err(FilesystemStoreError::InvalidPart);
                }
                if part.number <= previous {
                    return Err(FilesystemStoreError::InvalidPartOrder);
                }
                previous = part.number;
            }
            let upload_key = upload_lock(input.upload_id);
            let (first, second) = if Self::shard(&upload_key) <= Self::shard(key) {
                (upload_key.as_str(), key)
            } else {
                (key, upload_key.as_str())
            };
            let _first = self.lock(first, session, request)?;
            let _second = if Self::shard(first) != Self::shard(second) {
                Some(self.lock(second, session, request)?)
            } else {
                None
            };
            let (upload, state) = self.current_upload(key, input.upload_id)?;
            let mut reader = PartsReader {
                directory: upload.open_dir_nofollow("parts")?,
                parts: input.parts,
                index: 0,
                file: None,
                digest: Sha256::new(),
            };
            let prepared = self
                .prepare(
                    session,
                    key,
                    &mut reader,
                    state.content_type.as_str(),
                    None,
                    request,
                )
                .map_err(|e| match e {
                    FilesystemStoreError::Io(ref io)
                        if io
                            .get_ref()
                            .is_some_and(|cause| cause.is::<InvalidPartBody>()) =>
                    {
                        FilesystemStoreError::InvalidPart
                    }
                    other => other,
                })?;
            drop(reader);
            let info = self.publish_locked(session, key, prepared, input.conditions, request)?;
            self.remove_upload(upload).map_err(uncertain)?;
            request.check(session).map_err(uncertain)?;
            Ok(info)
        })();
        match result {
            Ok(info) => {
                request.check(session).map_err(uncertain)?;
                Ok(info)
            }
            Err(e @ FilesystemStoreError::CommitUncertain(_)) => Err(e),
            Err(e) => {
                request.check(session)?;
                Err(e)
            }
        }
    }
    pub fn abort_upload(
        &self,
        session: &VerifiedFilesystemSession,
        key: &str,
        id: &str,
        request: &FilesystemRequest,
    ) -> Result<(), FilesystemStoreError> {
        self.authorize(session, request, StorageOperation::Write, key)?;
        let result = (|| {
            if !upload_id(id) {
                return Err(FilesystemStoreError::NoSuchUpload);
            }
            let _guard = self.lock(&upload_lock(id), session, request)?;
            let (upload, _) = self.current_upload(key, id)?;
            request.check(session)?;
            self.remove_upload(upload).map_err(uncertain)?;
            request.check(session).map_err(uncertain)
        })();
        match result {
            Ok(()) => request.check(session).map_err(uncertain),
            Err(e @ FilesystemStoreError::CommitUncertain(_)) => Err(e),
            Err(e) => {
                request.check(session)?;
                Err(e)
            }
        }
    }
}
