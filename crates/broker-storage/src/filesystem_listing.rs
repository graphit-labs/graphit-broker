use crate::{
    FilesystemConditions, FilesystemObjectInfo, FilesystemRequest, FilesystemStore,
    FilesystemStoreError, VerifiedFilesystemSession, filesystem_session::key as valid_key,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::StorageOperation;
use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilesystemListEncoding {
    Plain,
    Url,
}
pub struct FilesystemListRequest<'a> {
    pub prefix: &'a str,
    pub delimiter: Option<&'a str>,
    pub start_after: Option<&'a str>,
    pub continuation_token: Option<&'a str>,
    pub max_keys: Option<i32>,
    pub encoding: FilesystemListEncoding,
}
pub struct FilesystemListedObject {
    pub key: String,
    pub info: FilesystemObjectInfo,
}
pub struct FilesystemListPage {
    pub objects: Vec<FilesystemListedObject>,
    pub common_prefixes: Vec<String>,
    pub key_count: u32,
    pub is_truncated: bool,
    pub next_token: Option<String>,
}
pub struct FilesystemCopyOptions<'a> {
    pub source_conditions: &'a FilesystemConditions,
    pub target_conditions: &'a FilesystemConditions,
}
pub struct FilesystemDeleteResult {
    pub key: String,
    pub result: Result<(), FilesystemStoreError>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    prefix: String,
    delimiter: Option<String>,
    marker: String,
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Candidate {
    key: String,
    common: bool,
}
fn interrupted_batch(
    results: Vec<FilesystemDeleteResult>,
    cause: FilesystemStoreError,
    processed: bool,
) -> FilesystemStoreError {
    for entry in results {
        if let Err(error @ FilesystemStoreError::CommitUncertain(_)) = entry.result {
            return error;
        }
    }
    if processed {
        FilesystemStoreError::CommitUncertain(Box::new(cause))
    } else {
        cause
    }
}
fn prefix_key(prefix: &str) -> &str {
    prefix.strip_suffix('/').unwrap_or(prefix)
}
fn encoded(value: &str, encoding: FilesystemListEncoding) -> String {
    match encoding {
        FilesystemListEncoding::Plain => value.to_owned(),
        FilesystemListEncoding::Url => url::form_urlencoded::byte_serialize(value.as_bytes())
            .collect::<String>()
            .replace('+', "%20")
            .replace("%2F", "/"),
    }
}
struct Selection<'a> {
    prefix: &'a str,
    delimiter: bool,
    marker: &'a str,
    limit: usize,
    candidates: BTreeSet<Candidate>,
    session: &'a VerifiedFilesystemSession,
    request: &'a FilesystemRequest,
}
impl Selection<'_> {
    fn walk(&mut self, dir: &Dir, parent: &str) -> Result<(), FilesystemStoreError> {
        for entry in dir.entries()? {
            self.request.check(self.session)?;
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(FilesystemStoreError::InvalidKey)?;
            let key = if parent.is_empty() {
                name.to_owned()
            } else {
                format!("{parent}/{name}")
            };
            if !self.prefix.starts_with(&format!("{key}/")) && !key.starts_with(self.prefix) {
                continue;
            }
            if !self.prefix.starts_with(&format!("{key}/"))
                && !self.session.allows(StorageOperation::Read, parent)
                && !self.session.allows(StorageOperation::Read, &key)
            {
                continue;
            }
            if !valid_key(&key) {
                return Err(FilesystemStoreError::InvalidKey);
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                self.walk(&dir.open_dir_nofollow(name)?, &key)?;
            } else if kind.is_file() {
                if !key.starts_with(self.prefix) {
                    continue;
                }
                if !valid_key(&key) || !self.session.allows(StorageOperation::Read, &key) {
                    return Err(FilesystemStoreError::Forbidden);
                }
                let candidate = if self.delimiter {
                    match key[self.prefix.len()..].find('/') {
                        Some(position) => Candidate {
                            key: key[..self.prefix.len() + position + 1].into(),
                            common: true,
                        },
                        None => Candidate { key, common: false },
                    }
                } else {
                    Candidate { key, common: false }
                };
                if candidate.key.as_str() <= self.marker {
                    continue;
                }
                self.candidates.insert(candidate);
                if self.candidates.len() > self.limit {
                    self.candidates.pop_last();
                }
            } else {
                return Err(FilesystemStoreError::InvalidKey);
            }
        }
        Ok(())
    }
}
impl FilesystemStore {
    pub fn list(
        &self,
        session: &VerifiedFilesystemSession,
        input: FilesystemListRequest<'_>,
        request: &FilesystemRequest,
    ) -> Result<FilesystemListPage, FilesystemStoreError> {
        self.authorize(
            session,
            request,
            StorageOperation::Read,
            prefix_key(input.prefix),
        )?;
        let result = (|| {
            if input.prefix.len() > 1024 || input.delimiter.is_some_and(|d| d != "/") {
                return Err(FilesystemStoreError::InvalidArgument);
            }
            let maximum = match input.max_keys {
                None | Some(0) => 1000,
                Some(value @ 1..=1000) => value as usize,
                _ => return Err(FilesystemStoreError::InvalidArgument),
            };
            let cursor = if let Some(token) = input.continuation_token {
                // The largest legal cursor has two canonical 1024-byte ASCII keys.
                let maximum_cursor = serde_json::to_vec(&Cursor {
                    prefix: "a".repeat(1024),
                    delimiter: Some("/".into()),
                    marker: "a".repeat(1024),
                })
                .map_err(|_| FilesystemStoreError::InvalidArgument)?
                .len()
                .div_ceil(3)
                    * 4;
                if token.len() > maximum_cursor {
                    return Err(FilesystemStoreError::InvalidArgument);
                }
                let bytes = URL_SAFE_NO_PAD
                    .decode(token)
                    .map_err(|_| FilesystemStoreError::InvalidArgument)?;
                let cursor: Cursor = serde_json::from_slice(&bytes)
                    .map_err(|_| FilesystemStoreError::InvalidArgument)?;
                if cursor.prefix != input.prefix
                    || cursor.delimiter.as_deref() != input.delimiter
                    || cursor.marker.len() > 1024
                    || !valid_key(prefix_key(&cursor.marker))
                    || !cursor.marker.starts_with(input.prefix)
                    || !session.allows(StorageOperation::Read, prefix_key(&cursor.marker))
                {
                    return Err(FilesystemStoreError::InvalidArgument);
                }
                Some(cursor)
            } else {
                None
            };
            let marker = cursor
                .as_ref()
                .map(|c| c.marker.as_str())
                .or(input.start_after)
                .unwrap_or("");
            if !marker.is_empty() && (marker.len() > 1024 || !valid_key(prefix_key(marker))) {
                return Err(FilesystemStoreError::InvalidArgument);
            }
            let mut selection = Selection {
                prefix: input.prefix,
                delimiter: input.delimiter.is_some(),
                marker,
                limit: maximum + 1,
                candidates: BTreeSet::new(),
                session,
                request,
            };
            selection.walk(&self.data, "")?;
            let truncated = selection.candidates.len() > maximum;
            if truncated {
                selection.candidates.pop_last();
            }
            let next_token = if truncated {
                let last = selection
                    .candidates
                    .last()
                    .ok_or(FilesystemStoreError::InvalidArgument)?;
                Some(
                    URL_SAFE_NO_PAD.encode(
                        serde_json::to_vec(&Cursor {
                            prefix: input.prefix.into(),
                            delimiter: input.delimiter.map(str::to_owned),
                            marker: last.key.clone(),
                        })
                        .map_err(|_| FilesystemStoreError::InvalidArgument)?,
                    ),
                )
            } else {
                None
            };
            let count = selection.candidates.len() as u32;
            let mut objects = Vec::new();
            let mut common_prefixes = Vec::new();
            for candidate in selection.candidates {
                if candidate.common {
                    common_prefixes.push(encoded(&candidate.key, input.encoding));
                } else {
                    objects.push(FilesystemListedObject {
                        info: self.head(session, &candidate.key, request)?,
                        key: encoded(&candidate.key, input.encoding),
                    });
                }
            }
            Ok(FilesystemListPage {
                objects,
                common_prefixes,
                key_count: count,
                is_truncated: truncated,
                next_token,
            })
        })();
        request.check(session)?;
        result
    }
    pub fn copy(
        &self,
        session: &VerifiedFilesystemSession,
        source: &str,
        target: &str,
        options: FilesystemCopyOptions<'_>,
        request: &FilesystemRequest,
    ) -> Result<FilesystemObjectInfo, FilesystemStoreError> {
        self.authorize(session, request, StorageOperation::Read, source)?;
        self.authorize(session, request, StorageOperation::Write, target)?;
        let result = (|| {
            let (first, second) = if Self::shard(source) <= Self::shard(target) {
                (source, target)
            } else {
                (target, source)
            };
            let _first = self.lock(first, session, request)?;
            let _second = if Self::shard(first) != Self::shard(second) {
                Some(self.lock(second, session, request)?)
            } else {
                None
            };
            let mut file = self.data_file(source)?;
            let info = self.describe(source, &mut file, session, request)?;
            options.source_conditions.check(Some(&info.etag))?;
            let prepared = self.prepare(
                session,
                target,
                &mut file,
                Some(&info.content_type),
                None,
                request,
            )?;
            self.publish_locked(
                session,
                target,
                prepared,
                options.target_conditions,
                request,
            )
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
    pub fn delete_batch(
        &self,
        session: &VerifiedFilesystemSession,
        keys: &[String],
        quiet: bool,
        request: &FilesystemRequest,
    ) -> Result<Vec<FilesystemDeleteResult>, FilesystemStoreError> {
        request.check(session)?;
        if session.bucket() != self.config.bucket {
            return Err(FilesystemStoreError::Forbidden);
        }
        let mut results = Vec::new();
        let mut processed = false;
        for key in keys {
            if let Err(cause) = request.check(session) {
                return Err(interrupted_batch(results, cause, processed));
            }
            let result = self.delete(session, key, request);
            processed |=
                result.is_ok() || matches!(result, Err(FilesystemStoreError::CommitUncertain(_)));
            if !quiet || result.is_err() {
                results.push(FilesystemDeleteResult {
                    key: key.clone(),
                    result,
                });
            }
        }
        if let Err(cause) = request.check(session) {
            return Err(interrupted_batch(results, cause, processed));
        }
        Ok(results)
    }
}
