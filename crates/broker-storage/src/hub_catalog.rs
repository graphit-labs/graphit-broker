//! Metadata-only discovery. No caller-selected storage route or issued S3 grant.
use crate::{FilesystemStore, FilesystemStoreError, StorageCredentialsService, service::Issuer};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{HubAccessResolution, StorageAdmissionError};
use cap_fs_ext::DirExt;
use futures_util::StreamExt;
use object_store::{
    ObjectStoreExt,
    list::{PaginatedListOptions, PaginatedListStore},
    path::Path,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Read},
    num::NonZeroUsize,
    sync::Arc,
    time::Instant,
};

#[derive(Debug)]
pub enum HubCatalogError {
    InvalidQuery,
    InvalidCursor,
    RestartRequired,
    InvalidMetadata,
    Authorization,
    Access(broker_control::HubAccessError),
    ConflictingRoutes,
    Storage,
    Deadline,
}
impl fmt::Display for HubCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hub catalog unavailable: {self:?}")
    }
}
impl std::error::Error for HubCatalogError {}
pub struct HubCatalogQuery {
    pub id: Option<String>,
    pub name_prefix: Option<String>,
    pub limit: usize,
    pub cursor: Option<String>,
}
#[derive(Serialize)]
pub struct HubCatalogProject {
    pub id: String,
    pub name: String,
}
#[derive(Serialize)]
pub struct HubCatalogPage {
    pub v: u8,
    pub subject: String,
    pub authorization_revision: String,
    pub projects: Vec<HubCatalogProject>,
    pub next_cursor: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    v: u8,
    project: Project,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    id: String,
    name: String,
    status: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    binding: String,
    route: usize,
    after: String,
}
fn project_id(id: &str) -> bool {
    id.len() == 26
        && id != "00000000000000000000000000"
        && id.as_bytes()[0] <= b'7'
        && id
            .bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}
fn key(prefix: &str, id: &str) -> String {
    format!("{prefix}/v1/projects/{id}/hub/metadata/project.json")
}
fn checked(resolved: &mut HubAccessResolution<'_>, end: Instant) -> Result<(), HubCatalogError> {
    if Instant::now() >= end {
        return Err(HubCatalogError::Deadline);
    }
    resolved.check().map_err(HubCatalogError::Access)
}
fn route_error(e: StorageAdmissionError) -> HubCatalogError {
    if e == StorageAdmissionError::ConflictingRoutes {
        HubCatalogError::ConflictingRoutes
    } else {
        HubCatalogError::Authorization
    }
}
/// Retains configured services/stores; never exposes a generic object-store handle.
pub struct HubCatalogReader {
    service: Arc<StorageCredentialsService>,
    stores: BTreeMap<String, Arc<FilesystemStore>>,
    metadata_bytes: NonZeroUsize,
}
impl HubCatalogReader {
    pub fn new(
        service: Arc<StorageCredentialsService>,
        stores: Vec<Arc<FilesystemStore>>,
        metadata_bytes: NonZeroUsize,
    ) -> Self {
        Self {
            service,
            stores: stores
                .into_iter()
                .map(|s| (s.config.bucket.clone(), s))
                .collect(),
            metadata_bytes,
        }
    }
    pub async fn page(
        &self,
        resolved: &mut HubAccessResolution<'_>,
        default: &str,
        q: HubCatalogQuery,
        end: Instant,
    ) -> Result<HubCatalogPage, HubCatalogError> {
        checked(resolved, end)?;
        if !(1..=1000).contains(&q.limit)
            || q.id.as_deref().is_some_and(|id| !project_id(id))
            || q.id.is_some() && q.name_prefix.is_some()
            || q.name_prefix
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > 1024 || p.chars().any(char::is_control))
        {
            return Err(HubCatalogError::InvalidQuery);
        }
        let routes = resolved.catalog_routes(default);
        let binding = Sha256::digest(
            serde_json::to_vec(&(
                q.id.as_deref(),
                q.name_prefix.as_deref(),
                q.limit,
                resolved.subject(),
                resolved.authorization_revision(),
                &routes,
            ))
            .map_err(|_| HubCatalogError::InvalidQuery)?,
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
        let cursor = if let Some(raw) = &q.cursor {
            if raw.len() > 1024 {
                return Err(HubCatalogError::InvalidCursor);
            }
            let c: Cursor = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(raw)
                    .map_err(|_| HubCatalogError::InvalidCursor)?,
            )
            .map_err(|_| HubCatalogError::InvalidCursor)?;
            if c.binding != binding {
                return Err(HubCatalogError::RestartRequired);
            }
            if c.route >= routes.len() || !project_id(&c.after) {
                return Err(HubCatalogError::InvalidCursor);
            }
            // A forged cursor cannot introduce authority or a backend path.
            if resolved
                .catalog_route(&c.after, default)
                .map_err(route_error)?
                != Some(routes[c.route].as_str())
            {
                return Err(HubCatalogError::InvalidCursor);
            }
            Some(c)
        } else {
            None
        };
        let mut projects = Vec::new();
        let mut last = None;
        for (index, route) in routes
            .iter()
            .enumerate()
            .skip(cursor.as_ref().map_or(0, |c| c.route))
        {
            let mut after = cursor
                .as_ref()
                .filter(|c| c.route == index)
                .map_or(String::new(), |c| c.after.clone());
            let all = resolved.catalog_route_all(route, default) && q.id.is_none();
            loop {
                checked(resolved, end)?;
                let (ids, more) = if all {
                    self.candidates(route, &after, q.limit.min(999) + 1, end)
                        .await?
                } else {
                    let mut ids = BTreeSet::new();
                    if let Some(id) = q.id.as_ref() {
                        ids.insert(id.clone());
                    } else {
                        for s in resolved.selectors() {
                            if let Some(id) = s.id() {
                                ids.insert(id.into());
                            }
                        }
                    }
                    let mut remaining = ids.into_iter().filter(|id| id > &after);
                    let ids = remaining
                        .by_ref()
                        .take(q.limit.min(999) + 1)
                        .collect::<Vec<_>>();
                    let more = remaining.next().is_some();
                    (ids, more)
                };
                if ids.is_empty() {
                    break;
                }
                for id in &ids {
                    checked(resolved, end)?;
                    after = id.clone();
                    if resolved.catalog_route(id, default).map_err(route_error)?
                        != Some(route.as_str())
                    {
                        continue;
                    }
                    let Some(project) = self.project(route, id, end).await? else {
                        continue;
                    };
                    checked(resolved, end)?;
                    if q.name_prefix
                        .as_ref()
                        .is_some_and(|prefix| !project.name.starts_with(prefix))
                    {
                        continue;
                    }
                    if projects.len() == q.limit {
                        let cursor = last.map(|(route, after)| Cursor {
                            binding: binding.clone(),
                            route,
                            after,
                        });
                        return Ok(HubCatalogPage {
                            v: 1,
                            subject: resolved.subject().into(),
                            authorization_revision: resolved.authorization_revision().into(),
                            projects,
                            next_cursor: cursor.map(|c| {
                                URL_SAFE_NO_PAD.encode(
                                    serde_json::to_vec(&c).expect("cursor fields serialize"),
                                )
                            }),
                        });
                    }
                    last = Some((index, id.clone()));
                    projects.push(project);
                }
                if !more {
                    break;
                }
            }
        }
        checked(resolved, end)?;
        Ok(HubCatalogPage {
            v: 1,
            subject: resolved.subject().into(),
            authorization_revision: resolved.authorization_revision().into(),
            projects,
            next_cursor: None,
        })
    }
    async fn candidates(
        &self,
        route: &str,
        after: &str,
        limit: usize,
        end: Instant,
    ) -> Result<(Vec<String>, bool), HubCatalogError> {
        let issuer = self
            .service
            .routes
            .get(route)
            .and_then(|i| self.service.issuers.get(*i))
            .ok_or(HubCatalogError::Storage)?;
        match issuer {
            Issuer::Aws(issuer) => {
                let (store, base) = issuer
                    .catalog(route)
                    .await
                    .map_err(|_| HubCatalogError::Storage)?;
                let prefix = format!("{base}/v1/projects/");
                let result = store
                    .list_paginated(
                        Some(&prefix),
                        PaginatedListOptions {
                            delimiter: Some("/".into()),
                            offset: (!after.is_empty()).then(|| format!("{prefix}{after}/")),
                            max_keys: Some(limit.min(1000)),
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|_| HubCatalogError::Storage)?;
                if !result.result.objects.is_empty() {
                    return Err(HubCatalogError::InvalidMetadata);
                }
                let more = result.page_token.is_some();
                let mut ids = Vec::new();
                for common in result.result.common_prefixes {
                    let id = common
                        .as_ref()
                        .strip_prefix(&prefix)
                        .map(|s| s.trim_end_matches('/'))
                        .unwrap_or("");
                    if !project_id(id) || id <= after {
                        return Err(HubCatalogError::InvalidMetadata);
                    }
                    ids.push(id.into());
                }
                ids.sort();
                ids.dedup();
                if ids.is_empty() && more {
                    return Err(HubCatalogError::Storage);
                }
                Ok((ids, more))
            }
            Issuer::Filesystem(issuer) => {
                let config = issuer
                    .gateway_routes()
                    .find(|r| r.name == route)
                    .ok_or(HubCatalogError::Storage)?;
                let store = self
                    .stores
                    .get(&config.bucket)
                    .ok_or(HubCatalogError::Storage)?;
                let prefix = format!("{}/v1/projects", config.base_prefix);
                let (parent, name) = match FilesystemStore::parent(&store.data, &prefix, false) {
                    Ok(v) => v,
                    Err(FilesystemStoreError::NotFound) => return Ok((Vec::new(), false)),
                    Err(_) => return Err(HubCatalogError::Storage),
                };
                let dir = match parent.open_dir_nofollow(&name) {
                    Ok(d) => d,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        return Ok((Vec::new(), false));
                    }
                    Err(_) => return Err(HubCatalogError::Storage),
                };
                let mut ids = BTreeSet::new();
                for entry in dir.entries().map_err(|_| HubCatalogError::Storage)? {
                    if Instant::now() >= end {
                        return Err(HubCatalogError::Deadline);
                    }
                    let entry = entry.map_err(|_| HubCatalogError::Storage)?;
                    let name = entry.file_name();
                    let id = name.to_str().ok_or(HubCatalogError::InvalidMetadata)?;
                    if !project_id(id)
                        || !entry
                            .file_type()
                            .map_err(|_| HubCatalogError::Storage)?
                            .is_dir()
                    {
                        return Err(HubCatalogError::InvalidMetadata);
                    }
                    if id > after {
                        ids.insert(id.to_owned());
                        if ids.len() > limit {
                            ids.pop_last();
                        }
                    }
                }
                let more = ids.len() == limit;
                Ok((ids.into_iter().collect(), more))
            }
        }
    }
    async fn project(
        &self,
        route: &str,
        id: &str,
        end: Instant,
    ) -> Result<Option<HubCatalogProject>, HubCatalogError> {
        let issuer = self
            .service
            .routes
            .get(route)
            .and_then(|i| self.service.issuers.get(*i))
            .ok_or(HubCatalogError::Storage)?;
        let bytes = match issuer {
            Issuer::Aws(issuer) => {
                let (store, base) = issuer
                    .catalog(route)
                    .await
                    .map_err(|_| HubCatalogError::Storage)?;
                let got = match store.get(&Path::from(key(base, id))).await {
                    Ok(v) => v,
                    Err(object_store::Error::NotFound { .. }) => return Ok(None),
                    Err(_) => return Err(HubCatalogError::Storage),
                };
                if got.meta.size > self.metadata_bytes.get() as u64 {
                    return Err(HubCatalogError::InvalidMetadata);
                }
                let mut bytes = Vec::new();
                let mut stream = got.into_stream();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|_| HubCatalogError::Storage)?;
                    if chunk.len() > self.metadata_bytes.get() - bytes.len() {
                        return Err(HubCatalogError::InvalidMetadata);
                    }
                    bytes.extend_from_slice(&chunk);
                }
                bytes
            }
            Issuer::Filesystem(issuer) => {
                let config = issuer
                    .gateway_routes()
                    .find(|r| r.name == route)
                    .ok_or(HubCatalogError::Storage)?;
                let store = self
                    .stores
                    .get(&config.bucket)
                    .ok_or(HubCatalogError::Storage)?;
                let key = key(&config.base_prefix, id);
                // Share the writer's existing shard so data/meta publication is
                // observed only after its critical section, without forging S3 authority.
                let _guard = store.shards[FilesystemStore::shard(&key)]
                    .try_lock_until(end)
                    .ok_or(HubCatalogError::Deadline)?;
                if Instant::now() >= end {
                    return Err(HubCatalogError::Deadline);
                }
                let file = match store.data_file(&key) {
                    Ok(f) => f,
                    Err(FilesystemStoreError::NotFound) => return Ok(None),
                    Err(_) => return Err(HubCatalogError::Storage),
                };
                let mut bytes = Vec::new();
                file.take(
                    (self.metadata_bytes.get() as u64)
                        .checked_add(1)
                        .ok_or(HubCatalogError::InvalidMetadata)?,
                )
                .read_to_end(&mut bytes)
                .map_err(|_| HubCatalogError::Storage)?;
                bytes
            }
        };
        if bytes.len() > self.metadata_bytes.get() {
            return Err(HubCatalogError::InvalidMetadata);
        }
        let doc: Document =
            serde_json::from_slice(&bytes).map_err(|_| HubCatalogError::InvalidMetadata)?;
        if doc.v != 1
            || doc.project.id != id
            || doc.project.status != "active"
            || doc.project.name.is_empty()
            || doc.project.name.trim() != doc.project.name
            || doc.project.name.chars().any(char::is_control)
        {
            return Err(HubCatalogError::InvalidMetadata);
        }
        Ok(Some(HubCatalogProject {
            id: doc.project.id,
            name: doc.project.name,
        }))
    }
}
