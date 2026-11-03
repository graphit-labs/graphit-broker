use super::SqliteControlStore;
use crate::{
    ControlError, InstanceReadError as Error, StoredInstanceInventory,
    instance_read::decode_inventory, instance_registry::canonical_instance_id,
};
use rusqlite::{OptionalExtension, params};
use std::{fmt, num::NonZeroUsize, time::Instant};
const SELECT_CANDIDATE: &str = r#"
WITH candidate AS MATERIALIZED (
 SELECT instance_id,owner_issuer,owner_subject,created_at,updated_at FROM broker_instances
 WHERE (?1 IS NULL OR instance_id COLLATE BINARY > ?1 COLLATE BINARY)
 ORDER BY instance_id COLLATE BINARY LIMIT 1
), inventory AS MATERIALIZED (
 SELECT i.instance_id,json_object(
  'instance_id',CASE WHEN typeof(i.instance_id)='text' THEN i.instance_id END,
  'owner_issuer',CASE WHEN typeof(i.owner_issuer)='text' THEN i.owner_issuer END,
  'owner_subject',CASE WHEN typeof(i.owner_subject)='text' THEN i.owner_subject END,
  'created_at',CASE WHEN typeof(i.created_at)='integer' THEN i.created_at END,
  'updated_at',CASE WHEN typeof(i.updated_at)='integer' THEN i.updated_at END,
  'versions',json(COALESCE((
    SELECT json_group_array(json_object(
      'project_id',CASE WHEN typeof(v.project_id)='text' THEN v.project_id END,
      'position',CASE WHEN typeof(v.position)='integer' THEN v.position END,
      'version',CASE WHEN typeof(v.version)='text' THEN v.version END
    ) ORDER BY v.project_id COLLATE BINARY,v.position)
    FROM broker_instance_project_versions v WHERE v.instance_id=i.instance_id
  ),'[]'))
 ) AS payload FROM candidate i
)
SELECT length(CAST(payload AS BLOB)),
 CASE WHEN length(CAST(payload AS BLOB))<=?2 THEN payload END,
 CASE WHEN length(CAST(payload AS BLOB))<=?2 THEN instance_id END
FROM inventory
"#;
/// One bounded durable candidate; no identity, authorization or HTTP cursor.
pub struct SqliteInstanceInventoryCandidates<'a> {
    owner: &'a SqliteControlStore,
    json_bytes: i64,
}
impl fmt::Debug for SqliteInstanceInventoryCandidates<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteInstanceInventoryCandidates([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn instance_inventory_candidates(
        &self,
        json_bytes: NonZeroUsize,
    ) -> Result<SqliteInstanceInventoryCandidates<'_>, Error> {
        isize::try_from(json_bytes.get()).map_err(|_| Error::InvalidLimits)?;
        let json_bytes = i64::try_from(json_bytes.get()).map_err(|_| Error::InvalidLimits)?;
        Ok(SqliteInstanceInventoryCandidates {
            owner: self,
            json_bytes,
        })
    }
}
impl SqliteInstanceInventoryCandidates<'_> {
    /// Least binary ID strictly after the optional canonical key, whether present or not.
    /// EOF is emitted only after the executor closes the read snapshot.
    pub async fn read_next(
        &self,
        after: Option<&str>,
        original: Instant,
    ) -> Result<Option<StoredInstanceInventory>, Error> {
        if after.is_some_and(|id| !canonical_instance_id(id)) {
            return Err(Error::InvalidInstanceId);
        }
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let after = after.map(str::to_owned);
        let cap = self.json_bytes;
        self.owner
            .executor
            .execute(end, move |owner, work| {
                Ok((|| -> Result<_, Error> {
                    let tx = owner.begin_read(work).map_err(ControlError::from)?;
                    let row = tx
                        .query_row(SELECT_CANDIDATE, params![after, cap], |row| {
                            Ok((
                                row.get::<_, i64>(0),
                                row.get::<_, Option<String>>(1),
                                row.get::<_, Option<String>>(2),
                            ))
                        })
                        .optional()
                        .map_err(|e| ControlError::from(work.sql(e)))?;
                    let result = if let Some((bytes, payload, id)) = row {
                        let bytes = bytes.map_err(|_| Error::MalformedStored)?;
                        if bytes < 0 {
                            return Err(Error::MalformedStored);
                        }
                        if bytes > cap {
                            return Err(Error::ReadLimitExceeded);
                        }
                        let id = id
                            .map_err(|_| Error::MalformedStored)?
                            .ok_or(Error::MalformedStored)?;
                        if !canonical_instance_id(&id)
                            || after.as_deref().is_some_and(|after| id.as_str() <= after)
                        {
                            return Err(Error::MalformedStored);
                        }
                        let payload = payload
                            .map_err(|_| Error::MalformedStored)?
                            .ok_or(Error::MalformedStored)?;
                        Some(decode_inventory(&id, &payload)?)
                    } else {
                        None
                    };
                    work.finish_read(tx).map_err(ControlError::from)?;
                    Ok(result)
                })())
            })
            .await
            .map_err(ControlError::from)?
    }
}
