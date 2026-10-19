use super::SqliteControlStore;
use crate::{
    ControlError, InstanceReadError as Error, StoredInstanceInventory,
    instance_read::decode_inventory, instance_registry::canonical_instance_id,
};
use rusqlite::{OptionalExtension, params};
use std::{fmt, num::NonZeroUsize, time::Instant};

// Keep SQLite types visible to the strict shared decoder. In particular JSON
// cannot represent a BLOB, so wrong scalar types become null, never coerced text.
const SELECT_INVENTORY: &str = r#"
WITH inventory AS MATERIALIZED (
 SELECT json_object(
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
 ) AS payload FROM broker_instances i WHERE i.instance_id=?1
)
SELECT length(CAST(payload AS BLOB)),
 CASE WHEN length(CAST(payload AS BLOB))<=?2 THEN payload END
FROM inventory
"#;

/// Borrowed durable data reader. Authenticate and authorize before disclosure.
pub struct SqliteInstanceInventories<'a> {
    store: &'a SqliteControlStore,
    json_bytes: i64,
}
impl fmt::Debug for SqliteInstanceInventories<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteInstanceInventories([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn instance_inventories(
        &self,
        json_bytes: NonZeroUsize,
    ) -> Result<SqliteInstanceInventories<'_>, Error> {
        isize::try_from(json_bytes.get()).map_err(|_| Error::InvalidLimits)?;
        let json_bytes = i64::try_from(json_bytes.get()).map_err(|_| Error::InvalidLimits)?;
        Ok(SqliteInstanceInventories {
            store: self,
            json_bytes,
        })
    }
}
impl SqliteInstanceInventories<'_> {
    pub async fn read(
        &self,
        instance_id: &str,
        caller: Instant,
    ) -> Result<Option<StoredInstanceInventory>, Error> {
        if !canonical_instance_id(instance_id) {
            return Err(Error::InvalidInstanceId);
        }
        let end = self
            .store
            .executor
            .deadline(caller)
            .map_err(ControlError::from)?;
        let id = instance_id.to_owned();
        let cap = self.json_bytes;
        self.store
            .executor
            .execute(end, move |state, work| {
                Ok((|| -> Result<_, Error> {
                    let tx = state.begin_read(work).map_err(ControlError::from)?;
                    let row = tx
                        .query_row(SELECT_INVENTORY, params![id, cap], |row| {
                            Ok((row.get::<_, i64>(0), row.get::<_, Option<String>>(1)))
                        })
                        .optional()
                        .map_err(|e| ControlError::from(work.sql(e)))?;
                    let snapshot = if let Some((bytes, payload)) = row {
                        let bytes = bytes.map_err(|_| Error::MalformedStored)?;
                        if bytes < 0 {
                            return Err(Error::MalformedStored);
                        }
                        if bytes > cap {
                            return Err(Error::ReadLimitExceeded);
                        }
                        let payload = payload
                            .map_err(|_| Error::MalformedStored)?
                            .ok_or(Error::MalformedStored)?;
                        Some(decode_inventory(&id, &payload)?)
                    } else {
                        None
                    };
                    work.finish_read(tx).map_err(ControlError::from)?;
                    Ok(snapshot)
                })())
            })
            .await
            .map_err(ControlError::from)?
    }
}
