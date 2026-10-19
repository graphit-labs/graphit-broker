use super::SqliteControlStore;
use crate::{
    ControlError, ResourceGrantReadError, ResourceGrantSnapshot, resource_grants::decode_snapshot,
    sqlite::executor::Work,
};
use rusqlite::{OptionalExtension, Transaction};
use std::{fmt, num::NonZeroUsize, time::Instant};

// Type-invalid dynamic SQLite values become JSON null for the closed shared codec,
// never string casts/default grants. The payload byte ceiling is checked inside SQL.
const SELECT_SNAPSHOT: &str = r#"WITH policy AS MATERIALIZED (
 SELECT s.revision,s.updated_at,(SELECT json_group_array(json_object(
  'id',CASE WHEN typeof(r.id)='text' THEN r.id END,
  'name',CASE WHEN typeof(r.name)='text' THEN r.name END,
  'access_kind',CASE WHEN typeof(r.access_kind)='text' THEN r.access_kind END,
  'principal',CASE WHEN typeof(r.principal)='text' THEN r.principal END,
  's3_route',CASE WHEN typeof(r.s3_route)='text' THEN r.s3_route END,
  'created_at',CASE WHEN typeof(r.created_at)='integer' THEN r.created_at END,
  'updated_at',CASE WHEN typeof(r.updated_at)='integer' THEN r.updated_at END,
  'capabilities',json((SELECT json_group_array(CASE WHEN typeof(c.value)='text' THEN c.value END ORDER BY c.value COLLATE BINARY) FROM grant_capabilities c WHERE c.grant_id=r.id)),
  'projects',json((SELECT json_group_array(CASE WHEN typeof(c.value)='text' THEN c.value END ORDER BY c.value COLLATE BINARY) FROM grant_projects c WHERE c.grant_id=r.id)),
  's3_operations',json((SELECT json_group_array(CASE WHEN typeof(c.value)='text' THEN c.value END ORDER BY c.value COLLATE BINARY) FROM grant_s3_operations c WHERE c.grant_id=r.id)),
  's3_prefixes',json((SELECT json_group_array(CASE WHEN typeof(c.value)='text' THEN c.value END ORDER BY c.value COLLATE BINARY) FROM grant_s3_prefixes c WHERE c.grant_id=r.id))
 ) ORDER BY r.id COLLATE BINARY) FROM resource_grants r) AS payload FROM resource_acl_state s WHERE s.id=1
) SELECT revision,updated_at,length(CAST(payload AS BLOB)) AS payload_bytes,CASE WHEN length(CAST(payload AS BLOB))<=?1 THEN payload END AS rules_json FROM policy"#;

/// Current raw ACL metadata borrowed from one physical store, not a policy lease.
/// A view cannot outlive its store.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore, cap: std::num::NonZeroUsize)
///     -> broker_control::SqliteResourceGrants<'static> { store.resource_grants(cap).unwrap() }
/// ```
pub struct SqliteResourceGrants<'a> {
    owner: &'a SqliteControlStore,
    json_bytes: i64,
}
impl fmt::Debug for SqliteResourceGrants<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteResourceGrants([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn resource_grants(
        &self,
        json_bytes: NonZeroUsize,
    ) -> Result<SqliteResourceGrants<'_>, ResourceGrantReadError> {
        isize::try_from(json_bytes.get()).map_err(|_| ResourceGrantReadError::InvalidLimits)?;
        let json_bytes =
            i64::try_from(json_bytes.get()).map_err(|_| ResourceGrantReadError::InvalidLimits)?;
        Ok(SqliteResourceGrants {
            owner: self,
            json_bytes,
        })
    }
}
impl SqliteResourceGrants<'_> {
    pub async fn read(
        &self,
        caller: Instant,
    ) -> Result<ResourceGrantSnapshot, ResourceGrantReadError> {
        let json_bytes = self.json_bytes;
        self.owner
            .executor
            .execute(caller, move |owner, work| {
                let tx = owner.begin_read(work)?;
                match observe_snapshot(&tx, work, json_bytes) {
                    Ok(snapshot) => {
                        work.finish_read(tx)?;
                        Ok(Ok(snapshot))
                    }
                    Err(error) => {
                        work.check()?;
                        Ok(Err(error))
                    }
                }
            })
            .await
            .map_err(ControlError::from)?
    }
}
pub(super) fn observe_snapshot(
    tx: &Transaction<'_>,
    work: &Work,
    json_bytes: i64,
) -> Result<ResourceGrantSnapshot, ResourceGrantReadError> {
    let mut statement = tx
        .prepare(SELECT_SNAPSHOT)
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let result = statement
        .query_row([json_bytes], |row| {
            let decoded = (|| {
                let bytes: i64 = row
                    .get(2)
                    .map_err(|_| ResourceGrantReadError::MalformedStored)?;
                if bytes < 0 {
                    return Err(ResourceGrantReadError::MalformedStored);
                }
                if bytes > json_bytes {
                    return Err(ResourceGrantReadError::ReadLimitExceeded);
                }
                let revision: i64 = row
                    .get(0)
                    .map_err(|_| ResourceGrantReadError::MalformedStored)?;
                let updated: i64 = row
                    .get(1)
                    .map_err(|_| ResourceGrantReadError::MalformedStored)?;
                let payload = row
                    .get_ref(3)
                    .map_err(|_| ResourceGrantReadError::MalformedStored)?
                    .as_str()
                    .map_err(|_| ResourceGrantReadError::MalformedStored)?;
                decode_snapshot(revision, updated, payload)
            })();
            Ok(decoded)
        })
        .optional()
        .map_err(|e| ControlError::from(work.sql(e)))?;
    work.check().map_err(ControlError::from)?;
    result.ok_or(ResourceGrantReadError::MalformedStored)?
}
