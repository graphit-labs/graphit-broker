use super::{ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error};
use crate::{
    InstanceReadError, StoredInstanceInventory, instance_read::decode_inventory,
    instance_registry::canonical_instance_id,
};
use sqlx_core::{connection::Connection, row::Row};
use std::{fmt, num::NonZeroUsize, time::Instant};

const SELECT_INVENTORY: &str = r#"WITH inventory AS MATERIALIZED (
 SELECT json_build_object(
   'instance_id',i.instance_id,'owner_issuer',i.owner_issuer,'owner_subject',i.owner_subject,
   'created_at',i.created_at,'updated_at',i.updated_at,
   'versions',COALESCE((SELECT json_agg(json_build_object(
      'project_id',v.project_id,'position',v.position,'version',v.version
    ) ORDER BY v.project_id COLLATE "C",v.position)
    FROM public.broker_instance_project_versions v WHERE v.instance_id=i.instance_id),'[]'::json)
 )::text AS payload FROM public.broker_instances i WHERE i.instance_id=$1
) SELECT pg_catalog.octet_length(payload)::bigint AS payload_bytes,
 CASE WHEN pg_catalog.octet_length(payload)::bigint<=$2 THEN payload END AS inventory_json FROM inventory"#;

/// Borrowed SQL data reader. Calling this API grants no permission.
/// ~~~compile_fail
/// fn escape(store: &broker_control::PostgresControlStore) -> broker_control::PostgresInstanceInventories<'static> {
///     store.instance_inventories(std::num::NonZeroUsize::new(1024).unwrap()).unwrap()
/// }
/// ~~~
pub struct PostgresInstanceInventories<'a> {
    owner: &'a PostgresControlStore,
    json_bytes: i64,
}
impl fmt::Debug for PostgresInstanceInventories<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresInstanceInventories([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn instance_inventories(
        &self,
        json_bytes: NonZeroUsize,
    ) -> Result<PostgresInstanceInventories<'_>, InstanceReadError> {
        isize::try_from(json_bytes.get()).map_err(|_| InstanceReadError::InvalidLimits)?;
        let json_bytes =
            i64::try_from(json_bytes.get()).map_err(|_| InstanceReadError::InvalidLimits)?;
        Ok(PostgresInstanceInventories {
            owner: self,
            json_bytes,
        })
    }
}
impl PostgresInstanceInventories<'_> {
    pub async fn read(
        &self,
        instance_id: &str,
        caller: Instant,
    ) -> Result<Option<StoredInstanceInventory>, InstanceReadError> {
        if !canonical_instance_id(instance_id) {
            return Err(InstanceReadError::InvalidInstanceId);
        }
        let end = bounded_deadline(caller, self.owner.budgets.operation_timeout)?;
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.owner.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
                .await
                .map_err(storage_error)?;
            let row = sqlx_core::query::query(SELECT_INVENTORY)
                .bind(instance_id)
                .bind(self.json_bytes)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?;
            let snapshot = if let Some(row) = row {
                let bytes: i64 = row
                    .try_get("payload_bytes")
                    .map_err(|_| InstanceReadError::MalformedStored)?;
                if bytes < 0 {
                    return Err(InstanceReadError::MalformedStored);
                }
                if bytes > self.json_bytes {
                    return Err(InstanceReadError::ReadLimitExceeded);
                }
                let json: &str = row
                    .try_get("inventory_json")
                    .map_err(|_| InstanceReadError::MalformedStored)?;
                Some(decode_inventory(instance_id, json)?)
            } else {
                None
            };
            tx.commit().await.map_err(storage_error)?;
            guard.confirmed();
            Ok(snapshot)
        })
        .await
        .map_err(|_| InstanceReadError::Control(crate::ControlError::Deadline))?
    }
}
