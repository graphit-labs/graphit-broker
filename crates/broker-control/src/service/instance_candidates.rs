use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    InstanceReadError, StoredInstanceInventory, instance_read::decode_inventory,
    instance_registry::canonical_instance_id,
};
use sqlx_core::{connection::Connection, row::Row};
use std::{
    fmt,
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const SELECT_CANDIDATE: &str = r#"WITH candidate AS MATERIALIZED (
 SELECT instance_id,owner_issuer,owner_subject,created_at,updated_at
 FROM public.broker_instances
 WHERE ($1::text IS NULL OR instance_id COLLATE "C">$1 COLLATE "C")
 ORDER BY instance_id COLLATE "C" ASC LIMIT 1
), inventory AS MATERIALIZED (
 SELECT i.instance_id,json_build_object(
   'instance_id',i.instance_id,'owner_issuer',i.owner_issuer,'owner_subject',i.owner_subject,
   'created_at',i.created_at,'updated_at',i.updated_at,
   'versions',COALESCE((SELECT json_agg(json_build_object(
      'project_id',v.project_id,'position',v.position,'version',v.version
    ) ORDER BY v.project_id COLLATE "C",v.position)
    FROM public.broker_instance_project_versions v WHERE v.instance_id=i.instance_id),'[]'::json)
 )::text AS payload FROM candidate i
) SELECT pg_catalog.octet_length(payload)::bigint AS payload_bytes,
 CASE WHEN pg_catalog.octet_length(payload)::bigint<=$2 THEN instance_id END AS instance_id,
 CASE WHEN pg_catalog.octet_length(payload)::bigint<=$2 THEN payload END AS inventory_json FROM inventory"#;

/// One candidate's SQL data, without authentication or authorization.
/// Calls have independent statement snapshots and convey no HTTP cursor.
/// ~~~compile_fail
/// fn escape(store: &broker_control::PostgresControlStore) -> broker_control::PostgresInstanceInventoryCandidates<'static> {
///     store.instance_inventory_candidates(std::num::NonZeroUsize::new(1024).unwrap()).unwrap()
/// }
/// ~~~
pub struct PostgresInstanceInventoryCandidates<'a> {
    owner: &'a PostgresControlStore,
    json_bytes: i64,
}
impl fmt::Debug for PostgresInstanceInventoryCandidates<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresInstanceInventoryCandidates([REDACTED])")
    }
}
impl PostgresControlStore {
    /// Create a borrowed reader with an explicit cap on the complete JSON payload.
    pub fn instance_inventory_candidates(
        &self,
        json_bytes: NonZeroUsize,
    ) -> Result<PostgresInstanceInventoryCandidates<'_>, InstanceReadError> {
        isize::try_from(json_bytes.get()).map_err(|_| InstanceReadError::InvalidLimits)?;
        let json_bytes =
            i64::try_from(json_bytes.get()).map_err(|_| InstanceReadError::InvalidLimits)?;
        Ok(PostgresInstanceInventoryCandidates {
            owner: self,
            json_bytes,
        })
    }
}
impl PostgresInstanceInventoryCandidates<'_> {
    /// Read the least stored ID strictly after the optional canonical ID in byte order.
    /// The ID need not exist. None is observed SQL EOF after confirmed read-only COMMIT.
    pub async fn read_next(
        &self,
        after: Option<&str>,
        caller: Instant,
    ) -> Result<Option<StoredInstanceInventory>, InstanceReadError> {
        if after.is_some_and(|id| !canonical_instance_id(id)) {
            return Err(InstanceReadError::InvalidInstanceId);
        }
        let end = bounded_deadline(caller, self.owner.budgets.operation_timeout)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.owner.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
                .await
                .map_err(storage_error)?;
            let row = sqlx_core::query::query(SELECT_CANDIDATE)
                .bind(after)
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
                let id: &str = row
                    .try_get("instance_id")
                    .map_err(|_| InstanceReadError::MalformedStored)?;
                if !canonical_instance_id(id) || after.is_some_and(|after| id <= after) {
                    return Err(InstanceReadError::MalformedStored);
                }
                let json: &str = row
                    .try_get("inventory_json")
                    .map_err(|_| InstanceReadError::MalformedStored)?;
                Some(decode_inventory(id, json)?)
            } else {
                None
            };
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| InstanceReadError::Control(crate::ControlError::OutcomeUncertain))?;
            guard.confirmed();
            Ok(snapshot)
        })
        .await
        .map_err(|_| InstanceReadError::Control(timeout_error(&commit_started)))?
    }
}
