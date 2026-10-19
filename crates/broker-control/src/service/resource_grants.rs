use super::{ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error};
use crate::{ResourceGrantReadError, ResourceGrantSnapshot, resource_grants::decode_snapshot};
use sqlx_core::{connection::Connection, row::Row};
use std::{fmt, num::NonZeroUsize, time::Instant};

const SELECT_SNAPSHOT: &str = r#"WITH policy AS MATERIALIZED (
 SELECT s.revision,s.updated_at,COALESCE((
   SELECT json_agg(json_build_object(
     'id',r.id,'name',r.name,'access_kind',r.access_kind,'principal',r.principal,'s3_route',r.s3_route,
     'created_at',r.created_at,'updated_at',r.updated_at,
     'capabilities',COALESCE((SELECT json_agg(c.value ORDER BY c.value COLLATE "C") FROM public.grant_capabilities c WHERE c.grant_id=r.id),'[]'::json),
     'projects',COALESCE((SELECT json_agg(p.value ORDER BY p.value COLLATE "C") FROM public.grant_projects p WHERE p.grant_id=r.id),'[]'::json),
     's3_operations',COALESCE((SELECT json_agg(o.value ORDER BY o.value COLLATE "C") FROM public.grant_s3_operations o WHERE o.grant_id=r.id),'[]'::json),
     's3_prefixes',COALESCE((SELECT json_agg(f.value ORDER BY f.value COLLATE "C") FROM public.grant_s3_prefixes f WHERE f.grant_id=r.id),'[]'::json)
   ) ORDER BY r.id COLLATE "C")::text FROM public.resource_grants r
 ),'[]') AS payload FROM public.resource_acl_state s WHERE s.id=1
) SELECT revision,updated_at,pg_catalog.octet_length(payload)::bigint AS payload_bytes,
CASE WHEN pg_catalog.octet_length(payload)::bigint<=$1 THEN payload END AS rules_json FROM policy"#;

pub struct PostgresResourceGrants<'a> {
    owner: &'a PostgresControlStore,
    json_bytes: i64,
}
impl fmt::Debug for PostgresResourceGrants<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresResourceGrants([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn resource_grants(
        &self,
        json_bytes: NonZeroUsize,
    ) -> Result<PostgresResourceGrants<'_>, ResourceGrantReadError> {
        isize::try_from(json_bytes.get()).map_err(|_| ResourceGrantReadError::InvalidLimits)?;
        let json_bytes =
            i64::try_from(json_bytes.get()).map_err(|_| ResourceGrantReadError::InvalidLimits)?;
        Ok(PostgresResourceGrants {
            owner: self,
            json_bytes,
        })
    }
}
impl PostgresResourceGrants<'_> {
    pub async fn read(
        &self,
        caller: Instant,
    ) -> Result<ResourceGrantSnapshot, ResourceGrantReadError> {
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
            let snapshot = observe_snapshot(&mut tx, self.json_bytes).await?;
            tx.commit().await.map_err(storage_error)?;
            guard.confirmed();
            Ok(snapshot)
        })
        .await
        .map_err(|_| ResourceGrantReadError::Control(crate::ControlError::Deadline))
        .and_then(|result| result)
    }
}

// DATA observation on the caller's existing connection/transaction. It does not
// authenticate a caller, authorize an action, commit, or grant a permission lease.
pub(super) async fn observe_snapshot(
    connection: &mut sqlx_postgres::PgConnection,
    json_bytes: i64,
) -> Result<ResourceGrantSnapshot, ResourceGrantReadError> {
    let row = sqlx_core::query::query(SELECT_SNAPSHOT)
        .bind(json_bytes)
        .fetch_optional(connection)
        .await
        .map_err(storage_error)?
        .ok_or(ResourceGrantReadError::MalformedStored)?;
    let get_error = |_| ResourceGrantReadError::MalformedStored;
    let bytes: i64 = row.try_get("payload_bytes").map_err(get_error)?;
    if bytes < 0 {
        return Err(ResourceGrantReadError::MalformedStored);
    }
    if bytes > json_bytes {
        return Err(ResourceGrantReadError::ReadLimitExceeded);
    }
    let revision: i64 = row.try_get("revision").map_err(get_error)?;
    let updated: i64 = row.try_get("updated_at").map_err(get_error)?;
    let json: &str = row.try_get("rules_json").map_err(get_error)?;
    decode_snapshot(revision, updated, json)
}
