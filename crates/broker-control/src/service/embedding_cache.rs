use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    ControlError,
    embedding_cache::{
        EmbeddingCacheEntry, EmbeddingCacheError, EmbeddingCacheKey, EmbeddingCacheLimits,
        EmbeddingCacheProvenance, EmbeddingCacheWrite, check_count, decode_vector, prepare_insert,
    },
};
use sqlx_core::{connection::Connection, row::Row};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

/// Borrowed batch data access; the request owner retains current authority.
pub struct PostgresEmbeddingCache<'a> {
    owner: &'a PostgresControlStore,
    limits: EmbeddingCacheLimits,
}
impl PostgresControlStore {
    pub fn embedding_cache(
        &self,
        limits: EmbeddingCacheLimits,
    ) -> Result<PostgresEmbeddingCache<'_>, EmbeddingCacheError> {
        Ok(PostgresEmbeddingCache {
            owner: self,
            limits: limits.validate()?,
        })
    }
}
fn check(end: Instant) -> Result<(), ControlError> {
    if Instant::now() >= end {
        Err(ControlError::Deadline)
    } else {
        Ok(())
    }
}
impl PostgresEmbeddingCache<'_> {
    pub async fn read(
        &self,
        keys: &[EmbeddingCacheKey],
        original: Instant,
    ) -> Result<Vec<Option<Vec<f32>>>, EmbeddingCacheError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        check_count(keys.len(), self.limits)?;
        let (compatibility, input): (Vec<_>, Vec<_>) =
            keys.iter().copied().map(EmbeddingCacheKey::sql).unzip();
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.owner.pool.acquire().await.map_err(storage_error)?));
            let mut tx = guard.connection()?.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY").await.map_err(storage_error)?;
            let rows = sqlx_core::query::query("SELECT c.compatibility_hash IS NOT NULL AS found, octet_length(c.embedding_json)::bigint AS bytes, CASE WHEN octet_length(c.embedding_json)<=$3 THEN c.embedding_json END AS payload, CASE WHEN octet_length(c.provider)+octet_length(c.revision)+octet_length(c.model)+octet_length(c.input_type)<=$4 THEN c.provider END AS provider, CASE WHEN octet_length(c.provider)+octet_length(c.revision)+octet_length(c.model)+octet_length(c.input_type)<=$4 THEN c.revision END AS revision, CASE WHEN octet_length(c.provider)+octet_length(c.revision)+octet_length(c.model)+octet_length(c.input_type)<=$4 THEN c.model END AS model, CASE WHEN octet_length(c.input_type)<=8 THEN c.input_type END AS input_type FROM unnest($1::text[],$2::text[]) WITH ORDINALITY AS requested(compatibility_hash,input_hash,position) LEFT JOIN public.embedding_cache c USING(compatibility_hash,input_hash) ORDER BY requested.position")
                .bind(&compatibility).bind(&input).bind(self.limits.vector_json_bytes.get() as i64).bind(self.limits.metadata_bytes.get() as i64)
                .fetch_all(&mut *tx).await.map_err(storage_error)?;
            check(end)?;
            if rows.len() != keys.len() { return Err(EmbeddingCacheError::MalformedStored); }
            let mut values = Vec::with_capacity(keys.len());
            for row in rows {
                check(end)?;
                let bad = |_| EmbeddingCacheError::MalformedStored;
                if !row.try_get::<bool,_>("found").map_err(bad)? { values.push(None); continue; }
                let bytes: i64 = row.try_get("bytes").map_err(bad)?;
                if bytes < 0 { return Err(EmbeddingCacheError::MalformedStored); }
                if bytes as u64 > self.limits.vector_json_bytes.get() as u64 { return Err(EmbeddingCacheError::ReadLimitExceeded); }
                let provenance = EmbeddingCacheProvenance { provider: row.try_get("provider").map_err(bad)?, revision: row.try_get("revision").map_err(bad)?, model: row.try_get("model").map_err(bad)?, input_type: row.try_get("input_type").map_err(bad)? };
                provenance.validate(self.limits).map_err(|_| EmbeddingCacheError::MalformedStored)?;
                let json: &str = row.try_get("payload").map_err(bad)?;
                values.push(Some(decode_vector(json, self.limits, &mut || check(end))?));
            }
            check(end)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| EmbeddingCacheError::Control(ControlError::OutcomeUncertain))?;
            guard.confirmed();
            Ok(values)
        }).await.map_err(|_| EmbeddingCacheError::Control(timeout_error(&commit_started)))?
    }
    pub async fn insert(
        &self,
        entries: &[EmbeddingCacheEntry<'_>],
        original: Instant,
    ) -> Result<EmbeddingCacheWrite, EmbeddingCacheError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        let data = prepare_insert(entries, self.limits, &mut || check(end))?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.owner.pool.acquire().await.map_err(storage_error)?));
            let mut tx = guard.connection()?.begin().await.map_err(storage_error)?;
            let changed = sqlx_core::query::query("INSERT INTO public.embedding_cache(compatibility_hash,input_hash,provider,revision,model,input_type,embedding_json) SELECT * FROM unnest($1::text[],$2::text[],$3::text[],$4::text[],$5::text[],$6::text[],$7::text[]) ON CONFLICT(compatibility_hash,input_hash) DO NOTHING")
                .bind(data.compatibility).bind(data.input).bind(data.provider).bind(data.revision).bind(data.model).bind(data.input_type).bind(data.json)
                .execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            let inserted = usize::try_from(changed).ok().filter(|n| *n <= entries.len()).ok_or(EmbeddingCacheError::Control(ControlError::Storage))?;
            check(end)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| EmbeddingCacheError::Control(ControlError::OutcomeUncertain))?;
            guard.confirmed();
            Ok(EmbeddingCacheWrite { inserted, unchanged: entries.len()-inserted })
        }).await.map_err(|_| EmbeddingCacheError::Control(timeout_error(&commit_started)))?
    }
}
