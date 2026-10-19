use super::SqliteControlStore;
use crate::{
    ControlError,
    embedding_cache::{
        EmbeddingCacheEntry, EmbeddingCacheError, EmbeddingCacheKey, EmbeddingCacheLimits,
        EmbeddingCacheProvenance, EmbeddingCacheWrite, check_count, decode_vector, prepare_insert,
    },
};
use rusqlite::{OptionalExtension, params};
use std::time::Instant;

/// Borrowed batch data access; one executor job and transaction per batch.
pub struct SqliteEmbeddingCache<'a> {
    owner: &'a SqliteControlStore,
    limits: EmbeddingCacheLimits,
}
impl SqliteControlStore {
    pub fn embedding_cache(
        &self,
        limits: EmbeddingCacheLimits,
    ) -> Result<SqliteEmbeddingCache<'_>, EmbeddingCacheError> {
        Ok(SqliteEmbeddingCache {
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
impl SqliteEmbeddingCache<'_> {
    pub async fn read(
        &self,
        keys: &[EmbeddingCacheKey],
        original: Instant,
    ) -> Result<Vec<Option<Vec<f32>>>, EmbeddingCacheError> {
        check(original)?;
        let limits = self.limits;
        check_count(keys.len(), limits)?;
        let keys: Vec<_> = keys.iter().copied().map(EmbeddingCacheKey::sql).collect();
        self.owner.executor.execute(original, move |owner, work| {
            let tx = owner.begin(work)?;
            let result = (|| -> Result<_,EmbeddingCacheError> {
                let mut statement = tx.prepare("SELECT length(CAST(embedding_json AS BLOB)),CASE WHEN typeof(embedding_json)='text' AND length(CAST(embedding_json AS BLOB))<=?3 THEN embedding_json END,CASE WHEN typeof(provider)='text' AND typeof(revision)='text' AND typeof(model)='text' AND length(CAST(provider AS BLOB))+length(CAST(revision AS BLOB))+length(CAST(model AS BLOB))+length(CAST(input_type AS BLOB))<=?4 THEN provider END,CASE WHEN length(CAST(revision AS BLOB))<=?4 THEN revision END,CASE WHEN length(CAST(model AS BLOB))<=?4 THEN model END,CASE WHEN typeof(input_type)='text' AND length(CAST(input_type AS BLOB))<=8 THEN input_type END FROM embedding_cache WHERE compatibility_hash=?1 AND input_hash=?2").map_err(|e|EmbeddingCacheError::Control(work.sql(e).into()))?;
                let mut values = Vec::with_capacity(keys.len());
                for (compatibility,input) in keys {
                    work.check().map_err(ControlError::from)?;
                    let row = statement.query_row(params![compatibility,input,limits.vector_json_bytes.get() as i64,limits.metadata_bytes.get() as i64], |row| {
                        let bytes:i64 = row.get(0)?;
                        if bytes < 0 { return Ok(Err(EmbeddingCacheError::MalformedStored)); }
                        if bytes as u64 > limits.vector_json_bytes.get() as u64 { return Ok(Err(EmbeddingCacheError::ReadLimitExceeded)); }
                        let json:String=row.get(1)?;
                        let provider:String=row.get(2)?; let revision:String=row.get(3)?; let model:String=row.get(4)?; let input_type:String=row.get(5)?;
                        if (EmbeddingCacheProvenance { provider:&provider, revision:&revision, model:&model, input_type:&input_type }).validate(limits).is_err() { return Ok(Err(EmbeddingCacheError::MalformedStored)); }
                        Ok(decode_vector(&json,limits,&mut ||work.check().map_err(ControlError::from)))
                    }).optional();
                    values.push(match row {
                        Ok(Some(value)) => Some(value?),
                        Ok(None) => None,
                        Err(rusqlite::Error::InvalidColumnType(..) | rusqlite::Error::FromSqlConversionFailure(..)) => return Err(EmbeddingCacheError::MalformedStored),
                        Err(error) => return Err(EmbeddingCacheError::Control(work.sql(error).into())),
                    });
                    work.check().map_err(ControlError::from)?;
                }
                Ok(values)
            })();
            match result {
                Ok(values) => {
                    work.check()?;
                    work.commit(tx)?;
                    Ok(Ok(values))
                }
                // The transaction drops and rolls back before returning. A
                // later cutoff must not replace an observed malformed row.
                Err(error) => Ok(Err(error)),
            }
        }).await.map_err(|e| EmbeddingCacheError::Control(e.into()))?
    }
    pub async fn insert(
        &self,
        entries: &[EmbeddingCacheEntry<'_>],
        original: Instant,
    ) -> Result<EmbeddingCacheWrite, EmbeddingCacheError> {
        let data = prepare_insert(entries, self.limits, &mut || check(original))?;
        let count = entries.len();
        self.owner.executor.execute(original, move |owner, work| {
            let tx = owner.begin(work)?;
            let inserted = {
                let mut statement = tx.prepare("INSERT INTO embedding_cache(compatibility_hash,input_hash,provider,revision,model,input_type,embedding_json) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(compatibility_hash,input_hash) DO NOTHING").map_err(|e|work.sql(e))?;
                let mut inserted = 0usize;
                for i in 0..count {
                    work.check()?;
                    let changed = statement.execute(params![data.compatibility[i],data.input[i],data.provider[i],data.revision[i],data.model[i],data.input_type[i],data.json[i]]).map_err(|e|work.sql(e))?;
                    if changed > 1 { return Err(super::super::SqliteControlError::Storage); }
                    inserted += changed;
                }
                inserted
            };
            work.commit(tx)?;
            Ok(EmbeddingCacheWrite { inserted, unchanged:count-inserted })
        }).await.map_err(|e| EmbeddingCacheError::Control(e.into()))
    }
}
