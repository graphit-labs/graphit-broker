use super::{RerankResult, WireError};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
struct Entry {
    created: Instant,
    expires: Instant,
    results: Arc<Vec<RerankResult>>,
}
pub(super) struct Cache {
    entries: HashMap<[u8; 32], Entry>,
}
impl Cache {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
    pub(super) fn get(&mut self, key: &[u8; 32], now: Instant) -> Option<Arc<Vec<RerankResult>>> {
        if self.entries.get(key).is_some_and(|e| e.expires <= now) {
            self.entries.remove(key);
            return None;
        }
        self.entries.get(key).map(|e| e.results.clone())
    }
    pub(super) fn put(
        &mut self,
        key: [u8; 32],
        results: Arc<Vec<RerankResult>>,
        now: Instant,
        ttl: Duration,
        capacity: usize,
        check: &mut impl FnMut() -> Result<(), WireError>,
    ) -> Result<(), WireError> {
        check()?;
        let mut expired = Vec::new();
        let mut oldest = None;
        for (key, entry) in &self.entries {
            check()?;
            if entry.expires <= now {
                expired.try_reserve(1).map_err(|_| WireError::Upstream)?;
                expired.push(*key);
            }
            if oldest.is_none_or(|(_, created)| entry.created < created) {
                oldest = Some((*key, entry.created));
            }
        }
        for key in expired {
            check()?;
            self.entries.remove(&key);
        }
        if !self.entries.contains_key(&key)
            && self.entries.len() >= capacity
            && let Some((key, _)) = oldest
        {
            self.entries.remove(&key);
        }
        check()?;
        self.entries
            .try_reserve(1)
            .map_err(|_| WireError::Upstream)?;
        self.entries.insert(
            key,
            Entry {
                created: now,
                expires: now.checked_add(ttl).ok_or(WireError::Upstream)?,
                results,
            },
        );
        if let Err(error) = check() {
            self.entries.remove(&key);
            return Err(error);
        }
        Ok(())
    }
}
