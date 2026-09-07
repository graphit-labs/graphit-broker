package broker

import (
	"sync"
	"time"
)

type cacheEntry struct {
	value     []byte
	expiresAt time.Time
	createdAt time.Time
}

type responseCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]cacheEntry
	now        func() time.Time
}

func newResponseCache(cfg CacheConfig) *responseCache {
	return &responseCache{ttl: cfg.TTL, maxEntries: cfg.MaxEntries, entries: map[string]cacheEntry{}, now: time.Now}
}

func (c *responseCache) Get(key string) ([]byte, bool) {
	if c == nil || c.ttl <= 0 || c.maxEntries <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !entry.expiresAt.After(c.now()) {
		delete(c.entries, key)
		return nil, false
	}
	return append([]byte(nil), entry.value...), true
}

func (c *responseCache) Put(key string, value []byte) {
	if c == nil || c.ttl <= 0 || c.maxEntries <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for key, entry := range c.entries {
		if !entry.expiresAt.After(now) {
			delete(c.entries, key)
		}
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		oldestKey := ""
		var oldest time.Time
		for candidate, entry := range c.entries {
			if oldestKey == "" || entry.createdAt.Before(oldest) {
				oldestKey, oldest = candidate, entry.createdAt
			}
		}
		delete(c.entries, oldestKey)
	}
	c.entries[key] = cacheEntry{value: append([]byte(nil), value...), createdAt: now, expiresAt: now.Add(c.ttl)}
}
