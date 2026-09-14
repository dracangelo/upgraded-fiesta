package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

type memoryCacheEntry struct {
	value     string
	expiresAt time.Time
}

// ProviderCache provides bounded TTL caching for external intelligence queries (VirusTotal, Censys, Shodan).
type ProviderCache struct {
	mu       sync.RWMutex
	store    RuntimeStore
	memCache map[string]memoryCacheEntry
}

// NewProviderCache initializes a ProviderCache wrapping the runtime store with an in-memory fallback.
func NewProviderCache(store RuntimeStore) *ProviderCache {
	return &ProviderCache{
		store:    store,
		memCache: make(map[string]memoryCacheEntry),
	}
}

// Get retrieves a cached intelligence response for a given provider and indicator.
func (c *ProviderCache) Get(ctx context.Context, provider, indicator string) (string, bool, error) {
	key := fmt.Sprintf("provider:%s:%s", strings.ToLower(strings.TrimSpace(provider)), strings.ToLower(strings.TrimSpace(indicator)))

	if c.store != nil {
		val, ok, err := c.store.CachedValue(ctx, key)
		if err == nil && ok {
			return val, true, nil
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, exists := c.memCache[key]
	if !exists || time.Now().UTC().After(entry.expiresAt) {
		return "", false, nil
	}
	return entry.value, true, nil
}

// Put stores a provider response with a bounded TTL.
func (c *ProviderCache) Put(ctx context.Context, provider, indicator, payload string, ttl time.Duration) error {
	key := fmt.Sprintf("provider:%s:%s", strings.ToLower(strings.TrimSpace(provider)), strings.ToLower(strings.TrimSpace(indicator)))

	if ttl <= 0 {
		ttl = 6 * time.Hour
	}

	if c.store != nil {
		_ = c.store.PutCachedValue(ctx, key, payload, ttl)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.memCache[key] = memoryCacheEntry{
		value:     payload,
		expiresAt: time.Now().UTC().Add(ttl),
	}
	return nil
}
