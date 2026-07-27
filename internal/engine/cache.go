package engine

import (
	"sync"
	"time"
)

type CacheItem struct {
	Value      any
	Expiration time.Time
}

type ScanCache struct {
	mu    sync.RWMutex
	items map[string]CacheItem
	ttl   time.Duration
}

func NewScanCache(ttl time.Duration) *ScanCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &ScanCache{
		items: make(map[string]CacheItem),
		ttl:   ttl,
	}
}

func (c *ScanCache) Get(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found {
		return nil, false
	}

	if time.Now().After(item.Expiration) {
		return nil, false
	}

	return item.Value, true
}

func (c *ScanCache) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = CacheItem{
		Value:      value,
		Expiration: time.Now().Add(c.ttl),
	}
}

func (c *ScanCache) PurgeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, item := range c.items {
		if now.After(item.Expiration) {
			delete(c.items, k)
		}
	}
}
