package engine

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"enumscan/internal/models"
)

type EventDeduplicator struct {
	mu   sync.RWMutex
	seen map[string]bool
}

func NewEventDeduplicator() *EventDeduplicator {
	return &EventDeduplicator{
		seen: make(map[string]bool),
	}
}

func (d *EventDeduplicator) IsDuplicate(evt models.Event) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	hashKey := d.computeHash(evt)
	if d.seen[hashKey] {
		return true
	}
	d.seen[hashKey] = true
	return false
}

func (d *EventDeduplicator) computeHash(evt models.Event) string {
	raw := fmt.Sprintf("%s:%s:%s:%v", evt.ScanID, evt.Type, evt.Target, evt.Data)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

func (d *EventDeduplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = make(map[string]bool)
}
