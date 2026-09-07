package scheduler

import (
	"hash/fnv"
	"sort"
	"strings"
	"sync"

	"enumscan/internal/models"
)

// eventDeduper uses a Bloom filter as a fast negative check and an exact,
// bounded set as the authority. Bloom false positives therefore never drop a
// scan event. The exact set is evicted FIFO to cap memory on broad scans.
type eventDeduper struct {
	mu       sync.Mutex
	bits     []uint64
	exact    map[string]struct{}
	order    []string
	capacity int
}

func newEventDeduper(capacity int) *eventDeduper {
	if capacity < 1 {
		capacity = 100000
	}
	return &eventDeduper{bits: make([]uint64, 1<<14), exact: make(map[string]struct{}, capacity), capacity: capacity}
}

func (d *eventDeduper) seen(event models.Event) bool {
	key := canonicalEventKey(event)
	d.mu.Lock()
	defer d.mu.Unlock()
	indexes := bloomIndexes(key, uint64(len(d.bits)*64))
	maybeSeen := true
	for _, index := range indexes {
		if d.bits[index/64]&(uint64(1)<<(index%64)) == 0 {
			maybeSeen = false
		}
	}
	if maybeSeen {
		if _, found := d.exact[key]; found {
			return true
		}
	}
	for _, index := range indexes {
		d.bits[index/64] |= uint64(1) << (index % 64)
	}
	d.exact[key] = struct{}{}
	d.order = append(d.order, key)
	if len(d.order) > d.capacity {
		oldest := d.order[0]
		d.order = d.order[1:]
		delete(d.exact, oldest)
	}
	return false
}

func canonicalEventKey(event models.Event) string {
	keys := make([]string, 0, len(event.Data))
	for key := range event.Data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+event.Data[key])
	}
	return event.ScanID + "\x00" + event.Type + "\x00" + event.Target + "\x00" + strings.Join(values, "\x00")
}

func bloomIndexes(value string, size uint64) [3]uint64 {
	var indexes [3]uint64
	for seed := uint64(1); seed <= 3; seed++ {
		h := fnv.New64a()
		_, _ = h.Write([]byte{byte(seed)})
		_, _ = h.Write([]byte(value))
		indexes[seed-1] = h.Sum64() % size
	}
	return indexes
}
