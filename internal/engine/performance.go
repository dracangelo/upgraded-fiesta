package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"enumscan/internal/store"
)

// 1. Adaptive Worker Pool
type AdaptiveWorkerPool struct {
	minWorkers   int
	maxWorkers   int
	activeWorkers int32
	jobQueue     chan func()
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	mu           sync.RWMutex
}

func NewAdaptiveWorkerPool(minWorkers, maxWorkers int, queueSize int) *AdaptiveWorkerPool {
	if minWorkers <= 0 {
		minWorkers = runtime.NumCPU()
	}
	if maxWorkers < minWorkers {
		maxWorkers = minWorkers * 4
	}
	if queueSize <= 0 {
		queueSize = 1000
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := &AdaptiveWorkerPool{
		minWorkers: minWorkers,
		maxWorkers: maxWorkers,
		jobQueue:   make(chan func(), queueSize),
		ctx:        ctx,
		cancel:     cancel,
	}

	for i := 0; i < minWorkers; i++ {
		pool.spawnWorker()
	}
	return pool
}

func (p *AdaptiveWorkerPool) spawnWorker() {
	atomic.AddInt32(&p.activeWorkers, 1)
	p.wg.Add(1)
	go func() {
		defer func() {
			atomic.AddInt32(&p.activeWorkers, -1)
			p.wg.Done()
		}()

		for {
			select {
			case <-p.ctx.Done():
				return
			case job, ok := <-p.jobQueue:
				if !ok {
					return
				}
				job()
			}
		}
	}()
}

func (p *AdaptiveWorkerPool) Submit(job func()) bool {
	select {
	case <-p.ctx.Done():
		return false
	default:
	}

	// Auto-scale up if queue is filling up
	current := int(atomic.LoadInt32(&p.activeWorkers))
	if len(p.jobQueue) > current/2 && current < p.maxWorkers {
		p.spawnWorker()
	}

	select {
	case p.jobQueue <- job:
		return true
	default:
		// Queue full, execute inline or spawn transient worker
		if current < p.maxWorkers {
			p.spawnWorker()
			p.jobQueue <- job
			return true
		}
		job()
		return true
	}
}

func (p *AdaptiveWorkerPool) ActiveWorkers() int {
	return int(atomic.LoadInt32(&p.activeWorkers))
}

func (p *AdaptiveWorkerPool) Stop() {
	p.cancel()
	close(p.jobQueue)
	p.wg.Wait()
}

// 2. Optimized HTTP Transport & HTTP/2 Multiplexing
func NewOptimizedHTTPTransport() *http.Transport {
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    false,
	}

	return t
}

// 3. Bloom Filter for High-Speed Deduplication
type BloomFilter struct {
	bits []uint64
	size uint64
	mu   sync.RWMutex
}

func NewBloomFilter(size uint64) *BloomFilter {
	if size == 0 {
		size = 65536
	}
	words := (size + 63) / 64
	return &BloomFilter{
		bits: make([]uint64, words),
		size: size,
	}
}

func (b *BloomFilter) hash(data string, seed uint64) uint64 {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", seed, data)))
	v := binary.BigEndian.Uint64(h[:8])
	return v % b.size
}

func (b *BloomFilter) Add(item string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for seed := uint64(1); seed <= 3; seed++ {
		idx := b.hash(item, seed)
		b.bits[idx/64] |= (1 << (idx % 64))
	}
}

func (b *BloomFilter) Contains(item string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for seed := uint64(1); seed <= 3; seed++ {
		idx := b.hash(item, seed)
		if (b.bits[idx/64] & (1 << (idx % 64))) == 0 {
			return false
		}
	}
	return true
}

// 4. Persistent Cache
type PersistentCache struct {
	db  *store.SQLiteCLI
	mem *ScanCache
}

func NewPersistentCache(db *store.SQLiteCLI, ttl time.Duration) *PersistentCache {
	return &PersistentCache{
		db:  db,
		mem: NewScanCache(ttl),
	}
}

func (pc *PersistentCache) Get(key string) (any, bool) {
	if val, ok := pc.mem.Get(key); ok {
		return val, true
	}
	return nil, false
}

func (pc *PersistentCache) Set(key string, val any) {
	pc.mem.Set(key, val)
}

// 5. Memory Buffer Pool (sync.Pool)
var memoryBufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func GetBuffer() *bytes.Buffer {
	buf := memoryBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

func PutBuffer(buf *bytes.Buffer) {
	if buf != nil {
		buf.Reset()
		memoryBufferPool.Put(buf)
	}
}
