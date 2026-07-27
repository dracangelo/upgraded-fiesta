package scheduler

import (
	"sync"
	"time"
)

type AdaptiveWorkerPool struct {
	mu             sync.RWMutex
	minConcurrency int
	maxConcurrency int
	current        int
	latencyWindow  []time.Duration
}

func NewAdaptiveWorkerPool(min, max int) *AdaptiveWorkerPool {
	if min <= 0 {
		min = 2
	}
	if max < min {
		max = min * 4
	}
	return &AdaptiveWorkerPool{
		minConcurrency: min,
		maxConcurrency: max,
		current:        min,
		latencyWindow:  make([]time.Duration, 0, 20),
	}
}

func (ap *AdaptiveWorkerPool) RecordLatency(d time.Duration) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	ap.latencyWindow = append(ap.latencyWindow, d)
	if len(ap.latencyWindow) > 20 {
		ap.latencyWindow = ap.latencyWindow[1:]
	}

	// Calculate average latency
	var total time.Duration
	for _, l := range ap.latencyWindow {
		total += l
	}
	avg := total / time.Duration(len(ap.latencyWindow))

	// Scale concurrency up if latency is low, down if latency is high
	if avg < 100*time.Millisecond && ap.current < ap.maxConcurrency {
		ap.current++
	} else if avg > 500*time.Millisecond && ap.current > ap.minConcurrency {
		ap.current--
	}
}

func (ap *AdaptiveWorkerPool) Concurrency() int {
	ap.mu.RLock()
	defer ap.mu.RUnlock()
	return ap.current
}
