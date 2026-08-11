package scheduler

import (
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestAdaptiveWorkerPool(t *testing.T) {
	pool := NewAdaptiveWorkerPool(0, 0) // Defaults to min=2, max=8
	if pool.Concurrency() != 2 {
		t.Fatalf("expected initial concurrency 2, got %d", pool.Concurrency())
	}

	// Record low latency to scale up
	for i := 0; i < 25; i++ {
		pool.RecordLatency(10 * time.Millisecond)
	}
	if pool.Concurrency() <= 2 {
		t.Errorf("expected concurrency to scale up, got %d", pool.Concurrency())
	}

	// Record high latency to scale down
	for i := 0; i < 30; i++ {
		pool.RecordLatency(600 * time.Millisecond)
	}
	if pool.Concurrency() > 4 {
		t.Errorf("expected concurrency to scale down, got %d", pool.Concurrency())
	}
}

func TestPriorityQueue(t *testing.T) {
	pq := NewPriorityQueue()
	if pq.Len() != 0 {
		t.Fatalf("expected empty queue")
	}

	evtLow := models.Event{Type: "low", Target: "target1"}
	evtHigh := models.Event{Type: "high", Target: "target2"}

	pq.Push(evtLow, PriorityLow)
	pq.Push(evtHigh, PriorityHigh)

	if pq.Len() != 2 {
		t.Fatalf("expected len 2, got %d", pq.Len())
	}

	first, ok := pq.Pop()
	if !ok || first.Type != "high" {
		t.Fatalf("expected highest priority item first, got %#v", first)
	}

	second, ok := pq.Pop()
	if !ok || second.Type != "low" {
		t.Fatalf("expected low priority item second, got %#v", second)
	}

	_, ok = pq.Pop()
	if ok {
		t.Fatalf("expected empty pop to return false")
	}
}
