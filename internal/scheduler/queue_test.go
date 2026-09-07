package scheduler

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type runtimeTestModule struct{}

func (runtimeTestModule) Name() string            { return "runtime-test" }
func (runtimeTestModule) Subscriptions() []string { return []string{"target"} }
func (runtimeTestModule) Handle(context.Context, models.Event) ([]models.Event, error) {
	return nil, nil
}

type fastRuntimeTestModule struct{}

func (fastRuntimeTestModule) Name() string            { return "fast-runtime-test" }
func (fastRuntimeTestModule) Subscriptions() []string { return []string{"target"} }
func (fastRuntimeTestModule) Handle(context.Context, models.Event) ([]models.Event, error) {
	return nil, nil
}

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

func TestSchedulerQueuesHighPriorityEventsFirst(t *testing.T) {
	s := New(1, 0, 0, time.Second, nil)
	s.EnqueuePriority(models.Event{Type: "low"}, PriorityLow)
	s.EnqueuePriority(models.Event{Type: "high"}, PriorityHigh)

	first, ok := s.nextEvent()
	if !ok || first.Type != "high" {
		t.Fatalf("expected high priority event first, got %#v", first)
	}
	second, ok := s.nextEvent()
	if !ok || second.Type != "low" {
		t.Fatalf("expected low priority event second, got %#v", second)
	}
}

func TestSchedulerDeduplicatesExactEventsWithoutBloomFalsePositiveLoss(t *testing.T) {
	s := New(1, 0, 0, time.Second, nil)
	first := models.Event{ScanID: "scan", Type: "http.url", Target: "https://example.test", Data: map[string]string{"b": "2", "a": "1"}}
	second := models.Event{ScanID: "scan", Type: "http.url", Target: "https://example.test", Data: map[string]string{"a": "1", "b": "2"}}
	s.Enqueue(first)
	s.Enqueue(second)
	item, ok := s.nextEvent()
	if !ok || item.Target != first.Target {
		t.Fatalf("expected first event, got %#v", item)
	}
	if len(s.normalQueue) != 0 {
		t.Fatal("duplicate event was queued")
	}
	// A distinct event must not be suppressed just because a Bloom filter says
	// it may have been seen; the exact set is authoritative.
	s.Enqueue(models.Event{ScanID: "scan", Type: "http.url", Target: "https://other.test"})
	if _, ok := s.nextEvent(); !ok {
		t.Fatal("distinct event was incorrectly dropped")
	}
}

func TestSchedulerPersistsObservedRuntimeStats(t *testing.T) {
	ctx := context.Background()
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "runtime.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s := New(1, 0, 0, time.Second, nil)
	s.SetScanID("runtime-scan")
	s.Register(runtimeTestModule{})
	s.Enqueue(models.Event{ScanID: "runtime-scan", Type: "target", Target: "example.test"})
	if err := s.Run(ctx, db); err != nil {
		t.Fatal(err)
	}
	var stats models.ScanRuntimeStats
	deadline := time.Now().Add(time.Second)
	for {
		stats, err = db.ScanRuntimeStats(ctx, "runtime-scan")
		if err != nil {
			t.Fatal(err)
		}
		if stats.ActiveWorkers == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stats.WorkerCapacity != 1 || stats.ActiveWorkers != 0 || stats.RunningModules != 0 || stats.CompletedEvents != 1 {
		t.Fatalf("unexpected terminal runtime snapshot: %#v", stats)
	}
}

func TestSchedulerAdaptiveWorkersChangeLiveCapacity(t *testing.T) {
	ctx := context.Background()
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "adaptive-runtime.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s := New(3, 0, 0, time.Second, nil)
	s.EnableAdaptiveWorkers(1)
	s.SetScanID("adaptive-runtime-scan")
	s.Register(fastRuntimeTestModule{})
	for index := 0; index < 4; index++ {
		s.Enqueue(models.Event{ScanID: "adaptive-runtime-scan", Type: "target", Target: "host-" + string(rune('a'+index))})
	}
	if err := s.Run(ctx, db); err != nil {
		t.Fatal(err)
	}
	stats, err := db.ScanRuntimeStats(ctx, "adaptive-runtime-scan")
	if err != nil {
		t.Fatal(err)
	}
	if stats.WorkerCapacity <= 1 || stats.WorkerCapacity > 3 || stats.ActiveWorkers != 0 {
		t.Fatalf("expected bounded adaptive capacity and no live workers after completion, got %#v", stats)
	}
}
