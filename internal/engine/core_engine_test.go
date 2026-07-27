package engine

import (
	"context"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/plugin"
	"enumscan/internal/scheduler"
	"enumscan/internal/store"
)

func TestNativeSQLiteStore(t *testing.T) {
	s := store.NewNativeSQLiteStore(t.TempDir() + "/test_native.db")
	if err := s.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	_ = s.Migrate(context.Background())
}

func TestPriorityQueueAndAdaptivePool(t *testing.T) {
	pq := scheduler.NewPriorityQueue()
	pq.Push(models.Event{Target: "low_prio"}, scheduler.PriorityLow)
	pq.Push(models.Event{Target: "high_prio"}, scheduler.PriorityHigh)

	item, ok := pq.Pop()
	if !ok || item.Target != "high_prio" {
		t.Errorf("expected high_prio item popped first, got %v", item)
	}

	ap := scheduler.NewAdaptiveWorkerPool(2, 8)
	initial := ap.Concurrency()
	ap.RecordLatency(10 * time.Millisecond)
	if ap.Concurrency() < initial {
		t.Errorf("expected worker pool scaling up on low latency")
	}
}

func TestCoordinatorAndRemoteAgent(t *testing.T) {
	coord := NewCoordinator()
	agent := NewRemoteAgent("agent-01", coord)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = agent.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	if coord.AgentCount() != 1 {
		t.Errorf("expected 1 registered agent, got %d", coord.AgentCount())
	}

	coord.Dispatch(models.Event{ScanID: "scan-dist", Type: "port.open", Target: "127.0.0.1:80"})
	time.Sleep(150 * time.Millisecond)
	cancel()
}

func TestEventDeduplicationAndCache(t *testing.T) {
	dedup := NewEventDeduplicator()
	evt := models.Event{ScanID: "s1", Type: "port.open", Target: "10.0.0.1:22"}

	if dedup.IsDuplicate(evt) {
		t.Errorf("first check should not be duplicate")
	}
	if !dedup.IsDuplicate(evt) {
		t.Errorf("second check must be marked as duplicate")
	}

	cache := NewScanCache(100 * time.Millisecond)
	cache.Set("key1", "val1")
	val, found := cache.Get("key1")
	if !found || val != "val1" {
		t.Errorf("expected cache hit for key1")
	}

	time.Sleep(150 * time.Millisecond)
	_, expired := cache.Get("key1")
	if expired {
		t.Errorf("expected cache miss for expired item")
	}
}

func TestPluginDependencyResolver(t *testing.T) {
	resolver := plugin.NewDependencyResolver()
	nodes := []plugin.DependencyNode{
		{Name: "vulnerability_scan", Dependencies: []string{"port_scan"}},
		{Name: "port_scan", Dependencies: []string{"dns_enum"}},
		{Name: "dns_enum", Dependencies: nil},
	}

	order, err := resolver.ResolveExecutionOrder(nodes)
	if err != nil {
		t.Fatalf("ResolveExecutionOrder: %v", err)
	}

	if len(order) != 3 || order[0] != "dns_enum" || order[1] != "port_scan" || order[2] != "vulnerability_scan" {
		t.Errorf("unexpected execution order: %v", order)
	}
}
