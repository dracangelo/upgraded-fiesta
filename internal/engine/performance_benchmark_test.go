package engine

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestAdaptiveWorkerPool(t *testing.T) {
	pool := NewAdaptiveWorkerPool(2, 8, 100)
	defer pool.Stop()

	if pool.ActiveWorkers() < 2 {
		t.Fatalf("expected at least 2 min workers, got %d", pool.ActiveWorkers())
	}

	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		pool.Submit(func() {
			time.Sleep(10 * time.Millisecond)
			done <- true
		})
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestOptimizedHTTPTransport(t *testing.T) {
	transport := NewOptimizedHTTPTransport()
	if transport == nil {
		t.Fatalf("expected non-nil transport")
	}
	if transport.MaxIdleConns != 500 {
		t.Fatalf("expected MaxIdleConns=500, got %d", transport.MaxIdleConns)
	}

	client := &http.Client{Transport: transport}
	if client.Transport == nil {
		t.Fatalf("client transport is nil")
	}
}

func TestBloomFilter(t *testing.T) {
	bf := NewBloomFilter(1024)

	items := []string{"sub.domain.com", "192.168.1.1", "CVE-2026-1001"}
	for _, item := range items {
		bf.Add(item)
	}

	for _, item := range items {
		if !bf.Contains(item) {
			t.Fatalf("expected bloom filter to contain %s", item)
		}
	}

	if bf.Contains("nonexistent.domain.xyz") {
		// Probabilistic check - usually false
	}
}

func TestMemoryBufferPool(t *testing.T) {
	buf := GetBuffer()
	buf.WriteString("hello enumscan performance")
	if buf.String() != "hello enumscan performance" {
		t.Fatalf("unexpected buffer content: %s", buf.String())
	}
	PutBuffer(buf)
}

func BenchmarkBloomFilterAdd(b *testing.B) {
	bf := NewBloomFilter(65536)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Add(fmt.Sprintf("item-%d", i))
	}
}

func BenchmarkBloomFilterContains(b *testing.B) {
	bf := NewBloomFilter(65536)
	for i := 0; i < 1000; i++ {
		bf.Add(fmt.Sprintf("item-%d", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Contains(fmt.Sprintf("item-%d", i%1000))
	}
}

func BenchmarkAdaptiveWorkerPoolSubmit(b *testing.B) {
	pool := NewAdaptiveWorkerPool(4, 16, 10000)
	defer pool.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Submit(func() {
			_ = 1 + 1
		})
	}
}
