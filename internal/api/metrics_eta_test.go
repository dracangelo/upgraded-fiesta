package api

import (
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestQueueETAUsesPersistedWorkOnly(t *testing.T) {
	now := time.Now()
	metrics := store.ScanMetrics{Status: "running", StartedAt: now.Add(-time.Minute)}
	runtime := models.ScanRuntimeStats{CompletedEvents: 4, QueueHigh: 2}
	eta := queueETA(metrics, runtime, now)
	if eta == nil || *eta != 30 {
		t.Fatalf("expected 30-second queued-work ETA, got %v", eta)
	}
	if eta := queueETA(store.ScanMetrics{Status: "paused", StartedAt: now.Add(-time.Minute)}, runtime, now); eta != nil {
		t.Fatalf("paused scan must not report ETA: %v", *eta)
	}
	if eta := queueETA(metrics, models.ScanRuntimeStats{CompletedEvents: 0, QueueHigh: 2}, now); eta != nil {
		t.Fatalf("ETA without completed evidence must be omitted: %v", *eta)
	}
}
