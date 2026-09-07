package scheduler

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type pauseTestModule struct{ calls atomic.Int32 }

func (m *pauseTestModule) Name() string            { return "pause-test" }
func (m *pauseTestModule) Subscriptions() []string { return []string{"target"} }
func (m *pauseTestModule) Handle(context.Context, models.Event) ([]models.Event, error) {
	m.calls.Add(1)
	return nil, nil
}

func TestSchedulerCooperativelyPausesAndResumes(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "pause.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.StartScan(ctx, "paused-scan"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateScanStatus(ctx, "paused-scan", "paused"); err != nil {
		t.Fatal(err)
	}
	queue := New(1, 0, 0, time.Second, nil)
	queue.SetScanID("paused-scan")
	module := &pauseTestModule{}
	queue.Register(module)
	queue.Enqueue(models.Event{ScanID: "paused-scan", Type: "target", Target: "127.0.0.1"})
	done := make(chan error, 1)
	go func() { done <- queue.Run(ctx, db) }()
	time.Sleep(75 * time.Millisecond)
	if module.calls.Load() != 0 {
		t.Fatal("paused scheduler ran a module")
	}
	if err := db.UpdateScanStatus(ctx, "paused-scan", "running"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not resume")
	}
	if module.calls.Load() != 1 {
		t.Fatalf("expected one module call after resume, got %d", module.calls.Load())
	}
}
