package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestScanHealthIncludesFailedModuleRuns(t *testing.T) {
	st, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "health.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.StartScan(ctx, "health-test"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordModuleRun(ctx, models.ModuleRun{ScanID: "health-test", Module: "http", EventType: "target", Target: "example.test", Status: "completed", Duration: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordModuleRun(ctx, models.ModuleRun{ScanID: "health-test", Module: "portscan", EventType: "target", Target: "example.test", Status: "failed", Error: "timeout"}); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(ctx, "health-test", "completed", ""); err != nil {
		t.Fatal(err)
	}
	health, err := st.ScanHealth(ctx, "health-test")
	if err != nil {
		t.Fatal(err)
	}
	if health.Healthy || health.CompletedRuns != 1 || health.FailedRuns != 1 {
		t.Fatalf("unexpected health: %+v", health)
	}
}
