package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"enumscan/internal/models"
)

func TestNativeSQLiteSerializesConcurrentPersistence(t *testing.T) {
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "concurrent.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.StartScan(ctx, "concurrent"); err != nil {
		t.Fatal(err)
	}

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := db.AddEvent(ctx, models.Event{ScanID: "concurrent", Type: "test", Target: "target-" + string(rune('a'+i))}); err != nil {
				errs <- err
				return
			}
			if err := db.AddAsset(ctx, models.Asset{ScanID: "concurrent", Type: "asset", Value: "value-" + string(rune('a'+i))}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent persistence failed: %v", err)
	}
	events, err := db.Events(ctx, "concurrent")
	if err != nil || len(events) != workers {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	assets, err := db.Assets(ctx, "concurrent")
	if err != nil || len(assets) != workers {
		t.Fatalf("assets=%d err=%v", len(assets), err)
	}
}
