package inventory

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/store"
)

func TestDemoDataGenerationAndSeeding(t *testing.T) {
	scanID := "test-demo-run-01"
	dataset := GenerateSanitizedDemoDataset(scanID)

	if dataset.ScanRun.ScanID != scanID {
		t.Errorf("expected scanID %s, got %s", scanID, dataset.ScanRun.ScanID)
	}

	// Verify all assets are RFC 5737 or RFC 2606
	for _, asset := range dataset.Assets {
		if asset.Type == "ipv4" {
			if !strings.HasPrefix(asset.Value, "198.51.100.") {
				t.Errorf("asset IP %s is not in RFC 5737 range", asset.Value)
			}
		} else if asset.Type == "domain" {
			if !strings.HasSuffix(asset.Value, ".example.internal") {
				t.Errorf("asset domain %s is not in RFC 2606/internal range", asset.Value)
			}
		}
	}

	if len(dataset.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(dataset.Findings))
	}
	if len(dataset.Events) != 3 {
		t.Errorf("expected 3 events, got %d", len(dataset.Events))
	}

	// Test seeding into real SQLite store
	dbPath := filepath.Join(t.TempDir(), "demo.db")
	db, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("failed migrating test store: %v", err)
	}

	seeded, err := SeedDemoDataset(ctx, db, scanID)
	if err != nil {
		t.Fatalf("failed seeding demo dataset: %v", err)
	}

	// Verify persistence
	runs, err := db.ScanRuns(ctx, 10)
	if err != nil {
		t.Fatalf("failed retrieving seeded scan runs: %v", err)
	}
	if len(runs) == 0 || runs[0].ScanID != scanID {
		t.Fatalf("expected scan run id %s, got %+v", scanID, runs)
	}

	assets, err := db.Assets(ctx, scanID)
	if err != nil || len(assets) != len(seeded.Assets) {
		t.Fatalf("expected %d assets, got %d (err: %v)", len(seeded.Assets), len(assets), err)
	}

	findings, err := db.Findings(ctx, scanID)
	if err != nil || len(findings) != len(seeded.Findings) {
		t.Fatalf("expected %d findings, got %d (err: %v)", len(seeded.Findings), len(findings), err)
	}
}
