package modules

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/inventory"
	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestRawTCPScannerTechniques(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	guard := scope.New([]string{"127.0.0.1"})

	techniques := []ScanTechnique{
		ScanSYN, ScanACK, ScanFIN, ScanNULL, ScanXMAS, ScanIdle, ScanFragmented, ScanDecoy,
	}

	for _, tech := range techniques {
		scanner := NewRawTCPScanner(db, guard, tech)
		if !strings.HasPrefix(scanner.Name(), "raw_tcp_scanner_") {
			t.Errorf("unexpected name: %s", scanner.Name())
		}

		_, err := scanner.Handle(context.Background(), models.Event{
			ScanID: "s1",
			Type:   EventHost,
			Target: "127.0.0.1",
		})
		if err != nil {
			t.Errorf("technique %s returned error: %v", tech, err)
		}
	}
}

func TestDifferentialPortScanner(t *testing.T) {
	diffScanner := inventory.NewDifferentialPortScanner()

	baseline := []models.Asset{
		{Value: "127.0.0.1:80", Type: "open_port"},
		{Value: "127.0.0.1:443", Type: "open_port"},
	}

	current := []models.Asset{
		{Value: "127.0.0.1:80", Type: "open_port"},
		{Value: "127.0.0.1:8080", Type: "open_port"},
	}

	diff := diffScanner.CompareScanRuns(baseline, current)
	if len(diff.NewOpenPorts) != 1 || diff.NewOpenPorts[0] != "127.0.0.1:8080" {
		t.Errorf("expected new open port 127.0.0.1:8080, got %v", diff.NewOpenPorts)
	}
	if len(diff.NewlyClosedPorts) != 1 || diff.NewlyClosedPorts[0] != "127.0.0.1:443" {
		t.Errorf("expected newly closed port 127.0.0.1:443, got %v", diff.NewlyClosedPorts)
	}

	findings := diffScanner.CreateDiffFindings(context.Background(), diff, "scan-diff-01")
	if len(findings) != 1 {
		t.Fatalf("expected 1 diff finding, got %d", len(findings))
	}
}
