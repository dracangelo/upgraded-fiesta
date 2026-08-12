package store

import (
	"context"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
)

func TestAddPortObservation(t *testing.T) {
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "ports.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPortObservation(ctx, models.PortObservation{ScanID: "s", Host: "127.0.0.1", Port: 443, Protocol: "tcp", State: "open", LatencyMS: 12}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM port_observations WHERE scan_id='s'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("unexpected stored observations: %d, %v", count, err)
	}
}
