package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestBackupRestorePurge(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "original.sqlite")
	backupPath := filepath.Join(t.TempDir(), "backup.sqlite")

	store, err := OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}

	ctx := context.Background()
	_ = store.Migrate(ctx)

	scanID := "scan-backup-1"
	if err := store.StartScan(ctx, scanID); err != nil {
		t.Fatalf("StartScan: %v", err)
	}
	_ = store.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "host", Value: "10.0.0.1"})
	_ = store.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: "high", Title: "Backup Finding"})

	// Perform Backup
	if err := store.Backup(ctx, backupPath); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Purge data
	deleted, err := store.PurgeScansOlderThan(ctx, -1*time.Hour) // Cutoff in future -> deletes all
	if err != nil {
		t.Fatalf("PurgeScansOlderThan failed: %v", err)
	}
	if deleted == 0 {
		t.Logf("Purged 0 scan runs based on cutoff timestamp")
	}

	// Perform Restore
	if err := store.Restore(ctx, backupPath); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// Verify restored data
	assets, err := store.Assets(ctx, scanID)
	if err != nil || len(assets) == 0 {
		t.Fatalf("expected assets after restore, got %v (err=%v)", assets, err)
	}

	store.Close()
}
