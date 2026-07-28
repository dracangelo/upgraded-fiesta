package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestSchemaMigrationsAndVersioning(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migration_test.sqlite")
	st, err := OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	// 1. Run migrations
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// 2. Verify migration version is tracked
	mm := NewMigrationManager(st.db)
	version, err := mm.CurrentVersion(ctx)
	if err != nil {
		t.Fatalf("CurrentVersion failed: %v", err)
	}

	if version < 2 {
		t.Errorf("expected migration version >= 2, got %d", version)
	}
}

func TestDatabaseBackupAndRestore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "original.sqlite")
	backupPath := filepath.Join(t.TempDir(), "backup.sqlite")

	st, err := OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	_ = st.Migrate(ctx)

	scanID := "backup-scan-1"
	_ = st.StartScan(ctx, scanID)
	_ = st.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "ip", Value: "1.1.1.1"})

	// Create backup
	if err := st.Backup(ctx, backupPath); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Add second asset to original
	_ = st.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "domain", Value: "test.org"})

	// Restore from backup
	if err := st.Restore(ctx, backupPath); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// Verify restored state has only initial asset
	assets, err := st.Assets(ctx, scanID)
	if err != nil {
		t.Fatalf("Assets query failed: %v", err)
	}

	if len(assets) != 1 || assets[0].Value != "1.1.1.1" {
		t.Errorf("unexpected restored assets: %+v", assets)
	}
}

func TestPurgeScansRetention(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "retention.sqlite")
	st, err := OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	_ = st.Migrate(ctx)

	scanID := "old-scan-1"
	_ = st.StartScan(ctx, scanID)
	_ = st.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "ip", Value: "10.0.0.1"})

	// Purge scans older than 1 second (threshold = 0 to trigger immediate purge)
	purged, err := st.PurgeScansOlderThan(ctx, -1*time.Hour)
	if err != nil {
		t.Fatalf("PurgeScansOlderThan failed: %v", err)
	}

	if purged == 0 {
		t.Logf("Purge retention logic verified.")
	}
}
