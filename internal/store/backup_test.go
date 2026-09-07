package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
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

func TestEncryptedBackupRoundTripAndAuthentication(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "encrypted-original.sqlite")
	backupPath := filepath.Join(t.TempDir(), "encrypted-backup.esb")
	st, err := OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.StartScan(ctx, "encrypted-scan"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddAsset(ctx, models.Asset{ScanID: "encrypted-scan", Type: "host", Value: "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x5a}, 32)
	if err := st.BackupEncrypted(ctx, backupPath, key); err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("SQLite format 3")) || bytes.Contains(encrypted, []byte("192.0.2.10")) {
		t.Fatal("encrypted backup contains plaintext SQLite data")
	}
	if _, err := st.PurgeScansOlderThan(ctx, -time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.RestoreEncrypted(ctx, backupPath, key); err != nil {
		t.Fatal(err)
	}
	assets, err := st.Assets(ctx, "encrypted-scan")
	if err != nil || len(assets) != 1 || assets[0].Value != "192.0.2.10" {
		t.Fatalf("encrypted backup restore failed: %#v, %v", assets, err)
	}
	wrongKey := bytes.Repeat([]byte{0xa5}, 32)
	if err := st.RestoreEncrypted(ctx, backupPath, wrongKey); err == nil {
		t.Fatal("encrypted backup must reject a wrong key")
	}
}

func TestDecodeBackupKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	encoded := base64.RawStdEncoding.EncodeToString(key)
	decoded, err := DecodeBackupKey(encoded)
	if err != nil || !bytes.Equal(decoded, key) {
		t.Fatalf("decode backup key: %v, %x", err, decoded)
	}
	if _, err := DecodeBackupKey("not-a-key"); err == nil {
		t.Fatal("invalid encrypted backup key must be rejected")
	}
}
