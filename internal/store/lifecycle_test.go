package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestDataLifecycleAndLegalHoldControls(t *testing.T) {
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "lifecycle.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// 1. Create three scans
	oldScanExpired := "scan-old-expired"
	oldScanHeld := "scan-old-legal-hold"
	newScan := "scan-recent"

	for _, s := range []string{oldScanExpired, oldScanHeld, newScan} {
		if err := db.StartScan(ctx, s); err != nil {
			t.Fatal(err)
		}
		_ = db.AddAsset(ctx, models.Asset{ScanID: s, Type: "ip", Value: "10.0.0.1", CreatedAt: time.Now()})
		_ = db.AddFinding(ctx, models.Finding{ScanID: s, Severity: "low", Asset: "10.0.0.1", Title: "Notice", CreatedAt: time.Now()})
	}

	// Backdate the first two scans to 60 days ago
	oldTimestamp := time.Now().UTC().Add(-60 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	_, err = db.db.ExecContext(ctx, `UPDATE scan_runs SET started_at=? WHERE scan_id IN (?, ?)`, oldTimestamp, oldScanExpired, oldScanHeld)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Place legal hold on oldScanHeld
	if err := db.SetLegalHold(ctx, oldScanHeld, true, "Incident Investigation INC-2026-99", "secops-officer"); err != nil {
		t.Fatalf("failed to set legal hold: %v", err)
	}

	isHeld, err := db.IsLegalHoldActive(ctx, oldScanHeld)
	if err != nil || !isHeld {
		t.Fatalf("expected legal hold to be active: %v", err)
	}

	isHeldExpired, _ := db.IsLegalHoldActive(ctx, oldScanExpired)
	if isHeldExpired {
		t.Fatal("expected oldScanExpired to NOT be on legal hold")
	}

	// 3. Execute lifecycle purge with 30-day threshold, MinScansKeep=1
	policy := RetentionPolicy{
		ProjectID:    "corp-project",
		MaxAge:       30 * 24 * time.Hour,
		MinScansKeep: 1,
	}

	auditEntry, err := db.PurgeScansWithLifecycle(ctx, policy, "automated-lifecycle-job")
	if err != nil {
		t.Fatalf("purge failed: %v", err)
	}

	// Expect exactly 1 scan purged (oldScanExpired)
	// oldScanHeld should NOT be purged because of the active legal hold!
	if auditEntry.ScansPurged != 1 {
		t.Fatalf("expected exactly 1 scan purged, got %d", auditEntry.ScansPurged)
	}

	// 4. Verify scan statuses in DB
	runs, err := db.ScanRuns(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}

	foundExpired := false
	foundHeld := false
	foundNew := false
	for _, r := range runs {
		if r.ScanID == oldScanExpired {
			foundExpired = true
		}
		if r.ScanID == oldScanHeld {
			foundHeld = true
		}
		if r.ScanID == newScan {
			foundNew = true
		}
	}

	if foundExpired {
		t.Fatal("expected expired scan to be purged")
	}
	if !foundHeld {
		t.Fatal("expected legal held scan to be PRESERVED despite being older than cutoff")
	}
	if !foundNew {
		t.Fatal("expected recent scan to be PRESERVED")
	}

	// 5. Verify Purge Audit History
	history, err := db.PurgeAuditHistory(ctx, 10)
	if err != nil || len(history) == 0 {
		t.Fatalf("failed to retrieve purge audit history: %v", err)
	}
	if history[0].ScansPurged != 1 || history[0].Operator != "automated-lifecycle-job" {
		t.Fatalf("unexpected audit entry: %#v", history[0])
	}
}
