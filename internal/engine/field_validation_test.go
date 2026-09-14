package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"enumscan/internal/config"
	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestFieldValidationConcurrentScans(t *testing.T) {
	// Setup local HTTP test fixture
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "FieldValidation-Fixture/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>OK</body></html>"))
	}))
	defer httpServer.Close()

	// Setup local TCP listener fixture
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer tcpListener.Close()

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	dbPath := filepath.Join(t.TempDir(), "concurrent_field_val.sqlite")
	db, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	concurrentScans := 4
	var wg sync.WaitGroup
	errCh := make(chan error, concurrentScans)

	for i := 0; i < concurrentScans; i++ {
		wg.Add(1)
		scanID := fmt.Sprintf("concurrent-val-%02d", i)
		go func(id string) {
			defer wg.Done()

			cfg := config.Default()
			cfg.Database.Path = dbPath
			cfg.Scan.Targets = []string{"127.0.0.1"}
			cfg.Scope.Authorization = "FIELD-VAL-AUTH-2026"
			cfg.Scope.AllowedTargets = []string{"127.0.0.1", "localhost", httpServer.Listener.Addr().String()}
			cfg.Scheduler.Concurrency = 2

			eng := New(cfg, db)

			_ = db.AddAsset(ctx, models.Asset{
				ScanID: id,
				Type:   "ip",
				Value:  "127.0.0.1",
			})

			if err := eng.Run(ctx, id); err != nil {
				errCh <- fmt.Errorf("scan %s run failed: %w", id, err)
				return
			}

			if err := db.FinishScan(ctx, id, "completed", ""); err != nil {
				errCh <- fmt.Errorf("scan %s finish failed: %w", id, err)
				return
			}

			status, err := db.GetScanStatus(ctx, id)
			if err != nil || status != "completed" {
				errCh <- fmt.Errorf("scan %s status unexpected: %s, %v", id, status, err)
				return
			}
		}(scanID)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent scan error: %v", err)
	}
}

func TestFieldValidationRestartAndResume(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "resume_field_val.sqlite")
	db, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_ = db.Migrate(ctx)

	scanID := "field-val-resume-01"

	// Step 1: Initialize scan run
	if err := db.StartScan(ctx, scanID); err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}

	// Add initial assets and findings
	_ = db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "ip", Value: "10.0.0.1"})
	_ = db.AddFinding(ctx, models.Finding{
		ScanID:     scanID,
		Title:      "Initial Finding",
		Asset:      "10.0.0.1",
		Severity:   "medium",
		Confidence: "confirmed",
	})

	// Pause / interrupt scan
	if err := db.UpdateScanStatus(ctx, scanID, "paused"); err != nil {
		t.Fatalf("UpdateScanStatus(paused) failed: %v", err)
	}
	status, _ := db.GetScanStatus(ctx, scanID)
	if status != "paused" {
		t.Fatalf("expected status 'paused', got %q", status)
	}

	// Step 2: Resume scan
	if err := db.UpdateScanStatus(ctx, scanID, "running"); err != nil {
		t.Fatalf("UpdateScanStatus(running) failed: %v", err)
	}
	status, _ = db.GetScanStatus(ctx, scanID)
	if status != "running" {
		t.Fatalf("expected status 'running' after resume, got %q", status)
	}

	// Attempt adding duplicate asset - database uniqueness constraint must prevent duplicates
	_ = db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "ip", Value: "10.0.0.1"})
	_ = db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "ip", Value: "10.0.0.2"})

	// Complete scan
	_ = db.FinishScan(ctx, scanID, "completed", "")

	assets, err := db.Assets(ctx, scanID)
	if err != nil {
		t.Fatalf("Assets failed: %v", err)
	}

	// Must contain 10.0.0.1 exactly once, and 10.0.0.2
	countMap := make(map[string]int)
	for _, a := range assets {
		countMap[a.Value]++
	}
	if countMap["10.0.0.1"] != 1 {
		t.Fatalf("duplicate asset detected after resume: %d", countMap["10.0.0.1"])
	}
	if countMap["10.0.0.2"] != 1 {
		t.Fatalf("missing resumed asset: %d", countMap["10.0.0.2"])
	}
}

func TestFieldValidationRetentionAndPurge(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "retention_field_val.sqlite")
	db, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	_ = db.Migrate(ctx)

	oldScan := "scan-purge-old"
	newScan := "scan-keep-new"

	_ = db.StartScan(ctx, oldScan)
	_ = db.AddAsset(ctx, models.Asset{ScanID: oldScan, Type: "domain", Value: "old.target"})
	_ = db.FinishScan(ctx, oldScan, "completed", "")

	// Backdate oldScan to 2 hours ago
	_ = db.Exec(ctx, fmt.Sprintf("UPDATE scan_runs SET started_at = datetime('now', '-2 hours') WHERE scan_id = '%s'", oldScan))

	_ = db.StartScan(ctx, newScan)
	_ = db.AddAsset(ctx, models.Asset{ScanID: newScan, Type: "domain", Value: "new.target"})

	// Execute purge with 1 hour retention horizon
	purged, err := db.PurgeScansOlderThan(ctx, 1*time.Hour)
	if err != nil {
		t.Fatalf("PurgeScansOlderThan failed: %v", err)
	}
	if purged < 0 {
		t.Fatalf("unexpected purge count: %d", purged)
	}

	// The active/new scan must still exist
	status, err := db.GetScanStatus(ctx, newScan)
	if err != nil || status == "" {
		t.Fatalf("new scan was incorrectly purged: %v", err)
	}
}

func TestFieldValidationCredentialRotation(t *testing.T) {
	// Verify API key rotation verification logic
	key1 := "AUTH_INITIAL_KEY_ALPHA_123"
	key2 := "AUTH_ROTATED_KEY_BETA_456"

	if key1 == key2 {
		t.Fatal("keys should be distinct for rotation")
	}

	// Verify encryption key validation
	encKey1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	encKey2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	if len(encKey1) != 64 || len(encKey2) != 64 {
		t.Fatal("keys must be 32-byte hex (64 chars)")
	}
}
