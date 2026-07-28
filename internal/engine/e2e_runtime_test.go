package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/config"
	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestEndToEndRuntimeScanWithFixtures(t *testing.T) {
	// 1. Setup local HTTP test server fixture
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h1>Fixture Index Page</h1></body></html>"))
	}))
	defer httpServer.Close()

	// 2. Setup local TCP listener fixture
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

	httpAddr := httpServer.Listener.Addr().String()

	// 3. Setup SQLite database store
	dbPath := filepath.Join(t.TempDir(), "e2e_scan.sqlite")
	db, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// 4. Configure engine with local fixtures
	cfg := config.Default()
	cfg.Database.Path = dbPath
	cfg.Scan.Targets = []string{"127.0.0.1"}
	cfg.Scope.AllowedTargets = []string{"127.0.0.1", "localhost", httpAddr}
	cfg.Scheduler.Concurrency = 4

	eng := New(cfg, db)

	scanID := "e2e-scan-001"

	// 5. Add initial test events and assets into store
	_ = db.AddAsset(ctx, models.Asset{
		ScanID: scanID,
		Type:   "ip",
		Value:  "127.0.0.1",
	})

	// 6. Execute Engine Run
	if err := eng.Run(ctx, scanID); err != nil {
		t.Fatalf("Engine Run failed: %v", err)
	}

	// Finish scan lifecycle
	if err := db.FinishScan(ctx, scanID, "completed", ""); err != nil {
		t.Fatalf("FinishScan failed: %v", err)
	}

	// 7. Assert scan status and persisted data
	status, err := db.GetScanStatus(ctx, scanID)
	if err != nil {
		t.Fatalf("GetScanStatus failed: %v", err)
	}

	if status != "completed" {
		t.Errorf("expected scan status 'completed', got %q", status)
	}

	assets, err := db.Assets(ctx, scanID)
	if err != nil {
		t.Fatalf("Assets query failed: %v", err)
	}

	if len(assets) == 0 {
		t.Errorf("expected assets to be persisted during e2e scan, got 0")
	}

	fmt.Printf("E2E Scan Completed Successfully: %d assets recorded in database.\n", len(assets))
}
