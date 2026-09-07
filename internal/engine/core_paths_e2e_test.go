package engine

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/config"
	"enumscan/internal/models"
	"enumscan/internal/store"
)

// TestCoreDiscoveryPortAndHTTPPath verifies the actual event hand-off used by
// an authorized scan: target -> host -> open port -> HTTP URL -> HTTP evidence.
// Port 8080 is an existing HTTP hand-off port; skip rather than testing another
// process when a developer already has it in use.
func TestCoreDiscoveryPortAndHTTPPath(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skipf("127.0.0.1:8080 unavailable for integration fixture: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "enumscan-fixture")
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="fixture"></head><body>enumscan HTTP fixture</body></html>`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "core-paths.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Scope.AllowedTargets = []string{"127.0.0.1"}
	cfg.Scope.Authorization = "TEST-AUTHORIZED-LOCAL-FIXTURE"
	cfg.Scan.Targets = []string{"127.0.0.1"}
	cfg.Scheduler.Concurrency = 1
	cfg.Scheduler.GlobalRateLimitMS = 0
	cfg.Scheduler.PerTargetRateLimitMS = 0
	cfg.Scheduler.ModuleTimeoutMS = 3000
	cfg.Discovery.EnableTCPHostProbes = true
	cfg.Discovery.TCPProbePorts = []int{8080}
	cfg.PortScan = models.PortScanConfig{
		Profile: "test", TCPPorts: []int{8080}, EnableTCP: true,
		MaxConcurrentPorts: 1, BaseTimeoutMS: 500, MaxTimeoutMS: 1000,
	}
	cfg.HTTP = models.HTTPConfig{MaxPagesPerHost: 1}

	const scanID = "core-discovery-port-http"
	if err := New(cfg, db).Run(ctx, scanID); err != nil {
		t.Fatalf("core scan path failed: %v", err)
	}
	assets, err := db.Assets(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := db.Events(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	assertAssetType(t, assets, "target")
	assertAssetType(t, assets, "live_host")
	assertAssetType(t, assets, "open_port")
	assertAssetValue(t, assets, "url", "http://127.0.0.1:8080")
	assertEventType(t, events, "host.discovered")
	assertEventType(t, events, "port.open")
	assertEventType(t, events, "http.url")
	findings, err := db.Findings(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingTitle(t, findings, "Overly Permissive CORS Policy")
}

func assertAssetType(t *testing.T, assets []models.Asset, want string) {
	t.Helper()
	for _, asset := range assets {
		if asset.Type == want {
			return
		}
	}
	t.Fatalf("missing asset type %q in %#v", want, assets)
}

func assertAssetValue(t *testing.T, assets []models.Asset, typ, value string) {
	t.Helper()
	for _, asset := range assets {
		if asset.Type == typ && asset.Value == value {
			return
		}
	}
	t.Fatalf("missing %s asset %q in %#v", typ, value, assets)
}

func assertEventType(t *testing.T, events []models.Event, want string) {
	t.Helper()
	for _, event := range events {
		if event.Type == want {
			return
		}
	}
	t.Fatalf("missing event type %q in %#v", want, events)
}

func assertFindingTitle(t *testing.T, findings []models.Finding, want string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Title == want {
			return
		}
	}
	t.Fatalf("missing finding %q in %#v", want, findings)
}
