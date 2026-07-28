package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/reporting"
	"enumscan/internal/scheduler"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestPostgresAndNeo4jStoreInit(t *testing.T) {
	pg := store.NewPostgresStore("postgres://user:pass@localhost:5432/enumscan")
	if err := pg.Migrate(context.Background()); err != nil {
		t.Fatalf("pg.Migrate: %v", err)
	}

	neo := store.NewNeo4jStore("bolt://localhost:7687", "neo4j", "password")
	if err := neo.SyncAsset(context.Background(), models.Asset{ScanID: "test", Type: "host", Value: "127.0.0.1"}); err != nil {
		t.Fatalf("neo.SyncAsset: %v", err)
	}
}

func TestScopeInheritance(t *testing.T) {
	guard := scope.New([]string{"example.com", "10.0.0.0/24", "192.168.1.10"})

	// Inherited subdomains
	if !guard.Allowed("sub.example.com") {
		t.Errorf("expected sub.example.com allowed via domain scope inheritance")
	}
	if !guard.Allowed("http://api.sub.example.com:8080/v1/users") {
		t.Errorf("expected URL allowed via domain scope inheritance")
	}

	// Inherited CIDR host and port
	if !guard.Allowed("10.0.0.45:22") {
		t.Errorf("expected 10.0.0.45:22 allowed via CIDR scope inheritance")
	}

	// Out of scope
	if guard.Allowed("google.com") {
		t.Errorf("expected google.com denied")
	}
	if guard.Allowed("172.16.0.1") {
		t.Errorf("expected 172.16.0.1 denied")
	}
}

func TestCronScheduler(t *testing.T) {
	cs := scheduler.NewCronScheduler()
	executed := make(chan bool, 1)

	cs.AddRecurringScan("task-1", "quick", "127.0.0.1", 10*time.Millisecond, func(ctx context.Context, task scheduler.ScheduledTask) error {
		executed <- true
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cs.Start(ctx)

	select {
	case <-executed:
		// Success
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected recurring scan task execution")
	}
	cs.Stop()
}

func TestHTMLAndPDFReporting(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	scanID := "scan-reports"
	_ = db.AddAsset(context.Background(), models.Asset{ScanID: scanID, Type: "host", Value: "127.0.0.1"})
	_ = db.AddFinding(context.Background(), models.Finding{ScanID: scanID, Severity: "high", Confidence: "high", Asset: "127.0.0.1:80", Title: "<script>alert(1)</script>"})

	htmlPath, err := reporting.Write(context.Background(), db, scanID, "html", t.TempDir())
	if err != nil || htmlPath == "" {
		t.Fatalf("Write HTML report failed: %v", err)
	}

	pdfPath, err := reporting.Write(context.Background(), db, scanID, "pdf", t.TempDir())
	if err != nil || pdfPath == "" {
		t.Fatalf("Write PDF report failed: %v", err)
	}
}

func TestAPIServer(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	scanID := "scan-api"
	_ = db.AddAsset(context.Background(), models.Asset{ScanID: scanID, Type: "host", Value: "10.0.0.1"})
	_ = db.AddFinding(context.Background(), models.Finding{ScanID: scanID, Severity: "critical", Confidence: "high", Asset: "10.0.0.1:22", Title: "SSH RCE"})

	srv := NewServer(db, 8089)
	srv.SetAPIKey("secret-token-123")

	// Test REST Health Endpoint (Unauthenticated)
	reqHealth := httptest.NewRequest("GET", "/api/v1/health", nil)
	wHealth := httptest.NewRecorder()
	srv.authMiddleware(http.HandlerFunc(srv.handleHealth)).ServeHTTP(wHealth, reqHealth)

	if wHealth.Code != 200 {
		t.Errorf("expected HTTP 200 for health endpoint, got %d", wHealth.Code)
	}

	// Test Unauthorized Endpoint
	reqScansUnauth := httptest.NewRequest("GET", "/api/v1/scans?scan_id="+scanID, nil)
	wScansUnauth := httptest.NewRecorder()
	srv.authMiddleware(http.HandlerFunc(srv.handleScans)).ServeHTTP(wScansUnauth, reqScansUnauth)

	if wScansUnauth.Code != 401 {
		t.Errorf("expected HTTP 401 for unauthorized scan request, got %d", wScansUnauth.Code)
	}

	// Test Authorized Endpoint
	reqScansAuth := httptest.NewRequest("GET", "/api/v1/scans?scan_id="+scanID, nil)
	reqScansAuth.Header.Set("X-API-Key", "secret-token-123")
	wScansAuth := httptest.NewRecorder()
	srv.authMiddleware(http.HandlerFunc(srv.handleScans)).ServeHTTP(wScansAuth, reqScansAuth)

	if wScansAuth.Code != 200 {
		t.Errorf("expected HTTP 200 for authorized scan request, got %d", wScansAuth.Code)
	}

	// Test GraphQL Handler
	reqGQL := httptest.NewRequest("POST", "/query?scan_id="+scanID, strings.NewReader(`{"query":"query { findings { title } assets { value } }"}`))
	wGQL := httptest.NewRecorder()
	srv.handleGraphQL(wGQL, reqGQL)

	if wGQL.Code != 200 || !strings.Contains(wGQL.Body.String(), "findingsCount") {
		t.Errorf("unexpected GraphQL response: %s", wGQL.Body.String())
	}

	srv.BroadcastEvent(models.Event{ScanID: scanID, Type: "test.event", Target: "10.0.0.1"})
}
