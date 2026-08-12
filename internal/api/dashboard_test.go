package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestOperatorDashboardAPIs(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "operator.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const scanID = "operator-scan"
	if err := db.StartScan(ctx, scanID); err != nil {
		t.Fatal(err)
	}
	_ = db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "host", Value: "app.example.test"})
	_ = db.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: "high", Confidence: "high", Asset: "app.example.test", Title: "Example finding"})
	_, _ = db.AddEvent(ctx, models.Event{ScanID: scanID, Type: "host.discovered", Target: "app.example.test"})

	srv := NewServer(db, 0)
	for _, path := range []string{"/", "/api/v1/events?scan_id=" + scanID, "/api/v1/graph?scan_id=" + scanID, "/api/v1/search?scan_id=" + scanID + "&q=example"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		switch {
		case path == "/":
			srv.handleDashboard(response, request)
		case strings.Contains(path, "/events"):
			srv.handleEvents(response, request)
		case strings.Contains(path, "/graph"):
			srv.handleGraph(response, request)
		default:
			srv.handleSearch(response, request)
		}
		if response.Code != http.StatusOK {
			t.Fatalf("%s returned %d: %s", path, response.Code, response.Body.String())
		}
		if path == "/" {
			for _, endpoint := range []string{"/api/v1/assets", "/api/v1/findings", "/api/v1/events", "/api/v1/graph", "/api/v1/screenshots", "/api/v1/scans/run", "/api/v1/saved-queries", "/api/v1/events/ws", "id=\"target\"", "192.168.56.0/24", "asList"} {
				if !strings.Contains(response.Body.String(), endpoint) {
					t.Errorf("dashboard template is missing live endpoint wiring for %s", endpoint)
				}
			}
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/saved-queries", strings.NewReader(`{"name":"example assets","query":"example"}`))
	response := httptest.NewRecorder()
	srv.handleSavedQueries(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("save query returned %d: %s", response.Code, response.Body.String())
	}
	queries, err := db.SavedQueries(ctx)
	if err != nil || len(queries) != 1 || queries[0].Name != "example assets" {
		t.Fatalf("unexpected saved queries: %#v, %v", queries, err)
	}
}
