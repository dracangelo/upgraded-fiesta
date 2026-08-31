package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/store"
)

func TestReactDashboardEndpoint(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.sqlite")
	cli, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	if err := cli.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	srv := NewServer(cli, 8087)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "ReactDOM.createRoot") || !strings.Contains(body, "App") {
		t.Fatalf("dashboard response does not contain React bundle: %s", body)
	}
}
