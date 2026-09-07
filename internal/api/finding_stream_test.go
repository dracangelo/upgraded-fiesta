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

func TestFindingStreamEmitsPersistedFindingsOnly(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "stream.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.AddFinding(ctx, models.Finding{ScanID: "stream-scan", Severity: "high", Title: "Persisted finding", Asset: "host:443"}); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, 0)
	rec := httptest.NewRecorder()
	srv.handleFindingStream(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings/stream?scan_id=stream-scan", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "event: finding") || !strings.Contains(rec.Body.String(), "Persisted finding") {
		t.Fatalf("unexpected SSE stream: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	srv.handleFindingStream(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings/stream", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected scan requirement, got %d", rec.Code)
	}
}
