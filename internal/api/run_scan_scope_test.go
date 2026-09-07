package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/config"
	"enumscan/internal/store"
)

func TestRunScanRejectsTargetsOutsideConfiguredAuthorizationScope(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "scan.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Scope.AllowedTargets = []string{"127.0.0.1"}
	cfg.Scope.Authorization = "TEST-APPROVED-SCOPE"
	srv := NewServer(db, 0)
	srv.SetConfig(cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/run", strings.NewReader(`{"target":"198.51.100.10"}`))
	res := httptest.NewRecorder()
	srv.handleRunScan(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("expected out-of-scope scan request to be rejected, got %d: %s", res.Code, res.Body.String())
	}
}

func TestRunScanRejectsUnknownRequestedProfile(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "scan.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Scope.AllowedTargets = []string{"127.0.0.1"}
	cfg.Scope.Authorization = "TEST-APPROVED-SCOPE"
	srv := NewServer(db, 0)
	srv.SetConfig(cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/run", strings.NewReader(`{"target":"127.0.0.1","profile":"not-real"}`))
	res := httptest.NewRecorder()
	srv.handleRunScan(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid profile to be rejected, got %d: %s", res.Code, res.Body.String())
	}
}
