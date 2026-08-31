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

func TestTask31BackendImprovements(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.sqlite")
	cli, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	if err := cli.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	srv := NewServer(cli, 8086)
	srv.SetAPIKey("test-api-key")

	// 1. Test Auth Token Issuance Endpoint
	tokReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token?role=analyst", nil)
	tokW := httptest.NewRecorder()
	srv.handleAuthToken(tokW, tokReq)
	if tokW.Code != http.StatusOK || !strings.Contains(tokW.Body.String(), "enumscan-token-") {
		t.Fatalf("handleAuthToken failed: %d, body: %s", tokW.Code, tokW.Body.String())
	}

	// 2. Test RBAC Restriction (Viewer role forbidden on POST)
	runReq := httptest.NewRequest(http.MethodPost, "/api/v1/scans/run", strings.NewReader(`{"target":"127.0.0.1"}`))
	runReq.Header.Set("X-API-Key", "test-api-key")
	runReq.Header.Set("X-User-Role", "viewer")
	runW := httptest.NewRecorder()
	srv.rbacMiddleware(http.HandlerFunc(srv.handleRunScan)).ServeHTTP(runW, runReq)

	if runW.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for viewer on POST, got %d", runW.Code)
	}

	// 3. Test GraphQL Mutations
	mutReq := httptest.NewRequest(http.MethodPost, "/query", strings.NewReader(`{"query":"mutation { runScan(target: \"10.0.0.1\") { scanID status } }"}`))
	mutW := httptest.NewRecorder()
	srv.handleGraphQL(mutW, mutReq)

	if mutW.Code != http.StatusOK || !strings.Contains(mutW.Body.String(), "runScan") {
		t.Fatalf("GraphQL mutation failed: %d, body: %s", mutW.Code, mutW.Body.String())
	}
}
