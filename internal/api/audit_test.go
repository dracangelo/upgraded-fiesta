package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestMutationAuditUsesTokenFingerprintNotTokenValue(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, 0)
	srv.SetAPITokens(map[string]string{"private-token-value": "analyst"})
	handler := srv.authMiddleware(srv.auditLoggerMiddleware(srv.rbacMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/pause?scan_id=scan-a", nil)
	req.Header.Set("Authorization", "Bearer private-token-value")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	entries, err := db.RecentAPIAudit(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Role != "analyst" || entries[0].ScanID != "scan-a" || entries[0].Status != http.StatusAccepted {
		t.Fatalf("unexpected audit entries: %#v", entries)
	}
	if entries[0].Actor == "private-token-value" || entries[0].Actor == "" {
		t.Fatalf("audit actor must be a non-secret token fingerprint: %#v", entries[0])
	}
}

func TestDeniedMutationIsAuditedAfterAuthentication(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "audit-denied.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, 0)
	srv.SetAPITokens(map[string]string{"viewer-token": "viewer"})
	handler := srv.authMiddleware(srv.auditLoggerMiddleware(srv.rbacMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))))
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/findings?scan_id=scan-b", nil)
	req.Header.Set("Authorization", "Bearer viewer-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected viewer mutation denial, got %d", response.Code)
	}
	entries, err := db.RecentAPIAudit(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Status != http.StatusForbidden || entries[0].Role != "viewer" || entries[0].ScanID != "scan-b" {
		t.Fatalf("expected denied mutation audit entry, got %#v", entries)
	}
}

func TestDistributedStatusRequiresAdminWhenTokensAreConfigured(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "distributed-status.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := db.RegisterDistributedAgent(context.Background(), "agent-status", base64.RawStdEncoding.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnqueueDistributedScanJob(context.Background(), "scan-status", "AUTH-789", strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, 0)
	srv.SetAPITokens(map[string]string{"viewer-token": "viewer", "admin-token": "admin"})
	handler := srv.authMiddleware(http.HandlerFunc(srv.handleDistributedStatus))
	viewerRequest := httptest.NewRequest(http.MethodGet, "/api/v1/distributed/status", nil)
	viewerRequest.Header.Set("Authorization", "Bearer viewer-token")
	viewerResponse := httptest.NewRecorder()
	handler.ServeHTTP(viewerResponse, viewerRequest)
	if viewerResponse.Code != http.StatusForbidden {
		t.Fatalf("expected viewer denial, got %d", viewerResponse.Code)
	}
	adminRequest := httptest.NewRequest(http.MethodGet, "/api/v1/distributed/status?limit=1", nil)
	adminRequest.Header.Set("Authorization", "Bearer admin-token")
	adminResponse := httptest.NewRecorder()
	handler.ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK || !strings.Contains(adminResponse.Body.String(), "scan-status") {
		t.Fatalf("expected admin coordinator status, got %d: %s", adminResponse.Code, adminResponse.Body.String())
	}
}

func TestAdminCanReloadExternalAPITokensWithoutExposingThem(t *testing.T) {
	srv := NewServer(nil, 0)
	srv.SetAPITokens(map[string]string{"old-admin-token": "admin", "viewer-token": "viewer"})
	srv.SetAPITokenLoader(func() (map[string]string, error) {
		return map[string]string{"new-admin-token": "admin"}, nil
	})
	handler := srv.authMiddleware(srv.rbacMiddleware(http.HandlerFunc(srv.handleReloadAPITokens)))
	viewerRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reload", nil)
	viewerRequest.Header.Set("Authorization", "Bearer viewer-token")
	viewerResponse := httptest.NewRecorder()
	handler.ServeHTTP(viewerResponse, viewerRequest)
	if viewerResponse.Code != http.StatusForbidden {
		t.Fatalf("expected viewer reload denial, got %d", viewerResponse.Code)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reload", nil)
	request.Header.Set("Authorization", "Bearer old-admin-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "new-admin-token") {
		t.Fatalf("unexpected reload response %d: %s", response.Code, response.Body.String())
	}
	if _, ok := srv.principalForToken("old-admin-token"); ok {
		t.Fatal("old token must not remain valid after reload")
	}
	principal, ok := srv.principalForToken("new-admin-token")
	if !ok || principal.role != "admin" {
		t.Fatalf("new token was not applied: %#v, %t", principal, ok)
	}
}

func TestAuditEndpointRequiresAdminWhenTokensAreConfigured(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "audit-endpoint.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAPIAudit(context.Background(), models.APIAuditEntry{Actor: "api-token:abc", Role: "admin", Action: "POST /api/v1/scans/run", Status: http.StatusAccepted}); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, 0)
	srv.SetAPITokens(map[string]string{"viewer-token": "viewer", "admin-token": "admin"})
	handler := srv.authMiddleware(http.HandlerFunc(srv.handleAPIAudit))
	viewerRequest := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	viewerRequest.Header.Set("Authorization", "Bearer viewer-token")
	viewerResponse := httptest.NewRecorder()
	handler.ServeHTTP(viewerResponse, viewerRequest)
	if viewerResponse.Code != http.StatusForbidden {
		t.Fatalf("expected viewer to be denied audit access, got %d", viewerResponse.Code)
	}
	adminRequest := httptest.NewRequest(http.MethodGet, "/api/v1/audit?limit=1", nil)
	adminRequest.Header.Set("Authorization", "Bearer admin-token")
	adminResponse := httptest.NewRecorder()
	handler.ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK || !strings.Contains(adminResponse.Body.String(), "api-token:abc") {
		t.Fatalf("expected admin audit response, got %d: %s", adminResponse.Code, adminResponse.Body.String())
	}
}
