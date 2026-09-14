package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/config"
)

func TestEngagementPlanRendersScopeLockedSafeConfig(t *testing.T) {
	srv := NewServer(nil, 0)
	body := bytes.NewBufferString(`{"target":"192.168.56.0/24","profile":"standard","authorization":"ENG-2026-004"}`)
	recorder := httptest.NewRecorder()
	srv.handleEngagementPlan(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/engagement/plan", body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected plan, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(response["config"], `allowed_targets: ["192.168.56.0/24"]`) || !strings.Contains(response["config"], "active_testing:") || !strings.Contains(response["config"], "enabled: false") {
		t.Fatalf("expected scope-locked, safe YAML, got %s", response["config"])
	}
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	if err := os.WriteFile(path, []byte(response["config"]), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("generated config must load: %v", err)
	}
}

func TestEngagementPlanRequiresAdminWhenDashboardAuthIsEnabled(t *testing.T) {
	srv := NewServer(nil, 0)
	cfg := config.Default()
	cfg.API.RequireAuth = true
	srv.SetConfig(cfg)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagement/plan", strings.NewReader(`{"target":"127.0.0.1","authorization":"ENG-1"}`))
	req = req.WithContext(context.WithValue(req.Context(), apiPrincipalContextKey{}, apiPrincipal{role: "analyst"}))
	recorder := httptest.NewRecorder()
	srv.handleEngagementPlan(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected admin restriction, got %d: %s", recorder.Code, recorder.Body.String())
	}
}
