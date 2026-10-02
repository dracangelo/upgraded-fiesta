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

func TestEngagementPlanCustomFilenameAndAllScanTypes(t *testing.T) {
	srv := NewServer(nil, 0)
	body := bytes.NewBufferString(`{"target":"10.0.0.1","profile":"all","authorization":"AUTH-ALL-01","filename":"my-custom-plan.yaml"}`)
	recorder := httptest.NewRecorder()
	srv.handleEngagementPlan(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/engagement/plan", body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected plan, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["filename"] != "my-custom-plan.yaml" {
		t.Fatalf("expected custom filename my-custom-plan.yaml, got %q", response["filename"])
	}
	if !strings.Contains(response["config"], `profile: "exhaustive"`) {
		t.Fatalf("expected all scan types to map to exhaustive profile, got: %s", response["config"])
	}

	// Test without .yaml extension
	body2 := bytes.NewBufferString(`{"target":"10.0.0.1","profile":"all_scan_types","authorization":"AUTH-ALL-02","filename":"pentest_report"}`)
	recorder2 := httptest.NewRecorder()
	srv.handleEngagementPlan(recorder2, httptest.NewRequest(http.MethodPost, "/api/v1/engagement/plan", body2))
	if recorder2.Code != http.StatusOK {
		t.Fatalf("expected plan, got %d: %s", recorder2.Code, recorder2.Body.String())
	}
	var response2 map[string]string
	if err := json.Unmarshal(recorder2.Body.Bytes(), &response2); err != nil {
		t.Fatal(err)
	}
	if response2["filename"] != "pentest_report.yaml" {
		t.Fatalf("expected pentest_report.yaml with extension appended, got %q", response2["filename"])
	}
}

