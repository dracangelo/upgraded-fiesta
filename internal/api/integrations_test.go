package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/modules"
)

func TestIntegrationStatusIsOfflineAndDoesNotExposeCredentials(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "must-not-appear")
	srv := NewServer(nil, 0)
	srv.SetConfig(models.Config{PassiveIntel: models.PassiveIntelConfig{Enabled: true, Sources: []string{"shodan", "bucket"}}})

	rec := httptest.NewRecorder()
	srv.handleIntegrations(rec, httptest.NewRequest(http.MethodGet, "/api/v1/integrations", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected integration status: %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "must-not-appear") {
		t.Fatalf("integration status exposed a credential: %s", rec.Body.String())
	}
	var report modules.PassiveIntelDoctorReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if len(report.Providers) != 2 || report.Providers[1].Source != "shodan" || len(report.Providers[1].Capabilities) == 0 {
		t.Fatalf("expected capability-bearing sorted diagnostics, got %#v", report.Providers)
	}

	rec = httptest.NewRecorder()
	srv.handleIntegrations(rec, httptest.NewRequest(http.MethodPost, "/api/v1/integrations", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected read-only endpoint, got %d", rec.Code)
	}
}
