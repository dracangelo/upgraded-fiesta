package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardHTMLRendering(t *testing.T) {
	srv := NewServer(nil, 0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	rec := httptest.NewRecorder()

	srv.handleDashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 from dashboard, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Recon OS — Enumeration Console") {
		t.Fatalf("expected body to contain title")
	}

	if !strings.Contains(body, "id=\"target\"") {
		t.Fatalf("expected body to contain target input ID")
	}

	if !strings.Contains(body, "Knowledge Graph Explorer") {
		t.Fatalf("expected body to contain Knowledge Graph Explorer")
	}

	if !strings.Contains(body, "Verified Screenshot Gallery") {
		t.Fatalf("expected body to contain verified screenshot gallery")
	}

	if !strings.Contains(body, "Integration Readiness") || !strings.Contains(body, "/api/v1/integrations") {
		t.Fatalf("expected body to contain integration readiness view")
	}
	if !strings.Contains(body, "/api/v1/findings/stream") {
		t.Fatalf("expected dashboard live finding stream wiring")
	}
	if !strings.Contains(body, "queue_eta_seconds") || !strings.Contains(body, "Current queue ETA") {
		t.Fatalf("expected evidence-based queue ETA wiring")
	}
	if !strings.Contains(body, "Neo4j Graph") || !strings.Contains(body, "/api/v1/neo4j/graph") {
		t.Fatalf("expected read-only Neo4j graph view wiring")
	}
}
