package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/html"
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
	if !strings.Contains(body, "New authorized engagement") || !strings.Contains(body, "/api/v1/engagement/plan") {
		t.Fatalf("expected downloadable scope-locked engagement wizard wiring")
	}
	document, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var inspect func(*html.Node)
	inspect = func(node *html.Node) {
		if node.Type == html.ElementNode && (node.Data == "script" || node.Data == "link") {
			for _, attr := range node.Attr {
				if (attr.Key == "src" || attr.Key == "href") && strings.HasPrefix(attr.Val, "http") {
					t.Errorf("dashboard has external runtime asset %q", attr.Val)
				}
				if node.Data == "script" && attr.Key == "type" && attr.Val == "text/babel" {
					t.Error("dashboard still uses in-browser Babel")
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			inspect(child)
		}
	}
	inspect(document)
	for _, marker := range []string{
		"Skip to main content", "aria-live", "Scanner console", "prefers-reduced-motion", "main-content",
		"save-query-title", "aria-modal", "Select knowledge graph node", "Evidence connection unavailable",
		"Refine the filter to narrow results", "Showing the first",
		"max-width: 1180px", "min-width: 700px",
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("dashboard accessibility marker missing: %s", marker)
		}
	}
}

func TestDashboardSecurityPolicyIsOfflineAndDisallowsEval(t *testing.T) {
	srv := NewServer(nil, 0)
	handler := srv.securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	policy := recorder.Header().Get("Content-Security-Policy")
	if strings.Contains(policy, "https:") || strings.Contains(policy, "unsafe-eval") || !strings.Contains(policy, "object-src 'none'") || !strings.Contains(policy, "frame-ancestors 'none'") {
		t.Fatalf("unexpected dashboard CSP: %s", policy)
	}
}

func TestDashboardHighVolumeRenderingAndAccessibility(t *testing.T) {
	srv := NewServer(nil, 0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	rec := httptest.NewRecorder()
	srv.handleDashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	body := rec.Body.String()

	// High-volume and accessibility markers verification
	expectedAttributes := []string{
		"role",
		"dialog",
		"aria-modal",
		"aria-live",
		"region",
		"navigation",
		"status",
		"prefers-reduced-motion",
		"Skip to main content",
		"Showing the first",
		"Refine the filter to narrow results",
	}
	for _, attr := range expectedAttributes {
		if !strings.Contains(body, attr) {
			t.Errorf("dashboard missing expected UX/a11y attribute: %s", attr)
		}
	}
}

