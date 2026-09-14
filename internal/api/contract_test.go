package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAPIContractSpecEndpoint(t *testing.T) {
	srv := NewServer(nil, 0)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/openapi.json", srv.handleOpenAPISpec)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK from openapi endpoint, got %d", rec.Code)
	}

	var spec map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		t.Fatalf("failed to parse openapi json: %v", err)
	}

	// 1. Verify OpenAPI version & Info
	if spec["openapi"] != "3.0.3" {
		t.Errorf("expected openapi version 3.0.3, got %v", spec["openapi"])
	}
	info, ok := spec["info"].(map[string]any)
	if !ok || info["title"] != "Enumscan API" || info["version"] != "v1" {
		t.Fatalf("unexpected openapi info object: %#v", info)
	}

	// 2. Verify registered Paths
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("missing paths in openapi spec")
	}

	requiredPaths := []string{
		"/api/v1/health",
		"/api/v1/capabilities",
		"/api/v1/engagement/plan",
		"/api/v1/scans",
		"/api/v1/assets",
		"/api/v1/findings",
		"/api/v1/metrics",
		"/api/v1/identity/organizations",
		"/api/v1/openapi.json",
	}

	for _, p := range requiredPaths {
		if _, exists := paths[p]; !exists {
			t.Errorf("expected path %s in openapi spec, but not found", p)
		}
	}

	// 3. Verify Components & Schemas
	components, ok := spec["components"].(map[string]any)
	if !ok {
		t.Fatal("missing components in openapi spec")
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		t.Fatal("missing schemas in openapi components")
	}

	requiredSchemas := []string{"ScanRun", "Asset", "Finding", "Organization"}
	for _, s := range requiredSchemas {
		if _, exists := schemas[s]; !exists {
			t.Errorf("expected schema %s in components.schemas, but not found", s)
		}
	}
}
