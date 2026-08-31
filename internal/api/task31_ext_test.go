package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"enumscan/internal/store"
)

func TestTask31FrontendAndGraphEndpoints(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.sqlite")
	cli, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	if err := cli.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	srv := NewServer(cli, 8085)

	// 1. Test Dashboard HTML Endpoint
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Dashboard endpoint failed")
	}

	// 2. Test Multi-Graph Types & Neo4j Export
	graphTypes := []string{"attack_surface", "attack_path", "technology", "asset_relationship", "certificate", "cloud_relationship"}
	for _, gType := range graphTypes {
		gReq := httptest.NewRequest(http.MethodGet, "/api/v1/graph?scan_id=default&type="+gType, nil)
		gW := httptest.NewRecorder()
		srv.handleGraph(gW, gReq)
		if gW.Code != http.StatusOK {
			t.Fatalf("graph type %s failed: %d", gType, gW.Code)
		}
	}

	// Neo4j Format Test
	neoReq := httptest.NewRequest(http.MethodGet, "/api/v1/graph?scan_id=default&format=neo4j", nil)
	neoW := httptest.NewRecorder()
	srv.handleGraph(neoW, neoReq)
	if neoW.Code != http.StatusOK {
		t.Fatalf("neo4j graph export failed: %d", neoW.Code)
	}

	// 3. Test GraphQL endpoint
	gqlReq := httptest.NewRequest(http.MethodGet, "/query?query={scans{id,status}}", nil)
	gqlW := httptest.NewRecorder()
	srv.handleGraphQL(gqlW, gqlReq)
	if gqlW.Code != http.StatusOK {
		t.Fatalf("graphql endpoint failed: %d", gqlW.Code)
	}
}
