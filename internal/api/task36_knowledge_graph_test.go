package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"enumscan/internal/inventory"
	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestTask36KnowledgeGraphEndpoints(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_kg.sqlite")
	cli, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	if err := cli.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	srv := NewServer(cli, 0)
	const scanID = "kg-scan-1"
	_ = cli.StartScan(context.Background(), scanID)
	_ = cli.AddAsset(context.Background(), models.Asset{ScanID: scanID, Type: "subdomain", Value: "auth.corp.local", Parent: "corp.local"})
	_ = cli.AddAsset(context.Background(), models.Asset{ScanID: scanID, Type: "technology", Value: "OAuth2", Parent: "auth.corp.local"})
	_ = cli.AddAsset(context.Background(), models.Asset{ScanID: scanID, Type: "secret", Value: "JWT_SECRET_KEY", Parent: "auth.corp.local"})
	_ = cli.AddFinding(context.Background(), models.Finding{ScanID: scanID, Severity: "critical", Title: "JWT Secret Exposure", Asset: "auth.corp.local"})

	// 1. Test GET /api/v1/knowledge-graph
	reqKG := httptest.NewRequest(http.MethodGet, "/api/v1/knowledge-graph?scan_id="+scanID, nil)
	recKG := httptest.NewRecorder()
	srv.handleKnowledgeGraph(recKG, reqKG)
	if recKG.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from knowledge graph endpoint, got %d", recKG.Code)
	}
	var kgGraph models.AssetGraph
	if err := json.Unmarshal(recKG.Body.Bytes(), &kgGraph); err != nil {
		t.Fatalf("unmarshal knowledge graph failed: %v", err)
	}
	if len(kgGraph.Nodes) == 0 {
		t.Fatalf("expected nodes in knowledge graph, got 0")
	}

	// 2. Test POST /api/v1/knowledge-graph/query
	queryBody, _ := json.Marshal(inventory.KnowledgeGraphOptions{FilterType: "secret"})
	reqQuery := httptest.NewRequest(http.MethodPost, "/api/v1/knowledge-graph/query?scan_id="+scanID, bytes.NewReader(queryBody))
	reqQuery.Header.Set("Content-Type", "application/json")
	recQuery := httptest.NewRecorder()
	srv.handleKnowledgeGraphQuery(recQuery, reqQuery)
	if recQuery.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from knowledge graph query, got %d", recQuery.Code)
	}
	var queryGraph models.AssetGraph
	if err := json.Unmarshal(recQuery.Body.Bytes(), &queryGraph); err != nil {
		t.Fatalf("unmarshal query graph failed: %v", err)
	}
	if len(queryGraph.Nodes) == 0 {
		t.Fatalf("expected filtered nodes from graph query, got 0")
	}
}
