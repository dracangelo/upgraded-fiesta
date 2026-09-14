package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestInteractiveGraphEndpoints(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "graph_api.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	ctx := context.Background()
	_ = db.Migrate(ctx)

	scanID := "scan-interactive-1"

	// Seed connected assets
	_ = db.AddAsset(ctx, models.Asset{
		ScanID:    scanID,
		Type:      "domain",
		Value:     "api.example.internal",
		CreatedAt: time.Now(),
	})
	_ = db.AddAsset(ctx, models.Asset{
		ScanID:    scanID,
		Type:      "ipv4",
		Value:     "10.0.0.8",
		Parent:    "api.example.internal",
		CreatedAt: time.Now(),
	})
	_ = db.AddAsset(ctx, models.Asset{
		ScanID:    scanID,
		Type:      "port",
		Value:     "10.0.0.8:443",
		Parent:    "10.0.0.8",
		CreatedAt: time.Now(),
	})
	_ = db.AddFinding(ctx, models.Finding{
		ScanID:      scanID,
		Title:       "TLS 1.0 Enabled",
		Severity:    "medium",
		Asset:       "10.0.0.8:443",
		Evidence:    "TLS 1.0 handshake accepted",
		Remediation: "Disable TLS 1.0",
		CreatedAt:   time.Now(),
	})

	server := NewServer(db, 0)

	// 1. Test /api/v1/graph/interactive with search filter
	reqFilter := httptest.NewRequest(http.MethodGet, "/api/v1/graph/interactive?scan_id="+scanID+"&query=example.internal", nil)
	recFilter := httptest.NewRecorder()
	server.handleInteractiveGraph(recFilter, reqFilter)

	if recFilter.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from interactive graph, got: %d", recFilter.Code)
	}

	var filterResp struct {
		Nodes []models.GraphNode `json:"nodes"`
		Edges []models.GraphEdge `json:"edges"`
	}
	if err := json.NewDecoder(recFilter.Body).Decode(&filterResp); err != nil {
		t.Fatalf("decode interactive response failed: %v", err)
	}
	if len(filterResp.Nodes) == 0 {
		t.Errorf("expected filtered nodes, got 0")
	}

	// 2. Test /api/v1/graph/expand
	targetNodeID := "api.example.internal"
	reqExpand := httptest.NewRequest(http.MethodGet, "/api/v1/graph/expand?scan_id="+scanID+"&node_id="+targetNodeID+"&depth=2", nil)
	recExpand := httptest.NewRecorder()
	server.handleGraphExpand(recExpand, reqExpand)

	if recExpand.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from graph expand, got: %d", recExpand.Code)
	}

	var expandResp struct {
		OriginNode string             `json:"origin_node"`
		Depth      int                `json:"depth"`
		Nodes      []models.GraphNode `json:"nodes"`
		Edges      []models.GraphEdge `json:"edges"`
	}
	if err := json.NewDecoder(recExpand.Body).Decode(&expandResp); err != nil {
		t.Fatalf("decode expand response failed: %v", err)
	}

	if expandResp.OriginNode != targetNodeID {
		t.Errorf("expected origin node %s, got %s", targetNodeID, expandResp.OriginNode)
	}
	if len(expandResp.Nodes) < 2 {
		t.Errorf("expected expanded neighbors, got %d nodes", len(expandResp.Nodes))
	}
}
