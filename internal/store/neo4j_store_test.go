package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"enumscan/internal/models"
)

func TestSyncScanToNeo4jTransfersPersistedEvidence(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if r.Method != http.MethodPost || !ok || user != "neo4j" || password != "test-password" {
			t.Fatalf("unexpected Neo4j request: %s %q %t", r.Method, user, ok)
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[],"errors":[]}`))
	}))
	defer server.Close()
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "neo4j.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAsset(ctx, models.Asset{ScanID: "neo-scan", Type: "host", Value: "example.test"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddFinding(ctx, models.Finding{ScanID: "neo-scan", Severity: "high", Asset: "example.test:443", Title: "Observed concern"}); err != nil {
		t.Fatal(err)
	}
	count, err := SyncScanToNeo4j(ctx, db, NewNeo4jStore(server.URL, "neo4j", "test-password"), "neo-scan")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || requests.Load() != 2 {
		t.Fatalf("expected two persisted records to sync, got count=%d requests=%d", count, requests.Load())
	}
}

func TestLoadScanGraphUsesFixedRows(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "MATCH (a:Asset") {
			t.Fatalf("expected fixed graph query, got %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"data":[{"row":["host-a","host","HAS_FINDING","finding-a","Finding"]}]}],"errors":[]}`))
	}))
	defer server.Close()
	graph, err := NewNeo4jStore(server.URL, "", "").LoadScanGraph(context.Background(), "scan-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Nodes) != 2 || len(graph.Edges) != 1 || graph.Edges[0].Relation != "HAS_FINDING" {
		t.Fatalf("unexpected graph: %#v", graph)
	}
}
