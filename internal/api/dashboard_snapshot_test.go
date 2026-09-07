package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestDashboardSnapshotContainsOnlySelectedScanEvidence(t *testing.T) {
	ctx := context.Background()
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "dashboard.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.StartScan(ctx, "selected"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAsset(ctx, models.Asset{ScanID: "selected", Type: "host", Value: "selected.example"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAsset(ctx, models.Asset{ScanID: "other", Type: "host", Value: "other.example"}); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(db, 0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/snapshot?scan_id=selected", nil)
	rec := httptest.NewRecorder()
	srv.handleDashboardSnapshot(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected snapshot success, got %d: %s", rec.Code, rec.Body.String())
	}
	var snapshot dashboardSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Assets) != 1 || snapshot.Assets[0].Value != "selected.example" {
		t.Fatalf("snapshot leaked or omitted scan evidence: %#v", snapshot.Assets)
	}
	if snapshot.Graph.Nodes == nil {
		t.Fatal("snapshot must return an empty-or-populated graph array, not null")
	}
}

func TestScanHistoryListsPersistedRunsWithEvidenceCounts(t *testing.T) {
	ctx := context.Background()
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "history.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.StartScan(ctx, "history-scan"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAsset(ctx, models.Asset{ScanID: "history-scan", Type: "host", Value: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddEvent(ctx, models.Event{ScanID: "history-scan", Type: "target", Target: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(db, 0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans?limit=10", nil)
	rec := httptest.NewRecorder()
	srv.handleScans(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected history success, got %d: %s", rec.Code, rec.Body.String())
	}
	var runs []models.ScanRun
	if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ScanID != "history-scan" || runs[0].AssetCount != 1 || runs[0].EventCount != 1 {
		t.Fatalf("unexpected scan history: %#v", runs)
	}
}
