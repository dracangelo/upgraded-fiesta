package api

import (
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

func TestTask34TimelineAndDriftEndpoints(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_timeline.sqlite")
	cli, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	if err := cli.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	srv := NewServer(cli, 0)
	const scanID = "timeline-scan-1"
	_ = cli.StartScan(context.Background(), scanID)
	_ = cli.AddAsset(context.Background(), models.Asset{ScanID: scanID, Type: "subdomain", Value: "app.internal", Parent: "internal"})
	_ = cli.AddAsset(context.Background(), models.Asset{ScanID: scanID, Type: "port", Value: "443/tcp", Parent: "app.internal"})
	_ = cli.AddFinding(context.Background(), models.Finding{ScanID: scanID, Severity: "high", Title: "Outdated TLS 1.0 Enabled", Asset: "app.internal"})

	// 1. Test Timeline Endpoint (/api/v1/timeline)
	reqTL := httptest.NewRequest(http.MethodGet, "/api/v1/timeline?scan_id="+scanID+"&category=host", nil)
	recTL := httptest.NewRecorder()
	srv.handleTimeline(recTL, reqTL)
	if recTL.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from timeline endpoint, got %d", recTL.Code)
	}
	var tlEntries []inventory.TimelineEntry
	if err := json.Unmarshal(recTL.Body.Bytes(), &tlEntries); err != nil {
		t.Fatalf("unmarshal timeline entries failed: %v", err)
	}
	if len(tlEntries) == 0 {
		t.Fatalf("expected timeline entries, got 0")
	}

	// 2. Test Configuration Drift Endpoint (/api/v1/drift)
	reqDrift := httptest.NewRequest(http.MethodGet, "/api/v1/drift?baseline="+scanID+"&current="+scanID, nil)
	recDrift := httptest.NewRecorder()
	srv.handleDrift(recDrift, reqDrift)
	if recDrift.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from drift endpoint, got %d", recDrift.Code)
	}
	var driftRep inventory.DriftReport
	if err := json.Unmarshal(recDrift.Body.Bytes(), &driftRep); err != nil {
		t.Fatalf("unmarshal drift report failed: %v", err)
	}

	// 3. Test Change Reports Endpoint (/api/v1/reports/changes)
	reqRep := httptest.NewRequest(http.MethodGet, "/api/v1/reports/changes?type=daily&scan_id="+scanID, nil)
	recRep := httptest.NewRecorder()
	srv.handleChangeReports(recRep, reqRep)
	if recRep.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from change report endpoint, got %d", recRep.Code)
	}
	var repSummary inventory.ChangeReportSummary
	if err := json.Unmarshal(recRep.Body.Bytes(), &repSummary); err != nil {
		t.Fatalf("unmarshal change report summary failed: %v", err)
	}
	if repSummary.ReportType != "daily" {
		t.Fatalf("expected daily report type, got %s", repSummary.ReportType)
	}
}
