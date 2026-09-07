package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestTask32LiveMonitoringEndpoints(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_mon.sqlite")
	cli, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	if err := cli.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	srv := NewServer(cli, 0)
	const scanID = "mon-scan-1"
	_ = cli.StartScan(context.Background(), scanID)
	if err := cli.RecordModuleRun(context.Background(), models.ModuleRun{
		ScanID: scanID, Module: "http", EventType: "http.url", Target: "example.test",
		Status: "completed", Duration: time.Millisecond,
	}); err != nil {
		t.Fatalf("RecordModuleRun failed: %v", err)
	}

	// 1. Test Pause Endpoint
	pauseReq := httptest.NewRequest(http.MethodPost, "/api/v1/scans/pause", strings.NewReader(`{"scan_id":"`+scanID+`"}`))
	pauseReq.Header.Set("Content-Type", "application/json")
	pauseRec := httptest.NewRecorder()
	srv.handlePauseScan(pauseRec, pauseReq)
	if pauseRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from pause scan, got %d", pauseRec.Code)
	}
	var pauseResp map[string]string
	_ = json.Unmarshal(pauseRec.Body.Bytes(), &pauseResp)
	if pauseResp["status"] != "paused" {
		t.Fatalf("expected status 'paused', got %s", pauseResp["status"])
	}

	// 2. Test Resume Endpoint
	resumeReq := httptest.NewRequest(http.MethodPost, "/api/v1/scans/resume", strings.NewReader(`{"scan_id":"`+scanID+`"}`))
	resumeReq.Header.Set("Content-Type", "application/json")
	resumeRec := httptest.NewRecorder()
	srv.handleResumeScan(resumeRec, resumeReq)
	if resumeRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from resume scan, got %d", resumeRec.Code)
	}
	var resumeResp map[string]string
	_ = json.Unmarshal(resumeRec.Body.Bytes(), &resumeResp)
	if resumeResp["status"] != "running" {
		t.Fatalf("expected status 'running', got %s", resumeResp["status"])
	}

	// 3. Test Metrics Endpoint
	metricsReq := httptest.NewRequest(http.MethodGet, "/api/v1/metrics?scan_id="+scanID, nil)
	metricsRec := httptest.NewRecorder()
	srv.handleMetrics(metricsRec, metricsReq)
	if metricsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from metrics, got %d", metricsRec.Code)
	}
	var metricsResp liveMetricsResponse
	if err := json.Unmarshal(metricsRec.Body.Bytes(), &metricsResp); err != nil {
		t.Fatalf("unmarshal metrics response failed: %v", err)
	}
	if metricsResp.ScanID != scanID {
		t.Fatalf("expected scan_id %s, got %s", scanID, metricsResp.ScanID)
	}
	if metricsResp.CompletedRuns != 1 || metricsResp.ThroughputPerMinute <= 0 {
		t.Fatalf("expected one completed run and positive measured throughput, got %+v", metricsResp)
	}
	if err := cli.UpsertRuntimeStats(context.Background(), models.ScanRuntimeStats{ScanID: scanID, WorkerCapacity: 4, ActiveWorkers: 2, QueueHigh: 1}); err != nil {
		t.Fatalf("UpsertRuntimeStats failed: %v", err)
	}
	metricsRec = httptest.NewRecorder()
	srv.handleMetrics(metricsRec, metricsReq)
	if err := json.Unmarshal(metricsRec.Body.Bytes(), &metricsResp); err != nil || metricsResp.Runtime == nil || metricsResp.Runtime.ActiveWorkers != 2 {
		t.Fatalf("expected persisted runtime stats, got %+v (error: %v)", metricsResp, err)
	}

	// 4. Test Live Logs Endpoint
	logsReq := httptest.NewRequest(http.MethodGet, "/api/v1/logs/stream?scan_id="+scanID, nil)
	logsRec := httptest.NewRecorder()
	srv.handleLiveLogs(logsRec, logsReq)
	if logsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from live logs stream, got %d", logsRec.Code)
	}
	if !strings.Contains(logsRec.Body.String(), `"module":"http"`) || strings.Contains(logsRec.Body.String(), "Live log stream attached") {
		t.Fatalf("unexpected log stream body: %s", logsRec.Body.String())
	}
}
