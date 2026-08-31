package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestTask33SearchEngineEndpoints(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_search.sqlite")
	cli, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI failed: %v", err)
	}
	if err := cli.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	srv := NewServer(cli, 0)
	const scanID = "search-scan-1"
	_ = cli.StartScan(context.Background(), scanID)
	_ = cli.AddAsset(context.Background(), models.Asset{ScanID: scanID, Type: "subdomain", Value: "api.example.com", Parent: "example.com"})
	_ = cli.AddAsset(context.Background(), models.Asset{ScanID: scanID, Type: "technology", Value: "React", Metadata: "v18.2.0"})
	_ = cli.AddFinding(context.Background(), models.Finding{ScanID: scanID, Severity: "high", Title: "Hardcoded API Secret Key", Asset: "api.example.com", Evidence: "SECRET_KEY=12345"})

	// 1. Test Category Search (asset)
	reqAsset := httptest.NewRequest(http.MethodGet, "/api/v1/search?scan_id="+scanID+"&q=example&category=asset", nil)
	recAsset := httptest.NewRecorder()
	srv.handleSearch(recAsset, reqAsset)
	if recAsset.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from search asset, got %d", recAsset.Code)
	}
	var resAsset map[string]any
	_ = json.Unmarshal(recAsset.Body.Bytes(), &resAsset)
	if resAsset["category"] != "asset" {
		t.Fatalf("expected category asset, got %v", resAsset["category"])
	}

	// 2. Test Category Search (secret)
	reqSecret := httptest.NewRequest(http.MethodGet, "/api/v1/search?scan_id="+scanID+"&q=secret&category=secret", nil)
	recSecret := httptest.NewRecorder()
	srv.handleSearch(recSecret, reqSecret)
	if recSecret.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from search secret, got %d", recSecret.Code)
	}
	var resSecret map[string]any
	_ = json.Unmarshal(recSecret.Body.Bytes(), &resSecret)
	findingsList, _ := resSecret["findings"].([]any)
	if len(findingsList) == 0 {
		t.Fatalf("expected secret findings match, got 0")
	}

	// 3. Test Saved Query POST & GET
	sqBody, _ := json.Marshal(models.SavedQuery{Name: "High Severity Secrets", Query: "secret"})
	reqSQ := httptest.NewRequest(http.MethodPost, "/api/v1/saved-queries", bytes.NewReader(sqBody))
	reqSQ.Header.Set("Content-Type", "application/json")
	recSQ := httptest.NewRecorder()
	srv.handleSavedQueries(recSQ, reqSQ)
	if recSQ.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from saved query, got %d", recSQ.Code)
	}

	reqGetSQ := httptest.NewRequest(http.MethodGet, "/api/v1/saved-queries", nil)
	recGetSQ := httptest.NewRecorder()
	srv.handleSavedQueries(recGetSQ, reqGetSQ)
	if recGetSQ.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from saved queries list, got %d", recGetSQ.Code)
	}
	var sqList []models.SavedQuery
	_ = json.Unmarshal(recGetSQ.Body.Bytes(), &sqList)
	if len(sqList) == 0 || sqList[0].Name != "High Severity Secrets" {
		t.Fatalf("unexpected saved queries list: %v", sqList)
	}
}
