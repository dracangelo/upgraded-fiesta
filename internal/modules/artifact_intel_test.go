package modules

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"enumscan/internal/store"
)

func TestArtifactIntelligenceYARAAndVirusTotal(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "intel.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	ctx := context.Background()
	_ = db.Migrate(ctx)

	cache := store.NewProviderCache(db)
	engine := NewArtifactIntelligenceEngine(cache)

	// 1. Scan artifact with WebShell pattern
	shellPayload := []byte(`<?php eval(base64_decode($_POST['cmd'])); ?>`)
	findings := engine.ScanArtifact(ctx, "scan-1", "http://example.com/shell.php", shellPayload)
	if len(findings) == 0 {
		t.Errorf("expected YARA finding for webshell payload, got 0")
	} else if findings[0].Severity != "critical" {
		t.Errorf("expected critical severity, got %s", findings[0].Severity)
	}

	// 2. Scan artifact with Miner pattern
	minerPayload := []byte(`var miner = new CoinHive.Anonymous('SITE_KEY'); miner.start();`)
	minerFindings := engine.ScanArtifact(ctx, "scan-1", "http://example.com/app.js", minerPayload)
	if len(minerFindings) == 0 {
		t.Errorf("expected YARA finding for miner script, got 0")
	}

	// 3. Scan clean payload
	cleanPayload := []byte(`console.log("Hello World");`)
	cleanFindings := engine.ScanArtifact(ctx, "scan-1", "http://example.com/clean.js", cleanPayload)
	if len(cleanFindings) != 0 {
		t.Errorf("expected 0 findings for clean payload, got %d", len(cleanFindings))
	}

	// 4. Privacy violation check: reject raw content upload to VirusTotal
	_, err = engine.CheckVirusTotalReputation(ctx, nil, "test-key", "raw_content", "some raw data")
	if !errors.Is(err, ErrPrivacyViolation) {
		t.Fatalf("expected ErrPrivacyViolation for raw content query, got: %v", err)
	}

	// 5. Mock VirusTotal API server for hash lookup and cache verification
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":   "test-hash",
				"type": "file",
				"attributes": map[string]any{
					"reputation": -50,
				},
			},
		})
	}))
	defer server.Close()

	hash := ComputeArtifactSHA256(shellPayload)

	// Direct query with mock transport
	client := server.Client()
	transport := client.Transport
	client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Redirect VirusTotal to local test server
		req.URL.Scheme = "http"
		req.URL.Host = server.Listener.Addr().String()
		return transport.RoundTrip(req)
	})

	res1, err := engine.CheckVirusTotalReputation(ctx, client, "fake-key", "hash", hash)
	if err != nil {
		t.Fatalf("VT reputation query failed: %v", err)
	}
	if res1 == nil {
		t.Fatalf("expected non-nil response")
	}
	if requestCount != 1 {
		t.Errorf("expected 1 HTTP request, got %d", requestCount)
	}

	// Second query must hit cache and NOT send an HTTP request
	res2, err := engine.CheckVirusTotalReputation(ctx, client, "fake-key", "hash", hash)
	if err != nil {
		t.Fatalf("VT cached query failed: %v", err)
	}
	if res2 == nil {
		t.Fatalf("expected non-nil cached response")
	}
	if requestCount != 1 {
		t.Errorf("expected cache hit with requestCount=1, got %d", requestCount)
	}
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
