package modules

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestLiveHistoricalHarvester(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "hist.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	ctx := context.Background()
	_ = db.Migrate(ctx)

	guard := scope.New([]string{"example.com", "sub.example.com"})

	// 1. Disabled by default
	harvesterDisabled := NewLiveHistoricalHarvester(db, guard, models.DiscoveryConfig{
		EnableLiveHistoricalHarvest: false,
	})
	_, err = harvesterDisabled.Harvest(ctx, "scan-1", "example.com")
	if !errors.Is(err, ErrLiveHarvestDisabled) {
		t.Fatalf("expected ErrLiveHarvestDisabled, got: %v", err)
	}

	// Mock Wayback and OTX servers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "cdx") {
			// Wayback format
			rows := [][]string{
				{"urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"},
				{"com,example)/login", "20230101", "https://example.com/login", "text/html", "200", "hash1", "123"},
				{"com,example)/api/v1", "20230102", "https://sub.example.com/api/v1", "application/json", "200", "hash2", "456"},
				{"com,evil)/hack", "20230103", "https://evil.com/hack", "text/html", "200", "hash3", "789"}, // Out of scope
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rows)
			return
		}

		if strings.Contains(r.URL.Path, "url_list") {
			// OTX format
			resp := map[string]any{
				"url_list": []map[string]string{
					{"url": "https://example.com/admin"},
					{"url": "https://malicious.org/bad"}, // Out of scope
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	harvester := NewLiveHistoricalHarvester(db, guard, models.DiscoveryConfig{
		EnableLiveHistoricalHarvest: true,
		MaxHistoricalURLsPerHost:    10,
	})
	harvester.waybackBaseURL = server.URL + "/cdx"
	harvester.otxBaseURL = server.URL + "/url_list"

	// 2. Scope rejection on domain
	_, err = harvester.Harvest(ctx, "scan-1", "unauthorized.org")
	if !errors.Is(err, ErrTargetOutOfScope) {
		t.Fatalf("expected ErrTargetOutOfScope, got: %v", err)
	}

	// 3. Harvest on authorized domain
	assets, err := harvester.Harvest(ctx, "scan-1", "example.com")
	if err != nil {
		t.Fatalf("Harvest failed: %v", err)
	}

	// Verify URLs in assets
	if len(assets) != 3 {
		t.Fatalf("expected 3 in-scope historical URLs, got %d", len(assets))
	}

	for _, a := range assets {
		if strings.Contains(a.Value, "evil.com") || strings.Contains(a.Value, "malicious.org") {
			t.Errorf("out of scope URL leaked into assets: %s", a.Value)
		}
	}
}
