package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

var (
	ErrLiveHarvestDisabled = errors.New("live historical URL harvesting is disabled; enable with discovery.enable_live_historical_harvest: true")
)

// LiveHistoricalHarvester collects historical URLs from Wayback, Common Crawl, and OTX
// only when explicitly enabled by the operator, enforcing strict bounds and scope controls.
type LiveHistoricalHarvester struct {
	db              store.RuntimeStore
	guard           scope.Guard
	config          models.DiscoveryConfig
	client          *http.Client
	waybackBaseURL  string
	otxBaseURL      string
}

// NewLiveHistoricalHarvester initializes the historical harvester.
func NewLiveHistoricalHarvester(db store.RuntimeStore, guard scope.Guard, config models.DiscoveryConfig) *LiveHistoricalHarvester {
	if config.MaxHistoricalURLsPerHost <= 0 {
		config.MaxHistoricalURLsPerHost = 50
	}
	return &LiveHistoricalHarvester{
		db:             db,
		guard:          guard,
		config:         config,
		client:         &http.Client{Timeout: 8 * time.Second},
		waybackBaseURL: "https://web.archive.org/cdx/search/cdx",
		otxBaseURL:     "https://otx.alienvault.com/api/v1/indicators/domain",
	}
}

// Name returns the module identifier.
func (h *LiveHistoricalHarvester) Name() string {
	return "live_historical_harvester"
}

// Subscriptions listens for domain and host discovery events.
func (h *LiveHistoricalHarvester) Subscriptions() []string {
	return []string{EventTarget, EventHost}
}

// Handle executes the harvest on discovered domain events.
func (h *LiveHistoricalHarvester) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !h.config.EnableLiveHistoricalHarvest {
		return nil, nil
	}

	targetDomain := strings.TrimSpace(evt.Target)
	if targetDomain == "" || !h.guard.Allowed(targetDomain) {
		return nil, nil
	}

	assets, err := h.Harvest(ctx, evt.ScanID, targetDomain)
	if err != nil {
		return nil, err
	}

	var events []models.Event
	for _, a := range assets {
		events = append(events, models.Event{
			ScanID: evt.ScanID,
			Type:   EventHTTPURL,
			Target: a.Value,
			Data:   map[string]string{"source": "live_historical_harvester"},
		})
	}

	return events, nil
}

// Harvest retrieves historical URLs from configured OSINT endpoints.
func (h *LiveHistoricalHarvester) Harvest(ctx context.Context, scanID, domain string) ([]models.Asset, error) {
	if !h.config.EnableLiveHistoricalHarvest {
		return nil, ErrLiveHarvestDisabled
	}

	if !h.guard.Allowed(domain) {
		return nil, fmt.Errorf("%w: %s", ErrTargetOutOfScope, domain)
	}

	limit := h.config.MaxHistoricalURLsPerHost
	if limit <= 0 {
		limit = 50
	}

	seen := make(map[string]bool)
	var assets []models.Asset

	// 1. Query Wayback Machine CDX
	wbURLs, _ := h.queryWaybackCDX(ctx, domain, limit)
	for _, rawURL := range wbURLs {
		if len(assets) >= limit {
			break
		}
		if h.isAllowedURL(rawURL) && !seen[rawURL] {
			seen[rawURL] = true
			asset := models.Asset{
				ScanID:    scanID,
				Type:      "historical_url",
				Value:     rawURL,
				Parent:    domain,
				Metadata:  "source=wayback;historical=true",
				CreatedAt: time.Now().UTC(),
			}
			if h.db != nil {
				_ = h.db.AddAsset(ctx, asset)
			}
			assets = append(assets, asset)
		}
	}

	// 2. Query AlienVault OTX if limit remains
	if len(assets) < limit {
		otxURLs, _ := h.queryAlienVaultOTX(ctx, domain, limit-len(assets))
		for _, rawURL := range otxURLs {
			if len(assets) >= limit {
				break
			}
			if h.isAllowedURL(rawURL) && !seen[rawURL] {
				seen[rawURL] = true
				asset := models.Asset{
					ScanID:    scanID,
					Type:      "historical_url",
					Value:     rawURL,
					Parent:    domain,
					Metadata:  "source=alienvault_otx;historical=true",
					CreatedAt: time.Now().UTC(),
				}
				if h.db != nil {
					_ = h.db.AddAsset(ctx, asset)
				}
				assets = append(assets, asset)
			}
		}
	}

	return assets, nil
}

func (h *LiveHistoricalHarvester) queryWaybackCDX(ctx context.Context, domain string, limit int) ([]string, error) {
	reqURL := fmt.Sprintf("%s?url=*.%s/*&output=json&collapse=urlkey&limit=%d",
		h.waybackBaseURL, url.QueryEscape(domain), limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback cdx returned HTTP %d", resp.StatusCode)
	}

	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}

	var urls []string
	// First row is header: ["urlkey", "timestamp", "original", ...]
	for i, row := range rows {
		if i == 0 || len(row) < 3 {
			continue
		}
		urls = append(urls, row[2])
	}
	return urls, nil
}

func (h *LiveHistoricalHarvester) queryAlienVaultOTX(ctx context.Context, domain string, limit int) ([]string, error) {
	reqURL := fmt.Sprintf("%s/%s/url_list?limit=%d",
		strings.TrimRight(h.otxBaseURL, "/"), url.PathEscape(domain), limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otx returned HTTP %d", resp.StatusCode)
	}

	var payload struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	var urls []string
	for _, item := range payload.URLList {
		if item.URL != "" {
			urls = append(urls, item.URL)
		}
	}
	return urls, nil
}

func (h *LiveHistoricalHarvester) isAllowedURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	return h.guard.Allowed(parsed.Hostname())
}
