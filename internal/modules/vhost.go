package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type VHostDiscovery struct {
	db        *store.SQLiteCLI
	guard     scope.Guard
	wordlist  []string
	client    *http.Client
}

func NewVHostDiscovery(db *store.SQLiteCLI, guard scope.Guard) *VHostDiscovery {
	return &VHostDiscovery{
		db:       db,
		guard:    guard,
		wordlist: []string{"admin", "dev", "staging", "api", "internal", "corp", "test", "portal", "mail", "app"},
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *VHostDiscovery) Name() string {
	return "vhost_discovery"
}

func (m *VHostDiscovery) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *VHostDiscovery) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":80") && !strings.HasSuffix(evt.Target, ":443") && !strings.HasSuffix(evt.Target, ":8080") {
		return nil, nil
	}

	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	scheme := "http"
	if strings.HasSuffix(evt.Target, ":443") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, evt.Target)

	// Fetch baseline HTTP response
	baselineReq, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return nil, nil
	}
	baselineReq.Host = "invalid-vhost-baseline.local"
	resp, err := m.client.Do(baselineReq)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	baselineBody, _ := io.ReadAll(resp.Body)
	baselineLen := len(baselineBody)

	var newEvents []models.Event
	baseDomain := "example.com"

	for _, sub := range m.wordlist {
		candidateVHost := fmt.Sprintf("%s.%s", sub, baseDomain)
		if !m.guard.Allowed(candidateVHost) {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
		if err != nil {
			continue
		}
		req.Host = candidateVHost

		r, err := m.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		// VHost match if length or status differs significantly from baseline
		if r.StatusCode != resp.StatusCode || absDiff(len(body), baselineLen) > 50 {
			vhostVal := fmt.Sprintf("%s (on %s)", candidateVHost, evt.Target)
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "vhost",
				Value:    vhostVal,
				Parent:   evt.Target,
				Metadata: fmt.Sprintf("status=%d len=%d", r.StatusCode, len(body)),
			})

			_ = m.db.AddFinding(ctx, models.Finding{
				ScanID:      evt.ScanID,
				Severity:    "info",
				Confidence:  "high",
				Asset:       candidateVHost,
				Title:       "Virtual Host Discovered",
				Evidence:    fmt.Sprintf("VHost %s resolved on IP %s (status %d)", candidateVHost, evt.Target, r.StatusCode),
				Remediation: "Ensure all virtual host endpoints are properly protected and monitored.",
			})

			newEvents = append(newEvents, models.Event{
				ScanID: evt.ScanID,
				Type:   "domain.discovered",
				Target: candidateVHost,
			})
		}
	}

	return newEvents, nil
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}
