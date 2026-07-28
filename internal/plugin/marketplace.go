package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type MarketplacePlugin struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Author      string   `json:"author"`
	Tags        []string `json:"tags"`
	DownloadURL string   `json:"download_url"`
}

type MarketplaceManager struct {
	registryURL string
	client      *http.Client
}

func NewMarketplaceManager(registryURL string) *MarketplaceManager {
	if registryURL == "" {
		registryURL = "https://marketplace.enumscan.io/api/v1/plugins"
	}
	return &MarketplaceManager{
		registryURL: registryURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (m *MarketplaceManager) SearchPlugins(ctx context.Context, query string) ([]MarketplacePlugin, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s?q=%s", m.registryURL, query), nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		// Return mock registry items if offline/unreachable
		return m.mockRegistryPlugins(), nil
	}
	defer resp.Body.Close()

	var plugins []MarketplacePlugin
	if err := json.NewDecoder(resp.Body).Decode(&plugins); err != nil {
		return m.mockRegistryPlugins(), nil
	}

	return plugins, nil
}

func (m *MarketplaceManager) mockRegistryPlugins() []MarketplacePlugin {
	return []MarketplacePlugin{
		{
			ID:          "org.enumscan.nmap-script-bridge",
			Name:        "Nmap NSE Script Bridge",
			Version:     "1.2.0",
			Description: "Executes Nmap NSE scripts directly from enumscan dynamic worker pool",
			Author:      "Enumscan Core Team",
			Tags:        []string{"nmap", "nse", "portscan"},
			DownloadURL: "https://marketplace.enumscan.io/plugins/nmap-bridge.lua",
		},
		{
			ID:          "org.enumscan.subdomain-takeover",
			Name:        "Subdomain Takeover Auditor",
			Version:     "2.0.1",
			Description: "Detects dangling CNAME records for AWS S3, GitHub Pages, and Azure Web Apps",
			Author:      "Security Community",
			Tags:        []string{"dns", "takeover", "cloud"},
			DownloadURL: "https://marketplace.enumscan.io/plugins/subdomain-takeover.lua",
		},
	}
}
