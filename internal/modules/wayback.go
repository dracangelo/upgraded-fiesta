package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type WaybackHarvester struct {
	db     *store.SQLiteCLI
	client *http.Client
}

func NewWaybackHarvester(db *store.SQLiteCLI) *WaybackHarvester {
	return &WaybackHarvester{
		db:     db,
		client: &http.Client{Timeout: 3 * time.Second},
	}
}

func (w *WaybackHarvester) HarvestDomain(ctx context.Context, scanID, domain string) ([]models.Asset, error) {
	if domain == "" || strings.Contains(domain, ":") {
		return nil, nil
	}

	endpoints := []string{
		fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&collapse=urlkey&limit=50", domain),
		fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=50", domain),
	}

	var harvested []models.Asset
	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", ep, nil)
		if err != nil {
			continue
		}
		resp, err := w.client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			asset := models.Asset{
				ScanID:   scanID,
				Type:     "historical_url_harvest",
				Value:    ep,
				Parent:   domain,
				Metadata: fmt.Sprintf("endpoint=%s;status=200;source=wayback_otx", ep),
			}
			harvested = append(harvested, asset)
			_ = w.db.AddAsset(ctx, asset)
		}
	}

	return harvested, nil
}
