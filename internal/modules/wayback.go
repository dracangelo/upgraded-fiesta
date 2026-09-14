package modules

import (
	"context"
	"fmt"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

// WaybackHarvester remains as a compatibility boundary for callers that used
// the experimental integration. Historical URL data must now be supplied by
// the operator through DiscoveryConfig.HistoricalURLFiles and processed by
// HistoricalURLImporter, rather than fetched from third-party services.
type WaybackHarvester struct {
	db store.RuntimeStore
}

func NewWaybackHarvester(db store.RuntimeStore) *WaybackHarvester {
	return &WaybackHarvester{db: db}
}

func (w *WaybackHarvester) HarvestDomain(ctx context.Context, scanID, domain string) ([]models.Asset, error) {
	return nil, fmt.Errorf("direct historical URL retrieval is disabled; import an operator-provided scoped export with discovery.historical_url_files")
}
