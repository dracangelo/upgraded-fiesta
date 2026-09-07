package modules

import (
	"bufio"
	"context"
	"net/url"
	"os"
	"strings"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

// HistoricalURLImporter consumes operator-provided plain-text exports from
// approved sources. It never contacts a third party; only scoped HTTP(S) URLs
// are retained or emitted to the regular HTTP module.
type HistoricalURLImporter struct {
	db    *store.SQLiteCLI
	guard scope.Guard
	files []string
}

func NewHistoricalURLImporter(db *store.SQLiteCLI, guard scope.Guard, files []string) *HistoricalURLImporter {
	return &HistoricalURLImporter{db: db, guard: guard, files: files}
}
func (m *HistoricalURLImporter) Name() string            { return "historical_url_importer" }
func (m *HistoricalURLImporter) Subscriptions() []string { return []string{EventTarget} }
func (m *HistoricalURLImporter) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	if len(m.files) == 0 || strings.Contains(event.Target, ":") {
		return nil, nil
	}
	next, seen := make([]models.Event, 0), make(map[string]bool)
	for _, path := range m.files {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		count := 0
		for scanner.Scan() && count < 10000 {
			raw := strings.TrimSpace(scanner.Text())
			parsed, err := url.Parse(raw)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || !sameDomain(event.Target, parsed.Hostname()) || !m.guard.Allowed(parsed.Hostname()) || seen[raw] {
				continue
			}
			seen[raw] = true
			count++
			_ = m.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "historical_url", Value: raw, Parent: event.Target, Metadata: "source=operator_provided_historical_export"})
			next = append(next, models.Event{ScanID: event.ScanID, Type: EventHTTPURL, Target: raw, Data: map[string]string{"source": "historical_url_import"}})
		}
		_ = file.Close()
	}
	return next, nil
}
