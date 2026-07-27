package modules

import (
	"context"
	"strings"

	"enumscan/internal/models"
	"enumscan/internal/scope"
)

// Reenumeration performs targeted follow-up after an asset-change event. The
// scope guard is repeated here because change events may originate externally.
type Reenumeration struct{ guard scope.Guard }

func NewReenumeration(guard scope.Guard) Reenumeration { return Reenumeration{guard: guard} }
func (r Reenumeration) Name() string                   { return "reenumeration" }
func (r Reenumeration) Subscriptions() []string        { return []string{EventAssetChanged} }

func (r Reenumeration) Handle(_ context.Context, event models.Event) ([]models.Event, error) {
	kind := strings.ToLower(event.Data["kind"])
	if (kind == "url" || kind == "certificate" || kind == "technology") && (strings.HasPrefix(event.Target, "http://") || strings.HasPrefix(event.Target, "https://")) {
		host := strings.TrimPrefix(strings.TrimPrefix(event.Target, "https://"), "http://")
		host = strings.Split(host, "/")[0]
		if r.guard.Allowed(host) {
			return []models.Event{{ScanID: event.ScanID, Type: EventHTTPURL, Target: event.Target, Data: map[string]string{"reason": "asset_change"}}}, nil
		}
	}
	if kind == "port" || kind == "service" || kind == "host" {
		host := strings.Split(event.Target, ":")[0]
		if r.guard.Allowed(host) {
			return []models.Event{{ScanID: event.ScanID, Type: EventHost, Target: host, Data: map[string]string{"reason": "asset_change"}}}, nil
		}
	}
	return nil, nil
}
