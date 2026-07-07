package modules

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type HTTP struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewHTTP(db *store.SQLiteCLI, guard scope.Guard) HTTP {
	return HTTP{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 4 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}
}

func (h HTTP) Name() string { return "http" }

func (h HTTP) Subscriptions() []string { return []string{EventHTTPURL} }

func (h HTTP) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, event.Target, nil)
	if err != nil {
		return nil, nil
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")
	meta := "status=" + resp.Status
	if server != "" {
		meta += ";server=" + server
	}
	if poweredBy != "" {
		meta += ";x_powered_by=" + poweredBy
	}
	_ = h.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "url", Value: event.Target, Metadata: meta})

	if resp.Header.Get("Strict-Transport-Security") == "" && strings.HasPrefix(event.Target, "https://") {
		_ = h.db.AddFinding(ctx, models.Finding{
			ScanID:      event.ScanID,
			Severity:    "low",
			Confidence:  "medium",
			Asset:       event.Target,
			Title:       "Missing HSTS header",
			Evidence:    "HTTPS response did not include Strict-Transport-Security",
			Remediation: "Set a Strict-Transport-Security policy after validating HTTPS is deployed across the site.",
		})
	}
	if server != "" {
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "technology", Value: server, Parent: event.Target, Metadata: "header=Server"})
	}
	if poweredBy != "" {
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "technology", Value: poweredBy, Parent: event.Target, Metadata: "header=X-Powered-By"})
	}
	return nil, nil
}
