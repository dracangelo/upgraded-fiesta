package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type SensitiveExposureScanner struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewSensitiveExposureScanner(db *store.SQLiteCLI, guard scope.Guard) *SensitiveExposureScanner {
	return &SensitiveExposureScanner{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *SensitiveExposureScanner) Name() string {
	return "sensitive_exposure_scanner"
}

func (m *SensitiveExposureScanner) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *SensitiveExposureScanner) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
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

	sensitivePaths := []string{
		"/.git/HEAD",
		"/.svn/entries",
		"/.env",
		"/.env.local",
		"/config.bak",
		"/backup.sql",
		"/dump.sql",
		"/backup.zip",
	}

	for _, path := range sensitivePaths {
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+path, nil)
		if err != nil {
			continue
		}

		resp, err := m.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "exposed_file",
					Value:    baseURL + path,
					Parent:   evt.Target,
					Metadata: fmt.Sprintf("sensitive_path status=%d", resp.StatusCode),
				})
			}
		}
	}

	return nil, nil
}
