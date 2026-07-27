package inventory

import (
	"context"
	"strings"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type Manager struct {
	store *store.InventoryStore
}

func NewManager(invStore *store.InventoryStore) *Manager {
	return &Manager{store: invStore}
}

func (m *Manager) ProcessEvent(ctx context.Context, evt models.Event) {
	if evt.Target == "" {
		return
	}

	assetType := "host"
	if strings.Contains(evt.Target, "://") || strings.Contains(evt.Target, "/") {
		assetType = "url"
	} else if strings.Contains(evt.Target, ":") {
		assetType = "service"
	}

	m.store.UpsertAsset(ctx, assetType, evt.Target, "", "secops", []string{"auto-discovered"})
}

func (m *Manager) ProcessFinding(ctx context.Context, finding models.Finding) {
	m.store.UpsertAsset(ctx, "finding_asset", finding.Asset, "", "secops", nil)

	if finding.Evidence != "" && strings.Contains(strings.ToLower(finding.Title), "secret") {
		m.store.AddSecret(ctx, models.SecretRecord{
			Asset:   finding.Asset,
			Type:    finding.Title,
			Snippet: finding.Evidence,
			Entropy: 4.5,
		})
	}
}

func (m *Manager) StoreScreenshot(ctx context.Context, asset, filePath, res, hash string) {
	m.store.AddScreenshot(ctx, models.ScreenshotRecord{
		Asset:      asset,
		FilePath:   filePath,
		Resolution: res,
		Hash:       hash,
	})
}

func (m *Manager) StoreTechnology(ctx context.Context, asset, product, cat, ver string) {
	m.store.AddTechnology(ctx, models.TechnologyRecord{
		Asset:      asset,
		Product:    product,
		Category:   cat,
		Version:    ver,
		Confidence: "high",
	})
}

func (m *Manager) StoreCertificate(ctx context.Context, asset, fingerprint, subject, issuer string) {
	m.store.AddCertificate(ctx, models.CertificateRecord{
		Asset:       asset,
		Fingerprint: fingerprint,
		Subject:     subject,
		Issuer:      issuer,
	})
}
