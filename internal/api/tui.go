package api

import (
	"fmt"

	"enumscan/internal/models"
)

type TUIDashboard struct{}

func NewTUIDashboard() *TUIDashboard {
	return &TUIDashboard{}
}

func (t *TUIDashboard) RenderSummary(scanID string, assets []models.Asset, findings []models.Finding) string {
	return fmt.Sprintf("=== EnumScan TUI Dashboard ===\nScan ID: %s\nTotal Discovered Assets: %d\nTotal Findings: %d\n===============================",
		scanID, len(assets), len(findings))
}
