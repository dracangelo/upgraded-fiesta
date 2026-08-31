package api

import (
	"strings"
	"testing"

	"enumscan/internal/models"
)

func TestTUIDashboard(t *testing.T) {
	tui := NewTUIDashboard()
	summary := tui.RenderSummary("scan_t26", []models.Asset{{Value: "127.0.0.1"}}, nil)
	if !strings.Contains(summary, "EnumScan TUI Dashboard") {
		t.Fatalf("TUI render error")
	}
}
