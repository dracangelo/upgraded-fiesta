package modules

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/reporting"
	"enumscan/internal/store"
	"enumscan/internal/vulnerability"
)

func TestTask26AdvancedIntelligenceAndModernWeb(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 1. Wappalyzer Test
	wap := NewWappalyzerDetector(db)
	assets := wap.Detect(context.Background(), "scan_t26", "https://example.com", "Server: nginx\r\n", "<div data-reactroot></div>")
	if len(assets) < 2 {
		t.Fatalf("expected at least 2 detected tech stacks, got %d", len(assets))
	}

	// 2. Wayback Harvester Test
	wb := NewWaybackHarvester(db)
	_, _ = wb.HarvestDomain(context.Background(), "scan_t26", "example.com")

	// 3. OOB Listener Test
	oob := vulnerability.NewOOBListenerClient("http://oob.local")
	payload := oob.GeneratePayload("token123")
	if !strings.Contains(payload, "token123") {
		t.Fatalf("OOB payload mismatch")
	}

	// 4. BloodHound Exporter Test
	bhJSON, err := reporting.ExportBloodHoundJSON([]models.Asset{
		{Type: "ldap_naming_context", Value: "dc=example,dc=com"},
	})
	if err != nil || !strings.Contains(string(bhJSON), "dc=example,dc=com") {
		t.Fatalf("BloodHound export error")
	}
}
