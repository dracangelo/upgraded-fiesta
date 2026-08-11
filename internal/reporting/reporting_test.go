package reporting

import (
	"context"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestReportingFormats(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	_ = db.Migrate(ctx)
	scanID := "scan-reporting-test"

	_ = db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "host", Value: "127.0.0.1", Parent: "local", Metadata: "active"})
	_ = db.AddFinding(ctx, models.Finding{
		ScanID:      scanID,
		Severity:    "high",
		Confidence:  "high",
		Asset:       "127.0.0.1:80",
		Title:       "Test Finding <script>",
		CVE:         "CVE-2023-0001",
		CWE:         "CWE-79",
		CVSS:        8.5,
		EPSS:        0.95,
		KEV:         true,
		Evidence:    "proof",
		Remediation: "fix it",
	})

	formats := []string{"json", "markdown", "md", "html", "pdf", "sarif", "neo4j", "cypher", "neo4j-json"}
	outDir := t.TempDir()

	for _, fmtName := range formats {
		path, err := Write(ctx, db, scanID, fmtName, outDir)
		if err != nil {
			t.Errorf("Write format %s failed: %v", fmtName, err)
		}
		if path == "" {
			t.Errorf("Write format %s returned empty path", fmtName)
		}
	}

	// Invalid format check
	if _, err := Write(ctx, db, scanID, "invalid_fmt", outDir); err == nil {
		t.Errorf("expected error for invalid format, got nil")
	}
}
