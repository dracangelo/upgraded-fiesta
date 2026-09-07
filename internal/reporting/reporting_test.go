package reporting

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

	formats := []string{"json", "markdown", "md", "executive", "technical", "triage", "html", "pdf", "sarif", "csv", "neo4j", "cypher", "neo4j-json"}
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

func TestWriteRestrictsExistingReportDirectoryAndFile(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "private-report.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAsset(ctx, models.Asset{ScanID: "private-report", Type: "host", Value: "192.0.2.20"}); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "reports")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(outDir, "private-report.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(ctx, db, "private-report", "json", outDir); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(outDir)
	if err != nil || dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("report directory permissions = %v, %v", dirInfo.Mode().Perm(), err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil || fileInfo.Mode().Perm() != 0600 {
		t.Fatalf("report file permissions = %v, %v", fileInfo.Mode().Perm(), err)
	}
}

func TestEvidenceOnlySummariesPreserveVerificationState(t *testing.T) {
	r := report{ScanID: "summary-test", Assets: []models.Asset{{Type: "open_port", Value: "127.0.0.1:443"}}, Findings: []models.Finding{
		{Severity: "high", Verification: "heuristic", Asset: "127.0.0.1:443", Title: "Observed service concern", Remediation: "Review configuration."},
	}}
	for _, text := range []string{ExecutiveSummary(r), TechnicalSummary(r)} {
		if !strings.Contains(text, "heuristic") || strings.Contains(strings.ToLower(text), "compromise confirmed") {
			t.Fatalf("summary must preserve evidence state without inventing impact: %s", text)
		}
	}
}

func TestTriageReportSuggestsOnlySafeEvidenceFollowUp(t *testing.T) {
	r := report{ScanID: "triage-test", Assets: []models.Asset{{Type: "open_port", Value: "127.0.0.1:443"}, {Type: "http_response", Value: "https://127.0.0.1/"}}, Findings: []models.Finding{{Severity: "high", Verification: "heuristic", Asset: "127.0.0.1:443", Title: "Service concern"}}}
	text := strings.ToLower(TriageReport(r))
	for _, expected := range []string{"non-destructive", "heuristic", "service fingerprints", "http and tls"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected triage content %q in %s", expected, text)
		}
	}
	for _, forbidden := range []string{"exploit the target", "brute force", "credential attack"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unsafe triage content %q in %s", forbidden, text)
		}
	}
}

func TestTriageRelationshipNarrativesDoNotAssertAttackPaths(t *testing.T) {
	r := report{ScanID: "narrative-test", Assets: []models.Asset{{Type: "open_port", Value: "host-a:443", Parent: "host-a"}}, Findings: []models.Finding{{Severity: "high", Verification: "observed", Asset: "host-a:443", Title: "Observed TLS concern"}}}
	text := TriageReport(r)
	if !strings.Contains(text, "host-a` → `host-a:443") || !strings.Contains(text, "not proof of reachability") {
		t.Fatalf("missing evidence-chain caveat: %s", text)
	}
}
