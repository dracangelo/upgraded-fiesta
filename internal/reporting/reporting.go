package reporting

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type report struct {
	ScanID   string           `json:"scan_id"`
	Assets   []models.Asset   `json:"assets"`
	Findings []models.Finding `json:"findings"`
}

func Write(ctx context.Context, db *store.SQLiteCLI, scanID, format, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return "", err
	}
	if err := os.Chmod(outputDir, 0700); err != nil {
		return "", fmt.Errorf("restrict report directory permissions: %w", err)
	}
	assets, err := db.Assets(ctx, scanID)
	if err != nil {
		return "", err
	}
	findings, err := db.Findings(ctx, scanID)
	if err != nil {
		return "", err
	}
	r := report{ScanID: scanID, Assets: assets, Findings: findings}
	switch strings.ToLower(format) {
	case "json":
		path := filepath.Join(outputDir, scanID+".json")
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return "", err
		}
		return path, writePrivateFile(path, data)
	case "markdown", "md":
		path := filepath.Join(outputDir, scanID+".md")
		return path, writePrivateFile(path, []byte(markdown(r)))
	case "executive", "executive-summary":
		path := filepath.Join(outputDir, scanID+"-executive.md")
		return path, writePrivateFile(path, []byte(ExecutiveSummary(r)))
	case "technical", "technical-summary":
		path := filepath.Join(outputDir, scanID+"-technical.md")
		return path, writePrivateFile(path, []byte(TechnicalSummary(r)))
	case "triage", "recommendations":
		path := filepath.Join(outputDir, scanID+"-triage.md")
		return path, writePrivateFile(path, []byte(TriageReport(r)))
	case "html":
		path := filepath.Join(outputDir, scanID+".html")
		return path, writePrivateFile(path, []byte(ExportHTML(r)))
	case "pdf":
		path := filepath.Join(outputDir, scanID+".pdf")
		return path, writePrivateFile(path, ExportPDFText(r))
	case "sarif":
		path := filepath.Join(outputDir, scanID+".sarif")
		data, err := ExportSARIF(r)
		if err != nil {
			return "", err
		}
		return path, writePrivateFile(path, data)
	case "csv":
		path := filepath.Join(outputDir, scanID+".csv")
		return path, writePrivateFile(path, ExportCSV(r))
	case "neo4j", "cypher":
		path := filepath.Join(outputDir, scanID+".cypher")
		cypherText := ExportNeo4jCypher(r)
		return path, writePrivateFile(path, []byte(cypherText))
	case "neo4j-json":
		path := filepath.Join(outputDir, scanID+".neo4j.json")
		data, err := ExportNeo4jJSON(r)
		if err != nil {
			return "", err
		}
		return path, writePrivateFile(path, data)
	default:
		return "", fmt.Errorf("unsupported report format %q", format)
	}
}

func writePrivateFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// ExportCSV creates a spreadsheet-safe flat finding report. Assets remain in
// richer report formats because flattening them into finding rows is ambiguous.
func ExportCSV(r report) []byte {
	var out bytes.Buffer
	writer := csv.NewWriter(&out)
	_ = writer.Write([]string{"scan_id", "severity", "confidence", "verification", "asset", "title", "cve", "cwe", "cvss", "epss", "kev", "evidence", "remediation", "references"})
	for _, finding := range r.Findings {
		verification := finding.Verification
		if verification == "" {
			verification = "confirmed"
		}
		_ = writer.Write([]string{
			r.ScanID, finding.Severity, finding.Confidence, verification, finding.Asset,
			finding.Title, finding.CVE, finding.CWE,
			fmt.Sprintf("%.1f", finding.CVSS), fmt.Sprintf("%.4f", finding.EPSS),
			fmt.Sprintf("%t", finding.KEV), finding.Evidence, finding.Remediation,
			strings.Join(finding.References, " | "),
		})
	}
	writer.Flush()
	return out.Bytes()
}

func markdown(r report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# enumscan report: %s\n\n", r.ScanID)
	fmt.Fprintf(&b, "## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("No findings recorded.\n\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "### %s\n\n", f.Title)
		verification := f.Verification
		if verification == "" {
			verification = "confirmed"
		}
		fmt.Fprintf(&b, "- Severity: %s\n- Confidence: %s\n- Verification: %s\n- Asset: `%s`\n", f.Severity, f.Confidence, verification, f.Asset)
		if f.CVE != "" {
			fmt.Fprintf(&b, "- CVE: %s\n", f.CVE)
		}
		if f.CWE != "" {
			fmt.Fprintf(&b, "- CWE: %s\n", f.CWE)
		}
		if f.CVSS > 0 {
			fmt.Fprintf(&b, "- CVSS Score: %.1f\n", f.CVSS)
		}
		if f.EPSS > 0 {
			fmt.Fprintf(&b, "- EPSS Score: %.2f\n", f.EPSS)
		}
		if f.KEV {
			fmt.Fprintf(&b, "- CISA KEV: Known Exploited\n")
		}
		fmt.Fprintf(&b, "- Evidence: %s\n- Remediation: %s\n\n", f.Evidence, f.Remediation)
	}
	fmt.Fprintf(&b, "## Assets\n\n")
	for _, a := range r.Assets {
		fmt.Fprintf(&b, "- `%s` `%s`", a.Type, a.Value)
		if a.Parent != "" {
			fmt.Fprintf(&b, " parent=`%s`", a.Parent)
		}
		if a.Metadata != "" {
			fmt.Fprintf(&b, " metadata=`%s`", a.Metadata)
		}
		b.WriteString("\n")
	}
	return b.String()
}
