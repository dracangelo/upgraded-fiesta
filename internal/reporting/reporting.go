package reporting

import (
	"context"
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
		return path, os.WriteFile(path, data, 0600)
	case "markdown", "md":
		path := filepath.Join(outputDir, scanID+".md")
		return path, os.WriteFile(path, []byte(markdown(r)), 0600)
	case "html":
		path := filepath.Join(outputDir, scanID+".html")
		return path, os.WriteFile(path, []byte(ExportHTML(r)), 0600)
	case "pdf":
		path := filepath.Join(outputDir, scanID+".pdf")
		return path, os.WriteFile(path, ExportPDFText(r), 0600)
	case "sarif":
		path := filepath.Join(outputDir, scanID+".sarif")
		data, err := ExportSARIF(r)
		if err != nil {
			return "", err
		}
		return path, os.WriteFile(path, data, 0600)
	case "neo4j", "cypher":
		path := filepath.Join(outputDir, scanID+".cypher")
		cypherText := ExportNeo4jCypher(r)
		return path, os.WriteFile(path, []byte(cypherText), 0600)
	case "neo4j-json":
		path := filepath.Join(outputDir, scanID+".neo4j.json")
		data, err := ExportNeo4jJSON(r)
		if err != nil {
			return "", err
		}
		return path, os.WriteFile(path, data, 0600)
	default:
		return "", fmt.Errorf("unsupported report format %q", format)
	}
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
