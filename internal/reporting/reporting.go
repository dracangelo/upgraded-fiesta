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
	if err := os.MkdirAll(outputDir, 0755); err != nil {
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
		return path, os.WriteFile(path, data, 0644)
	case "markdown", "md":
		path := filepath.Join(outputDir, scanID+".md")
		return path, os.WriteFile(path, []byte(markdown(r)), 0644)
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
		fmt.Fprintf(&b, "- Severity: %s\n- Confidence: %s\n- Asset: `%s`\n- Evidence: %s\n- Remediation: %s\n\n", f.Severity, f.Confidence, f.Asset, f.Evidence, f.Remediation)
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
