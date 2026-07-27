package inventory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type DifferentialScanResult struct {
	NewOpenPorts         []string `json:"new_open_ports"`
	NewlyClosedPorts     []string `json:"newly_closed_ports"`
	NewHosts             []string `json:"new_hosts"`
	RemovedHosts         []string `json:"removed_hosts"`
	ServiceChanges       []string `json:"service_changes"`
	CertificateChanges   []string `json:"certificate_changes"`
	TechnologyChanges    []string `json:"technology_changes"`
	VulnerabilityChanges []string `json:"vulnerability_changes"`
}

type DifferentialPortScanner struct{}

func NewDifferentialPortScanner() *DifferentialPortScanner {
	return &DifferentialPortScanner{}
}

// Compare captures material scan-to-scan changes from persisted inventory
// evidence. A removed asset means it was absent from the later scan, not that
// the underlying system has necessarily been decommissioned.
func (d *DifferentialPortScanner) Compare(baseline, current []models.Asset, baselineFindings, currentFindings []models.Finding) DifferentialScanResult {
	result := d.CompareScanRuns(baseline, current)
	result.NewHosts, result.RemovedHosts = assetSetDiff(baseline, current, "host")
	result.ServiceChanges = changedParentValues(baseline, current, "service")
	result.CertificateChanges = changedParentValues(baseline, current, "tls_certificate")
	result.TechnologyChanges = changedParentValues(baseline, current, "technology")
	result.VulnerabilityChanges = findingSetDiff(baselineFindings, currentFindings)
	return result
}

func CompareStoredScans(ctx context.Context, db *store.SQLiteCLI, baselineID, currentID string) (DifferentialScanResult, error) {
	baselineAssets, err := db.Assets(ctx, baselineID)
	if err != nil {
		return DifferentialScanResult{}, err
	}
	currentAssets, err := db.Assets(ctx, currentID)
	if err != nil {
		return DifferentialScanResult{}, err
	}
	baselineFindings, err := db.Findings(ctx, baselineID)
	if err != nil {
		return DifferentialScanResult{}, err
	}
	currentFindings, err := db.Findings(ctx, currentID)
	if err != nil {
		return DifferentialScanResult{}, err
	}
	return NewDifferentialPortScanner().Compare(baselineAssets, currentAssets, baselineFindings, currentFindings), nil
}

func (d DifferentialScanResult) Markdown(baselineID, currentID string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Scan Change Report\n\nBaseline: `%s`  \nCurrent: `%s`\n", baselineID, currentID)
	writeChanges := func(title string, values []string) {
		fmt.Fprintf(&b, "\n## %s\n", title)
		if len(values) == 0 {
			b.WriteString("\nNo changes detected.\n")
			return
		}
		for _, value := range values {
			fmt.Fprintf(&b, "\n- %s", value)
		}
		b.WriteByte('\n')
	}
	writeChanges("New Hosts", d.NewHosts)
	writeChanges("Removed Hosts", d.RemovedHosts)
	writeChanges("New Open Ports", d.NewOpenPorts)
	writeChanges("Closed Ports", d.NewlyClosedPorts)
	writeChanges("Service Changes", d.ServiceChanges)
	writeChanges("Certificate Changes", d.CertificateChanges)
	writeChanges("Technology Changes", d.TechnologyChanges)
	writeChanges("Vulnerability Changes", d.VulnerabilityChanges)
	return b.String()
}

func WriteChangeReport(outputDir, baselineID, currentID string, result DifferentialScanResult) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(outputDir, fmt.Sprintf("%s-diff-from-%s.md", currentID, baselineID))
	return path, os.WriteFile(path, []byte(result.Markdown(baselineID, currentID)), 0644)
}

func assetSetDiff(baseline, current []models.Asset, typ string) ([]string, []string) {
	before, after := valuesByType(baseline, typ), valuesByType(current, typ)
	return setDifference(after, before), setDifference(before, after)
}

func valuesByType(assets []models.Asset, typ string) map[string]bool {
	result := make(map[string]bool)
	for _, asset := range assets {
		if asset.Type == typ {
			result[asset.Value] = true
		}
	}
	return result
}

func changedParentValues(baseline, current []models.Asset, typ string) []string {
	before, after := make(map[string]map[string]bool), make(map[string]map[string]bool)
	for _, asset := range baseline {
		if asset.Type == typ {
			if before[asset.Parent] == nil {
				before[asset.Parent] = map[string]bool{}
			}
			before[asset.Parent][asset.Value] = true
		}
	}
	for _, asset := range current {
		if asset.Type == typ {
			if after[asset.Parent] == nil {
				after[asset.Parent] = map[string]bool{}
			}
			after[asset.Parent][asset.Value] = true
		}
	}
	parents := make(map[string]bool)
	for parent := range before {
		parents[parent] = true
	}
	for parent := range after {
		parents[parent] = true
	}
	var changes []string
	for parent := range parents {
		if !sameSet(before[parent], after[parent]) {
			changes = append(changes, fmt.Sprintf("%s: %s -> %s", parent, setLabel(before[parent]), setLabel(after[parent])))
		}
	}
	sort.Strings(changes)
	return changes
}

func findingSetDiff(baseline, current []models.Finding) []string {
	before, after := make(map[string]bool), make(map[string]bool)
	for _, finding := range baseline {
		before[findingKey(finding)] = true
	}
	for _, finding := range current {
		after[findingKey(finding)] = true
	}
	var changes []string
	for key := range after {
		if !before[key] {
			changes = append(changes, "new: "+key)
		}
	}
	for key := range before {
		if !after[key] {
			changes = append(changes, "removed: "+key)
		}
	}
	sort.Strings(changes)
	return changes
}

func findingKey(f models.Finding) string { return nonEmpty(f.CVE, f.Title) + "@" + f.Asset }
func nonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
func sameSet(a, b map[string]bool) bool { return len(a) == len(b) && len(setDifference(a, b)) == 0 }
func setDifference(a, b map[string]bool) []string {
	var values []string
	for value := range a {
		if !b[value] {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}
func setLabel(values map[string]bool) string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func (d *DifferentialPortScanner) CompareScanRuns(baseline, current []models.Asset) DifferentialScanResult {
	baselinePorts := make(map[string]bool)
	currentPorts := make(map[string]bool)

	for _, a := range baseline {
		if a.Type == "open_port" {
			baselinePorts[a.Value] = true
		}
	}

	for _, a := range current {
		if a.Type == "open_port" {
			currentPorts[a.Value] = true
		}
	}

	var newOpen []string
	var newlyClosed []string

	for p := range currentPorts {
		if !baselinePorts[p] {
			newOpen = append(newOpen, p)
		}
	}

	for p := range baselinePorts {
		if !currentPorts[p] {
			newlyClosed = append(newlyClosed, p)
		}
	}

	return DifferentialScanResult{
		NewOpenPorts:     newOpen,
		NewlyClosedPorts: newlyClosed,
	}
}

func (d *DifferentialPortScanner) CreateDiffFindings(ctx context.Context, diff DifferentialScanResult, scanID string) []models.Finding {
	var findings []models.Finding
	for _, portVal := range diff.NewOpenPorts {
		findings = append(findings, models.Finding{
			ScanID:      scanID,
			Severity:    "medium",
			Confidence:  "high",
			Asset:       portVal,
			Title:       fmt.Sprintf("New Open Port Discovered (%s)", portVal),
			Evidence:    fmt.Sprintf("Port %s was closed in baseline scan and is now open", portVal),
			Remediation: "Verify whether this port exposure is intended.",
		})
	}
	return findings
}
