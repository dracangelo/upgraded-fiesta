package reporting

import (
	"fmt"
	"sort"
	"strings"

	"enumscan/internal/models"
)

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func sortedFindings(findings []models.Finding) []models.Finding {
	ordered := append([]models.Finding(nil), findings...)
	sort.SliceStable(ordered, func(i, j int) bool {
		left, leftKnown := severityRank[strings.ToLower(ordered[i].Severity)]
		right, rightKnown := severityRank[strings.ToLower(ordered[j].Severity)]
		if !leftKnown {
			left = len(severityRank)
		}
		if !rightKnown {
			right = len(severityRank)
		}
		if left != right {
			return left < right
		}
		if ordered[i].KEV != ordered[j].KEV {
			return ordered[i].KEV
		}
		return ordered[i].Title < ordered[j].Title
	})
	return ordered
}

func severityCounts(findings []models.Finding) map[string]int {
	counts := make(map[string]int)
	for _, finding := range findings {
		severity := strings.ToLower(strings.TrimSpace(finding.Severity))
		if severity == "" {
			severity = "unclassified"
		}
		counts[severity]++
	}
	return counts
}

// ExecutiveSummary is deterministic and evidence-only: it never infers
// compromise, business impact, or exploitation from enumeration results.
func ExecutiveSummary(r report) string {
	counts, ordered := severityCounts(r.Findings), sortedFindings(r.Findings)
	var b strings.Builder
	fmt.Fprintf(&b, "# Executive Summary: %s\n\n", r.ScanID)
	b.WriteString("This local summary is generated from persisted enumeration evidence. It does not assert compromise or exploitation.\n\n")
	fmt.Fprintf(&b, "## Exposure Snapshot\n\n- Assets recorded: %d\n- Findings recorded: %d\n- Critical: %d\n- High: %d\n- Medium: %d\n- Low: %d\n- Informational: %d\n\n", len(r.Assets), len(r.Findings), counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"])
	b.WriteString("## Priority Review\n\n")
	if len(ordered) == 0 {
		b.WriteString("No findings were recorded for this scan.\n")
		return b.String()
	}
	for index, finding := range ordered {
		if index == 5 {
			break
		}
		verification := finding.Verification
		if verification == "" {
			verification = "not stated"
		}
		fmt.Fprintf(&b, "%d. **%s** — %s severity; %s evidence; asset `%s`.\n", index+1, finding.Title, finding.Severity, verification, finding.Asset)
		if finding.Remediation != "" {
			fmt.Fprintf(&b, "   Recommended action: %s\n", finding.Remediation)
		}
	}
	return b.String()
}

// TechnicalSummary presents persisted asset categories and findings for
// engineering triage while retaining every recorded verification state.
func TechnicalSummary(r report) string {
	types := make(map[string]int)
	for _, asset := range r.Assets {
		types[asset.Type]++
	}
	typeNames := make([]string, 0, len(types))
	for name := range types {
		typeNames = append(typeNames, name)
	}
	sort.Strings(typeNames)
	var b strings.Builder
	fmt.Fprintf(&b, "# Technical Summary: %s\n\n", r.ScanID)
	b.WriteString("All items below are persisted scan evidence. Review heuristic findings before treating them as confirmed.\n\n## Asset Categories\n\n")
	if len(typeNames) == 0 {
		b.WriteString("No assets recorded.\n\n")
	} else {
		for _, name := range typeNames {
			fmt.Fprintf(&b, "- `%s`: %d\n", name, types[name])
		}
		b.WriteString("\n")
	}
	b.WriteString("## Findings for Triage\n\n")
	for _, finding := range sortedFindings(r.Findings) {
		verification := finding.Verification
		if verification == "" {
			verification = "not stated"
		}
		fmt.Fprintf(&b, "### %s\n\n- Severity: %s\n- Verification: %s\n- Asset: `%s`\n", finding.Title, finding.Severity, verification, finding.Asset)
		if finding.CVE != "" {
			fmt.Fprintf(&b, "- CVE: %s\n", finding.CVE)
		}
		if finding.KEV {
			b.WriteString("- CISA KEV: listed\n")
		}
		if finding.Evidence != "" {
			fmt.Fprintf(&b, "- Evidence: %s\n", finding.Evidence)
		}
		if finding.Remediation != "" {
			fmt.Fprintf(&b, "- Remediation: %s\n", finding.Remediation)
		}
		b.WriteString("\n")
	}
	if len(r.Findings) == 0 {
		b.WriteString("No findings recorded.\n")
	}
	return b.String()
}
