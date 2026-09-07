package reporting

import (
	"fmt"
	"sort"
	"strings"

	"enumscan/internal/models"
)

// TriageReport derives local, evidence-backed next steps. It limits guidance to
// verification, remediation, and scoped enumeration; it never recommends
// credential attacks, exploitation, or out-of-scope activity.
func TriageReport(r report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Evidence Triage: %s\n\n", r.ScanID)
	b.WriteString("This deterministic report is based only on stored evidence. Carry out every next step within the written authorization for this engagement.\n\n")
	b.WriteString("## Finding Rationale and Priority\n\n")
	ordered := sortedFindings(r.Findings)
	if len(ordered) == 0 {
		b.WriteString("No findings were recorded. Continue only with the approved discovery and inventory plan.\n\n")
	} else {
		for _, finding := range ordered {
			verification := finding.Verification
			if verification == "" {
				verification = "not stated"
			}
			fmt.Fprintf(&b, "- **%s** on `%s`: %s severity, %s evidence.", finding.Title, finding.Asset, finding.Severity, verification)
			if finding.KEV {
				b.WriteString(" The associated CVE is listed in CISA KEV.")
			}
			if strings.EqualFold(verification, "heuristic") {
				b.WriteString(" Validate the indicator with a non-destructive, scoped observation before prioritizing remediation.")
			}
			if finding.Remediation != "" {
				fmt.Fprintf(&b, " Recommended remediation: %s", finding.Remediation)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	steps := safeNextSteps(r.Assets, r.Findings)
	b.WriteString("## Safe Next Enumeration Steps\n\n")
	if len(steps) == 0 {
		b.WriteString("No additional next steps were inferred from the stored asset categories.\n")
	} else {
		for index, step := range steps {
			fmt.Fprintf(&b, "%d. %s\n", index+1, step)
		}
	}
	b.WriteString("\n## Evidence Relationship Narratives\n\n")
	for _, narrative := range evidenceNarratives(r.Assets, r.Findings) {
		fmt.Fprintf(&b, "- %s\n", narrative)
	}
	return b.String()
}

func evidenceNarratives(assets []models.Asset, findings []models.Finding) []string {
	parents := make(map[string]string)
	for _, asset := range assets {
		if asset.Value != "" && asset.Parent != "" {
			parents[asset.Value] = asset.Parent
		}
	}
	narratives := make([]string, 0, len(findings))
	for _, finding := range sortedFindings(findings) {
		verification := finding.Verification
		if verification == "" {
			verification = "not stated"
		}
		chain := "`" + finding.Asset + "`"
		if parent := parents[finding.Asset]; parent != "" {
			chain = "`" + parent + "` → " + chain
		}
		narratives = append(narratives, chain+" is associated with **"+finding.Title+"** ("+verification+" evidence). Review this relationship as a triage aid; it is not proof of reachability, compromise, or exploitability.")
		if len(narratives) == 10 {
			break
		}
	}
	if len(narratives) == 0 {
		return []string{"No persisted finding-to-asset relationships are available for a narrative."}
	}
	return narratives
}

func safeNextSteps(assets []models.Asset, findings []models.Finding) []string {
	types := make(map[string]bool)
	for _, asset := range assets {
		types[strings.ToLower(asset.Type)] = true
	}
	steps := make(map[string]bool)
	if types["host"] || types["live_host"] || types["ip"] || types["hostname"] {
		steps["Confirm that the inventory is complete for the authorized scope, then compare this scan with an approved baseline for net-new hosts."] = true
	}
	if types["open_port"] || types["port_observation"] || types["service"] || types["service_fingerprint"] {
		steps["Review observed service fingerprints and banners, and confirm ownership and intended exposure for each reachable service."] = true
	}
	if types["http_response"] || types["http_url"] || types["tls_certificate"] || types["technology"] || types["wappalyzer"] {
		steps["Use the scoped HTTP and TLS inventory to review security headers, certificate names, robots/sitemap references, and documented API surfaces."] = true
	}
	if types["secret_exposure"] || types["secret_indicator"] {
		steps["Treat secret indicators as sensitive: verify the redacted fingerprint with the asset owner, rotate confirmed exposed material, and avoid transmitting values to third parties."] = true
	}
	for _, finding := range findings {
		if strings.EqualFold(finding.Verification, "heuristic") {
			steps["Prioritize non-destructive confirmation of heuristic findings before escalating them as confirmed risk."] = true
		}
		if strings.EqualFold(finding.Severity, "critical") || strings.EqualFold(finding.Severity, "high") {
			steps["Assign high-severity findings to the relevant system owner and track remediation against the recorded asset and evidence."] = true
		}
	}
	ordered := make([]string, 0, len(steps))
	for step := range steps {
		ordered = append(ordered, step)
	}
	sort.Strings(ordered)
	return ordered
}
