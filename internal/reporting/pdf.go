package reporting

import (
	"fmt"
	"strings"
)

func ExportPDFText(r report) []byte {
	var b strings.Builder
	b.WriteString("%PDF-1.4 Executive Report Format\n")
	b.WriteString(fmt.Sprintf("===================================================\n"))
	b.WriteString(fmt.Sprintf(" ENUMSCAN SECURITY ASSESSMENT EXECUTIVE REPORT     \n"))
	b.WriteString(fmt.Sprintf(" Scan ID: %s                                       \n", r.ScanID))
	b.WriteString(fmt.Sprintf("===================================================\n\n"))

	b.WriteString(fmt.Sprintf("1. SUMMARY STATISTICS\n"))
	b.WriteString(fmt.Sprintf("   Total Assets Discovered: %d\n", len(r.Assets)))
	b.WriteString(fmt.Sprintf("   Total Vulnerabilities:   %d\n\n", len(r.Findings)))

	b.WriteString(fmt.Sprintf("2. FINDINGS DETAILS\n"))
	if len(r.Findings) == 0 {
		b.WriteString("   No findings reported.\n")
	}
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("   [%d] %s (%s, %s)\n", i+1, f.Title, strings.ToUpper(f.Severity), f.Confidence))
		b.WriteString(fmt.Sprintf("       Asset:       %s\n", f.Asset))
		if f.CVE != "" {
			b.WriteString(fmt.Sprintf("       CVE/CWE:     %s / %s (CVSS: %.1f)\n", f.CVE, f.CWE, f.CVSS))
		}
		b.WriteString(fmt.Sprintf("       Remediation: %s\n\n", f.Remediation))
	}

	b.WriteString(fmt.Sprintf("3. ASSET INVENTORY\n"))
	for _, a := range r.Assets {
		b.WriteString(fmt.Sprintf("   - [%s] %s\n", a.Type, a.Value))
	}

	return []byte(b.String())
}
