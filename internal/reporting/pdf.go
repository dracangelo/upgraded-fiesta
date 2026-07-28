package reporting

import (
	"bytes"
	"fmt"
	"strings"
)

func ExportPDFText(r report) []byte {
	var body bytes.Buffer

	// Build plain text report text
	var textBuf strings.Builder
	textBuf.WriteString(fmt.Sprintf("ENUMSCAN SECURITY ASSESSMENT EXECUTIVE REPORT\\n"))
	textBuf.WriteString(fmt.Sprintf("Scan ID: %s\\n", r.ScanID))
	textBuf.WriteString(fmt.Sprintf("--------------------------------------------------\\n"))
	textBuf.WriteString(fmt.Sprintf("Summary: Assets (%d), Findings (%d)\\n\\n", len(r.Assets), len(r.Findings)))

	textBuf.WriteString(fmt.Sprintf("FINDINGS DETAILS:\\n"))
	if len(r.Findings) == 0 {
		textBuf.WriteString("  No findings reported.\\n")
	}
	for i, f := range r.Findings {
		textBuf.WriteString(fmt.Sprintf("  [%d] %s (%s, %s)\\n", i+1, cleanPDFText(f.Title), strings.ToUpper(f.Severity), f.Confidence))
		textBuf.WriteString(fmt.Sprintf("      Asset: %s\\n", cleanPDFText(f.Asset)))
		if f.CVE != "" {
			textBuf.WriteString(fmt.Sprintf("      CVE: %s (CVSS: %.1f)\\n", f.CVE, f.CVSS))
		}
		textBuf.WriteString(fmt.Sprintf("      Remediation: %s\\n", cleanPDFText(f.Remediation)))
	}

	textBuf.WriteString(fmt.Sprintf("\\nASSET INVENTORY:\\n"))
	for _, a := range r.Assets {
		textBuf.WriteString(fmt.Sprintf("  - [%s] %s\\n", a.Type, cleanPDFText(a.Value)))
	}

	rawLines := strings.Split(textBuf.String(), "\\n")
	var streamContent bytes.Buffer
	streamContent.WriteString("BT\n/F1 10 Tf\n20 750 Td\n14 TL\n")
	for _, line := range rawLines {
		streamContent.WriteString(fmt.Sprintf("(%s) '\n", line))
	}
	streamContent.WriteString("ET\n")

	streamBytes := streamContent.Bytes()

	// PDF 1.4 Structure Objects
	body.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	var offsets []int

	// Obj 1: Catalog
	offsets = append(offsets, body.Len())
	body.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	// Obj 2: Pages
	offsets = append(offsets, body.Len())
	body.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	// Obj 3: Page
	offsets = append(offsets, body.Len())
	body.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n")

	// Obj 4: Font
	offsets = append(offsets, body.Len())
	body.WriteString("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

	// Obj 5: Stream Contents
	offsets = append(offsets, body.Len())
	body.WriteString(fmt.Sprintf("5 0 obj\n<< /Length %d >>\nstream\n", len(streamBytes)))
	body.Write(streamBytes)
	body.WriteString("\nendstream\nendobj\n")

	// Cross-Reference Table
	xrefOffset := body.Len()
	body.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for _, off := range offsets {
		body.WriteString(fmt.Sprintf("%010d 00000 n \n", off))
	}

	// Trailer
	body.WriteString(fmt.Sprintf("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xrefOffset))

	return body.Bytes()
}

func cleanPDFText(s string) string {
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
