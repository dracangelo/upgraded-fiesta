package reporting

import (
	"fmt"
	"html"
	"strings"
)

func ExportHTML(r report) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>enumscan Report - ` + html.EscapeString(r.ScanID) + `</title>
    <style>
        :root {
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --accent: #58a6ff;
            --critical: #f85149;
            --high: #ff7b72;
            --medium: #d29922;
            --low: #3fb950;
            --info: #8b949e;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); borderRadius: 8px; padding: 20px; margin-bottom: 16px; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; text-transform: uppercase; }
        .badge-critical { background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid var(--critical); }
        .badge-high { background: rgba(255,123,114,0.15); color: var(--high); border: 1px solid var(--high); }
        .badge-medium { background: rgba(210,153,34,0.15); color: var(--medium); border: 1px solid var(--medium); }
        .badge-low { background: rgba(63,185,80,0.15); color: var(--low); border: 1px solid var(--low); }
        .badge-info { background: rgba(139,148,158,0.15); color: var(--info); border: 1px solid var(--info); }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; }
        th, td { border: 1px solid var(--border); padding: 8px 12px; text-align: left; }
        th { background: #21262d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>enumscan Security Assessment Report</h1>
            <p>Scan ID: <code>` + html.EscapeString(r.ScanID) + `</code></p>
        </div>
        <h2>Vulnerability Findings (` + fmt.Sprintf("%d", len(r.Findings)) + `)</h2>
`)

	if len(r.Findings) == 0 {
		b.WriteString("<p>No vulnerabilities identified.</p>")
	} else {
		for _, f := range r.Findings {
			sevClass := "badge-info"
			switch strings.ToLower(f.Severity) {
			case "critical":
				sevClass = "badge-critical"
			case "high":
				sevClass = "badge-high"
			case "medium":
				sevClass = "badge-medium"
			case "low":
				sevClass = "badge-low"
			}
			fmt.Fprintf(&b, `<div class="card">
                <h3>%s <span class="badge %s">%s</span></h3>
                <p><strong>Asset:</strong> <code>%s</code> | <strong>Confidence:</strong> %s</p>
`, html.EscapeString(f.Title), sevClass, html.EscapeString(f.Severity), html.EscapeString(f.Asset), html.EscapeString(f.Confidence))

			if f.CVE != "" {
				fmt.Fprintf(&b, "<p><strong>CVE:</strong> %s | <strong>CWE:</strong> %s | <strong>CVSS:</strong> %.1f</p>\n", html.EscapeString(f.CVE), html.EscapeString(f.CWE), f.CVSS)
			}
			fmt.Fprintf(&b, `<p><strong>Evidence:</strong> <code>%s</code></p>
                <p><strong>Remediation:</strong> %s</p>
            </div>`, html.EscapeString(f.Evidence), html.EscapeString(f.Remediation))
		}
	}

	b.WriteString(`<h2>Discovered Assets (` + fmt.Sprintf("%d", len(r.Assets)) + `)</h2>
        <table>
            <tr><th>Type</th><th>Value</th><th>Parent</th></tr>
`)

	for _, a := range r.Assets {
		fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td></tr>`, html.EscapeString(a.Type), html.EscapeString(a.Value), html.EscapeString(a.Parent))
	}

	b.WriteString(`</table>
    </div>
</body>
</html>`)

	return b.String()
}
