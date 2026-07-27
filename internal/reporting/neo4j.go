package reporting

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Neo4jNode struct {
	ID         string            `json:"id"`
	Label      string            `json:"label"`
	Properties map[string]string `json:"properties"`
}

type Neo4jEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
}

type Neo4jGraph struct {
	Nodes []Neo4jNode `json:"nodes"`
	Edges []Neo4jEdge `json:"edges"`
}

func ExportNeo4jCypher(r report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "// Neo4j Cypher Graph Export for Scan ID: %s\n\n", r.ScanID)
	fmt.Fprintf(&b, "MERGE (s:Scan {id: %q})\n", r.ScanID)

	// Create Assets
	for _, a := range r.Assets {
		nodeVar := sanitizeVarName(fmt.Sprintf("asset_%d", a.ID))
		label := "Asset"
		switch a.Type {
		case "host":
			label = "Host"
		case "service", "service_version":
			label = "Service"
		case "cloud_asset", "cloud_storage_bucket", "cloud_infrastructure":
			label = "CloudAsset"
		case "attack_path":
			label = "AttackPath"
		}

		fmt.Fprintf(&b, "MERGE (%s:%s {id: %q, value: %q, type: %q})\n", nodeVar, label, fmt.Sprintf("%s-%d", a.Type, a.ID), a.Value, a.Type)
		fmt.Fprintf(&b, "MERGE (s)-[:HAS_ASSET]->(%s)\n", nodeVar)

		if a.Parent != "" {
			parentVar := sanitizeVarName("parent_" + a.Parent)
			fmt.Fprintf(&b, "MERGE (%s:Asset {value: %q})\n", parentVar, a.Parent)
			fmt.Fprintf(&b, "MERGE (%s)-[:HAS_CHILD]->(%s)\n", parentVar, nodeVar)
		}
	}

	// Create Findings
	for _, f := range r.Findings {
		findVar := sanitizeVarName(fmt.Sprintf("finding_%d", f.ID))
		fmt.Fprintf(&b, "MERGE (%s:Finding {id: %d, title: %q, severity: %q, cve: %q, cvss: %f})\n",
			findVar, f.ID, f.Title, f.Severity, f.CVE, f.CVSS)

		assetVar := sanitizeVarName("parent_" + f.Asset)
		fmt.Fprintf(&b, "MERGE (%s:Asset {value: %q})\n", assetVar, f.Asset)
		fmt.Fprintf(&b, "MERGE (%s)-[:HAS_FINDING]->(%s)\n", assetVar, findVar)

		if f.CVE != "" {
			cveVar := sanitizeVarName("cve_" + f.CVE)
			fmt.Fprintf(&b, "MERGE (%s:Vulnerability {id: %q, cwe: %q, cvss: %f, epss: %f, kev: %t})\n",
				cveVar, f.CVE, f.CWE, f.CVSS, f.EPSS, f.KEV)
			fmt.Fprintf(&b, "MERGE (%s)-[:HAS_CVE]->(%s)\n", findVar, cveVar)
		}
	}

	return b.String()
}

func ExportNeo4jJSON(r report) ([]byte, error) {
	graph := Neo4jGraph{}
	nodeMap := make(map[string]bool)

	// Add Scan Node
	graph.Nodes = append(graph.Nodes, Neo4jNode{
		ID:    r.ScanID,
		Label: "Scan",
		Properties: map[string]string{
			"scan_id": r.ScanID,
		},
	})

	for _, a := range r.Assets {
		assetID := fmt.Sprintf("asset-%d", a.ID)
		if !nodeMap[assetID] {
			nodeMap[assetID] = true
			graph.Nodes = append(graph.Nodes, Neo4jNode{
				ID:    assetID,
				Label: "Asset",
				Properties: map[string]string{
					"value":    a.Value,
					"type":     a.Type,
					"parent":   a.Parent,
					"metadata": a.Metadata,
				},
			})
			graph.Edges = append(graph.Edges, Neo4jEdge{
				Source: r.ScanID,
				Target: assetID,
				Type:   "HAS_ASSET",
			})
		}
	}

	for _, f := range r.Findings {
		findID := fmt.Sprintf("finding-%d", f.ID)
		if !nodeMap[findID] {
			nodeMap[findID] = true
			graph.Nodes = append(graph.Nodes, Neo4jNode{
				ID:    findID,
				Label: "Finding",
				Properties: map[string]string{
					"title":       f.Title,
					"severity":    f.Severity,
					"confidence":  f.Confidence,
					"cve":         f.CVE,
					"cwe":         f.CWE,
					"cvss":        fmt.Sprintf("%.1f", f.CVSS),
					"remediation": f.Remediation,
				},
			})
		}
	}

	return json.MarshalIndent(graph, "", "  ")
}

func sanitizeVarName(v string) string {
	v = strings.ReplaceAll(v, "-", "_")
	v = strings.ReplaceAll(v, ".", "_")
	v = strings.ReplaceAll(v, ":", "_")
	v = strings.ReplaceAll(v, "/", "_")
	return "n_" + v
}
