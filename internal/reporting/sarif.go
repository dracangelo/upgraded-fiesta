package reporting

import (
	"encoding/json"
	"fmt"
	"strings"
)

type SarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	ShortDescription SarifMultiformatText `json:"shortDescription"`
	FullDescription  SarifMultiformatText `json:"fullDescription,omitempty"`
	Help             SarifMultiformatText `json:"help,omitempty"`
	Properties       map[string]any       `json:"properties,omitempty"`
}

type SarifResult struct {
	RuleID    string               `json:"ruleId"`
	Level     string               `json:"level"`
	Message   SarifMultiformatText `json:"message"`
	Locations []SarifLocation      `json:"locations,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifMultiformatText struct {
	Text string `json:"text"`
}

func ExportSARIF(r report) ([]byte, error) {
	rulesMap := make(map[string]SarifRule)
	var results []SarifResult

	for _, f := range r.Findings {
		ruleID := f.CVE
		if ruleID == "" {
			ruleID = f.CWE
		}
		if ruleID == "" {
			ruleID = fmt.Sprintf("ENUMSCAN-%d", f.ID)
		}

		if _, exists := rulesMap[ruleID]; !exists {
			props := map[string]any{
				"severity":   f.Severity,
				"confidence": f.Confidence,
			}
			if f.CVSS > 0 {
				props["cvss"] = f.CVSS
			}
			if f.EPSS > 0 {
				props["epss"] = f.EPSS
			}
			if f.KEV {
				props["kev"] = true
			}

			rulesMap[ruleID] = SarifRule{
				ID:               ruleID,
				Name:             f.Title,
				ShortDescription: SarifMultiformatText{Text: f.Title},
				FullDescription:  SarifMultiformatText{Text: f.Evidence},
				Help:             SarifMultiformatText{Text: f.Remediation},
				Properties:       props,
			}
		}

		level := severityToSarifLevel(f.Severity)
		locURI := f.Asset
		if !strings.Contains(locURI, "/") && !strings.Contains(locURI, "\\") {
			locURI = "network://" + locURI
		}

		results = append(results, SarifResult{
			RuleID:  ruleID,
			Level:   level,
			Message: SarifMultiformatText{Text: fmt.Sprintf("%s - Evidence: %s", f.Title, f.Evidence)},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{URI: locURI},
					},
				},
			},
		})
	}

	rules := make([]SarifRule, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	reportObj := SarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "enumscan",
						Version:        "1.0.0",
						InformationURI: "https://github.com/dracangelo/upgraded-fiesta",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(reportObj, "", "  ")
}

func severityToSarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "none"
	}
}
