package inventory

import (
	"context"
	"fmt"

	"enumscan/internal/models"
)

type DifferentialScanResult struct {
	NewOpenPorts     []string `json:"new_open_ports"`
	NewlyClosedPorts []string `json:"newly_closed_ports"`
}

type DifferentialPortScanner struct{}

func NewDifferentialPortScanner() *DifferentialPortScanner {
	return &DifferentialPortScanner{}
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
