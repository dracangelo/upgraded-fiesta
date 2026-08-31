package inventory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"enumscan/internal/store"
)

type TimelineEntry struct {
	Timestamp string `json:"timestamp"`
	Category  string `json:"category"`
	Target    string `json:"target"`
	Event     string `json:"event"`
	Details   string `json:"details"`
}

type DriftReport struct {
	BaselineScanID string                   `json:"baseline_scan_id"`
	CurrentScanID  string                   `json:"current_scan_id"`
	DriftDetected  bool                     `json:"drift_detected"`
	Changes        DifferentialScanResult `json:"changes"`
	DriftItems     []string                 `json:"drift_items"`
}

type ChangeReportSummary struct {
	ReportType string   `json:"report_type"`
	Period     string   `json:"period"`
	TotalScans int      `json:"total_scans"`
	NewAssets  int      `json:"new_assets"`
	NewFindings int     `json:"new_findings"`
	DriftEvents []string `json:"drift_events"`
}

type TimelineEngine struct {
	db *store.SQLiteCLI
}

func NewTimelineEngine(db *store.SQLiteCLI) *TimelineEngine {
	return &TimelineEngine{db: db}
}

func (t *TimelineEngine) BuildTimeline(ctx context.Context, scanID, category string) ([]TimelineEntry, error) {
	category = strings.ToLower(strings.TrimSpace(category))
	if category == "" {
		category = "all"
	}

	events, err := t.db.Events(ctx, scanID)
	if err != nil {
		return nil, err
	}
	assets, err := t.db.Assets(ctx, scanID)
	if err != nil {
		return nil, err
	}
	findings, err := t.db.Findings(ctx, scanID)
	if err != nil {
		return nil, err
	}

	var entries []TimelineEntry

	for _, a := range assets {
		catMatch := false
		switch category {
		case "host":
			catMatch = a.Type == "subdomain" || a.Type == "ip" || a.Type == "domain" || a.Type == "host"
		case "service":
			catMatch = a.Type == "port" || a.Type == "service" || a.Type == "url"
		case "certificate":
			catMatch = a.Type == "certificate" || a.Type == "tls"
		case "technology":
			catMatch = a.Type == "technology" || a.Type == "framework"
		case "all":
			catMatch = true
		}
		if catMatch {
			entries = append(entries, TimelineEntry{
				Timestamp: a.CreatedAt.Format(time.RFC3339),
				Category:  a.Type,
				Target:    a.Value,
				Event:     "Asset Discovered",
				Details:   fmt.Sprintf("Parent: %s | Metadata: %s", a.Parent, a.Metadata),
			})
		}
	}

	for _, f := range findings {
		catMatch := false
		switch category {
		case "vulnerability":
			catMatch = true
		case "secret":
			catMatch = strings.Contains(strings.ToLower(f.Title), "secret") || strings.Contains(strings.ToLower(f.Title), "token") || strings.Contains(strings.ToLower(f.Title), "key")
		case "all":
			catMatch = true
		}
		if catMatch {
			entries = append(entries, TimelineEntry{
				Timestamp: f.CreatedAt.Format(time.RFC3339),
				Category:  "finding",
				Target:    f.Asset,
				Event:     fmt.Sprintf("[%s] %s", strings.ToUpper(f.Severity), f.Title),
				Details:   fmt.Sprintf("CVE: %s | Evidence: %s", f.CVE, f.Evidence),
			})
		}
	}

	for _, e := range events {
		if category == "all" || category == "event" {
			entries = append(entries, TimelineEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Category:  "event",
				Target:    e.Target,
				Event:     e.Type,
				Details:   fmt.Sprintf("ScanID: %s", e.ScanID),
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp > entries[j].Timestamp
	})

	return entries, nil
}

func (t *TimelineEngine) DetectDrift(ctx context.Context, baselineID, currentID string) (DriftReport, error) {
	diff, err := CompareStoredScans(ctx, t.db, baselineID, currentID)
	if err != nil {
		return DriftReport{}, err
	}

	var driftItems []string
	for _, p := range diff.NewOpenPorts {
		driftItems = append(driftItems, "New Open Port: "+p)
	}
	for _, p := range diff.NewlyClosedPorts {
		driftItems = append(driftItems, "Port Closed: "+p)
	}
	for _, h := range diff.NewHosts {
		driftItems = append(driftItems, "New Host Discovered: "+h)
	}
	for _, h := range diff.RemovedHosts {
		driftItems = append(driftItems, "Host Removed/Unreachable: "+h)
	}
	driftItems = append(driftItems, diff.ServiceChanges...)
	driftItems = append(driftItems, diff.CertificateChanges...)
	driftItems = append(driftItems, diff.TechnologyChanges...)
	driftItems = append(driftItems, diff.VulnerabilityChanges...)

	return DriftReport{
		BaselineScanID: baselineID,
		CurrentScanID:  currentID,
		DriftDetected:  len(driftItems) > 0,
		Changes:        diff,
		DriftItems:     driftItems,
	}, nil
}

func (t *TimelineEngine) GenerateChangeReport(ctx context.Context, reportType, scanID string) (ChangeReportSummary, error) {
	assets, err := t.db.Assets(ctx, scanID)
	if err != nil {
		return ChangeReportSummary{}, err
	}
	findings, err := t.db.Findings(ctx, scanID)
	if err != nil {
		return ChangeReportSummary{}, err
	}

	period := "24 Hours (Daily)"
	if reportType == "weekly" {
		period = "7 Days (Weekly)"
	}

	var driftEvents []string
	if len(assets) > 0 {
		driftEvents = append(driftEvents, fmt.Sprintf("%d total inventory assets monitored", len(assets)))
	}
	if len(findings) > 0 {
		driftEvents = append(driftEvents, fmt.Sprintf("%d vulnerability findings recorded", len(findings)))
	}

	return ChangeReportSummary{
		ReportType:  reportType,
		Period:      period,
		TotalScans:  1,
		NewAssets:   len(assets),
		NewFindings: len(findings),
		DriftEvents: driftEvents,
	}, nil
}
