package inventory

import (
	"context"
	"fmt"
	"time"

	"enumscan/internal/models"
)

// DemoDataset holds synthetic, safe demonstration assets, findings, and events.
type DemoDataset struct {
	ScanRun  models.ScanRun   `json:"scan_run"`
	Assets   []models.Asset   `json:"assets"`
	Findings []models.Finding `json:"findings"`
	Events   []models.Event   `json:"events"`
}

// GenerateSanitizedDemoDataset produces realistic, fully synthetic evaluation data
// using RFC 5737 documentation networks (198.51.100.0/24) and RFC 2606 reserved domains.
// It generates zero external network traffic.
func GenerateSanitizedDemoDataset(scanID string) DemoDataset {
	if scanID == "" {
		scanID = "demo-scan-rfc5737"
	}
	now := time.Now().UTC()
	startedAt := now.Add(-15 * time.Minute)
	finishedAt := now

	scanRun := models.ScanRun{
		ScanID:     scanID,
		StartedAt:  startedAt,
		FinishedAt: &finishedAt,
		Status:     "completed",
	}

	assets := []models.Asset{
		{
			ScanID:    scanID,
			Type:      "ipv4",
			Value:     "198.51.100.10",
			CreatedAt: startedAt.Add(1 * time.Minute),
		},
		{
			ScanID:    scanID,
			Type:      "domain",
			Value:     "gateway.example.internal",
			CreatedAt: startedAt.Add(2 * time.Minute),
		},
		{
			ScanID:    scanID,
			Type:      "ipv4",
			Value:     "198.51.100.15",
			CreatedAt: startedAt.Add(3 * time.Minute),
		},
		{
			ScanID:    scanID,
			Type:      "domain",
			Value:     "web-portal.example.internal",
			CreatedAt: startedAt.Add(4 * time.Minute),
		},
		{
			ScanID:    scanID,
			Type:      "ipv4",
			Value:     "198.51.100.20",
			CreatedAt: startedAt.Add(5 * time.Minute),
		},
		{
			ScanID:    scanID,
			Type:      "domain",
			Value:     "db-primary.example.internal",
			CreatedAt: startedAt.Add(6 * time.Minute),
		},
	}

	findings := []models.Finding{
		{
			ID:          1001,
			ScanID:      scanID,
			Title:       "Outdated OpenSSH with Terrapin Attack Vulnerability",
			Asset:       "198.51.100.10:22",
			Severity:    "medium",
			Confidence:  "confirmed",
			CVE:         "CVE-2023-48795",
			CWE:         "CWE-310",
			CVSS:        5.9,
			EPSS:        0.72,
			Evidence:    "Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\nSupported ciphers: chacha20-poly1305@openssh.com",
			Remediation: "Upgrade OpenSSH to version 9.6p1 or newer, or disable ChaCha20-Poly1305 and CBC ciphers.",
			References:  []string{"https://terrapin-attack.com", "https://nvd.nist.gov/vuln/detail/CVE-2023-48795"},
			CreatedAt:   startedAt.Add(7 * time.Minute),
		},
		{
			ID:          1002,
			ScanID:      scanID,
			Title:       "Missing HTTP Strict-Transport-Security Header",
			Asset:       "web-portal.example.internal:443",
			Severity:    "low",
			Confidence:  "confirmed",
			CWE:         "CWE-319",
			CVSS:        3.1,
			Evidence:    "HTTP/1.1 200 OK\nServer: nginx/1.24.0\nStrict-Transport-Security header is absent",
			Remediation: "Configure Strict-Transport-Security response header with max-age >= 31536000 and includeSubDomains.",
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
			CreatedAt:   startedAt.Add(8 * time.Minute),
		},
		{
			ID:          1003,
			ScanID:      scanID,
			Title:       "Unauthenticated Redis Server Exposed to Documentation Network",
			Asset:       "198.51.100.20:6379",
			Severity:    "critical",
			Confidence:  "confirmed",
			CWE:         "CWE-306",
			CVSS:        9.8,
			EPSS:        0.91,
			Evidence:    "REDIS INFO response: redis_version:7.0.5 os:Linux 5.15\nCommand PING -> PONG (No authentication required)",
			Remediation: "Enable requirepass authentication and bind Redis strictly to localhost or protected internal VLAN.",
			References:  []string{"https://redis.io/docs/management/security/"},
			CreatedAt:   startedAt.Add(9 * time.Minute),
		},
	}

	events := []models.Event{
		{
			ID:     1,
			ScanID: scanID,
			Type:   "scan_started",
			Target: "198.51.100.0/28",
			Data:   map[string]string{"message": "Authorized reconnaissance started on synthetic scope 198.51.100.0/28"},
		},
		{
			ID:     2,
			ScanID: scanID,
			Type:   "port_discovered",
			Target: "198.51.100.10",
			Data:   map[string]string{"message": "Open TCP ports discovered: 22, 80, 443, 6379"},
		},
		{
			ID:     3,
			ScanID: scanID,
			Type:   "scan_completed",
			Target: "198.51.100.0/28",
			Data:   map[string]string{"message": "Synthetic demonstration scan finished with 3 findings recorded"},
		},
	}

	return DemoDataset{
		ScanRun:  scanRun,
		Assets:   assets,
		Findings: findings,
		Events:   events,
	}
}

// EvidenceStore defines the minimal persistence interface required to seed the demo dataset.
type EvidenceStore interface {
	StartScan(ctx context.Context, scanID string) error
	FinishScan(ctx context.Context, scanID, status, message string) error
	AddAsset(ctx context.Context, asset models.Asset) error
	AddFinding(ctx context.Context, finding models.Finding) error
	AddEvent(ctx context.Context, event models.Event) (int64, error)
}

// SeedDemoDataset inserts the synthetic dataset into the given evidence store.
func SeedDemoDataset(ctx context.Context, store EvidenceStore, scanID string) (DemoDataset, error) {
	data := GenerateSanitizedDemoDataset(scanID)

	if err := store.StartScan(ctx, data.ScanRun.ScanID); err != nil {
		return data, fmt.Errorf("failed starting demo scan run: %w", err)
	}

	for _, asset := range data.Assets {
		if err := store.AddAsset(ctx, asset); err != nil {
			return data, fmt.Errorf("failed adding demo asset: %w", err)
		}
	}

	for _, finding := range data.Findings {
		if err := store.AddFinding(ctx, finding); err != nil {
			return data, fmt.Errorf("failed adding demo finding: %w", err)
		}
	}

	for _, event := range data.Events {
		if _, err := store.AddEvent(ctx, event); err != nil {
			return data, fmt.Errorf("failed adding demo event: %w", err)
		}
	}

	if err := store.FinishScan(ctx, data.ScanRun.ScanID, data.ScanRun.Status, ""); err != nil {
		return data, fmt.Errorf("failed finishing demo scan run: %w", err)
	}

	return data, nil
}
