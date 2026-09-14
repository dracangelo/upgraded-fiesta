package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"enumscan/internal/store"
)

// WebhookPayload is the bounded evidence summary sent only by the explicit
// notify-webhook command. It never includes credentials or raw HTTP bodies.
type WebhookPayload struct {
	Event        string         `json:"event"`
	ScanID       string         `json:"scan_id"`
	GeneratedAt  time.Time      `json:"generated_at"`
	AssetCount   int            `json:"asset_count"`
	FindingCount int            `json:"finding_count"`
	Severities   map[string]int `json:"severities"`
	Summary      string         `json:"summary"`
}

// SlackPayload is compatible with Slack incoming webhooks. The content is a
// compact local summary rather than raw findings or captured HTTP content.
type SlackPayload struct {
	Text string `json:"text"`
}

// DeliverWebhook posts an evidence-only scan summary to an explicitly supplied
// endpoint. HTTPS is required for non-loopback targets; redirects are refused
// so a configured destination cannot silently forward scan information.
func DeliverWebhook(ctx context.Context, db store.RuntimeStore, scanID, endpoint string) error {
	if err := validateWebhookEndpoint(endpoint); err != nil {
		return err
	}
	assets, err := db.Assets(ctx, scanID)
	if err != nil {
		return err
	}
	findings, err := db.Findings(ctx, scanID)
	if err != nil {
		return err
	}
	payload := WebhookPayload{
		Event: "enumscan.scan_summary", ScanID: scanID, GeneratedAt: time.Now().UTC(),
		AssetCount: len(assets), FindingCount: len(findings), Severities: severityCounts(findings),
		Summary: ExecutiveSummary(report{ScanID: scanID, Assets: assets, Findings: findings}),
	}
	if err := postJSON(ctx, endpoint, payload); err != nil {
		return err
	}
	return nil
}

// DeliverSlackWebhook delivers a compact scan summary to an explicit Slack
// incoming-webhook endpoint. It shares the same transport safeguards as the
// generic webhook and is never invoked automatically by a scan.
func DeliverSlackWebhook(ctx context.Context, db store.RuntimeStore, scanID, endpoint string) error {
	if err := validateWebhookEndpoint(endpoint); err != nil {
		return err
	}
	assets, err := db.Assets(ctx, scanID)
	if err != nil {
		return err
	}
	findings, err := db.Findings(ctx, scanID)
	if err != nil {
		return err
	}
	counts := severityCounts(findings)
	text := fmt.Sprintf("Enumscan evidence summary for scan %s: %d assets, %d findings (critical: %d, high: %d, medium: %d).\n%s", scanID, len(assets), len(findings), counts["critical"], counts["high"], counts["medium"], ExecutiveSummary(report{ScanID: scanID, Assets: assets, Findings: findings}))
	// Keep delivery comfortably below provider message limits and avoid turning a
	// notification into a complete report export.
	if len(text) > 3500 {
		text = text[:3500] + "\n[summary truncated; retrieve the local report for full evidence]"
	}
	return postJSON(ctx, endpoint, SlackPayload{Text: text})
}

func postJSON(ctx context.Context, endpoint string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode webhook payload: %w", err)
	}
	if len(body) > 256*1024 {
		return fmt.Errorf("webhook payload exceeds 256 KiB safety limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "enumscan/authorized-webhook")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("webhook endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func validateWebhookEndpoint(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("webhook endpoint must be an absolute URL without embedded credentials or fragments")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	return fmt.Errorf("webhook endpoint must use HTTPS (HTTP is allowed only for localhost testing)")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
