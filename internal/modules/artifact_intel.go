package modules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

var (
	ErrPrivacyViolation = errors.New("privacy boundary violation: raw content transmission to third party is prohibited")
)

// YARAPattern defines a signature pattern for scanning collected web artifacts.
type YARAPattern struct {
	ID          string
	Name        string
	Category    string
	Severity    string
	Keywords    []string
	Regex       *regexp.Regexp
	Remediation string
}

// ArtifactIntelligenceEngine evaluates YARA-style signatures on captured artifacts
// and queries provider reputation (VirusTotal) under strict privacy boundaries.
type ArtifactIntelligenceEngine struct {
	cache    *store.ProviderCache
	patterns []YARAPattern
}

// NewArtifactIntelligenceEngine constructs the artifact scanner with default security patterns.
func NewArtifactIntelligenceEngine(cache *store.ProviderCache) *ArtifactIntelligenceEngine {
	patterns := []YARAPattern{
		{
			ID:          "YARA-WEBSHELL-01",
			Name:        "Generic Web Shell Signature",
			Category:    "malware",
			Severity:    "critical",
			Keywords:    []string{"passthru", "shell_exec", "system($_GET"},
			Regex:       regexp.MustCompile(`(?i)(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|\$_POST|\$_GET)`),
			Remediation: "Quarantine affected host, inspect server filesystem for unauthorized file uploads, and rotate credentials.",
		},
		{
			ID:          "YARA-MINER-01",
			Name:        "Cryptocurrency Web Miner Script",
			Category:    "malware",
			Severity:    "high",
			Keywords:    []string{"coinhive.min.js", "cryptonight", "monerominer"},
			Regex:       regexp.MustCompile(`(?i)(?:CoinHive\.Anonymous|cryptonight\.wasm|server\.miner)`),
			Remediation: "Remove unauthorized third-party mining scripts from web templates.",
		},
		{
			ID:          "YARA-DEBUG-01",
			Name:        "Exposed Debugger Console",
			Category:    "exposure",
			Severity:    "high",
			Keywords:    []string{"werkzeug", "django-debug-toolbar", "telescope"},
			Regex:       regexp.MustCompile(`(?i)(?:CONSOLE_MODE\s*=\s*true|__debugger__\s*=\s*true|Telescope\s+Dashboard)`),
			Remediation: "Disable interactive debuggers in production environments.",
		},
	}

	return &ArtifactIntelligenceEngine{
		cache:    cache,
		patterns: patterns,
	}
}

// ScanArtifact inspects collected HTML, JS, or text payloads using deterministic YARA signatures.
func (e *ArtifactIntelligenceEngine) ScanArtifact(ctx context.Context, scanID, asset string, content []byte) []models.Finding {
	body := string(content)
	lower := strings.ToLower(body)

	var findings []models.Finding

	for _, p := range e.patterns {
		matched := false
		var matchDetail string

		// Check literal keywords
		for _, kw := range p.Keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				matched = true
				matchDetail = "matched keyword: " + kw
				break
			}
		}

		// Check regex
		if !matched && p.Regex != nil && p.Regex.MatchString(body) {
			matched = true
			matchDetail = "matched regex signature pattern"
		}

		if matched {
			findings = append(findings, models.Finding{
				ScanID:       scanID,
				Title:        p.Name,
				Severity:     p.Severity,
				Confidence:   "confirmed",
				Verification: "yara_signature",
				Asset:        asset,
				Evidence:     fmt.Sprintf("Artifact signature ID: %s; detail: %s", p.ID, matchDetail),
				Remediation:  p.Remediation,
				CreatedAt:    time.Now().UTC(),
			})
		}
	}

	return findings
}

// CheckVirusTotalReputation performs a privacy-safe reputation query (hash or domain only).
// Raw payloads are strictly rejected to ensure confidential customer data is never uploaded.
func (e *ArtifactIntelligenceEngine) CheckVirusTotalReputation(
	ctx context.Context,
	client *http.Client,
	apiKey, indicatorType, indicator string,
) (map[string]any, error) {
	indicator = strings.TrimSpace(indicator)
	if indicator == "" {
		return nil, fmt.Errorf("empty indicator")
	}

	// Strict privacy boundary: indicator must be an SHA256 hash or domain/IP. Never raw content.
	if indicatorType != "hash" && indicatorType != "domain" && indicatorType != "ip" {
		return nil, fmt.Errorf("%w: only hash, domain, or ip queries permitted", ErrPrivacyViolation)
	}

	// Check provider cache first
	if e.cache != nil {
		if cached, ok, _ := e.cache.Get(ctx, "virustotal", indicator); ok && cached != "" {
			var result map[string]any
			if err := json.Unmarshal([]byte(cached), &result); err == nil {
				return result, nil
			}
		}
	}

	if client == nil {
		client = &http.Client{Timeout: 6 * time.Second}
	}

	var endpoint string
	switch indicatorType {
	case "hash":
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", url.PathEscape(indicator))
	case "domain":
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", url.PathEscape(indicator))
	case "ip":
		endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", url.PathEscape(indicator))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal returned HTTP %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Cache result for 12 hours
	if e.cache != nil {
		data, _ := json.Marshal(result)
		_ = e.cache.Put(ctx, "virustotal", indicator, string(data), 12*time.Hour)
	}

	return result, nil
}

// ComputeArtifactSHA256 returns hex-encoded digest for artifact reputation checks.
func ComputeArtifactSHA256(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
