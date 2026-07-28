package modules

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"enumscan/internal/models"
)

// SecretMatch contains only the classification and a redacted fingerprint.
// Raw credential material must never enter the asset store or scan report.
type SecretMatch struct {
	Kind       string
	Redacted   string
	Risk       string
	Confidence string
	Validated  bool // local structural validation; no credential is exercised
}

func (h *HTTP) recordSecretIntelligence(ctx context.Context, scanID, target, body string) {
	for _, match := range detectSecrets(body) {
		metadata := fmt.Sprintf("kind=%s;risk=%s;validated=%t;fingerprint=%s", match.Kind, match.Risk, match.Validated, match.Redacted)
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "secret_exposure", Value: match.Kind + ":" + match.Redacted, Parent: target, Metadata: metadata})
		_ = h.db.AddFinding(ctx, models.Finding{
			ScanID: scanID, Severity: match.Risk, Confidence: match.Confidence, Verification: "heuristic", Asset: target,
			Title:       "Potential " + secretTitle(match.Kind) + " exposed",
			Evidence:    "Redacted fingerprint " + match.Redacted + "; local format validation=" + fmt.Sprint(match.Validated),
			Remediation: "Remove the credential from client-accessible content, rotate it, and use a server-side secret manager.",
		})
	}
}

func detectSecrets(body string) []SecretMatch {
	patterns := []struct {
		kind, risk, confidence string
		re                     *regexp.Regexp
		validate               func(string) bool
	}{
		{"aws_access_key", "high", "high", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), validAWSAccessKey},
		{"aws_secret_key", "high", "medium", regexp.MustCompile(`(?i)(?:aws_)?secret(?:_access)?_?key["'\s:=]{1,8}([A-Za-z0-9/+]{40})`), validAWSSecret},
		{"azure_storage_connection", "high", "high", regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https?;AccountName=[^;\s"']+;AccountKey=[A-Za-z0-9+/=]{32,}`), validAzureConnection},
		{"azure_client_secret", "high", "medium", regexp.MustCompile(`(?i)(?:azure_)?client_?secret["'\s:=]{1,8}([A-Za-z0-9_~.\-/+=]{16,})`), validNonEmpty},
		{"gcp_api_key", "high", "high", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), validNonEmpty},
		{"gcp_service_account", "critical", "high", regexp.MustCompile(`(?s)"type"\s*:\s*"service_account".{0,1000}?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----`), validNonEmpty},
		{"jwt_secret", "high", "medium", regexp.MustCompile(`(?i)(?:jwt|signing)[_-]?secret["'\s:=]{1,8}([A-Za-z0-9_~.\-/+=]{16,})`), validNonEmpty},
		{"api_key", "medium", "low", regexp.MustCompile(`(?i)(?:api[_-]?key|token)["'\s:=]{1,8}([A-Za-z0-9_\-]{16,})`), validNonEmpty},
		{"private_key", "critical", "high", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), validNonEmpty},
	}
	seen := make(map[string]bool)
	results := make([]SecretMatch, 0)
	for _, pattern := range patterns {
		for _, raw := range pattern.re.FindAllString(body, -1) {
			fingerprint := redactFingerprint(raw)
			key := pattern.kind + ":" + fingerprint
			if seen[key] {
				continue
			}
			seen[key] = true
			results = append(results, SecretMatch{Kind: pattern.kind, Redacted: fingerprint, Risk: pattern.risk, Confidence: pattern.confidence, Validated: pattern.validate(raw)})
		}
	}
	return results
}

func validAWSAccessKey(value string) bool {
	return len(value) == 20 && (strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "ASIA"))
}
func validAWSSecret(value string) bool { return strings.Contains(value, "/") && len(value) >= 40 }
func validAzureConnection(value string) bool {
	return strings.Contains(value, "AccountName=") && strings.Contains(value, "AccountKey=")
}
func validNonEmpty(value string) bool { return len(strings.TrimSpace(value)) >= 16 }

func redactFingerprint(value string) string {
	value = strings.TrimSpace(value)
	sum := sha256.Sum256([]byte(value))
	if len(value) <= 10 {
		return fmt.Sprintf("sha256:%x", sum[:6])
	}
	return value[:4] + "..." + value[len(value)-4:] + ":sha256:" + fmt.Sprintf("%x", sum[:4])
}

func secretTitle(kind string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.ReplaceAll(kind, "_", " ")), "GCP", "GCP")
}

// validatePrivateKeyPEM provides optional local validation for callers that
// obtain PEM text from a controlled fixture; it is intentionally not used to
// parse or retain discovered key material.
func validatePrivateKeyPEM(value string) bool {
	_, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(value, "-----BEGIN PRIVATE KEY-----", ""), "-----END PRIVATE KEY-----", ""))
	return err == nil
}
