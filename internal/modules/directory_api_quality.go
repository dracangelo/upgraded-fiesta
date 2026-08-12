package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"enumscan/internal/models"
)

func validMercurialRequires(body string) bool {
	lower := strings.ToLower(strings.TrimSpace(body))
	return strings.Contains(lower, "revlogv") || strings.Contains(lower, "dotencode") || strings.Contains(lower, "fncache")
}

var sourceMapReference = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s]+)`)

func (m *DirectoryAPIEnumerator) parseSourceMap(ctx context.Context, scanID string, root, script *url.URL, scriptBody string) {
	reference := script.String() + ".map"
	if match := sourceMapReference.FindStringSubmatch(scriptBody); len(match) > 1 {
		if item, err := script.Parse(strings.TrimSpace(match[1])); err == nil {
			reference = item.String()
		}
	}
	item, err := url.Parse(reference)
	if err != nil || item.Hostname() != root.Hostname() || !m.guard.Allowed(item.Hostname()) {
		return
	}
	resp, body, err := m.get(ctx, item.String())
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	var sourceMap struct {
		Version        int      `json:"version"`
		File           string   `json:"file"`
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
	}
	if json.Unmarshal([]byte(body), &sourceMap) != nil || sourceMap.Version <= 0 {
		return
	}
	_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "source_map", Value: item.String(), Parent: script.String(), Metadata: fmt.Sprintf("version=%d;sources=%d", sourceMap.Version, len(sourceMap.Sources))})
	for _, source := range sourceMap.Sources {
		_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "source_map_source", Value: cleanEvidence(source), Parent: item.String()})
	}
	for _, content := range sourceMap.SourcesContent {
		for _, endpoint := range uniquePaths(extractJSEndpoints(content), 40) {
			candidate, ok := scopedPath(root, endpoint)
			if !ok {
				continue
			}
			_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "source_map_endpoint", Value: candidate.String(), Parent: item.String(), Metadata: "source=source_map"})
		}
		m.recordSourceMapSecrets(ctx, scanID, item.String(), content)
	}
}

func (m *DirectoryAPIEnumerator) recordSourceMapSecrets(ctx context.Context, scanID, target, content string) {
	for _, match := range detectSecrets(content) {
		metadata := fmt.Sprintf("kind=%s;risk=%s;validated=%t;fingerprint=%s;source=source_map", match.Kind, match.Risk, match.Validated, match.Redacted)
		_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "secret_exposure", Value: match.Kind + ":" + match.Redacted, Parent: target, Metadata: metadata})
		_ = m.db.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: match.Risk, Confidence: match.Confidence, Verification: "heuristic", Asset: target, Title: "Potential " + secretTitle(match.Kind) + " exposed in source map", Evidence: "Redacted fingerprint " + match.Redacted + "; local format validation=" + fmt.Sprint(match.Validated), Remediation: "Remove secrets from source assets, rotate affected credentials, and avoid publishing source maps with source content."})
	}
}

func (m *DirectoryAPIEnumerator) analyzeAPIRateLimits(ctx context.Context, scanID, endpoint string, resp *http.Response) {
	parts := make([]string, 0)
	for _, header := range []string{"RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"} {
		if value := resp.Header.Get(header); value != "" {
			parts = append(parts, strings.ToLower(strings.ReplaceAll(header, "-", "_"))+"="+cleanEvidence(value))
		}
	}
	if len(parts) > 0 {
		_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "api_rate_limit", Value: endpoint, Parent: endpoint, Metadata: strings.Join(parts, ";")})
	}
}

func (m *DirectoryAPIEnumerator) analyzeJSONResponse(ctx context.Context, scanID, endpoint, body string) {
	var value any
	if json.Unmarshal([]byte(body), &value) != nil {
		return
	}
	shape, fields := "scalar", 0
	switch typed := value.(type) {
	case map[string]any:
		shape, fields = "object", len(typed)
	case []any:
		shape, fields = "array", len(typed)
	}
	_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "api_json_shape", Value: endpoint, Parent: endpoint, Metadata: fmt.Sprintf("root=%s;entries=%d", shape, fields)})
}
