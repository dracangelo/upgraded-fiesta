package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"enumscan/internal/models"
)

func (h *HTTP) recordResponseProfile(ctx context.Context, scanID, target string, resp *http.Response, bytesRead int, latency time.Duration) {
	compression := resp.Header.Get("Content-Encoding")
	if compression == "" && resp.Uncompressed {
		compression = "gzip"
	}
	if compression == "" {
		compression = "none"
	}
	metadata := fmt.Sprintf("status=%d;latency_ms=%d;bytes=%d;content_type=%s;compression=%s", resp.StatusCode, latency.Milliseconds(), bytesRead, cleanEvidence(resp.Header.Get("Content-Type")), cleanEvidence(compression))
	_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "http_response_profile", Value: target, Parent: target, Metadata: metadata})

	// Audit missing compression for large text-based responses
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if bytesRead > 10240 && compression == "none" && (strings.Contains(contentType, "text") || strings.Contains(contentType, "json") || strings.Contains(contentType, "javascript")) {
		_ = h.db.AddFinding(ctx, models.Finding{
			ScanID:      scanID,
			Severity:    "info",
			Confidence:  "high",
			Asset:       target,
			Title:       "Uncompressed large web asset delivered",
			Evidence:    fmt.Sprintf("Asset size %d bytes delivered without gzip/brotli compression", bytesRead),
			Remediation: "Enable HTTP response compression (gzip or brotli) on web server.",
		})
	}
}

func (h *HTTP) recordErrorPage(ctx context.Context, scanID, target string, resp *http.Response, body string) {
	if resp.StatusCode < 400 {
		return
	}
	kind := "custom"
	lower := strings.ToLower(body + " " + resp.Header.Get("Server"))
	switch {
	case strings.Contains(lower, "apache") && (strings.Contains(lower, "not found") || strings.Contains(lower, "404")):
		kind = "apache_default"
	case strings.Contains(lower, "nginx") && (strings.Contains(lower, "not found") || strings.Contains(lower, "404")):
		kind = "nginx_default"
	case strings.Contains(lower, "iis") || strings.Contains(lower, "asp.net"):
		kind = "iis_or_aspnet"
	case strings.Contains(lower, "tomcat") || strings.Contains(lower, "apache tomcat"):
		kind = "tomcat_default"
	case strings.Contains(lower, "whitelabel error page") || strings.Contains(lower, "spring"):
		kind = "spring_boot_whitelabel"
	case strings.Contains(lower, "cannot get") || strings.Contains(lower, "express"):
		kind = "express_js"
	case strings.Contains(lower, "django") && strings.Contains(lower, "page not found"):
		kind = "django_debug_error"
	case strings.Contains(lower, "laravel") && strings.Contains(lower, "whoops"):
		kind = "laravel_debug_error"
	}
	_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "http_error_page", Value: target, Parent: target, Metadata: fmt.Sprintf("status=%d;fingerprint=%s", resp.StatusCode, kind)})
}

var canonicalPattern = regexp.MustCompile(`(?i)<link[^>]+rel=["']?canonical["']?[^>]+href=["']([^"']+)["']`)

func (h *HTTP) recordCanonicalURL(ctx context.Context, scanID, target string, resp *http.Response, body string) {
	canonical := ""
	for _, link := range resp.Header.Values("Link") {
		if strings.Contains(strings.ToLower(link), "rel=canonical") {
			if start, end := strings.Index(link, "<"), strings.Index(link, ">"); start >= 0 && end > start {
				canonical = link[start+1 : end]
				break
			}
		}
	}
	if canonical == "" {
		match := canonicalPattern.FindStringSubmatch(body)
		if len(match) > 1 {
			canonical = match[1]
		}
	}
	if canonical == "" {
		return
	}
	base, err := url.Parse(target)
	if err != nil {
		return
	}
	resolved, err := base.Parse(canonical)
	if err != nil || resolved.Hostname() == "" || !h.guard.Allowed(resolved.Hostname()) {
		return
	}
	_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "canonical_url", Value: resolved.String(), Parent: target, Metadata: "source=response"})
}

func (h *HTTP) recordRedirectChain(ctx context.Context, scanID, target string) {
	client := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	current, seen := target, map[string]bool{}
	for hop := 0; hop < 5 && !seen[current]; hop++ {
		seen[current] = true
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		location, status := resp.Header.Get("Location"), resp.StatusCode
		_ = resp.Body.Close()
		if status < 300 || status > 399 || location == "" {
			return
		}
		base, _ := url.Parse(current)
		next, err := base.Parse(location)
		if err != nil || next.Hostname() == "" || !h.guard.Allowed(next.Hostname()) {
			return
		}
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "http_redirect", Value: next.String(), Parent: current, Metadata: fmt.Sprintf("status=%d;hop=%d", status, hop+1)})
		current = next.String()
	}
}

func (h *HTTP) enumerateAllowedMethods(ctx context.Context, scanID, target string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
	if err != nil {
		return
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
	allow := strings.TrimSpace(resp.Header.Get("Allow"))
	if allow == "" {
		return
	}
	_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "http_allowed_methods", Value: allow, Parent: target, Metadata: "source=options;status=" + resp.Status})
	methods := normalizeAllowedMethods(allow)
	if strings.Contains(methods, ",TRACE,") {
		_ = h.db.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: "low", Confidence: "high", Verification: "observed", Asset: target, Title: "HTTP TRACE method advertised", Evidence: "OPTIONS Allow: " + allow, Remediation: "Disable TRACE unless a documented diagnostic need requires it."})
	}
}

func normalizeAllowedMethods(allow string) string {
	return "," + strings.ToUpper(strings.ReplaceAll(allow, " ", "")) + ","
}

type webManifest struct {
	Name       string `json:"name"`
	ShortName  string `json:"short_name"`
	StartURL   string `json:"start_url"`
	Display    string `json:"display"`
	ThemeColor string `json:"theme_color"`
}

func (h *HTTP) discoverWebManifest(ctx context.Context, scanID string, root *url.URL) {
	item := *root
	item.Path = "/manifest.json"
	item.RawQuery = ""
	resp, body, err := h.fetchSmall(ctx, item.String())
	if err != nil || resp.StatusCode >= 400 {
		return
	}
	var manifest webManifest
	if json.Unmarshal([]byte(body), &manifest) != nil || (manifest.Name == "" && manifest.StartURL == "") {
		return
	}
	metadata := "short_name=" + cleanEvidence(manifest.ShortName) + ";start_url=" + cleanEvidence(manifest.StartURL) + ";display=" + cleanEvidence(manifest.Display) + ";theme_color=" + cleanEvidence(manifest.ThemeColor)
	value := manifest.Name
	if value == "" {
		value = item.String()
	}
	_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "web_manifest", Value: value, Parent: root.String(), Metadata: metadata})
}
