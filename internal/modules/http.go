package modules

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type HTTP struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	config models.HTTPConfig
	client *http.Client
	mu     sync.Mutex
	pages  map[string]int
}

func NewHTTP(db *store.SQLiteCLI, guard scope.Guard, config models.HTTPConfig) *HTTP {
	if config.MaxDepth < 0 {
		config.MaxDepth = 0
	}
	if config.MaxPagesPerHost <= 0 {
		config.MaxPagesPerHost = 50
	}
	if len(config.APIPaths) == 0 {
		config.APIPaths = []string{"/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/graphql", "/soap?wsdl"}
	}
	return &HTTP{
		db:     db,
		guard:  guard,
		config: config,
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
		pages: make(map[string]int),
	}
}

func (h *HTTP) Name() string { return "http" }

func (h *HTTP) Subscriptions() []string { return []string{EventHTTPURL} }

func (h *HTTP) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	parsed, err := url.Parse(event.Target)
	if err != nil || parsed.Hostname() == "" || !h.guard.Allowed(parsed.Hostname()) {
		return nil, nil
	}
	if !h.allowPage(parsed.Hostname()) {
		return nil, nil
	}
	depth := eventDepth(event)
	if h.config.EnableTLS && parsed.Scheme == "https" {
		h.enumerateTLS(ctx, event.ScanID, parsed)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, event.Target, nil)
	if err != nil {
		return nil, nil
	}
	started := time.Now()
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	body := string(bodyBytes)
	meta := responseMetadata(resp)
	_ = h.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "url", Value: event.Target, Metadata: meta})
	h.recordResponseProfile(ctx, event.ScanID, event.Target, resp, len(bodyBytes), time.Since(started))
	h.auditSecurityHeaders(ctx, event.ScanID, event.Target, resp)
	h.recordTechnologies(ctx, event.ScanID, event.Target, resp)
	h.recordCanonicalURL(ctx, event.ScanID, event.Target, resp, body)
	h.recordErrorPage(ctx, event.ScanID, event.Target, resp, body)
	if h.config.EnableScreenshots {
		h.recordScreenshotTarget(ctx, event.ScanID, event.Target, resp.StatusCode)
	}

	next := make([]models.Event, 0)
	root := rootURL(parsed)
	if depth == 0 && h.config.EnableRedirectTracking {
		h.recordRedirectChain(ctx, event.ScanID, event.Target)
	}
	if depth == 0 && h.config.EnableMethodEnumeration {
		h.enumerateAllowedMethods(ctx, event.ScanID, event.Target)
	}
	if depth == 0 && h.config.EnableWebManifest {
		h.discoverWebManifest(ctx, event.ScanID, root)
	}
	if h.config.EnableCrawler && depth == 0 {
		next = append(next, h.fetchRobotsAndSitemap(ctx, event.ScanID, root)...)
	}
	if h.config.EnableAPIDiscovery && depth == 0 {
		h.discoverAPIs(ctx, event.ScanID, root)
	}
	if h.config.EnableJSAnalysis {
		h.analyzeJavaScript(ctx, event.ScanID, event.Target, body)
	}
	if h.config.EnableSecretIntel {
		h.recordSecretIntelligence(ctx, event.ScanID, event.Target, body)
	}
	if h.config.EnableCrawler && depth < h.config.MaxDepth {
		for _, link := range extractLinks(parsed, body) {
			if link.Hostname() == "" || !h.guard.Allowed(link.Hostname()) || link.Hostname() != parsed.Hostname() {
				continue
			}
			next = append(next, models.Event{
				ScanID: event.ScanID,
				Type:   EventHTTPURL,
				Target: link.String(),
				Data:   map[string]string{"depth": strconv.Itoa(depth + 1), "source": event.Target},
			})
		}
	}
	return next, nil
}

func (h *HTTP) allowPage(host string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pages[host] >= h.config.MaxPagesPerHost {
		return false
	}
	h.pages[host]++
	return true
}

func (h *HTTP) enumerateTLS(ctx context.Context, scanID string, parsed *url.URL) {
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(host, port)
	versions := []struct {
		name string
		id   uint16
		weak bool
	}{
		{"tls1.0", tls.VersionTLS10, true},
		{"tls1.1", tls.VersionTLS11, true},
		{"tls1.2", tls.VersionTLS12, false},
		{"tls1.3", tls.VersionTLS13, false},
	}
	for _, version := range versions {
		dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         version.id,
			MaxVersion:         version.id,
		}}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			continue
		}
		state := conn.(*tls.Conn).ConnectionState()
		_ = conn.Close()
		cipher := tls.CipherSuiteName(state.CipherSuite)
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "tls_version", Value: version.name, Parent: parsed.String(), Metadata: "cipher=" + cipher})
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "tls_cipher", Value: cipher, Parent: parsed.String(), Metadata: "version=" + version.name})
		if version.weak {
			_ = h.db.AddFinding(ctx, models.Finding{
				ScanID:      scanID,
				Severity:    "medium",
				Confidence:  "high",
				Asset:       parsed.String(),
				Title:       "Weak TLS protocol supported",
				Evidence:    version.name + " negotiated with " + cipher,
				Remediation: "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or newer.",
			})
		}
		for _, cert := range state.PeerCertificates {
			h.recordCertificate(ctx, scanID, parsed.String(), cert)
		}
	}
}

func (h *HTTP) recordCertificate(ctx context.Context, scanID, parent string, cert *x509.Certificate) {
	value := cert.Subject.CommonName
	if value == "" {
		value = cert.SerialNumber.String()
	}
	meta := fmt.Sprintf("issuer=%s;not_before=%s;not_after=%s;dns_names=%s", cleanEvidence(cert.Issuer.CommonName), cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), cleanEvidence(strings.Join(cert.DNSNames, "|")))
	_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "tls_certificate", Value: value, Parent: parent, Metadata: meta})
	for _, san := range cert.DNSNames {
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "tls_san", Value: san, Parent: parent})
		if strings.HasPrefix(san, "*.") {
			_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "tls_wildcard_certificate", Value: san, Parent: parent})
		}
	}
	if time.Until(cert.NotAfter) < 30*24*time.Hour {
		_ = h.db.AddFinding(ctx, models.Finding{
			ScanID:      scanID,
			Severity:    "low",
			Confidence:  "high",
			Asset:       parent,
			Title:       "TLS certificate expires soon",
			Evidence:    "Certificate expires at " + cert.NotAfter.Format(time.RFC3339),
			Remediation: "Renew and deploy a replacement certificate before expiration.",
		})
	}
}

func (h *HTTP) auditSecurityHeaders(ctx context.Context, scanID, target string, resp *http.Response) {
	checks := []struct {
		header string
		title  string
	}{
		{"Content-Security-Policy", "Missing Content-Security-Policy header"},
		{"X-Content-Type-Options", "Missing X-Content-Type-Options header"},
		{"X-Frame-Options", "Missing clickjacking protection header"},
		{"Referrer-Policy", "Missing Referrer-Policy header"},
	}
	if strings.HasPrefix(target, "https://") && resp.Header.Get("Strict-Transport-Security") == "" {
		_ = h.db.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: "low", Confidence: "medium", Asset: target, Title: "Missing HSTS header", Evidence: "HTTPS response did not include Strict-Transport-Security", Remediation: "Set a Strict-Transport-Security policy after validating HTTPS is deployed across the site."})
	}
	if hpkp := resp.Header.Get("Public-Key-Pins"); hpkp != "" {
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "hpkp_header", Value: target, Parent: target, Metadata: "value=" + cleanEvidence(hpkp)})
		_ = h.db.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: "info", Confidence: "observed", Verification: "observed", Asset: target, Title: "Deprecated HPKP header present", Evidence: "Public-Key-Pins was observed", Remediation: "Remove HPKP; modern browsers deprecated it due to operational recovery risk."})
	}
	for _, check := range checks {
		if resp.Header.Get(check.header) == "" {
			_ = h.db.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: "info", Confidence: "medium", Asset: target, Title: check.title, Evidence: check.header + " was not present", Remediation: "Review whether this response should set " + check.header + "."})
		}
	}
}

func (h *HTTP) recordTechnologies(ctx context.Context, scanID, target string, resp *http.Response) {
	for _, header := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		if value := resp.Header.Get(header); value != "" {
			_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "technology", Value: value, Parent: target, Metadata: "header=" + header})
		}
	}
}

func (h *HTTP) fetchRobotsAndSitemap(ctx context.Context, scanID string, root *url.URL) []models.Event {
	next := make([]models.Event, 0)
	for _, path := range []string{"/robots.txt", "/sitemap.xml"} {
		item := *root
		item.Path = path
		item.RawQuery = ""
		resp, body, err := h.fetchSmall(ctx, item.String())
		if err != nil || resp.StatusCode >= 400 {
			continue
		}
		assetType := "http_robots"
		if path == "/sitemap.xml" {
			assetType = "http_sitemap"
		}
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: assetType, Value: item.String(), Parent: root.String(), Metadata: "status=" + resp.Status})
		for _, link := range extractPlainURLs(root, body) {
			if h.guard.Allowed(link.Hostname()) && link.Hostname() == root.Hostname() {
				next = append(next, models.Event{ScanID: scanID, Type: EventHTTPURL, Target: link.String(), Data: map[string]string{"depth": "1", "source": item.String()}})
			}
		}
	}
	return next
}

func (h *HTTP) discoverAPIs(ctx context.Context, scanID string, root *url.URL) {
	for _, path := range h.config.APIPaths {
		item := *root
		if strings.HasPrefix(path, "/") {
			item.Path = path
			item.RawQuery = ""
		}
		resp, body, err := h.fetchSmall(ctx, item.String())
		if err != nil || resp.StatusCode >= 500 || resp.StatusCode == http.StatusNotFound {
			continue
		}
		kind := classifyAPI(path, resp, body)
		if kind == "" {
			continue
		}
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "api_endpoint", Value: item.String(), Parent: root.String(), Metadata: "kind=" + kind + ";status=" + resp.Status})
	}
}

func (h *HTTP) analyzeJavaScript(ctx context.Context, scanID, target, body string) {
	for _, endpoint := range extractJSEndpoints(body) {
		_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "js_endpoint", Value: endpoint, Parent: target})
	}
}

func (h *HTTP) recordScreenshotTarget(ctx context.Context, scanID, target string, statusCode int) {
	priority := "normal"
	lower := strings.ToLower(target)
	if statusCode >= 400 || strings.Contains(lower, "admin") || strings.Contains(lower, "login") || strings.Contains(lower, "dashboard") {
		priority = "high"
	}
	_ = h.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "screenshot_target", Value: target, Metadata: "priority=" + priority + ";status=queued;backend=not_configured"})
}

func (h *HTTP) fetchSmall(ctx context.Context, target string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp, string(body), nil
}

func responseMetadata(resp *http.Response) string {
	parts := []string{"status=" + resp.Status}
	for _, header := range []string{"Server", "X-Powered-By", "Content-Type", "Content-Encoding", "Cache-Control", "Location"} {
		if value := resp.Header.Get(header); value != "" {
			parts = append(parts, strings.ToLower(strings.ReplaceAll(header, "-", "_"))+"="+cleanEvidence(value))
		}
	}
	return strings.Join(parts, ";")
}

func eventDepth(event models.Event) int {
	if event.Data == nil {
		return 0
	}
	depth, _ := strconv.Atoi(event.Data["depth"])
	return depth
}

func rootURL(parsed *url.URL) *url.URL {
	return &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
}

func extractLinks(base *url.URL, body string) []*url.URL {
	matches := linkPattern.FindAllStringSubmatch(body, -1)
	out := make([]*url.URL, 0, len(matches))
	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		item, err := base.Parse(strings.TrimSpace(match[1]))
		if err != nil || item.Scheme == "mailto" || item.Scheme == "javascript" || item.Fragment != "" {
			continue
		}
		item.Fragment = ""
		key := item.String()
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	return out
}

func extractPlainURLs(base *url.URL, body string) []*url.URL {
	matches := plainURLPattern.FindAllString(body, -1)
	out := make([]*url.URL, 0, len(matches))
	for _, raw := range matches {
		item, err := base.Parse(strings.TrimSpace(raw))
		if err == nil {
			out = append(out, item)
		}
	}
	return out
}

func extractJSEndpoints(body string) []string {
	matches := jsEndpointPattern.FindAllStringSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		value := strings.Trim(match[1], `"'`)
		if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
			if !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
	}
	return out
}

func extractSecretHints(body string) []string {
	matches := secretPattern.FindAllString(body, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		out = append(out, redactSecret(match))
	}
	return out
}

func classifyAPI(path string, resp *http.Response, body string) string {
	lowerPath := strings.ToLower(path)
	lowerBody := strings.ToLower(body)
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	switch {
	case strings.Contains(lowerBody, `"openapi"`) || strings.Contains(lowerPath, "openapi"):
		return "openapi"
	case strings.Contains(lowerBody, "swagger") || strings.Contains(lowerPath, "swagger"):
		return "swagger"
	case strings.Contains(lowerPath, "graphql") || strings.Contains(lowerBody, "graphql"):
		return "graphql"
	case strings.Contains(lowerPath, "wsdl") || strings.Contains(lowerBody, "<wsdl"):
		return "soap"
	case strings.Contains(lowerPath, "grpc"):
		return "grpc"
	case strings.Contains(contentType, "json") && resp.StatusCode < 400:
		return "json_api"
	default:
		return ""
	}
}

func redactSecret(value string) string {
	if len(value) <= 12 {
		return "[redacted]"
	}
	return cleanEvidence(value[:6] + "..." + value[len(value)-4:])
}

var (
	linkPattern       = regexp.MustCompile(`(?i)(?:href|src|action)=["']([^"']+)["']`)
	plainURLPattern   = regexp.MustCompile(`(?i)(?:https?://[^\s<>"']+|/[a-z0-9_\-./?=&%]+)`)
	jsEndpointPattern = regexp.MustCompile(`(?i)["']((?:https?://|/)[a-z0-9_\-./?=&%:]+)["']`)
	secretPattern     = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{20,}|(?:api[_-]?key|token|secret)["'\s:=]{1,8}[0-9A-Za-z_\-]{12,})`)
)
