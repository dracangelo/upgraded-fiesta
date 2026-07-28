package modules

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

// PassiveIntel integrates opt-in third-party intelligence sources. It never
// runs unless explicitly enabled and keeps credentials in environment
// variables, avoiding accidental storage in YAML, reports, or checkpoints.
type PassiveIntel struct {
	db      *store.SQLiteCLI
	guard   scope.Guard
	cfg     models.PassiveIntelConfig
	client  *http.Client
	baseURL map[string]string // test/enterprise endpoint overrides
}

func NewPassiveIntel(db *store.SQLiteCLI, guard scope.Guard, cfg models.PassiveIntelConfig) *PassiveIntel {
	return &PassiveIntel{db: db, guard: guard, cfg: cfg, client: &http.Client{Timeout: 8 * time.Second}, baseURL: map[string]string{}}
}

func (m *PassiveIntel) Name() string            { return "passive_intelligence" }
func (m *PassiveIntel) Subscriptions() []string { return []string{EventTarget, EventHost} }

func (m *PassiveIntel) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	host := intelligenceHost(event.Target)
	if host == "" || !m.guard.Allowed(host) {
		return nil, nil
	}
	for _, source := range m.cfg.Sources {
		source = strings.ToLower(strings.TrimSpace(source))
		if source == "" {
			continue
		}
		if source == "bucket" {
			m.discoverPublicBuckets(ctx, event.ScanID, host)
			continue
		}
		req, ok := m.request(ctx, source, host)
		if !ok {
			continue // source is not credentialed/configured
		}
		resp, err := m.doWithRetry(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 || !validPassiveResponse(source, body) {
			continue
		}
		m.recordResponse(ctx, event.ScanID, host, source, string(body))
	}
	return nil, nil
}

func (m *PassiveIntel) request(ctx context.Context, source, host string) (*http.Request, bool) {
	endpoint := ""
	headers := make(http.Header)
	switch source {
	case "shodan":
		key := os.Getenv("SHODAN_API_KEY")
		if key == "" {
			return nil, false
		}
		endpoint = "https://api.shodan.io/shodan/host/" + url.PathEscape(host)
		endpoint = addQuery(endpoint, "key", key)
	case "censys":
		id, secret := os.Getenv("CENSYS_API_ID"), os.Getenv("CENSYS_API_SECRET")
		if id == "" || secret == "" {
			return nil, false
		}
		endpoint = "https://search.censys.io/api/v2/hosts/" + url.PathEscape(host)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint(source, endpoint), nil)
		req.SetBasicAuth(id, secret)
		return req, true
	case "securitytrails":
		key := os.Getenv("SECURITYTRAILS_API_KEY")
		if key == "" {
			return nil, false
		}
		endpoint = "https://api.securitytrails.com/v1/domain/" + url.PathEscape(host) + "/subdomains"
		headers.Set("APIKEY", key)
	case "fofa":
		email, key := os.Getenv("FOFA_EMAIL"), os.Getenv("FOFA_API_KEY")
		if email == "" || key == "" {
			return nil, false
		}
		qbase64 := base64.StdEncoding.EncodeToString([]byte(`domain="` + host + `"`))
		endpoint = "https://fofa.info/api/v1/search/all?email=" + url.QueryEscape(email) + "&key=" + url.QueryEscape(key) + "&qbase64=" + url.QueryEscape(qbase64)
	case "virustotal":
		key := os.Getenv("VIRUSTOTAL_API_KEY")
		if key == "" {
			return nil, false
		}
		endpoint = "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(host)
		headers.Set("x-apikey", key)
	case "wayback":
		endpoint = "https://web.archive.org/cdx/search/cdx?url=" + url.QueryEscape("*."+host+"/*") + "&output=json&fl=original,statuscode&filter=statuscode:200&collapse=urlkey"
	case "github":
		key := os.Getenv("GITHUB_TOKEN")
		if key == "" {
			return nil, false
		}
		endpoint = "https://api.github.com/search/code?q=" + url.QueryEscape(`"`+host+`"`)
		headers.Set("Authorization", "Bearer "+key)
		headers.Set("Accept", "application/vnd.github+json")
	case "gitlab":
		key := os.Getenv("GITLAB_TOKEN")
		if key == "" {
			return nil, false
		}
		endpoint = firstNonEmpty(os.Getenv("GITLAB_API_URL"), "https://gitlab.com/api/v4") + "/search?scope=blobs&search=" + url.QueryEscape(host)
		headers.Set("PRIVATE-TOKEN", key)
	case "paste":
		endpoint = os.Getenv("PASTE_MONITOR_URL")
		if endpoint == "" {
			return nil, false
		}
		endpoint = addQuery(endpoint, "q", host)
	default:
		return nil, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint(source, endpoint), nil)
	if err != nil {
		return nil, false
	}
	req.Header = headers
	return req, true
}

func (m *PassiveIntel) endpoint(source, fallback string) string {
	if override := m.baseURL[source]; override != "" {
		return override
	}
	return fallback
}

func (m *PassiveIntel) recordResponse(ctx context.Context, scanID, host, source, body string) {
	_ = m.db.RecordFeed(ctx, store.FeedMetadata{Source: "passive:" + source, Provenance: "passive intelligence API response"}, []byte(body))
	_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "passive_source", Value: source, Parent: host, Metadata: "response=validated;attribution=" + source})
	for _, value := range passiveURLs(body) {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		if m.guard.Allowed(parsed.Hostname()) {
			_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "passive_url", Value: value, Parent: host, Metadata: "source=" + source})
		}
	}
	for _, domain := range passiveDomains(body) {
		if m.guard.Allowed(domain) {
			_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "passive_domain", Value: domain, Parent: host, Metadata: "source=" + source})
		}
	}
}

func (m *PassiveIntel) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current := req.Clone(ctx)
		resp, err := m.client.Do(current)
		if err == nil && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			return resp, nil
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("passive source returned HTTP %d", resp.StatusCode)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 250 * time.Millisecond):
		}
	}
	return nil, lastErr
}

func validPassiveResponse(source string, body []byte) bool {
	source = strings.ToLower(source)
	if source == "paste" {
		return len(body) > 0
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	// Each supported provider returns JSON; accepting only a JSON object/array
	// rejects HTML error pages and malformed intermediary responses.
	switch payload.(type) {
	case map[string]any, []any:
		return true
	default:
		return false
	}
}

func (m *PassiveIntel) discoverPublicBuckets(ctx context.Context, scanID, host string) {
	for _, bucket := range bucketCandidates(host) {
		target := "https://" + bucket + ".s3.amazonaws.com"
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
		if err != nil {
			continue
		}
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		// S3 returns 200 for listable buckets and 403 for existing private
		// buckets. Only the former is reported as public.
		if resp.StatusCode == http.StatusOK {
			_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "public_bucket", Value: target, Parent: host, Metadata: "provider=aws_s3;status=200"})
			_ = m.db.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: "medium", Confidence: "high", Asset: target, Title: "Public cloud bucket discovered", Evidence: "Unauthenticated bucket listing endpoint returned HTTP 200.", Remediation: "Review bucket policy and public-access-block settings."})
		}
	}
}

func intelligenceHost(target string) string {
	if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return strings.TrimSpace(target)
}

func addQuery(raw, key, value string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	query := parsed.Query()
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func bucketCandidates(host string) []string {
	labels := strings.Split(strings.ToLower(host), ".")
	if len(labels) < 2 {
		return nil
	}
	base := strings.Join(labels[:len(labels)-1], "-")
	if len(labels) > 2 {
		base = strings.Join(labels[:len(labels)-2], "-")
	}
	if len(base) < 3 || len(base) > 63 {
		return nil
	}
	return []string{base, strings.ReplaceAll(host, ".", "-")}
}

var passiveURLPattern = regexp.MustCompile(`https?://[^\s"'<>\\]+`)
var passiveDomainPattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`)

func passiveURLs(body string) []string {
	return uniqueStrings(passiveURLPattern.FindAllString(body, -1), 200)
}
func passiveDomains(body string) []string {
	return uniqueStrings(passiveDomainPattern.FindAllString(strings.ToLower(body), -1), 200)
}

func uniqueStrings(values []string, limit int) []string {
	seen, result := make(map[string]bool), make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
		if len(result) == limit {
			break
		}
	}
	return result
}
