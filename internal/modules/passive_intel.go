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
	"strconv"
	"strings"
	"sync"
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
	rateMu  sync.Mutex
	nextAt  map[string]time.Time
	seenMu  sync.Mutex
	seen    map[string]struct{}
}

func NewPassiveIntel(db *store.SQLiteCLI, guard scope.Guard, cfg models.PassiveIntelConfig) *PassiveIntel {
	return &PassiveIntel{db: db, guard: guard, cfg: cfg, client: &http.Client{Timeout: 8 * time.Second}, baseURL: map[string]string{}, nextAt: make(map[string]time.Time), seen: make(map[string]struct{})}
}

func (m *PassiveIntel) Name() string { return "passive_intelligence" }
func (m *PassiveIntel) Subscriptions() []string {
	return []string{EventTarget, EventHost, EventService}
}

func (m *PassiveIntel) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	host := intelligenceHost(event.Target)
	if host == "" || !m.guard.Allowed(host) {
		return nil, nil
	}
	for _, source := range effectiveProviderSources(m.cfg) {
		source = strings.ToLower(strings.TrimSpace(source))
		if source == "" {
			continue
		}
		if event.Type == EventService && source != "circl_cve" {
			continue
		}
		if source == "circl_cve" && event.Type != EventService {
			continue
		}
		if source == "bucket" {
			if !m.reserveTarget(event.ScanID, source, host) {
				continue
			}
			m.discoverPublicBuckets(ctx, event.ScanID, host)
			continue
		}
		req, ok := m.requestForEvent(ctx, source, host, event)
		if !ok {
			continue // source is not credentialed/configured
		}
		reservationTarget := host
		if source == "circl_cve" {
			reservationTarget += "\x00" + event.Data["cpe"]
		}
		if !m.reserveTarget(event.ScanID, source, reservationTarget) {
			continue
		}
		if err := m.waitForProvider(ctx, source); err != nil {
			continue
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
		m.recordResponse(ctx, event.ScanID, host, source, string(safePassiveResponse(source, body)))
	}
	return nil, nil
}

// reserveTarget prevents multiple event types from querying the same passive
// provider for the same scan and host. It is intentionally in-memory: passive
// evidence remains fresh on later scans and is never cached as scan output.
func (m *PassiveIntel) reserveTarget(scanID, source, host string) bool {
	key := strings.ToLower(strings.TrimSpace(scanID)) + "\x00" + source + "\x00" + strings.ToLower(strings.TrimSpace(host))
	m.seenMu.Lock()
	defer m.seenMu.Unlock()
	if m.seen == nil {
		m.seen = make(map[string]struct{})
	}
	if _, seen := m.seen[key]; seen {
		return false
	}
	m.seen[key] = struct{}{}
	return true
}

// waitForProvider enforces an operator-configured minimum interval separately
// for each provider. Reservations are made before waiting so concurrent module
// workers cannot burst a provider with the same configured source.
func (m *PassiveIntel) waitForProvider(ctx context.Context, source string) error {
	interval := time.Duration(m.cfg.ProviderMinIntervalMS) * time.Millisecond
	if interval <= 0 {
		return nil
	}
	m.rateMu.Lock()
	if m.nextAt == nil {
		m.nextAt = make(map[string]time.Time)
	}
	now := time.Now()
	start := m.nextAt[source]
	if start.Before(now) {
		start = now
	}
	m.nextAt[source] = start.Add(interval)
	m.rateMu.Unlock()
	if delay := time.Until(start); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func (m *PassiveIntel) request(ctx context.Context, source, host string) (*http.Request, bool) {
	return m.requestForEvent(ctx, source, host, models.Event{})
}

func (m *PassiveIntel) requestForEvent(ctx context.Context, source, host string, event models.Event) (*http.Request, bool) {
	definition, known := passiveProviderDefinition(source)
	targetIP := net.ParseIP(host)
	if !known || (definition.IPOnly && targetIP == nil) || (definition.DomainOnly && targetIP != nil) {
		return nil, false
	}
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
		collection := "domains"
		if net.ParseIP(host) != nil {
			collection = "ip_addresses"
		}
		endpoint = "https://www.virustotal.com/api/v3/" + collection + "/" + url.PathEscape(host)
		headers.Set("x-apikey", key)
	case "abuseipdb":
		key := os.Getenv("ABUSEIPDB_API_KEY")
		if key == "" {
			return nil, false
		}
		endpoint = addQuery("https://api.abuseipdb.com/api/v2/check", "ipAddress", host)
		endpoint = addQuery(endpoint, "maxAgeInDays", "90")
		headers.Set("Key", key)
		headers.Set("Accept", "application/json")
	case "greynoise":
		key := os.Getenv("GREYNOISE_API_KEY")
		if key == "" {
			return nil, false
		}
		endpoint = "https://api.greynoise.io/v3/community/" + url.PathEscape(host)
		headers.Set("key", key)
	case "binaryedge":
		key := os.Getenv("BINARYEDGE_API_KEY")
		if key == "" {
			return nil, false
		}
		endpoint = "https://api.binaryedge.io/v2/query/ip/" + url.PathEscape(host)
		headers.Set("X-Key", key)
	case "urlscan":
		key := os.Getenv("URLSCAN_API_KEY")
		if key == "" {
			return nil, false
		}
		query := "domain:" + host
		if net.ParseIP(host) != nil {
			query = "ip:" + host
		}
		endpoint = addQuery("https://urlscan.io/api/v1/search/", "q", query)
		endpoint = addQuery(endpoint, "size", "20")
		headers.Set("API-Key", key)
	case "otx":
		key := os.Getenv("OTX_API_KEY")
		if key == "" {
			return nil, false
		}
		indicatorType := "hostname"
		if net.ParseIP(host) != nil {
			indicatorType = "IPv4"
			if strings.Contains(host, ":") {
				indicatorType = "IPv6"
			}
		}
		endpoint = "https://otx.alienvault.com/api/v1/indicators/" + indicatorType + "/" + url.PathEscape(host) + "/general"
		headers.Set("X-OTX-API-KEY", key)
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
		if version := configuredProviderVersion(m.cfg, source, definition); version != "" {
			headers.Set("X-GitHub-Api-Version", version)
		}
	case "gitlab":
		key := os.Getenv("GITLAB_TOKEN")
		if key == "" {
			return nil, false
		}
		endpoint = firstNonEmpty(os.Getenv("GITLAB_API_URL"), "https://gitlab.com/api/v4") + "/search?scope=blobs&search=" + url.QueryEscape(host)
		headers.Set("PRIVATE-TOKEN", key)
	case "hunter":
		key := os.Getenv("HUNTER_API_KEY")
		if key == "" || net.ParseIP(host) != nil {
			return nil, false
		}
		endpoint = addQuery("https://api.hunter.io/v2/domain-search", "domain", host)
		endpoint = addQuery(endpoint, "api_key", key)
		endpoint = addQuery(endpoint, "limit", "10")
	case "whoisxml":
		key := os.Getenv("WHOISXML_API_KEY")
		if key == "" || net.ParseIP(host) != nil {
			return nil, false
		}
		endpoint = addQuery("https://subdomains.whoisxmlapi.com/api/v2", "apiKey", key)
		endpoint = addQuery(endpoint, "domainName", host)
		endpoint = addQuery(endpoint, "outputFormat", "JSON")
	case "hibp":
		key := os.Getenv("HIBP_API_KEY")
		if key == "" || net.ParseIP(host) != nil {
			return nil, false
		}
		endpoint = "https://haveibeenpwned.com/api/v3/breachedDomain/" + url.PathEscape(host)
		headers.Set("hibp-api-key", key)
		headers.Set("User-Agent", "enumscan-passive-intelligence")
	case "dnsdb":
		key := os.Getenv("DNSDB_API_KEY")
		if key == "" || net.ParseIP(host) != nil {
			return nil, false
		}
		endpoint = "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/" + url.PathEscape(host)
		endpoint = addQuery(endpoint, "limit", "100")
		headers.Set("X-API-Key", key)
		headers.Set("Accept", "application/x-ndjson")
	case "circl_cve":
		vendor, product, valid := cpeVendorProduct(event.Data["cpe"])
		if !valid || event.Type != EventService {
			return nil, false
		}
		endpoint = "https://cve.circl.lu/api/search/" + url.PathEscape(vendor) + "/" + url.PathEscape(product)
		headers.Set("Accept", "application/json")
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
	for _, domain := range providerDerivedDomains(source, host, body) {
		if m.guard.Allowed(domain) {
			_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "passive_domain", Value: domain, Parent: host, Metadata: "source=" + source})
		}
	}
}

func providerDerivedDomains(source, host, body string) []string {
	if source != "securitytrails" {
		return nil
	}
	var payload struct {
		Subdomains []string `json:"subdomains"`
	}
	if json.Unmarshal([]byte(body), &payload) != nil {
		return nil
	}
	result := make([]string, 0, len(payload.Subdomains))
	for _, label := range payload.Subdomains {
		label = strings.Trim(strings.ToLower(strings.TrimSpace(label)), ".")
		if label != "" && !strings.ContainsAny(label, "/:@") {
			result = append(result, label+"."+strings.ToLower(host))
		}
	}
	return uniqueStrings(result, 200)
}

func (m *PassiveIntel) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current := req.Clone(ctx)
		resp, err := m.client.Do(current)
		if err == nil && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			return resp, nil
		}
		delay := retryDelay(resp, attempt, time.Duration(m.cfg.MaxRetryAfterMS)*time.Millisecond)
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
		case <-time.After(delay):
		}
	}
	return nil, lastErr
}

func retryDelay(resp *http.Response, attempt int, maxRetryAfter time.Duration) time.Duration {
	if maxRetryAfter < 0 {
		maxRetryAfter = 0
	}
	delay := time.Duration(attempt+1) * 250 * time.Millisecond
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		return delay
	}
	retryAfter := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds >= 0 {
		delay = time.Duration(seconds) * time.Second
	} else if when, err := http.ParseTime(retryAfter); err == nil {
		delay = time.Until(when)
	}
	if delay < 0 {
		delay = 0
	}
	if delay > maxRetryAfter {
		return maxRetryAfter
	}
	return delay
}

func validPassiveResponse(source string, body []byte) bool {
	source = strings.ToLower(source)
	if source == "paste" {
		return len(body) > 0
	}
	if source == "dnsdb" {
		return validNDJSON(body)
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	return validProviderPayload(source, payload)
}

func validProviderPayload(source string, payload any) bool {
	object, isObject := payload.(map[string]any)
	_, isArray := payload.([]any)
	switch source {
	case "shodan":
		_, ipOK := object["ip_str"]
		_, portsOK := object["ports"]
		return isObject && (ipOK || portsOK)
	case "censys":
		_, ok := object["result"]
		return isObject && ok
	case "securitytrails":
		_, ok := object["subdomains"]
		return isObject && ok
	case "fofa":
		_, ok := object["results"]
		return isObject && ok
	case "virustotal", "hunter":
		_, ok := object["data"]
		return isObject && ok
	case "github":
		_, ok := object["items"]
		return isObject && ok
	case "gitlab", "circl_cve":
		return isArray || isObject
	case "whoisxml":
		_, ok := object["result"]
		return isObject && ok
	case "hibp":
		return isObject
	default:
		return isObject || isArray
	}
}

func validNDJSON(body []byte) bool {
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return false
	}
	for _, line := range lines {
		var value map[string]any
		if json.Unmarshal([]byte(line), &value) != nil {
			return false
		}
	}
	return true
}

// safePassiveResponse removes provider-returned email aliases and code
// snippets that are unnecessary for scoped asset attribution.
func safePassiveResponse(source string, body []byte) []byte {
	switch source {
	case "hibp":
		var entries map[string][]string
		if json.Unmarshal(body, &entries) != nil {
			return []byte(`{"error":"invalid provider response"}`)
		}
		breaches := make([]string, 0)
		for _, names := range entries {
			breaches = append(breaches, names...)
		}
		result, _ := json.Marshal(map[string]any{"breached_alias_count": len(entries), "breaches": uniqueStrings(breaches, 200)})
		return result
	case "hunter":
		var payload struct {
			Data struct {
				Domain  string `json:"domain"`
				Pattern string `json:"pattern"`
				Emails  []any  `json:"emails"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &payload) == nil {
			result, _ := json.Marshal(map[string]any{"data": map[string]any{"domain": payload.Data.Domain, "pattern": payload.Data.Pattern, "email_count": len(payload.Data.Emails)}})
			return result
		}
	case "gitlab":
		var entries []map[string]any
		if json.Unmarshal(body, &entries) == nil {
			for _, entry := range entries {
				delete(entry, "data")
				delete(entry, "content")
			}
			result, _ := json.Marshal(entries)
			return result
		}
	}
	return body
}

func cpeVendorProduct(value string) (string, string, bool) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) < 5 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", "", false
	}
	vendor, product := strings.TrimSpace(parts[3]), strings.TrimSpace(parts[4])
	if vendor == "" || product == "" || vendor == "*" || product == "*" {
		return "", "", false
	}
	return vendor, product, true
}

func (m *PassiveIntel) discoverPublicBuckets(ctx context.Context, scanID, host string) {
	for _, bucket := range bucketCandidates(host) {
		if err := m.waitForProvider(ctx, "bucket"); err != nil {
			return
		}
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
