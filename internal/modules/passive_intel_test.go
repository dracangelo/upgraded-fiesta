package modules

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
)

func TestPassiveIntelHelpers(t *testing.T) {
	if got := intelligenceHost("https://api.example.test/path"); got != "api.example.test" {
		t.Fatalf("got host %q", got)
	}
	if got := intelligenceHost("127.0.0.1:443"); got != "127.0.0.1" {
		t.Fatalf("got host %q", got)
	}
	candidates := bucketCandidates("assets.example.test")
	if len(candidates) == 0 || candidates[0] != "assets" {
		t.Fatalf("unexpected bucket candidates: %#v", candidates)
	}
	urls := passiveURLs(`see https://api.example.test/v1 and https://api.example.test/v1`)
	if len(urls) != 1 {
		t.Fatalf("expected deduplicated URL, got %#v", urls)
	}
}

func TestDocumentedPassiveProviderRequestsAreReadOnlyAndTargetAware(t *testing.T) {
	m := NewPassiveIntel(nil, scope.New([]string{"192.0.2.10", "example.test"}), models.PassiveIntelConfig{})
	t.Setenv("ABUSEIPDB_API_KEY", "test-key")
	t.Setenv("GREYNOISE_API_KEY", "test-key")
	t.Setenv("BINARYEDGE_API_KEY", "test-key")
	t.Setenv("URLSCAN_API_KEY", "test-key")
	t.Setenv("OTX_API_KEY", "test-key")

	for _, test := range []struct{ source, target, header string }{
		{"abuseipdb", "192.0.2.10", "Key"},
		{"greynoise", "192.0.2.10", "Key"},
		{"binaryedge", "192.0.2.10", "X-Key"},
		{"urlscan", "example.test", "Api-Key"},
		{"otx", "example.test", "X-Otx-Api-Key"},
	} {
		req, ok := m.request(context.Background(), test.source, test.target)
		if !ok || req.Method != http.MethodGet || req.Header.Get(test.header) != "test-key" {
			t.Fatalf("unexpected %s request: %#v, enabled=%t", test.source, req, ok)
		}
	}
	if _, ok := m.request(context.Background(), "abuseipdb", "example.test"); ok {
		t.Fatal("IP-only provider must not query a hostname")
	}
	request, ok := m.request(context.Background(), "urlscan", "example.test")
	if !ok {
		t.Fatal("expected urlscan request")
	}
	parsed, err := url.Parse(request.URL.String())
	if err != nil || parsed.Query().Get("q") != "domain:example.test" {
		t.Fatalf("urlscan search must query only the observed target: %s", request.URL)
	}
}

func TestPassiveSourceCredentialGate(t *testing.T) {
	m := NewPassiveIntel(nil, scope.New([]string{"example.test"}), models.PassiveIntelConfig{})
	if _, ok := m.request(context.Background(), "shodan", "example.test"); ok {
		t.Fatal("Shodan request must be disabled without a credential")
	}
}

func TestPassiveResponseValidation(t *testing.T) {
	if !validPassiveResponse("wayback", []byte(`[["url"],["https://example.test"]]`)) {
		t.Fatal("expected JSON response to validate")
	}
	if validPassiveResponse("virustotal", []byte(`<html>rate limit</html>`)) {
		t.Fatal("HTML error response must be rejected")
	}
}

func TestPassiveIntelDeduplicatesTargetsAndBoundsRetryAfter(t *testing.T) {
	m := NewPassiveIntel(nil, scope.New([]string{"example.test"}), models.PassiveIntelConfig{ProviderMinIntervalMS: 1})
	if !m.reserveTarget("scan-1", "shodan", "Example.Test") {
		t.Fatal("first provider target should be reserved")
	}
	if m.reserveTarget("scan-1", "shodan", "example.test") {
		t.Fatal("same provider target must be deduplicated within a scan")
	}
	if !m.reserveTarget("scan-1", "virustotal", "example.test") {
		t.Fatal("different providers must retain independent reservations")
	}

	response := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"120"}}}
	if got := retryDelay(response, 0, 2*time.Second); got != 2*time.Second {
		t.Fatalf("Retry-After must be capped, got %s", got)
	}
	response.Header.Set("Retry-After", "not-a-delay")
	if got := retryDelay(response, 1, time.Second); got != 500*time.Millisecond {
		t.Fatalf("invalid Retry-After should use bounded backoff, got %s", got)
	}
}
