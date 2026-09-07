package modules

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
)

func configuredProviderModule(t *testing.T) *PassiveIntel {
	t.Helper()
	t.Setenv("VIRUSTOTAL_API_KEY", "vt-key")
	t.Setenv("SHODAN_API_KEY", "shodan-key")
	t.Setenv("CENSYS_API_ID", "censys-id")
	t.Setenv("CENSYS_API_SECRET", "censys-secret")
	t.Setenv("SECURITYTRAILS_API_KEY", "st-key")
	t.Setenv("FOFA_EMAIL", "operator@example.test")
	t.Setenv("FOFA_API_KEY", "fofa-key")
	t.Setenv("HUNTER_API_KEY", "hunter-key")
	t.Setenv("WHOISXML_API_KEY", "whoisxml-key")
	t.Setenv("HIBP_API_KEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("GITHUB_TOKEN", "github-token")
	t.Setenv("GITLAB_TOKEN", "gitlab-token")
	t.Setenv("DNSDB_API_KEY", "dnsdb-key")
	return NewPassiveIntel(nil, scope.New([]string{"example.test", "192.0.2.10"}), models.PassiveIntelConfig{})
}

func TestIndividuallyConfiguredProviderRequests(t *testing.T) {
	m := configuredProviderModule(t)
	tests := []struct {
		name       string
		host       string
		path       string
		queryKey   string
		queryValue string
		header     string
		headerVal  string
	}{
		{"virustotal", "example.test", "/api/v3/domains/example.test", "", "", "x-apikey", "vt-key"},
		{"shodan", "192.0.2.10", "/shodan/host/192.0.2.10", "key", "shodan-key", "", ""},
		{"censys", "192.0.2.10", "/api/v2/hosts/192.0.2.10", "", "", "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("censys-id:censys-secret"))},
		{"securitytrails", "example.test", "/v1/domain/example.test/subdomains", "", "", "APIKEY", "st-key"},
		{"fofa", "example.test", "/api/v1/search/all", "email", "operator@example.test", "", ""},
		{"hunter", "example.test", "/v2/domain-search", "domain", "example.test", "", ""},
		{"whoisxml", "example.test", "/api/v2", "domainName", "example.test", "", ""},
		{"hibp", "example.test", "/api/v3/breachedDomain/example.test", "", "", "hibp-api-key", "0123456789abcdef0123456789abcdef"},
		{"github", "example.test", "/search/code", "", "", "Authorization", "Bearer github-token"},
		{"gitlab", "example.test", "/api/v4/search", "scope", "blobs", "PRIVATE-TOKEN", "gitlab-token"},
		{"dnsdb", "example.test", "/dnsdb/v2/lookup/rrset/name/example.test", "limit", "100", "X-API-Key", "dnsdb-key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, ok := m.request(context.Background(), test.name, test.host)
			if !ok || req.Method != http.MethodGet {
				t.Fatalf("provider request was not constructed: %#v", req)
			}
			if req.URL.Path != test.path {
				t.Fatalf("path=%q, want %q", req.URL.Path, test.path)
			}
			if test.queryKey != "" && req.URL.Query().Get(test.queryKey) != test.queryValue {
				t.Fatalf("query %s=%q", test.queryKey, req.URL.Query().Get(test.queryKey))
			}
			if test.header != "" && req.Header.Get(test.header) != test.headerVal {
				t.Fatalf("header %s=%q", test.header, req.Header.Get(test.header))
			}
		})
	}

	vtIP, ok := m.request(context.Background(), "virustotal", "192.0.2.10")
	if !ok || !strings.Contains(vtIP.URL.Path, "/ip_addresses/") {
		t.Fatalf("VirusTotal IP lookup used wrong collection: %#v", vtIP)
	}
	for _, source := range []string{"shodan", "censys"} {
		if _, ok := m.request(context.Background(), source, "example.test"); ok {
			t.Fatalf("%s host endpoint must reject a domain", source)
		}
	}
	for _, source := range []string{"securitytrails", "hunter", "whoisxml", "hibp", "dnsdb"} {
		if _, ok := m.request(context.Background(), source, "192.0.2.10"); ok {
			t.Fatalf("%s domain endpoint must reject an IP", source)
		}
	}
}

func TestCIRCLCVERequestRequiresFingerprintCPE(t *testing.T) {
	m := configuredProviderModule(t)
	event := models.Event{Type: EventService, Data: map[string]string{"cpe": "cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*"}}
	req, ok := m.requestForEvent(context.Background(), "circl_cve", "example.test", event)
	if !ok || req.URL.Path != "/api/search/nginx/nginx" {
		t.Fatalf("unexpected CIRCL request: %#v", req)
	}
	if _, ok := m.request(context.Background(), "circl_cve", "example.test"); ok {
		t.Fatal("CIRCL must not infer a product from a hostname")
	}
}

func TestProviderSpecificResponseContracts(t *testing.T) {
	fixtures := map[string]string{
		"virustotal":     `{"data":{"id":"example.test","type":"domain"}}`,
		"shodan":         `{"ip_str":"192.0.2.10","ports":[443]}`,
		"censys":         `{"result":{"ip":"192.0.2.10"}}`,
		"securitytrails": `{"subdomains":["www"]}`,
		"fofa":           `{"results":[["example.test"]]}`,
		"hunter":         `{"data":{"domain":"example.test","emails":[]}}`,
		"whoisxml":       `{"result":{"records":[{"domain":"www.example.test"}]}}`,
		"hibp":           `{"admin":["ExampleBreach"]}`,
		"github":         `{"total_count":1,"items":[]}`,
		"gitlab":         `[{"path":"README.md"}]`,
		"dnsdb":          "{\"rrname\":\"example.test\",\"rrtype\":\"A\"}\n{\"rrname\":\"www.example.test\",\"rrtype\":\"A\"}\n",
		"circl_cve":      `[{"id":"CVE-2025-0001"}]`,
	}
	for source, fixture := range fixtures {
		t.Run(source, func(t *testing.T) {
			if !validPassiveResponse(source, []byte(fixture)) {
				t.Fatalf("valid %s fixture was rejected", source)
			}
		})
	}
	if validPassiveResponse("virustotal", []byte(`{"unexpected":true}`)) {
		t.Fatal("provider-shaped validation accepted a non-VirusTotal object")
	}
	if validPassiveResponse("dnsdb", []byte("{\"rrname\":\"ok\"}\nnot-json")) {
		t.Fatal("invalid DNSDB NDJSON was accepted")
	}
}

func TestSensitiveProviderResponsesAreReduced(t *testing.T) {
	hibp := string(safePassiveResponse("hibp", []byte(`{"admin":["A"],"security":["A","B"]}`)))
	if strings.Contains(hibp, "admin") || strings.Contains(hibp, "security") || !strings.Contains(hibp, "breached_alias_count") {
		t.Fatalf("HIBP aliases were not removed: %s", hibp)
	}
	hunter := string(safePassiveResponse("hunter", []byte(`{"data":{"domain":"example.test","pattern":"{first}","emails":[{"value":"person@example.test"}]}}`)))
	if strings.Contains(hunter, "person@") || !strings.Contains(hunter, "email_count") {
		t.Fatalf("Hunter addresses were not removed: %s", hunter)
	}
	gitlab := string(safePassiveResponse("gitlab", []byte(`[{"path":"secret.txt","data":"secret-value","content":"other-secret"}]`)))
	if strings.Contains(gitlab, "secret-value") || strings.Contains(gitlab, "other-secret") {
		t.Fatalf("GitLab snippets were not removed: %s", gitlab)
	}
}

func TestSecurityTrailsLabelsBecomeScopedDomains(t *testing.T) {
	got := providerDerivedDomains("securitytrails", "example.test", `{"subdomains":["www","api","bad/name"]}`)
	if strings.Join(got, ",") != "www.example.test,api.example.test" {
		t.Fatalf("unexpected derived domains: %#v", got)
	}
}

func TestProviderDiagnosticRequestsUseCredentialEndpoints(t *testing.T) {
	m := configuredProviderModule(t)
	expectedPaths := map[string]string{
		"virustotal": "/api/v3/users/current", "shodan": "/account/profile", "censys": "/api/v1/account",
		"securitytrails": "/v1/ping", "fofa": "/api/v1/info/my", "hunter": "/v2/account",
		"whoisxml": "/service/account-balance", "hibp": "/api/v3/subscribedDomains", "github": "/user",
		"gitlab": "/api/v4/user", "dnsdb": "/dnsdb/v2/rate_limit", "circl_cve": "/api/dbInfo",
	}
	for source, path := range expectedPaths {
		t.Run(source, func(t *testing.T) {
			req, ok := m.diagnosticRequest(context.Background(), source)
			if !ok || req.URL.Path != path {
				t.Fatalf("diagnostic request path=%v, want %q", requestURL(req), path)
			}
		})
	}
}

func requestURL(req *http.Request) *url.URL {
	if req == nil {
		return nil
	}
	return req.URL
}
