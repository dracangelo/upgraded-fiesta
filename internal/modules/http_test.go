package modules

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPQualityParsers(t *testing.T) {
	match := canonicalPattern.FindStringSubmatch(`<link rel="canonical" href="https://app.example.test/home">`)
	if len(match) != 2 || match[1] != "https://app.example.test/home" {
		t.Fatalf("unexpected canonical match: %#v", match)
	}
	if !strings.Contains(normalizeAllowedMethods("GET, OPTIONS, TRACE"), ",TRACE,") {
		t.Fatal("expected normalized method set")
	}
}

func TestExtractLinksKeepsScopedRelativeURLs(t *testing.T) {
	base, _ := url.Parse("https://example.test/app/index.html")
	body := `<a href="/admin">Admin</a><script src="../static/app.js"></script><form action="/login"></form>`

	links := extractLinks(base, body)
	got := make(map[string]bool)
	for _, link := range links {
		got[link.String()] = true
	}

	for _, want := range []string{
		"https://example.test/admin",
		"https://example.test/static/app.js",
		"https://example.test/login",
	} {
		if !got[want] {
			t.Fatalf("missing extracted link %s from %#v", want, links)
		}
	}
}

func TestExtractJSEndpointsAndSecretHints(t *testing.T) {
	body := `const api="/api/v1/users"; const remote="https://api.example.test/graphql"; const token="api_key = abcdefghijklmnopqrstuvwxyz";`

	endpoints := extractJSEndpoints(body)
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %#v", endpoints)
	}
	secrets := extractSecretHints(body)
	if len(secrets) == 0 {
		t.Fatal("expected potential secret hint")
	}
	if secrets[0] == "api_key = abcdefghijklmnopqrstuvwxyz" {
		t.Fatal("secret hint should be redacted")
	}
}

func TestClassifyAPI(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	if got := classifyAPI("/openapi.json", resp, `{"openapi":"3.0.0"}`); got != "openapi" {
		t.Fatalf("got %q", got)
	}
	if got := classifyAPI("/graphql", resp, `{"data":null}`); got != "graphql" {
		t.Fatalf("got %q", got)
	}
	if got := classifyAPI("/soap?wsdl", resp, `<wsdl:definitions></wsdl:definitions>`); got != "soap" {
		t.Fatalf("got %q", got)
	}
}
