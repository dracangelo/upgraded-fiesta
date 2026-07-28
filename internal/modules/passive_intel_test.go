package modules

import (
	"context"
	"testing"

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
