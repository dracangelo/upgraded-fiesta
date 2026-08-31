package modules

import (
	"context"
	"testing"
)

func TestTask27IntegrationsFramework(t *testing.T) {
	registry := NewProviderRegistry()

	// 1. Check registry contains all 17 providers
	providers := []string{
		"VirusTotal", "AbuseIPDB", "Shodan", "Censys", "SecurityTrails",
		"GreyNoise", "BinaryEdge", "FOFA", "AlienVault OTX", "URLScan.io",
		"Hunter.io", "WhoisXML API", "Have I Been Pwned", "GitHub", "GitLab",
		"DNSDB", "CIRCL CVE Search",
	}

	for _, name := range providers {
		p, ok := registry.Get(name)
		if !ok {
			t.Fatalf("provider %s not found in registry", name)
		}
		if p.Name() != name {
			t.Fatalf("provider name mismatch: expected %s, got %s", name, p.Name())
		}
		if err := p.ValidateAPIKey("valid-key"); err != nil {
			t.Fatalf("API key validation failed for %s: %v", name, err)
		}
	}

	// 2. Diagnostics test (enumscan doctor)
	diag := registry.RunDiagnostics(context.Background())
	if len(diag) < 17 {
		t.Fatalf("expected at least 17 diagnostic results, got %d", len(diag))
	}
}
