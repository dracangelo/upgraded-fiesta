package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProviderFrameworkConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "providers.yaml")
	data := `scope:
  allowed_targets: ["127.0.0.1"]
  authorization: "TEST"
scan:
  targets: ["127.0.0.1"]
passive_intel:
  enabled: true
  sources: ["github", "shodan"]
  provider_controls: ["shodan=false", "gitlab=true"]
  provider_versions: ["github=2026-03-10"]
  enable_quota_discovery: true
  enable_update_checks: true
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PassiveIntel.EnableQuotaDiscovery || !cfg.PassiveIntel.EnableUpdateChecks || len(cfg.PassiveIntel.ProviderControls) != 2 {
		t.Fatalf("provider mechanics not loaded: %#v", cfg.PassiveIntel)
	}
	cfg.PassiveIntel.ProviderControls = []string{"github=maybe"}
	if err := Validate(cfg); err == nil {
		t.Fatal("invalid provider control accepted")
	}
}
