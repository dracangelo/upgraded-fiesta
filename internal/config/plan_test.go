package config

import (
	"strings"
	"testing"
)

func TestResolveEffectivePlanIsOfflineAndRedacted(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "AUTH"
	cfg.Scan.Profile = "standard"
	cfg.Scan.Targets = []string{"127.0.0.1"}
	cfg.Database.EncryptionKeyEnv = "ENUMSCAN_KEY"
	cfg.Notifications.WebhookURL = "https://hooks.example.test/path/secret"
	cfg.PortScan.EnableRawScanning = true
	lookups := 0
	plan := ResolveEffectivePlan(cfg, func(name string) (string, bool) {
		lookups++
		return "must-not-appear", false
	})
	if lookups != 1 || len(plan.MissingEnvironment) != 1 || plan.MissingEnvironment[0] != "ENUMSCAN_KEY" {
		t.Fatalf("unexpected environment diagnostics: %#v", plan)
	}
	if len(plan.Outbound) != 1 || plan.Outbound[0] != "https://hooks.example.test" {
		t.Fatalf("outbound endpoint was not origin-reduced: %#v", plan.Outbound)
	}
	text := FormatEffectivePlanText(plan)
	if strings.Contains(text, "must-not-appear") || !strings.Contains(text, "raw network socket") {
		t.Fatalf("plan leaked a value or omitted privileges: %s", text)
	}
}
