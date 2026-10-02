package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEngagementConfigIsScopeLockedAndSafe(t *testing.T) {
	input := EngagementInput{Target: "192.168.56.0/24", Profile: "standard", Authorization: "ENG-2026-004"}
	cfg, err := BuildEngagementConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Scope.AllowedTargets) != 1 || len(cfg.Scan.Targets) != 1 || cfg.Scope.AllowedTargets[0] != cfg.Scan.Targets[0] {
		t.Fatalf("generated scope is not locked: %#v %#v", cfg.Scope.AllowedTargets, cfg.Scan.Targets)
	}
	if cfg.ActiveTesting.Enabled || cfg.PortScan.EnableRawSYN || cfg.PortScan.EnableRawScanning || len(cfg.PortScan.DecoyIPs) != 0 {
		t.Fatalf("generated config must be safe enumeration only: %#v", cfg)
	}
	text, err := RenderEngagementConfig(input)
	if err != nil || !strings.Contains(string(text), "allowed_targets: [\"192.168.56.0/24\"]") || !strings.Contains(string(text), "enabled: false") {
		t.Fatalf("unexpected generated YAML: %s (%v)", text, err)
	}
}

func TestEngagementConfigRejectsUnsafeInputAndDoesNotOverwrite(t *testing.T) {
	if _, err := BuildEngagementConfig(EngagementInput{Target: "https://example.test", Authorization: "ENG-1"}); err == nil {
		t.Fatal("URL target should be rejected")
	}
	if _, err := BuildEngagementConfig(EngagementInput{Target: "example.test", Authorization: "REPLACE_AUTH"}); err == nil {
		t.Fatal("placeholder authorization should be rejected")
	}
	path := filepath.Join(t.TempDir(), "private", "engagement.yaml")
	input := EngagementInput{Target: "example.test", Authorization: "ENG-1"}
	if err := WriteEngagementConfig(path, input); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("expected a mode-0600 config, got %#v (%v)", info, err)
	}
	if err := WriteEngagementConfig(path, input); err == nil {
		t.Fatal("writer must not overwrite an existing config")
	}
}

func TestEngagementTemplatesAndDependencyChecks(t *testing.T) {
	templates := AvailableEngagementTemplates()
	if len(templates) < 5 {
		t.Fatalf("expected at least 5 assessment templates, got %d", len(templates))
	}

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.sqlite")

	// Check valid target
	checks, err := RunEngagementDependencyChecks("192.168.1.1", dbPath)
	if err != nil {
		t.Fatalf("unexpected error running dependency checks: %v", err)
	}
	if len(checks) == 0 {
		t.Fatal("expected dependency checks to return results")
	}
	for _, c := range checks {
		if c.Severity == "error" {
			t.Fatalf("unexpected check failure: %s: %s", c.Name, c.Message)
		}
	}

	// Check invalid target fails dependency check
	badChecks, _ := RunEngagementDependencyChecks("invalid://bad-target", dbPath)
	foundError := false
	for _, c := range badChecks {
		if c.Severity == "error" {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Fatal("expected target validation error for bad target")
	}
}

func TestEngagementPlanPreviewAndEstimates(t *testing.T) {
	input := EngagementInput{
		Target:        "192.168.1.0/24",
		Profile:       "standard",
		Authorization: "AUTH-2026-VAL",
	}
	preview, err := PreviewEngagementPlan(input, filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("unexpected error previewing plan: %v", err)
	}

	if preview.Target != "192.168.1.0/24" {
		t.Errorf("expected target 192.168.1.0/24, got %s", preview.Target)
	}
	if preview.EstimatedHosts != 256 {
		t.Errorf("expected 256 estimated hosts for /24, got %d", preview.EstimatedHosts)
	}
	if preview.EstimatedPortProbes <= 0 {
		t.Errorf("expected positive port probes estimate, got %d", preview.EstimatedPortProbes)
	}
	if preview.EstimatedDuration == "" {
		t.Error("expected non-empty duration estimate")
	}
	if len(preview.SafetyGuarantees) < 3 {
		t.Errorf("expected at least 3 safety guarantees, got %d", len(preview.SafetyGuarantees))
	}
}

func TestBuildEngagementConfigAllScanTypes(t *testing.T) {
	input := EngagementInput{
		Target:        "192.168.1.10",
		Profile:       "all",
		Authorization: "AUTH-2026-ALL",
	}
	cfg, err := BuildEngagementConfig(input)
	if err != nil {
		t.Fatalf("unexpected error building config with profile 'all': %v", err)
	}
	if cfg.Scan.Profile != "exhaustive" {
		t.Errorf("expected profile to be normalized to exhaustive, got %s", cfg.Scan.Profile)
	}
	expectedModules := []string{"discovery", "portscan", "service", "specialized", "http", "passive_intel"}
	moduleMap := make(map[string]bool)
	for _, m := range cfg.Scan.ModulePlan {
		moduleMap[m] = true
	}
	for _, expected := range expectedModules {
		if !moduleMap[expected] {
			t.Errorf("expected module %s to be enabled in all scan types plan, plan was: %v", expected, cfg.Scan.ModulePlan)
		}
	}
}

