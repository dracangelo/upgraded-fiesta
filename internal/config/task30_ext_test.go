package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTask30ScanProfiles(t *testing.T) {
	// 1. Verify all 12 built-in scan profiles
	profiles := GetBuiltinProfiles()

	expectedProfiles := []ProfileType{
		ProfileQuick,
		ProfileStandard,
		ProfileExhaustive,
		ProfileExternalInfrastructure,
		ProfileInternalNetwork,
		ProfileWebApplication,
		ProfileAPIAssessment,
		ProfileActiveDirectory,
		ProfileKubernetes,
		ProfileCloudInfrastructure,
		ProfileBugBounty,
		ProfileCompliance,
	}

	for _, pType := range expectedProfiles {
		p, ok := profiles[pType]
		if !ok {
			t.Fatalf("built-in profile %s missing", pType)
		}
		if p.Name == "" || len(p.Modules) == 0 {
			t.Fatalf("invalid profile configuration for %s", pType)
		}
	}

	// 2. Test custom YAML profile template parsing
	customYAML := `
name: Custom API Deep Dive
description: Custom profile for API testing
modules:
  - directory_api
  - web_vuln_engine
ports:
  - 8080
  - 8443
concurrency: 25
timeout_sec: 150
`
	customProf, err := LoadCustomProfileTemplate([]byte(customYAML))
	if err != nil || customProf.Name != "Custom API Deep Dive" {
		t.Fatalf("failed to load custom profile template: %v", err)
	}
}

func TestApplyRequestedProfileChangesEffectiveScanSettings(t *testing.T) {
	cfg := Default()
	cfg.PortScan.TCPPorts = []int{1}
	cfg.PortScan.EnableUDP = true
	cfg.PortScan.EnableRawScanning = true
	cfg.Scheduler.Concurrency = 1

	configured, err := ApplyRequestedProfile(cfg, "web application")
	if err != nil {
		t.Fatal(err)
	}
	if configured.Scan.Profile != string(ProfileWebApplication) || configured.PortScan.Profile != string(ProfileWebApplication) {
		t.Fatalf("profile was not applied: %#v", configured.Scan)
	}
	if configured.Scheduler.Concurrency != GetBuiltinProfiles()[ProfileWebApplication].Concurrency {
		t.Fatalf("profile concurrency was not applied: %d", configured.Scheduler.Concurrency)
	}
	if len(configured.PortScan.TCPPorts) == 0 || configured.PortScan.TCPPorts[0] != 80 {
		t.Fatalf("profile port selection was not applied: %#v", configured.PortScan.TCPPorts)
	}
	if configured.PortScan.EnableUDP || configured.PortScan.EnableRawScanning {
		t.Fatalf("requested profile inherited unsafe scan modes: %#v", configured.PortScan)
	}
	if _, err := ApplyRequestedProfile(cfg, "not-a-profile"); err == nil {
		t.Fatal("unknown profile was accepted")
	}
}

func TestConfiguredProfilePreservesExplicitOverridesAndPlansModules(t *testing.T) {
	cfg := Default()
	cfg.Scan.Profile = "quick"
	cfg.PortScan.TCPPorts = []int{9443}
	cfg.Scheduler.Concurrency = 3

	configured, err := ApplyConfiguredProfile(cfg, cfg.Scan.Profile, map[string]bool{
		"portscan.tcp_ports":      true,
		"scheduler.concurrency":   true,
		"http.enable_tls":         true,
		"specialized.enable_ldap": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if configured.Scheduler.Concurrency != 3 || len(configured.PortScan.TCPPorts) != 1 || configured.PortScan.TCPPorts[0] != 9443 {
		t.Fatalf("explicit configuration was overwritten: %#v", configured)
	}
	if !ModuleEnabled(configured, ModuleDiscovery) || !ModuleEnabled(configured, ModulePortScan) || !ModuleEnabled(configured, ModuleHTTP) || !ModuleEnabled(configured, ModuleSpecialized) {
		t.Fatalf("expected profile and explicit module families in plan: %#v", configured.Scan.ModulePlan)
	}
	if ModuleEnabled(configured, ModulePassiveIntel) {
		t.Fatalf("unexpected passive-intel module in plan: %#v", configured.Scan.ModulePlan)
	}
}

func TestLoadCustomProfileAppliesToEngineConfiguration(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("name: Focused HTTP\nmodules:\n  - http\nports:\n  - 8443\nconcurrency: 7\ntimeout_sec: 45\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "scan.yaml")
	content := "scope:\n  allowed_targets: [\"127.0.0.1\"]\n  authorization: \"TEST-1\"\nscan:\n  custom_profile: \"profile.yaml\"\n  targets: [\"127.0.0.1\"]\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Scan.ProfileApplied || cfg.Scan.Profile != "custom" || cfg.Scheduler.Concurrency != 7 || cfg.Scheduler.ModuleTimeoutMS != 45000 {
		t.Fatalf("custom profile was not applied: %#v", cfg)
	}
	if len(cfg.PortScan.TCPPorts) != 1 || cfg.PortScan.TCPPorts[0] != 8443 || !ModuleEnabled(cfg, ModuleHTTP) || ModuleEnabled(cfg, ModulePortScan) {
		t.Fatalf("custom profile plan was not applied: %#v", cfg)
	}
}
