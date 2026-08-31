package config

import (
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
