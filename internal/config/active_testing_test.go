package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func authorizedActiveConfig(t *testing.T) string {
	t.Helper()
	t.Setenv("ENUMSCAN_ACTIVE_ACK", activeTestingAcknowledgement)
	return time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
}

func TestActiveTestingDisabledByDefault(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "AUTH-123"
	if cfg.ActiveTesting.Enabled {
		t.Fatal("active testing must be disabled by default")
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("default active-testing settings rejected: %v", err)
	}
}

func TestActiveTestingRequiresExplicitValidGate(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "AUTH-123"
	cfg.ActiveTesting.Enabled = true
	cfg.ActiveTesting.Operator = "security@example.test"
	cfg.ActiveTesting.AcknowledgementEnv = "ENUMSCAN_ACTIVE_ACK"
	cfg.ActiveTesting.AuthorizationExpires = authorizedActiveConfig(t)
	cfg.ActiveTesting.AllowedTechniques = []string{"tls_heartbleed", "web_sqli"}
	if err := Validate(cfg); err != nil {
		t.Fatalf("valid active-testing gate rejected: %v", err)
	}

	cfg.ActiveTesting.AuthorizationExpires = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	if err := Validate(cfg); err == nil {
		t.Fatal("expired active-testing authorization was accepted")
	}
}

func TestActiveTestingRejectsImplicitOrUnknownTechniques(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "AUTH-123"
	cfg.ActiveTesting.AllowedTechniques = []string{"web_sqli"}
	if err := Validate(cfg); err == nil {
		t.Fatal("technique allowlist was accepted while active testing was disabled")
	}

	cfg.ActiveTesting.Enabled = true
	cfg.ActiveTesting.Operator = "operator"
	cfg.ActiveTesting.AcknowledgementEnv = "ENUMSCAN_ACTIVE_ACK"
	cfg.ActiveTesting.AuthorizationExpires = authorizedActiveConfig(t)
	cfg.ActiveTesting.AllowedTechniques = []string{"not_a_technique"}
	if err := Validate(cfg); err == nil {
		t.Fatal("unknown active-testing technique was accepted")
	}
}

func TestActiveTestingTemplateLoadsAfterPlaceholdersAreReplaced(t *testing.T) {
	raw, err := os.ReadFile("../../configs/active-testing.template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := strings.ReplaceAll(string(raw), "data/REPLACE_active-engagement.sqlite", filepath.Join(t.TempDir(), "active.sqlite"))
	content = strings.ReplaceAll(content, "REPLACE_WITH_AUTHORIZED_IP_OR_CIDR", "127.0.0.1")
	content = strings.ReplaceAll(content, "REPLACE_WITH_WRITTEN_AUTHORIZATION_REFERENCE", "TEST-AUTH-123")
	path := filepath.Join(t.TempDir(), "active.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("runnable active-testing template rejected: %v", err)
	}
	if cfg.ActiveTesting.Enabled || cfg.Scan.Profile != "quick" {
		t.Fatalf("unexpected template defaults: %#v", cfg.ActiveTesting)
	}
}

func TestAssessmentTemplatesLoadAfterPlaceholdersAreReplaced(t *testing.T) {
	paths, err := filepath.Glob("../../configs/templates/*.yaml")
	if err != nil || len(paths) < 10 {
		t.Fatalf("expected assessment template library: paths=%d err=%v", len(paths), err)
	}
	for _, source := range paths {
		t.Run(strings.TrimSuffix(filepath.Base(source), filepath.Ext(source)), func(t *testing.T) {
			raw, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			content := strings.ReplaceAll(string(raw), "REPLACE_WITH_AUTHORIZED_TARGET", "127.0.0.1")
			content = strings.ReplaceAll(content, "REPLACE_WITH_WRITTEN_AUTHORIZATION_REFERENCE", "TEST-AUTH-123")
			content = strings.ReplaceAll(content, "data/REPLACE_", filepath.Join(t.TempDir(), "data-"))
			path := filepath.Join(t.TempDir(), "scan.yaml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err != nil {
				t.Fatalf("template rejected: %v", err)
			}
		})
	}
}

func TestWebTemplateLoadsAfterPlaceholdersAreReplaced(t *testing.T) {
	raw, err := os.ReadFile("../../configs/web.template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := strings.ReplaceAll(string(raw), "REPLACE_WITH_AUTHORIZED_WEB_TARGET_OR_URL", "127.0.0.1")
	content = strings.ReplaceAll(content, "REPLACE_WITH_WRITTEN_AUTHORIZATION_REFERENCE", "TEST-AUTH-123")
	content = strings.ReplaceAll(content, "data/REPLACE_web_engagement.sqlite", filepath.Join(t.TempDir(), "web.sqlite"))
	path := filepath.Join(t.TempDir(), "web.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("web template rejected: %v", err)
	}
	if !cfg.HTTP.EnableCrawler || !cfg.HTTP.EnableDirectoryAPI || cfg.HTTP.MaxDepth != 3 {
		t.Fatalf("unexpected web template config: %+v", cfg.HTTP)
	}
	if len(cfg.HTTP.APIPaths) == 0 {
		t.Fatalf("expected api_paths in web template")
	}
}

func TestRootScanTemplatesLoadAfterPlaceholdersAreReplaced(t *testing.T) {
	templates := []struct {
		file            string
		expectedProfile string
	}{
		{"../../configs/quick.template.yaml", "quick"},
		{"../../configs/standard.template.yaml", "standard"},
		{"../../configs/scan.template.yaml", "standard"},
		{"../../configs/exhaustive.template.yaml", "exhaustive"},
	}

	for _, tc := range templates {
		t.Run(filepath.Base(tc.file), func(t *testing.T) {
			raw, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			content := strings.ReplaceAll(string(raw), "REPLACE_WITH_AUTHORIZED_IP_OR_CIDR", "127.0.0.1")
			content = strings.ReplaceAll(content, "REPLACE_WITH_WRITTEN_AUTHORIZATION_REFERENCE", "TEST-AUTH-123")
			content = strings.ReplaceAll(content, "data/REPLACE_", filepath.Join(t.TempDir(), "data-"))
			path := filepath.Join(t.TempDir(), "scan.yaml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("template %s rejected: %v", tc.file, err)
			}
			if cfg.Scan.Profile != tc.expectedProfile {
				t.Fatalf("template %s: expected profile %s, got %s", tc.file, tc.expectedProfile, cfg.Scan.Profile)
			}
		})
	}
}

