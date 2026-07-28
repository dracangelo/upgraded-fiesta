package modules

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestWordlistEngine(t *testing.T) {
	engine := NewWordlistEngine()
	paths := engine.GenerateAdaptivePaths([]string{"WordPress", "Spring Boot"})

	foundWP := false
	foundSpring := false

	for _, p := range paths {
		if strings.Contains(p, "wp-admin") {
			foundWP = true
		}
		if strings.Contains(p, "actuator") {
			foundSpring = true
		}
	}

	if !foundWP || !foundSpring {
		t.Errorf("expected WP and Spring paths in adaptive wordlist, got %v", paths)
	}

	tokens := engine.ExtractTokensFromJS("const api = '/v1/users'; fetch('/api/v2/data');")
	if len(tokens) == 0 {
		t.Errorf("expected extracted tokens from JS, got none")
	}
}

func TestSensitiveAndAPIProtocolScanners(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	guard := scope.New([]string{"example.com", "127.0.0.1"})

	sensMod := NewSensitiveExposureScanner(db, guard)
	if sensMod.Name() != "sensitive_exposure_scanner" {
		t.Errorf("unexpected name: %s", sensMod.Name())
	}

	apiMod := NewAPIProtocolScanner(db, guard)
	if apiMod.Name() != "api_protocol_scanner" {
		t.Errorf("unexpected name: %s", apiMod.Name())
	}
}
