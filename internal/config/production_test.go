package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRequiresAuthorization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("scope:\n  allowed_targets: [\"127.0.0.1\"]\nscan:\n  targets: [\"127.0.0.1\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected missing authorization to be rejected")
	}
}

func TestProductionProfileRequiresReplacement(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "production.yaml")
	if _, err := Load(path); err == nil {
		t.Fatal("expected placeholder production profile to be rejected")
	}
}
