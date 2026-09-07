package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretManagerConfigurationAndDatastoreKeyReference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	content := `database:
  path: "data/test.sqlite"
  encryption_key_secret: "enumscan/datastore-key"
secrets:
  provider: "hashicorp_vault"
  endpoint: "https://vault.example"
  token_env: "VAULT_TOKEN"
  mount: "secret"
scope:
  allowed_targets: ["127.0.0.1"]
  authorization: "TEST-AUTH"
scan:
  targets: ["127.0.0.1"]
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.EncryptionKeySecret != "enumscan/datastore-key" || cfg.Secrets.Provider != "hashicorp_vault" || cfg.Secrets.TokenEnv != "VAULT_TOKEN" {
		t.Fatalf("secret configuration not parsed: %#v", cfg.Secrets)
	}
	cfg.Database.EncryptionKeyEnv = "DATASTORE_KEY"
	if err := Validate(cfg); err == nil {
		t.Fatal("multiple datastore key sources must be rejected")
	}
}
