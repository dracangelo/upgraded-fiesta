package store

import (
	"context"
	"testing"
)

func TestTask28SecretsManagement(t *testing.T) {
	ctx := context.Background()

	// 1. Env & Local Backend Test
	secMgr := NewMultiBackendSecretsManager(ProviderEnv)
	t.Setenv("ENUMSCAN_SECRET_DB_PASS", "secret123")
	val, err := secMgr.GetSecret(ctx, "db_pass")
	if err != nil || val != "secret123" {
		t.Fatalf("GetSecret failed")
	}

	// 2. Secret writes and rotation must not fabricate process-local state.
	if err := secMgr.SetSecret(ctx, "db_pass", "new_secret456"); err == nil {
		t.Fatal("environment secrets must reject in-process writes")
	}
	if err := secMgr.RotateSecret(ctx, "db_pass", "new_secret456"); err == nil {
		t.Fatal("environment secrets must reject in-process rotation")
	}

	// 3. Multi-Backend Providers Test
	backends := []ProviderType{
		ProviderOSKeychain,
		ProviderVault,
		ProviderK8s,
		ProviderAWS,
		ProviderAzure,
		ProviderGCP,
	}

	for _, backend := range backends {
		bm := NewMultiBackendSecretsManager(backend)
		if _, err := bm.GetSecret(ctx, "api_key"); err == nil {
			t.Fatalf("backend %s must not fabricate a secret", backend)
		}
	}
}
