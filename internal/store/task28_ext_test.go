package store

import (
	"context"
	"testing"
)

func TestTask28SecretsManagement(t *testing.T) {
	ctx := context.Background()

	// 1. Env & Local Backend Test
	secMgr := NewMultiBackendSecretsManager(ProviderEnv)
	if err := secMgr.SetSecret(ctx, "db_pass", "secret123"); err != nil {
		t.Fatalf("SetSecret failed: %v", err)
	}
	val, err := secMgr.GetSecret(ctx, "db_pass")
	if err != nil || val != "secret123" {
		t.Fatalf("GetSecret failed")
	}

	// 2. Secret Rotation Test
	if err := secMgr.RotateSecret(ctx, "db_pass", "new_secret456"); err != nil {
		t.Fatalf("RotateSecret failed: %v", err)
	}
	newVal, err := secMgr.GetSecret(ctx, "db_pass")
	if err != nil || newVal != "new_secret456" {
		t.Fatalf("rotated secret mismatch")
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
		sec, err := bm.GetSecret(ctx, "api_key")
		if err != nil || sec == "" {
			t.Fatalf("failed to retrieve secret for backend %s", backend)
		}
	}
}
