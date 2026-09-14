package plugin

import (
	"errors"
	"testing"
)

func TestSafeHotReloadLifecycleAndRollback(t *testing.T) {
	mgr := NewSafeHotReloadManager()

	manifestV1 := PluginManifest{
		Name:    "ssl-scanner",
		Version: "1.0.0",
		Type:    "grpc",
		Exec:    "/bin/ssl-scanner",
	}

	// 1. Discovery and registration: must be in "registered" state without auto-execution
	stage1, err := mgr.RegisterDiscoveredPlugin(manifestV1)
	if err != nil {
		t.Fatalf("failed registering plugin: %v", err)
	}
	if stage1.State != PluginStateRegistered {
		t.Errorf("expected state %s, got %s", PluginStateRegistered, stage1.State)
	}

	// 2. Promotion before verification MUST fail
	if err := mgr.PromoteToActive("ssl-scanner", "1.0.0"); !errors.Is(err, ErrPluginNotVerified) {
		t.Fatalf("expected ErrPluginNotVerified, got: %v", err)
	}

	// 3. Verification gate
	verifyErr := errors.New("bad signature")
	if err := mgr.VerifyPluginStage("ssl-scanner", "1.0.0", func(m PluginManifest) error {
		return verifyErr
	}); !errors.Is(err, verifyErr) {
		t.Fatalf("expected verification failure to propagate, got: %v", err)
	}

	// Successful verification
	if err := mgr.VerifyPluginStage("ssl-scanner", "1.0.0", func(m PluginManifest) error {
		return nil
	}); err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	stage1, _ = mgr.GetStage("ssl-scanner", "1.0.0")
	if stage1.State != PluginStateVerified {
		t.Errorf("expected state %s, got %s", PluginStateVerified, stage1.State)
	}

	// 4. Promotion to active
	if err := mgr.PromoteToActive("ssl-scanner", "1.0.0"); err != nil {
		t.Fatalf("failed promoting v1 to active: %v", err)
	}

	active, ok := mgr.GetActivePlugin("ssl-scanner")
	if !ok || active.Version != "1.0.0" || active.State != PluginStateActive {
		t.Fatalf("expected v1.0.0 active, got %+v", active)
	}

	// 5. Staging and promoting v2
	manifestV2 := PluginManifest{
		Name:    "ssl-scanner",
		Version: "2.0.0",
		Type:    "grpc",
		Exec:    "/bin/ssl-scanner-v2",
	}
	if _, err := mgr.RegisterDiscoveredPlugin(manifestV2); err != nil {
		t.Fatalf("failed registering v2: %v", err)
	}
	if err := mgr.VerifyPluginStage("ssl-scanner", "2.0.0", nil); err != nil {
		t.Fatalf("failed verifying v2: %v", err)
	}
	if err := mgr.PromoteToActive("ssl-scanner", "2.0.0"); err != nil {
		t.Fatalf("failed promoting v2: %v", err)
	}

	activeV2, ok := mgr.GetActivePlugin("ssl-scanner")
	if !ok || activeV2.Version != "2.0.0" {
		t.Fatalf("expected v2 active, got %+v", activeV2)
	}

	// 6. Instant rollback to v1
	if err := mgr.Rollback("ssl-scanner"); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	rolledBack, ok := mgr.GetActivePlugin("ssl-scanner")
	if !ok || rolledBack.Version != "1.0.0" || rolledBack.State != PluginStateActive {
		t.Fatalf("expected rolled back to v1.0.0 active, got %+v", rolledBack)
	}

	// 7. Rollback again when no previous remains should return ErrNoRollbackAvailable
	if err := mgr.Rollback("ssl-scanner"); !errors.Is(err, ErrNoRollbackAvailable) {
		t.Fatalf("expected ErrNoRollbackAvailable, got: %v", err)
	}
}
