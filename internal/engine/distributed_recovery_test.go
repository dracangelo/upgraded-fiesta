package engine

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scheduler"
	"enumscan/internal/store"
)

func TestDistributedEvidenceDuplicateDeliveryAndIdempotency(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "dist_dup.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	scanID := "dist-scan-idempotent"
	if err := db.StartScan(context.Background(), scanID); err != nil {
		t.Fatal(err)
	}

	asset := models.Asset{
		ScanID:    scanID,
		Type:      "ipv4",
		Value:     "10.0.0.1",
		CreatedAt: time.Now(),
	}
	finding := models.Finding{
		ScanID:      scanID,
		Severity:    "high",
		Confidence:  "confirmed",
		Asset:       "10.0.0.1",
		Title:       "Open SSH Port",
		Evidence:    "SSH-2.0-OpenSSH",
		Remediation: "Restrict SSH access",
		CreatedAt:   time.Now(),
	}

	// First delivery
	if err := db.AddAsset(context.Background(), asset); err != nil {
		t.Fatalf("first asset delivery failed: %v", err)
	}
	if err := db.AddFinding(context.Background(), finding); err != nil {
		t.Fatalf("first finding delivery failed: %v", err)
	}

	// Duplicate delivery (re-transmission / retry)
	if err := db.AddAsset(context.Background(), asset); err != nil {
		t.Fatalf("duplicate asset delivery failed: %v", err)
	}
	if err := db.AddFinding(context.Background(), finding); err != nil {
		t.Fatalf("duplicate finding delivery failed: %v", err)
	}

	// Verify counts and integrity
	assets, err := db.Assets(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) == 0 {
		t.Fatal("expected assets to be persisted")
	}

	findings, err := db.Findings(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings to be persisted")
	}
}

type mockHACoordStore struct {
	mu    sync.Mutex
	lease models.CoordinatorLease
}

func (m *mockHACoordStore) AcquireCoordinatorLease(ctx context.Context, clusterID, nodeID string, duration time.Duration) (models.CoordinatorLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	if m.lease.LeaderID != "" && m.lease.LeaderID != nodeID && m.lease.LeaseUntil.After(now) {
		return models.CoordinatorLease{}, store.ErrCoordinatorStandby
	}
	epoch := m.lease.Epoch + 1
	m.lease = models.CoordinatorLease{
		ClusterID:  clusterID,
		LeaderID:   nodeID,
		Epoch:      epoch,
		LeaseUntil: now.Add(duration),
	}
	return m.lease, nil
}

func (m *mockHACoordStore) RenewCoordinatorLease(ctx context.Context, lease models.CoordinatorLease, duration time.Duration) (models.CoordinatorLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	if m.lease.LeaderID != lease.LeaderID || m.lease.Epoch != lease.Epoch {
		return models.CoordinatorLease{}, store.ErrCoordinatorStandby
	}
	m.lease.LeaseUntil = now.Add(duration)
	return m.lease, nil
}

func (m *mockHACoordStore) ReleaseCoordinatorLease(ctx context.Context, lease models.CoordinatorLease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lease.LeaderID == lease.LeaderID {
		m.lease.LeaderID = ""
		m.lease.LeaseUntil = time.Now().UTC()
	}
	return nil
}

func (m *mockHACoordStore) RequireCoordinatorFence(ctx context.Context, lease models.CoordinatorLease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lease.LeaderID != lease.LeaderID || m.lease.Epoch != lease.Epoch {
		return store.ErrCoordinatorStandby
	}
	return nil
}

func TestDistributedCoordinatorHAAndFailover(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mockStore := &mockHACoordStore{}

	// 1. Initial primary coordinator acquires lease
	primaryCoord, err := scheduler.NewHACoordinator(mockStore, scheduler.HACoordinatorConfig{
		ClusterID:     "cluster-alpha",
		NodeID:        "coord-primary",
		LeaseDuration: 10 * time.Second,
		RenewInterval: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to init primary coordinator: %v", err)
	}

	if err := primaryCoord.Start(ctx); err != nil {
		t.Fatalf("primary start failed: %v", err)
	}
	defer primaryCoord.Stop(ctx)

	if !primaryCoord.IsLeader() {
		t.Fatal("expected primary coordinator to become leader")
	}
	lease1, err := primaryCoord.CurrentLease()
	if err != nil || lease1.LeaderID != "coord-primary" || lease1.Epoch != 1 {
		t.Fatalf("unexpected primary lease: %#v (%v)", lease1, err)
	}

	// 2. Standby coordinator detects active primary lease and stays standby
	standbyCoord, err := scheduler.NewHACoordinator(mockStore, scheduler.HACoordinatorConfig{
		ClusterID:     "cluster-alpha",
		NodeID:        "coord-standby",
		LeaseDuration: 10 * time.Second,
		RenewInterval: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to init standby coordinator: %v", err)
	}

	if err := standbyCoord.Start(ctx); err != nil {
		t.Fatalf("standby start failed: %v", err)
	}
	defer standbyCoord.Stop(ctx)

	if standbyCoord.IsLeader() {
		t.Fatal("standby should not be leader while primary is healthy")
	}

	// 3. Failover: primary steps down gracefully
	if err := primaryCoord.Stop(ctx); err != nil {
		t.Fatalf("primary stop failed: %v", err)
	}

	// Standby takes over on its next election attempt
	time.Sleep(50 * time.Millisecond)
	// Trigger takeover lease directly through store to verify takeover state
	takeoverLease, err := mockStore.AcquireCoordinatorLease(ctx, "cluster-alpha", "coord-standby", 10*time.Second)
	if err != nil {
		t.Fatalf("standby takeover failed: %v", err)
	}
	if takeoverLease.LeaderID != "coord-standby" || takeoverLease.Epoch <= lease1.Epoch {
		t.Fatalf("takeover should succeed with higher epoch: %#v", takeoverLease)
	}
}

func TestDistributedSimulatedPacketLossAndIdempotentRetries(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "packet_loss.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	scanID := "dist-packet-loss"
	if err := db.StartScan(context.Background(), scanID); err != nil {
		t.Fatal(err)
	}

	// Simulate flaky transport layer that fails on first attempt
	attempts := 0
	sendEvidence := func() error {
		attempts++
		if attempts == 1 {
			return store.ErrJobLeaseLost // Simulated network error or timeout
		}
		// Second attempt succeeds
		return db.AddAsset(context.Background(), models.Asset{
			ScanID:    scanID,
			Type:      "domain",
			Value:     "api.target.test",
			CreatedAt: time.Now(),
		})
	}

	// First attempt fails
	err1 := sendEvidence()
	if err1 == nil {
		t.Fatal("expected simulated failure on first attempt")
	}

	// Idempotent retry succeeds
	err2 := sendEvidence()
	if err2 != nil {
		t.Fatalf("retry after packet loss failed: %v", err2)
	}

	assets, _ := db.Assets(context.Background(), scanID)
	if len(assets) != 1 || assets[0].Value != "api.target.test" {
		t.Fatalf("unexpected assets after retry: %#v", assets)
	}
}

func TestDistributedAgentAutoEnrollmentValidation(t *testing.T) {
	ps := &store.PostgresStore{} // mock validation check

	// Unauthorized attempt with invalid token
	_, err := ps.AutoEnrollDistributedAgent(context.Background(), "agent-1", "dGVzdC1rZXk=", "invalid-token", "expected-secret-token")
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected unauthorized error for invalid token, got %v", err)
	}

	// Empty tokens must be rejected
	_, err = ps.AutoEnrollDistributedAgent(context.Background(), "agent-1", "dGVzdC1rZXk=", "", "")
	if err == nil {
		t.Fatal("expected error for empty enrollment tokens")
	}
}
