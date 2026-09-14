package scheduler

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

// mockCoordinatorStore implements CoordinatorStore for service-level failover and partition testing.
type mockCoordinatorStore struct {
	mu           sync.Mutex
	currentLease models.CoordinatorLease
	partitioned  map[string]bool
	mutations    []string
}

func newMockCoordinatorStore() *mockCoordinatorStore {
	return &mockCoordinatorStore{
		partitioned: make(map[string]bool),
	}
}

func (m *mockCoordinatorStore) AcquireCoordinatorLease(ctx context.Context, clusterID, nodeID string, duration time.Duration) (models.CoordinatorLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.partitioned[nodeID] {
		return models.CoordinatorLease{}, errors.New("network partition simulated")
	}

	now := time.Now().UTC()
	if m.currentLease.LeaderID != "" && m.currentLease.LeaderID != nodeID && m.currentLease.LeaseUntil.After(now) {
		return models.CoordinatorLease{}, store.ErrCoordinatorStandby
	}

	epoch := m.currentLease.Epoch
	if m.currentLease.LeaderID != nodeID {
		epoch++
	}

	m.currentLease = models.CoordinatorLease{
		ClusterID:  clusterID,
		LeaderID:   nodeID,
		Epoch:      epoch,
		LeaseUntil: now.Add(duration),
	}
	return m.currentLease, nil
}

func (m *mockCoordinatorStore) RenewCoordinatorLease(ctx context.Context, lease models.CoordinatorLease, duration time.Duration) (models.CoordinatorLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.partitioned[lease.LeaderID] {
		return models.CoordinatorLease{}, errors.New("network partition simulated")
	}

	now := time.Now().UTC()
	if m.currentLease.ClusterID != lease.ClusterID || m.currentLease.LeaderID != lease.LeaderID || m.currentLease.Epoch != lease.Epoch {
		return models.CoordinatorLease{}, store.ErrCoordinatorFenceLost
	}
	if !m.currentLease.LeaseUntil.After(now) {
		return models.CoordinatorLease{}, store.ErrCoordinatorFenceLost
	}

	m.currentLease.LeaseUntil = now.Add(duration)
	return m.currentLease, nil
}

func (m *mockCoordinatorStore) RequireCoordinatorFence(ctx context.Context, lease models.CoordinatorLease) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.partitioned[lease.LeaderID] {
		return errors.New("network partition simulated")
	}

	now := time.Now().UTC()
	if m.currentLease.ClusterID != lease.ClusterID || m.currentLease.LeaderID != lease.LeaderID || m.currentLease.Epoch != lease.Epoch {
		return store.ErrCoordinatorFenceLost
	}
	if !m.currentLease.LeaseUntil.After(now) {
		return store.ErrCoordinatorFenceLost
	}
	return nil
}

func (m *mockCoordinatorStore) ReleaseCoordinatorLease(ctx context.Context, lease models.CoordinatorLease) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentLease.ClusterID == lease.ClusterID && m.currentLease.LeaderID == lease.LeaderID && m.currentLease.Epoch == lease.Epoch {
		m.currentLease.LeaseUntil = time.Now().UTC().Add(-time.Second)
	}
	return nil
}

func TestHACoordinatorElectionAndStandby(t *testing.T) {
	mockStore := newMockCoordinatorStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coordA, err := NewHACoordinator(mockStore, HACoordinatorConfig{
		ClusterID:     "cluster-alpha",
		NodeID:        "node-a",
		LeaseDuration: 5 * time.Second,
		RenewInterval: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHACoordinator(node-a) failed: %v", err)
	}

	coordB, err := NewHACoordinator(mockStore, HACoordinatorConfig{
		ClusterID:     "cluster-alpha",
		NodeID:        "node-b",
		LeaseDuration: 5 * time.Second,
		RenewInterval: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHACoordinator(node-b) failed: %v", err)
	}

	if err := coordA.Start(ctx); err != nil {
		t.Fatalf("coordA.Start failed: %v", err)
	}
	defer coordA.Stop(ctx)

	if !coordA.IsLeader() {
		t.Fatalf("expected node-a to be elected leader")
	}
	if coordA.CurrentEpoch() != 1 {
		t.Fatalf("expected node-a epoch 1, got %d", coordA.CurrentEpoch())
	}

	// Start node-b as standby
	if err := coordB.Start(ctx); err != nil {
		t.Fatalf("coordB.Start failed: %v", err)
	}
	defer coordB.Stop(ctx)

	if coordB.IsLeader() {
		t.Fatalf("expected node-b to be standby while node-a is active leader")
	}
}

func TestHACoordinatorServiceFailoverAndFencing(t *testing.T) {
	mockStore := newMockCoordinatorStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coordA, _ := NewHACoordinator(mockStore, HACoordinatorConfig{
		ClusterID:     "cluster-failover",
		NodeID:        "node-failover-a",
		LeaseDuration: 5 * time.Second,
		RenewInterval: 50 * time.Millisecond,
	})
	coordB, _ := NewHACoordinator(mockStore, HACoordinatorConfig{
		ClusterID:     "cluster-failover",
		NodeID:        "node-failover-b",
		LeaseDuration: 5 * time.Second,
		RenewInterval: 50 * time.Millisecond,
	})

	_ = coordA.Start(ctx)
	_ = coordB.Start(ctx)

	if !coordA.IsLeader() {
		t.Fatalf("expected coordA to be leader")
	}

	// Execute mutation successfully on Node A
	mutationRan := false
	err := coordA.ExecuteFencedMutation(ctx, func(ctx context.Context, lease models.CoordinatorLease) error {
		mutationRan = true
		return nil
	})
	if err != nil || !mutationRan {
		t.Fatalf("coordA failed to execute fenced mutation: %v", err)
	}

	// Capture old lease from A
	staleLease, _ := coordA.CurrentLease()

	// Simulate crash of Node A: stop without graceful release, expire lease
	_ = coordA.Stop(ctx)
	mockStore.mu.Lock()
	mockStore.currentLease.LeaseUntil = time.Now().UTC().Add(-time.Second) // expired
	mockStore.mu.Unlock()

	// Give Node B time to detect lease expiration and take over
	time.Sleep(150 * time.Millisecond)

	if !coordB.IsLeader() {
		t.Fatalf("expected coordB to have taken over leadership after failover")
	}
	if coordB.CurrentEpoch() <= staleLease.Epoch {
		t.Fatalf("expected epoch to increase on takeover (stale=%d, new=%d)", staleLease.Epoch, coordB.CurrentEpoch())
	}

	// Try executing mutation from stale Node A lease - must be rejected with fence lost
	err = mockStore.RequireCoordinatorFence(ctx, staleLease)
	if !errors.Is(err, store.ErrCoordinatorFenceLost) {
		t.Fatalf("expected stale lease to be rejected with ErrCoordinatorFenceLost, got %v", err)
	}

	// Execute mutation from new leader Node B - must succeed
	bMutationRan := false
	err = coordB.ExecuteFencedMutation(ctx, func(ctx context.Context, lease models.CoordinatorLease) error {
		bMutationRan = true
		return nil
	})
	if err != nil || !bMutationRan {
		t.Fatalf("coordB failed to execute fenced mutation after failover: %v", err)
	}
}

func TestHACoordinatorNetworkPartition(t *testing.T) {
	mockStore := newMockCoordinatorStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coordA, _ := NewHACoordinator(mockStore, HACoordinatorConfig{
		ClusterID:     "cluster-partition",
		NodeID:        "node-partition-a",
		LeaseDuration: 5 * time.Second,
		RenewInterval: 50 * time.Millisecond,
	})

	_ = coordA.Start(ctx)
	defer coordA.Stop(ctx)

	if !coordA.IsLeader() {
		t.Fatalf("expected node-partition-a to be leader initially")
	}

	// Partition node A
	mockStore.mu.Lock()
	mockStore.partitioned["node-partition-a"] = true
	mockStore.mu.Unlock()

	// Wait for renewal attempt during partition
	time.Sleep(150 * time.Millisecond)

	if coordA.IsLeader() {
		t.Fatalf("expected node-partition-a to step down when partitioned from store")
	}

	// Mutations must fail
	err := coordA.ExecuteFencedMutation(ctx, func(ctx context.Context, lease models.CoordinatorLease) error {
		return nil
	})
	if !errors.Is(err, store.ErrCoordinatorFenceLost) {
		t.Fatalf("expected ErrCoordinatorFenceLost during partition, got %v", err)
	}
}
