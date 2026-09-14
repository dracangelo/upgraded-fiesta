package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

var (
	ErrCoordinatorNotLeader = errors.New("coordinator node is not the active leader")
)

// CoordinatorStore defines the transactional fencing and lease interface required for HA.
type CoordinatorStore interface {
	AcquireCoordinatorLease(ctx context.Context, clusterID, nodeID string, duration time.Duration) (models.CoordinatorLease, error)
	RenewCoordinatorLease(ctx context.Context, lease models.CoordinatorLease, duration time.Duration) (models.CoordinatorLease, error)
	RequireCoordinatorFence(ctx context.Context, lease models.CoordinatorLease) error
	ReleaseCoordinatorLease(ctx context.Context, lease models.CoordinatorLease) error
}

// HACoordinatorConfig configures active/passive coordinator election and heartbeat.
type HACoordinatorConfig struct {
	ClusterID     string
	NodeID        string
	LeaseDuration time.Duration
	RenewInterval time.Duration
}

// HACoordinator provides high-availability coordinator supervision with fenced mutations.
type HACoordinator struct {
	store    CoordinatorStore
	config   HACoordinatorConfig
	mu       sync.RWMutex
	lease    models.CoordinatorLease
	isLeader bool
	stopCh   chan struct{}
	doneCh   chan struct{}
	running  bool
}

// NewHACoordinator creates a high-availability coordinator instance.
func NewHACoordinator(store CoordinatorStore, config HACoordinatorConfig) (*HACoordinator, error) {
	if store == nil {
		return nil, fmt.Errorf("coordinator store is required")
	}
	if config.ClusterID == "" || config.NodeID == "" {
		return nil, fmt.Errorf("cluster ID and node ID are required")
	}
	if config.LeaseDuration < 5*time.Second || config.LeaseDuration > time.Minute {
		config.LeaseDuration = 10 * time.Second
	}
	if config.RenewInterval <= 0 || config.RenewInterval >= config.LeaseDuration {
		config.RenewInterval = config.LeaseDuration / 3
	}
	return &HACoordinator{
		store:  store,
		config: config,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}, nil
}

// Start begins the background leader election and renewal loop.
func (c *HACoordinator) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("HA coordinator is already running")
	}
	c.running = true
	c.mu.Unlock()

	// Initial election attempt synchronously
	c.tryElection(ctx)

	go c.run(ctx)
	return nil
}

// Stop gracefully shuts down the coordinator and releases leadership if held.
func (c *HACoordinator) Stop(ctx context.Context) error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	close(c.stopCh)
	c.mu.Unlock()

	<-c.doneCh

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isLeader {
		c.isLeader = false
		releaseCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		_ = c.store.ReleaseCoordinatorLease(releaseCtx, c.lease)
	}
	return nil
}

// IsLeader reports whether this node currently holds an active, unexpired lease.
func (c *HACoordinator) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isLeader && time.Now().UTC().Before(c.lease.LeaseUntil)
}

// CurrentLease returns the active lease or an error if this node is standby.
func (c *HACoordinator) CurrentLease() (models.CoordinatorLease, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.isLeader || !time.Now().UTC().Before(c.lease.LeaseUntil) {
		return models.CoordinatorLease{}, store.ErrCoordinatorStandby
	}
	return c.lease, nil
}

// CurrentEpoch returns the monotonic fencing epoch of the active lease or 0 if not leader.
func (c *HACoordinator) CurrentEpoch() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.isLeader {
		return 0
	}
	return c.lease.Epoch
}

// ExecuteFencedMutation guards coordinator mutations behind fence validation.
// If leadership is lost, expired, or superseded, it aborts with ErrCoordinatorFenceLost.
func (c *HACoordinator) ExecuteFencedMutation(ctx context.Context, mutation func(ctx context.Context, lease models.CoordinatorLease) error) error {
	c.mu.RLock()
	if !c.isLeader || !time.Now().UTC().Before(c.lease.LeaseUntil) {
		c.mu.RUnlock()
		return store.ErrCoordinatorFenceLost
	}
	activeLease := c.lease
	c.mu.RUnlock()

	// Verify fence in datastore
	if err := c.store.RequireCoordinatorFence(ctx, activeLease); err != nil {
		c.mu.Lock()
		c.isLeader = false
		c.mu.Unlock()
		return fmt.Errorf("%w: %v", store.ErrCoordinatorFenceLost, err)
	}

	return mutation(ctx, activeLease)
}

func (c *HACoordinator) run(ctx context.Context) {
	defer close(c.doneCh)
	ticker := time.NewTicker(c.config.RenewInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			leader := c.isLeader
			currentLease := c.lease
			c.mu.RUnlock()

			if leader {
				// Renew lease
				renewCtx, cancel := context.WithTimeout(ctx, c.config.RenewInterval)
				updated, err := c.store.RenewCoordinatorLease(renewCtx, currentLease, c.config.LeaseDuration)
				cancel()
				c.mu.Lock()
				if err != nil {
					// Lease renewal failed; immediately step down
					c.isLeader = false
				} else {
					c.lease = updated
				}
				c.mu.Unlock()
			} else {
				c.tryElection(ctx)
			}
		}
	}
}

func (c *HACoordinator) tryElection(ctx context.Context) {
	acquireCtx, cancel := context.WithTimeout(ctx, c.config.RenewInterval)
	defer cancel()

	lease, err := c.store.AcquireCoordinatorLease(acquireCtx, c.config.ClusterID, c.config.NodeID, c.config.LeaseDuration)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.isLeader = true
		c.lease = lease
	} else {
		c.isLeader = false
	}
}
