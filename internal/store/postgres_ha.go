package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"enumscan/internal/models"
)

var ErrCoordinatorStandby = errors.New("coordinator leadership is held by another active node")
var ErrCoordinatorFenceLost = errors.New("coordinator fencing lease is no longer valid")

// AcquireCoordinatorLease elects one PostgreSQL-backed coordinator. Every
// takeover increments Epoch, yielding a fencing token that stale processes
// cannot reproduce. PostgreSQL row locking serializes concurrent campaigns.
func (p *PostgresStore) AcquireCoordinatorLease(ctx context.Context, clusterID, nodeID string, duration time.Duration) (models.CoordinatorLease, error) {
	if p.db == nil {
		return models.CoordinatorLease{}, p.notOpenError()
	}
	if !validDistributedAgentID(clusterID) || !validDistributedAgentID(nodeID) || duration < 5*time.Second || duration > time.Minute {
		return models.CoordinatorLease{}, fmt.Errorf("cluster ID, node ID, and a lease duration between five seconds and one minute are required")
	}
	now := time.Now().UTC()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return models.CoordinatorLease{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO coordinator_leases(cluster_id,lease_until) VALUES($1,$2) ON CONFLICT(cluster_id) DO NOTHING`, clusterID, now.Add(-time.Second)); err != nil {
		return models.CoordinatorLease{}, err
	}
	var lease models.CoordinatorLease
	err = tx.QueryRowContext(ctx, `SELECT cluster_id,leader_id,epoch,lease_until FROM coordinator_leases WHERE cluster_id=$1 FOR UPDATE`, clusterID).Scan(&lease.ClusterID, &lease.LeaderID, &lease.Epoch, &lease.LeaseUntil)
	if err != nil {
		return models.CoordinatorLease{}, err
	}
	if lease.LeaderID != "" && lease.LeaderID != nodeID && lease.LeaseUntil.After(now) {
		return models.CoordinatorLease{}, ErrCoordinatorStandby
	}
	if lease.LeaderID != nodeID {
		lease.Epoch++
	}
	lease.LeaderID, lease.LeaseUntil = nodeID, now.Add(duration)
	if _, err = tx.ExecContext(ctx, `UPDATE coordinator_leases SET leader_id=$1,epoch=$2,lease_until=$3,updated_at=CURRENT_TIMESTAMP WHERE cluster_id=$4`, lease.LeaderID, lease.Epoch, lease.LeaseUntil, clusterID); err != nil {
		return models.CoordinatorLease{}, err
	}
	if err = tx.Commit(); err != nil {
		return models.CoordinatorLease{}, err
	}
	return lease, nil
}

// RenewCoordinatorLease preserves an epoch only for its current leader. A
// failed renewal must stop coordinator-owned mutations immediately.
func (p *PostgresStore) RenewCoordinatorLease(ctx context.Context, lease models.CoordinatorLease, duration time.Duration) (models.CoordinatorLease, error) {
	if p.db == nil {
		return models.CoordinatorLease{}, p.notOpenError()
	}
	if duration < 5*time.Second || duration > time.Minute {
		return models.CoordinatorLease{}, fmt.Errorf("lease duration must be between five seconds and one minute")
	}
	now := time.Now().UTC()
	until := now.Add(duration)
	result, err := p.db.ExecContext(ctx, `UPDATE coordinator_leases SET lease_until=$1,updated_at=CURRENT_TIMESTAMP WHERE cluster_id=$2 AND leader_id=$3 AND epoch=$4 AND lease_until>$5`, until, lease.ClusterID, lease.LeaderID, lease.Epoch, now)
	if err != nil {
		return models.CoordinatorLease{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return models.CoordinatorLease{}, ErrCoordinatorFenceLost
	}
	lease.LeaseUntil = until
	return lease, nil
}

// RequireCoordinatorFence is the mutation boundary. Coordinator-owned work
// must call it with the epoch received from Acquire/Renew before dispatching.
func (p *PostgresStore) RequireCoordinatorFence(ctx context.Context, lease models.CoordinatorLease) error {
	if p.db == nil {
		return p.notOpenError()
	}
	var found time.Time
	err := p.db.QueryRowContext(ctx, `SELECT lease_until FROM coordinator_leases WHERE cluster_id=$1 AND leader_id=$2 AND epoch=$3`, lease.ClusterID, lease.LeaderID, lease.Epoch).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCoordinatorFenceLost
	}
	if err != nil {
		return err
	}
	if !found.After(time.Now().UTC()) {
		return ErrCoordinatorFenceLost
	}
	return nil
}

func (p *PostgresStore) ReleaseCoordinatorLease(ctx context.Context, lease models.CoordinatorLease) error {
	if p.db == nil {
		return p.notOpenError()
	}
	_, err := p.db.ExecContext(ctx, `UPDATE coordinator_leases SET lease_until=$1,updated_at=CURRENT_TIMESTAMP WHERE cluster_id=$2 AND leader_id=$3 AND epoch=$4`, time.Now().UTC(), lease.ClusterID, lease.LeaderID, lease.Epoch)
	return err
}
