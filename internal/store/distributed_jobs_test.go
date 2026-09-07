package store

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDistributedScanJobLeaseAndCompletion(t *testing.T) {
	ctx := context.Background()
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "jobs.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := db.RegisterDistributedAgent(ctx, "agent-a", base64.RawStdEncoding.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	if err := db.HeartbeatDistributedAgent(ctx, "agent-a"); err != nil {
		t.Fatal(err)
	}
	queued, err := db.EnqueueDistributedScanJob(ctx, "scan-a", "AUTH-123", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	leased, err := db.LeaseDistributedScanJob(ctx, "agent-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if leased.ID != queued.ID || leased.LeaseOwner != "agent-a" || leased.Attempts != 1 || leased.Status != "leased" {
		t.Fatalf("unexpected lease: %#v", leased)
	}
	secondKey := append([]byte(nil), key...)
	secondKey[0] = 1
	if _, err := db.RegisterDistributedAgent(ctx, "agent-b", base64.RawStdEncoding.EncodeToString(secondKey)); err != nil {
		t.Fatal(err)
	}
	if err := db.HeartbeatDistributedAgent(ctx, "agent-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.LeaseDistributedScanJob(ctx, "agent-b", time.Minute); !errors.Is(err, ErrNoDistributedJob) {
		t.Fatalf("expected no second lease, got %v", err)
	}
	if err := db.CompleteDistributedScanJob(ctx, leased.ID, "agent-b", "completed"); !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("expected non-owner completion to fail, got %v", err)
	}
	if err := db.CompleteDistributedScanJob(ctx, leased.ID, "agent-a", "completed"); err != nil {
		t.Fatal(err)
	}
}

func TestDistributedLeaseRequiresFreshOnlineAgentAndStatusIsReadOnly(t *testing.T) {
	ctx := context.Background()
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "jobs-status.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnqueueDistributedScanJob(ctx, "scan-status", "AUTH-456", strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.LeaseDistributedScanJob(ctx, "unknown-agent", time.Minute); err == nil {
		t.Fatal("expected an unknown agent lease to be rejected")
	}
	status, err := db.DistributedCoordinatorStatus(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Jobs) != 1 || status.JobsByStatus["queued"] != 1 || len(status.Agents) != 0 {
		t.Fatalf("unexpected coordinator status: %#v", status)
	}
}
