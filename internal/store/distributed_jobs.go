package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"enumscan/internal/models"
)

var ErrNoDistributedJob = errors.New("no distributed scan job is available")
var ErrJobLeaseLost = errors.New("distributed scan job lease is no longer held by this agent")

func (s *SQLiteCLI) EnqueueDistributedScanJob(ctx context.Context, scanID, authorizationRef, configDigest string) (models.DistributedScanJob, error) {
	if strings.TrimSpace(scanID) == "" || strings.TrimSpace(authorizationRef) == "" || len(strings.TrimSpace(configDigest)) != 64 {
		return models.DistributedScanJob{}, fmt.Errorf("scan ID, authorization reference, and SHA-256 configuration digest are required")
	}
	id, err := distributedJobID()
	if err != nil {
		return models.DistributedScanJob{}, err
	}
	created := time.Now().UTC()
	job := models.DistributedScanJob{ID: id, ScanID: scanID, AuthorizationRef: authorizationRef, ConfigDigest: configDigest, Status: "queued", CreatedAt: created}
	_, err = s.db.ExecContext(ctx, `INSERT INTO distributed_scan_jobs(id,scan_id,authorization_ref,config_digest,status,created_at) VALUES(?,?,?,?,?,?)`, job.ID, job.ScanID, job.AuthorizationRef, job.ConfigDigest, job.Status, job.CreatedAt.Format(time.RFC3339Nano))
	return job, err
}

// IngestDistributedEvidence atomically accepts bounded evidence only from the
// agent that currently owns an unexpired lease. Agent-supplied IDs and times
// are ignored; the coordinator remains the authority for persisted records.
func (s *SQLiteCLI) IngestDistributedEvidence(ctx context.Context, agentID string, envelope models.DistributedEvidence) error {
	if envelope.JobID == "" || len(envelope.Assets) > 10000 || len(envelope.Findings) > 10000 || len(envelope.Events) > 50000 {
		return fmt.Errorf("distributed evidence envelope is invalid or exceeds bounds")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var scanID string
	err = tx.QueryRowContext(ctx, `SELECT scan_id FROM distributed_scan_jobs WHERE id=? AND lease_owner=? AND status='leased' AND lease_until > ?`, envelope.JobID, agentID, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrJobLeaseLost
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_runs(scan_id,status) VALUES(?, 'running') ON CONFLICT(scan_id) DO UPDATE SET status='running',error='',finished_at=NULL`, scanID); err != nil {
		return err
	}
	for _, asset := range envelope.Assets {
		if asset.ScanID != scanID {
			return fmt.Errorf("distributed asset is not bound to leased scan")
		}
		asset, err = s.protectAsset(asset)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO assets(scan_id,type,value,parent,metadata) VALUES(?,?,?,?,?)`, scanID, asset.Type, asset.Value, asset.Parent, asset.Metadata); err != nil {
			return err
		}
	}
	for _, finding := range envelope.Findings {
		if finding.ScanID != scanID {
			return fmt.Errorf("distributed finding is not bound to leased scan")
		}
		references, err := json.Marshal(finding.References)
		if err != nil {
			return err
		}
		verification := finding.Verification
		if verification == "" {
			verification = "confirmed"
		}
		finding, err = s.protectFinding(finding)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO findings(scan_id,severity,confidence,verification,asset,title,evidence,remediation,cwe,cve,cvss,epss,kev,references_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, scanID, finding.Severity, finding.Confidence, verification, finding.Asset, finding.Title, finding.Evidence, finding.Remediation, finding.CWE, finding.CVE, finding.CVSS, finding.EPSS, finding.KEV, string(references)); err != nil {
			return err
		}
	}
	for _, event := range envelope.Events {
		if event.ScanID != scanID {
			return fmt.Errorf("distributed event is not bound to leased scan")
		}
		event, data, err := s.protectEvent(event)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO events(scan_id,type,target,data) VALUES(?,?,?,?)`, scanID, event.Type, event.Target, data); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteCLI) LeaseDistributedScanJob(ctx context.Context, agentID string, duration time.Duration) (models.DistributedScanJob, error) {
	if strings.TrimSpace(agentID) == "" || duration < time.Second || duration > 30*time.Minute {
		return models.DistributedScanJob{}, fmt.Errorf("agent ID and a lease duration between one second and thirty minutes are required")
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return models.DistributedScanJob{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var agentStatus string
	var heartbeat string
	if err := tx.QueryRowContext(ctx, `SELECT status,last_heartbeat FROM distributed_agents WHERE id=?`, agentID).Scan(&agentStatus, &heartbeat); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.DistributedScanJob{}, fmt.Errorf("distributed agent %q is not enrolled", agentID)
		}
		return models.DistributedScanJob{}, err
	}
	if agentStatus != "online" || parseSQLiteTime(heartbeat).Before(now.Add(-5*time.Minute)) {
		return models.DistributedScanJob{}, fmt.Errorf("distributed agent %q must have an online heartbeat within five minutes", agentID)
	}
	var job models.DistributedScanJob
	var created string
	err = tx.QueryRowContext(ctx, `SELECT id,scan_id,authorization_ref,config_digest,status,attempts,created_at FROM distributed_scan_jobs WHERE status='queued' OR (status='leased' AND lease_until <= ?) ORDER BY created_at,id LIMIT 1`, now.Format(time.RFC3339Nano)).Scan(&job.ID, &job.ScanID, &job.AuthorizationRef, &job.ConfigDigest, &job.Status, &job.Attempts, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return models.DistributedScanJob{}, ErrNoDistributedJob
	}
	if err != nil {
		return models.DistributedScanJob{}, err
	}
	job.LeaseOwner = agentID
	job.LeaseUntil = now.Add(duration)
	job.Status = "leased"
	job.Attempts++
	job.CreatedAt = parseSQLiteTime(created)
	result, err := tx.ExecContext(ctx, `UPDATE distributed_scan_jobs SET status='leased',lease_owner=?,lease_until=?,attempts=? WHERE id=? AND (status='queued' OR (status='leased' AND lease_until <= ?))`, job.LeaseOwner, job.LeaseUntil.Format(time.RFC3339Nano), job.Attempts, job.ID, now.Format(time.RFC3339Nano))
	if err != nil {
		return models.DistributedScanJob{}, err
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return models.DistributedScanJob{}, ErrNoDistributedJob
	}
	if err := tx.Commit(); err != nil {
		return models.DistributedScanJob{}, err
	}
	return job, nil
}

// DistributedCoordinatorStatus returns recent durable coordinator records for
// local operator inspection. It never contacts or dispatches to an agent.
func (s *SQLiteCLI) DistributedCoordinatorStatus(ctx context.Context, limit int) (models.DistributedCoordinatorStatus, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	status := models.DistributedCoordinatorStatus{
		Jobs:         make([]models.DistributedScanJob, 0),
		Agents:       make([]models.DistributedAgent, 0),
		JobsByStatus: make(map[string]int),
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,scan_id,authorization_ref,config_digest,status,lease_owner,lease_until,attempts,created_at FROM distributed_scan_jobs ORDER BY created_at DESC,id DESC LIMIT ?`, limit)
	if err != nil {
		return status, err
	}
	defer rows.Close()
	for rows.Next() {
		var job models.DistributedScanJob
		var leaseUntil, created string
		if err := rows.Scan(&job.ID, &job.ScanID, &job.AuthorizationRef, &job.ConfigDigest, &job.Status, &job.LeaseOwner, &leaseUntil, &job.Attempts, &created); err != nil {
			return status, err
		}
		job.LeaseUntil = parseSQLiteTime(leaseUntil)
		job.CreatedAt = parseSQLiteTime(created)
		status.Jobs = append(status.Jobs, job)
		status.JobsByStatus[job.Status]++
	}
	if err := rows.Err(); err != nil {
		return status, err
	}
	agents, err := s.db.QueryContext(ctx, `SELECT id,public_key_fingerprint,status,last_heartbeat,registered_at FROM distributed_agents ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return status, err
	}
	defer agents.Close()
	for agents.Next() {
		var agent models.DistributedAgent
		var heartbeat, registered string
		if err := agents.Scan(&agent.ID, &agent.PublicKeyFingerprint, &agent.Status, &heartbeat, &registered); err != nil {
			return status, err
		}
		agent.LastHeartbeat = parseSQLiteTime(heartbeat)
		agent.RegisteredAt = parseSQLiteTime(registered)
		status.Agents = append(status.Agents, agent)
	}
	return status, agents.Err()
}

func (s *SQLiteCLI) CompleteDistributedScanJob(ctx context.Context, jobID, agentID, status string) error {
	if status != "completed" && status != "failed" {
		return fmt.Errorf("distributed job status must be completed or failed")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var scanID string
	err = tx.QueryRowContext(ctx, `SELECT scan_id FROM distributed_scan_jobs WHERE id=? AND lease_owner=? AND status='leased' AND lease_until > ?`, jobID, agentID, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrJobLeaseLost
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE distributed_scan_jobs SET status=?,completed_at=CURRENT_TIMESTAMP WHERE id=?`, status, jobID); err != nil {
		return err
	}
	message := ""
	if status == "failed" {
		message = "remote agent reported scan failure"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_runs(scan_id,status,error,finished_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(scan_id) DO UPDATE SET status=excluded.status,error=excluded.error,finished_at=CURRENT_TIMESTAMP`, scanID, status, message); err != nil {
		return err
	}
	return tx.Commit()
}

func distributedJobID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate distributed job ID: %w", err)
	}
	return "job-" + hex.EncodeToString(bytes), nil
}
