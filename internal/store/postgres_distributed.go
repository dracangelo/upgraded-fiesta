package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"enumscan/internal/models"
)

func (p *PostgresStore) RegisterDistributedAgent(ctx context.Context, agentID, publicKey string) (models.DistributedAgent, error) {
	if p.db == nil {
		return models.DistributedAgent{}, p.notOpenError()
	}
	if !validDistributedAgentID(agentID) {
		return models.DistributedAgent{}, fmt.Errorf("agent ID must be 3-64 lowercase letters, digits, dots, underscores, or hyphens")
	}
	key, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil || len(key) != 32 {
		return models.DistributedAgent{}, fmt.Errorf("agent public key must be an unpadded base64-encoded 32-byte value")
	}
	digest := sha256.Sum256(key)
	now := time.Now().UTC()
	agent := models.DistributedAgent{ID: agentID, PublicKeyFingerprint: hex.EncodeToString(digest[:]), Status: "enrolled", LastHeartbeat: now, RegisteredAt: now}
	_, err = p.db.ExecContext(ctx, `INSERT INTO distributed_agents(id,public_key_fingerprint,public_key,status,last_heartbeat,registered_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET public_key_fingerprint=EXCLUDED.public_key_fingerprint,public_key=EXCLUDED.public_key,status='enrolled',last_heartbeat=EXCLUDED.last_heartbeat`, agent.ID, agent.PublicKeyFingerprint, strings.TrimSpace(publicKey), agent.Status, agent.LastHeartbeat, agent.RegisteredAt)
	return agent, err
}

func (p *PostgresStore) HeartbeatDistributedAgent(ctx context.Context, agentID string) error {
	if p.db == nil {
		return p.notOpenError()
	}
	result, err := p.db.ExecContext(ctx, `UPDATE distributed_agents SET status='online',last_heartbeat=$1 WHERE id=$2`, time.Now().UTC(), agentID)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("distributed agent %q is not enrolled", agentID)
	}
	return nil
}

func (p *PostgresStore) AuthenticateDistributedAgent(ctx context.Context, agentID, timestamp, nonce, signature string, message []byte) error {
	if p.db == nil {
		return p.notOpenError()
	}
	if !validDistributedAgentID(agentID) || len(nonce) < 16 || len(nonce) > 128 {
		return fmt.Errorf("invalid distributed agent authentication headers")
	}
	for _, r := range nonce {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return fmt.Errorf("invalid distributed agent nonce")
		}
	}
	signedAt, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil || time.Since(signedAt).Abs() > 2*time.Minute {
		return fmt.Errorf("distributed agent signature timestamp is outside the allowed window")
	}
	var encoded string
	if err = p.db.QueryRowContext(ctx, `SELECT public_key FROM distributed_agents WHERE id=$1`, agentID).Scan(&encoded); err != nil {
		return fmt.Errorf("distributed agent is not enrolled")
	}
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("distributed agent enrollment has no usable public key")
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), message, sig) {
		return fmt.Errorf("invalid distributed agent signature")
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM distributed_agent_nonces WHERE used_at < $1`, time.Now().UTC().Add(-5*time.Minute)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO distributed_agent_nonces(agent_id,nonce,used_at) VALUES($1,$2,$3)`, agentID, nonce, time.Now().UTC()); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errors.New("distributed agent request nonce was already used")
		}
		return err
	}
	return tx.Commit()
}

func (p *PostgresStore) EnqueueDistributedScanJob(ctx context.Context, scanID, authorizationRef, configDigest string) (models.DistributedScanJob, error) {
	if p.db == nil {
		return models.DistributedScanJob{}, p.notOpenError()
	}
	if strings.TrimSpace(scanID) == "" || strings.TrimSpace(authorizationRef) == "" || len(strings.TrimSpace(configDigest)) != 64 {
		return models.DistributedScanJob{}, fmt.Errorf("scan ID, authorization reference, and SHA-256 configuration digest are required")
	}
	id, err := distributedJobID()
	if err != nil {
		return models.DistributedScanJob{}, err
	}
	job := models.DistributedScanJob{ID: id, ScanID: scanID, AuthorizationRef: authorizationRef, ConfigDigest: configDigest, Status: "queued", CreatedAt: time.Now().UTC()}
	_, err = p.db.ExecContext(ctx, `INSERT INTO distributed_scan_jobs(id,scan_id,authorization_ref,config_digest,status,created_at) VALUES($1,$2,$3,$4,$5,$6)`, job.ID, job.ScanID, job.AuthorizationRef, job.ConfigDigest, job.Status, job.CreatedAt)
	return job, err
}

// IngestDistributedEvidence atomically accepts bounded evidence only from the
// agent that owns an unexpired lease. The coordinator ignores agent-controlled
// identifiers and timestamps; the leased scan ID is the authority for every
// stored record.
func (p *PostgresStore) IngestDistributedEvidence(ctx context.Context, agentID string, envelope models.DistributedEvidence) error {
	if p.db == nil {
		return p.notOpenError()
	}
	if envelope.JobID == "" || len(envelope.Assets) > 10000 || len(envelope.Findings) > 10000 || len(envelope.Events) > 50000 {
		return fmt.Errorf("distributed evidence envelope is invalid or exceeds bounds")
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var scanID string
	err = tx.QueryRowContext(ctx, `SELECT scan_id FROM distributed_scan_jobs WHERE id=$1 AND lease_owner=$2 AND status='leased' AND lease_until > $3 FOR UPDATE`, envelope.JobID, agentID, time.Now().UTC()).Scan(&scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrJobLeaseLost
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_runs(scan_id,status) VALUES($1, 'running') ON CONFLICT(scan_id) DO UPDATE SET status='running',error='',finished_at=NULL`, scanID); err != nil {
		return err
	}
	for _, asset := range envelope.Assets {
		if asset.ScanID != scanID {
			return fmt.Errorf("distributed asset is not bound to leased scan")
		}
		asset, err = p.protectAsset(asset)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO assets(scan_id,type,value,parent,metadata) VALUES($1,$2,$3,$4,$5) ON CONFLICT (scan_id,type,value,parent) DO NOTHING`, scanID, asset.Type, asset.Value, asset.Parent, asset.Metadata); err != nil {
			return err
		}
	}
	for _, finding := range envelope.Findings {
		if finding.ScanID != scanID {
			return fmt.Errorf("distributed finding is not bound to leased scan")
		}
		finding, err = p.protectFinding(finding)
		if err != nil {
			return err
		}
		references, err := json.Marshal(finding.References)
		if err != nil {
			return err
		}
		verification := finding.Verification
		if verification == "" {
			verification = "confirmed"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO findings(scan_id,severity,confidence,verification,asset,title,evidence,remediation,cwe,cve,cvss,epss,kev,references_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, scanID, finding.Severity, finding.Confidence, verification, finding.Asset, finding.Title, finding.Evidence, finding.Remediation, finding.CWE, finding.CVE, finding.CVSS, finding.EPSS, finding.KEV, string(references)); err != nil {
			return err
		}
	}
	for _, event := range envelope.Events {
		if event.ScanID != scanID {
			return fmt.Errorf("distributed event is not bound to leased scan")
		}
		event, data, err := p.protectEvent(event)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO events(scan_id,type,target,data) VALUES($1,$2,$3,$4)`, scanID, event.Type, event.Target, data); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LeaseDistributedScanJob uses SKIP LOCKED, so concurrent PostgreSQL
// coordinators cannot assign the same eligible job.
func (p *PostgresStore) LeaseDistributedScanJob(ctx context.Context, agentID string, duration time.Duration) (models.DistributedScanJob, error) {
	if p.db == nil {
		return models.DistributedScanJob{}, p.notOpenError()
	}
	if strings.TrimSpace(agentID) == "" || duration < time.Second || duration > 30*time.Minute {
		return models.DistributedScanJob{}, fmt.Errorf("agent ID and a lease duration between one second and thirty minutes are required")
	}
	now := time.Now().UTC()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return models.DistributedScanJob{}, err
	}
	defer tx.Rollback()
	var status string
	var heartbeat time.Time
	if err := tx.QueryRowContext(ctx, `SELECT status,last_heartbeat FROM distributed_agents WHERE id=$1 FOR UPDATE`, agentID).Scan(&status, &heartbeat); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.DistributedScanJob{}, fmt.Errorf("distributed agent %q is not enrolled", agentID)
		}
		return models.DistributedScanJob{}, err
	}
	if status != "online" || heartbeat.Before(now.Add(-5*time.Minute)) {
		return models.DistributedScanJob{}, fmt.Errorf("distributed agent %q must have an online heartbeat within five minutes", agentID)
	}
	var job models.DistributedScanJob
	err = tx.QueryRowContext(ctx, `SELECT id,scan_id,authorization_ref,config_digest,attempts,created_at FROM distributed_scan_jobs WHERE status='queued' OR (status='leased' AND lease_until <= $1) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, now).Scan(&job.ID, &job.ScanID, &job.AuthorizationRef, &job.ConfigDigest, &job.Attempts, &job.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return models.DistributedScanJob{}, ErrNoDistributedJob
	}
	if err != nil {
		return models.DistributedScanJob{}, err
	}
	job.Status = "leased"
	job.LeaseOwner = agentID
	job.LeaseUntil = now.Add(duration)
	job.Attempts++
	if _, err = tx.ExecContext(ctx, `UPDATE distributed_scan_jobs SET status='leased',lease_owner=$1,lease_until=$2,attempts=$3 WHERE id=$4`, job.LeaseOwner, job.LeaseUntil, job.Attempts, job.ID); err != nil {
		return models.DistributedScanJob{}, err
	}
	if err = tx.Commit(); err != nil {
		return models.DistributedScanJob{}, err
	}
	return job, nil
}

func (p *PostgresStore) CompleteDistributedScanJob(ctx context.Context, jobID, agentID, status string) error {
	if p.db == nil {
		return p.notOpenError()
	}
	if status != "completed" && status != "failed" {
		return fmt.Errorf("distributed job status must be completed or failed")
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var scanID string
	err = tx.QueryRowContext(ctx, `SELECT scan_id FROM distributed_scan_jobs WHERE id=$1 AND lease_owner=$2 AND status='leased' AND lease_until > $3 FOR UPDATE`, jobID, agentID, time.Now().UTC()).Scan(&scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrJobLeaseLost
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE distributed_scan_jobs SET status=$1,completed_at=CURRENT_TIMESTAMP WHERE id=$2`, status, jobID); err != nil {
		return err
	}
	message := ""
	if status == "failed" {
		message = "remote agent reported scan failure"
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO scan_runs(scan_id,status,error,finished_at) VALUES($1,$2,$3,CURRENT_TIMESTAMP) ON CONFLICT(scan_id) DO UPDATE SET status=EXCLUDED.status,error=EXCLUDED.error,finished_at=CURRENT_TIMESTAMP`, scanID, status, message); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *PostgresStore) DistributedCoordinatorStatus(ctx context.Context, limit int) (models.DistributedCoordinatorStatus, error) {
	status := models.DistributedCoordinatorStatus{Jobs: make([]models.DistributedScanJob, 0), Agents: make([]models.DistributedAgent, 0), JobsByStatus: make(map[string]int)}
	if p.db == nil {
		return status, p.notOpenError()
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id,scan_id,authorization_ref,config_digest,status,lease_owner,lease_until,attempts,created_at FROM distributed_scan_jobs ORDER BY created_at DESC,id DESC LIMIT $1`, limit)
	if err != nil {
		return status, err
	}
	defer rows.Close()
	for rows.Next() {
		var job models.DistributedScanJob
		var until sql.NullTime
		if err := rows.Scan(&job.ID, &job.ScanID, &job.AuthorizationRef, &job.ConfigDigest, &job.Status, &job.LeaseOwner, &until, &job.Attempts, &job.CreatedAt); err != nil {
			return status, err
		}
		if until.Valid {
			job.LeaseUntil = until.Time
		}
		status.Jobs = append(status.Jobs, job)
		status.JobsByStatus[job.Status]++
	}
	if err := rows.Err(); err != nil {
		return status, err
	}
	agents, err := p.db.QueryContext(ctx, `SELECT id,public_key_fingerprint,status,last_heartbeat,registered_at FROM distributed_agents ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return status, err
	}
	defer agents.Close()
	for agents.Next() {
		var agent models.DistributedAgent
		if err := agents.Scan(&agent.ID, &agent.PublicKeyFingerprint, &agent.Status, &agent.LastHeartbeat, &agent.RegisteredAt); err != nil {
			return status, err
		}
		status.Agents = append(status.Agents, agent)
	}
	return status, agents.Err()
}

// FencedEnqueueDistributedScanJob validates the caller's coordinator fencing token
// before enqueuing a distributed scan job.
func (p *PostgresStore) FencedEnqueueDistributedScanJob(ctx context.Context, lease models.CoordinatorLease, scanID, authorizationRef, configDigest string) (models.DistributedScanJob, error) {
	if p.db == nil {
		return models.DistributedScanJob{}, p.notOpenError()
	}
	if err := p.RequireCoordinatorFence(ctx, lease); err != nil {
		return models.DistributedScanJob{}, err
	}
	return p.EnqueueDistributedScanJob(ctx, scanID, authorizationRef, configDigest)
}

// FencedCancelDistributedScanJob validates the caller's coordinator fencing token
// before canceling an active or queued distributed scan job.
func (p *PostgresStore) FencedCancelDistributedScanJob(ctx context.Context, lease models.CoordinatorLease, jobID string) error {
	if p.db == nil {
		return p.notOpenError()
	}
	if err := p.RequireCoordinatorFence(ctx, lease); err != nil {
		return err
	}
	result, err := p.db.ExecContext(ctx, `UPDATE distributed_scan_jobs SET status='failed', completed_at=CURRENT_TIMESTAMP WHERE id=$1 AND status IN ('queued', 'leased')`, jobID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return fmt.Errorf("no active job %q found to cancel", jobID)
	}
	return nil
}

// RequeueDistributedScanJob resets a failed or stuck leased job back to queued state.
func (p *PostgresStore) RequeueDistributedScanJob(ctx context.Context, jobID, reason string) error {
	if p.db == nil {
		return p.notOpenError()
	}
	result, err := p.db.ExecContext(ctx, `
		UPDATE distributed_scan_jobs
		SET status='queued', lease_owner='', lease_until=NULL
		WHERE id=$1 AND status IN ('leased', 'failed')
	`, jobID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return fmt.Errorf("no leased or failed job %q found to requeue", jobID)
	}
	return nil
}

// ResetStuckJobs identifies jobs with expired leases and releases them back to queued status.
func (p *PostgresStore) ResetStuckJobs(ctx context.Context, leaseTimeout time.Duration) (int64, error) {
	if p.db == nil {
		return 0, p.notOpenError()
	}
	result, err := p.db.ExecContext(ctx, `
		UPDATE distributed_scan_jobs
		SET status='queued', lease_owner='', lease_until=NULL
		WHERE status='leased' AND lease_until < CURRENT_TIMESTAMP
	`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// DrainDistributedAgent sets agent status to draining and re-queues any jobs currently leased by it.
func (p *PostgresStore) DrainDistributedAgent(ctx context.Context, agentID string) error {
	if p.db == nil {
		return p.notOpenError()
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Update agent status
	res, err := tx.ExecContext(ctx, `UPDATE distributed_agents SET status='draining' WHERE id=$1`, agentID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return fmt.Errorf("agent %q not found", agentID)
	}

	// Requeue active jobs leased to this agent
	_, err = tx.ExecContext(ctx, `
		UPDATE distributed_scan_jobs
		SET status='queued', lease_owner='', lease_until=NULL
		WHERE lease_owner=$1 AND status='leased'
	`, agentID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// AutoEnrollDistributedAgent securely auto-enrolls an agent if the pre-shared enrollment token matches.
func (p *PostgresStore) AutoEnrollDistributedAgent(ctx context.Context, agentID, publicKey, enrollmentToken, expectedToken string) (models.DistributedAgent, error) {
	if enrollmentToken == "" || expectedToken == "" || subtle.ConstantTimeCompare([]byte(enrollmentToken), []byte(expectedToken)) != 1 {
		return models.DistributedAgent{}, fmt.Errorf("unauthorized: invalid agent enrollment token")
	}
	if p.db == nil {
		return models.DistributedAgent{}, p.notOpenError()
	}
	return p.RegisterDistributedAgent(ctx, agentID, publicKey)
}


