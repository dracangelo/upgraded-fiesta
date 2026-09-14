package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"enumscan/internal/models"
)

type PostgresStore struct {
	connString string
	db         *sql.DB
	maxOpen    int
	maxIdle    int
	encryptor  *DatastoreEncryptor
}

func NewPostgresStore(connString string) *PostgresStore {
	return &PostgresStore{connString: connString, maxOpen: 16, maxIdle: 4}
}

func NewEncryptedPostgresStore(connString string, key []byte) (*PostgresStore, error) {
	encryptor, err := NewDatastoreEncryptorKey(key)
	if err != nil {
		return nil, err
	}
	store := NewPostgresStore(connString)
	store.encryptor = encryptor
	return store, nil
}

func (p *PostgresStore) ConfigurePool(maxOpen, maxIdle int) error {
	if maxOpen < 1 || maxOpen > 128 || maxIdle < 0 || maxIdle > maxOpen {
		return fmt.Errorf("invalid PostgreSQL pool limits")
	}
	p.maxOpen, p.maxIdle = maxOpen, maxIdle
	return nil
}

func (p *PostgresStore) Open() error {
	if p.db != nil {
		return nil
	}
	db, err := sql.Open("pgx", p.connString)
	if err != nil {
		return fmt.Errorf("open postgres database: %w", err)
	}
	db.SetMaxOpenConns(p.maxOpen)
	db.SetMaxIdleConns(p.maxIdle)
	p.db = db
	return nil
}

// OpenContext establishes and verifies a PostgreSQL connection before normal
// scan, API, or operational use.
func (p *PostgresStore) OpenContext(ctx context.Context) error {
	if err := p.Open(); err != nil {
		return err
	}
	if err := p.db.PingContext(ctx); err != nil {
		_ = p.Close()
		return fmt.Errorf("ping PostgreSQL database: %w", err)
	}
	return nil
}

func (p *PostgresStore) Close() error {
	if p.db != nil {
		err := p.db.Close()
		p.db = nil
		if p.encryptor != nil {
			for index := range p.encryptor.key {
				p.encryptor.key[index] = 0
			}
		}
		return err
	}
	return nil
}

func (p *PostgresStore) Migrate(ctx context.Context) error {
	if p.db == nil {
		return p.notOpenError()
	}
	const schema = `
CREATE TABLE IF NOT EXISTS scan_runs (
    scan_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    error TEXT DEFAULT '',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    parent TEXT DEFAULT '',
    metadata TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, type, value, parent)
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    verification TEXT NOT NULL DEFAULT 'confirmed',
    asset TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    cwe TEXT DEFAULT '',
    cve TEXT DEFAULT '',
    cvss DOUBLE PRECISION DEFAULT 0.0,
    epss DOUBLE PRECISION DEFAULT 0.0,
    kev BOOLEAN DEFAULT FALSE,
    references_json TEXT DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL,
    type TEXT NOT NULL,
    target TEXT NOT NULL,
    data TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nvd_cves (
    cve_id TEXT PRIMARY KEY,
    cwe_id TEXT NOT NULL DEFAULT '',
    cvss DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    epss DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    kev BOOLEAN NOT NULL DEFAULT FALSE,
    description TEXT NOT NULL DEFAULT '',
    cpe_configurations TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS intelligence_feeds (
    source TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    provenance TEXT NOT NULL,
    checksum TEXT NOT NULL,
    fetched_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS finding_suppressions (
    fingerprint TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_records (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL,
    finding_fingerprint TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    classification TEXT NOT NULL,
    retained_until TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, finding_fingerprint, sha256)
);
CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence_records(scan_id);

CREATE TABLE IF NOT EXISTS checkpoints (
    scan_id TEXT NOT NULL,
    module TEXT NOT NULL,
    event_type TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT DEFAULT '',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (scan_id, module, event_type, target)
);

CREATE TABLE IF NOT EXISTS module_runs (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL,
    module TEXT NOT NULL,
    event_type TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_module_runs_scan_status ON module_runs(scan_id, status);

CREATE TABLE IF NOT EXISTS port_observations (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    latency_ms BIGINT NOT NULL DEFAULT 0,
    evidence TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_port_observations_host_port ON port_observations(host, port, protocol, observed_at DESC);

CREATE TABLE IF NOT EXISTS scan_runtime_stats (
    scan_id TEXT PRIMARY KEY,
    worker_capacity INTEGER NOT NULL DEFAULT 0,
    active_workers INTEGER NOT NULL DEFAULT 0,
    running_modules INTEGER NOT NULL DEFAULT 0,
    queue_high INTEGER NOT NULL DEFAULT 0,
    queue_normal INTEGER NOT NULL DEFAULT 0,
    queue_low INTEGER NOT NULL DEFAULT 0,
    enqueued_events BIGINT NOT NULL DEFAULT 0,
    completed_events BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS operator_cache (
    cache_key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_operator_cache_expiry ON operator_cache(expires_at);

CREATE TABLE IF NOT EXISTS datastore_encryption (
    id INTEGER PRIMARY KEY CHECK(id=1),
    verifier TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS saved_queries (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    query TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_audit_records (
    id SERIAL PRIMARY KEY,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    scan_id TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_api_audit_created ON api_audit_records(created_at DESC);

CREATE TABLE IF NOT EXISTS distributed_agents (
    id TEXT PRIMARY KEY,
    public_key_fingerprint TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    last_heartbeat TIMESTAMP NOT NULL,
    registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_distributed_agents_status_heartbeat ON distributed_agents(status, last_heartbeat);

CREATE TABLE IF NOT EXISTS distributed_agent_nonces (
    agent_id TEXT NOT NULL REFERENCES distributed_agents(id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    used_at TIMESTAMP NOT NULL,
    PRIMARY KEY(agent_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_distributed_agent_nonces_used ON distributed_agent_nonces(used_at);

CREATE TABLE IF NOT EXISTS distributed_scan_jobs (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    authorization_ref TEXT NOT NULL,
    config_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_until TIMESTAMP,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_distributed_jobs_lease ON distributed_scan_jobs(status, lease_until, created_at);

CREATE TABLE IF NOT EXISTS coordinator_leases (
    cluster_id TEXT PRIMARY KEY,
    leader_id TEXT NOT NULL DEFAULT '',
    epoch BIGINT NOT NULL DEFAULT 0,
    lease_until TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- PostgreSQL installations created by earlier enumscan releases did not
-- retain finding verification. Keep this idempotent migration adjacent to the
-- bootstrap schema until the full versioned datastore migration lands.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verification TEXT NOT NULL DEFAULT 'confirmed';
`
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS postgres_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)`); err != nil {
		return fmt.Errorf("create PostgreSQL migration ledger: %w", err)
	}
	// Serialize schema changes across coordinator processes. The fixed advisory
	// key is scoped to enumscan's PostgreSQL migration ledger.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(730424915)`); err != nil {
		return fmt.Errorf("lock PostgreSQL migrations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply PostgreSQL schema: %w", err)
	}
	for version, name := range postgresMigrationNames {
		if _, err := tx.ExecContext(ctx, `INSERT INTO postgres_schema_migrations(version,name) VALUES($1,$2) ON CONFLICT(version) DO NOTHING`, version+1, name); err != nil {
			return fmt.Errorf("record PostgreSQL migration %d: %w", version+1, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if p.encryptor != nil {
		return p.initializePostgresEvidenceEncryption(ctx)
	}
	return nil
}

// postgresMigrationNames mirrors the SQLite migration history. PostgreSQL's
// idempotent DDL is applied under the transaction lock above, then each
// compatible historical version is durably recorded. This lets an existing
// PostgreSQL deployment converge safely and gives operators a version ledger
// for audit and upgrade verification.
var postgresMigrationNames = []string{
	"initial_schema",
	"performance_indices",
	"intelligence_quality_controls",
	"operational_observability",
	"operator_saved_queries",
	"port_observation_history",
	"task39_performance_indices",
	"bounded_operator_cache",
	"scheduler_runtime_snapshots",
	"durable_distributed_scan_jobs",
	"durable_distributed_agent_enrollment",
	"api_audit_records",
	"authenticated_distributed_agent_transport",
	"live_evidence_encryption_metadata",
	"fenced_coordinator_leases",
}

func (p *PostgresStore) StartScan(ctx context.Context, scanID string) error {
	if p.db == nil {
		return p.notOpenError()
	}
	query := `INSERT INTO scan_runs(scan_id, status) VALUES($1, 'running')
ON CONFLICT (scan_id) DO UPDATE SET status='running', error='', finished_at=NULL`
	_, err := p.db.ExecContext(ctx, query, scanID)
	return err
}

func (p *PostgresStore) FinishScan(ctx context.Context, scanID, status, errMessage string) error {
	if p.db == nil {
		return p.notOpenError()
	}
	sealed, err := p.seal("scan_runs.error", errMessage)
	if err != nil {
		return err
	}
	query := `UPDATE scan_runs SET status=$1, error=$2, finished_at=CURRENT_TIMESTAMP WHERE scan_id=$3`
	_, err = p.db.ExecContext(ctx, query, status, sealed, scanID)
	return err
}

func (p *PostgresStore) UpdateScanStatus(ctx context.Context, scanID, status string) error {
	if p.db == nil {
		return p.notOpenError()
	}
	_, err := p.db.ExecContext(ctx, `INSERT INTO scan_runs(scan_id,status) VALUES($1,$2)
ON CONFLICT(scan_id) DO UPDATE SET status=EXCLUDED.status`, scanID, status)
	return err
}

func (p *PostgresStore) GetScanStatus(ctx context.Context, scanID string) (string, error) {
	if p.db == nil {
		return "", p.notOpenError()
	}
	var status string
	err := p.db.QueryRowContext(ctx, `SELECT status FROM scan_runs WHERE scan_id=$1`, scanID).Scan(&status)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return status, err
}

// ScanRuns returns bounded, evidence-counted scan history for operator views.
func (p *PostgresStore) ScanRuns(ctx context.Context, limit int) ([]models.ScanRun, error) {
	if p.db == nil {
		return nil, p.notOpenError()
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := p.db.QueryContext(ctx, `SELECT sr.scan_id,sr.status,sr.error,sr.started_at,sr.finished_at,
  (SELECT COUNT(*) FROM assets a WHERE a.scan_id=sr.scan_id),
  (SELECT COUNT(*) FROM findings f WHERE f.scan_id=sr.scan_id),
  (SELECT COUNT(*) FROM events e WHERE e.scan_id=sr.scan_id)
  FROM scan_runs sr ORDER BY sr.started_at DESC,sr.scan_id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := make([]models.ScanRun, 0)
	for rows.Next() {
		var run models.ScanRun
		var finished sql.NullTime
		if err := rows.Scan(&run.ScanID, &run.Status, &run.Error, &run.StartedAt, &finished, &run.AssetCount, &run.FindingCount, &run.EventCount); err != nil {
			return nil, err
		}
		if finished.Valid {
			finishedAt := finished.Time
			run.FinishedAt = &finishedAt
		}
		if run.Error, err = p.open("scan_runs.error", run.Error); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (p *PostgresStore) AddAsset(ctx context.Context, asset models.Asset) error {
	if p.db == nil {
		return p.notOpenError()
	}
	protected, err := p.protectAsset(asset)
	if err != nil {
		return err
	}
	query := `INSERT INTO assets(scan_id, type, value, parent, metadata) VALUES($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`
	_, err = p.db.ExecContext(ctx, query, protected.ScanID, protected.Type, protected.Value, protected.Parent, protected.Metadata)
	return err
}

func (p *PostgresStore) Assets(ctx context.Context, scanID string) ([]models.Asset, error) {
	if p.db == nil {
		return nil, p.notOpenError()
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id, scan_id, type, value, parent, metadata, created_at FROM assets WHERE scan_id=$1 ORDER BY type, value`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []models.Asset
	for rows.Next() {
		var a models.Asset
		var created time.Time
		if err := rows.Scan(&a.ID, &a.ScanID, &a.Type, &a.Value, &a.Parent, &a.Metadata, &created); err != nil {
			return nil, err
		}
		a.CreatedAt = created
		if err := p.revealAsset(&a); err != nil {
			return nil, err
		}
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

func (p *PostgresStore) AddFinding(ctx context.Context, finding models.Finding) error {
	if p.db == nil {
		return p.notOpenError()
	}
	protected, err := p.protectFinding(finding)
	if err != nil {
		return err
	}
	refs, err := json.Marshal(protected.References)
	if err != nil {
		return err
	}
	verification := protected.Verification
	if verification == "" {
		verification = "confirmed"
	}
	query := `INSERT INTO findings(scan_id, severity, confidence, verification, asset, title, evidence, remediation, cwe, cve, cvss, epss, kev, references_json) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	_, err = p.db.ExecContext(ctx, query, protected.ScanID, protected.Severity, protected.Confidence, verification, protected.Asset, protected.Title, protected.Evidence, protected.Remediation, protected.CWE, protected.CVE, protected.CVSS, protected.EPSS, protected.KEV, string(refs))
	return err
}

func (p *PostgresStore) Findings(ctx context.Context, scanID string) ([]models.Finding, error) {
	if p.db == nil {
		return nil, p.notOpenError()
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id, scan_id, severity, confidence, verification, asset, title, evidence, remediation, cwe, cve, cvss, epss, kev, references_json, created_at FROM findings WHERE scan_id=$1 ORDER BY cvss DESC, severity, title`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		var refs string
		var created time.Time
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Severity, &f.Confidence, &f.Verification, &f.Asset, &f.Title, &f.Evidence, &f.Remediation, &f.CWE, &f.CVE, &f.CVSS, &f.EPSS, &f.KEV, &refs, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(refs), &f.References)
		f.CreatedAt = created
		if err := p.revealFinding(&f); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (p *PostgresStore) AddEvent(ctx context.Context, event models.Event) (int64, error) {
	if p.db == nil {
		return 0, p.notOpenError()
	}
	protected, data, err := p.protectEvent(event)
	if err != nil {
		return 0, err
	}
	query := `INSERT INTO events(scan_id, type, target, data) VALUES($1, $2, $3, $4) RETURNING id`
	var id int64
	err = p.db.QueryRowContext(ctx, query, protected.ScanID, protected.Type, protected.Target, data).Scan(&id)
	return id, err
}

func (p *PostgresStore) Events(ctx context.Context, scanID string) ([]models.Event, error) {
	if p.db == nil {
		return nil, p.notOpenError()
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id, scan_id, type, target, data FROM events WHERE scan_id=$1 ORDER BY id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var e models.Event
		var rawData string
		if err := rows.Scan(&e.ID, &e.ScanID, &e.Type, &e.Target, &rawData); err != nil {
			return nil, err
		}
		if err := p.revealEvent(&e, rawData); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func (p *PostgresStore) UpsertCheckpoint(ctx context.Context, checkpoint models.Checkpoint) error {
	if p.db == nil {
		return p.notOpenError()
	}
	var err error
	if checkpoint.Target, err = p.seal("checkpoints.target", checkpoint.Target); err != nil {
		return err
	}
	if checkpoint.Error, err = p.seal("checkpoints.error", checkpoint.Error); err != nil {
		return err
	}
	query := `INSERT INTO checkpoints(scan_id, module, event_type, target, status, error, updated_at) VALUES($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
ON CONFLICT (scan_id, module, event_type, target) DO UPDATE SET status=EXCLUDED.status, error=EXCLUDED.error, updated_at=CURRENT_TIMESTAMP`
	_, err = p.db.ExecContext(ctx, query, checkpoint.ScanID, checkpoint.Module, checkpoint.EventType, checkpoint.Target, checkpoint.Status, checkpoint.Error)
	return err
}

func (p *PostgresStore) CheckpointStatus(ctx context.Context, scanID, module, eventType, target string) (string, error) {
	if p.db == nil {
		return "", p.notOpenError()
	}
	sealedTarget, err := p.seal("checkpoints.target", target)
	if err != nil {
		return "", err
	}
	var status string
	err = p.db.QueryRowContext(ctx, `SELECT status FROM checkpoints WHERE scan_id=$1 AND module=$2 AND event_type=$3 AND target=$4`, scanID, module, eventType, sealedTarget).Scan(&status)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return status, err
}

func (p *PostgresStore) RecordModuleRun(ctx context.Context, run models.ModuleRun) error {
	if p.db == nil {
		return p.notOpenError()
	}
	var err error
	if run.Target, err = p.seal("module_runs.target", run.Target); err != nil {
		return err
	}
	if run.Error, err = p.seal("module_runs.error", run.Error); err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO module_runs(scan_id,module,event_type,target,status,duration_ms,error) VALUES($1,$2,$3,$4,$5,$6,$7)`, run.ScanID, run.Module, run.EventType, run.Target, run.Status, run.Duration.Milliseconds(), run.Error)
	return err
}

func (p *PostgresStore) ScanHealth(ctx context.Context, scanID string) (models.ScanHealth, error) {
	health := models.ScanHealth{ScanID: scanID}
	if p.db == nil {
		return health, p.notOpenError()
	}
	if err := p.db.QueryRowContext(ctx, `SELECT status FROM scan_runs WHERE scan_id=$1`, scanID).Scan(&health.Status); err == sql.ErrNoRows {
		return health, nil
	} else if err != nil {
		return health, err
	}
	if err := p.db.QueryRowContext(ctx, `SELECT
 COALESCE(SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END), 0),
 COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END), 0)
 FROM module_runs WHERE scan_id=$1`, scanID).Scan(&health.CompletedRuns, &health.FailedRuns); err != nil {
		return health, err
	}
	health.Healthy = health.Status == "completed" && health.FailedRuns == 0
	return health, nil
}

func (p *PostgresStore) AddPortObservation(ctx context.Context, observation models.PortObservation) error {
	if p.db == nil {
		return p.notOpenError()
	}
	var err error
	if observation.Host, err = p.seal("port_observations.host", observation.Host); err != nil {
		return err
	}
	if observation.Evidence, err = p.seal("port_observations.evidence", observation.Evidence); err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO port_observations(scan_id,host,port,protocol,state,latency_ms,evidence,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, observation.ScanID, observation.Host, observation.Port, observation.Protocol, observation.State, observation.LatencyMS, observation.Evidence, observation.ObservedAt)
	return err
}

func (p *PostgresStore) UpsertRuntimeStats(ctx context.Context, stats models.ScanRuntimeStats) error {
	if p.db == nil {
		return p.notOpenError()
	}
	_, err := p.db.ExecContext(ctx, `INSERT INTO scan_runtime_stats(scan_id,worker_capacity,active_workers,running_modules,queue_high,queue_normal,queue_low,enqueued_events,completed_events,updated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP)
ON CONFLICT(scan_id) DO UPDATE SET worker_capacity=EXCLUDED.worker_capacity,active_workers=EXCLUDED.active_workers,running_modules=EXCLUDED.running_modules,queue_high=EXCLUDED.queue_high,queue_normal=EXCLUDED.queue_normal,queue_low=EXCLUDED.queue_low,enqueued_events=EXCLUDED.enqueued_events,completed_events=EXCLUDED.completed_events,updated_at=CURRENT_TIMESTAMP`, stats.ScanID, stats.WorkerCapacity, stats.ActiveWorkers, stats.RunningModules, stats.QueueHigh, stats.QueueNormal, stats.QueueLow, stats.EnqueuedEvents, stats.CompletedEvents)
	return err
}

func (p *PostgresStore) ScanRuntimeStats(ctx context.Context, scanID string) (models.ScanRuntimeStats, error) {
	stats := models.ScanRuntimeStats{ScanID: scanID}
	if p.db == nil {
		return stats, p.notOpenError()
	}
	err := p.db.QueryRowContext(ctx, `SELECT worker_capacity,active_workers,running_modules,queue_high,queue_normal,queue_low,enqueued_events,completed_events,updated_at FROM scan_runtime_stats WHERE scan_id=$1`, scanID).Scan(&stats.WorkerCapacity, &stats.ActiveWorkers, &stats.RunningModules, &stats.QueueHigh, &stats.QueueNormal, &stats.QueueLow, &stats.EnqueuedEvents, &stats.CompletedEvents, &stats.UpdatedAt)
	return stats, err
}

func (p *PostgresStore) Ping(ctx context.Context) error {
	if p.db == nil {
		return p.notOpenError()
	}
	return p.db.PingContext(ctx)
}

func pgQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (p *PostgresStore) notOpenError() error {
	return fmt.Errorf("postgres store is not open; configure a PostgreSQL driver and call Open before use")
}
