package store

import (
	"context"
	"database/sql"
	"fmt"
)

type Migration struct {
	Version      int
	Name         string
	SQLStatement string
}

var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial_schema",
		SQLStatement: `
CREATE TABLE IF NOT EXISTS assets (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL,
 parent TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(scan_id,type,value,parent));

CREATE TABLE IF NOT EXISTS findings (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL,
 asset TEXT NOT NULL, title TEXT NOT NULL, evidence TEXT NOT NULL, remediation TEXT NOT NULL,
 cwe TEXT NOT NULL DEFAULT '', cve TEXT NOT NULL DEFAULT '', cvss REAL NOT NULL DEFAULT 0.0,
 epss REAL NOT NULL DEFAULT 0.0, kev INTEGER NOT NULL DEFAULT 0, references_json TEXT NOT NULL DEFAULT '[]',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS nvd_cves (
 cve_id TEXT PRIMARY KEY, cwe_id TEXT NOT NULL DEFAULT '', cvss REAL NOT NULL DEFAULT 0.0,
 epss REAL NOT NULL DEFAULT 0.0, kev INTEGER NOT NULL DEFAULT 0, description TEXT NOT NULL DEFAULT '',
 cpe_configurations TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, type TEXT NOT NULL, target TEXT NOT NULL,
 data TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS scan_runs (
 scan_id TEXT PRIMARY KEY, status TEXT NOT NULL, started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 finished_at TEXT, error TEXT NOT NULL DEFAULT '');

CREATE TABLE IF NOT EXISTS checkpoints (
 scan_id TEXT NOT NULL, module TEXT NOT NULL, event_type TEXT NOT NULL, target TEXT NOT NULL,
 status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(scan_id,module,event_type,target));
`,
	},
	{
		Version: 2,
		Name:    "performance_indices",
		SQLStatement: `
CREATE INDEX IF NOT EXISTS idx_assets_scan_type ON assets(scan_id, type);
CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON findings(scan_id, cvss DESC, severity);
CREATE INDEX IF NOT EXISTS idx_events_scan_id ON events(scan_id);
`,
	},
	{
		Version: 3,
		Name:    "intelligence_quality_controls",
		SQLStatement: `
ALTER TABLE findings ADD COLUMN verification TEXT NOT NULL DEFAULT 'confirmed';
CREATE TABLE IF NOT EXISTS intelligence_feeds (
 source TEXT PRIMARY KEY, version TEXT NOT NULL, provenance TEXT NOT NULL, checksum TEXT NOT NULL,
 fetched_at TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS finding_suppressions (
 fingerprint TEXT PRIMARY KEY, reason TEXT NOT NULL, expires_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS evidence_records (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, finding_fingerprint TEXT NOT NULL,
 sha256 TEXT NOT NULL, classification TEXT NOT NULL, retained_until TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(scan_id, finding_fingerprint, sha256));
CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence_records(scan_id);
`,
	},
	{
		Version: 4,
		Name:    "operational_observability",
		SQLStatement: `
CREATE TABLE IF NOT EXISTS module_runs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, module TEXT NOT NULL,
 event_type TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
 duration_ms INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_module_runs_scan_status ON module_runs(scan_id, status);
`,
	},
	{
		Version: 5,
		Name:    "operator_saved_queries",
		SQLStatement: `
CREATE TABLE IF NOT EXISTS saved_queries (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, query TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
`,
	},
	{
		Version: 6,
		Name:    "port_observation_history",
		SQLStatement: `
CREATE TABLE IF NOT EXISTS port_observations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, host TEXT NOT NULL,
 port INTEGER NOT NULL, protocol TEXT NOT NULL, state TEXT NOT NULL,
 latency_ms INTEGER NOT NULL DEFAULT 0, evidence TEXT NOT NULL DEFAULT '',
 observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_port_observations_host_port ON port_observations(host, port, protocol, observed_at DESC);
`,
	},
	{
		Version: 7,
		Name:    "task39_performance_indices",
		SQLStatement: `
CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);
CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(parent);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_events_target ON events(target);
`,
	},
	{
		Version: 8,
		Name:    "bounded_operator_cache",
		SQLStatement: `
CREATE TABLE IF NOT EXISTS operator_cache (
 cache_key TEXT PRIMARY KEY,
 value TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_operator_cache_expiry ON operator_cache(expires_at);
`,
	},
	{
		Version: 9,
		Name:    "scheduler_runtime_snapshots",
		SQLStatement: `
CREATE TABLE IF NOT EXISTS scan_runtime_stats (
 scan_id TEXT PRIMARY KEY, worker_capacity INTEGER NOT NULL DEFAULT 0,
 active_workers INTEGER NOT NULL DEFAULT 0, running_modules INTEGER NOT NULL DEFAULT 0,
 queue_high INTEGER NOT NULL DEFAULT 0, queue_normal INTEGER NOT NULL DEFAULT 0,
 queue_low INTEGER NOT NULL DEFAULT 0, enqueued_events INTEGER NOT NULL DEFAULT 0,
 completed_events INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`,
	},
	{
		Version: 10,
		Name:    "durable_distributed_scan_jobs",
		SQLStatement: `
CREATE TABLE IF NOT EXISTS distributed_scan_jobs (
 id TEXT PRIMARY KEY,
 scan_id TEXT NOT NULL,
 authorization_ref TEXT NOT NULL,
 config_digest TEXT NOT NULL,
 status TEXT NOT NULL,
 lease_owner TEXT NOT NULL DEFAULT '',
 lease_until TEXT NOT NULL DEFAULT '',
 attempts INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_distributed_jobs_lease ON distributed_scan_jobs(status, lease_until, created_at);
`,
	},
	{
		Version: 11,
		Name:    "durable_distributed_agent_enrollment",
		SQLStatement: `
CREATE TABLE IF NOT EXISTS distributed_agents (
 id TEXT PRIMARY KEY,
 public_key_fingerprint TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL,
 last_heartbeat TEXT NOT NULL,
 registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_distributed_agents_status_heartbeat ON distributed_agents(status, last_heartbeat);
`,
	},
	{
		Version: 12,
		Name:    "api_audit_records",
		SQLStatement: `
CREATE TABLE IF NOT EXISTS api_audit_records (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 actor TEXT NOT NULL,
 role TEXT NOT NULL,
 action TEXT NOT NULL,
 scan_id TEXT NOT NULL DEFAULT '',
 status INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_api_audit_created ON api_audit_records(created_at DESC);
`,
	},
	{
		Version: 13,
		Name:    "authenticated_distributed_agent_transport",
		SQLStatement: `
ALTER TABLE distributed_agents ADD COLUMN public_key TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS distributed_agent_nonces (
 agent_id TEXT NOT NULL, nonce TEXT NOT NULL, used_at TEXT NOT NULL,
 PRIMARY KEY(agent_id, nonce),
 FOREIGN KEY(agent_id) REFERENCES distributed_agents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_distributed_agent_nonces_used ON distributed_agent_nonces(used_at);
`,
	},
	{
		Version: 14,
		Name:    "live_evidence_encryption_metadata",
		SQLStatement: `
CREATE TABLE IF NOT EXISTS datastore_encryption (
 id INTEGER PRIMARY KEY CHECK(id=1), verifier TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`,
	},
}

type MigrationManager struct {
	db *sql.DB
}

func NewMigrationManager(db *sql.DB) *MigrationManager {
	return &MigrationManager{db: db}
}

func (m *MigrationManager) RunMigrations(ctx context.Context) error {
	if m.db == nil {
		return fmt.Errorf("database connection is nil")
	}

	// 1. Ensure migrations tracking table exists
	const trackingTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);`
	if _, err := m.db.ExecContext(ctx, trackingTable); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	// 2. Get currently applied migration version
	var currentVersion int
	err := m.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&currentVersion)
	if err != nil {
		currentVersion = 0
	}

	// 3. Execute pending migrations sequentially inside a transaction
	for _, mig := range migrations {
		if mig.Version <= currentVersion {
			continue
		}

		tx, err := m.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin transaction for migration v%d: %w", mig.Version, err)
		}

		if _, err := tx.ExecContext(ctx, mig.SQLStatement); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("execute migration v%d (%s): %w", mig.Version, mig.Name, err)
		}

		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name) VALUES(?, ?)`, mig.Version, mig.Name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration v%d: %w", mig.Version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration v%d: %w", mig.Version, err)
		}
	}

	return nil
}

func (m *MigrationManager) CurrentVersion(ctx context.Context) (int, error) {
	if m.db == nil {
		return 0, nil
	}
	var version int
	err := m.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return version, err
}
