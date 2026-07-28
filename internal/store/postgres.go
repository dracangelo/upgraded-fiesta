package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"enumscan/internal/models"
)

type PostgresStore struct {
	connString string
	db         *sql.DB
}

func NewPostgresStore(connString string) *PostgresStore {
	return &PostgresStore{connString: connString}
}

func (p *PostgresStore) Open() error {
	if p.db != nil {
		return nil
	}
	db, err := sql.Open("postgres", p.connString)
	if err != nil {
		return fmt.Errorf("open postgres database: %w", err)
	}
	p.db = db
	return nil
}

func (p *PostgresStore) Close() error {
	if p.db != nil {
		err := p.db.Close()
		p.db = nil
		return err
	}
	return nil
}

func (p *PostgresStore) Migrate(ctx context.Context) error {
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
`
	if p.db == nil {
		return nil
	}
	_, err := p.db.ExecContext(ctx, schema)
	return err
}

func (p *PostgresStore) StartScan(ctx context.Context, scanID string) error {
	if p.db == nil {
		return nil
	}
	query := `INSERT INTO scan_runs(scan_id, status) VALUES($1, 'running')
ON CONFLICT (scan_id) DO UPDATE SET status='running', error='', finished_at=NULL`
	_, err := p.db.ExecContext(ctx, query, scanID)
	return err
}

func (p *PostgresStore) FinishScan(ctx context.Context, scanID, status, errMessage string) error {
	if p.db == nil {
		return nil
	}
	query := `UPDATE scan_runs SET status=$1, error=$2, finished_at=CURRENT_TIMESTAMP WHERE scan_id=$3`
	_, err := p.db.ExecContext(ctx, query, status, errMessage, scanID)
	return err
}

func (p *PostgresStore) AddAsset(ctx context.Context, asset models.Asset) error {
	if p.db == nil {
		return nil
	}
	query := `INSERT INTO assets(scan_id, type, value, parent, metadata) VALUES($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`
	_, err := p.db.ExecContext(ctx, query, asset.ScanID, asset.Type, asset.Value, asset.Parent, asset.Metadata)
	return err
}

func (p *PostgresStore) Assets(ctx context.Context, scanID string) ([]models.Asset, error) {
	if p.db == nil {
		return []models.Asset{}, nil
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
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

func (p *PostgresStore) AddFinding(ctx context.Context, finding models.Finding) error {
	if p.db == nil {
		return nil
	}
	refs, err := json.Marshal(finding.References)
	if err != nil {
		return err
	}
	query := `INSERT INTO findings(scan_id, severity, confidence, asset, title, evidence, remediation, cwe, cve, cvss, epss, kev, references_json) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	_, err = p.db.ExecContext(ctx, query, finding.ScanID, finding.Severity, finding.Confidence, finding.Asset, finding.Title, finding.Evidence, finding.Remediation, finding.CWE, finding.CVE, finding.CVSS, finding.EPSS, finding.KEV, string(refs))
	return err
}

func (p *PostgresStore) Findings(ctx context.Context, scanID string) ([]models.Finding, error) {
	if p.db == nil {
		return []models.Finding{}, nil
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id, scan_id, severity, confidence, asset, title, evidence, remediation, cwe, cve, cvss, epss, kev, references_json, created_at FROM findings WHERE scan_id=$1 ORDER BY cvss DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		var refs string
		var created time.Time
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Severity, &f.Confidence, &f.Asset, &f.Title, &f.Evidence, &f.Remediation, &f.CWE, &f.CVE, &f.CVSS, &f.EPSS, &f.KEV, &refs, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(refs), &f.References)
		f.CreatedAt = created
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (p *PostgresStore) AddEvent(ctx context.Context, event models.Event) error {
	if p.db == nil {
		return nil
	}
	query := `INSERT INTO events(scan_id, type, target, data) VALUES($1, $2, $3, $4)`
	_, err := p.db.ExecContext(ctx, query, event.ScanID, event.Type, event.Target, flatten(event.Data))
	return err
}

func (p *PostgresStore) Events(ctx context.Context, scanID string) ([]models.Event, error) {
	if p.db == nil {
		return []models.Event{}, nil
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
		e.Data = inflate(rawData)
		events = append(events, e)
	}
	return events, rows.Err()
}

func (p *PostgresStore) UpsertCheckpoint(ctx context.Context, checkpoint models.Checkpoint) error {
	if p.db == nil {
		return nil
	}
	query := `INSERT INTO checkpoints(scan_id, module, event_type, target, status, error, updated_at) VALUES($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
ON CONFLICT (scan_id, module, event_type, target) DO UPDATE SET status=EXCLUDED.status, error=EXCLUDED.error, updated_at=CURRENT_TIMESTAMP`
	_, err := p.db.ExecContext(ctx, query, checkpoint.ScanID, checkpoint.Module, checkpoint.EventType, checkpoint.Target, checkpoint.Status, checkpoint.Error)
	return err
}

func pgQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
