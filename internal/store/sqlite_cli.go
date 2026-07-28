package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"enumscan/internal/models"
)

// SQLiteCLI is retained as the public store name for compatibility. Its
// implementation is now a native, process-local SQLite connection rather
// than a sqlite3 command bridge.
type SQLiteCLI struct {
	path string
	db   *sql.DB
}

func OpenSQLiteCLI(path string) (*SQLiteCLI, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	// SQLite has one writer. A single pooled connection serializes writes while
	// WAL keeps reads responsive, eliminating CLI-process lock contention.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping SQLite database: %w", err)
	}
	return &SQLiteCLI{path: path, db: db}, nil
}

func (s *SQLiteCLI) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteCLI) Migrate(ctx context.Context) error {
	mm := NewMigrationManager(s.db)
	return mm.RunMigrations(ctx)
}

func (s *SQLiteCLI) StartScan(ctx context.Context, scanID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO scan_runs(scan_id,status) VALUES(?, 'running')
ON CONFLICT(scan_id) DO UPDATE SET status='running', error='', finished_at=NULL`, scanID)
	return err
}

func (s *SQLiteCLI) FinishScan(ctx context.Context, scanID, status, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE scan_runs SET status=?, error=?, finished_at=CURRENT_TIMESTAMP WHERE scan_id=?`, status, message, scanID)
	return err
}

func (s *SQLiteCLI) GetScanStatus(ctx context.Context, scanID string) (string, error) {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM scan_runs WHERE scan_id=?`, scanID).Scan(&status)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return status, err
}

func (s *SQLiteCLI) AddAsset(ctx context.Context, asset models.Asset) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO assets(scan_id,type,value,parent,metadata) VALUES(?,?,?,?,?)`, asset.ScanID, asset.Type, asset.Value, asset.Parent, asset.Metadata)
	return err
}

func (s *SQLiteCLI) AddFinding(ctx context.Context, finding models.Finding) error {
	references, err := json.Marshal(finding.References)
	if err != nil {
		return err
	}
	kev := 0
	if finding.KEV {
		kev = 1
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO findings(scan_id,severity,confidence,asset,title,evidence,remediation,cwe,cve,cvss,epss,kev,references_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, finding.ScanID, finding.Severity, finding.Confidence, finding.Asset, finding.Title, finding.Evidence, finding.Remediation, finding.CWE, finding.CVE, finding.CVSS, finding.EPSS, kev, string(references))
	return err
}

func (s *SQLiteCLI) AddEvent(ctx context.Context, event models.Event) (int64, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO events(scan_id,type,target,data) VALUES(?,?,?,?)`, event.ScanID, event.Type, event.Target, flatten(event.Data))
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *SQLiteCLI) CheckpointStatus(ctx context.Context, scanID, module, eventType, target string) (string, error) {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM checkpoints WHERE scan_id=? AND module=? AND event_type=? AND target=?`, scanID, module, eventType, target).Scan(&status)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return status, err
}

func (s *SQLiteCLI) UpsertCheckpoint(ctx context.Context, checkpoint models.Checkpoint) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO checkpoints(scan_id,module,event_type,target,status,error,updated_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)
ON CONFLICT(scan_id,module,event_type,target) DO UPDATE SET status=excluded.status,error=excluded.error,updated_at=CURRENT_TIMESTAMP`, checkpoint.ScanID, checkpoint.Module, checkpoint.EventType, checkpoint.Target, checkpoint.Status, checkpoint.Error)
	return err
}

func (s *SQLiteCLI) Assets(ctx context.Context, scanID string) ([]models.Asset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,scan_id,type,value,parent,metadata,created_at FROM assets WHERE scan_id=? ORDER BY type,value`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assets []models.Asset
	for rows.Next() {
		var a models.Asset
		var created string
		if err := rows.Scan(&a.ID, &a.ScanID, &a.Type, &a.Value, &a.Parent, &a.Metadata, &created); err != nil {
			return nil, err
		}
		a.CreatedAt = parseSQLiteTime(created)
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

func (s *SQLiteCLI) Findings(ctx context.Context, scanID string) ([]models.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,scan_id,severity,confidence,asset,title,evidence,remediation,cwe,cve,cvss,epss,kev,references_json,created_at FROM findings WHERE scan_id=? ORDER BY cvss DESC,severity,title`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		var kev int
		var refs, created string
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Severity, &f.Confidence, &f.Asset, &f.Title, &f.Evidence, &f.Remediation, &f.CWE, &f.CVE, &f.CVSS, &f.EPSS, &kev, &refs, &created); err != nil {
			return nil, err
		}
		f.KEV = kev != 0
		_ = json.Unmarshal([]byte(refs), &f.References)
		f.CreatedAt = parseSQLiteTime(created)
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (s *SQLiteCLI) Events(ctx context.Context, scanID string) ([]models.Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,scan_id,type,target,data FROM events WHERE scan_id=? ORDER BY id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []models.Event
	for rows.Next() {
		var e models.Event
		var data string
		if err := rows.Scan(&e.ID, &e.ScanID, &e.Type, &e.Target, &data); err != nil {
			return nil, err
		}
		e.Data = inflate(data)
		events = append(events, e)
	}
	return events, rows.Err()
}

// Exec remains for controlled internal migration/import statements.
func (s *SQLiteCLI) Exec(ctx context.Context, statement string) error {
	_, err := s.db.ExecContext(ctx, statement)
	return err
}

func flatten(data map[string]string) string {
	if len(data) == 0 {
		return ""
	}
	parts := make([]string, 0, len(data))
	for key, value := range data {
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, ";")
}
func inflate(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	data := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		if key, value, ok := strings.Cut(part, "="); ok {
			data[key] = value
		}
	}
	return data
}
func parseSQLiteTime(value string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}
