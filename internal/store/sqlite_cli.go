package store

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"enumscan/internal/models"
)

type SQLiteCLI struct {
	path string
}

func OpenSQLiteCLI(path string) (*SQLiteCLI, error) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil, fmt.Errorf("sqlite3 command not found: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	return &SQLiteCLI{path: path}, nil
}

func (s SQLiteCLI) Migrate(ctx context.Context) error {
	sql := `
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  parent TEXT NOT NULL DEFAULT '',
  metadata TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(scan_id, type, value, parent)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  asset TEXT NOT NULL,
  title TEXT NOT NULL,
  evidence TEXT NOT NULL,
  remediation TEXT NOT NULL,
  cwe TEXT NOT NULL DEFAULT '',
  cve TEXT NOT NULL DEFAULT '',
  cvss REAL NOT NULL DEFAULT 0.0,
  epss REAL NOT NULL DEFAULT 0.0,
  kev INTEGER NOT NULL DEFAULT 0,
  references_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS nvd_cves (
  cve_id TEXT PRIMARY KEY,
  cwe_id TEXT NOT NULL DEFAULT '',
  cvss REAL NOT NULL DEFAULT 0.0,
  epss REAL NOT NULL DEFAULT 0.0,
  kev INTEGER NOT NULL DEFAULT 0,
  description TEXT NOT NULL DEFAULT '',
  cpe_configurations TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  type TEXT NOT NULL,
  target TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scan_runs (
  scan_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TEXT,
  error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS checkpoints (
  scan_id TEXT NOT NULL,
  module TEXT NOT NULL,
  event_type TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(scan_id, module, event_type, target)
);`
	if err := s.Exec(ctx, sql); err != nil {
		return err
	}
	// Best-effort column additions for legacy SQLite files
	_ = s.Exec(ctx, "ALTER TABLE findings ADD COLUMN cwe TEXT NOT NULL DEFAULT '';")
	_ = s.Exec(ctx, "ALTER TABLE findings ADD COLUMN cve TEXT NOT NULL DEFAULT '';")
	_ = s.Exec(ctx, "ALTER TABLE findings ADD COLUMN cvss REAL NOT NULL DEFAULT 0.0;")
	_ = s.Exec(ctx, "ALTER TABLE findings ADD COLUMN epss REAL NOT NULL DEFAULT 0.0;")
	_ = s.Exec(ctx, "ALTER TABLE findings ADD COLUMN kev INTEGER NOT NULL DEFAULT 0;")
	_ = s.Exec(ctx, "ALTER TABLE findings ADD COLUMN references_json TEXT NOT NULL DEFAULT '[]';")
	return nil
}

func (s SQLiteCLI) StartScan(ctx context.Context, scanID string) error {
	sql := fmt.Sprintf("INSERT INTO scan_runs(scan_id,status) VALUES(%s,'running') ON CONFLICT(scan_id) DO UPDATE SET status='running', error='', finished_at=NULL;",
		quote(scanID))
	return s.Exec(ctx, sql)
}

func (s SQLiteCLI) FinishScan(ctx context.Context, scanID, status, message string) error {
	sql := fmt.Sprintf("UPDATE scan_runs SET status=%s, error=%s, finished_at=CURRENT_TIMESTAMP WHERE scan_id=%s;",
		quote(status), quote(message), quote(scanID))
	return s.Exec(ctx, sql)
}

func (s SQLiteCLI) AddAsset(ctx context.Context, asset models.Asset) error {
	sql := fmt.Sprintf("INSERT OR IGNORE INTO assets(scan_id,type,value,parent,metadata) VALUES(%s,%s,%s,%s,%s);",
		quote(asset.ScanID), quote(asset.Type), quote(asset.Value), quote(asset.Parent), quote(asset.Metadata))
	return s.Exec(ctx, sql)
}

func (s SQLiteCLI) AddFinding(ctx context.Context, finding models.Finding) error {
	refsJSON := "[]"
	if len(finding.References) > 0 {
		var parts []string
		for _, ref := range finding.References {
			parts = append(parts, quote(ref))
		}
		refsJSON = "[" + strings.Join(parts, ",") + "]"
	}
	kevInt := 0
	if finding.KEV {
		kevInt = 1
	}
	sql := fmt.Sprintf("INSERT INTO findings(scan_id,severity,confidence,asset,title,evidence,remediation,cwe,cve,cvss,epss,kev,references_json) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%f,%f,%d,%s);",
		quote(finding.ScanID), quote(finding.Severity), quote(finding.Confidence), quote(finding.Asset), quote(finding.Title), quote(finding.Evidence), quote(finding.Remediation),
		quote(finding.CWE), quote(finding.CVE), finding.CVSS, finding.EPSS, kevInt, quote(refsJSON))
	return s.Exec(ctx, sql)
}

func (s SQLiteCLI) AddEvent(ctx context.Context, event models.Event) (int64, error) {
	sql := fmt.Sprintf("INSERT INTO events(scan_id,type,target,data) VALUES(%s,%s,%s,%s) RETURNING id;",
		quote(event.ScanID), quote(event.Type), quote(event.Target), quote(flatten(event.Data)))
	rows, err := s.query(ctx, sql)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		return 0, nil
	}
	id, err := strconv.ParseInt(rows[0][0], 10, 64)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s SQLiteCLI) CheckpointStatus(ctx context.Context, scanID, module, eventType, target string) (string, error) {
	rows, err := s.query(ctx, fmt.Sprintf("SELECT status FROM checkpoints WHERE scan_id=%s AND module=%s AND event_type=%s AND target=%s;",
		quote(scanID), quote(module), quote(eventType), quote(target)))
	if err != nil {
		return "", err
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		return "", nil
	}
	return rows[0][0], nil
}

func (s SQLiteCLI) UpsertCheckpoint(ctx context.Context, checkpoint models.Checkpoint) error {
	sql := fmt.Sprintf(`INSERT INTO checkpoints(scan_id,module,event_type,target,status,error,updated_at)
VALUES(%s,%s,%s,%s,%s,%s,CURRENT_TIMESTAMP)
ON CONFLICT(scan_id,module,event_type,target) DO UPDATE SET
  status=excluded.status,
  error=excluded.error,
  updated_at=CURRENT_TIMESTAMP;`,
		quote(checkpoint.ScanID),
		quote(checkpoint.Module),
		quote(checkpoint.EventType),
		quote(checkpoint.Target),
		quote(checkpoint.Status),
		quote(checkpoint.Error))
	return s.Exec(ctx, sql)
}

func (s SQLiteCLI) Assets(ctx context.Context, scanID string) ([]models.Asset, error) {
	rows, err := s.query(ctx, fmt.Sprintf("SELECT id,scan_id,type,value,parent,metadata,created_at FROM assets WHERE scan_id=%s ORDER BY type,value;", quote(scanID)))
	if err != nil {
		return nil, err
	}
	assets := make([]models.Asset, 0, len(rows))
	for _, row := range rows {
		if len(row) < 7 {
			continue
		}
		id, _ := strconv.ParseInt(row[0], 10, 64)
		created := parseSQLiteTime(row[6])
		assets = append(assets, models.Asset{ID: id, ScanID: row[1], Type: row[2], Value: row[3], Parent: row[4], Metadata: row[5], CreatedAt: created})
	}
	return assets, nil
}

func (s SQLiteCLI) Findings(ctx context.Context, scanID string) ([]models.Finding, error) {
	rows, err := s.query(ctx, fmt.Sprintf("SELECT id,scan_id,severity,confidence,asset,title,evidence,remediation,cwe,cve,cvss,epss,kev,references_json,created_at FROM findings WHERE scan_id=%s ORDER BY cvss DESC, severity, title;", quote(scanID)))
	if err != nil {
		return nil, err
	}
	findings := make([]models.Finding, 0, len(rows))
	for _, row := range rows {
		if len(row) < 9 {
			continue
		}
		id, _ := strconv.ParseInt(row[0], 10, 64)
		cwe := ""
		cve := ""
		cvss := 0.0
		epss := 0.0
		kev := false
		var refs []string
		createdAtIdx := 8

		if len(row) >= 15 {
			cwe = row[8]
			cve = row[9]
			cvss, _ = strconv.ParseFloat(row[10], 64)
			epss, _ = strconv.ParseFloat(row[11], 64)
			kevInt, _ := strconv.Atoi(row[12])
			kev = kevInt == 1
			refs = parseSimpleJSONList(row[13])
			createdAtIdx = 14
		}

		created := parseSQLiteTime(row[createdAtIdx])
		findings = append(findings, models.Finding{
			ID:          id,
			ScanID:      row[1],
			Severity:    row[2],
			Confidence:  row[3],
			Asset:       row[4],
			Title:       row[5],
			Evidence:    row[6],
			Remediation: row[7],
			CWE:         cwe,
			CVE:         cve,
			CVSS:        cvss,
			EPSS:        epss,
			KEV:         kev,
			References:  refs,
			CreatedAt:   created,
		})
	}
	return findings, nil
}

func (s *SQLiteCLI) Events(ctx context.Context, scanID string) ([]models.Event, error) {
	rows, err := s.query(ctx, fmt.Sprintf("SELECT id,scan_id,type,target,data FROM events WHERE scan_id=%s ORDER BY id;", quote(scanID)))
	if err != nil {
		return nil, err
	}
	events := make([]models.Event, 0, len(rows))
	for _, row := range rows {
		if len(row) < 5 {
			continue
		}
		id, _ := strconv.ParseInt(row[0], 10, 64)
		events = append(events, models.Event{ID: id, ScanID: row[1], Type: row[2], Target: row[3], Data: inflate(row[4])})
	}
	return events, nil
}

func (s *SQLiteCLI) Exec(ctx context.Context, sql string) error {
	cmd := exec.CommandContext(ctx, "sqlite3", s.path, sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sqlite3: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *SQLiteCLI) query(ctx context.Context, sql string) ([][]string, error) {
	cmd := exec.CommandContext(ctx, "sqlite3", "-csv", s.path, sql)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(out)) == "" {
		return nil, nil
	}
	return csv.NewReader(strings.NewReader(string(out))).ReadAll()
}

func quote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

func flatten(data map[string]string) string {
	if len(data) == 0 {
		return ""
	}
	parts := make([]string, 0, len(data))
	for k, v := range data {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ";")
}

func inflate(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ";") {
		key, value, ok := strings.Cut(part, "=")
		if ok {
			out[key] = value
		}
	}
	return out
}

func parseSimpleJSONList(raw string) []string {
	raw = strings.Trim(raw, "[]")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.Trim(strings.TrimSpace(p), "'\""))
	}
	return out
}

func parseSQLiteTime(value string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t
		}
	}
	return time.Time{}
}
