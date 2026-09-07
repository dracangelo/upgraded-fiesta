package store

import (
	"context"
	"time"

	"enumscan/internal/models"
)

func (s *SQLiteCLI) RecordAPIAudit(ctx context.Context, entry models.APIAuditEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_audit_records(actor,role,action,scan_id,status,created_at) VALUES(?,?,?,?,?,?)`, entry.Actor, entry.Role, entry.Action, entry.ScanID, entry.Status, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *SQLiteCLI) RecentAPIAudit(ctx context.Context, limit int) ([]models.APIAuditEntry, error) {
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor,role,action,scan_id,status,created_at FROM api_audit_records ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]models.APIAuditEntry, 0)
	for rows.Next() {
		var entry models.APIAuditEntry
		var created string
		if err := rows.Scan(&entry.ID, &entry.Actor, &entry.Role, &entry.Action, &entry.ScanID, &entry.Status, &created); err != nil {
			return nil, err
		}
		entry.CreatedAt = parseSQLiteTime(created)
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}
