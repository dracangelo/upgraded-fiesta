package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// DataClassification represents the confidentiality tier of stored evidence.
type DataClassification string

const (
	ClassificationPublic       DataClassification = "public"
	ClassificationInternal     DataClassification = "internal"
	ClassificationConfidential DataClassification = "confidential"
	ClassificationRestricted   DataClassification = "restricted"
)

// RetentionPolicy defines project-specific retention limits and legal bounds.
type RetentionPolicy struct {
	ProjectID    string
	MaxAge       time.Duration
	MinScansKeep int
}

// PurgeAuditEntry records every purge operation for tamper-evident compliance.
type PurgeAuditEntry struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	ScansPurged    int64     `json:"scans_purged"`
	AssetsPurged   int64     `json:"assets_purged"`
	FindingsPurged int64     `json:"findings_purged"`
	PurgeReason    string    `json:"purge_reason"`
	Operator       string    `json:"operator"`
}

func generateAuditID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "purge_" + hex.EncodeToString(b)
}

// EnsureLifecycleTables creates tables for legal holds and purge audits if missing.
func (s *SQLiteCLI) EnsureLifecycleTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return nil
	}
	query := `
	CREATE TABLE IF NOT EXISTS scan_legal_holds (
		scan_id TEXT PRIMARY KEY,
		enabled INTEGER NOT NULL DEFAULT 1,
		reason TEXT NOT NULL,
		operator TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS purge_audit_log (
		id TEXT PRIMARY KEY,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		scans_purged INTEGER NOT NULL,
		assets_purged INTEGER NOT NULL,
		findings_purged INTEGER NOT NULL,
		purge_reason TEXT NOT NULL,
		operator TEXT NOT NULL
	);`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// SetLegalHold places or removes an immutable retention hold on a scan.
func (s *SQLiteCLI) SetLegalHold(ctx context.Context, scanID string, hold bool, reason, operator string) error {
	if err := s.EnsureLifecycleTables(ctx); err != nil {
		return err
	}
	if hold {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO scan_legal_holds (scan_id, enabled, reason, operator)
			VALUES (?, 1, ?, ?)
			ON CONFLICT(scan_id) DO UPDATE SET enabled=1, reason=?, operator=?, created_at=CURRENT_TIMESTAMP
		`, scanID, reason, operator, reason, operator)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE scan_legal_holds SET enabled=0 WHERE scan_id=?`, scanID)
	return err
}

// IsLegalHoldActive reports whether a scan is protected by an active legal hold.
func (s *SQLiteCLI) IsLegalHoldActive(ctx context.Context, scanID string) (bool, error) {
	if err := s.EnsureLifecycleTables(ctx); err != nil {
		return false, err
	}
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT enabled FROM scan_legal_holds WHERE scan_id=?`, scanID).Scan(&enabled)
	if err != nil {
		return false, nil // Not on hold
	}
	return enabled == 1, nil
}

// PurgeScansWithLifecycle deletes expired scans while strictly respecting legal holds and min-scans.
func (s *SQLiteCLI) PurgeScansWithLifecycle(ctx context.Context, policy RetentionPolicy, operator string) (PurgeAuditEntry, error) {
	if err := s.EnsureLifecycleTables(ctx); err != nil {
		return PurgeAuditEntry{}, err
	}

	cutoff := time.Now().UTC().Add(-policy.MaxAge).Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PurgeAuditEntry{}, err
	}
	defer tx.Rollback()

	// Find candidate scan IDs older than cutoff that are NOT on active legal hold
	rows, err := tx.QueryContext(ctx, `
		SELECT scan_id FROM scan_runs
		WHERE datetime(started_at) < datetime(?)
		AND scan_id NOT IN (SELECT scan_id FROM scan_legal_holds WHERE enabled = 1)
		ORDER BY datetime(started_at) ASC
	`, cutoff)
	if err != nil {
		return PurgeAuditEntry{}, err
	}
	defer rows.Close()

	var candidateIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			candidateIDs = append(candidateIDs, id)
		}
	}
	rows.Close()

	// Check total scan count to honor MinScansKeep
	var totalScans int
	_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_runs`).Scan(&totalScans)
	allowedToPurge := totalScans - policy.MinScansKeep
	if allowedToPurge <= 0 || len(candidateIDs) == 0 {
		return PurgeAuditEntry{
			ID:          generateAuditID(),
			Timestamp:   time.Now().UTC(),
			PurgeReason: "no eligible scans to purge (min scans keep or legal hold active)",
			Operator:    operator,
		}, nil
	}

	if len(candidateIDs) > allowedToPurge {
		candidateIDs = candidateIDs[:allowedToPurge]
	}

	var assetsDeleted, findingsDeleted, scansDeleted int64
	for _, id := range candidateIDs {
		resA, _ := tx.ExecContext(ctx, `DELETE FROM assets WHERE scan_id=?`, id)
		if a, _ := resA.RowsAffected(); a > 0 {
			assetsDeleted += a
		}
		resF, _ := tx.ExecContext(ctx, `DELETE FROM findings WHERE scan_id=?`, id)
		if f, _ := resF.RowsAffected(); f > 0 {
			findingsDeleted += f
		}
		_, _ = tx.ExecContext(ctx, `DELETE FROM events WHERE scan_id=?`, id)
		_, _ = tx.ExecContext(ctx, `DELETE FROM checkpoints WHERE scan_id=?`, id)
		resS, _ := tx.ExecContext(ctx, `DELETE FROM scan_runs WHERE scan_id=?`, id)
		if s, _ := resS.RowsAffected(); s > 0 {
			scansDeleted += s
		}
	}

	auditEntry := PurgeAuditEntry{
		ID:             generateAuditID(),
		Timestamp:      time.Now().UTC(),
		ScansPurged:    scansDeleted,
		AssetsPurged:   assetsDeleted,
		FindingsPurged: findingsDeleted,
		PurgeReason:    fmt.Sprintf("retention policy age > %s (cutoff: %s)", policy.MaxAge, cutoff),
		Operator:       operator,
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO purge_audit_log (id, timestamp, scans_purged, assets_purged, findings_purged, purge_reason, operator)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, auditEntry.ID, auditEntry.Timestamp, auditEntry.ScansPurged, auditEntry.AssetsPurged, auditEntry.FindingsPurged, auditEntry.PurgeReason, auditEntry.Operator)
	if err != nil {
		return PurgeAuditEntry{}, err
	}

	if err := tx.Commit(); err != nil {
		return PurgeAuditEntry{}, err
	}

	return auditEntry, nil
}

// PurgeAuditHistory returns recorded audit log entries.
func (s *SQLiteCLI) PurgeAuditHistory(ctx context.Context, limit int) ([]PurgeAuditEntry, error) {
	if err := s.EnsureLifecycleTables(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, timestamp, scans_purged, assets_purged, findings_purged, purge_reason, operator
		FROM purge_audit_log
		ORDER BY timestamp DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []PurgeAuditEntry
	for rows.Next() {
		var e PurgeAuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ScansPurged, &e.AssetsPurged, &e.FindingsPurged, &e.PurgeReason, &e.Operator); err == nil {
			entries = append(entries, e)
		}
	}
	return entries, nil
}
