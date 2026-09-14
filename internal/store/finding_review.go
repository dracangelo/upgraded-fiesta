package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"enumscan/internal/models"
)

func generateTransitionID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "audit_" + hex.EncodeToString(b)
}

// EnsureFindingReviewTables adds review columns and the state transition audit table.
func (s *SQLiteCLI) EnsureFindingReviewTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return nil
	}

	// 1. Add review columns to findings if they don't exist yet
	queries := []string{
		"ALTER TABLE findings ADD COLUMN review_status TEXT NOT NULL DEFAULT 'open'",
		"ALTER TABLE findings ADD COLUMN assignee TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE findings ADD COLUMN review_notes TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE findings ADD COLUMN verified_at DATETIME",
		"ALTER TABLE findings ADD COLUMN verifier TEXT NOT NULL DEFAULT ''",
	}
	for _, q := range queries {
		_, _ = s.db.ExecContext(ctx, q) // ignore error if column already exists
	}

	// 2. Audit transition table
	createAudit := `
	CREATE TABLE IF NOT EXISTS finding_state_audit (
		id TEXT PRIMARY KEY,
		finding_id INTEGER NOT NULL,
		from_state TEXT NOT NULL,
		to_state TEXT NOT NULL,
		actor TEXT NOT NULL,
		justification TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, err := s.db.ExecContext(ctx, createAudit)
	return err
}

// UpdateFindingReviewState transitions a finding's status after checking valid state flow.
func (s *SQLiteCLI) UpdateFindingReviewState(ctx context.Context, findingID int64, newState models.FindingState, actor, justification string) error {
	if err := s.EnsureFindingReviewTables(ctx); err != nil {
		return err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return fmt.Errorf("actor identity required for finding state change")
	}
	justification = strings.TrimSpace(justification)
	if justification == "" {
		return fmt.Errorf("justification required for finding state change")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Get current status
	var currentStatus string
	row := tx.QueryRowContext(ctx, `SELECT review_status FROM findings WHERE id = ?`, findingID)
	if err := row.Scan(&currentStatus); err != nil {
		return fmt.Errorf("finding %d not found: %w", findingID, err)
	}

	// Validate transition
	if err := models.ValidateFindingStateTransition(models.FindingState(currentStatus), newState); err != nil {
		return err
	}

	var verifiedAt any = nil
	verifier := ""
	if newState == models.FindingStateVerified {
		verifiedAt = time.Now().UTC()
		verifier = actor
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE findings
		SET review_status = ?, verified_at = ?, verifier = ?
		WHERE id = ?
	`, string(newState), verifiedAt, verifier, findingID)
	if err != nil {
		return err
	}

	// Insert audit record
	auditID := generateTransitionID()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO finding_state_audit (id, finding_id, from_state, to_state, actor, justification, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, auditID, findingID, currentStatus, string(newState), actor, justification)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// AssignFinding assigns a finding to an operator or analyst.
func (s *SQLiteCLI) AssignFinding(ctx context.Context, findingID int64, assignee, actor string) error {
	if err := s.EnsureFindingReviewTables(ctx); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE findings
		SET assignee = ?
		WHERE id = ?
	`, assignee, findingID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return fmt.Errorf("finding %d not found", findingID)
	}

	// Record audit
	auditID := generateTransitionID()
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO finding_state_audit (id, finding_id, from_state, to_state, actor, justification, timestamp)
		VALUES (?, ?, 'assigned', 'assigned', ?, ?, CURRENT_TIMESTAMP)
	`, auditID, findingID, actor, "assigned to "+assignee)

	return nil
}

// FindingReviewState returns the review details of a finding.
func (s *SQLiteCLI) FindingReviewState(ctx context.Context, findingID int64) (state string, assignee string, verifier string, err error) {
	if err := s.EnsureFindingReviewTables(ctx); err != nil {
		return "", "", "", err
	}
	row := s.db.QueryRowContext(ctx, `SELECT review_status, assignee, verifier FROM findings WHERE id = ?`, findingID)
	err = row.Scan(&state, &assignee, &verifier)
	return state, assignee, verifier, err
}

// FindingAuditHistory returns the full state transition audit trail for a finding.
func (s *SQLiteCLI) FindingAuditHistory(ctx context.Context, findingID int64) ([]models.FindingAuditTransition, error) {
	if err := s.EnsureFindingReviewTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, finding_id, from_state, to_state, actor, justification, timestamp
		FROM finding_state_audit
		WHERE finding_id = ?
		ORDER BY timestamp ASC
	`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []models.FindingAuditTransition
	for rows.Next() {
		var t models.FindingAuditTransition
		var from, to string
		if err := rows.Scan(&t.ID, &t.FindingID, &from, &to, &t.Actor, &t.Justification, &t.Timestamp); err == nil {
			t.FromState = models.FindingState(from)
			t.ToState = models.FindingState(to)
			history = append(history, t)
		}
	}
	return history, rows.Err()
}
