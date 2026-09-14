package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"enumscan/internal/models"
)

var (
	ErrEngagementNotFound = errors.New("engagement not found")
)

// EnsureEngagementTables creates the durable engagement tables if they do not exist.
func (s *SQLiteCLI) EnsureEngagementTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return nil
	}
	query := `
	CREATE TABLE IF NOT EXISTS engagements (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		org_id TEXT NOT NULL,
		owner_id TEXT NOT NULL,
		allowed_targets TEXT NOT NULL,
		authorization_ref TEXT NOT NULL,
		status TEXT NOT NULL,
		tags TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS engagement_scans (
		engagement_id TEXT NOT NULL,
		scan_id TEXT NOT NULL,
		added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		phase TEXT NOT NULL,
		PRIMARY KEY (engagement_id, scan_id)
	);`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// CreateEngagement creates a new durable engagement project.
func (s *SQLiteCLI) CreateEngagement(ctx context.Context, eng models.Engagement) error {
	if err := s.EnsureEngagementTables(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(eng.ID) == "" {
		return fmt.Errorf("engagement id is required")
	}
	if strings.TrimSpace(eng.Name) == "" {
		return fmt.Errorf("engagement name is required")
	}
	if strings.TrimSpace(eng.AuthorizationRef) == "" {
		return fmt.Errorf("written authorization reference is required")
	}
	if eng.Status == "" {
		eng.Status = "planning"
	}

	targetsJSON, _ := json.Marshal(eng.AllowedTargets)
	tagsJSON, _ := json.Marshal(eng.Tags)
	now := time.Now().UTC()
	if eng.CreatedAt.IsZero() {
		eng.CreatedAt = now
	}
	if eng.UpdatedAt.IsZero() {
		eng.UpdatedAt = now
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO engagements (id, name, org_id, owner_id, allowed_targets, authorization_ref, status, tags, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, eng.ID, eng.Name, eng.OrgID, eng.OwnerID, string(targetsJSON), eng.AuthorizationRef, eng.Status, string(tagsJSON), eng.CreatedAt, eng.UpdatedAt)
	return err
}

// GetEngagement retrieves an engagement by ID.
func (s *SQLiteCLI) GetEngagement(ctx context.Context, id string) (models.Engagement, error) {
	if err := s.EnsureEngagementTables(ctx); err != nil {
		return models.Engagement{}, err
	}
	var eng models.Engagement
	var targetsJSON, tagsJSON string

	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, org_id, owner_id, allowed_targets, authorization_ref, status, tags, created_at, updated_at
		FROM engagements WHERE id = ?
	`, id)
	err := row.Scan(&eng.ID, &eng.Name, &eng.OrgID, &eng.OwnerID, &targetsJSON, &eng.AuthorizationRef, &eng.Status, &tagsJSON, &eng.CreatedAt, &eng.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return models.Engagement{}, ErrEngagementNotFound
	}
	if err != nil {
		return models.Engagement{}, err
	}

	_ = json.Unmarshal([]byte(targetsJSON), &eng.AllowedTargets)
	_ = json.Unmarshal([]byte(tagsJSON), &eng.Tags)
	return eng, nil
}

// ListEngagements returns all engagements optionally filtered by organization ID.
func (s *SQLiteCLI) ListEngagements(ctx context.Context, orgID string) ([]models.Engagement, error) {
	if err := s.EnsureEngagementTables(ctx); err != nil {
		return nil, err
	}
	var rows *sql.Rows
	var err error

	if orgID != "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, name, org_id, owner_id, allowed_targets, authorization_ref, status, tags, created_at, updated_at
			FROM engagements WHERE org_id = ? ORDER BY created_at DESC
		`, orgID)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, name, org_id, owner_id, allowed_targets, authorization_ref, status, tags, created_at, updated_at
			FROM engagements ORDER BY created_at DESC
		`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Engagement
	for rows.Next() {
		var eng models.Engagement
		var targetsJSON, tagsJSON string
		if err := rows.Scan(&eng.ID, &eng.Name, &eng.OrgID, &eng.OwnerID, &targetsJSON, &eng.AuthorizationRef, &eng.Status, &tagsJSON, &eng.CreatedAt, &eng.UpdatedAt); err == nil {
			_ = json.Unmarshal([]byte(targetsJSON), &eng.AllowedTargets)
			_ = json.Unmarshal([]byte(tagsJSON), &eng.Tags)
			out = append(out, eng)
		}
	}
	return out, rows.Err()
}

// UpdateEngagementStatus updates the lifecycle status of an engagement.
func (s *SQLiteCLI) UpdateEngagementStatus(ctx context.Context, id string, status string) error {
	if err := s.EnsureEngagementTables(ctx); err != nil {
		return err
	}
	status = strings.ToLower(strings.TrimSpace(status))
	res, err := s.db.ExecContext(ctx, `
		UPDATE engagements
		SET status = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, status, id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrEngagementNotFound
	}
	return nil
}

// AddScanToEngagement associates an executed scan with an engagement.
func (s *SQLiteCLI) AddScanToEngagement(ctx context.Context, engagementID, scanID, phase string) error {
	if err := s.EnsureEngagementTables(ctx); err != nil {
		return err
	}
	if phase == "" {
		phase = "scan"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO engagement_scans (engagement_id, scan_id, added_at, phase)
		VALUES (?, ?, CURRENT_TIMESTAMP, ?)
		ON CONFLICT(engagement_id, scan_id) DO UPDATE SET phase = ?, added_at = CURRENT_TIMESTAMP
	`, engagementID, scanID, phase, phase)
	return err
}

// ListEngagementScans returns all scan runs associated with an engagement.
func (s *SQLiteCLI) ListEngagementScans(ctx context.Context, engagementID string) ([]models.EngagementScan, error) {
	if err := s.EnsureEngagementTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT engagement_id, scan_id, added_at, phase
		FROM engagement_scans
		WHERE engagement_id = ?
		ORDER BY added_at ASC
	`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.EngagementScan
	for rows.Next() {
		var es models.EngagementScan
		if err := rows.Scan(&es.EngagementID, &es.ScanID, &es.AddedAt, &es.Phase); err == nil {
			scans = append(scans, es)
		}
	}
	return scans, rows.Err()
}
