package store

import (
	"context"
	"database/sql"
	"fmt"

	"enumscan/internal/models"
)

// RecordModuleRun persists module outcomes for operator review and health
// reporting. This is intentionally independent of checkpoints: a failed
// database write or module invocation must remain observable.
func (s *SQLiteCLI) RecordModuleRun(ctx context.Context, run models.ModuleRun) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO module_runs(scan_id,module,event_type,target,status,duration_ms,error) VALUES(?,?,?,?,?,?,?)`,
		run.ScanID, run.Module, run.EventType, run.Target, run.Status, run.Duration.Milliseconds(), run.Error)
	return err
}

// ScanHealth summarizes persisted module outcomes. A completed scan is not
// healthy if any module invocation failed.
func (s *SQLiteCLI) ScanHealth(ctx context.Context, scanID string) (models.ScanHealth, error) {
	health := models.ScanHealth{ScanID: scanID}
	if s == nil || s.db == nil {
		return health, fmt.Errorf("database connection is nil")
	}
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM scan_runs WHERE scan_id=?`, scanID).Scan(&health.Status); err != nil {
		if err == sql.ErrNoRows {
			return health, nil
		}
		return health, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT
 COALESCE(SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END), 0),
 COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END), 0)
 FROM module_runs WHERE scan_id=?`, scanID).Scan(&health.CompletedRuns, &health.FailedRuns); err != nil {
		return health, err
	}
	health.Healthy = health.Status == "completed" && health.FailedRuns == 0
	return health, nil
}

func (s *SQLiteCLI) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	return s.db.PingContext(ctx)
}
