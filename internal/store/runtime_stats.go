package store

import (
	"context"
	"fmt"

	"enumscan/internal/models"
)

// UpsertRuntimeStats stores an observed snapshot from the local scheduler.
// A snapshot is overwritten rather than accumulated, so a restart cannot be
// mistaken for still-running workers.
func (s *SQLiteCLI) UpsertRuntimeStats(ctx context.Context, stats models.ScanRuntimeStats) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO scan_runtime_stats(
 scan_id,worker_capacity,active_workers,running_modules,queue_high,queue_normal,queue_low,enqueued_events,completed_events,updated_at
) VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
ON CONFLICT(scan_id) DO UPDATE SET
 worker_capacity=excluded.worker_capacity,active_workers=excluded.active_workers,running_modules=excluded.running_modules,
 queue_high=excluded.queue_high,queue_normal=excluded.queue_normal,queue_low=excluded.queue_low,
 enqueued_events=excluded.enqueued_events,completed_events=excluded.completed_events,updated_at=CURRENT_TIMESTAMP`,
		stats.ScanID, stats.WorkerCapacity, stats.ActiveWorkers, stats.RunningModules,
		stats.QueueHigh, stats.QueueNormal, stats.QueueLow, stats.EnqueuedEvents, stats.CompletedEvents)
	return err
}

func (s *SQLiteCLI) ScanRuntimeStats(ctx context.Context, scanID string) (models.ScanRuntimeStats, error) {
	stats := models.ScanRuntimeStats{ScanID: scanID}
	if s == nil || s.db == nil {
		return stats, fmt.Errorf("database connection is nil")
	}
	var updatedAt string
	err := s.db.QueryRowContext(ctx, `SELECT worker_capacity,active_workers,running_modules,queue_high,queue_normal,queue_low,enqueued_events,completed_events,updated_at
FROM scan_runtime_stats WHERE scan_id=?`, scanID).Scan(
		&stats.WorkerCapacity, &stats.ActiveWorkers, &stats.RunningModules,
		&stats.QueueHigh, &stats.QueueNormal, &stats.QueueLow,
		&stats.EnqueuedEvents, &stats.CompletedEvents, &updatedAt,
	)
	if err != nil {
		return stats, err
	}
	stats.UpdatedAt = parseSQLiteTime(updatedAt)
	return stats, nil
}

func (s *SQLiteCLI) RecentModuleRunLogs(ctx context.Context, scanID string, limit int) ([]models.ModuleRunLog, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,scan_id,module,event_type,target,status,duration_ms,error,created_at
FROM module_runs WHERE scan_id=? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logs := make([]models.ModuleRunLog, 0)
	for rows.Next() {
		var entry models.ModuleRunLog
		var createdAt string
		if err := rows.Scan(&entry.ID, &entry.ScanID, &entry.Module, &entry.EventType, &entry.Target, &entry.Status, &entry.DurationMS, &entry.Error, &createdAt); err != nil {
			return nil, err
		}
		if entry.Target, err = s.open("module_runs.target", entry.Target); err != nil {
			return nil, err
		}
		if entry.Error, err = s.open("module_runs.error", entry.Error); err != nil {
			return nil, err
		}
		entry.CreatedAt = parseSQLiteTime(createdAt)
		logs = append(logs, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The database query is newest-first for an efficient index walk; return
	// chronological order so an SSE client renders activity naturally.
	for left, right := 0, len(logs)-1; left < right; left, right = left+1, right-1 {
		logs[left], logs[right] = logs[right], logs[left]
	}
	return logs, nil
}
