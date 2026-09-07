package store

import (
	"context"
	"fmt"
	"time"
)

// ScanMetrics contains only counts persisted for a scan. Scheduler worker
// state and ETA are intentionally absent: they are process-local and must not
// be guessed by an API that may be served from a different process.
type ScanMetrics struct {
	ScanID              string
	Status              string
	Assets              int
	Findings            int
	Events              int
	CompletedRuns       int
	FailedRuns          int
	StartedAt           time.Time
	ThroughputPerMinute float64
}

func (s *SQLiteCLI) ScanMetrics(ctx context.Context, scanID string) (ScanMetrics, error) {
	metrics := ScanMetrics{ScanID: scanID}
	if s == nil || s.db == nil {
		return metrics, fmt.Errorf("database connection is nil")
	}
	var started string
	if err := s.db.QueryRowContext(ctx, `SELECT status, started_at FROM scan_runs WHERE scan_id=?`, scanID).Scan(&metrics.Status, &started); err != nil {
		return metrics, err
	}
	metrics.StartedAt = parseSQLiteTime(started)
	for _, item := range []struct {
		query string
		dest  *int
	}{
		{`SELECT COUNT(*) FROM assets WHERE scan_id=?`, &metrics.Assets},
		{`SELECT COUNT(*) FROM findings WHERE scan_id=?`, &metrics.Findings},
		{`SELECT COUNT(*) FROM events WHERE scan_id=?`, &metrics.Events},
		{`SELECT COALESCE(SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END), 0) FROM module_runs WHERE scan_id=?`, &metrics.CompletedRuns},
		{`SELECT COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END), 0) FROM module_runs WHERE scan_id=?`, &metrics.FailedRuns},
	} {
		if err := s.db.QueryRowContext(ctx, item.query, scanID).Scan(item.dest); err != nil {
			return metrics, err
		}
	}
	if !metrics.StartedAt.IsZero() {
		elapsed := time.Since(metrics.StartedAt).Minutes()
		if elapsed > 0 {
			metrics.ThroughputPerMinute = float64(metrics.CompletedRuns) / elapsed
		}
	}
	return metrics, nil
}
