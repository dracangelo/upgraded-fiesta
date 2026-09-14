package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"enumscan/internal/models"
)

func (p *PostgresStore) AssetByID(ctx context.Context, id int64) (models.Asset, error) {
	var asset models.Asset
	if p.db == nil {
		return asset, p.notOpenError()
	}
	err := p.db.QueryRowContext(ctx, `SELECT id,scan_id,type,value,parent,metadata,created_at FROM assets WHERE id=$1`, id).Scan(&asset.ID, &asset.ScanID, &asset.Type, &asset.Value, &asset.Parent, &asset.Metadata, &asset.CreatedAt)
	if err != nil {
		return asset, err
	}
	return asset, p.revealAsset(&asset)
}

func (p *PostgresStore) DeleteAssets(ctx context.Context, ids []int64) error {
	if p.db == nil {
		return p.notOpenError()
	}
	query, args := postgresIDsDeleteQuery("assets", ids)
	if query == "" {
		return nil
	}
	_, err := p.db.ExecContext(ctx, query, args...)
	return err
}

func (p *PostgresStore) DeleteFindings(ctx context.Context, ids []int64) error {
	if p.db == nil {
		return p.notOpenError()
	}
	query, args := postgresIDsDeleteQuery("findings", ids)
	if query == "" {
		return nil
	}
	_, err := p.db.ExecContext(ctx, query, args...)
	return err
}

func postgresIDsDeleteQuery(table string, ids []int64) (string, []any) {
	if len(ids) == 0 {
		return "", nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for index, id := range ids {
		placeholders[index] = fmt.Sprintf("$%d", index+1)
		args[index] = id
	}
	return "DELETE FROM " + table + " WHERE id IN (" + strings.Join(placeholders, ",") + ")", args
}

// Exec remains for controlled internal migration/import statements. Callers
// must not use it with untrusted SQL.
func (p *PostgresStore) Exec(ctx context.Context, statement string) error {
	if p.db == nil {
		return p.notOpenError()
	}
	_, err := p.db.ExecContext(ctx, statement)
	return err
}

func (p *PostgresStore) ScanMetrics(ctx context.Context, scanID string) (ScanMetrics, error) {
	metrics := ScanMetrics{ScanID: scanID}
	if p.db == nil {
		return metrics, p.notOpenError()
	}
	if err := p.db.QueryRowContext(ctx, `SELECT status,started_at FROM scan_runs WHERE scan_id=$1`, scanID).Scan(&metrics.Status, &metrics.StartedAt); err != nil {
		return metrics, err
	}
	for _, item := range []struct {
		query string
		dest  *int
	}{
		{`SELECT COUNT(*) FROM assets WHERE scan_id=$1`, &metrics.Assets},
		{`SELECT COUNT(*) FROM findings WHERE scan_id=$1`, &metrics.Findings},
		{`SELECT COUNT(*) FROM events WHERE scan_id=$1`, &metrics.Events},
		{`SELECT COALESCE(SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END),0) FROM module_runs WHERE scan_id=$1`, &metrics.CompletedRuns},
		{`SELECT COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0) FROM module_runs WHERE scan_id=$1`, &metrics.FailedRuns},
	} {
		if err := p.db.QueryRowContext(ctx, item.query, scanID).Scan(item.dest); err != nil {
			return metrics, err
		}
	}
	if !metrics.StartedAt.IsZero() {
		if elapsed := time.Since(metrics.StartedAt).Minutes(); elapsed > 0 {
			metrics.ThroughputPerMinute = float64(metrics.CompletedRuns) / elapsed
		}
	}
	return metrics, nil
}

// PurgeScansOlderThan deletes the same scan-bound evidence SQLite retains.
func (p *PostgresStore) PurgeScansOlderThan(ctx context.Context, threshold time.Duration) (int64, error) {
	if p.db == nil {
		return 0, p.notOpenError()
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	cutoff := time.Now().UTC().Add(-threshold)
	for _, table := range []string{"assets", "findings", "events", "checkpoints"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE scan_id IN (SELECT scan_id FROM scan_runs WHERE started_at < $1)", cutoff); err != nil {
			return 0, err
		}
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM scan_runs WHERE started_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
