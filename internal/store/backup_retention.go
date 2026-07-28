package store

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Backup creates a file copy / snapshot of the SQLite database at targetPath.
func (s *SQLiteCLI) Backup(ctx context.Context, targetPath string) error {
	if s == nil || s.path == "" {
		return fmt.Errorf("invalid store path")
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	// Lock writes during backup file copy using VACUUM INTO or file copy
	if s.db != nil {
		query := fmt.Sprintf("VACUUM INTO '%s'", targetPath)
		if _, err := s.db.ExecContext(ctx, query); err == nil {
			return nil
		}
	}

	// Fallback to direct file copy if VACUUM INTO fails or file unsupported
	srcFile, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("open source db: %w", err)
	}
	defer srcFile.Close()

	destFile, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("create backup target: %w", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, srcFile); err != nil {
		return fmt.Errorf("copy backup data: %w", err)
	}

	return nil
}

// Restore overwrites the store database file from a backup snapshot at backupPath.
func (s *SQLiteCLI) Restore(ctx context.Context, backupPath string) error {
	if s == nil || s.path == "" {
		return fmt.Errorf("invalid store path")
	}

	backupFile, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("open backup file: %w", err)
	}
	defer backupFile.Close()

	// Close open DB handle before overwriting file
	if s.db != nil {
		_ = s.db.Close()
	}

	destFile, err := os.Create(s.path)
	if err != nil {
		return fmt.Errorf("create dest db file: %w", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, backupFile); err != nil {
		return fmt.Errorf("restore backup data: %w", err)
	}

	// Re-open DB
	newStore, err := OpenSQLiteCLI(s.path)
	if err != nil {
		return fmt.Errorf("reopen database after restore: %w", err)
	}
	s.db = newStore.db

	return nil
}

// PurgeScansOlderThan deletes scan runs, assets, findings, events, and checkpoints older than threshold.
func (s *SQLiteCLI) PurgeScansOlderThan(ctx context.Context, threshold time.Duration) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}

	cutoff := time.Now().Add(-threshold).Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}

	// Delete from child tables using scan_runs created_at / started_at
	_, _ = tx.ExecContext(ctx, `DELETE FROM assets WHERE scan_id IN (SELECT scan_id FROM scan_runs WHERE started_at < ?)`, cutoff)
	_, _ = tx.ExecContext(ctx, `DELETE FROM findings WHERE scan_id IN (SELECT scan_id FROM scan_runs WHERE started_at < ?)`, cutoff)
	_, _ = tx.ExecContext(ctx, `DELETE FROM events WHERE scan_id IN (SELECT scan_id FROM scan_runs WHERE started_at < ?)`, cutoff)
	_, _ = tx.ExecContext(ctx, `DELETE FROM checkpoints WHERE scan_id IN (SELECT scan_id FROM scan_runs WHERE started_at < ?)`, cutoff)

	res, err := tx.ExecContext(ctx, `DELETE FROM scan_runs WHERE started_at < ?`, cutoff)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}

	rowsDeleted, _ := res.RowsAffected()

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return rowsDeleted, nil
}
