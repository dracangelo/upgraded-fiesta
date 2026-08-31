package store

import (
	"context"
	"fmt"
	"time"

	"enumscan/internal/models"
)

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Operator  string    `json:"operator"`
	Action    string    `json:"action"`
	ScanID    string    `json:"scan_id"`
	Details   string    `json:"details"`
}

type AuditLogger struct {
	db *SQLiteCLI
}

func NewAuditLogger(db *SQLiteCLI) *AuditLogger {
	return &AuditLogger{db: db}
}

func (a *AuditLogger) LogAction(ctx context.Context, operator, action, scanID, details string) error {
	entry := AuditEntry{
		Timestamp: time.Now().UTC(),
		Operator:  operator,
		Action:    action,
		ScanID:    scanID,
		Details:   details,
	}

	metadata := fmt.Sprintf("operator=%s;action=%s;timestamp=%s;details=%s",
		entry.Operator, entry.Action, entry.Timestamp.Format(time.RFC3339), entry.Details)

	return a.db.AddAsset(ctx, models.Asset{
		ScanID:   scanID,
		Type:     "audit_log_entry",
		Value:    fmt.Sprintf("%s:%s", operator, action),
		Metadata: metadata,
	})
}
