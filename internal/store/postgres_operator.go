package store

import (
	"context"
	"strings"
	"time"

	"enumscan/internal/models"
)

func (p *PostgresStore) SaveQuery(ctx context.Context, name, query string) error {
	if p.db == nil {
		return p.notOpenError()
	}
	_, err := p.db.ExecContext(ctx, `INSERT INTO saved_queries(name,query) VALUES($1,$2) ON CONFLICT(name) DO UPDATE SET query=EXCLUDED.query`, strings.TrimSpace(name), strings.TrimSpace(query))
	return err
}

func (p *PostgresStore) SavedQueries(ctx context.Context) ([]models.SavedQuery, error) {
	if p.db == nil {
		return nil, p.notOpenError()
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id,name,query,created_at FROM saved_queries ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	queries := make([]models.SavedQuery, 0)
	for rows.Next() {
		var query models.SavedQuery
		if err := rows.Scan(&query.ID, &query.Name, &query.Query, &query.CreatedAt); err != nil {
			return nil, err
		}
		queries = append(queries, query)
	}
	return queries, rows.Err()
}

func (p *PostgresStore) Search(ctx context.Context, scanID, query string) ([]models.Asset, []models.Finding, error) {
	result, err := p.SearchCategorized(ctx, scanID, query, "global")
	if err != nil {
		return nil, nil, err
	}
	return result.Assets, result.Findings, nil
}

// SearchCategorized deliberately applies the same category and matching rules
// as SQLite after reading the evidence. This preserves result semantics across
// databases without relying on database-specific full-text search behavior.
func (p *PostgresStore) SearchCategorized(ctx context.Context, scanID, query, category string) (CategorizedSearchResult, error) {
	if p.db == nil {
		return CategorizedSearchResult{}, p.notOpenError()
	}
	category = strings.ToLower(strings.TrimSpace(category))
	if category == "" {
		category = "global"
	}
	query = strings.ToLower(strings.TrimSpace(query))
	assets, err := p.Assets(ctx, scanID)
	if err != nil {
		return CategorizedSearchResult{}, err
	}
	findings, err := p.Findings(ctx, scanID)
	if err != nil {
		return CategorizedSearchResult{}, err
	}
	match := func(values ...string) bool {
		if query == "" {
			return true
		}
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), query) {
				return true
			}
		}
		return false
	}
	result := CategorizedSearchResult{Category: category, Assets: make([]models.Asset, 0), Findings: make([]models.Finding, 0)}
	for _, asset := range assets {
		switch category {
		case "asset":
			if (asset.Type == "subdomain" || asset.Type == "ip" || asset.Type == "cidr" || asset.Type == "domain" || asset.Type == "host") && match(asset.Value, asset.Parent, asset.Metadata) {
				result.Assets = append(result.Assets, asset)
			}
		case "service":
			if (asset.Type == "port" || asset.Type == "service" || asset.Type == "url") && match(asset.Value, asset.Parent, asset.Metadata) {
				result.Assets = append(result.Assets, asset)
			}
		case "technology":
			if (asset.Type == "technology" || asset.Type == "framework") && match(asset.Value, asset.Parent, asset.Metadata) {
				result.Assets = append(result.Assets, asset)
			}
		case "certificate":
			if (asset.Type == "certificate" || asset.Type == "tls") && match(asset.Value, asset.Parent, asset.Metadata) {
				result.Assets = append(result.Assets, asset)
			}
		case "secret":
			if (asset.Type == "secret" || asset.Type == "token" || asset.Type == "credential") && match(asset.Value, asset.Parent, asset.Metadata) {
				result.Assets = append(result.Assets, asset)
			}
		case "screenshot":
			if asset.Type == "screenshot" && match(asset.Value, asset.Parent, asset.Metadata) {
				result.Assets = append(result.Assets, asset)
			}
		default:
			if match(asset.Type, asset.Value, asset.Parent, asset.Metadata) {
				result.Assets = append(result.Assets, asset)
			}
		}
	}
	for _, finding := range findings {
		switch category {
		case "secret":
			title := strings.ToLower(finding.Title)
			if (strings.Contains(title, "secret") || strings.Contains(title, "token") || strings.Contains(title, "key")) && match(finding.Title, finding.Asset, finding.Evidence) {
				result.Findings = append(result.Findings, finding)
			}
		case "finding", "global":
			if match(finding.Title, finding.Asset, finding.Severity, finding.CVE, finding.CWE, finding.Evidence, finding.Remediation) {
				result.Findings = append(result.Findings, finding)
			}
		}
	}
	return result, nil
}

func (p *PostgresStore) ScreenshotAssets(ctx context.Context, scanID string) ([]models.Asset, error) {
	if p.db == nil {
		return nil, p.notOpenError()
	}
	query := `SELECT id,scan_id,type,value,parent,metadata,created_at FROM assets WHERE type='screenshot' ORDER BY id DESC`
	args := []any(nil)
	if scanID != "" {
		query = `SELECT id,scan_id,type,value,parent,metadata,created_at FROM assets WHERE type='screenshot' AND scan_id=$1 ORDER BY id DESC`
		args = []any{scanID}
	}
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	assets := make([]models.Asset, 0)
	for rows.Next() {
		var asset models.Asset
		if err := rows.Scan(&asset.ID, &asset.ScanID, &asset.Type, &asset.Value, &asset.Parent, &asset.Metadata, &asset.CreatedAt); err != nil {
			return nil, err
		}
		if err := p.revealAsset(&asset); err != nil {
			return nil, err
		}
		assets = append(assets, asset)
	}
	return assets, rows.Err()
}

func (p *PostgresStore) RecordAPIAudit(ctx context.Context, entry models.APIAuditEntry) error {
	if p.db == nil {
		return p.notOpenError()
	}
	_, err := p.db.ExecContext(ctx, `INSERT INTO api_audit_records(actor,role,action,scan_id,status,created_at) VALUES($1,$2,$3,$4,$5,$6)`, entry.Actor, entry.Role, entry.Action, entry.ScanID, entry.Status, time.Now().UTC())
	return err
}

func (p *PostgresStore) RecentAPIAudit(ctx context.Context, limit int) ([]models.APIAuditEntry, error) {
	if p.db == nil {
		return nil, p.notOpenError()
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id,actor,role,action,scan_id,status,created_at FROM api_audit_records ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]models.APIAuditEntry, 0)
	for rows.Next() {
		var entry models.APIAuditEntry
		if err := rows.Scan(&entry.ID, &entry.Actor, &entry.Role, &entry.Action, &entry.ScanID, &entry.Status, &entry.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (p *PostgresStore) RecentModuleRunLogs(ctx context.Context, scanID string, limit int) ([]models.ModuleRunLog, error) {
	if p.db == nil {
		return nil, p.notOpenError()
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id,scan_id,module,event_type,target,status,duration_ms,error,created_at FROM module_runs WHERE scan_id=$1 ORDER BY id DESC LIMIT $2`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logs := make([]models.ModuleRunLog, 0)
	for rows.Next() {
		var entry models.ModuleRunLog
		if err := rows.Scan(&entry.ID, &entry.ScanID, &entry.Module, &entry.EventType, &entry.Target, &entry.Status, &entry.DurationMS, &entry.Error, &entry.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for left, right := 0, len(logs)-1; left < right; left, right = left+1, right-1 {
		logs[left], logs[right] = logs[right], logs[left]
	}
	return logs, nil
}
