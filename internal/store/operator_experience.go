package store

import (
	"context"
	"strings"

	"enumscan/internal/models"
)

func (s *SQLiteCLI) SaveQuery(ctx context.Context, name, query string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO saved_queries(name,query) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET query=excluded.query`, strings.TrimSpace(name), strings.TrimSpace(query))
	return err
}

func (s *SQLiteCLI) SavedQueries(ctx context.Context) ([]models.SavedQuery, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,query,created_at FROM saved_queries ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SavedQuery
	for rows.Next() {
		var item models.SavedQuery
		var created string
		if err := rows.Scan(&item.ID, &item.Name, &item.Query, &created); err != nil {
			return nil, err
		}
		item.CreatedAt = parseSQLiteTime(created)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLiteCLI) Search(ctx context.Context, scanID, query string) ([]models.Asset, []models.Finding, error) {
	query = "%" + strings.ToLower(strings.TrimSpace(query)) + "%"
	assets, err := s.Assets(ctx, scanID)
	if err != nil {
		return nil, nil, err
	}
	findings, err := s.Findings(ctx, scanID)
	if err != nil {
		return nil, nil, err
	}
	if query == "%%" {
		return assets, findings, nil
	}
	match := func(values ...string) bool {
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), strings.Trim(query, "%")) {
				return true
			}
		}
		return false
	}
	filteredAssets := make([]models.Asset, 0)
	for _, asset := range assets {
		if match(asset.Type, asset.Value, asset.Parent, asset.Metadata) {
			filteredAssets = append(filteredAssets, asset)
		}
	}
	filteredFindings := make([]models.Finding, 0)
	for _, finding := range findings {
		if match(finding.Title, finding.Asset, finding.Severity, finding.CVE, finding.CWE, finding.Evidence) {
			filteredFindings = append(filteredFindings, finding)
		}
	}
	return filteredAssets, filteredFindings, nil
}

func (s *SQLiteCLI) ScreenshotAssets(ctx context.Context, scanID string) ([]models.Asset, error) {
	assets, err := s.Assets(ctx, scanID)
	if err != nil {
		return nil, err
	}
	out := make([]models.Asset, 0)
	for _, asset := range assets {
		// Only an actual renderer should create this type. Queued screenshot
		// targets are intentionally excluded from the gallery.
		if asset.Type == "screenshot" {
			out = append(out, asset)
		}
	}
	return out, nil
}
