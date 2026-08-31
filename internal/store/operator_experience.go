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
	res, err := s.SearchCategorized(ctx, scanID, query, "global")
	if err != nil {
		return nil, nil, err
	}
	return res.Assets, res.Findings, nil
}

type CategorizedSearchResult struct {
	Category string           `json:"category"`
	Assets   []models.Asset   `json:"assets"`
	Findings []models.Finding `json:"findings"`
}

func (s *SQLiteCLI) SearchCategorized(ctx context.Context, scanID, query, category string) (CategorizedSearchResult, error) {
	category = strings.ToLower(strings.TrimSpace(category))
	if category == "" {
		category = "global"
	}
	qLower := strings.ToLower(strings.TrimSpace(query))

	allAssets, err := s.Assets(ctx, scanID)
	if err != nil {
		return CategorizedSearchResult{}, err
	}
	allFindings, err := s.Findings(ctx, scanID)
	if err != nil {
		return CategorizedSearchResult{}, err
	}

	match := func(values ...string) bool {
		if qLower == "" {
			return true
		}
		for _, v := range values {
			if strings.Contains(strings.ToLower(v), qLower) {
				return true
			}
		}
		return false
	}

	resAssets := make([]models.Asset, 0)
	resFindings := make([]models.Finding, 0)

	for _, a := range allAssets {
		switch category {
		case "asset":
			if (a.Type == "subdomain" || a.Type == "ip" || a.Type == "cidr" || a.Type == "domain" || a.Type == "host") && match(a.Value, a.Parent, a.Metadata) {
				resAssets = append(resAssets, a)
			}
		case "service":
			if (a.Type == "port" || a.Type == "service" || a.Type == "url") && match(a.Value, a.Parent, a.Metadata) {
				resAssets = append(resAssets, a)
			}
		case "technology":
			if (a.Type == "technology" || a.Type == "framework") && match(a.Value, a.Parent, a.Metadata) {
				resAssets = append(resAssets, a)
			}
		case "certificate":
			if (a.Type == "certificate" || a.Type == "tls") && match(a.Value, a.Parent, a.Metadata) {
				resAssets = append(resAssets, a)
			}
		case "secret":
			if (a.Type == "secret" || a.Type == "token" || a.Type == "credential") && match(a.Value, a.Parent, a.Metadata) {
				resAssets = append(resAssets, a)
			}
		case "screenshot":
			if a.Type == "screenshot" && match(a.Value, a.Parent, a.Metadata) {
				resAssets = append(resAssets, a)
			}
		default: // global & graph
			if match(a.Type, a.Value, a.Parent, a.Metadata) {
				resAssets = append(resAssets, a)
			}
		}
	}

	for _, f := range allFindings {
		switch category {
		case "secret":
			if (strings.Contains(strings.ToLower(f.Title), "secret") || strings.Contains(strings.ToLower(f.Title), "token") || strings.Contains(strings.ToLower(f.Title), "key")) && match(f.Title, f.Asset, f.Evidence) {
				resFindings = append(resFindings, f)
			}
		case "finding", "global":
			if match(f.Title, f.Asset, f.Severity, f.CVE, f.CWE, f.Evidence, f.Remediation) {
				resFindings = append(resFindings, f)
			}
		}
	}

	return CategorizedSearchResult{
		Category: category,
		Assets:   resAssets,
		Findings: resFindings,
	}, nil
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
