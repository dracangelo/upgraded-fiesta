package modules

import (
	"context"
	"fmt"
	"strings"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type WappalyzerRule struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Headers    []string `json:"headers"`
	HTMLBody   []string `json:"html_body"`
	ScriptTags []string `json:"script_tags"`
}

type WappalyzerDetector struct {
	db    *store.SQLiteCLI
	rules []WappalyzerRule
}

func NewWappalyzerDetector(db *store.SQLiteCLI) *WappalyzerDetector {
	defaultRules := []WappalyzerRule{
		{
			Name:       "WordPress",
			Category:   "CMS",
			HTMLBody:   []string{"wp-content", "wp-includes"},
			ScriptTags: []string{"wp-embed.min.js"},
		},
		{
			Name:       "React",
			Category:   "JavaScript Framework",
			HTMLBody:   []string{"data-reactroot", "react-dom"},
			ScriptTags: []string{"react.production.min.js"},
		},
		{
			Name:     "Cloudflare",
			Category: "CDN / WAF",
			Headers:  []string{"server: cloudflare", "cf-ray"},
		},
		{
			Name:     "Nginx",
			Category: "Web Server",
			Headers:  []string{"server: nginx"},
		},
	}
	return &WappalyzerDetector{db: db, rules: defaultRules}
}

func (w *WappalyzerDetector) Detect(ctx context.Context, scanID, url, headers, body string) []models.Asset {
	var detected []models.Asset
	lowerHeaders := strings.ToLower(headers)
	lowerBody := strings.ToLower(body)

	for _, rule := range w.rules {
		matched := false
		for _, h := range rule.Headers {
			if strings.Contains(lowerHeaders, strings.ToLower(h)) {
				matched = true
				break
			}
		}
		if !matched {
			for _, b := range rule.HTMLBody {
				if strings.Contains(lowerBody, strings.ToLower(b)) {
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, s := range rule.ScriptTags {
				if strings.Contains(lowerBody, strings.ToLower(s)) {
					matched = true
					break
				}
			}
		}

		if matched {
			metadata := fmt.Sprintf("technology=%s;category=%s;source=wappalyzer_rule_engine", rule.Name, rule.Category)
			asset := models.Asset{
				ScanID:   scanID,
				Type:     "wappalyzer_technology",
				Value:    rule.Name,
				Parent:   url,
				Metadata: metadata,
			}
			detected = append(detected, asset)
			_ = w.db.AddAsset(ctx, asset)
		}
	}

	return detected
}
