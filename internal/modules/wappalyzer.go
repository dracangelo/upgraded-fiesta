package modules

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

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

const (
	maxWappalyzerRuleFiles = 16
	maxWappalyzerRules     = 2000
	maxWappalyzerPattern   = 1024
)

type WappalyzerDetector struct {
	db    *store.SQLiteCLI
	rules []WappalyzerRule
}

func NewWappalyzerDetector(db *store.SQLiteCLI) *WappalyzerDetector {
	return &WappalyzerDetector{db: db, rules: builtinWappalyzerRules()}
}

func builtinWappalyzerRules() []WappalyzerRule {
	return []WappalyzerRule{
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
}

// NewWappalyzerDetectorWithRuleFiles extends the built-in signatures with the
// Wappalyzer community JSON format. Rule files are local, operator-supplied
// inputs; malformed or over-large files fail configuration rather than being
// silently ignored.
func NewWappalyzerDetectorWithRuleFiles(db *store.SQLiteCLI, paths []string) (*WappalyzerDetector, error) {
	if len(paths) > maxWappalyzerRuleFiles {
		return nil, fmt.Errorf("at most %d Wappalyzer rule files are allowed", maxWappalyzerRuleFiles)
	}
	rules := builtinWappalyzerRules()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read Wappalyzer rule file %q: %w", path, err)
		}
		cacheKey := fmt.Sprintf("wappalyzer-rules:%x", sha256.Sum256(data))
		var loaded []WappalyzerRule
		if cached, ok, cacheErr := db.CachedValue(context.Background(), cacheKey); cacheErr == nil && ok {
			if err := json.Unmarshal([]byte(cached), &loaded); err != nil {
				loaded = nil
			}
		}
		if len(loaded) == 0 {
			loaded, err = parseWappalyzerJSON(data)
			if err != nil {
				return nil, fmt.Errorf("parse Wappalyzer rule file %q: %w", path, err)
			}
			if encoded, err := json.Marshal(loaded); err == nil {
				_ = db.PutCachedValue(context.Background(), cacheKey, string(encoded), 24*time.Hour)
			}
		}
		if len(rules)+len(loaded) > maxWappalyzerRules {
			return nil, fmt.Errorf("Wappalyzer rules exceed limit of %d", maxWappalyzerRules)
		}
		rules = append(rules, loaded...)
	}
	return &WappalyzerDetector{db: db, rules: rules}, nil
}

type wappalyzerDocument struct {
	Technologies map[string]wappalyzerTechnology `json:"technologies"`
	Categories   map[string]struct {
		Name string `json:"name"`
	} `json:"categories"`
}

type wappalyzerTechnology struct {
	Cats    []int                      `json:"cats"`
	Headers map[string]json.RawMessage `json:"headers"`
	HTML    json.RawMessage            `json:"html"`
	Script  json.RawMessage            `json:"script"`
}

func parseWappalyzerJSON(data []byte) ([]WappalyzerRule, error) {
	var document wappalyzerDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if len(document.Technologies) == 0 {
		return nil, fmt.Errorf("no technologies found")
	}
	rules := make([]WappalyzerRule, 0, len(document.Technologies))
	for name, technology := range document.Technologies {
		rule := WappalyzerRule{Name: strings.TrimSpace(name)}
		if rule.Name == "" {
			continue
		}
		if len(technology.Cats) > 0 {
			rule.Category = document.Categories[fmt.Sprint(technology.Cats[0])].Name
		}
		for header, raw := range technology.Headers {
			for _, pattern := range wappalyzerPatterns(raw) {
				rule.Headers = append(rule.Headers, header+": "+pattern)
			}
		}
		rule.HTMLBody = wappalyzerPatterns(technology.HTML)
		rule.ScriptTags = wappalyzerPatterns(technology.Script)
		if len(rule.Headers)+len(rule.HTMLBody)+len(rule.ScriptTags) == 0 {
			continue
		}
		if err := validateWappalyzerRule(rule); err != nil {
			return nil, fmt.Errorf("technology %q: %w", rule.Name, err)
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no usable technology rules found")
	}
	return rules, nil
}

func wappalyzerPatterns(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{stripWappalyzerMetadata(one)}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		patterns := make([]string, 0, len(many))
		for _, value := range many {
			patterns = append(patterns, stripWappalyzerMetadata(value))
		}
		return patterns
	}
	return nil
}

func stripWappalyzerMetadata(pattern string) string {
	pattern, _, _ = strings.Cut(pattern, "\\;")
	return strings.TrimSpace(pattern)
}

func validateWappalyzerRule(rule WappalyzerRule) error {
	for _, pattern := range append(append([]string{}, rule.Headers...), append(rule.HTMLBody, rule.ScriptTags...)...) {
		if len(pattern) == 0 || len(pattern) > maxWappalyzerPattern {
			return fmt.Errorf("pattern must be between 1 and %d bytes", maxWappalyzerPattern)
		}
		if _, err := regexp.Compile("(?i)" + pattern); err != nil {
			return fmt.Errorf("invalid regular expression: %w", err)
		}
	}
	return nil
}

func (w *WappalyzerDetector) Detect(ctx context.Context, scanID, url, headers, body string) []models.Asset {
	var detected []models.Asset
	lowerHeaders := strings.ToLower(headers)
	lowerBody := strings.ToLower(body)

	for _, rule := range w.rules {
		matched := false
		for _, h := range rule.Headers {
			if wappalyzerMatches(h, lowerHeaders) {
				matched = true
				break
			}
		}
		if !matched {
			for _, b := range rule.HTMLBody {
				if wappalyzerMatches(b, lowerBody) {
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, s := range rule.ScriptTags {
				if wappalyzerMatches(s, lowerBody) {
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

func wappalyzerMatches(pattern, value string) bool {
	compiled, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		// Built-in rules are deliberately simple literals. A malformed external
		// rule is rejected while loading, so this is only a defensive fallback.
		return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
	}
	return compiled.MatchString(value)
}
