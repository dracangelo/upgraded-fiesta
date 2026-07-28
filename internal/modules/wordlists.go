package modules

import (
	"regexp"
	"strings"
)

type WordlistEngine struct{}

func NewWordlistEngine() *WordlistEngine {
	return &WordlistEngine{}
}

func (w *WordlistEngine) GenerateAdaptivePaths(techStack []string) []string {
	basePaths := []string{
		"/admin", "/api", "/v1", "/v2", "/health", "/metrics", "/status",
		"/login", "/dashboard", "/user", "/config", "/test", "/dev",
	}

	techMap := map[string][]string{
		"wordpress":  {"/wp-admin", "/wp-content", "/wp-includes", "/wp-json/wp/v2/users"},
		"spring":     {"/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/logfile"},
		"aspnet":     {"/elmah.axd", "/trace.axd", "/web.config"},
		"php":        {"/phpinfo.php", "/info.php", "/composer.json", "/composer.lock"},
		"node":       {"/package.json", "/package-lock.json", "/node_modules/"},
		"laravel":    {"/.env", "/storage/logs/laravel.log"},
		"django":     {"/admin/login/", "/static/admin/"},
	}

	result := append([]string{}, basePaths...)
	for _, tech := range techStack {
		tLower := strings.ToLower(tech)
		for key, paths := range techMap {
			if strings.Contains(tLower, key) {
				result = append(result, paths...)
			}
		}
	}
	return result
}

func (w *WordlistEngine) ExtractTokensFromJS(jsContent string) []string {
	tokenRegex := regexp.MustCompile(`[a-zA-Z0-9_\-/]{3,30}`)
	matches := tokenRegex.FindAllString(jsContent, -1)

	seen := make(map[string]bool)
	var tokens []string

	for _, m := range matches {
		if strings.HasPrefix(m, "/") && !seen[m] {
			seen[m] = true
			tokens = append(tokens, m)
		}
	}

	return tokens
}
