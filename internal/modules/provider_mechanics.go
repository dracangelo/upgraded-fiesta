package modules

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"enumscan/internal/models"
)

func jsonInteger(body []byte, key string) (int, bool) {
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return 0, false
	}
	value, ok := payload[key].(float64)
	if !ok || value < 0 {
		return 0, false
	}
	return int(value), true
}

type ProviderQuota struct {
	Limit     *int   `json:"limit,omitempty"`
	Remaining *int   `json:"remaining,omitempty"`
	Used      *int   `json:"used,omitempty"`
	ResetAt   string `json:"reset_at,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Source    string `json:"source,omitempty"`
}

func providerAssignments(values []string) map[string]string {
	result := make(map[string]string, len(values))
	for _, item := range values {
		name, value, ok := strings.Cut(item, "=")
		if ok {
			result[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
		}
	}
	return result
}

func effectiveProviderSources(cfg models.PassiveIntelConfig) []string {
	selected := make(map[string]bool)
	for _, source := range cfg.Sources {
		source = strings.ToLower(strings.TrimSpace(source))
		if source != "" {
			selected[source] = true
		}
	}
	for source, raw := range providerAssignments(cfg.ProviderControls) {
		enabled, err := strconv.ParseBool(raw)
		if err == nil {
			selected[source] = enabled
		}
	}
	result := make([]string, 0, len(selected))
	for source, enabled := range selected {
		if enabled {
			result = append(result, source)
		}
	}
	sort.Strings(result)
	return result
}

func providerExplicitlyDisabled(cfg models.PassiveIntelConfig, source string) bool {
	raw, ok := providerAssignments(cfg.ProviderControls)[strings.ToLower(source)]
	if !ok {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	return err == nil && !enabled
}

func configuredProviderVersion(cfg models.PassiveIntelConfig, source string, definition PassiveProviderDefinition) string {
	if version := providerAssignments(cfg.ProviderVersions)[source]; version != "" {
		return version
	}
	return definition.APIVersion
}

func quotaFromResponse(source string, header http.Header, body []byte) *ProviderQuota {
	quota := &ProviderQuota{Source: "headers"}
	quota.Limit = integerHeader(header, "RateLimit-Limit", "X-RateLimit-Limit")
	quota.Remaining = integerHeader(header, "RateLimit-Remaining", "X-RateLimit-Remaining")
	quota.Used = integerHeader(header, "RateLimit-Used", "X-RateLimit-Used")
	quota.Resource = firstHeader(header, "X-RateLimit-Resource", "RateLimit-Name")
	if reset := firstHeader(header, "RateLimit-Reset", "X-RateLimit-Reset"); reset != "" {
		if epoch, err := strconv.ParseInt(reset, 10, 64); err == nil {
			quota.ResetAt = time.Unix(epoch, 0).UTC().Format(time.RFC3339)
		} else if parsed, err := http.ParseTime(reset); err == nil {
			quota.ResetAt = parsed.UTC().Format(time.RFC3339)
		}
	}
	if source == "shodan" {
		if credits, ok := jsonInteger(body, "credits"); ok {
			quota.Remaining = &credits
			quota.Resource = "query credits"
			quota.Source = "response body"
		}
	}
	if quota.Limit == nil && quota.Remaining == nil && quota.Used == nil && quota.ResetAt == "" {
		return nil
	}
	return quota
}

func integerHeader(header http.Header, names ...string) *int {
	for _, name := range names {
		if value, err := strconv.Atoi(strings.TrimSpace(header.Get(name))); err == nil && value >= 0 {
			return &value
		}
	}
	return nil
}
func firstHeader(header http.Header, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func providerUpdateStatus(cfg models.PassiveIntelConfig, source string, definition PassiveProviderDefinition, header http.Header) string {
	if !cfg.EnableUpdateChecks {
		return ""
	}
	configured := configuredProviderVersion(cfg, source, definition)
	if sunset := header.Get("Sunset"); sunset != "" {
		return "update required: provider announced sunset " + boundedDiagnostic(sunset)
	}
	if deprecation := header.Get("Deprecation"); deprecation != "" && deprecation != "false" {
		return "update advised: provider marked this API deprecated"
	}
	selected := firstHeader(header, "X-GitHub-Api-Version-Selected", "X-API-Version", "API-Version")
	if selected != "" && configured != "" && selected != configured {
		return "update available: configured=" + configured + " provider=" + boundedDiagnostic(selected)
	}
	if configured == "" {
		return "no pinned API version and no deprecation signal"
	}
	return "current API contract " + configured + "; no deprecation signal"
}
