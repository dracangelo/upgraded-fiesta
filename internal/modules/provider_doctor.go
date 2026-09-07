package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"enumscan/internal/models"
)

// EnvironmentLookup lets the doctor command inspect whether an operator has
// supplied a setting without reading, logging, or retaining its value.
type EnvironmentLookup func(string) (string, bool)

// ProviderDiagnostic is a local configuration preflight result. It is not a
// provider health check: no provider is contacted and credentials are never
// transmitted or shown.
type ProviderDiagnostic struct {
	Source              string         `json:"source"`
	Enabled             bool           `json:"enabled"`
	Status              string         `json:"status"`
	RequiredEnvironment []string       `json:"required_environment,omitempty"`
	MissingEnvironment  []string       `json:"missing_environment,omitempty"`
	Capabilities        []string       `json:"capabilities,omitempty"`
	Mode                string         `json:"mode"`
	Note                string         `json:"note,omitempty"`
	RemoteStatus        string         `json:"remote_status,omitempty"`
	QuotaRemaining      *int           `json:"quota_remaining,omitempty"`
	Quota               *ProviderQuota `json:"quota,omitempty"`
	CredentialStatus    string         `json:"credential_status,omitempty"`
	APIVersion          string         `json:"api_version,omitempty"`
	UpdateStatus        string         `json:"update_status,omitempty"`
}

// PassiveIntelDoctorReport describes the operator's passive-intel preflight.
// In its default form it is entirely local. When explicitly requested, it can
// also carry bounded remote diagnostic results; credential presence and a
// successful response never establish account entitlement or a true quota.
type PassiveIntelDoctorReport struct {
	PassiveIntelEnabled        bool                 `json:"passive_intel_enabled"`
	RemoteDiagnosticsRequested bool                 `json:"remote_diagnostics_requested,omitempty"`
	Providers                  []ProviderDiagnostic `json:"providers"`
	Warnings                   []string             `json:"warnings,omitempty"`
}

// DiagnosePassiveIntel performs an offline preflight for every configured
// source. It reports environment variable names only, never their contents.
func DiagnosePassiveIntel(cfg models.PassiveIntelConfig, lookup EnvironmentLookup) PassiveIntelDoctorReport {
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}

	sources := make(map[string]struct{}, len(cfg.Sources))
	for _, source := range cfg.Sources {
		source = strings.ToLower(strings.TrimSpace(source))
		if source != "" {
			sources[source] = struct{}{}
		}
	}
	for source := range providerAssignments(cfg.ProviderControls) {
		sources[source] = struct{}{}
	}
	names := make([]string, 0, len(sources))
	for source := range sources {
		names = append(names, source)
	}
	sort.Strings(names)

	report := PassiveIntelDoctorReport{PassiveIntelEnabled: cfg.Enabled, Providers: make([]ProviderDiagnostic, 0, len(names))}
	if !cfg.Enabled && len(names) > 0 {
		report.Warnings = append(report.Warnings, "passive_intel is disabled; configured sources will not run")
	}
	if cfg.Enabled && len(names) == 0 {
		report.Warnings = append(report.Warnings, "passive_intel is enabled but no sources are configured")
	}

	for _, source := range names {
		definition, supported := passiveProviderDefinition(source)
		result := ProviderDiagnostic{Source: source, Enabled: cfg.Enabled && !providerExplicitlyDisabled(cfg, source), RequiredEnvironment: append([]string(nil), definition.RequiredEnvironment...), Capabilities: append([]string(nil), definition.Capabilities...), Mode: definition.Mode, Note: definition.Note, APIVersion: configuredProviderVersion(cfg, source, definition)}
		if !supported {
			result.Status = "unsupported"
			result.Mode = "unknown"
			result.Note = "No built-in passive-intelligence implementation exists for this source."
			report.Providers = append(report.Providers, result)
			continue
		}
		for _, name := range definition.RequiredEnvironment {
			value, present := lookup(name)
			if !present || strings.TrimSpace(value) == "" {
				result.MissingEnvironment = append(result.MissingEnvironment, name)
			}
		}
		switch {
		case !result.Enabled:
			result.Status = "disabled"
		case len(result.MissingEnvironment) > 0:
			result.Status = "not ready"
		case !validProviderCredentialShape(source, lookup):
			result.Status = "invalid credential configuration"
		case source == "bucket" || source == "wayback":
			result.Status = "ready with authorization"
		default:
			result.Status = "ready to attempt"
		}
		report.Providers = append(report.Providers, result)
	}
	return report
}

// DiagnosePassiveIntelRemote makes an operator-requested, bounded provider
// request for configured credentialed sources. It is intentionally separate
// from doctor: a remote response can establish reachability or rejection, but
// does not by itself prove account entitlement or a provider's true quota.
func DiagnosePassiveIntelRemote(ctx context.Context, cfg models.PassiveIntelConfig, lookup EnvironmentLookup) PassiveIntelDoctorReport {
	report := DiagnosePassiveIntel(cfg, lookup)
	report.RemoteDiagnosticsRequested = true
	if !cfg.Enabled {
		return report
	}
	probe := &PassiveIntel{cfg: cfg, client: &http.Client{Timeout: 8 * time.Second}, baseURL: map[string]string{}}
	for index := range report.Providers {
		item := &report.Providers[index]
		definition, supported := passiveProviderDefinition(item.Source)
		if item.Status != "ready to attempt" || !supported || !definition.RemoteProbe {
			if supported && definition.IPOnly && item.Status == "ready to attempt" {
				item.RemoteStatus = "not checked: this source requires an explicitly configured IP target"
			}
			if item.Status == "ready with authorization" {
				item.RemoteStatus = "not checked: direct network source"
			}
			continue
		}
		req, ok := probe.diagnosticRequest(ctx, item.Source)
		if !ok {
			item.RemoteStatus = "not checked: local configuration changed"
			continue
		}
		resp, err := probe.client.Do(req)
		if err != nil {
			item.RemoteStatus = "unreachable: " + boundedDiagnostic(err.Error())
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if cfg.EnableQuotaDiscovery {
			item.Quota = quotaFromResponse(item.Source, resp.Header, body)
			if item.Quota != nil {
				item.QuotaRemaining = item.Quota.Remaining
			}
		}
		item.UpdateStatus = providerUpdateStatus(cfg, item.Source, definition, resp.Header)
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			item.RemoteStatus = fmt.Sprintf("credential rejected (HTTP %d)", resp.StatusCode)
			item.CredentialStatus = "rejected"
		case http.StatusTooManyRequests:
			item.RemoteStatus = "rate limited (HTTP 429)"
		case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent:
			item.RemoteStatus = fmt.Sprintf("provider reachable (HTTP %d)", resp.StatusCode)
			if len(definition.RequiredEnvironment) > 0 {
				item.CredentialStatus = "accepted"
			}
		default:
			item.RemoteStatus = fmt.Sprintf("provider responded HTTP %d; credential state unconfirmed", resp.StatusCode)
			item.CredentialStatus = "unconfirmed"
		}
	}
	return report
}

func validProviderCredentialShape(source string, lookup EnvironmentLookup) bool {
	definition, ok := passiveProviderDefinition(source)
	if !ok {
		return false
	}
	values := make(map[string]string, len(definition.RequiredEnvironment))
	for _, name := range definition.RequiredEnvironment {
		value, present := lookup(name)
		if !present || value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return false
		}
		values[name] = value
	}
	if source == "fofa" && !strings.Contains(values["FOFA_EMAIL"], "@") {
		return false
	}
	if source == "hibp" {
		key := values["HIBP_API_KEY"]
		if len(key) != 32 {
			return false
		}
		for _, character := range key {
			if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
				return false
			}
		}
	}
	return true
}

func (m *PassiveIntel) diagnosticRequest(ctx context.Context, source string) (*http.Request, bool) {
	var endpoint string
	headers := make(http.Header)
	switch source {
	case "shodan":
		endpoint = "https://api.shodan.io/account/profile"
		endpoint = addQuery(endpoint, "key", os.Getenv("SHODAN_API_KEY"))
	case "censys":
		endpoint = "https://search.censys.io/api/v1/account"
	case "github":
		endpoint = "https://api.github.com/user"
		headers.Set("Authorization", "Bearer "+os.Getenv("GITHUB_TOKEN"))
		headers.Set("Accept", "application/vnd.github+json")
		if definition, ok := passiveProviderDefinition(source); ok {
			headers.Set("X-GitHub-Api-Version", configuredProviderVersion(m.cfg, source, definition))
		}
	case "gitlab":
		endpoint = firstNonEmpty(os.Getenv("GITLAB_API_URL"), "https://gitlab.com/api/v4") + "/user"
		headers.Set("PRIVATE-TOKEN", os.Getenv("GITLAB_TOKEN"))
	case "fofa":
		endpoint = "https://fofa.info/api/v1/info/my?email=" + url.QueryEscape(os.Getenv("FOFA_EMAIL")) + "&key=" + url.QueryEscape(os.Getenv("FOFA_API_KEY"))
	case "securitytrails":
		endpoint = "https://api.securitytrails.com/v1/ping"
		headers.Set("APIKEY", os.Getenv("SECURITYTRAILS_API_KEY"))
	case "virustotal":
		endpoint = "https://www.virustotal.com/api/v3/users/current"
		headers.Set("x-apikey", os.Getenv("VIRUSTOTAL_API_KEY"))
	case "hunter":
		endpoint = addQuery("https://api.hunter.io/v2/account", "api_key", os.Getenv("HUNTER_API_KEY"))
	case "whoisxml":
		endpoint = addQuery("https://user.whoisxmlapi.com/service/account-balance", "apiKey", os.Getenv("WHOISXML_API_KEY"))
	case "hibp":
		endpoint = "https://haveibeenpwned.com/api/v3/subscribedDomains"
		headers.Set("hibp-api-key", os.Getenv("HIBP_API_KEY"))
		headers.Set("User-Agent", "enumscan-passive-intelligence")
	case "dnsdb":
		endpoint = "https://api.dnsdb.info/dnsdb/v2/rate_limit"
		headers.Set("X-API-Key", os.Getenv("DNSDB_API_KEY"))
		headers.Set("Accept", "application/json")
	case "circl_cve":
		endpoint = "https://cve.circl.lu/api/dbInfo"
	default:
		return m.request(ctx, source, "example.invalid")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint(source, endpoint), nil)
	if err != nil {
		return nil, false
	}
	req.Header = headers
	if source == "censys" {
		req.SetBasicAuth(os.Getenv("CENSYS_API_ID"), os.Getenv("CENSYS_API_SECRET"))
	}
	return req, true
}

func remoteCheckSupported(source string) bool {
	definition, supported := passiveProviderDefinition(source)
	return supported && definition.RemoteProbe
}

func quotaFromHeaders(header http.Header) *int {
	for _, name := range []string{"RateLimit-Remaining", "X-RateLimit-Remaining", "X-Rate-Limit-Remaining"} {
		if value, err := strconv.Atoi(strings.TrimSpace(header.Get(name))); err == nil && value >= 0 {
			return &value
		}
	}
	return nil
}

func boundedDiagnostic(value string) string {
	if len(value) > 160 {
		return value[:160]
	}
	return value
}

// FormatPassiveIntelDoctorText provides stable, credential-safe CLI output.
func FormatPassiveIntelDoctorText(report PassiveIntelDoctorReport) string {
	var out strings.Builder
	if report.PassiveIntelEnabled {
		out.WriteString("Passive intelligence: enabled\n")
	} else {
		out.WriteString("Passive intelligence: disabled\n")
	}
	if len(report.Providers) == 0 {
		out.WriteString("No passive-intelligence sources are configured.\n")
	}
	for _, provider := range report.Providers {
		fmt.Fprintf(&out, "- %s: %s (%s)\n", provider.Source, provider.Status, provider.Mode)
		if len(provider.MissingEnvironment) > 0 {
			fmt.Fprintf(&out, "  missing environment: %s\n", strings.Join(provider.MissingEnvironment, ", "))
		}
		if provider.Note != "" {
			fmt.Fprintf(&out, "  note: %s\n", provider.Note)
		}
		if provider.RemoteStatus != "" {
			fmt.Fprintf(&out, "  remote: %s\n", provider.RemoteStatus)
		}
		if provider.CredentialStatus != "" {
			fmt.Fprintf(&out, "  credential: %s\n", provider.CredentialStatus)
		}
		if provider.APIVersion != "" {
			fmt.Fprintf(&out, "  API contract: %s\n", provider.APIVersion)
		}
		if provider.QuotaRemaining != nil {
			fmt.Fprintf(&out, "  reported quota remaining: %d\n", *provider.QuotaRemaining)
		}
		if provider.Quota != nil {
			if provider.Quota.Limit != nil {
				fmt.Fprintf(&out, "  reported quota limit: %d\n", *provider.Quota.Limit)
			}
			if provider.Quota.Used != nil {
				fmt.Fprintf(&out, "  reported quota used: %d\n", *provider.Quota.Used)
			}
			if provider.Quota.ResetAt != "" {
				fmt.Fprintf(&out, "  reported quota reset: %s\n", provider.Quota.ResetAt)
			}
			if provider.Quota.Resource != "" {
				fmt.Fprintf(&out, "  quota resource: %s\n", provider.Quota.Resource)
			}
		}
		if provider.UpdateStatus != "" {
			fmt.Fprintf(&out, "  update: %s\n", provider.UpdateStatus)
		}
	}
	for _, warning := range report.Warnings {
		fmt.Fprintf(&out, "Warning: %s\n", warning)
	}
	if report.RemoteDiagnosticsRequested {
		out.WriteString("Remote diagnostics were explicitly requested. They report only reachability, rejection, rate limiting, and provider-supplied quota headers; they do not prove account entitlement.\n")
	} else {
		out.WriteString("Doctor is an offline preflight: it does not contact providers, validate credentials, or retrieve quota.\n")
	}
	return out.String()
}
