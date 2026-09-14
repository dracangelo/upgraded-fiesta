package config

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"enumscan/internal/models"
)

type EffectiveLimits struct {
	Concurrency           int `json:"concurrency"`
	MinConcurrency        int `json:"min_concurrency"`
	GlobalRateLimitMS     int `json:"global_rate_limit_ms"`
	PerTargetRateLimitMS  int `json:"per_target_rate_limit_ms"`
	ModuleTimeoutMS       int `json:"module_timeout_ms"`
	MaxConcurrentPorts    int `json:"max_concurrent_ports"`
	CIDRMaxHosts          int `json:"cidr_max_hosts"`
	MaxPagesPerHost       int `json:"max_pages_per_host"`
	ActiveRequestsPerHost int `json:"active_requests_per_host,omitempty"`
	ActiveConcurrency     int `json:"active_concurrency,omitempty"`
	ActiveRequestDelayMS  int `json:"active_request_delay_ms,omitempty"`
}

type EffectivePlan struct {
	Valid              bool            `json:"valid"`
	Profile            string          `json:"profile"`
	Targets            []string        `json:"targets"`
	Modules            []string        `json:"modules"`
	Privileges         []string        `json:"required_privileges"`
	Outbound           []string        `json:"outbound_destinations"`
	EnvironmentRefs    []string        `json:"environment_references"`
	MissingEnvironment []string        `json:"missing_environment"`
	ActiveTesting      bool            `json:"active_testing"`
	ActiveTechniques   []string        `json:"active_techniques,omitempty"`
	Limits             EffectiveLimits `json:"limits"`
}

// ResolveEffectivePlan is offline. lookup checks only whether referenced
// variables exist and never returns or retains their values.
func ResolveEffectivePlan(cfg models.Config, lookup func(string) (string, bool)) EffectivePlan {
	plan := EffectivePlan{
		Valid:            true,
		Profile:          cfg.Scan.Profile,
		Targets:          append([]string(nil), cfg.Scan.Targets...),
		Modules:          append([]string(nil), cfg.Scan.ModulePlan...),
		ActiveTesting:    cfg.ActiveTesting.Enabled,
		ActiveTechniques: append([]string(nil), cfg.ActiveTesting.AllowedTechniques...),
		Limits: EffectiveLimits{
			Concurrency: cfg.Scheduler.Concurrency, MinConcurrency: cfg.Scheduler.MinConcurrency,
			GlobalRateLimitMS: cfg.Scheduler.GlobalRateLimitMS, PerTargetRateLimitMS: cfg.Scheduler.PerTargetRateLimitMS,
			ModuleTimeoutMS: cfg.Scheduler.ModuleTimeoutMS, MaxConcurrentPorts: cfg.PortScan.MaxConcurrentPorts,
			CIDRMaxHosts: cfg.Discovery.CIDRMaxHosts, MaxPagesPerHost: cfg.HTTP.MaxPagesPerHost,
		},
	}
	if len(plan.Modules) == 0 {
		plan.Modules = []string{ModuleDiscovery, ModulePortScan, ModuleService, ModuleHTTP, ModuleSpecialized, ModulePassiveIntel}
	}
	if cfg.ActiveTesting.Enabled {
		plan.Limits.ActiveRequestsPerHost = cfg.ActiveTesting.MaxRequestsPerHost
		plan.Limits.ActiveConcurrency = cfg.ActiveTesting.MaxConcurrency
		plan.Limits.ActiveRequestDelayMS = cfg.ActiveTesting.MinimumRequestDelayMS
	}
	if cfg.PortScan.EnableRawScanning || cfg.PortScan.EnableRawSYN || cfg.Discovery.EnableTCPSYNProbes || cfg.Discovery.EnableTCPACKProbes {
		plan.Privileges = append(plan.Privileges, "raw network socket capability or administrator/root")
	}
	if cfg.Discovery.EnableLiveCapture {
		plan.Privileges = append(plan.Privileges, "packet capture interface access")
	}
	if cfg.HTTP.EnableScreenshots {
		plan.Privileges = append(plan.Privileges, "execute configured browser wrapper")
	}
	if cfg.PassiveIntel.Enabled {
		for _, source := range cfg.PassiveIntel.Sources {
			plan.Outbound = append(plan.Outbound, "provider:"+strings.ToLower(strings.TrimSpace(source)))
		}
	}
	for _, raw := range []string{cfg.Neo4j.URI, cfg.Notifications.WebhookURL, cfg.Reporting.LocalLLMURL, cfg.Secrets.Endpoint} {
		if endpoint, err := url.Parse(strings.TrimSpace(raw)); err == nil && endpoint.Host != "" {
			plan.Outbound = append(plan.Outbound, endpoint.Scheme+"://"+endpoint.Host)
		}
	}
	envNames := []string{cfg.Database.EncryptionKeyEnv}
	if strings.EqualFold(cfg.Database.Driver, "postgres") {
		envNames = append(envNames, cfg.Database.PostgresDSNEnv)
	}
	if cfg.Neo4j.URI != "" {
		envNames = append(envNames, cfg.Neo4j.PasswordEnv)
	}
	if cfg.HTTP.EnableAuthenticatedCrawling {
		envNames = append(envNames, cfg.HTTP.AuthCookieEnv)
	}
	if cfg.API.RequireAuth {
		envNames = append(envNames, cfg.API.TokensEnv)
	}
	if cfg.Secrets.Provider != "" {
		envNames = append(envNames, cfg.Secrets.TokenEnv)
	}
	if cfg.ActiveTesting.Enabled {
		envNames = append(envNames, cfg.ActiveTesting.AcknowledgementEnv)
	}
	seen := make(map[string]bool)
	for _, name := range envNames {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		plan.EnvironmentRefs = append(plan.EnvironmentRefs, name)
		if _, ok := lookup(name); !ok {
			plan.MissingEnvironment = append(plan.MissingEnvironment, name)
		}
	}
	sort.Strings(plan.Targets)
	sort.Strings(plan.Modules)
	sort.Strings(plan.Privileges)
	sort.Strings(plan.Outbound)
	sort.Strings(plan.EnvironmentRefs)
	sort.Strings(plan.MissingEnvironment)
	sort.Strings(plan.ActiveTechniques)
	plan.Valid = len(plan.MissingEnvironment) == 0
	return plan
}

func FormatEffectivePlanText(plan EffectivePlan) string {
	join := func(values []string) string {
		if len(values) == 0 {
			return "none"
		}
		return strings.Join(values, ", ")
	}
	return fmt.Sprintf("Configuration valid: %t\nProfile: %s\nTargets: %s\nModules: %s\nRequired privileges: %s\nOutbound destinations: %s\nEnvironment references: %s\nMissing environment: %s\nActive testing: %t\nActive techniques: %s\nLimits: concurrency=%d, global_delay_ms=%d, per_target_delay_ms=%d, module_timeout_ms=%d, max_ports=%d, cidr_hosts=%d, pages_per_host=%d\n",
		plan.Valid, plan.Profile, join(plan.Targets), join(plan.Modules), join(plan.Privileges), join(plan.Outbound),
		join(plan.EnvironmentRefs), join(plan.MissingEnvironment), plan.ActiveTesting, join(plan.ActiveTechniques),
		plan.Limits.Concurrency, plan.Limits.GlobalRateLimitMS, plan.Limits.PerTargetRateLimitMS,
		plan.Limits.ModuleTimeoutMS, plan.Limits.MaxConcurrentPorts, plan.Limits.CIDRMaxHosts, plan.Limits.MaxPagesPerHost)
}
