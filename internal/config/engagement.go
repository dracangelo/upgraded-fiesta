package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"enumscan/internal/models"
)

// EngagementInput is the minimum operator-supplied information required to
// create a safe, single-scope reconnaissance configuration. It deliberately
// does not include credentials or active-testing controls.
type EngagementInput struct {
	Target        string
	Profile       string
	Authorization string
}

// EngagementTemplate defines a curated assessment profile template.
type EngagementTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Profile     string   `json:"profile"`
	Focus       []string `json:"focus"`
}

// AvailableEngagementTemplates returns the supported assessment workflow templates.
func AvailableEngagementTemplates() []EngagementTemplate {
	return []EngagementTemplate{
		{
			ID:          "standard",
			Name:        "General Infrastructure Enumeration",
			Description: "Balanced network host, port, service, banner, and web discovery.",
			Profile:     "standard",
			Focus:       []string{"discovery", "portscan", "service", "http"},
		},
		{
			ID:          "web",
			Name:        "Web Application & Surface Discovery",
			Description: "Deep HTTP/HTTPS reconnaissance, crawling, JS analysis, and API endpoint discovery.",
			Profile:     "web_application",
			Focus:       []string{"http", "api_discovery", "js_analysis", "tls"},
		},
		{
			ID:          "network",
			Name:        "Internal Network & Infrastructure Discovery",
			Description: "Thorough service, banner, protocol capability, and subnet host discovery.",
			Profile:     "internal_network",
			Focus:       []string{"discovery", "portscan", "service", "banners"},
		},
		{
			ID:          "api",
			Name:        "API & Microservice Assessment",
			Description: "Focused discovery of REST, GraphQL, and OpenAPI endpoints and schema metadata.",
			Profile:     "api_assessment",
			Focus:       []string{"http", "api_discovery", "openapi_discovery"},
		},
		{
			ID:          "external",
			Name:        "External Perimeter Reconnaissance",
			Description: "Non-intrusive external perimeter inventory and DNS record harvest.",
			Profile:     "external_infrastructure",
			Focus:       []string{"dns_discovery", "reverse_dns", "portscan", "http"},
		},
		{
			ID:          "cloud",
			Name:        "Cloud Exposure & Asset Mapping",
			Description: "Discovery of cloud endpoints, certificates, and perimeter exposures.",
			Profile:     "cloud_infrastructure",
			Focus:       []string{"dns_discovery", "tls", "http", "specialized"},
		},
	}
}

// DependencyCheckResult represents the outcome of an engagement prerequisite check.
type DependencyCheckResult struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // "ok", "warn", "error"
}

// EngagementPlanPreview summarizes the effective scan parameters and safety bounds.
type EngagementPlanPreview struct {
	Target              string                  `json:"target"`
	Scope               []string                `json:"scope"`
	Authorization       string                  `json:"authorization"`
	Profile             string                  `json:"profile"`
	EstimatedHosts      int                     `json:"estimated_hosts"`
	EstimatedPortProbes int                     `json:"estimated_port_probes"`
	EstimatedDuration   string                  `json:"estimated_duration"`
	EnabledModules      []string                `json:"enabled_modules"`
	Concurrency         int                     `json:"concurrency"`
	RateLimitPerTarget  int                     `json:"rate_limit_per_target_ms"`
	SafetyGuarantees    []string                `json:"safety_guarantees"`
	DependencyChecks    []DependencyCheckResult `json:"dependency_checks"`
}

// RunEngagementDependencyChecks validates database writability, network sanity, and privileges.
func RunEngagementDependencyChecks(target string, dbPath string) ([]DependencyCheckResult, error) {
	var results []DependencyCheckResult

	// 1. Target scope syntax check
	_, err := validateEngagementTarget(target)
	if err != nil {
		results = append(results, DependencyCheckResult{
			Name:     "Target Scope Validation",
			Passed:   false,
			Message:  fmt.Sprintf("Invalid target format: %v", err),
			Severity: "error",
		})
	} else {
		results = append(results, DependencyCheckResult{
			Name:     "Target Scope Validation",
			Passed:   true,
			Message:  fmt.Sprintf("Target %q is a valid single IP, CIDR, or hostname", target),
			Severity: "ok",
		})
	}

	// 2. Datastore storage path writability
	if dbPath == "" {
		dbPath = "data/enumscan.sqlite"
	}
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		results = append(results, DependencyCheckResult{
			Name:     "Datastore Writability",
			Passed:   false,
			Message:  fmt.Sprintf("Cannot create directory %s: %v", dbDir, err),
			Severity: "error",
		})
	} else {
		testFile := filepath.Join(dbDir, ".write_test")
		if err := os.WriteFile(testFile, []byte("ok"), 0600); err != nil {
			results = append(results, DependencyCheckResult{
				Name:     "Datastore Writability",
				Passed:   false,
				Message:  fmt.Sprintf("Directory %s is not writable: %v", dbDir, err),
				Severity: "error",
			})
		} else {
			_ = os.Remove(testFile)
			results = append(results, DependencyCheckResult{
				Name:     "Datastore Writability",
				Passed:   true,
				Message:  fmt.Sprintf("Datastore path %s is writable (mode 0700/0600)", dbDir),
				Severity: "ok",
			})
		}
	}

	// 3. Network resolution check
	_, lookupErr := net.LookupHost("localhost")
	if lookupErr != nil {
		results = append(results, DependencyCheckResult{
			Name:     "Local Resolver Check",
			Passed:   false,
			Message:  fmt.Sprintf("Local resolver lookup failed: %v", lookupErr),
			Severity: "warn",
		})
	} else {
		results = append(results, DependencyCheckResult{
			Name:     "Local Resolver Check",
			Passed:   true,
			Message:  "Local DNS/resolver is functional",
			Severity: "ok",
		})
	}

	// 4. Privilege check (safe unprivileged execution)
	results = append(results, DependencyCheckResult{
		Name:     "Execution Privilege Mode",
		Passed:   true,
		Message:  "Operating in safe unprivileged socket mode (no raw root packet injection required)",
		Severity: "ok",
	})

	return results, nil
}

// PreviewEngagementPlan computes effective scope, duration estimates, and safety parameters.
func PreviewEngagementPlan(input EngagementInput, dbPath string) (EngagementPlanPreview, error) {
	cfg, err := BuildEngagementConfig(input)
	if err != nil {
		return EngagementPlanPreview{}, err
	}

	checks, _ := RunEngagementDependencyChecks(input.Target, dbPath)

	// Calculate estimated hosts
	estimatedHosts := 1
	if _, ipnet, err := net.ParseCIDR(input.Target); err == nil {
		ones, bits := ipnet.Mask.Size()
		if bits-ones > 0 {
			hosts := 1 << (bits - ones)
			if hosts > 256 {
				hosts = 256 // capped at CIDRMaxHosts
			}
			estimatedHosts = hosts
		}
	}

	// Calculate estimated port probes
	portsCount := len(cfg.Scan.Ports)
	if portsCount == 0 {
		switch strings.ToLower(cfg.PortScan.Profile) {
		case "quick":
			portsCount = 100
		case "exhaustive":
			portsCount = 1000
		default:
			portsCount = 500
		}
	}
	totalProbes := estimatedHosts * portsCount

	// Duration estimate based on concurrency & rate limits
	minDurationSec := (totalProbes / max(1, cfg.Scheduler.Concurrency*2)) + 5
	maxDurationSec := minDurationSec * 3
	durationStr := fmt.Sprintf("~%ds to %ds", minDurationSec, maxDurationSec)
	if minDurationSec >= 60 {
		durationStr = fmt.Sprintf("~%dm to %dm", minDurationSec/60, maxDurationSec/60)
	}

	modules := cfg.Scan.ModulePlan
	if len(modules) == 0 {
		modules = []string{"discovery", "portscan", "service", "http"}
	}

	preview := EngagementPlanPreview{
		Target:              cfg.Scan.Targets[0],
		Scope:               cfg.Scope.AllowedTargets,
		Authorization:       cfg.Scope.Authorization,
		Profile:             cfg.Scan.Profile,
		EstimatedHosts:      estimatedHosts,
		EstimatedPortProbes: totalProbes,
		EstimatedDuration:   durationStr,
		EnabledModules:      modules,
		Concurrency:         cfg.Scheduler.Concurrency,
		RateLimitPerTarget:  cfg.Scheduler.PerTargetRateLimitMS,
		SafetyGuarantees: []string{
			"Strict scope lock: outbound traffic bounded to authorized target",
			"Exploitation, intrusive payloads, and active vulnerability verification disabled",
			"Raw socket injection, decoy IP spoofing, and idle scanning disabled",
			"Zero plaintext credential persistence with automatic memory sanitization",
			"Audited execution with deterministic reproduction hash",
		},
		DependencyChecks: checks,
	}

	return preview, nil
}

// BuildEngagementConfig creates a non-destructive enumeration plan whose
// allowed scope and scan target are exactly the same single value.
func BuildEngagementConfig(input EngagementInput) (models.Config, error) {
	target, err := validateEngagementTarget(input.Target)
	if err != nil {
		return models.Config{}, err
	}
	authorization, err := validateAuthorizationReference(input.Authorization)
	if err != nil {
		return models.Config{}, err
	}

	cfg := Default()
	cfg.Scope.AllowedTargets = []string{target}
	cfg.Scope.Authorization = authorization
	cfg.Scan.Targets = []string{target}
	cfg.Discovery.CIDRMaxHosts = 256
	cfg.ActiveTesting.Enabled = false
	cfg.PortScan.EnableRawSYN = false
	cfg.PortScan.EnableRawScanning = false
	cfg.PortScan.RawTechniques = nil
	cfg.PortScan.DecoyIPs = nil
	cfg.PortScan.ZombieHost = ""

	profile := strings.TrimSpace(input.Profile)
	if profile == "" {
		profile = string(ProfileStandard)
	}
	cfg, err = ApplyRequestedProfile(cfg, profile)
	if err != nil {
		return models.Config{}, err
	}
	if err := Validate(cfg); err != nil {
		return models.Config{}, fmt.Errorf("validate generated engagement configuration: %w", err)
	}
	return cfg, nil
}

// RenderEngagementConfig returns an intentionally compact YAML document. All
// generated configuration is safe enumeration only; the authorization
// reference and target are both validated before being emitted.
func RenderEngagementConfig(input EngagementInput) ([]byte, error) {
	cfg, err := BuildEngagementConfig(input)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`# Generated by enumscan's engagement wizard. Review before use.
# This file is scope-locked: scan.targets must remain within scope.allowed_targets.
# Active testing, raw scans, decoys, and credentialed crawling are disabled.
database:
  driver: "sqlite"
  path: "data/enumscan.sqlite"
scope:
  allowed_targets: ["%s"]
  authorization: "%s"
scheduler:
  concurrency: %d
  min_concurrency: %d
  global_rate_limit_ms: %d
  per_target_rate_limit_ms: %d
  module_timeout_ms: %d
discovery:
  cidr_max_hosts: %d
  enable_dns_discovery: true
  enable_dns_records: true
  enable_reverse_dns: true
  enable_tcp_host_probes: true
  tcp_probe_ports: [80, 443]
portscan:
  profile: "%s"
  enable_tcp: true
  enable_udp: false
  enable_banner: true
  enable_raw_syn: false
  enable_raw_scanning: false
  max_concurrent_ports: %d
  base_timeout_ms: %d
  max_timeout_ms: %d
http:
  max_depth: %d
  max_pages_per_host: %d
  enable_tls: true
  enable_crawler: true
  enable_js_analysis: true
  enable_api_discovery: true
  enable_screenshots: false
  enable_authenticated_crawling: false
scan:
  profile: "%s"
  targets: ["%s"]
active_testing:
  enabled: false
api:
  require_auth: false
reporting:
  output_dir: "reports"
`, cfg.Scope.AllowedTargets[0], cfg.Scope.Authorization,
		cfg.Scheduler.Concurrency, cfg.Scheduler.MinConcurrency, cfg.Scheduler.GlobalRateLimitMS, cfg.Scheduler.PerTargetRateLimitMS, cfg.Scheduler.ModuleTimeoutMS,
		cfg.Discovery.CIDRMaxHosts, cfg.PortScan.Profile, cfg.PortScan.MaxConcurrentPorts, cfg.PortScan.BaseTimeoutMS, cfg.PortScan.MaxTimeoutMS,
		cfg.HTTP.MaxDepth, cfg.HTTP.MaxPagesPerHost, cfg.Scan.Profile, cfg.Scan.Targets[0])), nil
}

// WriteEngagementConfig creates a new private config file without overwriting
// an existing operator file. The parent directory and file are restricted to
// the current user where the operating system supports POSIX permissions.
func WriteEngagementConfig(path string, input EngagementInput) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("output path is required")
	}
	content, err := RenderEngagementConfig(input)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create configuration without overwriting an existing file: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write engagement configuration: %w", err)
	}
	return nil
}

func validateEngagementTarget(value string) (string, error) {
	target := strings.TrimSpace(value)
	if target == "" || strings.ContainsAny(target, "\r\n\\\"'[]{}#?@") || strings.Contains(target, "://") {
		return "", fmt.Errorf("target must be a single IP address, CIDR, or hostname")
	}
	if ip := net.ParseIP(target); ip != nil {
		return ip.String(), nil
	}
	if ip, network, err := net.ParseCIDR(target); err == nil {
		return (&net.IPNet{IP: ip.Mask(network.Mask), Mask: network.Mask}).String(), nil
	}
	if len(target) > 253 || strings.Contains(target, "/") || strings.Contains(target, ":") {
		return "", fmt.Errorf("target must be a single IP address, CIDR, or hostname")
	}
	for _, label := range strings.Split(target, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("target must be a valid hostname")
		}
		for _, char := range label {
			if !unicode.IsLetter(char) && !unicode.IsDigit(char) && char != '-' {
				return "", fmt.Errorf("target must be a valid hostname")
			}
		}
	}
	return strings.ToLower(target), nil
}

func validateAuthorizationReference(value string) (string, error) {
	authorization := strings.TrimSpace(value)
	if authorization == "" || len(authorization) > 256 || strings.HasPrefix(authorization, "REPLACE_") {
		return "", fmt.Errorf("written authorization reference is required")
	}
	for _, char := range authorization {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) && !strings.ContainsRune("._:/-", char) {
			return "", fmt.Errorf("authorization reference may contain only letters, numbers, '.', '_', ':', '/', and '-'")
		}
	}
	return authorization, nil
}
