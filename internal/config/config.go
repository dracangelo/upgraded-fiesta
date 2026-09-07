package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"enumscan/internal/models"
)

func Default() models.Config {
	return models.Config{
		Database:  models.DatabaseConfig{Path: "data/enumscan.sqlite", Driver: "sqlite", PostgresMaxOpenConns: 16, PostgresMaxIdleConns: 4},
		Scheduler: models.SchedulerConfig{Concurrency: 1, MinConcurrency: 1, GlobalRateLimitMS: 500, PerTargetRateLimitMS: 1000, ModuleTimeoutMS: 10000},
		Discovery: models.DiscoveryConfig{
			CIDRMaxHosts:      64,
			TCPProbePorts:     []int{80, 443},
			UDPProbePorts:     []int{53, 123},
			SNMPCommunities:   []string{},
			SNMPProbePorts:    []int{161},
			CaptureInterface:  "any",
			CaptureDurationMS: 1000,
		},
		PortScan: models.PortScanConfig{Profile: "quick", EnableTCP: false, EnableUDP: false, EnableBanner: false, MaxConcurrentPorts: 4, BaseTimeoutMS: 750, MaxTimeoutMS: 3000},
		Scope:    models.ScopeConfig{AllowedTargets: []string{"127.0.0.1", "localhost"}},
		Scan:     models.ScanConfig{Targets: []string{"127.0.0.1"}},
		HTTP: models.HTTPConfig{
			MaxDepth:                1,
			MaxPagesPerHost:         50,
			EnableTLS:               false,
			EnableCrawler:           false,
			EnableJSAnalysis:        false,
			EnableAPIDiscovery:      false,
			EnableScreenshots:       false,
			MaxScreenshotsPerScan:   25,
			APIPaths:                []string{"/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/graphql", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "/soap?wsdl"},
			EnableDirectoryAPI:      false,
			MaxDirectoryPaths:       80,
			EnableSecretIntel:       false,
			EnableWebManifest:       false,
			EnableRedirectTracking:  false,
			EnableMethodEnumeration: false,
			EnableSourceMapAnalysis: false,
		},
		Specialized: models.SpecializedConfig{
			SNMPCommunities: []string{},
		},
		PassiveIntel: models.PassiveIntelConfig{Enabled: false, ProviderMinIntervalMS: 1000, MaxRetryAfterMS: 30000},
		Reporting:    models.ReportingConfig{OutputDir: "reports", LocalLLMTimeoutMS: 30000},
		Monitoring:   models.MonitoringConfig{Enabled: false, IntervalMinutes: 60, MaxRuns: 1},
		API:          models.APIConfig{RequireAuth: false},
		ActiveTesting: models.ActiveTestingConfig{
			MaxRequestsPerHost:    25,
			MaxConcurrency:        1,
			MinimumRequestDelayMS: 500,
		},
	}
}

func Load(path string) (models.Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return models.Config{}, err
	}
	cfg := Default()

	section := ""
	explicit := make(map[string]bool)
	for lineNo, rawLine := range strings.Split(string(raw), "\n") {
		line := stripComment(rawLine)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		text := strings.TrimSpace(line)
		if indent == 0 && strings.HasSuffix(text, ":") {
			section = strings.TrimSuffix(text, ":")
			continue
		}
		if section == "" {
			return cfg, fmt.Errorf("line %d: key outside section", lineNo+1)
		}
		key, value, ok := strings.Cut(text, ":")
		if !ok {
			return cfg, fmt.Errorf("line %d: expected key: value", lineNo+1)
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if err := assign(&cfg, section, key, value); err != nil {
			return cfg, fmt.Errorf("line %d: %w", lineNo+1, err)
		}
		explicit[section+"."+key] = true
	}
	if strings.TrimSpace(cfg.Scan.CustomProfile) != "" {
		profilePath := cfg.Scan.CustomProfile
		if !filepath.IsAbs(profilePath) {
			profilePath = filepath.Join(filepath.Dir(path), profilePath)
		}
		profileBytes, err := os.ReadFile(filepath.Clean(profilePath))
		if err != nil {
			return cfg, fmt.Errorf("load scan.custom_profile: %w", err)
		}
		profile, err := LoadCustomProfileTemplate(profileBytes)
		if err != nil {
			return cfg, fmt.Errorf("load scan.custom_profile: %w", err)
		}
		cfg = applyProfile(cfg, *profile, "custom", explicit)
	} else if strings.TrimSpace(cfg.Scan.Profile) != "" {
		var err error
		cfg, err = ApplyConfiguredProfile(cfg, cfg.Scan.Profile, explicit)
		if err != nil {
			return cfg, err
		}
	}
	if len(cfg.Scope.AllowedTargets) == 0 {
		return cfg, fmt.Errorf("scope.allowed_targets must contain at least one target")
	}
	if len(cfg.Scan.Targets) == 0 {
		return cfg, fmt.Errorf("scan.targets must contain at least one target")
	}
	if strings.TrimSpace(cfg.Scope.Authorization) == "" {
		return cfg, fmt.Errorf("scope.authorization must identify the written authorization for this scan")
	}
	if strings.HasPrefix(cfg.Scope.Authorization, "REPLACE_") || strings.HasPrefix(cfg.Scope.AllowedTargets[0], "REPLACE_") || strings.HasPrefix(cfg.Scan.Targets[0], "REPLACE_") {
		return cfg, fmt.Errorf("replace the production-profile authorization and placeholder targets before use")
	}
	if err := Validate(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate enforces the operating bounds required by both CLI and API scans.
// It is intentionally separate from Load so callers constructing a Config in
// code can apply the same safety checks before running a scan.
func Validate(cfg models.Config) error {
	switch strings.ToLower(strings.TrimSpace(cfg.Database.Driver)) {
	case "", "sqlite":
	case "postgres":
		if strings.TrimSpace(cfg.Database.PostgresDSNEnv) == "" || cfg.Database.PostgresMaxOpenConns < 1 || cfg.Database.PostgresMaxOpenConns > 128 || cfg.Database.PostgresMaxIdleConns < 0 || cfg.Database.PostgresMaxIdleConns > cfg.Database.PostgresMaxOpenConns {
			return fmt.Errorf("database.postgres_dsn_env and valid PostgreSQL pool limits are required when database.driver is postgres")
		}
	default:
		return fmt.Errorf("database.driver must be sqlite or postgres")
	}
	if cfg.Database.EncryptionKeyEnv != "" && cfg.Database.EncryptionKeySecret != "" {
		return fmt.Errorf("configure only one of database.encryption_key_env or database.encryption_key_secret")
	}
	if cfg.Database.EncryptionKeySecret != "" && strings.TrimSpace(cfg.Secrets.Provider) == "" {
		return fmt.Errorf("database.encryption_key_secret requires a configured secrets.provider")
	}
	if strings.TrimSpace(cfg.Scope.Authorization) == "" {
		return fmt.Errorf("scope.authorization must identify the written authorization for this scan")
	}
	if err := validateActiveTesting(cfg.ActiveTesting); err != nil {
		return err
	}
	if cfg.Scheduler.Concurrency < 1 || cfg.Scheduler.Concurrency > 256 {
		return fmt.Errorf("scheduler.concurrency must be between 1 and 256")
	}
	if cfg.Scheduler.MinConcurrency < 1 || cfg.Scheduler.MinConcurrency > cfg.Scheduler.Concurrency {
		return fmt.Errorf("scheduler.min_concurrency must be between 1 and scheduler.concurrency")
	}
	if cfg.Scheduler.GlobalRateLimitMS < 0 || cfg.Scheduler.PerTargetRateLimitMS < 0 || cfg.Scheduler.ModuleTimeoutMS <= 0 {
		return fmt.Errorf("scheduler rate limits must be non-negative and module_timeout_ms must be positive")
	}
	if cfg.PassiveIntel.ProviderMinIntervalMS < 0 || cfg.PassiveIntel.ProviderMinIntervalMS > 60000 || cfg.PassiveIntel.MaxRetryAfterMS < 0 || cfg.PassiveIntel.MaxRetryAfterMS > 300000 {
		return fmt.Errorf("passive_intel provider_min_interval_ms must be 0-60000 and max_retry_after_ms must be 0-300000")
	}
	if err := validateProviderAssignments(cfg.PassiveIntel.ProviderControls, true); err != nil {
		return err
	}
	if err := validateProviderAssignments(cfg.PassiveIntel.ProviderVersions, false); err != nil {
		return err
	}
	if cfg.Monitoring.IntervalMinutes < 5 || cfg.Monitoring.IntervalMinutes > 1440 || cfg.Monitoring.MaxRuns < 1 || cfg.Monitoring.MaxRuns > 1000 {
		return fmt.Errorf("monitoring.interval_minutes must be 5-1440 and monitoring.max_runs must be 1-1000")
	}
	if cfg.API.RequireAuth && strings.TrimSpace(cfg.API.TokensEnv) == "" {
		return fmt.Errorf("api.tokens_env is required when api.require_auth is enabled")
	}
	if cfg.Reporting.LocalLLMURL != "" {
		endpoint, err := url.Parse(cfg.Reporting.LocalLLMURL)
		if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() == "" || !localLLMHost(endpoint.Hostname()) {
			return fmt.Errorf("reporting.local_llm_url must be an HTTP loopback endpoint")
		}
		if strings.TrimSpace(cfg.Reporting.LocalLLMModel) == "" || cfg.Reporting.LocalLLMTimeoutMS < 1000 || cfg.Reporting.LocalLLMTimeoutMS > 120000 {
			return fmt.Errorf("reporting.local_llm_model is required and local_llm_timeout_ms must be 1000-120000 when local_llm_url is set")
		}
	}
	if cfg.Neo4j.URI != "" {
		endpoint, err := url.Parse(cfg.Neo4j.URI)
		if err != nil || endpoint.Hostname() == "" || (endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && localLLMHost(endpoint.Hostname()))) {
			return fmt.Errorf("neo4j.uri must use HTTPS (HTTP is allowed only for a loopback endpoint)")
		}
		if strings.TrimSpace(cfg.Neo4j.Username) == "" || strings.TrimSpace(cfg.Neo4j.PasswordEnv) == "" {
			return fmt.Errorf("neo4j.username and neo4j.password_env are required when neo4j.uri is set")
		}
	}
	if cfg.Notifications.EnableScanCompletedWebhook && strings.TrimSpace(cfg.Notifications.WebhookURL) == "" {
		return fmt.Errorf("notifications.webhook_url is required when scan-completed webhook delivery is enabled")
	}
	if cfg.Notifications.EnableScanCompletedWebhook {
		endpoint, err := url.Parse(cfg.Notifications.WebhookURL)
		if err != nil || endpoint.Hostname() == "" || (endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && localLLMHost(endpoint.Hostname()))) {
			return fmt.Errorf("notifications.webhook_url must use HTTPS (HTTP is allowed only for a loopback endpoint)")
		}
	}
	if cfg.PortScan.MaxConcurrentPorts < 1 || cfg.PortScan.MaxConcurrentPorts > 1024 {
		return fmt.Errorf("portscan.max_concurrent_ports must be between 1 and 1024")
	}
	if cfg.PortScan.BaseTimeoutMS <= 0 || cfg.PortScan.MaxTimeoutMS < cfg.PortScan.BaseTimeoutMS {
		return fmt.Errorf("portscan timeouts must be positive and max_timeout_ms must not be below base_timeout_ms")
	}
	for _, ports := range [][]int{cfg.Scan.Ports, cfg.PortScan.TCPPorts, cfg.PortScan.UDPPorts, cfg.Discovery.TCPProbePorts, cfg.Discovery.UDPProbePorts, cfg.Discovery.SNMPProbePorts} {
		for _, port := range ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("port %d is outside the valid range 1-65535", port)
			}
		}
	}
	if len(cfg.PortScan.DecoyIPs) > 0 || strings.TrimSpace(cfg.PortScan.ZombieHost) != "" {
		return fmt.Errorf("decoy and idle scan settings are not supported in authorized-enumeration mode")
	}
	for _, technique := range cfg.PortScan.RawTechniques {
		switch strings.ToUpper(strings.TrimSpace(technique)) {
		case "DECOY", "IDLE":
			return fmt.Errorf("raw technique %q is not supported in authorized-enumeration mode", technique)
		}
	}
	if cfg.HTTP.EnableScreenshots {
		if !filepath.IsAbs(cfg.HTTP.ScreenshotRenderer) || !filepath.IsAbs(cfg.HTTP.ScreenshotOutputDir) {
			return fmt.Errorf("http screenshot renderer and output directory must be absolute paths when screenshots are enabled")
		}
		if cfg.HTTP.MaxScreenshotsPerScan < 1 || cfg.HTTP.MaxScreenshotsPerScan > 1000 {
			return fmt.Errorf("http.max_screenshots_per_scan must be between 1 and 1000 when screenshots are enabled")
		}
		urlArg, outputArg := false, false
		for _, arg := range cfg.HTTP.ScreenshotRendererArgs {
			urlArg = urlArg || strings.Contains(arg, "{url}")
			outputArg = outputArg || strings.Contains(arg, "{output}")
		}
		if !urlArg || !outputArg {
			return fmt.Errorf("http.screenshot_renderer_args must contain both {url} and {output} when screenshots are enabled")
		}
	}
	if cfg.HTTP.EnableAuthenticatedCrawling && strings.TrimSpace(cfg.HTTP.AuthCookieEnv) == "" {
		return fmt.Errorf("http.auth_cookie_env is required when authenticated crawling is enabled")
	}
	return nil
}

const activeTestingAcknowledgement = "I_ACKNOWLEDGE_ACTIVE_TESTING_IS_AUTHORIZED"

var activeTestingTechniques = map[string]bool{
	"idle_scan": true, "decoy_scan": true,
	"tls_heartbleed": true, "tls_robot": true, "tls_crime": true, "tls_breach": true,
	"web_sqli": true, "web_xss": true, "web_ssrf": true, "web_lfi_rfi": true,
	"web_xxe": true, "web_ssti": true, "web_host_header": true,
	"web_request_smuggling": true, "web_prototype_pollution": true,
	"oob_interaction": true, "ssh_credentialed": true, "winrm_credentialed": true,
	"active_directory_authenticated": true, "kerberos_roast_discovery": true,
	"kerberos_asrep": true, "laps_acl_audit": true, "smb_permission_audit": true,
	"ssh_auth_audit": true, "ftp_write_audit": true, "smtp_relay_audit": true,
	"snmp_mib_walk": true, "kubernetes_secret_audit": true,
	"docker_compose_audit": true, "cloud_imds_audit": true, "dns_axfr": true,
	"dnssec_zone_walk": true, "dns_cache_snoop": true,
}

func validateActiveTesting(cfg models.ActiveTestingConfig) error {
	if !cfg.Enabled {
		if len(cfg.AllowedTechniques) > 0 {
			return fmt.Errorf("active_testing.allowed_techniques requires active_testing.enabled")
		}
		return nil
	}
	if strings.TrimSpace(cfg.Operator) == "" || strings.TrimSpace(cfg.AcknowledgementEnv) == "" {
		return fmt.Errorf("active_testing.operator and acknowledgement_env are required when active testing is enabled")
	}
	expires, err := time.Parse(time.RFC3339, strings.TrimSpace(cfg.AuthorizationExpires))
	if err != nil || !expires.After(time.Now().UTC()) {
		return fmt.Errorf("active_testing.authorization_expires must be a future RFC3339 timestamp")
	}
	if os.Getenv(cfg.AcknowledgementEnv) != activeTestingAcknowledgement {
		return fmt.Errorf("active testing requires %s=%s", cfg.AcknowledgementEnv, activeTestingAcknowledgement)
	}
	if len(cfg.AllowedTechniques) == 0 {
		return fmt.Errorf("active_testing.allowed_techniques must explicitly name at least one technique")
	}
	seen := make(map[string]bool)
	for _, value := range cfg.AllowedTechniques {
		name := strings.ToLower(strings.TrimSpace(value))
		if !activeTestingTechniques[name] {
			return fmt.Errorf("unknown active testing technique %q", value)
		}
		if seen[name] {
			return fmt.Errorf("duplicate active testing technique %q", value)
		}
		seen[name] = true
	}
	if cfg.MaxRequestsPerHost < 1 || cfg.MaxRequestsPerHost > 1000 {
		return fmt.Errorf("active_testing.max_requests_per_host must be between 1 and 1000")
	}
	if cfg.MaxConcurrency < 1 || cfg.MaxConcurrency > 16 {
		return fmt.Errorf("active_testing.max_concurrency must be between 1 and 16")
	}
	if cfg.MinimumRequestDelayMS < 50 || cfg.MinimumRequestDelayMS > 60000 {
		return fmt.Errorf("active_testing.minimum_request_delay_ms must be between 50 and 60000")
	}
	return nil
}

func validateProviderAssignments(values []string, boolean bool) error {
	seen := make(map[string]bool)
	for _, item := range values {
		name, value, ok := strings.Cut(strings.TrimSpace(item), "=")
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if !ok || name == "" || value == "" || seen[name] {
			return fmt.Errorf("passive_intel provider assignments must be unique name=value entries")
		}
		if boolean {
			if _, err := strconv.ParseBool(value); err != nil {
				return fmt.Errorf("passive_intel provider control %q must be true or false", item)
			}
		}
		seen[name] = true
	}
	return nil
}

func assign(cfg *models.Config, section, key, value string) error {
	switch section + "." + key {
	case "database.path":
		cfg.Database.Path = value
	case "database.driver":
		cfg.Database.Driver = strings.ToLower(value)
	case "database.postgres_dsn_env":
		cfg.Database.PostgresDSNEnv = value
	case "database.encryption_key_env":
		cfg.Database.EncryptionKeyEnv = value
	case "database.encryption_key_secret":
		cfg.Database.EncryptionKeySecret = value
	case "database.postgres_max_open_conns":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Database.PostgresMaxOpenConns = n
	case "database.postgres_max_idle_conns":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Database.PostgresMaxIdleConns = n
	case "neo4j.uri":
		cfg.Neo4j.URI = value
	case "neo4j.username":
		cfg.Neo4j.Username = value
	case "neo4j.password_env":
		cfg.Neo4j.PasswordEnv = value
	case "scope.allowed_targets":
		cfg.Scope.AllowedTargets = parseList(value)
	case "scope.authorization":
		cfg.Scope.Authorization = value
	case "active_testing.enabled":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.ActiveTesting.Enabled = enabled
	case "active_testing.authorization_expires":
		cfg.ActiveTesting.AuthorizationExpires = value
	case "active_testing.operator":
		cfg.ActiveTesting.Operator = value
	case "active_testing.acknowledgement_env":
		cfg.ActiveTesting.AcknowledgementEnv = value
	case "active_testing.allowed_techniques":
		cfg.ActiveTesting.AllowedTechniques = parseList(value)
	case "active_testing.max_requests_per_host":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.ActiveTesting.MaxRequestsPerHost = n
	case "active_testing.max_concurrency":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.ActiveTesting.MaxConcurrency = n
	case "active_testing.minimum_request_delay_ms":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.ActiveTesting.MinimumRequestDelayMS = n
	case "scheduler.concurrency":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Scheduler.Concurrency = n
	case "scheduler.enable_adaptive_workers":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Scheduler.EnableAdaptiveWorkers = enabled
	case "scheduler.min_concurrency":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Scheduler.MinConcurrency = n
	case "scheduler.rate_limit_ms", "scheduler.global_rate_limit_ms":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Scheduler.GlobalRateLimitMS = n
	case "scheduler.per_target_rate_limit_ms":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Scheduler.PerTargetRateLimitMS = n
	case "scheduler.module_timeout_ms":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Scheduler.ModuleTimeoutMS = n
	case "discovery.cidr_max_hosts":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Discovery.CIDRMaxHosts = n
	case "discovery.enable_dns_discovery":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableDNSDiscovery = enabled
	case "discovery.enable_dns_records":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableDNSRecords = enabled
	case "discovery.enable_reverse_dns":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableReverseDNS = enabled
	case "discovery.enable_wildcard_dns":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableWildcardDNS = enabled
	case "discovery.enable_rdap":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableRDAP = enabled
	case "discovery.enable_icmp_sweep":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableICMPSweep = enabled
	case "discovery.enable_tcp_host_probes":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableTCPHostProbes = enabled
	case "discovery.tcp_probe_ports":
		ports, err := parseInts(value)
		if err != nil {
			return err
		}
		cfg.Discovery.TCPProbePorts = ports
	case "discovery.enable_udp_live_probes":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableUDPLiveProbes = enabled
	case "discovery.udp_probe_ports":
		ports, err := parseInts(value)
		if err != nil {
			return err
		}
		cfg.Discovery.UDPProbePorts = ports
	case "discovery.enable_tcp_syn_probes":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableTCPSYNProbes = enabled
	case "discovery.enable_tcp_ack_probes":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableTCPACKProbes = enabled
	case "discovery.enable_snmp_probes":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableSNMPProbes = enabled
	case "discovery.snmp_communities":
		cfg.Discovery.SNMPCommunities = parseList(value)
	case "discovery.snmp_probe_ports":
		ports, err := parseInts(value)
		if err != nil {
			return err
		}
		cfg.Discovery.SNMPProbePorts = ports
	case "discovery.enable_live_capture":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Discovery.EnableLiveCapture = enabled
	case "discovery.capture_interface":
		cfg.Discovery.CaptureInterface = value
	case "discovery.capture_duration_ms":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Discovery.CaptureDurationMS = n
	case "discovery.passive_dns_files":
		cfg.Discovery.PassiveDNSFiles = parseList(value)
	case "discovery.certificate_transparency_files":
		cfg.Discovery.CertificateTransparencyFiles = parseList(value)
	case "discovery.passive_capture_files":
		cfg.Discovery.PassiveCaptureFiles = parseList(value)
	case "discovery.historical_url_files":
		cfg.Discovery.HistoricalURLFiles = parseList(value)
	case "portscan.profile":
		cfg.PortScan.Profile = value
	case "portscan.tcp_ports":
		ports, err := parseInts(value)
		if err != nil {
			return err
		}
		cfg.PortScan.TCPPorts = ports
	case "portscan.udp_ports":
		ports, err := parseInts(value)
		if err != nil {
			return err
		}
		cfg.PortScan.UDPPorts = ports
	case "portscan.enable_tcp":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.PortScan.EnableTCP = enabled
	case "portscan.enable_udp":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.PortScan.EnableUDP = enabled
	case "portscan.enable_banner":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.PortScan.EnableBanner = enabled
	case "portscan.enable_raw_syn":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.PortScan.EnableRawSYN = enabled
	case "portscan.enable_raw_scanning":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.PortScan.EnableRawScanning = enabled
	case "portscan.raw_techniques":
		cfg.PortScan.RawTechniques = parseList(value)
	case "portscan.decoy_ips":
		cfg.PortScan.DecoyIPs = parseList(value)
	case "portscan.zombie_host":
		cfg.PortScan.ZombieHost = value
	case "portscan.enable_two_phase_sweep":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.PortScan.EnableTwoPhaseSweep = enabled
	case "portscan.max_concurrent_ports":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.PortScan.MaxConcurrentPorts = n
	case "portscan.record_closed_ports":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.PortScan.RecordClosedPorts = enabled
	case "portscan.base_timeout_ms":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.PortScan.BaseTimeoutMS = n
	case "portscan.max_timeout_ms":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.PortScan.MaxTimeoutMS = n
	case "http.max_depth":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.HTTP.MaxDepth = n
	case "http.max_pages_per_host":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.HTTP.MaxPagesPerHost = n
	case "http.enable_tls":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableTLS = enabled
	case "http.enable_crawler":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableCrawler = enabled
	case "http.enable_js_analysis":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableJSAnalysis = enabled
	case "http.enable_api_discovery":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableAPIDiscovery = enabled
	case "http.enable_screenshots":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableScreenshots = enabled
	case "http.screenshot_renderer":
		cfg.HTTP.ScreenshotRenderer = value
	case "http.screenshot_renderer_args":
		cfg.HTTP.ScreenshotRendererArgs = parseList(value)
	case "http.screenshot_output_dir":
		cfg.HTTP.ScreenshotOutputDir = value
	case "http.max_screenshots_per_scan":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.HTTP.MaxScreenshotsPerScan = n
	case "http.api_paths":
		cfg.HTTP.APIPaths = parseList(value)
	case "http.enable_directory_api":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableDirectoryAPI = enabled
	case "http.directory_wordlist":
		cfg.HTTP.DirectoryWordlist = parseList(value)
	case "http.max_directory_paths":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.HTTP.MaxDirectoryPaths = n
	case "http.enable_secret_intelligence":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableSecretIntel = enabled
	case "http.enable_web_manifest":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableWebManifest = enabled
	case "http.enable_redirect_tracking":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableRedirectTracking = enabled
	case "http.enable_method_enumeration":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableMethodEnumeration = enabled
	case "http.enable_source_map_analysis":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableSourceMapAnalysis = enabled
	case "http.wappalyzer_rule_files":
		cfg.HTTP.WappalyzerRuleFiles = parseList(value)
	case "http.enable_cookie_jar":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableCookieJar = enabled
	case "http.enable_authenticated_crawling":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableAuthenticatedCrawling = enabled
	case "http.auth_cookie_env":
		cfg.HTTP.AuthCookieEnv = value
	case "http.enable_http3":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableHTTP3 = enabled
	case "http.enable_grpc_reflection":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.HTTP.EnableGRPCReflection = enabled
	case "http.grpc_reflection_ports":
		ports, err := parseInts(value)
		if err != nil {
			return err
		}
		cfg.HTTP.GRPCReflectionPorts = ports
	case "specialized.enable_smb":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Specialized.EnableSMB = enabled
	case "specialized.enable_ldap":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Specialized.EnableLDAP = enabled
	case "specialized.enable_snmp":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Specialized.EnableSNMP = enabled
	case "specialized.enable_cloud":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Specialized.EnableCloud = enabled
	case "specialized.enable_container":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Specialized.EnableContainer = enabled
	case "specialized.enable_database":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Specialized.EnableDatabase = enabled
	case "specialized.enable_protocol_enumeration":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Specialized.EnableProtocolEnumeration = enabled
	case "specialized.snmp_communities":
		cfg.Specialized.SNMPCommunities = parseList(value)
	case "passive_intel.enabled":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.PassiveIntel.Enabled = enabled
	case "passive_intel.sources":
		cfg.PassiveIntel.Sources = parseList(value)
	case "passive_intel.provider_controls":
		cfg.PassiveIntel.ProviderControls = parseList(value)
	case "passive_intel.provider_versions":
		cfg.PassiveIntel.ProviderVersions = parseList(value)
	case "passive_intel.enable_quota_discovery":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.PassiveIntel.EnableQuotaDiscovery = enabled
	case "passive_intel.enable_update_checks":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.PassiveIntel.EnableUpdateChecks = enabled
	case "passive_intel.provider_min_interval_ms":
		interval, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.PassiveIntel.ProviderMinIntervalMS = interval
	case "passive_intel.max_retry_after_ms":
		delay, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.PassiveIntel.MaxRetryAfterMS = delay
	case "scan.profile":
		cfg.Scan.Profile = value
	case "scan.custom_profile":
		cfg.Scan.CustomProfile = value
	case "scan.targets":
		cfg.Scan.Targets = parseList(value)
	case "scan.ports":
		ports, err := parseInts(value)
		if err != nil {
			return err
		}
		cfg.Scan.Ports = ports
	case "reporting.output_dir":
		cfg.Reporting.OutputDir = value
	case "reporting.local_llm_url":
		cfg.Reporting.LocalLLMURL = value
	case "reporting.local_llm_model":
		cfg.Reporting.LocalLLMModel = value
	case "reporting.local_llm_timeout_ms":
		timeout, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Reporting.LocalLLMTimeoutMS = timeout
	case "notifications.enable_scan_completed_webhook":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Notifications.EnableScanCompletedWebhook = enabled
	case "notifications.webhook_url":
		cfg.Notifications.WebhookURL = value
	case "monitoring.enabled":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.Monitoring.Enabled = enabled
	case "monitoring.interval_minutes":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Monitoring.IntervalMinutes = n
	case "monitoring.max_runs":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Monitoring.MaxRuns = n
	case "api.require_auth":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		cfg.API.RequireAuth = enabled
	case "api.tokens_env":
		cfg.API.TokensEnv = value
	case "secrets.provider":
		cfg.Secrets.Provider = value
	case "secrets.endpoint":
		cfg.Secrets.Endpoint = value
	case "secrets.token_env":
		cfg.Secrets.TokenEnv = value
	case "secrets.token_file":
		cfg.Secrets.TokenFile = value
	case "secrets.namespace":
		cfg.Secrets.Namespace = value
	case "secrets.project":
		cfg.Secrets.Project = value
	case "secrets.region":
		cfg.Secrets.Region = value
	case "secrets.mount":
		cfg.Secrets.Mount = value
	case "secrets.service":
		cfg.Secrets.Service = value
	default:
		return fmt.Errorf("unknown config key %s.%s", section, key)
	}
	return nil
}

func localLLMHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseList(value string) []string {
	value = strings.Trim(value, "[]")
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.Trim(strings.TrimSpace(part), `"`))
	}
	return out
}

func parseInts(value string) ([]int, error) {
	parts := parseList(value)
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func stripComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return line[:idx]
	}
	return line
}
