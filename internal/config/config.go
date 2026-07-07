package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"enumscan/internal/models"
)

func Load(path string) (models.Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return models.Config{}, err
	}
	cfg := models.Config{
		Database:  models.DatabaseConfig{Path: "data/enumscan.sqlite"},
		Scheduler: models.SchedulerConfig{Concurrency: 4, GlobalRateLimitMS: 250, PerTargetRateLimitMS: 500, ModuleTimeoutMS: 10000},
		Discovery: models.DiscoveryConfig{CIDRMaxHosts: 256, EnableReverseDNS: true, EnableWildcardDNS: true},
		PortScan:  models.PortScanConfig{Profile: "quick", EnableTCP: true, EnableUDP: false, EnableBanner: true, BaseTimeoutMS: 750, MaxTimeoutMS: 3000},
		HTTP: models.HTTPConfig{
			MaxDepth:           1,
			MaxPagesPerHost:    50,
			EnableTLS:          true,
			EnableCrawler:      true,
			EnableJSAnalysis:   true,
			EnableAPIDiscovery: true,
			EnableScreenshots:  true,
			APIPaths:           []string{"/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/graphql", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "/soap?wsdl"},
		},
		Reporting: models.ReportingConfig{OutputDir: "reports"},
	}

	section := ""
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
	}
	if len(cfg.Scope.AllowedTargets) == 0 {
		return cfg, fmt.Errorf("scope.allowed_targets must contain at least one target")
	}
	if len(cfg.Scan.Targets) == 0 {
		return cfg, fmt.Errorf("scan.targets must contain at least one target")
	}
	return cfg, nil
}

func assign(cfg *models.Config, section, key, value string) error {
	switch section + "." + key {
	case "database.path":
		cfg.Database.Path = value
	case "scope.allowed_targets":
		cfg.Scope.AllowedTargets = parseList(value)
	case "scheduler.concurrency":
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Scheduler.Concurrency = n
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
	case "discovery.passive_dns_files":
		cfg.Discovery.PassiveDNSFiles = parseList(value)
	case "discovery.certificate_transparency_files":
		cfg.Discovery.CertificateTransparencyFiles = parseList(value)
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
	case "http.api_paths":
		cfg.HTTP.APIPaths = parseList(value)
	case "scan.profile":
		cfg.Scan.Profile = value
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
	default:
		return fmt.Errorf("unknown config key %s.%s", section, key)
	}
	return nil
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
