package config

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"enumscan/internal/models"
)

const (
	ModuleDiscovery    = "discovery"
	ModulePortScan     = "portscan"
	ModuleService      = "service"
	ModuleHTTP         = "http"
	ModuleSpecialized  = "specialized"
	ModulePassiveIntel = "passive_intel"
)

type ProfileType string

const (
	ProfileQuick                  ProfileType = "quick"
	ProfileStandard               ProfileType = "standard"
	ProfileExhaustive             ProfileType = "exhaustive"
	ProfileExternalInfrastructure ProfileType = "external_infrastructure"
	ProfileInternalNetwork        ProfileType = "internal_network"
	ProfileWebApplication         ProfileType = "web_application"
	ProfileAPIAssessment          ProfileType = "api_assessment"
	ProfileActiveDirectory        ProfileType = "active_directory"
	ProfileKubernetes             ProfileType = "kubernetes"
	ProfileCloudInfrastructure    ProfileType = "cloud_infrastructure"
	ProfileBugBounty              ProfileType = "bug_bounty"
	ProfileCompliance             ProfileType = "compliance"
)

type ScanProfile struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Modules     []string `json:"modules"`
	Ports       []int    `json:"ports"`
	Concurrency int      `json:"concurrency"`
	TimeoutSec  int      `json:"timeout_sec"`
}

// ApplyRequestedProfile applies a named built-in profile to a scan that was
// explicitly requested by an operator (for example through the dashboard).
// It deliberately replaces port and scheduler defaults so the selected
// profile has an observable effect. File-based configuration retains explicit
// port and scheduler values; those are the operator's more specific choices.
func ApplyRequestedProfile(cfg models.Config, name string) (models.Config, error) {
	key := ProfileType(normalizeProfileName(name))
	profile, ok := GetBuiltinProfiles()[key]
	if !ok {
		return cfg, fmt.Errorf("unknown scan profile %q", name)
	}

	cfg = applyProfile(cfg, profile, string(key), nil)
	cfg.Scan.Ports = nil
	cfg.PortScan.UDPPorts = nil
	cfg.PortScan.EnableUDP = false
	cfg.PortScan.EnableRawSYN = false
	cfg.PortScan.EnableRawScanning = false
	cfg.PortScan.RawTechniques = nil
	cfg.PortScan.DecoyIPs = nil
	cfg.PortScan.ZombieHost = ""
	return cfg, nil
}

// ApplyConfiguredProfile applies profile defaults to file-based configuration.
// Values the operator explicitly supplied in the YAML file win over profile
// defaults. The resulting ModulePlan is consumed by the engine.
func ApplyConfiguredProfile(cfg models.Config, name string, explicit map[string]bool) (models.Config, error) {
	key := ProfileType(normalizeProfileName(name))
	profile, ok := GetBuiltinProfiles()[key]
	if !ok {
		return cfg, fmt.Errorf("unknown scan profile %q", name)
	}
	return applyProfile(cfg, profile, string(key), explicit), nil
}

// ApplyEngineProfile provides the same profile behavior for callers that
// construct a Config in code instead of loading YAML. Loaded configurations
// are already marked as applied, so their explicit overrides are preserved.
func ApplyEngineProfile(cfg models.Config) (models.Config, error) {
	if cfg.Scan.ProfileApplied || strings.TrimSpace(cfg.Scan.Profile) == "" {
		return cfg, nil
	}
	return ApplyConfiguredProfile(cfg, cfg.Scan.Profile, nil)
}

func applyProfile(cfg models.Config, profile ScanProfile, profileName string, explicit map[string]bool) models.Config {
	wasExplicit := func(key string) bool { return explicit != nil && explicit[key] }
	cfg.Scan.Profile = profileName
	cfg.Scan.ModulePlan = mergeModulePlan(profile.Modules, explicit)
	cfg.Scan.ProfileApplied = true

	if !wasExplicit("portscan.profile") {
		cfg.PortScan.Profile = profileName
	}
	if !wasExplicit("scheduler.concurrency") && profile.Concurrency > 0 {
		cfg.Scheduler.Concurrency = profile.Concurrency
	}
	if !wasExplicit("scheduler.module_timeout_ms") && profile.TimeoutSec > 0 {
		cfg.Scheduler.ModuleTimeoutMS = profile.TimeoutSec * 1000
	}
	if !wasExplicit("portscan.tcp_ports") && !wasExplicit("scan.ports") {
		if profileName == string(ProfileExhaustive) {
			// The port scanner expands this lazily into the valid port range.
			cfg.PortScan.TCPPorts = nil
		} else {
			cfg.PortScan.TCPPorts = append([]int(nil), profile.Ports...)
		}
	}
	if !wasExplicit("portscan.enable_tcp") {
		cfg.PortScan.EnableTCP = true
	}
	return cfg
}

func mergeModulePlan(profileModules []string, explicit map[string]bool) []string {
	set := make(map[string]bool, len(profileModules)+4)
	for _, module := range profileModules {
		if normalized := normalizeModuleName(module); normalized != "" {
			set[normalized] = true
		}
	}
	for key := range explicit {
		switch {
		case strings.HasPrefix(key, "discovery."):
			set[ModuleDiscovery] = true
		case strings.HasPrefix(key, "portscan.") || key == "scan.ports":
			set[ModulePortScan] = true
		case strings.HasPrefix(key, "http."):
			set[ModuleHTTP] = true
		case strings.HasPrefix(key, "specialized."):
			set[ModuleSpecialized] = true
		case strings.HasPrefix(key, "passive_intel."):
			set[ModulePassiveIntel] = true
		}
	}
	plan := make([]string, 0, len(set))
	for _, module := range []string{ModuleDiscovery, ModulePortScan, ModuleService, ModuleHTTP, ModuleSpecialized, ModulePassiveIntel} {
		if set[module] {
			plan = append(plan, module)
		}
	}
	return plan
}

func normalizeModuleName(module string) string {
	switch normalizeProfileName(module) {
	case "discovery", "dns", "icmp_sweep":
		return ModuleDiscovery
	case "portscan", "port_scan":
		return ModulePortScan
	case "service", "service_fingerprint":
		return ModuleService
	case "http", "wappalyzer", "dir_fuzzing", "directory_api", "web_vuln_engine", "container_checks", "cis_compliance":
		return ModuleHTTP
	case "specialized", "smb", "ldap", "kerberos", "bloodhound":
		return ModuleSpecialized
	case "passive_intel", "wayback", "secret_intel":
		return ModulePassiveIntel
	default:
		return ""
	}
}

// ModuleEnabled reports whether a profile-derived plan permits a module
// family. Configurations without a selected profile retain the legacy behavior
// of enabling all registered safe module families.
func ModuleEnabled(cfg models.Config, module string) bool {
	if len(cfg.Scan.ModulePlan) == 0 {
		return true
	}
	module = normalizeModuleName(module)
	for _, planned := range cfg.Scan.ModulePlan {
		if planned == module {
			return true
		}
	}
	return false
}

func normalizeProfileName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.NewReplacer("-", "_", " ", "_").Replace(name)
	switch name {
	case "web":
		return string(ProfileWebApplication)
	case "network", "internal":
		return string(ProfileInternalNetwork)
	case "api", "api_assessment":
		return string(ProfileAPIAssessment)
	case "external", "perimeter":
		return string(ProfileExternalInfrastructure)
	case "cloud":
		return string(ProfileCloudInfrastructure)
	case "ad":
		return string(ProfileActiveDirectory)
	case "k8s":
		return string(ProfileKubernetes)
	}
	return name
}

func GetBuiltinProfiles() map[ProfileType]ScanProfile {
	return map[ProfileType]ScanProfile{
		ProfileQuick: {
			Name:        "Quick",
			Description: "Fast surface discovery scan",
			Modules:     []string{"discovery", "portscan"},
			Ports:       []int{80, 443, 22, 8080},
			Concurrency: 50,
			TimeoutSec:  30,
		},
		ProfileStandard: {
			Name:        "Standard",
			Description: "Standard reconnaissance and service fingerprinting",
			Modules:     []string{"discovery", "portscan", "service_fingerprint", "http"},
			Ports:       []int{80, 443, 22, 21, 25, 8080, 8443},
			Concurrency: 20,
			TimeoutSec:  60,
		},
		ProfileExhaustive: {
			Name:        "Exhaustive",
			Description: "Deep authorized enumeration across all TCP ports and safe fingerprinting modules",
			Modules:     []string{"discovery", "portscan", "service", "specialized", "http", "passive_intel"},
			Ports:       []int{1, 65535},
			Concurrency: 10,
			TimeoutSec:  300,
		},
		ProfileExternalInfrastructure: {
			Name:        "External Infrastructure",
			Description: "External perimeter discovery, DNS enrichment, and web/service enumeration",
			Modules:     []string{"discovery", "portscan", "service", "http", "passive_intel"},
			Ports:       []int{80, 443, 53, 8080, 8443},
			Concurrency: 25,
			TimeoutSec:  120,
		},
		ProfileInternalNetwork: {
			Name:        "Internal Network",
			Description: "Internal subnet discovery and safe service enumeration",
			Modules:     []string{"discovery", "portscan", "service", "specialized"},
			Ports:       []int{139, 445, 389, 636, 88},
			Concurrency: 30,
			TimeoutSec:  90,
		},
		ProfileWebApplication: {
			Name:        "Web Application",
			Description: "Web technology stack, directory fuzzing, and CORS/CSRF heuristic analysis",
			Modules:     []string{"discovery", "portscan", "service", "http"},
			Ports:       []int{80, 443, 8000, 8080, 8443},
			Concurrency: 15,
			TimeoutSec:  180,
		},
		ProfileAPIAssessment: {
			Name:        "API Assessment",
			Description: "REST/GraphQL API endpoint harvesting and CORS testing",
			Modules:     []string{"discovery", "portscan", "service", "http"},
			Ports:       []int{80, 443, 3000, 5000, 8080},
			Concurrency: 20,
			TimeoutSec:  120,
		},
		ProfileActiveDirectory: {
			Name:        "Active Directory",
			Description: "Directory-service endpoint discovery and unauthenticated service fingerprinting",
			Modules:     []string{"discovery", "portscan", "service", "specialized"},
			Ports:       []int{88, 389, 636, 3268},
			Concurrency: 10,
			TimeoutSec:  180,
		},
		ProfileKubernetes: {
			Name:        "Kubernetes",
			Description: "Kubernetes endpoint and web/service metadata enumeration",
			Modules:     []string{"discovery", "portscan", "service", "http", "specialized"},
			Ports:       []int{6443, 10250, 10255},
			Concurrency: 15,
			TimeoutSec:  60,
		},
		ProfileCloudInfrastructure: {
			Name:        "Cloud Infrastructure",
			Description: "Cloud-facing endpoint, TLS, and passive-intelligence enumeration",
			Modules:     []string{"discovery", "portscan", "service", "http", "passive_intel"},
			Ports:       []int{80, 443},
			Concurrency: 20,
			TimeoutSec:  60,
		},
		ProfileBugBounty: {
			Name:        "Bug Bounty",
			Description: "Authorized external surface enumeration with optional passive intelligence",
			Modules:     []string{"discovery", "portscan", "service", "http", "passive_intel"},
			Ports:       []int{80, 443},
			Concurrency: 30,
			TimeoutSec:  240,
		},
		ProfileCompliance: {
			Name:        "Compliance",
			Description: "CIS benchmarks and web header security hardening audit",
			Modules:     []string{"discovery", "portscan", "service", "http"},
			Ports:       []int{80, 443},
			Concurrency: 10,
			TimeoutSec:  60,
		},
	}
}

func LoadCustomProfileTemplate(yamlContent []byte) (*ScanProfile, error) {
	scanner := bufio.NewScanner(bytes.NewReader(yamlContent))
	var profile ScanProfile
	currentList := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "- ") {
			item := strings.TrimSpace(line[2:])
			if currentList == "modules" {
				profile.Modules = append(profile.Modules, item)
			} else if currentList == "ports" {
				if val, err := strconv.Atoi(item); err == nil {
					profile.Ports = append(profile.Ports, val)
				}
			}
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "name":
			profile.Name = strings.Trim(val, `"'`)
		case "description":
			profile.Description = strings.Trim(val, `"'`)
		case "modules":
			currentList = "modules"
		case "ports":
			currentList = "ports"
		case "concurrency":
			if c, err := strconv.Atoi(val); err == nil {
				profile.Concurrency = c
			}
		case "timeout_sec":
			if t, err := strconv.Atoi(val); err == nil {
				profile.TimeoutSec = t
			}
		}
	}

	if strings.TrimSpace(profile.Name) == "" {
		return nil, fmt.Errorf("profile template name cannot be empty")
	}
	return &profile, nil
}
