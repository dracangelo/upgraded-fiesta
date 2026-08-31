package config

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
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
			Description: "Deep exhaustive scan covering all ports and specialized modules",
			Modules:     []string{"discovery", "portscan", "service_fingerprint", "specialized", "vulnerability", "web"},
			Ports:       []int{1, 65535},
			Concurrency: 10,
			TimeoutSec:  300,
		},
		ProfileExternalInfrastructure: {
			Name:        "External Infrastructure",
			Description: "External perimeter discovery and DNS/cloud enumeration",
			Modules:     []string{"discovery", "dns", "cloud_imds", "portscan"},
			Ports:       []int{80, 443, 53, 8080, 8443},
			Concurrency: 25,
			TimeoutSec:  120,
		},
		ProfileInternalNetwork: {
			Name:        "Internal Network",
			Description: "Internal subnet sweep, NetBIOS, and SMB discovery",
			Modules:     []string{"icmp_sweep", "smb", "ldap", "portscan"},
			Ports:       []int{139, 445, 389, 636, 88},
			Concurrency: 30,
			TimeoutSec:  90,
		},
		ProfileWebApplication: {
			Name:        "Web Application",
			Description: "Web technology stack, directory fuzzing, and CORS/CSRF heuristic analysis",
			Modules:     []string{"http", "wappalyzer", "dir_fuzzing", "web_vuln_engine"},
			Ports:       []int{80, 443, 8000, 8080, 8443},
			Concurrency: 15,
			TimeoutSec:  180,
		},
		ProfileAPIAssessment: {
			Name:        "API Assessment",
			Description: "REST/GraphQL API endpoint harvesting and CORS testing",
			Modules:     []string{"http", "directory_api", "web_vuln_engine"},
			Ports:       []int{80, 443, 3000, 5000, 8080},
			Concurrency: 20,
			TimeoutSec:  120,
		},
		ProfileActiveDirectory: {
			Name:        "Active Directory",
			Description: "Kerberoasting, LAPS, and LDAP schema auditing",
			Modules:     []string{"ldap", "kerberos", "bloodhound"},
			Ports:       []int{88, 389, 636, 3268},
			Concurrency: 10,
			TimeoutSec:  180,
		},
		ProfileKubernetes: {
			Name:        "Kubernetes",
			Description: "K8s API server and Kubelet unauthenticated probe",
			Modules:     []string{"container_checks", "http"},
			Ports:       []int{6443, 10250, 10255},
			Concurrency: 15,
			TimeoutSec:  60,
		},
		ProfileCloudInfrastructure: {
			Name:        "Cloud Infrastructure",
			Description: "IMDS reachability and public cloud asset discovery",
			Modules:     []string{"cloud_imds", "passive_intel"},
			Ports:       []int{80, 443},
			Concurrency: 20,
			TimeoutSec:  60,
		},
		ProfileBugBounty: {
			Name:        "Bug Bounty",
			Description: "Subdomain enumeration, historical URLs, and secret harvesting",
			Modules:     []string{"discovery", "wayback", "secret_intel"},
			Ports:       []int{80, 443},
			Concurrency: 30,
			TimeoutSec:  240,
		},
		ProfileCompliance: {
			Name:        "Compliance",
			Description: "CIS benchmarks and web header security hardening audit",
			Modules:     []string{"cis_compliance", "http"},
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
