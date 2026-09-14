// Package capability owns the product capability manifest used by the CLI,
// API, and generated documentation. Feature status must be changed here only
// when the implementation and its tests satisfy the release-audit rule.
package capability

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Status string

const (
	Implemented           Status = "implemented"
	Experimental          Status = "experimental"
	Gated                 Status = "gated"
	Planned               Status = "planned"
	IntentionallyExcluded Status = "intentionally_excluded"
)

type Entry struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Category           string   `json:"category"`
	Status             Status   `json:"status"`
	Summary            string   `json:"summary"`
	Platforms          []string `json:"platforms"`
	Privileges         []string `json:"privileges,omitempty"`
	Credentials        []string `json:"credentials,omitempty"`
	ConfigKeys         []string `json:"config_keys,omitempty"`
	NetworkEffects     []string `json:"network_effects,omitempty"`
	RequiredConditions []string `json:"required_conditions,omitempty"`
}

type Manifest struct {
	SchemaVersion string  `json:"schema_version"`
	Product       string  `json:"product"`
	Capabilities  []Entry `json:"capabilities"`
}

func Current() Manifest {
	all := []string{"linux", "macos", "windows"}
	entries := []Entry{
		{ID: "scope-enforcement", Name: "Target scope enforcement", Category: "safety", Status: Implemented, Summary: "Checks configured and discovered targets against explicit address, CIDR, and domain scope.", Platforms: all, ConfigKeys: []string{"scope.allowed_targets", "scope.authorization"}},
		{ID: "bounded-scheduler", Name: "Bounded event scheduler", Category: "engine", Status: Implemented, Summary: "Runs event-driven modules with global/per-target pacing, timeouts, deduplication, and optional adaptive workers.", Platforms: all, ConfigKeys: []string{"scheduler.concurrency", "scheduler.global_rate_limit_ms", "scheduler.per_target_rate_limit_ms", "scheduler.module_timeout_ms"}, NetworkEffects: []string{"bounded target connections"}},
		{ID: "discovery", Name: "Host and DNS discovery", Category: "scanning", Status: Implemented, Summary: "Performs bounded DNS, CIDR, liveness, IPv6, ARP, virtual-host, and offline evidence discovery.", Platforms: all, ConfigKeys: []string{"discovery.*"}, NetworkEffects: []string{"DNS queries", "optional ICMP/TCP/UDP probes"}},
		{ID: "port-service", Name: "Port and service enumeration", Category: "scanning", Status: Implemented, Summary: "Collects bounded TCP/UDP state, banners, protocol responses, services, and CPE candidates.", Platforms: all, ConfigKeys: []string{"portscan.*"}, NetworkEffects: []string{"TCP connections", "optional UDP probes"}},
		{ID: "raw-tcp", Name: "Raw TCP techniques", Category: "scanning", Status: Gated, Summary: "Supports explicitly selected raw SYN, ACK, FIN, NULL, XMAS, window, Maimon, and fragmented probes.", Platforms: []string{"linux", "macos"}, Privileges: []string{"raw socket capability or administrator/root"}, ConfigKeys: []string{"portscan.enable_raw_scanning", "portscan.raw_techniques"}, NetworkEffects: []string{"crafted TCP packets"}, RequiredConditions: []string{"explicit configuration", "platform raw-socket support"}},
		{ID: "idle-decoy", Name: "Idle and decoy scanning", Category: "active-testing", Status: Planned, Summary: "Third-party and spoofed-traffic runners are not connected to production scans.", Platforms: []string{"linux", "macos"}, Privileges: []string{"raw socket capability or administrator/root"}, ConfigKeys: []string{"active_testing.allowed_techniques", "portscan.decoy_ips", "portscan.zombie_host"}, NetworkEffects: []string{"spoofed traffic", "third-party host interaction"}, RequiredConditions: []string{"active-testing gate", "separate authorization for every participating host"}},
		{ID: "http-enumeration", Name: "HTTP, TLS, and API enumeration", Category: "scanning", Status: Implemented, Summary: "Provides bounded crawling, technology, directory/API, source-map, screenshot, HTTP/3, and gRPC-reflection enumeration.", Platforms: all, Credentials: []string{"optional session cookie environment variable"}, ConfigKeys: []string{"http.*"}, NetworkEffects: []string{"scoped HTTP requests"}},
		{ID: "specialized-protocols", Name: "Specialized protocol enumeration", Category: "scanning", Status: Implemented, Summary: "Provides opt-in SMB, LDAP, SNMP, cloud, container, database, SSH, FTP, and SMTP capability checks.", Platforms: all, ConfigKeys: []string{"specialized.*"}, NetworkEffects: []string{"protocol-specific read-only requests"}},
		{ID: "passive-intelligence", Name: "Passive intelligence providers", Category: "integrations", Status: Implemented, Summary: "Normalizes supported third-party intelligence providers with pacing, quota, version, and credential diagnostics.", Platforms: all, Credentials: []string{"provider-specific environment variables"}, ConfigKeys: []string{"passive_intel.*"}, NetworkEffects: []string{"configured third-party HTTPS API requests"}, RequiredConditions: []string{"provider opt-in", "engagement authorization"}},
		{ID: "tier4-tls", Name: "Active TLS vulnerability verification", Category: "active-testing", Status: Planned, Summary: "Heartbleed, ROBOT, CRIME, and BREACH runners are not connected to scans.", Platforms: all, ConfigKeys: []string{"active_testing.*"}, NetworkEffects: []string{"crafted TLS/application requests"}, RequiredConditions: []string{"active-testing gate", "per-technique authorization"}},
		{ID: "tier4-web", Name: "Active web payload verification", Category: "active-testing", Status: Planned, Summary: "SQLi, XSS, SSRF, file inclusion, XXE, SSTI, host-header, request-smuggling, and prototype-pollution runners are not connected.", Platforms: all, ConfigKeys: []string{"active_testing.*"}, NetworkEffects: []string{"application payload requests"}, RequiredConditions: []string{"active-testing gate", "per-technique authorization"}},
		{ID: "tier4-credentialed", Name: "Credentialed host and directory assessment", Category: "active-testing", Status: Planned, Summary: "SSH, WinRM, authenticated AD, Kerberos, LAPS, permission, secret, IMDS, and active DNS runners remain planned.", Platforms: all, Credentials: []string{"future secret-manager references"}, ConfigKeys: []string{"active_testing.*"}, NetworkEffects: []string{"authenticated and active protocol requests"}, RequiredConditions: []string{"active-testing gate", "least-privilege credentials"}},
		{ID: "inventory-analysis", Name: "Inventory, drift, graphs, and risk", Category: "analysis", Status: Implemented, Summary: "Persists history and builds deterministic changes, relationships, prioritization, risk, and exposure-chain evidence.", Platforms: all},
		{ID: "reporting", Name: "Reports and notifications", Category: "output", Status: Implemented, Summary: "Generates JSON, Markdown, HTML, PDF, SARIF, CSV, executive, technical, triage, and graph outputs with explicit notifications.", Platforms: all, ConfigKeys: []string{"reporting.*", "notifications.*"}, NetworkEffects: []string{"optional configured webhook, Slack, SMTP, Neo4j, or loopback Ollama requests"}},
		{ID: "dashboard-api", Name: "Dashboard, REST, GraphQL, and streams", Category: "interface", Status: Implemented, Summary: "Provides operator views, scan controls, evidence APIs, event streams, token roles, and mutation audit.", Platforms: all, Credentials: []string{"optional API token environment variable"}, ConfigKeys: []string{"api.*"}, NetworkEffects: []string{"loopback HTTP by default", "TLS required for non-loopback"}},
		{ID: "sqlite", Name: "SQLite operational datastore", Category: "storage", Status: Implemented, Summary: "Provides native migrations, evidence persistence, encrypted sensitive fields, retention, and encrypted backup/restore.", Platforms: all, Credentials: []string{"optional encryption key reference"}, ConfigKeys: []string{"database.path", "database.encryption_key_env", "database.encryption_key_secret"}},
		{ID: "postgres", Name: "PostgreSQL operational datastore", Category: "storage", Status: Experimental, Summary: "Core schema and operations exist, but full SQLite behavioral and migration parity is not release-complete.", Platforms: all, Credentials: []string{"PostgreSQL DSN environment variable"}, ConfigKeys: []string{"database.driver", "database.postgres_dsn_env", "database.postgres_max_open_conns", "database.postgres_max_idle_conns"}},
		{ID: "secret-managers", Name: "Production secret managers", Category: "storage", Status: Implemented, Summary: "Supports native OS keychains plus configured Vault, Kubernetes, AWS, Azure, and GCP adapters without plaintext fallback.", Platforms: all, Credentials: []string{"workload identity or backend token"}, ConfigKeys: []string{"secrets.*"}, NetworkEffects: []string{"configured secret-backend requests"}},
		{ID: "distributed", Name: "Authenticated distributed scanning", Category: "operations", Status: Implemented, Summary: "Provides digest-bound jobs, enrolled Ed25519 agents, replay protection, bounded leases, evidence upload, and centralized reporting.", Platforms: all, Credentials: []string{"agent Ed25519 private key"}, NetworkEffects: []string{"HTTPS coordinator traffic"}, RequiredConditions: []string{"agent enrollment", "matching authorization and configuration digest"}},
		{ID: "ha-coordinator", Name: "HA coordinator failover", Category: "operations", Status: Implemented, Summary: "Provides active/passive coordinator leadership, fenced mutations, standby rejection, and monotonic epoch takeover.", Platforms: all},
		{ID: "monitoring", Name: "Bounded continuous monitoring", Category: "operations", Status: Implemented, Summary: "Runs finite recurring scope-locked scans only through an explicit monitor command.", Platforms: all, ConfigKeys: []string{"monitoring.*"}},
		{ID: "plugin-marketplace", Name: "Signed plugin marketplace", Category: "plugins", Status: Implemented, Summary: "Provides explicit HTTPS discovery, ratings, versions, Ed25519 verification, atomic installation, and updates.", Platforms: all, Credentials: []string{"pinned marketplace public key"}, NetworkEffects: []string{"configured registry HTTPS requests"}},
		{ID: "plugin-runtimes", Name: "Lua and gRPC plugin runtimes", Category: "plugins", Status: Gated, Summary: "Provides capability-limited Lua and TLS-required remote gRPC execution; scans do not auto-load plugins.", Platforms: all, ConfigKeys: []string{"plugin manifest permissions"}, NetworkEffects: []string{"manifest-authorized target or gRPC requests"}, RequiredConditions: []string{"explicit activation", "verified package"}},
		{ID: "plugin-os-sandbox", Name: "OS-level plugin sandbox", Category: "plugins", Status: Implemented, Summary: "Provides OS-level process isolation, separate process groups, resource ceilings, and stripped environments for untrusted plugins.", Platforms: all},
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return Manifest{SchemaVersion: "1.0", Product: "enumscan", Capabilities: entries}
}

func JSON() ([]byte, error) { return json.MarshalIndent(Current(), "", "  ") }

func Text() string {
	var out strings.Builder
	fmt.Fprintln(&out, "STATUS                  CAPABILITY                    SUMMARY")
	for _, entry := range Current().Capabilities {
		fmt.Fprintf(&out, "%-23s %-29s %s\n", entry.Status, entry.ID, entry.Summary)
	}
	return out.String()
}

func Markdown() string {
	var out strings.Builder
	out.WriteString("# Capability manifest\n\n")
	out.WriteString("Generated from `internal/capability`; do not edit this file manually.\n\n")
	out.WriteString("| Capability | Category | Status | Platforms | Summary |\n")
	out.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, entry := range Current().Capabilities {
		fmt.Fprintf(&out, "| `%s` | %s | `%s` | %s | %s |\n", entry.ID, entry.Category, entry.Status, strings.Join(entry.Platforms, ", "), entry.Summary)
	}
	return out.String()
}
