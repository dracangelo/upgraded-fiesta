package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRequiresAuthorization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("scope:\n  allowed_targets: [\"127.0.0.1\"]\nscan:\n  targets: [\"127.0.0.1\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected missing authorization to be rejected")
	}
}

func TestProductionProfileRequiresReplacement(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "production.yaml")
	if _, err := Load(path); err == nil {
		t.Fatal("expected placeholder production profile to be rejected")
	}
}

func TestInteractiveScanTemplateRequiresReplacement(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "scan.template.yaml")
	if _, err := Load(path); err == nil {
		t.Fatal("expected interactive scan template placeholders to be rejected")
	}
}

func TestDiscoveryActiveProbeOptionsLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `scope:
  allowed_targets: ["127.0.0.1"]
  authorization: "TEST-123"
discovery:
  enable_dns_discovery: true
  enable_dns_records: true
  enable_icmp_sweep: true
  enable_tcp_host_probes: true
  tcp_probe_ports: [80, 443]
  enable_udp_live_probes: true
  udp_probe_ports: [53, 123]
scan:
  targets: ["127.0.0.1"]
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Discovery.EnableDNSDiscovery || !cfg.Discovery.EnableDNSRecords || !cfg.Discovery.EnableICMPSweep || !cfg.Discovery.EnableTCPHostProbes || !cfg.Discovery.EnableUDPLiveProbes {
		t.Fatalf("discovery options not loaded: %#v", cfg.Discovery)
	}
}

func TestPassiveIntelPacingOptionsLoadAndValidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `scope:
  allowed_targets: ["127.0.0.1"]
  authorization: "TEST-123"
passive_intel:
  enabled: true
  sources: ["shodan"]
  provider_min_interval_ms: 2500
  max_retry_after_ms: 45000
scan:
  targets: ["127.0.0.1"]
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PassiveIntel.ProviderMinIntervalMS != 2500 || cfg.PassiveIntel.MaxRetryAfterMS != 45000 {
		t.Fatalf("passive intelligence pacing configuration did not load: %#v", cfg.PassiveIntel)
	}
	cfg.PassiveIntel.MaxRetryAfterMS = 300001
	if err := Validate(cfg); err == nil {
		t.Fatal("expected excessive passive Retry-After cap to be rejected")
	}
}

func TestPostgresDatabaseConfigurationIsExplicitAndBounded(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "TEST-123"
	cfg.Database.Driver = "postgres"
	cfg.Database.PostgresDSNEnv = "ENUMSCAN_POSTGRES_DSN"
	cfg.Database.PostgresMaxOpenConns = 8
	cfg.Database.PostgresMaxIdleConns = 2
	if err := Validate(cfg); err != nil {
		t.Fatalf("expected valid PostgreSQL preflight configuration: %v", err)
	}
	cfg.Database.PostgresMaxIdleConns = 9
	if err := Validate(cfg); err == nil {
		t.Fatal("expected invalid PostgreSQL connection-pool configuration")
	}
}

func TestMonitoringConfigurationIsBounded(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "TEST-123"
	cfg.Monitoring.Enabled = true
	cfg.Monitoring.IntervalMinutes = 5
	cfg.Monitoring.MaxRuns = 2
	if err := Validate(cfg); err != nil {
		t.Fatalf("expected valid bounded monitoring configuration: %v", err)
	}
	cfg.Monitoring.MaxRuns = 0
	if err := Validate(cfg); err == nil {
		t.Fatal("expected unbounded monitoring configuration to be rejected")
	}
}

func TestHTTP3TransportRequiresExplicitOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `scope:
  allowed_targets: ["127.0.0.1"]
  authorization: "TEST-123"
http:
  enable_http3: true
scan:
  targets: ["127.0.0.1"]
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HTTP.EnableHTTP3 || Default().HTTP.EnableHTTP3 {
		t.Fatalf("unexpected HTTP/3 opt-in state: %#v", cfg.HTTP)
	}
}

func TestScreenshotRendererRequiresExplicitSafeConfiguration(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "TEST-123"
	cfg.HTTP.EnableScreenshots = true
	if err := Validate(cfg); err == nil {
		t.Fatal("enabled screenshots without a renderer configuration must be rejected")
	}
	cfg.HTTP.ScreenshotRenderer = "/usr/local/bin/engagement-browser"
	cfg.HTTP.ScreenshotOutputDir = "/var/lib/enumscan/screenshots"
	cfg.HTTP.ScreenshotRendererArgs = []string{"--url", "{url}", "--output", "{output}"}
	if err := Validate(cfg); err != nil {
		t.Fatalf("complete explicit screenshot configuration was rejected: %v", err)
	}
}

func TestValidateRejectsUnsafeOrInvalidScanSettings(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "TEST-123"
	cfg.PortScan.DecoyIPs = []string{"192.0.2.10"}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected decoy configuration to be rejected")
	}

	cfg = Default()
	cfg.Scope.Authorization = "TEST-123"
	cfg.PortScan.TCPPorts = []int{70000}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected invalid port to be rejected")
	}
}

func TestNeo4jRequiresSecureConfiguredEndpoint(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "TEST-123"
	cfg.Neo4j.URI = "http://neo4j.example.test:7474"
	cfg.Neo4j.Username = "neo4j"
	cfg.Neo4j.PasswordEnv = "ENUMSCAN_NEO4J_PASSWORD"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected non-loopback HTTP Neo4j endpoint rejection")
	}
	cfg.Neo4j.URI = "https://neo4j.example.test:7474"
	if err := Validate(cfg); err != nil {
		t.Fatalf("expected secure Neo4j endpoint acceptance: %v", err)
	}
}

func TestAuthenticatedCrawlingRequiresExplicitCookieEnvironmentName(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "TEST-123"
	cfg.HTTP.EnableAuthenticatedCrawling = true
	if err := Validate(cfg); err == nil {
		t.Fatal("expected authenticated crawling without a cookie environment name to be rejected")
	}
	cfg.HTTP.AuthCookieEnv = "ENUMSCAN_AUTH_COOKIE"
	if err := Validate(cfg); err != nil {
		t.Fatalf("explicit cookie environment name was rejected: %v", err)
	}
}

func TestCompletedWebhookSubscriptionRequiresSecureEndpoint(t *testing.T) {
	cfg := Default()
	cfg.Scope.Authorization = "TEST-123"
	cfg.Notifications.EnableScanCompletedWebhook = true
	cfg.Notifications.WebhookURL = "http://alerts.example.test/hook"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected remote HTTP webhook rejection")
	}
	cfg.Notifications.WebhookURL = "https://alerts.example.test/hook"
	if err := Validate(cfg); err != nil {
		t.Fatalf("expected HTTPS webhook acceptance: %v", err)
	}
}
