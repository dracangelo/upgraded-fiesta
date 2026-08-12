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
