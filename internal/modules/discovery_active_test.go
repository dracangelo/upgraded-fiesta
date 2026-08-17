package modules

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestCIDRSkipsIPv4NetworkAndBroadcast(t *testing.T) {
	_, cidr, err := net.ParseCIDR("192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if !skipCIDREndpoint(cidr, net.ParseIP("192.0.2.0")) || !skipCIDREndpoint(cidr, net.ParseIP("192.0.2.3")) || skipCIDREndpoint(cidr, net.ParseIP("192.0.2.1")) {
		t.Fatal("unexpected IPv4 CIDR endpoint handling")
	}
}

func TestDNSProbePayloadIsValidQuestion(t *testing.T) {
	payload := dnsProbePayload()
	if len(payload) != 19 || payload[2] != 1 || payload[4] != 0 || payload[5] != 1 || payload[12] != 1 || payload[13] != 'a' {
		t.Fatalf("unexpected DNS payload: %x", payload)
	}
}

func TestPassiveCaptureImportIsScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.txt")
	if err := os.WriteFile(path, []byte("IP 10.20.30.4.443 > 10.20.30.1.51522\nIP 192.0.2.5.443 > 10.20.30.1.51522\n"), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "scan.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	discovery := NewDiscovery(db, scope.New([]string{"10.20.30.0/24"}), models.DiscoveryConfig{CIDRMaxHosts: 4, PassiveCaptureFiles: []string{path}})
	events, err := discovery.Handle(context.Background(), models.Event{ScanID: "capture", Type: EventTarget, Target: "10.20.30.1"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Target == "10.20.30.4" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected scoped capture host event, got %#v", events)
	}
}

func TestSNMPGetRequestPayload(t *testing.T) {
	req := buildSNMPGetRequest("public")
	if len(req) < 10 || req[0] != 0x30 {
		t.Fatalf("unexpected SNMP request payload: %x", req)
	}
}

func TestBuildTCPHeader(t *testing.T) {
	hdr := buildTCPHeader(8080, 80, 0x02)
	if len(hdr) != 20 || hdr[13] != 0x02 {
		t.Fatalf("unexpected TCP header: %x", hdr)
	}
}

func TestTCPSYNACKProbesAndLiveCaptureGracefulFallback(t *testing.T) {
	ctx := context.Background()
	// Unreachable IP address should return false cleanly without panicking
	if tcpSYNHostResponsive(ctx, "192.0.2.1", 65432) {
		t.Fatal("expected unreachable IP to fail SYN probe")
	}
	if tcpACKHostResponsive(ctx, "192.0.2.1", 65432) {
		t.Fatal("expected unreachable IP to fail ACK probe")
	}
	if snmpHostResponsive(ctx, "192.0.2.1", 65432, "public") {
		t.Fatal("expected unreachable IP to fail SNMP probe")
	}
}
