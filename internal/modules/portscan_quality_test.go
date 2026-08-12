package modules

import (
	"context"
	"errors"
	"path/filepath"
	"syscall"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestPortScanRespectsDisabledProtocols(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "ports.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	scanner := NewPortScan(db, scope.New([]string{"127.0.0.1"}), models.PortScanConfig{EnableTCP: false, EnableUDP: false})
	events, err := scanner.Handle(context.Background(), models.Event{ScanID: "disabled", Type: EventHost, Target: "127.0.0.1"})
	if err != nil || len(events) != 0 {
		t.Fatalf("disabled scanner emitted %#v, err=%v", events, err)
	}
}

func TestTCPStateClassification(t *testing.T) {
	if classifyTCPState(nil) != "open" || classifyTCPState(errors.New("other")) != "unreachable" || classifyTCPState(syscall.ECONNREFUSED) != "closed" || classifyTCPState(context.DeadlineExceeded) != "filtered" {
		t.Fatal("unexpected TCP state classification")
	}
}

func TestUDPServiceProbeValidation(t *testing.T) {
	if len(udpProbe(69)) == 0 || len(udpProbe(5060)) == 0 || len(udpProbe(5353)) == 0 || udpProbeName(1812) != "radius_access_request" {
		t.Fatal("expected configured UDP service probes")
	}
	if !validUDPResponse(69, []byte{0, 3, 0, 1}) || !validUDPResponse(5060, []byte("SIP/2.0 200 OK")) || validUDPResponse(123, []byte{1, 2}) {
		t.Fatal("unexpected UDP response validation")
	}
}
