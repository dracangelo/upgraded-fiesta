package modules

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestCalculateChecksum(t *testing.T) {
	data := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01}
	csum := calculateChecksum(data)
	if csum == 0 {
		t.Fatal("expected non-zero IPv4 checksum")
	}
}

func TestBuildIPHeader(t *testing.T) {
	src := net.ParseIP("192.0.2.1")
	dst := net.ParseIP("192.0.2.2")
	hdr := buildIPHeader(src, dst, 20, 6)
	if len(hdr) != 20 || hdr[0] != 0x45 || hdr[9] != 6 {
		t.Fatalf("unexpected IP header: %x", hdr)
	}
}

func TestRawTCPScannerTechniqueHandling(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "scan.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	techniques := []ScanTechnique{
		ScanSYN, ScanACK, ScanFIN, ScanNULL, ScanXMAS, ScanWindow, ScanMaimon, ScanFragmented, ScanDecoy, ScanIdle,
	}

	guard := scope.New([]string{"127.0.0.1"})

	for _, tech := range techniques {
		scanner := NewRawTCPScannerWithConfig(db, guard, models.PortScanConfig{TCPPorts: []int{65432}}, tech)
		if scanner.Name() == "" {
			t.Fatalf("expected non-empty name for technique %s", tech)
		}
		// Execute scanner against 127.0.0.1; should fall back gracefully if raw sockets are unprivileged
		events, err := scanner.Handle(context.Background(), models.Event{ScanID: "test_raw", Type: EventHost, Target: "127.0.0.1"})
		if err != nil {
			t.Fatalf("technique %s returned error: %v", tech, err)
		}
		_ = events
	}
}
