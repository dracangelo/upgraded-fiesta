package modules

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestPassiveOSFingerprintClassification(t *testing.T) {
	// 1. Test live listener fingerprinting via fallback
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed starting test listener: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	osFamily, cpe, evidence := tcpIPStackOSFingerprint(context.Background(), "127.0.0.1", port)
	if osFamily == "" {
		t.Fatalf("expected non-empty osFamily from active listener")
	}
	if !strings.Contains(evidence, "ttl=") || !strings.Contains(evidence, "window_size=") {
		t.Errorf("evidence missing traits: %s", evidence)
	}
	if !strings.Contains(osFamily, "Linux") && !strings.Contains(osFamily, "Unix") {
		t.Errorf("unexpected osFamily for loopback: %s (cpe=%s)", osFamily, cpe)
	}

	// 2. Test offline closed port behavior
	osFamilyClosed, _, _ := tcpIPStackOSFingerprint(context.Background(), "127.0.0.1", 64321)
	if osFamilyClosed != "" {
		t.Errorf("expected empty osFamily for closed port, got: %s", osFamilyClosed)
	}
}
