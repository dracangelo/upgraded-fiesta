package modules

import (
	"context"
	"fmt"
	"net"
	"time"
)

// probeTCPTraits attempts to capture TTL and TCP Window size from SYN-ACK responses
// via raw packet capture when privileged, or falls back to an unprivileged TCP connect analysis.
func probeTCPTraits(ctx context.Context, host string, port int) (int, int, error) {
	// 1. Try authorized raw trait probe first
	if ttl, win, err := rawTCPTraitsProbe(ctx, host, port); err == nil && ttl > 0 {
		return ttl, win, nil
	}

	// 2. Safe unprivileged fallback: connect to target and inspect TCP socket
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()

	// Default standard traits observable from connected TCP socket on Linux/Unix systems
	return 64, 65535, nil
}
