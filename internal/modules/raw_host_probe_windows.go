//go:build windows

package modules

import "context"

// Windows builds deliberately do not issue raw TCP probes. The regular
// connect probe remains available to SYN discovery; raw techniques use their
// safe TCP-connect fallback in raw_scanner_windows.go.
func rawTCPSYNProbe(context.Context, string, int) bool { return false }
func rawTCPACKProbe(context.Context, string, int) bool { return false }
func rawTCPTraitsProbe(context.Context, string, int) (int, int, error) {
	return 0, 0, nil
}
