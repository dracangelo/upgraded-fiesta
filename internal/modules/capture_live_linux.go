//go:build linux

package modules

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"time"

	"enumscan/internal/models"
)

func (d Discovery) captureLiveTraffic(ctx context.Context, scanID, parent string) []models.Event {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(uint16(0x0300)))
	if err != nil {
		_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "discovery_note", Value: parent, Metadata: "live_packet_capture_status=disabled_or_unprivileged"})
		return nil
	}
	defer syscall.Close(fd)
	duration := d.config.CaptureDurationMS
	if duration <= 0 {
		duration = 1000
	}
	timeout := syscall.NsecToTimeval((time.Duration(duration) * time.Millisecond).Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)
	buffer := make([]byte, 4096)
	deadline := time.Now().Add(time.Duration(duration) * time.Millisecond)
	next, seen := make([]models.Event, 0), make(map[string]bool)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return next
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil || n < 14 {
			break
		}
		if binary.BigEndian.Uint16(buffer[12:14]) != 0x0800 || n < 34 {
			continue
		}
		for _, ip := range []string{net.IP(buffer[26:30]).String(), net.IP(buffer[30:34]).String()} {
			if ip == "" || !d.guard.Allowed(ip) || seen[ip] {
				continue
			}
			seen[ip] = true
			_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "passive_observed_ip", Value: ip, Parent: parent, Metadata: "source=live_packet_capture"})
			next = append(next, models.Event{ScanID: scanID, Type: EventHost, Target: ip, Data: map[string]string{"source": "live_packet_capture"}})
		}
	}
	return next
}
