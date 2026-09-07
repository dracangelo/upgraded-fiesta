//go:build !linux

package modules

import (
	"context"

	"enumscan/internal/models"
)

// Packet capture uses Linux AF_PACKET. Other platforms keep the explicit
// offline capture-import path and report that live capture is unavailable.
func (d Discovery) captureLiveTraffic(ctx context.Context, scanID, parent string) []models.Event {
	_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "discovery_note", Value: parent, Metadata: "live_packet_capture_status=unsupported_platform"})
	return nil
}
