package modules

import (
	"context"
	"fmt"
	"net"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type ARPDiscovery struct {
	db    *store.SQLiteCLI
	guard scope.Guard
}

func NewARPDiscovery(db *store.SQLiteCLI, guard scope.Guard) *ARPDiscovery {
	return &ARPDiscovery{db: db, guard: guard}
}

func (m *ARPDiscovery) Name() string {
	return "arp_discovery"
}

func (m *ARPDiscovery) Subscriptions() []string {
	return []string{EventTarget}
}

func (m *ARPDiscovery) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !m.guard.Allowed(evt.Target) {
		return nil, nil
	}

	ip := net.ParseIP(evt.Target)
	if ip == nil || ip.To4() == nil {
		return nil, nil
	}

	// Probe local network ARP neighbor table / interface lookup
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}

	var newEvents []models.Event
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.Contains(ip) {
				macStr := iface.HardwareAddr.String()
				if macStr != "" {
					_ = m.db.AddAsset(ctx, models.Asset{
						ScanID:   evt.ScanID,
						Type:     "arp_neighbor",
						Value:    fmt.Sprintf("%s (%s)", evt.Target, macStr),
						Parent:   iface.Name,
						Metadata: "arp_discovery",
					})
					newEvents = append(newEvents, models.Event{
						ScanID: evt.ScanID,
						Type:   "host.discovered",
						Target: evt.Target,
					})
				}
			}
		}
	}

	return newEvents, nil
}
