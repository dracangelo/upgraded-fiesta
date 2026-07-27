package modules

import (
	"context"
	"net"
	"strings"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type IPv6Discovery struct {
	db    *store.SQLiteCLI
	guard scope.Guard
}

func NewIPv6Discovery(db *store.SQLiteCLI, guard scope.Guard) *IPv6Discovery {
	return &IPv6Discovery{db: db, guard: guard}
}

func (m *IPv6Discovery) Name() string {
	return "ipv6_discovery"
}

func (m *IPv6Discovery) Subscriptions() []string {
	return []string{EventTarget, "domain.discovered"}
}

func (m *IPv6Discovery) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !m.guard.Allowed(evt.Target) {
		return nil, nil
	}

	var newEvents []models.Event

	// Check if target is an IPv6 CIDR string
	if strings.Contains(evt.Target, ":") && strings.Contains(evt.Target, "/") {
		ip, ipNet, err := net.ParseCIDR(evt.Target)
		if err == nil && ip.To4() == nil {
			// Expand IPv6 network targets
			expanded := expandIPv6Net(ipNet, 16)
			for _, ipv6Addr := range expanded {
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "ipv6_host",
					Value:    ipv6Addr,
					Parent:   evt.Target,
					Metadata: "ipv6_discovery",
				})
				newEvents = append(newEvents, models.Event{
					ScanID: evt.ScanID,
					Type:   "host.discovered",
					Target: ipv6Addr,
				})
			}
		}
	} else if !strings.Contains(evt.Target, ":") {
		// Target is hostname/domain: perform AAAA lookup
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip6", evt.Target)
		if err == nil {
			for _, ip := range ips {
				ipStr := ip.String()
				if !m.guard.Allowed(ipStr) {
					continue
				}
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "ipv6_host",
					Value:    ipStr,
					Parent:   evt.Target,
					Metadata: "aaaa_lookup",
				})
				newEvents = append(newEvents, models.Event{
					ScanID: evt.ScanID,
					Type:   "host.discovered",
					Target: ipStr,
				})
			}
		}
	}

	return newEvents, nil
}

func expandIPv6Net(ipNet *net.IPNet, maxLimit int) []string {
	var result []string
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)

	for i := 0; i < maxLimit; i++ {
		if ipNet.Contains(ip) {
			result = append(result, ip.String())
		}
		// Increment IPv6 IP address
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}
	return result
}
