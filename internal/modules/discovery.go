package modules

import (
	"context"
	"net"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type Discovery struct {
	db    *store.SQLiteCLI
	guard scope.Guard
}

func NewDiscovery(db *store.SQLiteCLI, guard scope.Guard) Discovery {
	return Discovery{db: db, guard: guard}
}

func (d Discovery) Name() string { return "discovery" }

func (d Discovery) Subscriptions() []string { return []string{EventTarget} }

func (d Discovery) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	if !d.guard.Allowed(event.Target) {
		return nil, nil
	}
	_ = d.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "target", Value: event.Target})
	next := []models.Event{{ScanID: event.ScanID, Type: EventHost, Target: event.Target}}

	if ip := net.ParseIP(event.Target); ip == nil {
		addrs, _ := net.DefaultResolver.LookupHost(ctx, event.Target)
		for _, addr := range addrs {
			if d.guard.Allowed(addr) {
				_ = d.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "ip", Value: addr, Parent: event.Target})
				next = append(next, models.Event{ScanID: event.ScanID, Type: EventHost, Target: addr, Data: map[string]string{"hostname": event.Target}})
			}
		}
	}
	return next, nil
}
