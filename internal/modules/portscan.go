package modules

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type PortScan struct {
	db    *store.SQLiteCLI
	guard scope.Guard
	ports []int
}

func NewPortScan(db *store.SQLiteCLI, guard scope.Guard, ports []int) PortScan {
	if len(ports) == 0 {
		ports = []int{80, 443, 8080, 8443}
	}
	return PortScan{db: db, guard: guard, ports: ports}
}

func (p PortScan) Name() string { return "portscan" }

func (p PortScan) Subscriptions() []string { return []string{EventHost} }

func (p PortScan) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	if !p.guard.Allowed(event.Target) {
		return nil, nil
	}
	next := make([]models.Event, 0)
	dialer := net.Dialer{Timeout: 750 * time.Millisecond}
	for _, port := range p.ports {
		address := net.JoinHostPort(event.Target, strconv.Itoa(port))
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			continue
		}
		_ = conn.Close()
		value := fmt.Sprintf("%s/tcp", address)
		_ = p.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "open_port", Value: value, Parent: event.Target})
		next = append(next, models.Event{ScanID: event.ScanID, Type: EventPort, Target: address, Data: map[string]string{"port": strconv.Itoa(port), "protocol": "tcp"}})
		if port == 80 || port == 8080 {
			next = append(next, models.Event{ScanID: event.ScanID, Type: EventHTTPURL, Target: "http://" + address})
		}
		if port == 443 || port == 8443 {
			next = append(next, models.Event{ScanID: event.ScanID, Type: EventHTTPURL, Target: "https://" + address})
		}
	}
	return next, nil
}
