package modules

import (
	"context"
	"path/filepath"
	"testing"

	"enumscan/internal/inventory"
	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestIPv6DiscoveryAndARP(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	guard := scope.New([]string{"2001:db8::/120", "127.0.0.1"})

	ipv6Mod := NewIPv6Discovery(db, guard)
	if ipv6Mod.Name() != "ipv6_discovery" {
		t.Errorf("unexpected name: %s", ipv6Mod.Name())
	}

	events, err := ipv6Mod.Handle(context.Background(), models.Event{
		ScanID: "s1",
		Type:   EventTarget,
		Target: "2001:db8::/124",
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(events) == 0 {
		t.Errorf("expected expanded IPv6 host events")
	}

	arpMod := NewARPDiscovery(db, guard)
	_, _ = arpMod.Handle(context.Background(), models.Event{
		ScanID: "s1",
		Type:   EventTarget,
		Target: "127.0.0.1",
	})
}

func TestVHostDiscovery(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	guard := scope.New([]string{"example.com", "127.0.0.1"})

	vhostMod := NewVHostDiscovery(db, guard)
	if vhostMod.Name() != "vhost_discovery" {
		t.Errorf("unexpected name: %s", vhostMod.Name())
	}

	// Should ignore non-HTTP port targets
	evts, err := vhostMod.Handle(context.Background(), models.Event{
		ScanID: "s1",
		Type:   "port.open",
		Target: "127.0.0.1:22",
	})
	if err != nil || len(evts) != 0 {
		t.Errorf("expected no events for port 22")
	}
}

func TestHostClusterer(t *testing.T) {
	clusterer := inventory.NewHostClusterer()
	assets := []models.InventoryAsset{
		{Value: "192.168.1.10", Type: "host"},
		{Value: "192.168.1.25", Type: "host"},
		{Value: "2001:db8::1", Type: "ipv6_host"},
		{Value: "sub.example.com", Type: "domain"},
	}

	clusters := clusterer.ClusterAssets(assets)
	if len(clusters) < 2 {
		t.Errorf("expected at least 2 clusters, got %d", len(clusters))
	}
}
