package inventory

import (
	"context"
	"strings"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestInventoryTrackingAndTimeline(t *testing.T) {
	invStore := store.NewInventoryStore()
	mgr := NewManager(invStore)

	ctx := context.Background()
	mgr.ProcessEvent(ctx, models.Event{ScanID: "s1", Type: "host.discovered", Target: "192.168.1.1"})

	assets := invStore.GetAssets()
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset in inventory, got %d", len(assets))
	}

	firstSeen := assets[0].FirstSeen
	time.Sleep(10 * time.Millisecond)

	mgr.ProcessEvent(ctx, models.Event{ScanID: "s2", Type: "host.discovered", Target: "192.168.1.1"})
	assetsUpdated := invStore.GetAssets()

	if assetsUpdated[0].ScanCount != 2 {
		t.Errorf("expected ScanCount=2, got %d", assetsUpdated[0].ScanCount)
	}
	if !assetsUpdated[0].LastSeen.After(firstSeen) {
		t.Errorf("expected LastSeen timestamp to update")
	}
}

func TestTechnologiesCertificatesAndSecrets(t *testing.T) {
	invStore := store.NewInventoryStore()
	mgr := NewManager(invStore)

	ctx := context.Background()
	mgr.StoreTechnology(ctx, "example.com", "Nginx", "Web Server", "1.20.1")
	mgr.StoreCertificate(ctx, "example.com", "sha256-fingerprint", "CN=example.com", "Let's Encrypt")
	mgr.StoreScreenshot(ctx, "example.com", "/tmp/shot.png", "1920x1080", "hash123")

	mgr.ProcessFinding(ctx, models.Finding{
		Asset:    "example.com",
		Title:    "AWS Secret Key Exposure",
		Evidence: "AKIAIOSFODNN7EXAMPLE",
	})

	graphEng := NewGraphEngine(invStore)
	dot := graphEng.BuildGraphDOT()
	if !strings.Contains(dot, "example.com") || !strings.Contains(dot, "USES_TECH") {
		t.Errorf("unexpected DOT output: %s", dot)
	}

	jsonBytes, err := graphEng.BuildGraphJSON()
	if err != nil || len(jsonBytes) == 0 {
		t.Errorf("BuildGraphJSON failed: %v", err)
	}
}
