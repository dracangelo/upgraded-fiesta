package modules

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestDynamicBrowserRendererLifecycle(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "render.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	ctx := context.Background()
	_ = db.Migrate(ctx)

	guard := scope.New([]string{"example.com", "127.0.0.1"})
	config := models.HTTPConfig{
		ScreenshotRenderer:    "mock",
		MaxScreenshotsPerScan: 10,
	}

	renderer := NewDynamicBrowserRenderer(db, guard, config)
	if renderer.Name() != "dynamic_browser_renderer" {
		t.Errorf("unexpected name: %s", renderer.Name())
	}

	// 1. Process authorized URL
	events, err := renderer.Handle(ctx, models.Event{
		ScanID: "scan-dyn-1",
		Type:   EventHTTPURL,
		Target: "http://example.com/",
	})
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	// Verify newly discovered dynamic API endpoints were emitted
	if len(events) == 0 {
		t.Errorf("expected discovered dynamic API endpoint events, got 0")
	} else {
		if !strings.Contains(events[0].Target, "/api/v1/user/profile") {
			t.Errorf("unexpected emitted event target: %s", events[0].Target)
		}
	}

	// Verify assets in store
	assets, err := db.Assets(ctx, "scan-dyn-1")
	if err != nil || len(assets) == 0 {
		t.Fatalf("expected recorded assets in store, got %d (err: %v)", len(assets), err)
	}

	hasDOM := false
	hasScript := false
	hasAPI := false
	for _, a := range assets {
		if a.Type == "rendered_dom" {
			hasDOM = true
		}
		if a.Type == "client_script" {
			hasScript = true
		}
		if a.Type == "api_endpoint" {
			hasAPI = true
		}
	}

	if !hasDOM || !hasScript || !hasAPI {
		t.Errorf("missing asset types: dom=%t script=%t api=%t", hasDOM, hasScript, hasAPI)
	}

	// 2. Reject out-of-scope URL
	outScopeEvents, err := renderer.Handle(ctx, models.Event{
		ScanID: "scan-dyn-1",
		Type:   EventHTTPURL,
		Target: "http://out-of-scope.net/",
	})
	if err != nil || len(outScopeEvents) != 0 {
		t.Errorf("expected out-of-scope URL to be dropped cleanly, got %v", outScopeEvents)
	}
}
