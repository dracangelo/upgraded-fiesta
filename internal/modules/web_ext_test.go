package modules

import (
	"context"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestBrowserScreenshotAndALPN(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	guard := scope.New([]string{"example.com", "127.0.0.1"})

	shotMod := NewBrowserScreenshotRenderer(db, guard)
	if shotMod.Name() != "browser_screenshot_renderer" {
		t.Errorf("unexpected name: %s", shotMod.Name())
	}

	_, _ = shotMod.Handle(context.Background(), models.Event{
		ScanID: "s1",
		Type:   "url.crawled",
		Target: "http://example.com/index.html",
	})

	h23Mod := NewHTTP2Fingerprinter(db, guard)
	if h23Mod.Name() != "http2_fingerprinter" {
		t.Errorf("unexpected name: %s", h23Mod.Name())
	}
}

func TestFaviconAndWasmSPADiscovery(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	guard := scope.New([]string{"example.com", "127.0.0.1"})

	favMod := NewFaviconFingerprinter(db, guard)
	if favMod.Name() != "favicon_fingerprinter" {
		t.Errorf("unexpected name: %s", favMod.Name())
	}

	wasmMod := NewWasmAndSPADiscovery(db, guard)
	if wasmMod.Name() != "wasm_spa_discovery" {
		t.Errorf("unexpected name: %s", wasmMod.Name())
	}

	_, _ = wasmMod.Handle(context.Background(), models.Event{
		ScanID: "s1",
		Type:   "url.crawled",
		Target: "http://example.com/app.wasm",
	})
}
