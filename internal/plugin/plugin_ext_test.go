package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestPluginSignerAndSandbox(t *testing.T) {
	signer, err := NewPluginSigner("")
	if err != nil {
		t.Fatalf("NewPluginSigner: %v", err)
	}

	tempDir := t.TempDir()
	pluginFile := filepath.Join(tempDir, "plugin.lua")
	sigFile := filepath.Join(tempDir, "plugin.sig")

	_ = os.WriteFile(pluginFile, []byte("print('hello')"), 0644)
	valid, err := signer.VerifyPlugin(pluginFile, sigFile)
	if err != nil {
		t.Fatalf("VerifyPlugin error: %v", err)
	}
	if valid {
		t.Errorf("expected signature check to fail for missing signature file")
	}

	sandbox := NewPluginSandbox(50 * time.Millisecond)
	_, err = sandbox.ExecuteSandboxed(context.Background(), func(ctx context.Context) ([]models.Event, error) {
		time.Sleep(100 * time.Millisecond)
		return nil, nil
	})
	if err == nil {
		t.Errorf("expected timeout error from sandbox execution, got nil")
	}
}

func TestHotReloadAndMarketplace(t *testing.T) {
	dir := t.TempDir()
	watcher := NewHotReloadWatcher(dir, nil)
	watcher.Start(context.Background(), 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	watcher.Stop()

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"example.plugin","name":"Example","version":"1.0.0"}]`))
	}))
	defer registry.Close()
	mp := NewMarketplaceManager(registry.URL)
	plugins, err := mp.SearchPlugins(context.Background(), "nmap")
	if err != nil {
		t.Fatalf("SearchPlugins error: %v", err)
	}
	if len(plugins) == 0 {
		t.Errorf("expected marketplace plugins result, got empty")
	}
}

func TestMarketplaceRequiresExplicitTrustedRegistry(t *testing.T) {
	mp := NewMarketplaceManager("")
	if _, err := mp.SearchPlugins(context.Background(), "example"); err == nil {
		t.Fatal("expected marketplace search without an explicit registry to fail")
	}
	mp = NewMarketplaceManager("http://example.com/plugins")
	if _, err := mp.SearchPlugins(context.Background(), "example"); err == nil {
		t.Fatal("expected non-loopback HTTP marketplace registry to be rejected")
	}
}
