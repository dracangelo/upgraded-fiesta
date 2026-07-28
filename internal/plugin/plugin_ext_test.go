package plugin

import (
	"context"
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

	mp := NewMarketplaceManager("")
	plugins, err := mp.SearchPlugins(context.Background(), "nmap")
	if err != nil {
		t.Fatalf("SearchPlugins error: %v", err)
	}
	if len(plugins) == 0 {
		t.Errorf("expected marketplace plugins result, got empty")
	}
}
