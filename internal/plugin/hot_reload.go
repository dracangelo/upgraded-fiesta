package plugin

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type HotReloadWatcher struct {
	pluginDir  string
	manager    *PluginManager
	modTimes   map[string]time.Time
	mu         sync.Mutex
	stopChan   chan struct{}
}

func NewHotReloadWatcher(pluginDir string, manager *PluginManager) *HotReloadWatcher {
	return &HotReloadWatcher{
		pluginDir: pluginDir,
		manager:   manager,
		modTimes:  make(map[string]time.Time),
		stopChan:  make(chan struct{}),
	}
}

func (w *HotReloadWatcher) Start(ctx context.Context, checkInterval time.Duration) {
	if checkInterval <= 0 {
		checkInterval = 2 * time.Second
	}

	ticker := time.NewTicker(checkInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				w.checkAndReload(ctx)
			case <-w.stopChan:
				ticker.Stop()
				return
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func (w *HotReloadWatcher) Stop() {
	close(w.stopChan)
}

func (w *HotReloadWatcher) checkAndReload(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()

	entries, err := os.ReadDir(w.pluginDir)
	if err != nil {
		return
	}

	shouldReload := false
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(w.pluginDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		lastMod, exists := w.modTimes[filePath]
		if !exists || info.ModTime().After(lastMod) {
			w.modTimes[filePath] = info.ModTime()
			shouldReload = true
		}
	}

	if shouldReload && w.manager != nil {
		_ = w.manager.LoadPlugins(w.pluginDir)
	}
}
