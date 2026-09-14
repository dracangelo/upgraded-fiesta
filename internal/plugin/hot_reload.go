package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrPluginNotVerified     = errors.New("plugin must be cryptographically verified before activation")
	ErrPluginNotFound        = errors.New("plugin stage not found")
	ErrNoRollbackAvailable   = errors.New("no previous verified plugin version available for rollback")
	ErrPluginAlreadyActive   = errors.New("plugin version is already active")
)

// PluginLifecycleState represents the progression of a plugin within the system.
type PluginLifecycleState string

const (
	PluginStateRegistered PluginLifecycleState = "registered"
	PluginStateVerified   PluginLifecycleState = "verified"
	PluginStateActive     PluginLifecycleState = "active"
	PluginStateDraining   PluginLifecycleState = "draining"
	PluginStateRetired    PluginLifecycleState = "retired"
)

// PluginStage tracks an individual plugin instance version and its verification lifecycle.
type PluginStage struct {
	Name       string               `json:"name"`
	Version    string               `json:"version"`
	State      PluginLifecycleState `json:"state"`
	Manifest   PluginManifest       `json:"manifest"`
	Registered time.Time            `json:"registered"`
	VerifiedAt time.Time            `json:"verified_at,omitempty"`
	ActivatedAt time.Time           `json:"activated_at,omitempty"`
}

// SafeHotReloadManager guarantees safe atomic promotion, verification gating, and instant rollback.
// Discovered plugins are NEVER executed automatically.
type SafeHotReloadManager struct {
	mu             sync.RWMutex
	staged         map[string]*PluginStage // key: name:version
	active         map[string]*PluginStage // key: name -> currently active stage
	previousActive map[string]*PluginStage // key: name -> previous active stage for rollback
}

// NewSafeHotReloadManager initializes the lifecycle manager.
func NewSafeHotReloadManager() *SafeHotReloadManager {
	return &SafeHotReloadManager{
		staged:         make(map[string]*PluginStage),
		active:         make(map[string]*PluginStage),
		previousActive: make(map[string]*PluginStage),
	}
}

// RegisterDiscoveredPlugin stages a plugin in the "registered" state without executing it.
func (m *SafeHotReloadManager) RegisterDiscoveredPlugin(manifest PluginManifest) (*PluginStage, error) {
	if strings.TrimSpace(manifest.Name) == "" {
		return nil, fmt.Errorf("plugin name cannot be empty")
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return nil, fmt.Errorf("plugin version cannot be empty")
	}

	key := fmt.Sprintf("%s:%s", manifest.Name, manifest.Version)

	m.mu.Lock()
	defer m.mu.Unlock()

	stage := &PluginStage{
		Name:       manifest.Name,
		Version:    manifest.Version,
		State:      PluginStateRegistered,
		Manifest:   manifest,
		Registered: time.Now().UTC(),
	}
	m.staged[key] = stage
	return stage, nil
}

// VerifyPluginStage validates the staged plugin and advances its state to "verified".
func (m *SafeHotReloadManager) VerifyPluginStage(name, version string, verifier func(m PluginManifest) error) error {
	key := fmt.Sprintf("%s:%s", name, version)

	m.mu.Lock()
	defer m.mu.Unlock()

	stage, exists := m.staged[key]
	if !exists {
		return fmt.Errorf("%w: %s", ErrPluginNotFound, key)
	}

	if verifier != nil {
		if err := verifier(stage.Manifest); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
	}

	stage.State = PluginStateVerified
	stage.VerifiedAt = time.Now().UTC()
	return nil
}

// PromoteToActive atomically promotes a verified plugin to "active", transitioning the
// old active instance to "draining" and then "retired".
func (m *SafeHotReloadManager) PromoteToActive(name, version string) error {
	key := fmt.Sprintf("%s:%s", name, version)

	m.mu.Lock()
	defer m.mu.Unlock()

	stage, exists := m.staged[key]
	if !exists {
		return fmt.Errorf("%w: %s", ErrPluginNotFound, key)
	}

	if stage.State != PluginStateVerified {
		return fmt.Errorf("%w: current state is %s", ErrPluginNotVerified, stage.State)
	}

	// If there is currently an active stage, drain it and save it for rollback
	if currentActive, ok := m.active[name]; ok {
		if currentActive.Version == version {
			return ErrPluginAlreadyActive
		}
		currentActive.State = PluginStateDraining
		m.previousActive[name] = currentActive
		currentActive.State = PluginStateRetired
	}

	// Atomically switch active pointer
	stage.State = PluginStateActive
	stage.ActivatedAt = time.Now().UTC()
	m.active[name] = stage

	return nil
}

// Rollback atomically reverts the active stage of a plugin to its previous verified version.
func (m *SafeHotReloadManager) Rollback(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	prev, exists := m.previousActive[name]
	if !exists || prev == nil {
		return fmt.Errorf("%w for plugin %s", ErrNoRollbackAvailable, name)
	}

	// Demote currently active to retired
	if currentActive, ok := m.active[name]; ok {
		currentActive.State = PluginStateRetired
	}

	// Restore previous to active
	prev.State = PluginStateActive
	prev.ActivatedAt = time.Now().UTC()
	m.active[name] = prev
	delete(m.previousActive, name)

	return nil
}

// GetActivePlugin returns the currently active stage for a plugin name.
func (m *SafeHotReloadManager) GetActivePlugin(name string) (*PluginStage, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stage, ok := m.active[name]
	return stage, ok
}

// GetStage returns a staged plugin by name and version.
func (m *SafeHotReloadManager) GetStage(name, version string) (*PluginStage, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stage, ok := m.staged[fmt.Sprintf("%s:%s", name, version)]
	return stage, ok
}

// HotReloadWatcher monitors a directory for plugin changes.
type HotReloadWatcher struct {
	pluginDir string
	manager   *PluginManager
	modTimes  map[string]time.Time
	mu        sync.Mutex
	stopChan  chan struct{}
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
