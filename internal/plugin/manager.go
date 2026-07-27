package plugin

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type PluginManager struct {
	db        *store.SQLiteCLI
	guard     scope.Guard
	manifests []*PluginManifest
}

func NewManager(db *store.SQLiteCLI, guard scope.Guard, pluginDir string) (*PluginManager, error) {
	pm := &PluginManager{db: db, guard: guard}
	if pluginDir != "" {
		_ = pm.LoadPlugins(pluginDir)
	}
	return pm, nil
}

func (pm *PluginManager) LoadPlugins(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasPrefix(name, "plugin") && !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".json")) {
			continue
		}
		path := filepath.Join(dir, name)
		manifest, err := LoadManifest(path)
		if err == nil {
			pm.manifests = append(pm.manifests, manifest)
		}
	}
	return nil
}

func (pm *PluginManager) RegisterPlugin(manifest *PluginManifest) {
	pm.manifests = append(pm.manifests, manifest)
}

func (pm *PluginManager) Name() string {
	return "plugin_sdk"
}

func (pm *PluginManager) Subscriptions() []string {
	var subs []string
	subMap := make(map[string]bool)
	for _, m := range pm.manifests {
		for _, s := range m.Subscriptions {
			if !subMap[s] {
				subMap[s] = true
				subs = append(subs, s)
			}
		}
	}
	return subs
}

func (pm *PluginManager) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	if event.Target != "" && !pm.guard.Allowed(event.Target) {
		return nil, nil
	}

	var newEvents []models.Event
	for _, m := range pm.manifests {
		if !subscribesTo(m.Subscriptions, event.Type) {
			continue
		}

		switch m.Type {
		case "lua":
			runner := NewLuaRunner(m)
			res, err := runner.Execute(ctx, event)
			if err != nil {
				continue
			}
			for _, a := range res.Assets {
				_ = pm.db.AddAsset(ctx, a)
			}
			for _, f := range res.Findings {
				_ = pm.db.AddFinding(ctx, f)
			}
			newEvents = append(newEvents, res.Events...)
		case "grpc":
			host := NewGRPCHost(m)
			res, err := host.Execute(ctx, event)
			if err != nil {
				continue
			}
			for _, a := range res.Assets {
				_ = pm.db.AddAsset(ctx, a)
			}
			for _, f := range res.Findings {
				_ = pm.db.AddFinding(ctx, f)
			}
			newEvents = append(newEvents, res.Events...)
		}
	}

	return newEvents, nil
}

func subscribesTo(subs []string, eventType string) bool {
	for _, s := range subs {
		if s == eventType || s == "*" {
			return true
		}
	}
	return false
}
