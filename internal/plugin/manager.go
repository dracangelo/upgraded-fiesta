package plugin

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type PluginManager struct {
	db        store.RuntimeStore
	guard     scope.Guard
	manifests []*PluginManifest
}

func NewManager(db store.RuntimeStore, guard scope.Guard, pluginDir string) (*PluginManager, error) {
	pm := &PluginManager{db: db, guard: guard}
	if pluginDir != "" {
		if err := pm.LoadPlugins(pluginDir); err != nil {
			return nil, err
		}
	}
	return pm, nil
}

func (pm *PluginManager) LoadPlugins(dir string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve plugin directory: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	manifests := make([]*PluginManifest, 0, len(entries))
	seenNames := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension != ".yaml" && extension != ".yml" && extension != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		manifest, err := LoadManifest(path)
		if err != nil {
			return fmt.Errorf("load plugin manifest %s: %w", entry.Name(), err)
		}
		if _, duplicate := seenNames[manifest.Name]; duplicate {
			return fmt.Errorf("duplicate plugin manifest name %q", manifest.Name)
		}
		seenNames[manifest.Name] = struct{}{}
		manifests = append(manifests, manifest)
	}
	pm.manifests = manifests
	return nil
}

func (pm *PluginManager) RegisterPlugin(manifest *PluginManifest) {
	pm.manifests = append(pm.manifests, manifest)
}

// LoadInstalled verifies the registry signature and every installed file
// before explicitly activating one plugin. Scans never call this implicitly.
func (pm *PluginManager) LoadInstalled(root, id string, trustedKey ed25519.PublicKey) error {
	if !safePluginComponent(id) || len(trustedKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid plugin id or trusted key")
	}
	versionBytes, err := os.ReadFile(filepath.Join(root, id, "current"))
	if err != nil {
		return fmt.Errorf("read installed plugin version: %w", err)
	}
	version := strings.TrimSpace(string(versionBytes))
	if !safePluginComponent(version) {
		return fmt.Errorf("invalid installed plugin version")
	}
	dir := filepath.Join(root, id, version)
	payload, err := os.ReadFile(filepath.Join(dir, "package.epk"))
	if err != nil {
		return fmt.Errorf("read installed plugin package: %w", err)
	}
	signatureText, err := os.ReadFile(filepath.Join(dir, "package.sig"))
	if err != nil {
		return fmt.Errorf("read installed plugin signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureText)))
	if err != nil || !ed25519.Verify(trustedKey, payload, signature) {
		return fmt.Errorf("installed plugin signature verification failed")
	}
	var archive PluginPackage
	if err := json.Unmarshal(payload, &archive); err != nil {
		return fmt.Errorf("decode installed plugin package: %w", err)
	}
	if archive.Manifest.Version != version {
		return fmt.Errorf("installed plugin version does not match signed package")
	}
	for name, encoded := range archive.Files {
		expected, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("decode signed plugin file: %w", err)
		}
		actual, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(actual) != string(expected) {
			return fmt.Errorf("installed plugin file %q failed verification", name)
		}
	}
	manifest := archive.Manifest
	if manifest.Type == "lua" {
		manifest.Exec = filepath.Join(dir, manifest.Exec)
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	pm.RegisterPlugin(&manifest)
	return nil
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
