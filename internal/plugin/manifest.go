package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type PluginManifest struct {
	Name          string   `yaml:"name" json:"name"`
	Version       string   `yaml:"version" json:"version"`
	Author        string   `yaml:"author" json:"author"`
	Description   string   `yaml:"description" json:"description"`
	Type          string   `yaml:"type" json:"type"` // "grpc" or "lua"
	Exec          string   `yaml:"exec" json:"exec"` // executable command or lua script path
	Permissions   []string `yaml:"permissions" json:"permissions"`
	Subscriptions []string `yaml:"subscriptions" json:"subscriptions"`
}

func LoadManifest(path string) (*PluginManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest file: %w", err)
	}

	var manifest PluginManifest
	if jsonErr := json.Unmarshal(data, &manifest); jsonErr == nil && manifest.Name != "" {
		if err := manifest.Validate(); err != nil {
			return nil, fmt.Errorf("invalid manifest: %w", err)
		}
		return &manifest, nil
	}

	// Line-based simple YAML parser
	lines := strings.Split(string(data), "\n")
	var currentList *[]string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if currentList != nil {
				*currentList = append(*currentList, item)
			}
			continue
		}

		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.Trim(strings.TrimSpace(parts[1]), "\"")

		switch key {
		case "name":
			manifest.Name = val
			currentList = nil
		case "version":
			manifest.Version = val
			currentList = nil
		case "author":
			manifest.Author = val
			currentList = nil
		case "description":
			manifest.Description = val
			currentList = nil
		case "type":
			manifest.Type = val
			currentList = nil
		case "exec":
			manifest.Exec = val
			currentList = nil
		case "permissions":
			currentList = &manifest.Permissions
		case "subscriptions":
			currentList = &manifest.Subscriptions
		}
	}

	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	return &manifest, nil
}

func (m *PluginManifest) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("plugin name is required")
	}
	if m.Type != "grpc" && m.Type != "lua" {
		return fmt.Errorf("plugin type must be 'grpc' or 'lua', got %q", m.Type)
	}
	if m.Exec == "" {
		return fmt.Errorf("plugin exec target is required")
	}
	if len(m.Subscriptions) == 0 {
		return fmt.Errorf("plugin must specify at least one event subscription")
	}
	return nil
}
