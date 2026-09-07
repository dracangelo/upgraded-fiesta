package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxPluginPackageBytes = 16 << 20

type MarketplacePlugin struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Author      string          `json:"author"`
	Tags        []string        `json:"tags"`
	DownloadURL string          `json:"download_url"`
	SHA256      string          `json:"sha256"`
	Signature   string          `json:"signature"`
	Rating      float64         `json:"rating"`
	RatingCount int             `json:"rating_count"`
	Community   bool            `json:"community"`
	Versions    []PluginVersion `json:"versions,omitempty"`
}

type PluginVersion struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
	Signature   string `json:"signature"`
}

type PluginPackage struct {
	Manifest PluginManifest    `json:"manifest"`
	Files    map[string]string `json:"files"`
}

type MarketplaceManager struct {
	registryURL string
	client      *http.Client
	trustedKey  ed25519.PublicKey
	installDir  string
}

func NewMarketplaceManager(registryURL string) *MarketplaceManager {
	return NewTrustedMarketplaceManager(registryURL, nil, "")
}

func NewTrustedMarketplaceManager(registryURL string, trustedKey ed25519.PublicKey, installDir string) *MarketplaceManager {
	return &MarketplaceManager{registryURL: strings.TrimSpace(registryURL), trustedKey: append(ed25519.PublicKey(nil), trustedKey...), installDir: installDir, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (m *MarketplaceManager) SearchPlugins(ctx context.Context, query string) ([]MarketplacePlugin, error) {
	endpoint, err := m.apiEndpoint("/v1/plugins")
	if err != nil {
		return nil, err
	}
	parameters := endpoint.Query()
	parameters.Set("q", strings.TrimSpace(query))
	endpoint.RawQuery = parameters.Encode()
	var envelope struct {
		Plugins []MarketplacePlugin `json:"plugins"`
	}
	body, err := m.get(ctx, endpoint.String(), 1<<20)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(body, &envelope.Plugins) == nil {
		return envelope.Plugins, nil
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode marketplace registry response: %w", err)
	}
	return envelope.Plugins, nil
}

func (m *MarketplaceManager) GetPlugin(ctx context.Context, id string) (MarketplacePlugin, error) {
	endpoint, err := m.apiEndpoint("/v1/plugins/" + url.PathEscape(id))
	if err != nil {
		return MarketplacePlugin{}, err
	}
	body, err := m.get(ctx, endpoint.String(), 1<<20)
	if err != nil {
		return MarketplacePlugin{}, err
	}
	var plugin MarketplacePlugin
	if err := json.Unmarshal(body, &plugin); err != nil {
		return plugin, fmt.Errorf("decode marketplace plugin: %w", err)
	}
	return plugin, nil
}

func (m *MarketplaceManager) Install(ctx context.Context, id, version string) (string, error) {
	if len(m.trustedKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("trusted marketplace public key is not configured")
	}
	if strings.TrimSpace(m.installDir) == "" {
		return "", fmt.Errorf("plugin install directory is not configured")
	}
	plugin, err := m.GetPlugin(ctx, id)
	if err != nil {
		return "", err
	}
	selected, err := selectPluginVersion(plugin, version)
	if err != nil {
		return "", err
	}
	if !validSemver(selected.Version) {
		return "", fmt.Errorf("registry returned an invalid plugin version")
	}
	if _, err := registryEndpoint(selected.DownloadURL); err != nil {
		return "", fmt.Errorf("unsafe plugin download URL: %w", err)
	}
	payload, err := m.get(ctx, selected.DownloadURL, maxPluginPackageBytes)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), selected.SHA256) {
		return "", fmt.Errorf("plugin package checksum mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(selected.Signature)
	if err != nil || !ed25519.Verify(m.trustedKey, payload, signature) {
		return "", fmt.Errorf("plugin package signature verification failed")
	}
	var archive PluginPackage
	if err := json.Unmarshal(payload, &archive); err != nil {
		return "", fmt.Errorf("decode plugin package: %w", err)
	}
	if err := archive.Manifest.Validate(); err != nil {
		return "", err
	}
	if archive.Manifest.Name != plugin.Name || archive.Manifest.Version != selected.Version {
		return "", fmt.Errorf("plugin package identity does not match registry metadata")
	}
	return installVerifiedPackage(m.installDir, id, archive, payload, signature)
}

func (m *MarketplaceManager) Update(ctx context.Context, id string) (string, error) {
	return m.Install(ctx, id, "")
}

func (m *MarketplaceManager) RatePlugin(ctx context.Context, id string, rating int) error {
	if rating < 1 || rating > 5 {
		return fmt.Errorf("rating must be between 1 and 5")
	}
	endpoint, err := m.apiEndpoint("/v1/plugins/" + url.PathEscape(id) + "/ratings")
	if err != nil {
		return err
	}
	payload := strings.NewReader(fmt.Sprintf(`{"rating":%d}`, rating))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), payload)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("rate marketplace plugin: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("marketplace registry returned %s", resp.Status)
	}
	return nil
}

func (m *MarketplaceManager) apiEndpoint(path string) (*url.URL, error) {
	base, err := registryEndpoint(m.registryURL)
	if err != nil {
		return nil, err
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	base.RawQuery = ""
	return base, nil
}

func (m *MarketplaceManager) get(ctx context.Context, endpoint string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request marketplace registry: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("marketplace registry returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("marketplace response exceeds size limit")
	}
	return body, nil
}

func selectPluginVersion(plugin MarketplacePlugin, requested string) (PluginVersion, error) {
	if requested == "" || requested == plugin.Version {
		return PluginVersion{Version: plugin.Version, DownloadURL: plugin.DownloadURL, SHA256: plugin.SHA256, Signature: plugin.Signature}, nil
	}
	for _, version := range plugin.Versions {
		if version.Version == requested {
			return version, nil
		}
	}
	return PluginVersion{}, fmt.Errorf("plugin version %q is not available", requested)
}

func installVerifiedPackage(root, id string, archive PluginPackage, signedPackage, signature []byte) (string, error) {
	if !safePluginComponent(id) || !safePluginComponent(archive.Manifest.Version) {
		return "", fmt.Errorf("unsafe plugin identity or version")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	target := filepath.Join(root, id, archive.Manifest.Version)
	if _, err := os.Stat(target); err == nil {
		if err := os.WriteFile(filepath.Join(root, id, "current"), []byte(archive.Manifest.Version+"\n"), 0600); err != nil {
			return "", err
		}
		return target, nil
	}
	staging, err := os.MkdirTemp(root, ".plugin-install-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	for name, encoded := range archive.Files {
		if filepath.Base(name) != name || !safePluginComponent(name) {
			return "", fmt.Errorf("unsafe plugin package path %q", name)
		}
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("decode plugin file %q: %w", name, err)
		}
		mode := os.FileMode(0600)
		if archive.Manifest.Type == "grpc" && name == archive.Manifest.Exec {
			mode = 0700
		}
		if err := os.WriteFile(filepath.Join(staging, name), content, mode); err != nil {
			return "", err
		}
	}
	if _, ok := archive.Files[archive.Manifest.Exec]; archive.Manifest.Type == "lua" && !ok {
		return "", fmt.Errorf("plugin entrypoint is missing from package")
	}
	if archive.Manifest.Type == "lua" {
		archive.Manifest.Exec = filepath.Join(target, archive.Manifest.Exec)
	}
	manifest, _ := json.MarshalIndent(archive.Manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(staging, "manifest.json"), manifest, 0600); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(staging, "package.epk"), signedPackage, 0600); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(staging, "package.sig"), []byte(base64.StdEncoding.EncodeToString(signature)), 0600); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return "", err
	}
	if err := os.Rename(staging, target); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(root, id, "current"), []byte(archive.Manifest.Version+"\n"), 0600); err != nil {
		return "", err
	}
	return target, nil
}

func safePluginComponent(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.ContainsAny(value, "/\\\x00")
}

// registryEndpoint has no default public service. TLS is mandatory except for
// an explicitly configured loopback development registry.
func registryEndpoint(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("plugin marketplace registry is not configured")
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Host == "" || endpoint.User != nil {
		return nil, fmt.Errorf("invalid plugin marketplace registry URL")
	}
	if endpoint.Scheme == "https" {
		return endpoint, nil
	}
	host := strings.ToLower(endpoint.Hostname())
	if endpoint.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
		return endpoint, nil
	}
	return nil, fmt.Errorf("plugin marketplace registry must use HTTPS (HTTP is allowed only for loopback development)")
}
