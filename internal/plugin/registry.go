package plugin

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type RegistryPublication struct {
	ID        string            `json:"id"`
	Manifest  PluginManifest    `json:"manifest"`
	Files     map[string]string `json:"files"`
	Tags      []string          `json:"tags"`
	Community bool              `json:"community"`
}

type Registry struct {
	mu      sync.RWMutex
	baseURL string
	private ed25519.PrivateKey
	plugins map[string]map[string]registryRelease
	ratings map[string][]int
}

type registryRelease struct {
	Metadata MarketplacePlugin
	Package  []byte
}

func NewRegistry(baseURL string, privateKey ed25519.PrivateKey) (*Registry, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("registry requires an Ed25519 signing key")
	}
	if _, err := registryEndpoint(baseURL); err != nil {
		return nil, fmt.Errorf("registry public URL: %w", err)
	}
	return &Registry{baseURL: strings.TrimRight(baseURL, "/"), private: append(ed25519.PrivateKey(nil), privateKey...), plugins: make(map[string]map[string]registryRelease), ratings: make(map[string][]int)}, nil
}

func (r *Registry) LoadCatalog(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read registry catalog: %w", err)
	}
	var publications []RegistryPublication
	if err := json.Unmarshal(data, &publications); err != nil {
		return fmt.Errorf("decode registry catalog: %w", err)
	}
	for _, publication := range publications {
		files := make(map[string][]byte, len(publication.Files))
		for name, encoded := range publication.Files {
			content, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return fmt.Errorf("decode %s file %q: %w", publication.ID, name, err)
			}
			files[name] = content
		}
		if err := r.Publish(publication.ID, publication.Manifest, files, publication.Tags, publication.Community); err != nil {
			return fmt.Errorf("publish %s: %w", publication.ID, err)
		}
	}
	return nil
}

// Publish signs the exact package served by the registry. Community releases
// use the same registry signature and client-side trust root as first-party ones.
func (r *Registry) Publish(id string, manifest PluginManifest, files map[string][]byte, tags []string, community bool) error {
	if !safePluginComponent(id) || !validSemver(manifest.Version) {
		return fmt.Errorf("invalid plugin id or semantic version")
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	encodedFiles := make(map[string]string, len(files))
	for name, content := range files {
		if filepathUnsafe(name) {
			return fmt.Errorf("unsafe plugin package path %q", name)
		}
		encodedFiles[name] = base64.StdEncoding.EncodeToString(content)
	}
	payload, err := json.Marshal(PluginPackage{Manifest: manifest, Files: encodedFiles})
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	signature := ed25519.Sign(r.private, payload)
	download := r.baseURL + "/v1/plugins/" + id + "/" + manifest.Version + "/download"
	metadata := MarketplacePlugin{ID: id, Name: manifest.Name, Version: manifest.Version, Description: manifest.Description, Author: manifest.Author, Tags: append([]string(nil), tags...), DownloadURL: download, SHA256: hex.EncodeToString(digest[:]), Signature: base64.StdEncoding.EncodeToString(signature), Community: community}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.plugins[id] == nil {
		r.plugins[id] = make(map[string]registryRelease)
	}
	if _, exists := r.plugins[id][manifest.Version]; exists {
		return fmt.Errorf("plugin version already exists")
	}
	r.plugins[id][manifest.Version] = registryRelease{Metadata: metadata, Package: payload}
	return nil
}

func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.Trim(strings.TrimPrefix(req.URL.Path, "/v1/plugins"), "/")
	if path == "" && req.Method == http.MethodGet {
		r.search(w, req)
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) == 1 && req.Method == http.MethodGet {
		r.describe(w, parts[0])
		return
	}
	if len(parts) == 2 && parts[1] == "ratings" && req.Method == http.MethodPost {
		r.rate(w, req, parts[0])
		return
	}
	if len(parts) == 3 && parts[2] == "download" && req.Method == http.MethodGet {
		r.download(w, parts[0], parts[1])
		return
	}
	http.NotFound(w, req)
}

func (r *Registry) search(w http.ResponseWriter, req *http.Request) {
	query := strings.ToLower(strings.TrimSpace(req.URL.Query().Get("q")))
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]MarketplacePlugin, 0, len(r.plugins))
	for id := range r.plugins {
		plugin, ok := r.latestLocked(id)
		if !ok || (query != "" && !strings.Contains(strings.ToLower(plugin.Name+" "+plugin.Description+" "+strings.Join(plugin.Tags, " ")), query)) {
			continue
		}
		plugin.Rating, plugin.RatingCount = ratingSummary(r.ratings[id])
		result = append(result, plugin)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	_ = json.NewEncoder(w).Encode(result)
}

func (r *Registry) describe(w http.ResponseWriter, id string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	plugin, ok := r.latestLocked(id)
	if !ok {
		http.Error(w, `{"error":"plugin not found"}`, http.StatusNotFound)
		return
	}
	for _, release := range r.plugins[id] {
		plugin.Versions = append(plugin.Versions, PluginVersion{Version: release.Metadata.Version, DownloadURL: release.Metadata.DownloadURL, SHA256: release.Metadata.SHA256, Signature: release.Metadata.Signature})
	}
	sort.Slice(plugin.Versions, func(i, j int) bool { return compareSemver(plugin.Versions[i].Version, plugin.Versions[j].Version) > 0 })
	plugin.Rating, plugin.RatingCount = ratingSummary(r.ratings[id])
	_ = json.NewEncoder(w).Encode(plugin)
}

func (r *Registry) rate(w http.ResponseWriter, req *http.Request, id string) {
	var input struct {
		Rating int `json:"rating"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, req.Body, 1024)).Decode(&input) != nil || input.Rating < 1 || input.Rating > 5 {
		http.Error(w, `{"error":"rating must be 1-5"}`, http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.plugins[id]; !exists {
		http.NotFound(w, req)
		return
	}
	r.ratings[id] = append(r.ratings[id], input.Rating)
	w.WriteHeader(http.StatusNoContent)
}

func (r *Registry) download(w http.ResponseWriter, id, version string) {
	r.mu.RLock()
	release, ok := r.plugins[id][version]
	r.mu.RUnlock()
	if !ok {
		http.Error(w, `{"error":"plugin version not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.enumscan.plugin+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(release.Package)
}

func (r *Registry) latestLocked(id string) (MarketplacePlugin, bool) {
	var selected MarketplacePlugin
	found := false
	for _, release := range r.plugins[id] {
		if !found || compareSemver(release.Metadata.Version, selected.Version) > 0 {
			selected, found = release.Metadata, true
		}
	}
	return selected, found
}

func ratingSummary(values []int) (float64, int) {
	if len(values) == 0 {
		return 0, 0
	}
	total := 0
	for _, value := range values {
		total += value
	}
	return float64(total) / float64(len(values)), len(values)
}

func validSemver(value string) bool {
	parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

func compareSemver(left, right string) int {
	a, b := strings.Split(strings.TrimPrefix(left, "v"), "."), strings.Split(strings.TrimPrefix(right, "v"), ".")
	for index := 0; index < 3; index++ {
		ai, _ := strconv.Atoi(a[index])
		bi, _ := strconv.Atoi(b[index])
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

func filepathUnsafe(name string) bool {
	return !safePluginComponent(name)
}
