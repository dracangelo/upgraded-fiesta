package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

// DirectoryAPIEnumerator performs small, evidence-driven web enumeration. It
// deliberately uses a bounded request list: it is intended for an authorized
// recon scan, not as a high-volume content discovery tool.
type DirectoryAPIEnumerator struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	config models.HTTPConfig
	client *http.Client
}

func NewDirectoryAPIEnumerator(db *store.SQLiteCLI, guard scope.Guard, config models.HTTPConfig) *DirectoryAPIEnumerator {
	if config.MaxDirectoryPaths <= 0 {
		config.MaxDirectoryPaths = 80
	}
	return &DirectoryAPIEnumerator{
		db: db, guard: guard, config: config,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (m *DirectoryAPIEnumerator) Name() string            { return "directory_api_enumerator" }
func (m *DirectoryAPIEnumerator) Subscriptions() []string { return []string{EventHTTPURL} }

func (m *DirectoryAPIEnumerator) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	base, err := url.Parse(evt.Target)
	if err != nil || base.Hostname() == "" || !m.guard.Allowed(base.Hostname()) || eventDepth(evt) != 0 {
		return nil, nil
	}
	root := rootURL(base)
	_, landing, err := m.get(ctx, root.String())
	if err != nil {
		return nil, nil
	}

	paths := m.wordlist(landing)
	for _, path := range paths {
		m.probePath(ctx, evt.ScanID, root, path, "wordlist")
	}
	m.probeSensitiveFiles(ctx, evt.ScanID, root)
	m.generateFromJavaScript(ctx, evt.ScanID, root, landing)
	m.enumerateAPIs(ctx, evt.ScanID, root)
	return nil, nil
}

func (m *DirectoryAPIEnumerator) wordlist(landing string) []string {
	paths := []string{"/admin", "/login", "/api", "/api/v1", "/assets", "/uploads", "/health", "/metrics"}
	paths = append(paths, m.config.DirectoryWordlist...)
	lower := strings.ToLower(landing)
	switch {
	case strings.Contains(lower, "wp-content") || strings.Contains(lower, "wordpress"):
		paths = append(paths, "/wp-admin/", "/wp-login.php", "/wp-json/")
	case strings.Contains(lower, "drupal"):
		paths = append(paths, "/user/login", "/core/install.php")
	case strings.Contains(lower, "laravel"):
		paths = append(paths, "/telescope", "/_ignition/health-check")
	case strings.Contains(lower, "django"):
		paths = append(paths, "/admin/login/")
	case strings.Contains(lower, "jenkins"):
		paths = append(paths, "/login", "/api/json")
	}
	return uniquePaths(paths, m.config.MaxDirectoryPaths)
}

func (m *DirectoryAPIEnumerator) probePath(ctx context.Context, scanID string, root *url.URL, path, source string) {
	item, ok := scopedPath(root, path)
	if !ok {
		return
	}
	resp, _, err := m.get(ctx, item.String())
	if err != nil || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return
	}
	_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "directory", Value: item.String(), Parent: root.String(), Metadata: fmt.Sprintf("status=%s;source=%s", resp.Status, source)})
}

func (m *DirectoryAPIEnumerator) probeSensitiveFiles(ctx context.Context, scanID string, root *url.URL) {
	checks := []struct{ path, typ, title string }{
		{"/.git/HEAD", "git_exposure", "Git metadata exposed"},
		{"/.svn/entries", "svn_exposure", "SVN metadata exposed"},
		{"/.env", "environment_file", "Environment file exposed"},
		{"/.env.production", "environment_file", "Production environment file exposed"},
		{"/backup.zip", "backup_file", "Backup archive exposed"},
		{"/backup.tar.gz", "backup_file", "Backup archive exposed"},
		{"/db.sql", "backup_file", "Database dump exposed"},
	}
	for _, check := range checks {
		item, _ := scopedPath(root, check.path)
		resp, body, err := m.get(ctx, item.String())
		if err != nil || resp.StatusCode != http.StatusOK || len(body) == 0 {
			continue
		}
		if check.typ == "git_exposure" && !strings.HasPrefix(body, "ref:") {
			continue
		}
		_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: check.typ, Value: item.String(), Parent: root.String(), Metadata: "status=" + resp.Status})
		_ = m.db.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: "high", Confidence: "high", Asset: item.String(), Title: check.title, Evidence: "HTTP " + resp.Status, Remediation: "Remove the file from the web root and invalidate any exposed credentials or source history."})
	}
}

func (m *DirectoryAPIEnumerator) generateFromJavaScript(ctx context.Context, scanID string, root *url.URL, landing string) {
	for _, link := range extractLinks(root, landing) {
		if !strings.HasSuffix(strings.ToLower(link.Path), ".js") || link.Hostname() != root.Hostname() {
			continue
		}
		_, body, err := m.get(ctx, link.String())
		if err != nil {
			continue
		}
		for _, path := range uniquePaths(extractJSEndpoints(body), 40) {
			item, ok := scopedPath(root, path)
			if !ok {
				continue
			}
			_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "generated_wordlist_path", Value: item.String(), Parent: link.String(), Metadata: "source=javascript"})
			m.probePath(ctx, scanID, root, path, "javascript")
		}
	}
}

func (m *DirectoryAPIEnumerator) enumerateAPIs(ctx context.Context, scanID string, root *url.URL) {
	paths := append([]string(nil), m.config.APIPaths...)
	paths = append(paths, "/openapi.json", "/swagger.json", "/graphql", "/soap?wsdl", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo")
	for _, path := range uniquePaths(paths, 30) {
		item, ok := scopedPath(root, path)
		if !ok {
			continue
		}
		resp, body, err := m.get(ctx, item.String())
		if err != nil || resp.StatusCode >= 500 || resp.StatusCode == http.StatusNotFound {
			continue
		}
		kind := classifyAPI(path, resp, body)
		if kind == "" {
			continue
		}
		_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "api_endpoint", Value: item.String(), Parent: root.String(), Metadata: "kind=" + kind + ";status=" + resp.Status})
		switch kind {
		case "openapi", "swagger":
			m.validateOpenAPI(ctx, scanID, item.String(), body)
		case "graphql":
			m.extractGraphQLSchema(ctx, scanID, item)
		case "soap":
			m.extractSOAP(ctx, scanID, item.String(), body)
		case "grpc":
			m.probeGRPCReflection(ctx, scanID, item)
		}
	}
}

func (m *DirectoryAPIEnumerator) validateOpenAPI(ctx context.Context, scanID, endpoint, body string) {
	var spec struct {
		OpenAPI string                     `json:"openapi"`
		Swagger string                     `json:"swagger"`
		Paths   map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(body), &spec); err != nil || (spec.OpenAPI == "" && spec.Swagger == "") || len(spec.Paths) == 0 {
		_ = m.db.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: "low", Confidence: "high", Asset: endpoint, Title: "Invalid OpenAPI document", Evidence: "The endpoint was identified as OpenAPI/Swagger but has no version or paths object.", Remediation: "Publish a valid, access-controlled API description or remove the unintended endpoint."})
		return
	}
	_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "openapi_schema", Value: endpoint, Metadata: fmt.Sprintf("version=%s%s;paths=%d", spec.OpenAPI, spec.Swagger, len(spec.Paths))})
	for path := range spec.Paths {
		_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "openapi_operation_path", Value: path, Parent: endpoint})
	}
}

func (m *DirectoryAPIEnumerator) extractGraphQLSchema(ctx context.Context, scanID string, endpoint *url.URL) {
	query := `{"query":"{ __schema { queryType { name } types { name kind } } }"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewBufferString(query))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	var result struct {
		Data struct {
			Schema struct {
				QueryType struct {
					Name string `json:"name"`
				} `json:"queryType"`
				Types []struct {
					Name string `json:"name"`
					Kind string `json:"kind"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &result) != nil || result.Data.Schema.QueryType.Name == "" {
		return
	}
	_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "graphql_schema", Value: endpoint.String(), Metadata: "query_type=" + result.Data.Schema.QueryType.Name})
	for _, typ := range result.Data.Schema.Types {
		if strings.HasPrefix(typ.Name, "__") {
			continue
		}
		_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "graphql_type", Value: typ.Name, Parent: endpoint.String(), Metadata: "kind=" + typ.Kind})
	}
}

func (m *DirectoryAPIEnumerator) extractSOAP(ctx context.Context, scanID, endpoint, body string) {
	operations := regexp.MustCompile(`(?i)<(?:\w+:)?operation\b[^>]*\bname=["']([^"']+)`).FindAllStringSubmatch(body, -1)
	_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "soap_wsdl", Value: endpoint, Metadata: fmt.Sprintf("operations=%d", len(operations))})
	for _, match := range operations {
		if len(match) > 1 {
			_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "soap_operation", Value: match[1], Parent: endpoint})
		}
	}
}

func (m *DirectoryAPIEnumerator) probeGRPCReflection(ctx context.Context, scanID string, endpoint *url.URL) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 500 {
		_ = m.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "grpc_reflection", Value: endpoint.String(), Metadata: "status=" + resp.Status})
	}
}

func (m *DirectoryAPIEnumerator) get(ctx context.Context, target string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return resp, string(body), nil
}

func scopedPath(root *url.URL, path string) (*url.URL, bool) {
	item, err := root.Parse(path)
	if err != nil || item.Hostname() != root.Hostname() || (item.Scheme != "http" && item.Scheme != "https") {
		return nil, false
	}
	return item, true
}

func uniquePaths(paths []string, limit int) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] || (!strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://")) {
			continue
		}
		seen[path] = true
		result = append(result, path)
	}
	sort.Strings(result)
	if limit > 0 && len(result) > limit {
		return result[:limit]
	}
	return result
}
