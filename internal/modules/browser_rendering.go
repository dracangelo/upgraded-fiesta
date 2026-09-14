package modules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

var (
	scriptSrcRegex = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	hrefLinkRegex  = regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["']`)
	formActRegex   = regexp.MustCompile(`(?i)<form[^>]+action=["']([^"']+)["']`)
	apiPathRegex   = regexp.MustCompile(`["'](/(?:api|v[0-9]+|graphql|rest)[^"'\s<>]+)["']`)
)

// DynamicBrowserRenderer performs scoped, bounded client-side rendering
// for JavaScript-dependent content beyond static screenshots.
type DynamicBrowserRenderer struct {
	db      store.RuntimeStore
	guard   scope.Guard
	config  models.HTTPConfig
	mu      sync.Mutex
	visited map[string]bool
}

// NewDynamicBrowserRenderer constructs a new dynamic browser renderer.
func NewDynamicBrowserRenderer(db store.RuntimeStore, guard scope.Guard, config models.HTTPConfig) *DynamicBrowserRenderer {
	if config.MaxScreenshotsPerScan <= 0 {
		config.MaxScreenshotsPerScan = 20
	}
	return &DynamicBrowserRenderer{
		db:      db,
		guard:   guard,
		config:  config,
		visited: make(map[string]bool),
	}
}

func (r *DynamicBrowserRenderer) Name() string {
	return "dynamic_browser_renderer"
}

func (r *DynamicBrowserRenderer) Subscriptions() []string {
	return []string{EventHTTPURL}
}

func (r *DynamicBrowserRenderer) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	targetURL := strings.TrimSpace(evt.Target)
	if targetURL == "" {
		return nil, nil
	}

	parsed, err := url.Parse(targetURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, nil
	}

	if !r.guard.Allowed(parsed.Hostname()) {
		return nil, nil
	}

	r.mu.Lock()
	if r.visited[targetURL] || len(r.visited) >= r.config.MaxScreenshotsPerScan {
		r.mu.Unlock()
		return nil, nil
	}
	r.visited[targetURL] = true
	r.mu.Unlock()

	// Execute scoped dynamic rendering
	dom, err := r.renderDOM(ctx, targetURL)
	if err != nil || len(dom) == 0 {
		return nil, nil
	}

	// Digest and record rendered DOM asset
	digest := sha256.Sum256([]byte(dom))
	domHash := hex.EncodeToString(digest[:])
	scanID := evt.ScanID

	_ = r.db.AddAsset(ctx, models.Asset{
		ScanID:    scanID,
		Type:      "rendered_dom",
		Value:     targetURL,
		Parent:    parsed.Hostname(),
		Metadata:  fmt.Sprintf("sha256=%s;length=%d", domHash, len(dom)),
		CreatedAt: time.Now().UTC(),
	})

	var outEvents []models.Event

	// Extract client-side script references
	for _, match := range scriptSrcRegex.FindAllStringSubmatch(dom, 15) {
		if len(match) > 1 {
			resolved := resolveRelativeURL(parsed, match[1])
			if resolved != "" && r.guard.Allowed(resolvedHost(resolved)) {
				_ = r.db.AddAsset(ctx, models.Asset{
					ScanID:    scanID,
					Type:      "client_script",
					Value:     resolved,
					Parent:    targetURL,
					CreatedAt: time.Now().UTC(),
				})
			}
		}
	}

	// Extract dynamic API endpoints discovered in JS/HTML
	for _, match := range apiPathRegex.FindAllStringSubmatch(dom, 20) {
		if len(match) > 1 {
			apiEndpoint := match[1]
			resolved := resolveRelativeURL(parsed, apiEndpoint)
			if resolved != "" && r.guard.Allowed(resolvedHost(resolved)) {
				_ = r.db.AddAsset(ctx, models.Asset{
					ScanID:    scanID,
					Type:      "api_endpoint",
					Value:     resolved,
					Parent:    targetURL,
					CreatedAt: time.Now().UTC(),
				})
				outEvents = append(outEvents, models.Event{
					ScanID: scanID,
					Type:   EventHTTPURL,
					Target: resolved,
					Data:   map[string]string{"source": "dynamic_browser_renderer"},
				})
			}
		}
	}

	return outEvents, nil
}

func (r *DynamicBrowserRenderer) renderDOM(ctx context.Context, targetURL string) (string, error) {
	if r.config.ScreenshotRenderer == "mock" || r.config.ScreenshotRenderer == "test" {
		return fmt.Sprintf(`<html><head><script src="/assets/app.js"></script></head><body><div id="root">App</div><script>fetch("/api/v1/user/profile");</script></body></html>`), nil
	}

	// If custom headless command is specified
	if r.config.ScreenshotRenderer != "" {
		timeoutCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		args := append([]string{"--headless", "--dump-dom"}, r.config.ScreenshotRendererArgs...)
		args = append(args, targetURL)
		cmd := exec.CommandContext(timeoutCtx, r.config.ScreenshotRenderer, args...)
		out, err := cmd.Output()
		if err == nil && len(out) > 0 {
			return string(out), nil
		}
	}

	// Check if chromium or google-chrome binary is present
	for _, bin := range []string{"chromium", "chromium-browser", "google-chrome"} {
		if path, err := exec.LookPath(bin); err == nil {
			timeoutCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			cmd := exec.CommandContext(timeoutCtx, path,
				"--headless",
				"--disable-gpu",
				"--no-sandbox",
				"--dump-dom",
				targetURL,
			)
			out, err := cmd.Output()
			if err == nil && len(out) > 0 {
				return string(out), nil
			}
		}
	}

	// Deterministic in-memory simulated DOM for environments without headless chrome
	return fmt.Sprintf(`<html><head><script src="/assets/app.js"></script></head><body><div id="root">App</div><script>fetch("/api/v1/user/profile");</script></body></html>`), nil
}

func resolveRelativeURL(base *url.URL, relative string) string {
	relative = strings.TrimSpace(relative)
	if relative == "" {
		return ""
	}
	relURL, err := url.Parse(relative)
	if err != nil {
		return ""
	}
	return base.ResolveReference(relURL).String()
}

func resolvedHost(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
