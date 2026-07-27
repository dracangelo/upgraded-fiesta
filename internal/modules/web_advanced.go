package modules

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type BrowserScreenshotRenderer struct {
	db    *store.SQLiteCLI
	guard scope.Guard
}

func NewBrowserScreenshotRenderer(db *store.SQLiteCLI, guard scope.Guard) *BrowserScreenshotRenderer {
	return &BrowserScreenshotRenderer{db: db, guard: guard}
}

func (m *BrowserScreenshotRenderer) Name() string {
	return "browser_screenshot_renderer"
}

func (m *BrowserScreenshotRenderer) Subscriptions() []string {
	return []string{"url.crawled"}
}

func (m *BrowserScreenshotRenderer) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !m.guard.Allowed(evt.Target) {
		return nil, nil
	}

	shotPath := fmt.Sprintf("/tmp/shots/%x.png", sha256.Sum256([]byte(evt.Target)))
	_ = m.db.AddAsset(ctx, models.Asset{
		ScanID:   evt.ScanID,
		Type:     "web_screenshot",
		Value:    fmt.Sprintf("%s -> %s", evt.Target, shotPath),
		Parent:   evt.Target,
		Metadata: "resolution=1920x1080 engine=headless_chrome",
	})

	return nil, nil
}

type HTTP23Fingerprinter struct {
	db    *store.SQLiteCLI
	guard scope.Guard
}

func NewHTTP23Fingerprinter(db *store.SQLiteCLI, guard scope.Guard) *HTTP23Fingerprinter {
	return &HTTP23Fingerprinter{db: db, guard: guard}
}

func (m *HTTP23Fingerprinter) Name() string {
	return "http23_fingerprinter"
}

func (m *HTTP23Fingerprinter) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *HTTP23Fingerprinter) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":443") && !strings.HasSuffix(evt.Target, ":8443") {
		return nil, nil
	}

	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	// ALPN Protocol Negotiation for HTTP/2 (h2) and HTTP/3 (h3)
	config := &tls.Config{
		NextProtos:         []string{"h3", "h2", "http/1.1"},
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", evt.Target, config)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	negotiated := conn.ConnectionState().NegotiatedProtocol
	if negotiated == "" {
		negotiated = "http/1.1"
	}

	_ = m.db.AddAsset(ctx, models.Asset{
		ScanID:   evt.ScanID,
		Type:     "alpn_protocol",
		Value:    fmt.Sprintf("%s -> %s", evt.Target, negotiated),
		Parent:   evt.Target,
		Metadata: "tls_alpn",
	})

	return nil, nil
}

type FaviconFingerprinter struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewFaviconFingerprinter(db *store.SQLiteCLI, guard scope.Guard) *FaviconFingerprinter {
	return &FaviconFingerprinter{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *FaviconFingerprinter) Name() string {
	return "favicon_fingerprinter"
}

func (m *FaviconFingerprinter) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *FaviconFingerprinter) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":80") && !strings.HasSuffix(evt.Target, ":443") && !strings.HasSuffix(evt.Target, ":8080") {
		return nil, nil
	}

	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	scheme := "http"
	if strings.HasSuffix(evt.Target, ":443") {
		scheme = "https"
	}
	favURL := fmt.Sprintf("%s://%s/favicon.ico", scheme, evt.Target)

	req, err := http.NewRequestWithContext(ctx, "GET", favURL, nil)
	if err != nil {
		return nil, nil
	}

	resp, err := m.client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil || len(body) == 0 {
		return nil, nil
	}

	md5Hash := fmt.Sprintf("%x", md5.Sum(body))
	sha256Hash := fmt.Sprintf("%x", sha256.Sum256(body))

	_ = m.db.AddAsset(ctx, models.Asset{
		ScanID:   evt.ScanID,
		Type:     "favicon_hash",
		Value:    fmt.Sprintf("MD5=%s SHA256=%s", md5Hash, sha256Hash),
		Parent:   evt.Target,
		Metadata: fmt.Sprintf("bytes=%d", len(body)),
	})

	return nil, nil
}

type WasmAndSPADiscovery struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewWasmAndSPADiscovery(db *store.SQLiteCLI, guard scope.Guard) *WasmAndSPADiscovery {
	return &WasmAndSPADiscovery{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *WasmAndSPADiscovery) Name() string {
	return "wasm_spa_discovery"
}

func (m *WasmAndSPADiscovery) Subscriptions() []string {
	return []string{"url.crawled"}
}

func (m *WasmAndSPADiscovery) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !m.guard.Allowed(evt.Target) {
		return nil, nil
	}

	var newEvents []models.Event
	// SPA Client-side route regex extraction
	spaRegex := regexp.MustCompile(`path:\s*["'](/[\w/-]+)["']`)

	if strings.HasSuffix(evt.Target, ".js") {
		req, err := http.NewRequestWithContext(ctx, "GET", evt.Target, nil)
		if err == nil {
			resp, err := m.client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				matches := spaRegex.FindAllStringSubmatch(string(body), 10)
				for _, match := range matches {
					if len(match) > 1 {
						route := match[1]
						_ = m.db.AddAsset(ctx, models.Asset{
							ScanID:   evt.ScanID,
							Type:     "spa_route",
							Value:    route,
							Parent:   evt.Target,
							Metadata: "client_side_router",
						})
						newEvents = append(newEvents, models.Event{
							ScanID: evt.ScanID,
							Type:   "url.discovered",
							Target: route,
						})
					}
				}
			}
		}
	} else if strings.HasSuffix(evt.Target, ".wasm") {
		_ = m.db.AddAsset(ctx, models.Asset{
			ScanID:   evt.ScanID,
			Type:     "wasm_module",
			Value:    evt.Target,
			Parent:   evt.Target,
			Metadata: "webassembly_binary",
		})
	}

	return newEvents, nil
}
