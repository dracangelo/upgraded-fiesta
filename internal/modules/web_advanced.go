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

	"github.com/quic-go/quic-go/http3"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type HTTP2Fingerprinter struct {
	db          *store.SQLiteCLI
	guard       scope.Guard
	enableHTTP3 bool
}

func NewHTTP2Fingerprinter(db *store.SQLiteCLI, guard scope.Guard) *HTTP2Fingerprinter {
	return &HTTP2Fingerprinter{db: db, guard: guard}
}

// NewHTTP2FingerprinterWithHTTP3 enables a bounded HTTP/3 confirmation only
// when the operator opts in. HTTP/3 confirmation is restricted to literal IP
// targets so QUIC transport never introduces a second DNS resolution path.
func NewHTTP2FingerprinterWithHTTP3(db *store.SQLiteCLI, guard scope.Guard, enableHTTP3 bool) *HTTP2Fingerprinter {
	return &HTTP2Fingerprinter{db: db, guard: guard, enableHTTP3: enableHTTP3}
}

func (m *HTTP2Fingerprinter) Name() string {
	return "http2_fingerprinter"
}

func (m *HTTP2Fingerprinter) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *HTTP2Fingerprinter) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":443") && !strings.HasSuffix(evt.Target, ":8443") {
		return nil, nil
	}

	targetIP := eventHost(evt.Target)

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	// Negotiate ALPN including HTTP/3 (h3), HTTP/2 (h2), and HTTP/1.1
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

	// Check for Alt-Svc HTTP/3 header advertisement
	if h3Supported := checkHTTP3AltSvc(ctx, evt.Target, m.guard); h3Supported {
		_ = m.db.AddAsset(ctx, models.Asset{
			ScanID:   evt.ScanID,
			Type:     "alpn_protocol",
			Value:    fmt.Sprintf("%s -> h3 (HTTP/3 QUIC)", evt.Target),
			Parent:   evt.Target,
			Metadata: "quic_alt_svc_advertised",
		})
		if m.enableHTTP3 {
			if status, ok := probeHTTP3(ctx, evt.Target); ok {
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "http3_transport",
					Value:    fmt.Sprintf("%s -> HTTP/3", evt.Target),
					Parent:   evt.Target,
					Metadata: fmt.Sprintf("verification=observed;method=HEAD;status=%d", status),
				})
			}
		}
	}

	return nil, nil
}

func checkHTTP3AltSvc(ctx context.Context, target string, guard scope.Guard) bool {
	client := scopedHTTPClient(guard, 2*time.Second, &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}})
	req, err := http.NewRequestWithContext(ctx, "HEAD", "https://"+target, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	altSvc := resp.Header.Get("Alt-Svc")
	return strings.Contains(altSvc, "h3") || strings.Contains(altSvc, "quic")
}

// probeHTTP3 confirms an advertised HTTP/3 service with a read-only HEAD
// request. It does not follow redirects and accepts literal IP targets only,
// keeping QUIC traffic inside the already-authorized port-scan endpoint.
func probeHTTP3(ctx context.Context, target string) (int, bool) {
	host, _, err := net.SplitHostPort(target)
	if err != nil || net.ParseIP(host) == nil {
		return 0, false
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}
	defer transport.Close()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(probeCtx, http.MethodHead, "https://"+target, nil)
	if err != nil {
		return 0, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.ProtoMajor == 3
}

func NewHTTP23Fingerprinter(db *store.SQLiteCLI, guard scope.Guard) *HTTP2Fingerprinter {
	return NewHTTP2Fingerprinter(db, guard)
}

type FaviconFingerprinter struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewFaviconFingerprinter(db *store.SQLiteCLI, guard scope.Guard) *FaviconFingerprinter {
	return &FaviconFingerprinter{
		db:     db,
		guard:  guard,
		client: scopedHTTPClient(guard, 3*time.Second, nil),
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

	targetIP := eventHost(evt.Target)

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
		db:     db,
		guard:  guard,
		client: scopedHTTPClient(guard, 3*time.Second, nil),
	}
}

func (m *WasmAndSPADiscovery) Name() string {
	return "wasm_spa_discovery"
}

func (m *WasmAndSPADiscovery) Subscriptions() []string {
	return []string{EventHTTPURL}
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
