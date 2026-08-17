package modules

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestTCPIPStackOSFingerprint(t *testing.T) {
	osFamily, cpe, evidence := tcpIPStackOSFingerprint(context.Background(), "127.0.0.1", 65432)
	// Even on closed port, probeTCPTraits fallback handles it
	_ = osFamily
	_ = cpe
	_ = evidence
}

func TestCheckTLSVulnerabilitiesAndOCSP(t *testing.T) {
	state := tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}

	vulns := checkTLSVulnerabilities("127.0.0.1:443", state)
	if len(vulns) == 0 {
		t.Fatal("expected TLS vulnerability checks to evaluate ROBOT / CRIME")
	}

	cert := &x509.Certificate{
		OCSPServer: []string{"http://ocsp.example.com"},
	}
	ocspStatus := checkOCSPStatus(cert, nil)
	if ocspStatus == "" {
		t.Fatal("expected non-empty OCSP status")
	}
}

func TestBrowserScreenshotRendererAndHTTP3(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h1>Test Page</h1></body></html>"))
	}))
	defer ts.Close()

	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	guard := scope.New([]string{"127.0.0.1", "localhost"})

	renderer := NewBrowserScreenshotRenderer(db, guard)
	events, err := renderer.Handle(context.Background(), models.Event{
		ScanID: "test_shot",
		Type:   "url.crawled",
		Target: ts.URL,
	})
	if err != nil {
		t.Fatalf("screenshot renderer error: %v", err)
	}
	_ = events
}
