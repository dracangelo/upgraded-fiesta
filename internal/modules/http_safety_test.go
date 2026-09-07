package modules

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestHTTPDoesNotFollowRedirectOutsideScope(t *testing.T) {
	var outsideHits atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		outsideHits.Add(1)
	}))
	defer outside.Close()

	inside := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outside.URL, http.StatusFound)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inside.Listener = listener
	inside.Start()
	defer inside.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "http.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	mod := NewHTTP(db, scope.New([]string{"localhost"}), models.HTTPConfig{MaxPagesPerHost: 1})
	_, err = mod.Handle(context.Background(), models.Event{ScanID: "scope", Type: EventHTTPURL, Target: "http://localhost:" + port})
	if err != nil {
		t.Fatal(err)
	}
	if outsideHits.Load() != 0 {
		t.Fatal("HTTP module followed a redirect to a host outside configured scope")
	}
}

func TestEventHostPreservesIPv6Address(t *testing.T) {
	if got := eventHost("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatalf("eventHost=%q", got)
	}
}

func TestTCPIPTraitsDoNotFabricatePacketEvidence(t *testing.T) {
	if _, _, err := probeTCPTraits(context.Background(), "127.0.0.1", 443); err == nil {
		t.Fatal("TCP/IP traits unexpectedly reported evidence without a packet collector")
	}
}

type cookieCaptureTransport struct{ cookie string }

func (t *cookieCaptureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.cookie = req.Header.Get("Cookie")
	return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
}

func TestAuthenticatedCrawlerInjectsOnlyEnvironmentSessionCookie(t *testing.T) {
	capture := &cookieCaptureTransport{}
	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withSessionCookie(capture, "session=operator-value; flags=1").RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	if capture.cookie != "session=operator-value; flags=1" {
		t.Fatalf("expected session cookie injection, got %q", capture.cookie)
	}
	request.Header.Set("Cookie", "request-specific=1")
	if _, err := withSessionCookie(capture, "session=operator-value").RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	if capture.cookie != "request-specific=1" {
		t.Fatalf("existing request cookie must win, got %q", capture.cookie)
	}
	if strings.Contains(capture.cookie, "\n") {
		t.Fatal("cookie header must remain single-line")
	}
}
