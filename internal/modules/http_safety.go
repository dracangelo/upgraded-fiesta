package modules

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"enumscan/internal/scope"
)

type sessionCookieTransport struct {
	base   http.RoundTripper
	cookie string
}

func withSessionCookie(base http.RoundTripper, cookie string) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return sessionCookieTransport{base: base, cookie: cookie}
}

func (t sessionCookieTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.cookie == "" || request.Header.Get("Cookie") != "" {
		return t.base.RoundTrip(request)
	}
	cloned := request.Clone(request.Context())
	cloned.Header = request.Header.Clone()
	cloned.Header.Set("Cookie", t.cookie)
	return t.base.RoundTrip(cloned)
}

// scopedHTTPClient prevents a redirect from expanding an authorized scan to a
// different host. The initial request is checked by each module; this closure
// enforces the same boundary for every redirect hop.
func scopedHTTPClient(guard scope.Guard, timeout time.Duration, transport http.RoundTripper) *http.Client {
	if transport == nil {
		transport = optimizedHTTPTransport()
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !guard.Allowed(req.URL.Hostname()) || len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// optimizedHTTPTransport is shared by all scope-checked HTTP modules. Its
// connection pool and HTTP/2 settings reduce repeat handshakes while retaining
// the direct, no-proxy behavior used by authorized scans.
func optimizedHTTPTransport() *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

func eventHost(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err == nil {
		return host
	}
	return target
}
