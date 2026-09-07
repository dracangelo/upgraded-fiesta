package modules

import "testing"

func TestOptimizedHTTPTransportUsesBoundedReusableConnections(t *testing.T) {
	transport := optimizedHTTPTransport()
	if !transport.ForceAttemptHTTP2 || transport.MaxIdleConns <= 0 || transport.MaxIdleConnsPerHost <= 0 || transport.TLSClientConfig == nil {
		t.Fatalf("unexpected transport tuning: %#v", transport)
	}
}
