package modules

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestProbeHTTP3UsesQUICForLiteralIP(t *testing.T) {
	certificate, err := testHTTP3Certificate()
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodHead {
				t.Errorf("expected a read-only HEAD request, got %s", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
	}
	go func() { _ = server.Serve(packetConn) }()
	defer server.Close()
	defer packetConn.Close()

	target := packetConn.LocalAddr().String()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if status, ok := probeHTTP3(context.Background(), target); ok {
			if status != http.StatusNoContent {
				t.Fatalf("expected HTTP/3 response status %d, got %d", http.StatusNoContent, status)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("HTTP/3 QUIC probe did not confirm the local server")
}

func TestProbeHTTP3RejectsHostnames(t *testing.T) {
	if _, ok := probeHTTP3(context.Background(), "localhost:443"); ok {
		t.Fatal("HTTP/3 probe must reject a hostname to avoid an extra DNS resolution path")
	}
}

func testHTTP3Certificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
