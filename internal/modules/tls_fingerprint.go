package modules

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type TLSFingerprinter struct {
	db    store.RuntimeStore
	guard scope.Guard
}

func NewTLSFingerprinter(db store.RuntimeStore, guard scope.Guard) *TLSFingerprinter {
	return &TLSFingerprinter{db: db, guard: guard}
}

func (m *TLSFingerprinter) Name() string {
	return "tls_fingerprinter"
}

func (m *TLSFingerprinter) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *TLSFingerprinter) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":443") && !strings.HasSuffix(evt.Target, ":8443") {
		return nil, nil
	}

	targetIP := eventHost(evt.Target)

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", evt.Target, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var newEvents []models.Event

	// Calculate JA3S fingerprint hash
	ja3sRaw := fmt.Sprintf("%d,%d,%d", state.Version, state.CipherSuite, len(state.PeerCertificates))
	ja3sHash := fmt.Sprintf("%x", md5.Sum([]byte(ja3sRaw)))

	_ = m.db.AddAsset(ctx, models.Asset{
		ScanID:   evt.ScanID,
		Type:     "tls_fingerprint",
		Value:    fmt.Sprintf("JA3S=%s Cipher=0x%x", ja3sHash, state.CipherSuite),
		Parent:   evt.Target,
		Metadata: fmt.Sprintf("tls_version=%d", state.Version),
	})

	// Extract Subject Alternative Names (SANs) from certificate chain
	for _, cert := range state.PeerCertificates {
		for _, dnsName := range cert.DNSNames {
			if m.guard.Allowed(dnsName) {
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "san_domain",
					Value:    dnsName,
					Parent:   evt.Target,
					Metadata: "tls_san_cert",
				})

				newEvents = append(newEvents, models.Event{
					ScanID: evt.ScanID,
					Type:   "domain.discovered",
					Target: dnsName,
				})
			}
		}
	}

	// OCSP Certificate Status Checking
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		status := checkOCSPStatus(cert, state.OCSPResponse)
		_ = m.db.AddAsset(ctx, models.Asset{
			ScanID:   evt.ScanID,
			Type:     "ocsp_status",
			Value:    status,
			Parent:   evt.Target,
			Metadata: "certificate_ocsp_staple",
		})
	}

	return newEvents, nil
}

type tlsVuln struct{ Name, Severity, CVE, Evidence string }

func checkTLSVulnerabilities(target string, state tls.ConnectionState) []tlsVuln {
	// These vulnerabilities cannot be established from a normal TLS handshake.
	// Heartbleed needs a heartbeat-memory-leak proof, ROBOT needs an oracle
	// comparison, and CRIME/BREACH need compression behavior correlated with a
	// secret-bearing response. Returning no finding is deliberate: callers must
	// use a dedicated, explicitly authorized verifier before claiming any of
	// them as detected.
	return nil
}

func isHeartbleedVulnerable(target string) bool {
	// No synthetic heartbeat claim: this function remains false until a real,
	// dedicated verifier is supplied by an explicitly authorized integration.
	return false
}

func isRSACipherSuite(suite uint16) bool {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return true
	default:
		return false
	}
}

func checkOCSPStatus(cert *x509.Certificate, ocspResponse []byte) string {
	if len(ocspResponse) > 0 {
		return "stapled_good"
	}
	if len(cert.OCSPServer) > 0 {
		return fmt.Sprintf("responder_available;uri=%s", cert.OCSPServer[0])
	}
	return "no_ocsp_staple"
}
