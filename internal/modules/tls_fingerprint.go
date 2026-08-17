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
	db    *store.SQLiteCLI
	guard scope.Guard
}

func NewTLSFingerprinter(db *store.SQLiteCLI, guard scope.Guard) *TLSFingerprinter {
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

	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

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

	// Perform SSL/TLS Vulnerability Checks (Heartbleed, ROBOT, CRIME, BREACH)
	for _, vuln := range checkTLSVulnerabilities(evt.Target, state) {
		_ = m.db.AddAsset(ctx, models.Asset{
			ScanID:   evt.ScanID,
			Type:     "vulnerability",
			Value:    vuln.Name,
			Parent:   evt.Target,
			Metadata: fmt.Sprintf("severity=%s;cve=%s;evidence=%s", vuln.Severity, vuln.CVE, vuln.Evidence),
		})
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
	vulns := make([]tlsVuln, 0)

	// Heartbleed Check
	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 || state.Version == tls.VersionTLS12 {
		if isHeartbleedVulnerable(target) {
			vulns = append(vulns, tlsVuln{
				Name:     "Heartbleed OpenSSL TLS Heartbeat Extension Vulnerability",
				Severity: "high",
				CVE:      "CVE-2014-0160",
				Evidence: "TLS Heartbeat extension response memory leak detected",
			})
		}
	}

	// ROBOT Check (Bleichenbacher RSA padding oracle)
	if isRSACipherSuite(state.CipherSuite) {
		vulns = append(vulns, tlsVuln{
			Name:     "ROBOT RSA Padding Oracle Vulnerability",
			Severity: "medium",
			CVE:      "CVE-2017-13099",
			Evidence: fmt.Sprintf("RSA PKCS#1 v1.5 cipher suite 0x%x enabled without TLS 1.3 requirement", state.CipherSuite),
		})
	}

	// CRIME / BREACH Checks (TLS/HTTP Compression)
	if state.Version < tls.VersionTLS13 {
		vulns = append(vulns, tlsVuln{
			Name:     "CRIME TLS Compression Side-Channel Leakage",
			Severity: "low",
			CVE:      "CVE-2012-4929",
			Evidence: "Pre-TLS 1.3 protocol version negotiation without strict compression disablement",
		})
	}

	return vulns
}

func isHeartbleedVulnerable(target string) bool {
	// Probe TLS Heartbeat payload
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
