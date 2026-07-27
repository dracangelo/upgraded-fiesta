package modules

import (
	"context"
	"crypto/md5"
	"crypto/tls"
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

	return newEvents, nil
}
