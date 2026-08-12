package modules

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type KerberosADFingerprint struct {
	db    *store.SQLiteCLI
	guard scope.Guard
}

func NewKerberosADFingerprint(db *store.SQLiteCLI, guard scope.Guard) *KerberosADFingerprint {
	return &KerberosADFingerprint{db: db, guard: guard}
}

func (m *KerberosADFingerprint) Name() string {
	return "kerberos_ad_fingerprint"
}

func (m *KerberosADFingerprint) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *KerberosADFingerprint) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":88") && !strings.HasSuffix(evt.Target, ":389") && !strings.HasSuffix(evt.Target, ":636") {
		return nil, nil
	}

	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	conn, err := net.DialTimeout("tcp", evt.Target, 500*time.Millisecond)
	if err != nil {
		return nil, nil
	}
	_ = conn.Close()

	_ = m.db.AddAsset(ctx, models.Asset{
		ScanID:   evt.ScanID,
		Type:     "kerberos_service",
		Value:    evt.Target,
		Parent:   evt.Target,
		Metadata: "verification=observed;method=tcp_connect",
	})

	return []models.Event{{
		ScanID: evt.ScanID,
		Type:   "service.identified",
		Target: evt.Target,
		Data:   map[string]string{"service": "kerberos"},
	}}, nil
}

type SNMPWalkFingerprint struct {
	db    *store.SQLiteCLI
	guard scope.Guard
}

func NewSNMPWalkFingerprint(db *store.SQLiteCLI, guard scope.Guard) *SNMPWalkFingerprint {
	return &SNMPWalkFingerprint{db: db, guard: guard}
}

func (m *SNMPWalkFingerprint) Name() string {
	return "snmp_walk_fingerprint"
}

func (m *SNMPWalkFingerprint) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *SNMPWalkFingerprint) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":161") {
		return nil, nil
	}

	// A real SNMP walk requires an explicitly configured community and is
	// performed by the specialized module. Do not invent sysDescr evidence.
	return nil, nil
}

type OSStackFingerprint struct {
	db    *store.SQLiteCLI
	guard scope.Guard
}

func NewOSStackFingerprint(db *store.SQLiteCLI, guard scope.Guard) *OSStackFingerprint {
	return &OSStackFingerprint{db: db, guard: guard}
}

func (m *OSStackFingerprint) Name() string {
	return "os_stack_fingerprint"
}

func (m *OSStackFingerprint) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *OSStackFingerprint) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	targetIP, _, err := net.SplitHostPort(evt.Target)
	if err != nil {
		targetIP = evt.Target
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	// Raw packet collection is intentionally not part of this production build.
	// If a separately authorized passive collector supplies TCP/IP traits, retain
	// them as heuristic evidence rather than fabricating an OS conclusion.
	ttl, window, options := evt.Data["ttl"], evt.Data["tcp_window"], evt.Data["tcp_options"]
	if ttl == "" && window == "" && options == "" {
		return nil, nil
	}
	guess := passiveOSGuess(ttl, window, options)
	if guess == "" {
		return nil, nil
	}

	_ = m.db.AddAsset(ctx, models.Asset{
		ScanID:   evt.ScanID,
		Type:     "operating_system",
		Value:    guess,
		Parent:   targetIP,
		Metadata: fmt.Sprintf("verification=heuristic;ttl=%s;tcp_window=%s;tcp_options=%s", ttl, window, options),
	})

	return nil, nil
}

func passiveOSGuess(ttl, window, options string) string {
	value, err := strconv.Atoi(ttl)
	if err != nil || value < 1 || value > 255 {
		return ""
	}
	// TTL observations are altered by routing. Keep these broad families and
	// label them heuristic; no subnet/address-based inference is made.
	switch {
	case value <= 64:
		return "Unix-like network stack"
	case value <= 128:
		return "Windows-like network stack"
	default:
		return "network appliance or Unix-like stack"
	}
}
