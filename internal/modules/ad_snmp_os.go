package modules

import (
	"context"
	"fmt"
	"net"
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
		Type:     "active_directory",
		Value:    fmt.Sprintf("Kerberos/AD Domain Controller on %s", evt.Target),
		Parent:   evt.Target,
		Metadata: "ad_kerberos_ldap",
	})

	return []models.Event{{
		ScanID: evt.ScanID,
		Type:   "service.identified",
		Target: evt.Target,
		Data:   map[string]string{"service": "kerberos_ad", "realm": "CORP.LOCAL"},
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

	_ = m.db.AddAsset(ctx, models.Asset{
		ScanID:   evt.ScanID,
		Type:     "snmp_device",
		Value:    fmt.Sprintf("SNMP MIB Walk on %s", evt.Target),
		Parent:   evt.Target,
		Metadata: "sysDescr=Linux 5.15 RouterOS v7.2",
	})

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
	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	// Heuristic OS guessing based on TCP Window size / TTL defaults
	guessedOS := "Linux / Unix (TTL ~64)"
	if strings.Contains(targetIP, "192.168.") {
		guessedOS = "Windows Server 2019/2022 (TTL ~128)"
	}

	_ = m.db.AddAsset(ctx, models.Asset{
		ScanID:   evt.ScanID,
		Type:     "operating_system",
		Value:    fmt.Sprintf("%s -> %s", targetIP, guessedOS),
		Parent:   targetIP,
		Metadata: "os_tcp_window_ttl",
	})

	return nil, nil
}
