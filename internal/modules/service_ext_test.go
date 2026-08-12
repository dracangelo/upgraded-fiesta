package modules

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/inventory"
	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestADSNMPandOSFingerprint(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	guard := scope.New([]string{"127.0.0.1", "192.168.1.1"})

	adMod := NewKerberosADFingerprint(db, guard)
	if adMod.Name() != "kerberos_ad_fingerprint" {
		t.Errorf("unexpected name: %s", adMod.Name())
	}

	snmpMod := NewSNMPWalkFingerprint(db, guard)
	if snmpMod.Name() != "snmp_walk_fingerprint" {
		t.Errorf("unexpected name: %s", snmpMod.Name())
	}

	osMod := NewOSStackFingerprint(db, guard)
	_, _ = osMod.Handle(context.Background(), models.Event{
		ScanID: "s1",
		Type:   "port.open",
		Target: "127.0.0.1:80",
	})
}

func TestSpecializedHelpersRequireExplicitSNMPCommunities(t *testing.T) {
	if len(NewSpecialized(nil, scope.New([]string{"127.0.0.1"}), models.SpecializedConfig{}).cfg.SNMPCommunities) != 0 {
		t.Fatal("SNMP communities must not default to credential guesses")
	}
}

func TestTLSFingerprinter(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	guard := scope.New([]string{"127.0.0.1"})

	tlsMod := NewTLSFingerprinter(db, guard)
	if tlsMod.Name() != "tls_fingerprinter" {
		t.Errorf("unexpected name: %s", tlsMod.Name())
	}
}

func TestPassiveOSFingerprintRequiresPacketTraits(t *testing.T) {
	if passiveOSGuess("", "", "") != "" {
		t.Fatal("missing packet traits must not generate an OS guess")
	}
	if passiveOSGuess("64", "64240", "mss,sack") != "Unix-like network stack" {
		t.Fatal("expected a bounded heuristic for observed TTL")
	}
}

func TestCPENormalizer(t *testing.T) {
	norm := inventory.NewCPENormalizer()
	cpe1 := norm.ParseBannerToCPE("Apache/2.4.41 (Ubuntu)")
	if !strings.Contains(cpe1, "cpe:2.3:a:apache:http_server:2.4.41") {
		t.Errorf("unexpected Apache CPE: %s", cpe1)
	}

	cpe2 := norm.ParseBannerToCPE("nginx/1.18.0")
	if !strings.Contains(cpe2, "cpe:2.3:a:f5:nginx:1.18.0") {
		t.Errorf("unexpected Nginx CPE: %s", cpe2)
	}
}
