package store

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestLiveDatastoreEncryptionMigratesAndProtectsEvidenceAtRest(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "encrypted.sqlite")
	plain, err := OpenSQLiteCLI(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := plain.AddAsset(ctx, models.Asset{ScanID: "scan-encrypted", Type: "host", Value: "secret.example", Parent: "scope.example", Metadata: "token=redacted"}); err != nil {
		t.Fatal(err)
	}
	if err := plain.AddFinding(ctx, models.Finding{ScanID: "scan-encrypted", Severity: "high", Confidence: "high", Asset: "secret.example", Title: "Sensitive finding", Evidence: "private evidence", Remediation: "rotate credential"}); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.AddEvent(ctx, models.Event{ScanID: "scan-encrypted", Type: "target", Target: "secret.example", Data: map[string]string{"source": "private"}}); err != nil {
		t.Fatal(err)
	}
	if err := plain.StartScan(ctx, "scan-encrypted"); err != nil {
		t.Fatal(err)
	}
	if err := plain.RecordModuleRun(ctx, models.ModuleRun{ScanID: "scan-encrypted", Module: "test", EventType: "target", Target: "secret.example", Status: "failed", Error: "private failure", Duration: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if err := plain.UpsertCheckpoint(ctx, models.Checkpoint{ScanID: "scan-encrypted", Module: "test", EventType: "target", Target: "secret.example", Status: "failed", Error: "private checkpoint"}); err != nil {
		t.Fatal(err)
	}
	if err := plain.AddPortObservation(ctx, models.PortObservation{ScanID: "scan-encrypted", Host: "secret.example", Port: 443, Protocol: "tcp", State: "open", Evidence: "private banner"}); err != nil {
		t.Fatal(err)
	}
	if err := plain.FinishScan(ctx, "scan-encrypted", "failed", "private scan failure"); err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}

	key := bytes.Repeat([]byte{0x42}, 32)
	encrypted, err := OpenEncryptedSQLiteCLI(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := encrypted.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var rawValue, rawEvidence, rawTarget string
	if err := encrypted.db.QueryRowContext(ctx, `SELECT value FROM assets WHERE scan_id=?`, "scan-encrypted").Scan(&rawValue); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.db.QueryRowContext(ctx, `SELECT evidence FROM findings WHERE scan_id=?`, "scan-encrypted").Scan(&rawEvidence); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.db.QueryRowContext(ctx, `SELECT target FROM events WHERE scan_id=?`, "scan-encrypted").Scan(&rawTarget); err != nil {
		t.Fatal(err)
	}
	var rawModuleTarget, rawCheckpointTarget, rawPortHost, rawScanError string
	if err := encrypted.db.QueryRowContext(ctx, `SELECT target FROM module_runs WHERE scan_id=?`, "scan-encrypted").Scan(&rawModuleTarget); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.db.QueryRowContext(ctx, `SELECT target FROM checkpoints WHERE scan_id=?`, "scan-encrypted").Scan(&rawCheckpointTarget); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.db.QueryRowContext(ctx, `SELECT host FROM port_observations WHERE scan_id=?`, "scan-encrypted").Scan(&rawPortHost); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.db.QueryRowContext(ctx, `SELECT error FROM scan_runs WHERE scan_id=?`, "scan-encrypted").Scan(&rawScanError); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{rawValue, rawEvidence, rawTarget, rawModuleTarget, rawCheckpointTarget, rawPortHost, rawScanError} {
		if !strings.HasPrefix(value, encryptedFieldPrefix) || strings.Contains(value, "secret.example") || strings.Contains(value, "private") {
			t.Fatalf("evidence remained plaintext at rest: %q", value)
		}
	}
	assets, err := encrypted.Assets(ctx, "scan-encrypted")
	if err != nil || len(assets) != 1 || assets[0].Value != "secret.example" {
		t.Fatalf("transparent asset read failed: %#v %v", assets, err)
	}
	findings, err := encrypted.Findings(ctx, "scan-encrypted")
	if err != nil || len(findings) != 1 || findings[0].Evidence != "private evidence" {
		t.Fatalf("transparent finding read failed: %#v %v", findings, err)
	}
	events, err := encrypted.Events(ctx, "scan-encrypted")
	if err != nil || len(events) != 1 || events[0].Target != "secret.example" || events[0].Data["source"] != "private" {
		t.Fatalf("transparent event read failed: %#v %v", events, err)
	}
	logs, err := encrypted.RecentModuleRunLogs(ctx, "scan-encrypted", 10)
	if err != nil || len(logs) != 1 || logs[0].Target != "secret.example" || logs[0].Error != "private failure" {
		t.Fatalf("transparent module log read failed: %#v %v", logs, err)
	}
	status, err := encrypted.CheckpointStatus(ctx, "scan-encrypted", "test", "target", "secret.example")
	if err != nil || status != "failed" {
		t.Fatalf("encrypted checkpoint lookup failed: %q %v", status, err)
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}

	wrong, err := OpenEncryptedSQLiteCLI(path, bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if err := wrong.Migrate(ctx); err == nil {
		t.Fatal("wrong live datastore key must be rejected")
	}
}
