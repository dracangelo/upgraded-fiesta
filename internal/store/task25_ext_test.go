package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestTask25DataHandlingAndSecretsProtection(t *testing.T) {
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 1. Encryption Test
	enc, err := NewDatastoreEncryptor("")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("Sensitive Vulnerability Finding Evidence")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil || bytes.Equal(ciphertext, plaintext) {
		t.Fatalf("encryption failed")
	}
	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decryption failed")
	}

	// 2. Secrets Manager Test
	secMgr := NewLocalSecretsManager()
	_ = secMgr.SetSecret(context.Background(), "ssh_key", "secret_passphrase")
	val, err := secMgr.GetSecret(context.Background(), "ssh_key")
	if err != nil || val != "secret_passphrase" {
		t.Fatalf("secrets manager error")
	}

	// 3. Audit Log Test
	audit := NewAuditLogger(db)
	if err := audit.LogAction(context.Background(), "admin", "START_SCAN", "scan_101", "started production scan"); err != nil {
		t.Fatalf("audit logger error: %v", err)
	}

	// 4. Chain of Custody Test
	custody := NewChainOfCustodyLogger(db)
	h1, err := custody.RecordEvidence(context.Background(), "scan_101", "10.0.0.1", "port_scan", "open 80")
	if err != nil || h1 == "" {
		t.Fatalf("custody hash 1 failed")
	}
	h2, err := custody.RecordEvidence(context.Background(), "scan_101", "10.0.0.1", "http_banner", "Apache/2.4")
	if err != nil || h2 == "" || h1 == h2 {
		t.Fatalf("custody hash chain failed")
	}
}
