package modules

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestRuleUpdateCryptographicLifecycle(t *testing.T) {
	// Generate keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating ed25519 key: %v", err)
	}
	pubKeyHex := hex.EncodeToString(pubKey)

	tempDir := t.TempDir()
	rulesDir := filepath.Join(tempDir, "rules")
	backupDir := filepath.Join(tempDir, "backup")

	updater := NewRuleUpdater(rulesDir, backupDir, "1.5.0", []string{pubKeyHex})

	// Create valid rule content (valid JSON)
	validContent := []byte(`{"version":"2026.09.1","rules":[{"id":"R1","name":"Test Rule"}]}`)
	digest := sha256.Sum256(validContent)
	digestHex := hex.EncodeToString(digest[:])
	signature := ed25519.Sign(privKey, digest[:])
	sigHex := hex.EncodeToString(signature)

	manifest := RuleManifest{
		Version:          "2026.09.1",
		ContentSHA256:    digestHex,
		Signature:        sigHex,
		PublisherKey:     pubKeyHex,
		RulesCount:       1,
		MinEngineVersion: "1.0.0",
	}

	// 1. Successful verification and application
	ruleFilename := "cve_rules.json"
	if err := updater.ApplyRuleUpdate(manifest, validContent, ruleFilename); err != nil {
		t.Fatalf("expected successful rule update, got: %v", err)
	}

	// Verify file was written
	written, err := os.ReadFile(filepath.Join(rulesDir, ruleFilename))
	if err != nil || string(written) != string(validContent) {
		t.Fatalf("rules file not written correctly: %v", err)
	}

	// 2. Tampered content check
	tamperedContent := []byte(`{"version":"2026.09.1","rules":[{"id":"R1","name":"Hacked"}]}`)
	if err := updater.ApplyRuleUpdate(manifest, tamperedContent, ruleFilename); err == nil {
		t.Fatal("expected digest mismatch error for tampered content, got nil")
	}

	// 3. Forged signature check
	badManifest := manifest
	badSig := make([]byte, len(signature))
	copy(badSig, signature)
	badSig[0] ^= 0xFF
	badManifest.Signature = hex.EncodeToString(badSig)
	if err := updater.ApplyRuleUpdate(badManifest, validContent, ruleFilename); err == nil {
		t.Fatal("expected signature verification failure, got nil")
	}

	// 4. Untrusted publisher check
	untrustedPub, untrustedPriv, _ := ed25519.GenerateKey(rand.Reader)
	untrustedSig := ed25519.Sign(untrustedPriv, digest[:])
	untrustedManifest := RuleManifest{
		Version:          "2026.09.1",
		ContentSHA256:    digestHex,
		Signature:        hex.EncodeToString(untrustedSig),
		PublisherKey:     hex.EncodeToString(untrustedPub),
		RulesCount:       1,
		MinEngineVersion: "1.0.0",
	}
	if err := updater.ApplyRuleUpdate(untrustedManifest, validContent, ruleFilename); err == nil {
		t.Fatal("expected untrusted publisher error, got nil")
	}

	// 5. Incompatible engine version check
	incompatibleManifest := manifest
	incompatibleManifest.MinEngineVersion = "2.0.0"
	if err := updater.ApplyRuleUpdate(incompatibleManifest, validContent, ruleFilename); err == nil {
		t.Fatal("expected engine incompatibility error, got nil")
	}

	// 6. Invalid JSON syntax check
	badSyntaxContent := []byte(`not json at all`)
	badSyntaxDigest := sha256.Sum256(badSyntaxContent)
	badSyntaxSig := ed25519.Sign(privKey, badSyntaxDigest[:])
	badSyntaxManifest := RuleManifest{
		Version:          "2026.09.2",
		ContentSHA256:    hex.EncodeToString(badSyntaxDigest[:]),
		Signature:        hex.EncodeToString(badSyntaxSig),
		PublisherKey:     pubKeyHex,
		RulesCount:       1,
		MinEngineVersion: "1.0.0",
	}
	if err := updater.ApplyRuleUpdate(badSyntaxManifest, badSyntaxContent, ruleFilename); err == nil {
		t.Fatal("expected syntax check error, got nil")
	}

	// 7. Update to v2 and Rollback check
	v2Content := []byte(`{"version":"2026.09.2","rules":[{"id":"R1","name":"Rule v2"}]}`)
	v2Digest := sha256.Sum256(v2Content)
	v2Sig := ed25519.Sign(privKey, v2Digest[:])
	v2Manifest := RuleManifest{
		Version:          "2026.09.2",
		ContentSHA256:    hex.EncodeToString(v2Digest[:]),
		Signature:        hex.EncodeToString(v2Sig),
		PublisherKey:     pubKeyHex,
		RulesCount:       1,
		MinEngineVersion: "1.0.0",
	}
	if err := updater.ApplyRuleUpdate(v2Manifest, v2Content, ruleFilename); err != nil {
		t.Fatalf("failed applying v2 update: %v", err)
	}

	// Ensure v2 is active
	current, _ := os.ReadFile(filepath.Join(rulesDir, ruleFilename))
	if string(current) != string(v2Content) {
		t.Fatalf("expected v2 content to be active")
	}

	// Rollback to v1
	if err := updater.RollbackRuleUpdate(ruleFilename); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	rolledBack, _ := os.ReadFile(filepath.Join(rulesDir, ruleFilename))
	if string(rolledBack) != string(validContent) {
		t.Fatalf("expected rolled back content to match v1 content")
	}
}
