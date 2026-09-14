package modules

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	ErrUntrustedPublisher     = errors.New("publisher key is not in trusted keys list")
	ErrInvalidContentDigest   = errors.New("rule content SHA256 digest mismatch")
	ErrInvalidSignature       = errors.New("cryptographic signature verification failed")
	ErrIncompatibleEngine     = errors.New("rule update requires a newer engine version")
	ErrInvalidRuleSyntax      = errors.New("rule content failed validation or syntax check")
	ErrNoBackupAvailable      = errors.New("no backup available to rollback")
)

// RuleManifest describes a signed bundle of rules or provider definitions.
type RuleManifest struct {
	Version          string `json:"version"`
	ContentSHA256    string `json:"content_sha256"`
	Signature        string `json:"signature"`         // hex-encoded Ed25519 signature of ContentSHA256
	PublisherKey     string `json:"publisher_key"`     // hex-encoded Ed25519 public key
	RulesCount       int    `json:"rules_count"`
	MinEngineVersion string `json:"min_engine_version"`
}

// RuleUpdater manages cryptographic verification, atomic application, and rollback of rules.
type RuleUpdater struct {
	mu                   sync.RWMutex
	rulesDir             string
	backupDir            string
	currentEngineVersion string
	trustedKeys          map[string]bool
}

// NewRuleUpdater initializes a RuleUpdater with trusted publisher keys and local paths.
func NewRuleUpdater(rulesDir, backupDir, engineVersion string, trustedPublicKeys []string) *RuleUpdater {
	keys := make(map[string]bool)
	for _, k := range trustedPublicKeys {
		keys[strings.ToLower(strings.TrimSpace(k))] = true
	}
	return &RuleUpdater{
		rulesDir:             rulesDir,
		backupDir:            backupDir,
		currentEngineVersion: engineVersion,
		trustedKeys:          keys,
	}
}

// VerifyManifest validates engine version, trusted publisher, content digest, and Ed25519 signature.
func (u *RuleUpdater) VerifyManifest(manifest RuleManifest, content []byte) error {
	// 1. Min engine version check
	if manifest.MinEngineVersion != "" && u.currentEngineVersion != "" {
		if manifest.MinEngineVersion > u.currentEngineVersion {
			return fmt.Errorf("%w: required %s > current %s", ErrIncompatibleEngine, manifest.MinEngineVersion, u.currentEngineVersion)
		}
	}

	// 2. Trusted publisher key check
	pubKeyHex := strings.ToLower(strings.TrimSpace(manifest.PublisherKey))
	u.mu.RLock()
	trusted := u.trustedKeys[pubKeyHex]
	u.mu.RUnlock()
	if !trusted {
		return fmt.Errorf("%w: %s", ErrUntrustedPublisher, pubKeyHex)
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid publisher public key format")
	}

	// 3. Content SHA-256 digest validation
	digest := sha256.Sum256(content)
	computedDigestHex := hex.EncodeToString(digest[:])
	if !strings.EqualFold(computedDigestHex, manifest.ContentSHA256) {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidContentDigest, manifest.ContentSHA256, computedDigestHex)
	}

	// 4. Cryptographic Ed25519 signature verification
	sigBytes, err := hex.DecodeString(manifest.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid signature encoding", ErrInvalidSignature)
	}

	// The signature signs the content hash bytes
	if !ed25519.Verify(pubKeyBytes, digest[:], sigBytes) {
		return ErrInvalidSignature
	}

	return nil
}

// ApplyRuleUpdate verifies, backs up, and atomically writes the new rules file.
func (u *RuleUpdater) ApplyRuleUpdate(manifest RuleManifest, content []byte, filename string) error {
	// 1. Cryptographic and integrity verification (performed outside lock)
	if err := u.VerifyManifest(manifest, content); err != nil {
		return err
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	// 2. Basic syntax validation (JSON or non-empty structured text)
	var dummy any
	if err := json.Unmarshal(content, &dummy); err != nil {
		return fmt.Errorf("%w: content must be valid JSON: %v", ErrInvalidRuleSyntax, err)
	}

	// Ensure directories exist
	if err := os.MkdirAll(u.rulesDir, 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(u.backupDir, 0750); err != nil {
		return err
	}

	targetFile := filepath.Join(u.rulesDir, filename)
	backupFile := filepath.Join(u.backupDir, filename+".bak")

	// 3. Backup active rule set if present
	if _, err := os.Stat(targetFile); err == nil {
		existingData, err := os.ReadFile(targetFile)
		if err != nil {
			return fmt.Errorf("failed to read existing rules for backup: %w", err)
		}
		if err := os.WriteFile(backupFile, existingData, 0600); err != nil {
			return fmt.Errorf("failed to write rule backup: %w", err)
		}
	}

	// 4. Atomic write via temporary file
	tmpFile := filepath.Join(u.rulesDir, filename+".tmp")
	if err := os.WriteFile(tmpFile, content, 0600); err != nil {
		return fmt.Errorf("failed writing temporary rule file: %w", err)
	}

	if err := os.Rename(tmpFile, targetFile); err != nil {
		_ = os.Remove(tmpFile)
		// Attempt rollback from backup if target failed
		_ = u.rollbackFile(filename)
		return fmt.Errorf("failed atomic rule replacement: %w", err)
	}

	return nil
}

// RollbackRuleUpdate restores the previous backup of the specified rule file.
func (u *RuleUpdater) RollbackRuleUpdate(filename string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.rollbackFile(filename)
}

func (u *RuleUpdater) rollbackFile(filename string) error {
	targetFile := filepath.Join(u.rulesDir, filename)
	backupFile := filepath.Join(u.backupDir, filename+".bak")

	backupData, err := os.ReadFile(backupFile)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNoBackupAvailable
		}
		return err
	}

	if err := os.WriteFile(targetFile, backupData, 0600); err != nil {
		return fmt.Errorf("failed restoring rule from backup: %w", err)
	}

	return nil
}
