package plugin

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

type PluginSigner struct {
	publicKey ed25519.PublicKey
}

func NewPluginSigner(pubKeyHex string) (*PluginSigner, error) {
	if pubKeyHex == "" {
		// Generate default keypair for testing
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		return &PluginSigner{publicKey: pub}, nil
	}

	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}

	return &PluginSigner{publicKey: ed25519.PublicKey(keyBytes)}, nil
}

func (s *PluginSigner) VerifyPlugin(pluginFilePath, sigFilePath string) (bool, error) {
	data, err := os.ReadFile(pluginFilePath)
	if err != nil {
		return false, fmt.Errorf("failed to read plugin file: %w", err)
	}

	sigHex, err := os.ReadFile(sigFilePath)
	if err != nil {
		// If sig file does not exist, consider unverified
		return false, nil
	}

	sigBytes, err := hex.DecodeString(string(sigHex))
	if err != nil {
		return false, fmt.Errorf("invalid signature format: %w", err)
	}

	valid := ed25519.Verify(s.publicKey, data, sigBytes)
	return valid, nil
}
