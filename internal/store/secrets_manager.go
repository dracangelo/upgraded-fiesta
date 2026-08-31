package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
)

type SecretsManager interface {
	GetSecret(ctx context.Context, key string) (string, error)
	SetSecret(ctx context.Context, key, value string) error
	RotateSecret(ctx context.Context, key, newValue string) error
}

type ProviderType string

const (
	ProviderEnv        ProviderType = "env"
	ProviderOSKeychain ProviderType = "os_keychain"
	ProviderVault      ProviderType = "hashicorp_vault"
	ProviderK8s        ProviderType = "k8s_secrets"
	ProviderAWS        ProviderType = "aws_secrets_manager"
	ProviderAzure      ProviderType = "azure_key_vault"
	ProviderGCP        ProviderType = "gcp_secret_manager"
)

type MultiBackendSecretsManager struct {
	mu            sync.RWMutex
	activeBackend ProviderType
	secrets       map[string]string
	history       map[string][]string
}

func NewLocalSecretsManager() *MultiBackendSecretsManager {
	return NewMultiBackendSecretsManager(ProviderEnv)
}

func NewMultiBackendSecretsManager(backend ProviderType) *MultiBackendSecretsManager {
	return &MultiBackendSecretsManager{
		activeBackend: backend,
		secrets:       make(map[string]string),
		history:       make(map[string][]string),
	}
}

func (s *MultiBackendSecretsManager) GetSecret(ctx context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 1. In-memory check
	if val, ok := s.secrets[key]; ok {
		return val, nil
	}

	// 2. Env check
	envKey := "ENUMSCAN_SECRET_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	if val := os.Getenv(envKey); val != "" {
		return val, nil
	}

	// 3. Provider abstraction resolution
	switch s.activeBackend {
	case ProviderOSKeychain:
		return fmt.Sprintf("mock_keychain_secret_for_%s", key), nil
	case ProviderVault:
		return fmt.Sprintf("mock_vault_secret_for_%s", key), nil
	case ProviderK8s:
		return fmt.Sprintf("mock_k8s_secret_for_%s", key), nil
	case ProviderAWS:
		return fmt.Sprintf("mock_aws_secret_for_%s", key), nil
	case ProviderAzure:
		return fmt.Sprintf("mock_azure_secret_for_%s", key), nil
	case ProviderGCP:
		return fmt.Sprintf("mock_gcp_secret_for_%s", key), nil
	}

	return "", fmt.Errorf("secret %q not found in backend %s", key, s.activeBackend)
}

func (s *MultiBackendSecretsManager) SetSecret(ctx context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[key] = value
	return nil
}

func (s *MultiBackendSecretsManager) RotateSecret(ctx context.Context, key, newValue string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if old, ok := s.secrets[key]; ok {
		s.history[key] = append(s.history[key], old)
	}
	s.secrets[key] = newValue
	return nil
}
