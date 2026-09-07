package store

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

type SecretsManager interface {
	GetSecret(context.Context, string) (string, error)
	SetSecret(context.Context, string, string) error
	RotateSecret(context.Context, string, string) error
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

type SecretsManagerConfig struct {
	Provider   ProviderType
	Endpoint   string
	TokenEnv   string
	TokenFile  string
	Namespace  string
	Project    string
	Region     string
	Mount      string
	Service    string
	HTTPClient *http.Client
}

type MultiBackendSecretsManager struct {
	activeBackend ProviderType
	backend       SecretsManager
}

func NewLocalSecretsManager() *MultiBackendSecretsManager {
	return NewMultiBackendSecretsManager(ProviderEnv)
}

// NewMultiBackendSecretsManager keeps remote providers fail-closed until an
// explicit endpoint/identity configuration is supplied.
func NewMultiBackendSecretsManager(provider ProviderType) *MultiBackendSecretsManager {
	manager := &MultiBackendSecretsManager{activeBackend: provider}
	switch provider {
	case ProviderEnv:
		manager.backend = environmentSecretsManager{}
	}
	return manager
}

func NewConfiguredSecretsManager(config SecretsManagerConfig) (*MultiBackendSecretsManager, error) {
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	manager := &MultiBackendSecretsManager{activeBackend: config.Provider}
	switch config.Provider {
	case ProviderEnv:
		manager.backend = environmentSecretsManager{}
	case ProviderOSKeychain:
		service := strings.TrimSpace(config.Service)
		if service == "" {
			service = "enumscan"
		}
		manager.backend = &osKeychainSecretsManager{service: service}
	case ProviderVault, ProviderK8s, ProviderAWS, ProviderAzure, ProviderGCP:
		backend, err := newHTTPSecretsBackend(config)
		if err != nil {
			return nil, err
		}
		manager.backend = backend
	default:
		return nil, fmt.Errorf("unsupported secret backend %q", config.Provider)
	}
	return manager, nil
}

func (s *MultiBackendSecretsManager) GetSecret(ctx context.Context, key string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s == nil || s.backend == nil {
		return "", fmt.Errorf("secret backend %q requires explicit production configuration", s.activeBackend)
	}
	return s.backend.GetSecret(ctx, key)
}
func (s *MultiBackendSecretsManager) SetSecret(ctx context.Context, key, value string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.backend == nil {
		return fmt.Errorf("secret backend %q requires explicit production configuration", s.activeBackend)
	}
	return s.backend.SetSecret(ctx, key, value)
}
func (s *MultiBackendSecretsManager) RotateSecret(ctx context.Context, key, value string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.backend == nil {
		return fmt.Errorf("secret backend %q requires explicit production configuration", s.activeBackend)
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("rotated secret value must not be empty")
	}
	return s.backend.RotateSecret(ctx, key, value)
}

type environmentSecretsManager struct{}

func (environmentSecretsManager) GetSecret(_ context.Context, key string) (string, error) {
	name, err := environmentSecretName(key)
	if err != nil {
		return "", err
	}
	value, present := os.LookupEnv(name)
	if !present || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("secret %q is not set in environment variable %s", key, name)
	}
	return value, nil
}
func (environmentSecretsManager) SetSecret(_ context.Context, key, value string) error {
	return fmt.Errorf("secret writes are not supported; supply %s through the configured external backend", environmentSecretNameUnsafe(key))
}
func (environmentSecretsManager) RotateSecret(_ context.Context, key, value string) error {
	return fmt.Errorf("secret rotation is not supported by the environment backend; rotate %s outside enumscan", environmentSecretNameUnsafe(key))
}

type osKeychainSecretsManager struct{ service string }

func (s *osKeychainSecretsManager) GetSecret(_ context.Context, key string) (string, error) {
	if err := validateExternalSecretKey(key); err != nil {
		return "", err
	}
	value, err := keyring.Get(s.service, key)
	if err != nil {
		return "", fmt.Errorf("read %q from OS keychain: %w", key, err)
	}
	return value, nil
}
func (s *osKeychainSecretsManager) SetSecret(_ context.Context, key, value string) error {
	if err := validateSecretWrite(key, value); err != nil {
		return err
	}
	if err := keyring.Set(s.service, key, value); err != nil {
		return fmt.Errorf("write %q to OS keychain: %w", key, err)
	}
	return nil
}
func (s *osKeychainSecretsManager) RotateSecret(ctx context.Context, key, value string) error {
	return s.SetSecret(ctx, key, value)
}

func validateSecretWrite(key, value string) error {
	if err := validateExternalSecretKey(key); err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("secret value must not be empty")
	}
	if len(value) > 1<<20 {
		return fmt.Errorf("secret value exceeds one MiB")
	}
	return nil
}
func validateExternalSecretKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 512 || strings.Contains(key, "..") || strings.HasPrefix(key, "/") {
		return fmt.Errorf("invalid secret name")
	}
	for _, r := range key {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("-_./", r)) {
			return fmt.Errorf("secret name %q contains unsupported characters", key)
		}
	}
	return nil
}

func environmentSecretName(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("secret name is empty")
	}
	for _, character := range key {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '-' && character != '_' {
			return "", fmt.Errorf("secret name %q contains unsupported characters", key)
		}
	}
	return environmentSecretNameUnsafe(key), nil
}
func environmentSecretNameUnsafe(key string) string {
	return "ENUMSCAN_SECRET_" + strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
}
