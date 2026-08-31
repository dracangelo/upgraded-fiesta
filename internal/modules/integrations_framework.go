package modules

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

type IntegrationProvider interface {
	Name() string
	Capabilities() []string
	ValidateAPIKey(key string) error
	HealthCheck(ctx context.Context) error
	RemainingQuota() int
}

type BaseProvider struct {
	name         string
	apiKey       string
	enabled      bool
	quota        int
	capabilities []string
}

func (b *BaseProvider) Name() string           { return b.name }
func (b *BaseProvider) Capabilities() []string { return b.capabilities }
func (b *BaseProvider) RemainingQuota() int    { return b.quota }
func (b *BaseProvider) ValidateAPIKey(key string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("empty API key")
	}
	return nil
}
func (b *BaseProvider) HealthCheck(ctx context.Context) error {
	if !b.enabled || b.apiKey == "" {
		return errors.New("provider disabled or missing API key")
	}
	return nil
}

type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]IntegrationProvider
}

func NewProviderRegistry() *ProviderRegistry {
	r := &ProviderRegistry{
		providers: make(map[string]IntegrationProvider),
	}

	names := []string{
		"VirusTotal", "AbuseIPDB", "Shodan", "Censys", "SecurityTrails",
		"GreyNoise", "BinaryEdge", "FOFA", "AlienVault OTX", "URLScan.io",
		"Hunter.io", "WhoisXML API", "Have I Been Pwned", "GitHub", "GitLab",
		"DNSDB", "CIRCL CVE Search",
	}

	for _, name := range names {
		r.providers[strings.ToLower(name)] = &BaseProvider{
			name:         name,
			apiKey:       "mock-key",
			enabled:      true,
			quota:        1000,
			capabilities: []string{"enrichment", "threat_intel"},
		}
	}

	return r
}

func (r *ProviderRegistry) Register(p IntegrationProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[strings.ToLower(p.Name())] = p
}

func (r *ProviderRegistry) Get(name string) (IntegrationProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[strings.ToLower(name)]
	return p, ok
}

func (r *ProviderRegistry) RunDiagnostics(ctx context.Context) map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make(map[string]string)
	for name, p := range r.providers {
		err := p.HealthCheck(ctx)
		if err != nil {
			results[name] = fmt.Sprintf("FAIL (%v)", err)
		} else {
			results[name] = fmt.Sprintf("OK (Quota: %d)", p.RemainingQuota())
		}
	}
	return results
}
