package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type AuthProtocolScanner struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewAuthProtocolScanner(db *store.SQLiteCLI, guard scope.Guard) *AuthProtocolScanner {
	return &AuthProtocolScanner{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *AuthProtocolScanner) Name() string {
	return "auth_protocol_scanner"
}

func (m *AuthProtocolScanner) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *AuthProtocolScanner) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":80") && !strings.HasSuffix(evt.Target, ":443") && !strings.HasSuffix(evt.Target, ":8080") && !strings.HasSuffix(evt.Target, ":8443") {
		return nil, nil
	}

	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	scheme := "http"
	if strings.HasSuffix(evt.Target, ":443") || strings.HasSuffix(evt.Target, ":8443") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, evt.Target)

	// 1. OIDC / OAuth 2.0 Discovery
	oidcEndpoints := []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/oauth/v2/authorize",
		"/oauth2/token",
	}

	for _, ep := range oidcEndpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+ep, nil)
		if err == nil {
			if resp, err := m.client.Do(req); err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode == http.StatusOK && (strings.Contains(string(body), "issuer") || strings.Contains(string(body), "authorization_endpoint")) {
					_ = m.db.AddAsset(ctx, models.Asset{
						ScanID:   evt.ScanID,
						Type:     "auth_protocol",
						Value:    baseURL + ep,
						Parent:   evt.Target,
						Metadata: "oidc_oauth2_configuration",
					})
				}
			}
		}
	}

	// 2. SAML Metadata Discovery
	samlEndpoints := []string{
		"/saml/metadata",
		"/FederationMetadata/2007-06/FederationMetadata.xml",
		"/saml2/service-provider-metadata",
	}

	for _, ep := range samlEndpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+ep, nil)
		if err == nil {
			if resp, err := m.client.Do(req); err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode == http.StatusOK && (strings.Contains(string(body), "EntityDescriptor") || strings.Contains(string(body), "SPSSODescriptor")) {
					_ = m.db.AddAsset(ctx, models.Asset{
						ScanID:   evt.ScanID,
						Type:     "auth_protocol",
						Value:    baseURL + ep,
						Parent:   evt.Target,
						Metadata: "saml_metadata_definition",
					})
				}
			}
		}
	}

	// 3. SSO Provider Identification
	reqRoot, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/", nil)
	if err == nil {
		if resp, err := m.client.Do(reqRoot); err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			bStr := string(body)

			ssoProvider := ""
			if strings.Contains(bStr, "okta.com") || strings.Contains(bStr, "okta-login") {
				ssoProvider = "Okta SSO"
			} else if strings.Contains(bStr, "auth0.com") {
				ssoProvider = "Auth0"
			} else if strings.Contains(bStr, "keycloak") || strings.Contains(bStr, "/auth/realms/") {
				ssoProvider = "Keycloak IAM"
			} else if strings.Contains(bStr, "pingidentity") {
				ssoProvider = "PingIdentity"
			} else if strings.Contains(bStr, "login.microsoftonline.com") {
				ssoProvider = "Azure AD / Entra ID SSO"
			}

			if ssoProvider != "" {
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "sso_provider",
					Value:    fmt.Sprintf("%s -> %s", evt.Target, ssoProvider),
					Parent:   evt.Target,
					Metadata: "identity_provider",
				})
			}
		}
	}

	return nil, nil
}
