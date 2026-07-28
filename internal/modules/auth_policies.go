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

type AuthPoliciesDetector struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewAuthPoliciesDetector(db *store.SQLiteCLI, guard scope.Guard) *AuthPoliciesDetector {
	return &AuthPoliciesDetector{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *AuthPoliciesDetector) Name() string {
	return "auth_policies_detector"
}

func (m *AuthPoliciesDetector) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *AuthPoliciesDetector) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
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

	loginEndpoints := []string{"/login", "/signin", "/auth/login", "/user/login"}

	for _, ep := range loginEndpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+ep, nil)
		if err != nil {
			continue
		}

		resp, err := m.client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			bStr := strings.ToLower(string(body))

			// 1. MFA Mechanisms Detection
			if strings.Contains(bStr, "two-factor") || strings.Contains(bStr, "2fa") || strings.Contains(bStr, "authenticator") || strings.Contains(bStr, "webauthn") {
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "auth_policy",
					Value:    fmt.Sprintf("MFA Multi-Factor Auth on %s%s", evt.Target, ep),
					Parent:   evt.Target,
					Metadata: "mfa_2fa_prompt",
				})
			}

			// 2. Password Policy Hints Detection
			if strings.Contains(bStr, "password must contain") || strings.Contains(bStr, "at least 8 characters") || strings.Contains(bStr, "uppercase") {
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "auth_policy",
					Value:    fmt.Sprintf("Password Policy Hint on %s%s", evt.Target, ep),
					Parent:   evt.Target,
					Metadata: "password_policy_requirements",
				})
			}

			// 3. Account Lockout Indicators Detection
			if strings.Contains(bStr, "account locked") || strings.Contains(bStr, "too many failed attempts") || strings.Contains(bStr, "lockout") {
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "auth_policy",
					Value:    fmt.Sprintf("Account Lockout Protection on %s%s", evt.Target, ep),
					Parent:   evt.Target,
					Metadata: "account_lockout_protection",
				})
			}
		}
	}

	return nil, nil
}
