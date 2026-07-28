package modules

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type SessionJWTScanner struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewSessionJWTScanner(db *store.SQLiteCLI, guard scope.Guard) *SessionJWTScanner {
	return &SessionJWTScanner{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *SessionJWTScanner) Name() string {
	return "session_jwt_scanner"
}

func (m *SessionJWTScanner) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *SessionJWTScanner) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
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

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/", nil)
	if err != nil {
		return nil, nil
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// 1. Audit Session Cookie Security Flags
	for _, cookie := range resp.Cookies() {
		flags := []string{}
		if !cookie.HttpOnly {
			flags = append(flags, "missing_httponly")
		}
		if !cookie.Secure {
			flags = append(flags, "missing_secure")
		}
		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == http.SameSiteNoneMode {
			flags = append(flags, "weak_samesite")
		}

		_ = m.db.AddAsset(ctx, models.Asset{
			ScanID:   evt.ScanID,
			Type:     "session_cookie",
			Value:    fmt.Sprintf("%s (%s)", cookie.Name, evt.Target),
			Parent:   evt.Target,
			Metadata: fmt.Sprintf("flags=%s", strings.Join(flags, ",")),
		})

		// 2. Audit JWT Token in Cookie or Headers
		if strings.HasPrefix(cookie.Value, "eyJ") {
			alg := m.extractJWTAlg(cookie.Value)
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "jwt_token",
				Value:    fmt.Sprintf("JWT Cookie %s on %s", cookie.Name, evt.Target),
				Parent:   evt.Target,
				Metadata: fmt.Sprintf("alg=%s", alg),
			})
		}
	}

	// Audit Bearer JWT in Authorization header response if present
	authHeader := resp.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer eyJ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		alg := m.extractJWTAlg(tokenStr)
		_ = m.db.AddAsset(ctx, models.Asset{
			ScanID:   evt.ScanID,
			Type:     "jwt_token",
			Value:    fmt.Sprintf("JWT Authorization Header on %s", evt.Target),
			Parent:   evt.Target,
			Metadata: fmt.Sprintf("alg=%s", alg),
		})
	}

	return nil, nil
}

func (m *SessionJWTScanner) extractJWTAlg(jwtToken string) string {
	parts := strings.Split(jwtToken, ".")
	if len(parts) < 2 {
		return "unknown"
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "invalid"
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err == nil {
		if alg, ok := header["alg"].(string); ok {
			return alg
		}
	}
	return "unknown"
}
