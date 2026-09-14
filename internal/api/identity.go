package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"enumscan/internal/models"
)

var (
	ErrOrganizationNotFound = errors.New("organization not found")
	ErrUserNotFound         = errors.New("user not found")
	ErrInvalidSession       = errors.New("invalid or expired session")
	ErrTenantMismatch       = errors.New("tenant isolation policy violation: unauthorized access across organizations")
	ErrInvalidOIDCClaims    = errors.New("invalid OIDC claims or expired token")
	ErrInvalidSAMLAssertion = errors.New("invalid SAML assertion attributes")
)

// IdentityManager manages enterprise organizations, teams, users, sessions, and audit events.
type IdentityManager struct {
	mu            sync.RWMutex
	organizations map[string]models.Organization
	teams         map[string]models.Team
	users         map[string]models.User
	sessions      map[string]models.Session
	auditLogs     []models.IdentityAuditEvent
}

// NewIdentityManager creates an initialized IdentityManager.
func NewIdentityManager() *IdentityManager {
	return &IdentityManager{
		organizations: make(map[string]models.Organization),
		teams:         make(map[string]models.Team),
		users:         make(map[string]models.User),
		sessions:      make(map[string]models.Session),
		auditLogs:     make([]models.IdentityAuditEvent, 0),
	}
}

func generateSecureToken(prefix string) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

// CreateOrganization creates a new enterprise tenant.
func (im *IdentityManager) CreateOrganization(name, domain string, allowedScopes []string) (models.Organization, error) {
	im.mu.Lock()
	defer im.mu.Unlock()

	name = strings.TrimSpace(name)
	if name == "" {
		return models.Organization{}, fmt.Errorf("organization name is required")
	}
	orgID := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	if _, exists := im.organizations[orgID]; exists {
		orgID = fmt.Sprintf("%s-%d", orgID, time.Now().Unix()%1000)
	}

	org := models.Organization{
		ID:            orgID,
		Name:          name,
		Domain:        domain,
		Status:        "active",
		AllowedScopes: allowedScopes,
		CreatedAt:     time.Now().UTC(),
	}
	im.organizations[orgID] = org
	im.recordAuditLocked("system", orgID, "organization", "create", true, "organization created")
	return org, nil
}

// GetOrganization returns an organization by ID.
func (im *IdentityManager) GetOrganization(orgID string) (models.Organization, error) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	org, ok := im.organizations[orgID]
	if !ok {
		return models.Organization{}, ErrOrganizationNotFound
	}
	return org, nil
}

// CreateTeam creates a team within an organization.
func (im *IdentityManager) CreateTeam(orgID, name, description string) (models.Team, error) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if _, ok := im.organizations[orgID]; !ok {
		return models.Team{}, ErrOrganizationNotFound
	}
	teamID := generateSecureToken("team")
	team := models.Team{
		ID:          teamID,
		OrgID:       orgID,
		Name:        name,
		Description: description,
		CreatedAt:   time.Now().UTC(),
	}
	im.teams[teamID] = team
	im.recordAuditLocked("system", orgID, teamID, "create_team", true, "team created")
	return team, nil
}

// CreateUser registers a new user under an organization.
func (im *IdentityManager) CreateUser(orgID, email, name, role, provider string) (models.User, error) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if _, ok := im.organizations[orgID]; !ok {
		return models.User{}, ErrOrganizationNotFound
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return models.User{}, fmt.Errorf("valid email required")
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role != "admin" && role != "analyst" && role != "viewer" {
		role = "viewer"
	}
	if provider == "" {
		provider = "local"
	}

	userID := generateSecureToken("usr")
	user := models.User{
		ID:           userID,
		OrgID:        orgID,
		Email:        email,
		Name:         name,
		Role:         role,
		AuthProvider: provider,
		Status:       "active",
		CreatedAt:    time.Now().UTC(),
	}
	im.users[userID] = user
	im.recordAuditLocked(email, orgID, userID, "create_user", true, "user registered")
	return user, nil
}

// CreateSession issues a secure session token for a user.
func (im *IdentityManager) CreateSession(user models.User, duration time.Duration) (models.Session, error) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if duration <= 0 {
		duration = 24 * time.Hour
	}
	sessionToken := generateSecureToken("sess")
	session := models.Session{
		ID:        generateSecureToken("sid"),
		Token:     sessionToken,
		UserID:    user.ID,
		OrgID:     user.OrgID,
		Role:      user.Role,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(duration),
		Revoked:   false,
	}
	im.sessions[sessionToken] = session
	im.recordAuditLocked(user.Email, user.OrgID, session.ID, "login", true, "session created")
	return session, nil
}

// ValidateSession verifies a session token and returns the session and user.
func (im *IdentityManager) ValidateSession(token string) (models.Session, models.User, error) {
	im.mu.RLock()
	defer im.mu.RUnlock()

	session, ok := im.sessions[token]
	if !ok || session.Revoked || time.Now().UTC().After(session.ExpiresAt) {
		return models.Session{}, models.User{}, ErrInvalidSession
	}
	user, ok := im.users[session.UserID]
	if !ok || user.Status != "active" {
		return models.Session{}, models.User{}, ErrUserNotFound
	}
	return session, user, nil
}

// RevokeSession terminates an active session.
func (im *IdentityManager) RevokeSession(token string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	session, ok := im.sessions[token]
	if !ok {
		return ErrInvalidSession
	}
	session.Revoked = true
	im.sessions[token] = session
	im.recordAuditLocked(session.UserID, session.OrgID, session.ID, "logout", true, "session revoked")
	return nil
}

// ValidateOIDCClaims processes and validates claims from an OIDC token exchange.
func (im *IdentityManager) ValidateOIDCClaims(claims models.OIDCClaims, expectedIssuer, expectedAudience string) (models.User, error) {
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return models.User{}, fmt.Errorf("%w: issuer mismatch", ErrInvalidOIDCClaims)
	}
	if expectedAudience != "" && claims.Audience != expectedAudience {
		return models.User{}, fmt.Errorf("%w: audience mismatch", ErrInvalidOIDCClaims)
	}
	if claims.Expiration > 0 && time.Now().UTC().Unix() > claims.Expiration {
		return models.User{}, fmt.Errorf("%w: token expired", ErrInvalidOIDCClaims)
	}
	if claims.Email == "" || claims.TenantID == "" {
		return models.User{}, fmt.Errorf("%w: email and tenant_id claims are required", ErrInvalidOIDCClaims)
	}

	role := "analyst"
	for _, r := range claims.Roles {
		if strings.ToLower(r) == "admin" {
			role = "admin"
			break
		}
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	// Find existing user or provision JIT (Just-In-Time) user
	for _, u := range im.users {
		if u.Email == claims.Email && u.OrgID == claims.TenantID {
			im.recordAuditLocked(claims.Email, claims.TenantID, u.ID, "sso_oidc", true, "OIDC SSO login")
			return u, nil
		}
	}

	// JIT provision user under the tenant
	if _, ok := im.organizations[claims.TenantID]; !ok {
		// Auto-provision tenant if valid
		im.organizations[claims.TenantID] = models.Organization{
			ID:        claims.TenantID,
			Name:      claims.TenantID,
			Status:    "active",
			CreatedAt: time.Now().UTC(),
		}
	}

	userID := generateSecureToken("usr_oidc")
	name := claims.Name
	if name == "" {
		name = claims.Email
	}
	user := models.User{
		ID:           userID,
		OrgID:        claims.TenantID,
		Email:        claims.Email,
		Name:         name,
		Role:         role,
		AuthProvider: "oidc",
		Status:       "active",
		CreatedAt:    time.Now().UTC(),
	}
	im.users[userID] = user
	im.recordAuditLocked(claims.Email, claims.TenantID, userID, "sso_oidc", true, "JIT user provisioned via OIDC")
	return user, nil
}

// ValidateSAMLAssertion validates SAML assertion attributes and returns an authenticated user.
func (im *IdentityManager) ValidateSAMLAssertion(attrs models.SAMLAttributes) (models.User, error) {
	if attrs.Email == "" || attrs.OrgID == "" {
		return models.User{}, fmt.Errorf("%w: email and org_id are required", ErrInvalidSAMLAssertion)
	}
	role := strings.ToLower(attrs.Role)
	if role != "admin" && role != "analyst" && role != "viewer" {
		role = "analyst"
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	for _, u := range im.users {
		if u.Email == attrs.Email && u.OrgID == attrs.OrgID {
			im.recordAuditLocked(attrs.Email, attrs.OrgID, u.ID, "sso_saml", true, "SAML SSO login")
			return u, nil
		}
	}

	if _, ok := im.organizations[attrs.OrgID]; !ok {
		im.organizations[attrs.OrgID] = models.Organization{
			ID:        attrs.OrgID,
			Name:      attrs.OrgID,
			Status:    "active",
			CreatedAt: time.Now().UTC(),
		}
	}

	userID := generateSecureToken("usr_saml")
	user := models.User{
		ID:           userID,
		OrgID:        attrs.OrgID,
		Email:        attrs.Email,
		Name:         attrs.Email,
		Role:         role,
		AuthProvider: "saml",
		Status:       "active",
		CreatedAt:    time.Now().UTC(),
	}
	im.users[userID] = user
	im.recordAuditLocked(attrs.Email, attrs.OrgID, userID, "sso_saml", true, "JIT user provisioned via SAML")
	return user, nil
}

// EnforceTenantIsolation checks that an actor tenant matches the target resource tenant.
func (im *IdentityManager) EnforceTenantIsolation(actorTenantID, resourceTenantID string) error {
	if actorTenantID == "" || resourceTenantID == "" {
		return nil // Non-tenanted or global resource
	}
	if actorTenantID != resourceTenantID {
		im.mu.Lock()
		im.recordAuditLocked(actorTenantID, resourceTenantID, "tenant_resource", "access", false, "Tenant isolation violation attempt")
		im.mu.Unlock()
		return ErrTenantMismatch
	}
	return nil
}

func (im *IdentityManager) recordAuditLocked(actor, tenantID, targetResource, action string, success bool, reason string) {
	event := models.IdentityAuditEvent{
		ID:             generateSecureToken("aud"),
		Timestamp:      time.Now().UTC(),
		EventType:      action,
		Actor:          actor,
		TenantID:       tenantID,
		TargetResource: targetResource,
		Action:         action,
		Success:        success,
		Reason:         reason,
	}
	im.auditLogs = append(im.auditLogs, event)
	if len(im.auditLogs) > 1000 {
		im.auditLogs = im.auditLogs[len(im.auditLogs)-1000:]
	}
}

// AuditLogs returns recorded identity and tenant audit events.
func (im *IdentityManager) AuditLogs(tenantID string, limit int) []models.IdentityAuditEvent {
	im.mu.RLock()
	defer im.mu.RUnlock()

	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []models.IdentityAuditEvent
	for i := len(im.auditLogs) - 1; i >= 0 && len(out) < limit; i-- {
		entry := im.auditLogs[i]
		if tenantID == "" || entry.TenantID == tenantID {
			out = append(out, entry)
		}
	}
	return out
}

// TenantContextMiddleware attaches tenant context and validates cross-tenant boundaries.
func (im *IdentityManager) TenantContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqTenant := r.Header.Get("X-Tenant-ID")

		// Check for Session Token in Authorization: Bearer sess_...
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer sess_") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			session, _, err := im.ValidateSession(token)
			if err == nil {
				if reqTenant != "" && reqTenant != session.OrgID {
					http.Error(w, `{"error":"forbidden: cross-tenant access violation"}`, http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// SetupIdentityRoutes wires the identity and tenancy REST endpoints.
func (im *IdentityManager) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/identity/organizations", im.handleOrganizations)
	mux.HandleFunc("/api/v1/identity/users", im.handleUsers)
	mux.HandleFunc("/api/v1/identity/sessions", im.handleSessions)
	mux.HandleFunc("/api/v1/identity/sso/oidc", im.handleOIDC)
	mux.HandleFunc("/api/v1/identity/sso/saml", im.handleSAML)
	mux.HandleFunc("/api/v1/identity/audit", im.handleAudit)
}

func (im *IdentityManager) handleOrganizations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Name          string   `json:"name"`
			Domain        string   `json:"domain"`
			AllowedScopes []string `json:"allowed_scopes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		org, err := im.CreateOrganization(req.Name, req.Domain, req.AllowedScopes)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(org)
	case http.MethodGet:
		im.mu.RLock()
		orgs := make([]models.Organization, 0, len(im.organizations))
		for _, org := range im.organizations {
			orgs = append(orgs, org)
		}
		im.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(orgs)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (im *IdentityManager) handleUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		OrgID string `json:"org_id"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	user, err := im.CreateUser(req.OrgID, req.Email, req.Name, req.Role, "local")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(user)
}

func (im *IdentityManager) handleSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodPost:
		var req struct {
			UserID string `json:"user_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		im.mu.RLock()
		user, ok := im.users[req.UserID]
		im.mu.RUnlock()
		if !ok {
			http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
			return
		}
		session, err := im.CreateSession(user, 24*time.Hour)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(session)
	case http.MethodDelete:
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, `{"error":"token parameter is required"}`, http.StatusBadRequest)
			return
		}
		if err := im.RevokeSession(token); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (im *IdentityManager) handleOIDC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var claims models.OIDCClaims
	if err := json.NewDecoder(r.Body).Decode(&claims); err != nil {
		http.Error(w, `{"error":"invalid oidc claims"}`, http.StatusBadRequest)
		return
	}
	user, err := im.ValidateOIDCClaims(claims, "", "")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusUnauthorized)
		return
	}
	session, err := im.CreateSession(user, 12*time.Hour)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(session)
}

func (im *IdentityManager) handleSAML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var attrs models.SAMLAttributes
	if err := json.NewDecoder(r.Body).Decode(&attrs); err != nil {
		http.Error(w, `{"error":"invalid saml attributes"}`, http.StatusBadRequest)
		return
	}
	user, err := im.ValidateSAMLAssertion(attrs)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusUnauthorized)
		return
	}
	session, err := im.CreateSession(user, 8*time.Hour)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(session)
}

func (im *IdentityManager) handleAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tenantID := r.URL.Query().Get("tenant_id")
	logs := im.AuditLogs(tenantID, 50)
	_ = json.NewEncoder(w).Encode(logs)
}
