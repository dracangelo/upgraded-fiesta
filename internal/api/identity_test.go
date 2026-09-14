package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestIdentityOrganizationAndUserLifecycle(t *testing.T) {
	im := NewIdentityManager()

	// 1. Create Organization
	org, err := im.CreateOrganization("CyberCorp Global", "cybercorp.test", []string{"192.168.1.0/24", "corp.internal"})
	if err != nil {
		t.Fatalf("failed to create organization: %v", err)
	}
	if org.ID == "" || org.Name != "CyberCorp Global" {
		t.Fatalf("unexpected organization: %#v", org)
	}

	retrievedOrg, err := im.GetOrganization(org.ID)
	if err != nil || retrievedOrg.ID != org.ID {
		t.Fatalf("failed to retrieve organization: %v", err)
	}

	// 2. Create Team
	team, err := im.CreateTeam(org.ID, "Red Team", "Authorized assessment team")
	if err != nil {
		t.Fatalf("failed to create team: %v", err)
	}
	if team.OrgID != org.ID || team.Name != "Red Team" {
		t.Fatalf("unexpected team: %#v", team)
	}

	// 3. Create Users
	adminUser, err := im.CreateUser(org.ID, "admin@cybercorp.test", "Alice Admin", "admin", "local")
	if err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}
	if adminUser.Role != "admin" || adminUser.OrgID != org.ID {
		t.Fatalf("unexpected user: %#v", adminUser)
	}

	analystUser, err := im.CreateUser(org.ID, "analyst@cybercorp.test", "Bob Analyst", "analyst", "local")
	if err != nil {
		t.Fatalf("failed to create analyst user: %v", err)
	}
	if analystUser.Role != "analyst" {
		t.Fatalf("expected analyst role, got %s", analystUser.Role)
	}

	// 4. Session Lifecycle
	session, err := im.CreateSession(adminUser, 2*time.Hour)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	if session.Token == "" || session.UserID != adminUser.ID {
		t.Fatalf("unexpected session: %#v", session)
	}

	// Validate Session
	validatedSess, validatedUser, err := im.ValidateSession(session.Token)
	if err != nil {
		t.Fatalf("failed to validate session: %v", err)
	}
	if validatedSess.ID != session.ID || validatedUser.ID != adminUser.ID {
		t.Fatalf("session user mismatch: %#v %#v", validatedSess, validatedUser)
	}

	// Revoke Session
	if err := im.RevokeSession(session.Token); err != nil {
		t.Fatalf("failed to revoke session: %v", err)
	}
	if _, _, err := im.ValidateSession(session.Token); err != ErrInvalidSession {
		t.Fatalf("expected ErrInvalidSession after revocation, got %v", err)
	}
}

func TestIdentitySSOOIDCAndSAML(t *testing.T) {
	im := NewIdentityManager()

	// 1. Test OIDC Claims Exchange
	oidcClaims := models.OIDCClaims{
		Issuer:     "https://auth.enterprise.invalid",
		Subject:    "auth0|123456",
		Audience:   "enumscan-app",
		Email:      "secops@enterprise.invalid",
		Name:       "Sarah SecOps",
		Roles:      []string{"admin", "analyst"},
		TenantID:   "enterprise-tenant",
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
	}

	user, err := im.ValidateOIDCClaims(oidcClaims, "https://auth.enterprise.invalid", "enumscan-app")
	if err != nil {
		t.Fatalf("failed to validate OIDC claims: %v", err)
	}
	if user.Email != "secops@enterprise.invalid" || user.OrgID != "enterprise-tenant" || user.Role != "admin" {
		t.Fatalf("unexpected OIDC user: %#v", user)
	}

	// Verify token expiration check
	expiredClaims := oidcClaims
	expiredClaims.Expiration = time.Now().Add(-1 * time.Hour).Unix()
	if _, err := im.ValidateOIDCClaims(expiredClaims, "https://auth.enterprise.invalid", "enumscan-app"); err == nil {
		t.Fatal("expected error for expired OIDC token")
	}

	// 2. Test SAML Assertion Attributes
	samlAttrs := models.SAMLAttributes{
		NameID: "user@partner.invalid",
		OrgID:  "partner-org",
		Email:  "user@partner.invalid",
		Role:   "analyst",
	}

	samlUser, err := im.ValidateSAMLAssertion(samlAttrs)
	if err != nil {
		t.Fatalf("failed to validate SAML assertion: %v", err)
	}
	if samlUser.Email != "user@partner.invalid" || samlUser.OrgID != "partner-org" || samlUser.Role != "analyst" {
		t.Fatalf("unexpected SAML user: %#v", samlUser)
	}
}

func TestTenantIsolationAndAuditControls(t *testing.T) {
	im := NewIdentityManager()

	// Enforce matching tenant succeeds
	if err := im.EnforceTenantIsolation("org-alpha", "org-alpha"); err != nil {
		t.Fatalf("expected tenant match to pass: %v", err)
	}

	// Cross-tenant access attempt must fail and log audit violation
	if err := im.EnforceTenantIsolation("org-alpha", "org-bravo"); err != ErrTenantMismatch {
		t.Fatalf("expected ErrTenantMismatch, got %v", err)
	}

	// Verify audit logs contain the violation
	logs := im.AuditLogs("", 10)
	foundViolation := false
	for _, l := range logs {
		if l.Action == "access" && !l.Success && l.TenantID == "org-bravo" {
			foundViolation = true
			break
		}
	}
	if !foundViolation {
		t.Fatal("expected tenant violation audit record in audit logs")
	}
}

func TestIdentityHTTPEndpoints(t *testing.T) {
	srv := NewServer(nil, 0)
	mux := http.NewServeMux()
	srv.IdentityManager().RegisterRoutes(mux)

	// 1. POST /api/v1/identity/organizations
	orgBody := bytes.NewBufferString(`{"name":"HTTP Test Org","domain":"http.test","allowed_scopes":["10.0.0.0/8"]}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/identity/organizations", orgBody))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}
	var org models.Organization
	if err := json.Unmarshal(rec.Body.Bytes(), &org); err != nil || org.ID == "" {
		t.Fatalf("failed to parse created org: %v", err)
	}

	// 2. POST /api/v1/identity/users
	userBody := bytes.NewBufferString(`{"org_id":"` + org.ID + `","email":"tester@http.test","name":"Tester","role":"analyst"}`)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/identity/users", userBody))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}
	var user models.User
	if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil || user.ID == "" {
		t.Fatalf("failed to parse created user: %v", err)
	}

	// 3. POST /api/v1/identity/sessions
	sessBody := bytes.NewBufferString(`{"user_id":"` + user.ID + `"}`)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/identity/sessions", sessBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	var session models.Session
	if err := json.Unmarshal(rec.Body.Bytes(), &session); err != nil || session.Token == "" {
		t.Fatalf("failed to parse created session: %v", err)
	}

	// 4. GET /api/v1/identity/audit
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/identity/audit", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	var auditLogs []models.IdentityAuditEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &auditLogs); err != nil || len(auditLogs) == 0 {
		t.Fatalf("failed to parse audit logs: %v", err)
	}
}
