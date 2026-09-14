package models

import "time"

// Organization represents a top-level enterprise tenant.
type Organization struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Domain        string    `json:"domain"`
	Status        string    `json:"status"` // "active", "suspended"
	AllowedScopes []string  `json:"allowed_scopes"`
	CreatedAt     time.Time `json:"created_at"`
}

// Team represents a group within an organization for delegation.
type Team struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// User represents an enterprise operator or stakeholder.
type User struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	TeamIDs      []string  `json:"team_ids,omitempty"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Role         string    `json:"role"`          // "admin", "analyst", "viewer"
	AuthProvider string    `json:"auth_provider"` // "local", "oidc", "saml"
	Status       string    `json:"status"`        // "active", "suspended"
	CreatedAt    time.Time `json:"created_at"`
}

// Session represents an active authenticated token-backed session.
type Session struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	OrgID     string    `json:"org_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// OIDCClaims represents decoded claims from an OpenID Connect identity token.
type OIDCClaims struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   string   `json:"aud"`
	Email      string   `json:"email"`
	Name       string   `json:"name"`
	Groups     []string `json:"groups,omitempty"`
	Roles      []string `json:"roles,omitempty"`
	TenantID   string   `json:"tenant_id,omitempty"`
	Expiration int64    `json:"exp"`
}

// SAMLAttributes represents assertion attributes from a SAML 2.0 Identity Provider.
type SAMLAttributes struct {
	NameID       string `json:"name_id"`
	OrgID        string `json:"org_id"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	SessionIndex string `json:"session_index,omitempty"`
}

// IdentityAuditEvent represents an immutable audit log for authentication and tenant isolation.
type IdentityAuditEvent struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	EventType      string    `json:"event_type"` // "login", "sso_oidc", "sso_saml", "logout", "tenant_violation", "user_created"
	Actor          string    `json:"actor"`
	TenantID       string    `json:"tenant_id"`
	TargetResource string    `json:"target_resource"`
	Action         string    `json:"action"`
	Success        bool      `json:"success"`
	Reason         string    `json:"reason,omitempty"`
	IPAddress      string    `json:"ip_address,omitempty"`
}

// TenantContext holds the validated tenant and user security context for a request.
type TenantContext struct {
	OrgID         string   `json:"org_id"`
	UserID        string   `json:"user_id"`
	Role          string   `json:"role"`
	AllowedScopes []string `json:"allowed_scopes"`
}
