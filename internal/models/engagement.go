package models

import "time"

// Engagement represents a durable security assessment project above individual scan runs.
type Engagement struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	OrgID            string    `json:"org_id"`
	OwnerID          string    `json:"owner_id"`
	AllowedTargets   []string  `json:"allowed_targets"`
	AuthorizationRef string    `json:"authorization_ref"`
	Status           string    `json:"status"` // "planning", "active", "paused", "completed", "archived"
	Tags             []string  `json:"tags,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// EngagementScan records an association between a durable engagement and an executed scan run.
type EngagementScan struct {
	EngagementID string    `json:"engagement_id"`
	ScanID       string    `json:"scan_id"`
	AddedAt      time.Time `json:"added_at"`
	Phase        string    `json:"phase"` // e.g., "baseline", "rescan", "delta"
}
