package plugin

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrPluginRevoked           = errors.New("plugin package or version is revoked")
	ErrPublisherNotVerified    = errors.New("plugin publisher is not verified or is untrusted")
	ErrInvalidReviewRating     = errors.New("rating must be between 1 and 5")
	ErrEmptyPluginID           = errors.New("plugin ID cannot be empty")
)

// TrustTier categorizes publisher trustworthiness.
type TrustTier string

const (
	TrustTierUntrusted  TrustTier = "untrusted"
	TrustTierVerified   TrustTier = "verified"
	TrustTierOfficial   TrustTier = "official"
	TrustTierRevoked    TrustTier = "revoked"
)

// PublisherPolicy holds verification status and pinned signing keys for a plugin publisher.
type PublisherPolicy struct {
	PublisherID string    `json:"publisher_id"`
	Name        string    `json:"name"`
	SigningKey  string    `json:"signing_key"` // hex-encoded Ed25519 public key
	Tier        TrustTier `json:"tier"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RevocationEntry documents a revoked plugin or specific version.
type RevocationEntry struct {
	PluginID   string    `json:"plugin_id"`
	Version    string    `json:"version"` // empty means all versions revoked
	Reason     string    `json:"reason"`
	RevokedAt  time.Time `json:"revoked_at"`
	AdvisoryID string    `json:"advisory_id,omitempty"`
}

// CommunityReview records operator or community feedback for a plugin.
type CommunityReview struct {
	PluginID   string    `json:"plugin_id"`
	ReviewerID string    `json:"reviewer_id"`
	Rating     int       `json:"rating"` // 1 - 5
	Comment    string    `json:"comment"`
	CreatedAt  time.Time `json:"created_at"`
}

// PluginReputation aggregates ratings and governance status for a plugin.
type PluginReputation struct {
	PluginID        string    `json:"plugin_id"`
	PublisherTier   TrustTier `json:"publisher_tier"`
	AverageRating   float64   `json:"average_rating"`
	ReviewCount     int       `json:"review_count"`
	IsRevoked       bool      `json:"is_revoked"`
	RevocationCause string    `json:"revocation_cause,omitempty"`
}

// MarketplaceGovernance enforces marketplace trust, revocation lists, and review aggregation.
type MarketplaceGovernance struct {
	mu          sync.RWMutex
	publishers  map[string]PublisherPolicy // publisher_id -> policy
	revocations map[string][]RevocationEntry // plugin_id -> entries
	reviews     map[string][]CommunityReview // plugin_id -> reviews
}

// NewMarketplaceGovernance initializes a governance manager.
func NewMarketplaceGovernance() *MarketplaceGovernance {
	return &MarketplaceGovernance{
		publishers:  make(map[string]PublisherPolicy),
		revocations: make(map[string][]RevocationEntry),
		reviews:     make(map[string][]CommunityReview),
	}
}

// RegisterPublisher adds or updates a publisher trust policy.
func (g *MarketplaceGovernance) RegisterPublisher(p PublisherPolicy) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p.PublisherID = strings.ToLower(strings.TrimSpace(p.PublisherID))
	p.SigningKey = strings.ToLower(strings.TrimSpace(p.SigningKey))
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now().UTC()
	}
	g.publishers[p.PublisherID] = p
}

// RevokePlugin adds an entry to the Certificate/Plugin Revocation List.
func (g *MarketplaceGovernance) RevokePlugin(entry RevocationEntry) {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry.PluginID = strings.ToLower(strings.TrimSpace(entry.PluginID))
	entry.Version = strings.TrimSpace(entry.Version)
	if entry.RevokedAt.IsZero() {
		entry.RevokedAt = time.Now().UTC()
	}
	g.revocations[entry.PluginID] = append(g.revocations[entry.PluginID], entry)
}

// IsRevoked checks whether a specific plugin ID and version are on the revocation list.
func (g *MarketplaceGovernance) IsRevoked(pluginID, version string) (bool, string) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	pluginID = strings.ToLower(strings.TrimSpace(pluginID))
	version = strings.TrimSpace(version)

	entries, exists := g.revocations[pluginID]
	if !exists {
		return false, ""
	}

	for _, entry := range entries {
		// Empty version in revocation means ALL versions are revoked
		if entry.Version == "" || entry.Version == version {
			return true, fmt.Sprintf("revoked: %s (advisory: %s)", entry.Reason, entry.AdvisoryID)
		}
	}
	return false, ""
}

// AddCommunityReview adds a user rating and comment for a plugin.
func (g *MarketplaceGovernance) AddCommunityReview(review CommunityReview) error {
	if strings.TrimSpace(review.PluginID) == "" {
		return ErrEmptyPluginID
	}
	if review.Rating < 1 || review.Rating > 5 {
		return ErrInvalidReviewRating
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	review.PluginID = strings.ToLower(strings.TrimSpace(review.PluginID))
	if review.CreatedAt.IsZero() {
		review.CreatedAt = time.Now().UTC()
	}
	g.reviews[review.PluginID] = append(g.reviews[review.PluginID], review)
	return nil
}

// GetPluginReputation returns aggregate ratings, trust status, and revocation status.
func (g *MarketplaceGovernance) GetPluginReputation(pluginID, publisherID string) PluginReputation {
	g.mu.RLock()
	defer g.mu.RUnlock()

	pluginID = strings.ToLower(strings.TrimSpace(pluginID))
	publisherID = strings.ToLower(strings.TrimSpace(publisherID))

	rep := PluginReputation{
		PluginID:      pluginID,
		PublisherTier: TrustTierUntrusted,
	}

	if pub, ok := g.publishers[publisherID]; ok {
		rep.PublisherTier = pub.Tier
	}

	// Check revocation (for any version)
	if entries, ok := g.revocations[pluginID]; ok && len(entries) > 0 {
		rep.IsRevoked = true
		rep.RevocationCause = entries[0].Reason
	}

	// Compute average review
	if revs, ok := g.reviews[pluginID]; ok && len(revs) > 0 {
		var sum int
		for _, r := range revs {
			sum += r.Rating
		}
		rep.ReviewCount = len(revs)
		rep.AverageRating = float64(sum) / float64(len(revs))
	}

	return rep
}

// ValidateInstallation checks revocation and publisher trust before allowing installation or execution.
func (g *MarketplaceGovernance) ValidateInstallation(pluginID, version, publisherID string, allowCommunity bool) error {
	revoked, reason := g.IsRevoked(pluginID, version)
	if revoked {
		return fmt.Errorf("%w: %s", ErrPluginRevoked, reason)
	}

	g.mu.RLock()
	pub, ok := g.publishers[strings.ToLower(strings.TrimSpace(publisherID))]
	g.mu.RUnlock()

	if !ok {
		if !allowCommunity {
			return fmt.Errorf("%w: publisher %s is unregistered", ErrPublisherNotVerified, publisherID)
		}
		return nil
	}

	if pub.Tier == TrustTierRevoked {
		return fmt.Errorf("%w: publisher %s has been revoked", ErrPublisherNotVerified, publisherID)
	}

	if !allowCommunity && pub.Tier != TrustTierOfficial && pub.Tier != TrustTierVerified {
		return fmt.Errorf("%w: publisher %s is %s", ErrPublisherNotVerified, publisherID, pub.Tier)
	}

	return nil
}
