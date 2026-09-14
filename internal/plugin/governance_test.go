package plugin

import (
	"errors"
	"testing"
	"time"
)

func TestMarketplaceGovernanceWorkflows(t *testing.T) {
	gov := NewMarketplaceGovernance()

	// 1. Register publisher policies
	gov.RegisterPublisher(PublisherPolicy{
		PublisherID: "official-team",
		Name:        "Enumscan Core Team",
		SigningKey:  "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
		Tier:        TrustTierOfficial,
	})
	gov.RegisterPublisher(PublisherPolicy{
		PublisherID: "verified-partner",
		Name:        "Verified Sec Corp",
		SigningKey:  "ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000",
		Tier:        TrustTierVerified,
	})
	gov.RegisterPublisher(PublisherPolicy{
		PublisherID: "malicious-actor",
		Name:        "Rogue Labs",
		SigningKey:  "9999000099990000999900009999000099990000999900009999000099990000",
		Tier:        TrustTierRevoked,
	})

	// 2. Validate installation for official and verified publishers
	if err := gov.ValidateInstallation("core-dns", "1.0.0", "official-team", false); err != nil {
		t.Fatalf("expected official plugin to be permitted: %v", err)
	}
	if err := gov.ValidateInstallation("partner-enum", "2.1.0", "verified-partner", false); err != nil {
		t.Fatalf("expected verified partner plugin to be permitted: %v", err)
	}

	// 3. Reject revoked publisher
	if err := gov.ValidateInstallation("bad-tool", "1.0.0", "malicious-actor", true); !errors.Is(err, ErrPublisherNotVerified) {
		t.Fatalf("expected ErrPublisherNotVerified for revoked publisher, got: %v", err)
	}

	// 4. Reject unverified community plugin when allowCommunity is false
	if err := gov.ValidateInstallation("random-tool", "0.1.0", "random-dev", false); !errors.Is(err, ErrPublisherNotVerified) {
		t.Fatalf("expected ErrPublisherNotVerified for unverified publisher in strict mode, got: %v", err)
	}

	// But allow when allowCommunity is true
	if err := gov.ValidateInstallation("random-tool", "0.1.0", "random-dev", true); err != nil {
		t.Fatalf("expected community plugin to pass when allowCommunity=true: %v", err)
	}

	// 5. Revocation testing (CRL)
	gov.RevokePlugin(RevocationEntry{
		PluginID:   "partner-enum",
		Version:    "2.1.0",
		Reason:     "Critical vulnerability discovered",
		RevokedAt:  time.Now(),
		AdvisoryID: "ADV-2026-001",
	})

	// 2.1.0 should now be revoked
	if err := gov.ValidateInstallation("partner-enum", "2.1.0", "verified-partner", false); !errors.Is(err, ErrPluginRevoked) {
		t.Fatalf("expected ErrPluginRevoked for revoked version 2.1.0, got: %v", err)
	}
	// 2.2.0 should still be valid
	if err := gov.ValidateInstallation("partner-enum", "2.2.0", "verified-partner", false); err != nil {
		t.Fatalf("expected version 2.2.0 to be permitted: %v", err)
	}

	// 6. Community ratings and reviews
	if err := gov.AddCommunityReview(CommunityReview{
		PluginID:   "partner-enum",
		ReviewerID: "analyst1",
		Rating:     5,
		Comment:    "Great scanner",
	}); err != nil {
		t.Fatalf("failed adding review: %v", err)
	}
	if err := gov.AddCommunityReview(CommunityReview{
		PluginID:   "partner-enum",
		ReviewerID: "analyst2",
		Rating:     3,
		Comment:    "High memory usage",
	}); err != nil {
		t.Fatalf("failed adding review: %v", err)
	}

	// Invalid rating validation
	if err := gov.AddCommunityReview(CommunityReview{
		PluginID: "partner-enum",
		Rating:   6,
	}); !errors.Is(err, ErrInvalidReviewRating) {
		t.Fatalf("expected ErrInvalidReviewRating for rating 6, got: %v", err)
	}

	rep := gov.GetPluginReputation("partner-enum", "verified-partner")
	if rep.PublisherTier != TrustTierVerified {
		t.Errorf("expected PublisherTierVerified, got %v", rep.PublisherTier)
	}
	if rep.ReviewCount != 2 {
		t.Errorf("expected 2 reviews, got %d", rep.ReviewCount)
	}
	if rep.AverageRating != 4.0 {
		t.Errorf("expected average rating 4.0, got %f", rep.AverageRating)
	}
	if !rep.IsRevoked {
		t.Errorf("expected IsRevoked to be true because of version 2.1.0 revocation entry")
	}
}
