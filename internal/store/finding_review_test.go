package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestFindingReviewLifecycleAndAuditTrail(t *testing.T) {
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "finding_review.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	scanID := "scan-review-test"
	if err := db.StartScan(ctx, scanID); err != nil {
		t.Fatal(err)
	}

	finding := models.Finding{
		ScanID:      scanID,
		Severity:    "high",
		Confidence:  "confirmed",
		Asset:       "10.0.0.5",
		Title:       "Vulnerable Service",
		Evidence:    "Version 1.0.0",
		Remediation: "Upgrade to 1.0.1",
		CreatedAt:   time.Now(),
	}
	if err := db.AddFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}

	findings, _ := db.Findings(ctx, scanID)
	if len(findings) == 0 {
		t.Fatal("expected finding to be persisted")
	}
	findingID := findings[0].ID

	// 1. Initial State should be 'open'
	state, assignee, verifier, err := db.FindingReviewState(ctx, findingID)
	if err != nil || state != "open" {
		t.Fatalf("expected initial state 'open', got %s (%v)", state, err)
	}

	// 2. Assign to analyst
	if err := db.AssignFinding(ctx, findingID, "analyst@cybercorp.test", "lead@cybercorp.test"); err != nil {
		t.Fatalf("failed to assign finding: %v", err)
	}
	_, assignee, _, _ = db.FindingReviewState(ctx, findingID)
	if assignee != "analyst@cybercorp.test" {
		t.Fatalf("expected assignee analyst@cybercorp.test, got %s", assignee)
	}

	// 3. Transition to 'in_review'
	if err := db.UpdateFindingReviewState(ctx, findingID, models.FindingStateInReview, "analyst@cybercorp.test", "Starting investigation"); err != nil {
		t.Fatalf("failed transition to in_review: %v", err)
	}

	// 4. Invalid direct transition to 'verified' must be rejected
	if err := db.UpdateFindingReviewState(ctx, findingID, models.FindingStateVerified, "analyst@cybercorp.test", "Attempting skip"); err == nil {
		t.Fatal("expected error on invalid transition in_review -> verified")
	}

	// 5. Transition to 'confirmed' -> 'remediated' -> 'verified'
	if err := db.UpdateFindingReviewState(ctx, findingID, models.FindingStateConfirmed, "analyst@cybercorp.test", "Verified on staging"); err != nil {
		t.Fatalf("failed transition to confirmed: %v", err)
	}
	if err := db.UpdateFindingReviewState(ctx, findingID, models.FindingStateRemediated, "devops@cybercorp.test", "Patched to 1.0.1"); err != nil {
		t.Fatalf("failed transition to remediated: %v", err)
	}
	if err := db.UpdateFindingReviewState(ctx, findingID, models.FindingStateVerified, "lead@cybercorp.test", "Confirmed patch via rescan"); err != nil {
		t.Fatalf("failed transition to verified: %v", err)
	}

	state, _, verifier, _ = db.FindingReviewState(ctx, findingID)
	if state != "verified" || verifier != "lead@cybercorp.test" {
		t.Fatalf("expected verified state with lead verifier, got state=%s verifier=%s", state, verifier)
	}

	// 6. Verify full audit trail
	history, err := db.FindingAuditHistory(ctx, findingID)
	if err != nil {
		t.Fatalf("failed to get audit history: %v", err)
	}
	// Expect 1 assignment + 4 state transitions = 5 audit entries
	if len(history) < 5 {
		t.Fatalf("expected at least 5 audit history entries, got %d", len(history))
	}
}
