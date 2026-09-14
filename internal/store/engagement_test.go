package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestEngagementStoreLifecycle(t *testing.T) {
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "engagements.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	eng := models.Engagement{
		ID:               "eng-corp-2026-q3",
		Name:             "Q3 Infrastructure Audit",
		OrgID:            "org-cybercorp",
		OwnerID:          "secops-lead",
		AllowedTargets:   []string{"10.0.0.0/16", "corp.internal"},
		AuthorizationRef: "AUTH-2026-Q3-APPROVED",
		Status:           "planning",
		Tags:             []string{"quarterly", "production"},
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	// 1. Create Engagement
	if err := db.CreateEngagement(ctx, eng); err != nil {
		t.Fatalf("failed to create engagement: %v", err)
	}

	// 2. Retrieve Engagement
	retrieved, err := db.GetEngagement(ctx, "eng-corp-2026-q3")
	if err != nil {
		t.Fatalf("failed to get engagement: %v", err)
	}
	if retrieved.Name != eng.Name || len(retrieved.AllowedTargets) != 2 || retrieved.Status != "planning" {
		t.Fatalf("unexpected retrieved engagement: %#v", retrieved)
	}

	// 3. Update Status
	if err := db.UpdateEngagementStatus(ctx, "eng-corp-2026-q3", "active"); err != nil {
		t.Fatalf("failed to update status: %v", err)
	}
	updated, _ := db.GetEngagement(ctx, "eng-corp-2026-q3")
	if updated.Status != "active" {
		t.Fatalf("expected status active, got %s", updated.Status)
	}

	// 4. Associate Scans
	if err := db.AddScanToEngagement(ctx, "eng-corp-2026-q3", "scan-q3-baseline", "baseline"); err != nil {
		t.Fatalf("failed to add scan: %v", err)
	}
	if err := db.AddScanToEngagement(ctx, "eng-corp-2026-q3", "scan-q3-rescan", "rescan"); err != nil {
		t.Fatalf("failed to add second scan: %v", err)
	}

	scans, err := db.ListEngagementScans(ctx, "eng-corp-2026-q3")
	if err != nil || len(scans) != 2 {
		t.Fatalf("expected 2 engagement scans, got %d (err: %v)", len(scans), err)
	}
	if scans[0].ScanID != "scan-q3-baseline" || scans[1].ScanID != "scan-q3-rescan" {
		t.Fatalf("unexpected scans order: %#v", scans)
	}

	// 5. List Engagements by Org
	list, err := db.ListEngagements(ctx, "org-cybercorp")
	if err != nil || len(list) != 1 {
		t.Fatalf("expected 1 engagement for org-cybercorp, got %d", len(list))
	}
}
