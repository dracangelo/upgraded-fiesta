package store

import (
	"context"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
)

func TestTask3ScreenshotInventoryPersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "inventory.sqlite")

	db, err := OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		t.Fatal(err)
	}
	want := models.Asset{
		ScanID:   "task-3",
		Type:     "screenshot",
		Value:    "/approved/screenshots/task-3/home.png",
		Parent:   "https://example.test/",
		Metadata: "sha256=abc123;format=png;width=1280;height=720;renderer=operator_configured",
	}
	if err := db.AddAsset(ctx, want); err != nil {
		db.Close()
		t.Fatal(err)
	}
	// A queued target is not a captured screenshot and must not appear in the
	// persistent screenshot inventory.
	if err := db.AddAsset(ctx, models.Asset{ScanID: "task-3", Type: "screenshot_queue", Value: want.Parent}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.ScreenshotAssets(ctx, "task-3")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one persisted captured screenshot, got %#v", got)
	}
	if got[0].Value != want.Value || got[0].Parent != want.Parent || got[0].Metadata != want.Metadata || got[0].CreatedAt.IsZero() {
		t.Fatalf("persisted screenshot record mismatch: %#v", got[0])
	}
}
