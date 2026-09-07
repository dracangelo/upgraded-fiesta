package modules

import (
	"context"
	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestHistoricalURLImporterUsesOnlyScopedExportedURLs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "urls.txt")
	if err := os.WriteFile(file, []byte("https://api.example.test/v1\nhttps://outside.test/x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenSQLiteCLI(filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	items, err := NewHistoricalURLImporter(db, scope.New([]string{"example.test"}), []string{file}).Handle(context.Background(), models.Event{ScanID: "history", Type: EventTarget, Target: "example.test"})
	if err != nil || len(items) != 1 || items[0].Target != "https://api.example.test/v1" {
		t.Fatalf("unexpected imported URLs: %#v, %v", items, err)
	}
}
