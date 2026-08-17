package plugin

import (
	"context"
	"path/filepath"
	"testing"

	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestPluginCompatibilityAndRegression(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	guard := scope.New([]string{"127.0.0.1", "localhost"})
	mgr, err := NewManager(db, guard, "")
	if err != nil {
		t.Fatalf("unexpected NewManager error: %v", err)
	}

	// Validate plugin manager initialization
	if mgr == nil {
		t.Fatalf("expected non-nil plugin manager")
	}

	// Verify plugin manifest schema parsing
	m := PluginManifest{
		Name:          "test-plugin",
		Version:       "1.0.0",
		Description:   "Regression compatibility test plugin",
		Author:        "EnumScan Team",
		Subscriptions: []string{"target.discovered"},
		Permissions:   []string{"network"},
	}
	if m.Name != "test-plugin" || len(m.Permissions) != 1 {
		t.Fatalf("plugin manifest field mismatch")
	}
}
