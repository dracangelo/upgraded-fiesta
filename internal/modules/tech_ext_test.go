package modules

import (
	"context"
	"path/filepath"
	"testing"

	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestTechDetectors(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	guard := scope.New([]string{"example.com", "127.0.0.1"})

	cmsMod := NewCMSEnumerator(db, guard)
	if cmsMod.Name() != "cms_enumerator" {
		t.Errorf("unexpected name: %s", cmsMod.Name())
	}

	fwMod := NewFrameworkEnumerator(db, guard)
	if fwMod.Name() != "framework_enumerator" {
		t.Errorf("unexpected name: %s", fwMod.Name())
	}

	entMod := NewEnterpriseAppEnumerator(db, guard)
	if entMod.Name() != "enterprise_app_enumerator" {
		t.Errorf("unexpected name: %s", entMod.Name())
	}
}
