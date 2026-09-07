package engine

import (
	"context"
	"path/filepath"
	"testing"

	"enumscan/internal/config"
	"enumscan/internal/store"
)

func TestRunRejectsMissingWrittenAuthorization(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "scan.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Scan.Targets = []string{"127.0.0.1"}
	cfg.Scope.AllowedTargets = []string{"127.0.0.1"}
	if err := New(cfg, db).Run(context.Background(), "unauthorized"); err == nil {
		t.Fatal("scan without a written authorization reference was accepted")
	}
}
