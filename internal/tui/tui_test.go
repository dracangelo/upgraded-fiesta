package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"enumscan/internal/store"
)

func TestModelRendersPersistedScanAndNavigation(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "tui.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := db.StartScan(context.Background(), "tui-scan"); err != nil {
		t.Fatal(err)
	}
	m := New(db)
	message := m.loadRuns()
	updated, _ := m.Update(message)
	view := updated.(Model).View()
	if !strings.Contains(view, "tui-scan") || !strings.Contains(view, "OPERATOR CONSOLE") {
		t.Fatalf("unexpected view: %s", view)
	}
	updated, _ = updated.(Model).Update(tea.KeyMsg{Type: tea.KeyDown})
	if updated.(Model).selected != 0 {
		t.Fatal("single scan selection should remain stable")
	}
}
