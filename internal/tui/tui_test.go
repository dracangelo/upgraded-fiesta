package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestExpandedTUIWorkflows(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "tui_expanded.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	scanID := "tui-corp-scan"
	if err := db.StartScan(context.Background(), scanID); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAsset(context.Background(), models.Asset{
		ScanID:    scanID,
		Type:      "ipv4",
		Value:     "192.168.1.10",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddFinding(context.Background(), models.Finding{
		ScanID:      scanID,
		Severity:    "high",
		Confidence:  "confirmed",
		Asset:       "192.168.1.10",
		Title:       "Exposed Admin Interface",
		Evidence:    "HTTP 200 on /admin",
		Remediation: "Restrict /admin to internal network",
		References:  []string{"CWE-200"},
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	m := New(db)
	loadedMsg := m.loadData()
	updatedModel, _ := m.Update(loadedMsg)
	m = updatedModel.(Model)

	// 1. Verify Scans Tab View
	view := m.View()
	if !strings.Contains(view, scanID) || !strings.Contains(view, "[1] Scans") {
		t.Fatalf("unexpected scans tab view: %s", view)
	}

	// 2. Tab Switch to Assets (key "2")
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")})
	m = updatedModel.(Model)
	if m.activeTab != tabAssets {
		t.Fatalf("expected activeTab tabAssets, got %d", m.activeTab)
	}
	view = m.View()
	if !strings.Contains(view, "192.168.1.10") || !strings.Contains(view, "ipv4") {
		t.Fatalf("expected asset in view: %s", view)
	}

	// 3. Tab Switch to Findings (key "3")
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	m = updatedModel.(Model)
	if m.activeTab != tabFindings {
		t.Fatalf("expected activeTab tabFindings, got %d", m.activeTab)
	}
	view = m.View()
	if !strings.Contains(view, "Exposed Admin Interface") || !strings.Contains(view, "HIGH") {
		t.Fatalf("expected finding in view: %s", view)
	}

	// 4. Detail view toggle (key Enter)
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updatedModel.(Model)
	if !m.showDetail {
		t.Fatal("expected showDetail to be true after Enter")
	}
	view = m.View()
	if !strings.Contains(view, "HTTP 200 on /admin") {
		t.Fatalf("expected evidence details in view: %s", view)
	}

	// 5. Tab Switch to Health (key "4")
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("4")})
	m = updatedModel.(Model)
	if m.activeTab != tabHealth {
		t.Fatalf("expected activeTab tabHealth, got %d", m.activeTab)
	}
	view = m.View()
	if !strings.Contains(view, "HEALTH STATUS") || !strings.Contains(view, "Datastore Connectivity") {
		t.Fatalf("expected health status in view: %s", view)
	}

	// 6. Search filtering on Scans Tab (key "1" then "/")
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1")})
	m = updatedModel.(Model)
	// Enter search mode
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	m = updatedModel.(Model)
	if !m.searchMode {
		t.Fatal("expected searchMode true")
	}
	// Type query "nonexistent"
	for _, ch := range "nonexistent" {
		updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}})
		m = updatedModel.(Model)
	}
	// Press Enter to finish search input
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updatedModel.(Model)
	view = m.View()
	if !strings.Contains(view, "No scan runs found matching current filter") {
		t.Fatalf("expected no scan runs for nonmatching search query: %s", view)
	}

	// Clear filter with Esc
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updatedModel.(Model)
	view = m.View()
	if !strings.Contains(view, scanID) {
		t.Fatalf("expected scanID restored after clearing filter: %s", view)
	}
}
