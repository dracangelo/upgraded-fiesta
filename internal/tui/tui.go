// Package tui provides a lightweight terminal view of persisted enumscan
// activity. It is deliberately read-only: launching the console never starts
// or changes a scan.
package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type runsLoadedMsg struct {
	runs []models.ScanRun
	err  error
}

// Model is kept small so it remains usable over SSH and restricted terminals.
// The selected scan's real persisted counters are shown in the detail pane.
type Model struct {
	db       *store.SQLiteCLI
	runs     []models.ScanRun
	selected int
	err      error
}

func New(db *store.SQLiteCLI) Model { return Model{db: db} }

func (m Model) Init() tea.Cmd { return m.loadRuns }

func (m Model) loadRuns() tea.Msg {
	runs, err := m.db.ScanRuns(context.Background(), 50)
	return runsLoadedMsg{runs: runs, err: err}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch message := msg.(type) {
	case runsLoadedMsg:
		m.runs, m.err = message.runs, message.err
		if m.selected >= len(m.runs) {
			m.selected = max(0, len(m.runs)-1)
		}
		return m, nil
	case tea.KeyMsg:
		switch message.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "r":
			return m, m.loadRuns
		case "up", "k":
			m.selected = max(0, m.selected-1)
		case "down", "j":
			m.selected = min(len(m.runs)-1, m.selected+1)
		}
	}
	return m, nil
}

func (m Model) View() string {
	var out strings.Builder
	out.WriteString("ENUMSCAN  /  OPERATOR CONSOLE\n")
	out.WriteString("read-only scan history  •  ↑↓ select  r refresh  q quit\n\n")
	if m.err != nil {
		fmt.Fprintf(&out, "Unable to load scan history: %v\n", m.err)
		return out.String()
	}
	if len(m.runs) == 0 {
		out.WriteString("No persisted scans in this database yet.\n")
		return out.String()
	}
	out.WriteString("  STATUS       SCAN ID                              ASSETS  FINDINGS  EVENTS\n")
	for index, run := range m.runs {
		marker := " "
		if index == m.selected {
			marker = ">"
		}
		fmt.Fprintf(&out, "%s %-12s %-36s %6d  %8d  %6d\n", marker, run.Status, truncate(run.ScanID, 36), run.AssetCount, run.FindingCount, run.EventCount)
	}
	selected := m.runs[m.selected]
	fmt.Fprintf(&out, "\nSelected: %s\nStarted: %s\n", selected.ScanID, selected.StartedAt.Local().Format("2006-01-02 15:04:05"))
	if selected.Error != "" {
		fmt.Fprintf(&out, "Last error: %s\n", selected.Error)
	}
	return out.String()
}

func Run(db *store.SQLiteCLI) error {
	_, err := tea.NewProgram(New(db), tea.WithAltScreen()).Run()
	return err
}

func truncate(value string, size int) string {
	if len(value) <= size {
		return value
	}
	return value[:size-1] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
