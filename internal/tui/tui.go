// Package tui provides a rich terminal view of persisted enumscan
// activity. It is deliberately read-only: launching the console never starts
// or changes a scan.
package tui

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type tabIndex int

const (
	tabScans tabIndex = iota
	tabAssets
	tabFindings
	tabHealth
)

type dataLoadedMsg struct {
	runs      []models.ScanRun
	assets    []models.Asset
	findings  []models.Finding
	dbHealthy bool
	dbError   string
	err       error
}

// Model provides an interactive multi-tab operator console over SSH or terminal.
type Model struct {
	db              store.RuntimeStore
	activeTab       tabIndex
	runs            []models.ScanRun
	selectedRun     int
	assets          []models.Asset
	selectedAsset   int
	findings        []models.Finding
	selectedFinding int

	searchMode  bool
	searchQuery string
	showDetail  bool

	dbHealthy      bool
	dbError        string
	healthLoadedAt time.Time
	err            error
}

// New creates a read-only operator console model.
func New(db store.RuntimeStore) Model {
	return Model{
		db:        db,
		activeTab: tabScans,
	}
}

func (m Model) Init() tea.Cmd {
	return m.loadData
}

func (m Model) loadData() tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	runs, err := m.db.ScanRuns(ctx, 50)
	if err != nil {
		return dataLoadedMsg{err: err}
	}

	var assets []models.Asset
	var findings []models.Finding
	if len(runs) > 0 {
		targetScanID := runs[0].ScanID
		if m.selectedRun >= 0 && m.selectedRun < len(runs) {
			targetScanID = runs[m.selectedRun].ScanID
		}
		assets, _ = m.db.Assets(ctx, targetScanID)
		findings, _ = m.db.Findings(ctx, targetScanID)
	}

	dbHealthy := true
	dbErrStr := ""
	if pingErr := m.db.Ping(ctx); pingErr != nil {
		dbHealthy = false
		dbErrStr = pingErr.Error()
	}

	return dataLoadedMsg{
		runs:      runs,
		assets:    assets,
		findings:  findings,
		dbHealthy: dbHealthy,
		dbError:   dbErrStr,
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch message := msg.(type) {
	case dataLoadedMsg:
		m.err = message.err
		if message.err == nil {
			m.runs = message.runs
			m.assets = message.assets
			m.findings = message.findings
			m.dbHealthy = message.dbHealthy
			m.dbError = message.dbError
			m.healthLoadedAt = time.Now()
			if m.selectedRun >= len(m.runs) {
				m.selectedRun = max(0, len(m.runs)-1)
			}
			if m.selectedAsset >= len(m.assets) {
				m.selectedAsset = max(0, len(m.assets)-1)
			}
			if m.selectedFinding >= len(m.findings) {
				m.selectedFinding = max(0, len(m.findings)-1)
			}
		}
		return m, nil

	case tea.KeyMsg:
		if m.searchMode {
			switch message.String() {
			case "esc", "enter":
				m.searchMode = false
				return m, nil
			case "backspace":
				if len(m.searchQuery) > 0 {
					m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
				}
				return m, nil
			default:
				if len(message.String()) == 1 {
					m.searchQuery += message.String()
				}
				return m, nil
			}
		}

		switch message.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.showDetail {
				m.showDetail = false
				return m, nil
			}
			if m.searchQuery != "" {
				m.searchQuery = ""
				return m, nil
			}
			return m, tea.Quit
		case "r":
			return m, m.loadData
		case "tab":
			m.activeTab = (m.activeTab + 1) % 4
			m.showDetail = false
			return m, nil
		case "shift+tab":
			m.activeTab = (m.activeTab + 3) % 4
			m.showDetail = false
			return m, nil
		case "1":
			m.activeTab = tabScans
			m.showDetail = false
			return m, nil
		case "2":
			m.activeTab = tabAssets
			m.showDetail = false
			return m, nil
		case "3":
			m.activeTab = tabFindings
			m.showDetail = false
			return m, nil
		case "4":
			m.activeTab = tabHealth
			m.showDetail = false
			return m, nil
		case "/":
			m.searchMode = true
			return m, nil
		case "enter":
			m.showDetail = !m.showDetail
			return m, nil
		case "up", "k":
			m.moveSelection(-1)
			return m, nil
		case "down", "j":
			m.moveSelection(1)
			return m, nil
		}
	}
	return m, nil
}

func (m *Model) moveSelection(delta int) {
	switch m.activeTab {
	case tabScans:
		filtered := m.filteredRuns()
		if len(filtered) > 0 {
			m.selectedRun = clamp(m.selectedRun+delta, 0, len(filtered)-1)
		}
	case tabAssets:
		filtered := m.filteredAssets()
		if len(filtered) > 0 {
			m.selectedAsset = clamp(m.selectedAsset+delta, 0, len(filtered)-1)
		}
	case tabFindings:
		filtered := m.filteredFindings()
		if len(filtered) > 0 {
			m.selectedFinding = clamp(m.selectedFinding+delta, 0, len(filtered)-1)
		}
	}
}

func (m Model) filteredRuns() []models.ScanRun {
	if m.searchQuery == "" {
		return m.runs
	}
	query := strings.ToLower(m.searchQuery)
	var out []models.ScanRun
	for _, r := range m.runs {
		if strings.Contains(strings.ToLower(r.ScanID), query) || strings.Contains(strings.ToLower(r.Status), query) {
			out = append(out, r)
		}
	}
	return out
}

func (m Model) filteredAssets() []models.Asset {
	if m.searchQuery == "" {
		return m.assets
	}
	query := strings.ToLower(m.searchQuery)
	var out []models.Asset
	for _, a := range m.assets {
		if strings.Contains(strings.ToLower(a.Value), query) || strings.Contains(strings.ToLower(a.Type), query) {
			out = append(out, a)
		}
	}
	return out
}

func (m Model) filteredFindings() []models.Finding {
	if m.searchQuery == "" {
		return m.findings
	}
	query := strings.ToLower(m.searchQuery)
	var out []models.Finding
	for _, f := range m.findings {
		if strings.Contains(strings.ToLower(f.Title), query) || strings.Contains(strings.ToLower(f.Severity), query) || strings.Contains(strings.ToLower(f.Asset), query) {
			out = append(out, f)
		}
	}
	return out
}

func (m Model) View() string {
	var out strings.Builder
	out.WriteString("================================================================================\n")
	out.WriteString(" ENUMSCAN OPERATOR CONSOLE — READ-ONLY OBSERVABILITY\n")
	out.WriteString("================================================================================\n")

	// Tabs Header
	tabs := []string{"[1] Scans", "[2] Assets", "[3] Findings", "[4] Health"}
	for i, t := range tabs {
		if tabIndex(i) == m.activeTab {
			fmt.Fprintf(&out, " >> %s << ", t)
		} else {
			fmt.Fprintf(&out, "    %s    ", t)
		}
	}
	out.WriteString("\n--------------------------------------------------------------------------------\n")

	if m.searchMode {
		fmt.Fprintf(&out, "SEARCH: %s_\n", m.searchQuery)
	} else if m.searchQuery != "" {
		fmt.Fprintf(&out, "Active Filter: %q (press esc to clear)\n", m.searchQuery)
	}

	if m.err != nil {
		fmt.Fprintf(&out, "Error loading data: %v\n", m.err)
		return out.String()
	}

	switch m.activeTab {
	case tabScans:
		m.renderScansTab(&out)
	case tabAssets:
		m.renderAssetsTab(&out)
	case tabFindings:
		m.renderFindingsTab(&out)
	case tabHealth:
		m.renderHealthTab(&out)
	}

	out.WriteString("\n--------------------------------------------------------------------------------\n")
	out.WriteString("Tab: switch tab • ↑↓/jk: navigate • /: filter • Enter: details • r: refresh • q: quit\n")
	return out.String()
}

func (m Model) renderScansTab(out *strings.Builder) {
	runs := m.filteredRuns()
	if len(runs) == 0 {
		out.WriteString("No scan runs found matching current filter.\n")
		return
	}
	out.WriteString("  STATUS       SCAN ID                              ASSETS  FINDINGS  EVENTS\n")
	for i, r := range runs {
		marker := " "
		if i == m.selectedRun {
			marker = ">"
		}
		fmt.Fprintf(out, "%s %-12s %-36s %6d  %8d  %6d\n", marker, r.Status, truncate(r.ScanID, 36), r.AssetCount, r.FindingCount, r.EventCount)
	}
	if m.selectedRun < len(runs) {
		sel := runs[m.selectedRun]
		fmt.Fprintf(out, "\n[Selected Scan: %s]\n", sel.ScanID)
		fmt.Fprintf(out, "Started: %s", sel.StartedAt.Local().Format("2006-01-02 15:04:05"))
		if sel.FinishedAt != nil && !sel.FinishedAt.IsZero() {
			fmt.Fprintf(out, " • Finished: %s (Duration: %s)", sel.FinishedAt.Local().Format("15:04:05"), sel.FinishedAt.Sub(sel.StartedAt).Round(time.Second))
		}
		out.WriteString("\n")
		if sel.Error != "" {
			fmt.Fprintf(out, "Last Error: %s\n", sel.Error)
		}
		if m.showDetail {
			out.WriteString("\n--- Scan Configuration & Details ---\n")
			fmt.Fprintf(out, "Status: %s\nTotal Assets: %d\nTotal Findings: %d\nTotal Events: %d\n", sel.Status, sel.AssetCount, sel.FindingCount, sel.EventCount)
		}
	}
}

func (m Model) renderAssetsTab(out *strings.Builder) {
	assets := m.filteredAssets()
	if len(assets) == 0 {
		out.WriteString("No assets recorded for selected scan.\n")
		return
	}
	out.WriteString("  TYPE         VALUE                                          CREATED\n")
	for i, a := range assets {
		marker := " "
		if i == m.selectedAsset {
			marker = ">"
		}
		fmt.Fprintf(out, "%s %-12s %-46s %s\n", marker, a.Type, truncate(a.Value, 46), a.CreatedAt.Local().Format("15:04:05"))
	}
	if m.selectedAsset < len(assets) {
		sel := assets[m.selectedAsset]
		fmt.Fprintf(out, "\n[Selected Asset: %s (%s)]\n", sel.Value, sel.Type)
		if m.showDetail {
			fmt.Fprintf(out, "Scan ID:   %s\nParent:    %s\nCreated:   %s\nMetadata:  %s\n", sel.ScanID, sel.Parent, sel.CreatedAt.Format(time.RFC3339), sel.Metadata)
		}
	}
}

func (m Model) renderFindingsTab(out *strings.Builder) {
	findings := m.filteredFindings()
	if len(findings) == 0 {
		out.WriteString("No findings recorded for selected scan.\n")
		return
	}
	out.WriteString("  SEVERITY  AFFECTED ASSET                  TITLE\n")
	for i, f := range findings {
		marker := " "
		if i == m.selectedFinding {
			marker = ">"
		}
		fmt.Fprintf(out, "%s %-9s %-31s %s\n", marker, strings.ToUpper(f.Severity), truncate(f.Asset, 31), truncate(f.Title, 35))
	}
	if m.selectedFinding < len(findings) {
		sel := findings[m.selectedFinding]
		fmt.Fprintf(out, "\n[Selected Finding: %s - %s]\n", sel.Severity, sel.Title)
		if m.showDetail {
			fmt.Fprintf(out, "Asset:        %s\nConfidence:   %s\nEvidence:     %s\nRemediation:  %s\n", sel.Asset, sel.Confidence, sel.Evidence, sel.Remediation)
			if sel.CWE != "" {
				fmt.Fprintf(out, "CWE:          %s\n", sel.CWE)
			}
			if len(sel.References) > 0 {
				fmt.Fprintf(out, "References:   %s\n", strings.Join(sel.References, ", "))
			}
		}
	}
}

func (m Model) renderHealthTab(out *strings.Builder) {
	var mStats runtime.MemStats
	runtime.ReadMemStats(&mStats)

	out.WriteString("SYSTEM & STORAGE HEALTH STATUS\n\n")
	dbStatus := "[OK] HEALTHY"
	if !m.dbHealthy {
		dbStatus = fmt.Sprintf("[FAIL] %s", m.dbError)
	}
	fmt.Fprintf(out, "  Datastore Connectivity:  %s\n", dbStatus)
	fmt.Fprintf(out, "  Persisted Scans Loaded:  %d\n", len(m.runs))
	fmt.Fprintf(out, "  Active Assets in View:   %d\n", len(m.assets))
	fmt.Fprintf(out, "  Active Findings in View: %d\n", len(m.findings))
	fmt.Fprintf(out, "  Go Runtime Version:      %s\n", runtime.Version())
	fmt.Fprintf(out, "  Active Goroutines:       %d\n", runtime.NumGoroutine())
	fmt.Fprintf(out, "  Allocated Memory:        %.2f MB\n", float64(mStats.Alloc)/(1024*1024))
	fmt.Fprintf(out, "  System Memory Reserved:  %.2f MB\n", float64(mStats.Sys)/(1024*1024))
	fmt.Fprintf(out, "  GC Cycles Completed:     %d\n", mStats.NumGC)
	fmt.Fprintf(out, "  Last Health Check:       %s\n", m.healthLoadedAt.Local().Format("2006-01-02 15:04:05"))
}

// Run starts the Bubble Tea event loop in the terminal.
func Run(db store.RuntimeStore) error {
	_, err := tea.NewProgram(New(db), tea.WithAltScreen()).Run()
	return err
}

func truncate(value string, size int) string {
	if len(value) <= size {
		return value
	}
	return value[:size-1] + "…"
}

func clamp(val, minVal, maxVal int) int {
	if val < minVal {
		return minVal
	}
	if val > maxVal {
		return maxVal
	}
	return val
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
