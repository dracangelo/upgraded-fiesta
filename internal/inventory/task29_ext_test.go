package inventory

import (
	"testing"

	"enumscan/internal/models"
)

func TestTask29ProjectsAndWorkspaces(t *testing.T) {
	pm := NewProjectManager()

	// 1. Create project
	proj, err := pm.CreateProject("p1", "Enterprise Alpha", []string{"10.0.0.0/8", "example.com"})
	if err != nil || proj.Name != "Enterprise Alpha" {
		t.Fatalf("failed to create project: %v", err)
	}

	// 2. Per-project keys & integrations
	proj.APIKeys["shodan"] = "key-123"
	proj.Integrations["virustotal"] = true
	proj.ScanIDs = append(proj.ScanIDs, "scan-alpha-1")

	// 3. Filter findings per project
	findings := []models.Finding{
		{ID: 1, ScanID: "scan-alpha-1", Title: "Open Admin Interface"},
		{ID: 2, ScanID: "scan-other-2", Title: "Outdated SSH"},
	}
	filtered := FilterFindingsByProject(findings, proj)
	if len(filtered) != 1 || filtered[0].ID != 1 {
		t.Fatalf("project findings filtering failed")
	}

	// 4. Archive project
	if err := pm.ArchiveProject("p1"); err != nil {
		t.Fatalf("failed to archive project: %v", err)
	}
	if !proj.Archived {
		t.Fatalf("expected project archived flag true")
	}

	// 5. Export and Import project
	exported, err := pm.ExportProject("p1")
	if err != nil {
		t.Fatalf("export project failed: %v", err)
	}
	imported, err := pm.ImportProject(exported)
	if err != nil || imported.ID != "p1" || !imported.Archived {
		t.Fatalf("import project failed: %v", err)
	}
}
