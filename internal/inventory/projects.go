package inventory

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"enumscan/internal/models"
)

type Project struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Scope        []string          `json:"scope"`
	Integrations map[string]bool   `json:"integrations"`
	APIKeys      map[string]string `json:"api_keys"`
	Archived     bool              `json:"archived"`
	CreatedAt    time.Time         `json:"created_at"`
	ScanIDs      []string          `json:"scan_ids"`
}

type ProjectManager struct {
	mu       sync.RWMutex
	projects map[string]*Project
}

func NewProjectManager() *ProjectManager {
	return &ProjectManager{
		projects: make(map[string]*Project),
	}
}

func (p *ProjectManager) CreateProject(id, name string, scope []string) (*Project, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.projects[id]; exists {
		return nil, fmt.Errorf("project ID %q already exists", id)
	}

	proj := &Project{
		ID:           id,
		Name:         name,
		Scope:        scope,
		Integrations: make(map[string]bool),
		APIKeys:      make(map[string]string),
		Archived:     false,
		CreatedAt:    time.Now().UTC(),
		ScanIDs:      make([]string, 0),
	}
	p.projects[id] = proj
	return proj, nil
}

func (p *ProjectManager) GetProject(id string) (*Project, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	proj, exists := p.projects[id]
	if !exists {
		return nil, fmt.Errorf("project ID %q not found", id)
	}
	return proj, nil
}

func (p *ProjectManager) ArchiveProject(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	proj, exists := p.projects[id]
	if !exists {
		return fmt.Errorf("project ID %q not found", id)
	}
	proj.Archived = true
	return nil
}

func (p *ProjectManager) ExportProject(id string) ([]byte, error) {
	proj, err := p.GetProject(id)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(proj, "", "  ")
}

func (p *ProjectManager) ImportProject(data []byte) (*Project, error) {
	var proj Project
	if err := json.Unmarshal(data, &proj); err != nil {
		return nil, fmt.Errorf("invalid project JSON: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.projects[proj.ID] = &proj
	return &proj, nil
}

func FilterFindingsByProject(findings []models.Finding, proj *Project) []models.Finding {
	if proj == nil {
		return findings
	}
	scanMap := make(map[string]bool)
	for _, sid := range proj.ScanIDs {
		scanMap[sid] = true
	}
	var res []models.Finding
	for _, f := range findings {
		if scanMap[f.ScanID] {
			res = append(res, f)
		}
	}
	return res
}
