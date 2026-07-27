package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"enumscan/internal/models"
)

type InventoryStore struct {
	mu           sync.RWMutex
	assets       map[string]*models.InventoryAsset
	services     map[string]*models.ServiceRecord
	technologies map[string]*models.TechnologyRecord
	certificates map[string]*models.CertificateRecord
	secrets      map[string]*models.SecretRecord
	screenshots  map[string]*models.ScreenshotRecord
	edges        []models.GraphEdge
}

func NewInventoryStore() *InventoryStore {
	return &InventoryStore{
		assets:       make(map[string]*models.InventoryAsset),
		services:     make(map[string]*models.ServiceRecord),
		technologies: make(map[string]*models.TechnologyRecord),
		certificates: make(map[string]*models.CertificateRecord),
		secrets:      make(map[string]*models.SecretRecord),
		screenshots:  make(map[string]*models.ScreenshotRecord),
		edges:        make([]models.GraphEdge, 0),
	}
}

func (s *InventoryStore) UpsertAsset(ctx context.Context, assetType, value, parent, owner string, tags []string) *models.InventoryAsset {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	existing, found := s.assets[value]
	if found {
		existing.LastSeen = now
		existing.ScanCount++
		if owner != "" {
			existing.Owner = owner
		}
		if len(tags) > 0 {
			existing.Tags = append(existing.Tags, tags...)
		}
		return existing
	}

	newItem := &models.InventoryAsset{
		ID:        int64(len(s.assets) + 1),
		Type:      assetType,
		Value:     value,
		Parent:    parent,
		Owner:     owner,
		Tags:      tags,
		ScanCount: 1,
		FirstSeen: now,
		LastSeen:  now,
	}
	s.assets[value] = newItem

	if parent != "" {
		s.edges = append(s.edges, models.GraphEdge{
			Source:   parent,
			Target:   value,
			Relation: "PARENT_OF",
		})
	}
	return newItem
}

func (s *InventoryStore) AddService(ctx context.Context, rec models.ServiceRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%d", rec.Asset, rec.Port)
	now := time.Now()
	if existing, found := s.services[key]; found {
		existing.LastSeen = now
		existing.Banner = rec.Banner
		existing.CPE = rec.CPE
	} else {
		rec.ID = int64(len(s.services) + 1)
		rec.FirstSeen = now
		rec.LastSeen = now
		s.services[key] = &rec
		s.edges = append(s.edges, models.GraphEdge{
			Source:   rec.Asset,
			Target:   key,
			Relation: "RUNS_SERVICE",
		})
	}
}

func (s *InventoryStore) AddTechnology(ctx context.Context, rec models.TechnologyRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%s", rec.Asset, rec.Product)
	now := time.Now()
	if existing, found := s.technologies[key]; found {
		existing.LastSeen = now
		existing.Version = rec.Version
	} else {
		rec.ID = int64(len(s.technologies) + 1)
		rec.FirstSeen = now
		rec.LastSeen = now
		s.technologies[key] = &rec
		s.edges = append(s.edges, models.GraphEdge{
			Source:   rec.Asset,
			Target:   rec.Product,
			Relation: "USES_TECH",
		})
	}
}

func (s *InventoryStore) AddCertificate(ctx context.Context, rec models.CertificateRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := rec.Fingerprint
	if key == "" {
		key = rec.Asset
	}
	rec.ID = int64(len(s.certificates) + 1)
	rec.FirstSeen = time.Now()
	s.certificates[key] = &rec
	s.edges = append(s.edges, models.GraphEdge{
		Source:   rec.Asset,
		Target:   key,
		Relation: "HAS_CERT",
	})
}

func (s *InventoryStore) AddSecret(ctx context.Context, rec models.SecretRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%s:%s", rec.Asset, rec.Type, rec.Snippet)
	rec.ID = int64(len(s.secrets) + 1)
	rec.FirstSeen = time.Now()
	s.secrets[key] = &rec
	s.edges = append(s.edges, models.GraphEdge{
		Source:   rec.Asset,
		Target:   key,
		Relation: "HAS_SECRET",
	})
}

func (s *InventoryStore) AddScreenshot(ctx context.Context, rec models.ScreenshotRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec.ID = int64(len(s.screenshots) + 1)
	rec.CreatedAt = time.Now()
	s.screenshots[rec.Asset] = &rec
}

func (s *InventoryStore) GetAssets() []models.InventoryAsset {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]models.InventoryAsset, 0, len(s.assets))
	for _, a := range s.assets {
		res = append(res, *a)
	}
	return res
}

func (s *InventoryStore) GetGraph() models.AssetGraph {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nodesMap := make(map[string]models.GraphNode)
	for val, a := range s.assets {
		nodesMap[val] = models.GraphNode{ID: val, Label: val, Type: a.Type}
	}

	nodes := make([]models.GraphNode, 0, len(nodesMap))
	for _, n := range nodesMap {
		nodes = append(nodes, n)
	}

	return models.AssetGraph{
		Nodes: nodes,
		Edges: s.edges,
	}
}
