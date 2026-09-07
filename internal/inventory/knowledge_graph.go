package inventory

import (
	"context"
	"strings"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type KnowledgeGraphOptions struct {
	FilterType string `json:"filter_type,omitempty"`
	Query      string `json:"query,omitempty"`
}

type KnowledgeGraphEngine struct {
	db *store.SQLiteCLI
}

func NewKnowledgeGraphEngine(db *store.SQLiteCLI) *KnowledgeGraphEngine {
	return &KnowledgeGraphEngine{db: db}
}

func (k *KnowledgeGraphEngine) BuildKnowledgeGraph(ctx context.Context, scanID string, opts KnowledgeGraphOptions) (models.AssetGraph, error) {
	assets, err := k.db.Assets(ctx, scanID)
	if err != nil {
		return models.AssetGraph{}, err
	}
	findings, err := k.db.Findings(ctx, scanID)
	if err != nil {
		return models.AssetGraph{}, err
	}

	nodesMap := make(map[string]models.GraphNode)
	var edges []models.GraphEdge

	addNode := func(id, label, typ string) {
		if id != "" {
			if _, exists := nodesMap[id]; !exists {
				nodesMap[id] = models.GraphNode{ID: id, Label: label, Type: typ}
			}
		}
	}

	addEdge := func(src, tgt, rel string) {
		if src != "" && tgt != "" {
			edges = append(edges, models.GraphEdge{Source: src, Target: tgt, Relation: rel})
		}
	}

	// 1. Asset & Host Relationships
	for _, a := range assets {
		val := a.Value
		typ := a.Type

		switch typ {
		case "domain", "subdomain", "ip", "cidr", "host":
			addNode(val, val, "asset")
			if a.Parent != "" {
				addNode(a.Parent, a.Parent, "asset")
				addEdge(a.Parent, val, "CONTAINS")
			}

		case "port", "service", "url":
			addNode(val, val, "service")
			if a.Parent != "" {
				addNode(a.Parent, a.Parent, "asset")
				addEdge(a.Parent, val, "PROVIDES_SERVICE")
			}

		case "technology", "framework":
			addNode("tech:"+val, val, "technology")
			parent := a.Parent
			if parent == "" {
				parent = "global"
			}
			addNode(parent, parent, "asset")
			addEdge(parent, "tech:"+val, "RUNS_TECH")

		case "certificate", "tls":
			addNode("cert:"+val, val, "certificate")
			if a.Parent != "" {
				addNode(a.Parent, a.Parent, "asset")
				addEdge(a.Parent, "cert:"+val, "SECURED_BY_CERT")
			}

		case "secret", "token", "credential":
			addNode("secret:"+val, val, "secret")
			if a.Parent != "" {
				addNode(a.Parent, a.Parent, "asset")
				addEdge(a.Parent, "secret:"+val, "EXPOSES_SECRET")
			}

		case "cloud", "s3", "k8s":
			addNode("cloud:"+val, val, "cloud")
			if a.Parent != "" {
				addNode(a.Parent, a.Parent, "asset")
				addEdge(a.Parent, "cloud:"+val, "HOSTED_ON_CLOUD")
			}

		case "identity", "user", "email":
			addNode("id:"+val, val, "identity")
			if a.Parent != "" {
				addNode(a.Parent, a.Parent, "asset")
				addEdge("id:"+val, a.Parent, "USES_IDENTITY")
			}

		case "trust", "partner":
			addNode("trust:"+val, val, "trust")
			if a.Parent != "" {
				addNode(a.Parent, a.Parent, "asset")
				addEdge(a.Parent, "trust:"+val, "TRUSTS_DOMAIN")
			}

		case "app", "business_app":
			addNode("app:"+val, val, "app")
			if a.Parent != "" {
				addNode(a.Parent, a.Parent, "asset")
				addEdge(a.Parent, "app:"+val, "BELONGS_TO_APP")
			}
		}
	}

	// 2. Vulnerability & Attack Path Relationships
	for _, f := range findings {
		pathID := "path:" + f.Title + "@" + f.Asset
		addNode(f.Asset, f.Asset, "asset")
		addNode(pathID, f.Title, "attack_path")
		addEdge(f.Asset, pathID, "EXPLOITS_PATH")
	}

	// Convert nodes map to slice
	nodes := make([]models.GraphNode, 0, len(nodesMap))
	for _, n := range nodesMap {
		nodes = append(nodes, n)
	}

	fullGraph := models.AssetGraph{Nodes: nodes, Edges: edges}

	if opts.FilterType != "" || opts.Query != "" {
		return k.QueryKnowledgeGraph(fullGraph, opts), nil
	}

	return fullGraph, nil
}

func (k *KnowledgeGraphEngine) QueryKnowledgeGraph(graph models.AssetGraph, opts KnowledgeGraphOptions) models.AssetGraph {
	filterType := strings.ToLower(strings.TrimSpace(opts.FilterType))
	query := strings.ToLower(strings.TrimSpace(opts.Query))

	validNodeIDs := make(map[string]bool)
	var filteredNodes []models.GraphNode

	for _, n := range graph.Nodes {
		matchType := filterType == "" || strings.ToLower(n.Type) == filterType
		matchQuery := query == "" || strings.Contains(strings.ToLower(n.ID), query) || strings.Contains(strings.ToLower(n.Label), query)

		if matchType && matchQuery {
			filteredNodes = append(filteredNodes, n)
			validNodeIDs[n.ID] = true
		}
	}

	var filteredEdges []models.GraphEdge
	for _, e := range graph.Edges {
		if validNodeIDs[e.Source] || validNodeIDs[e.Target] {
			filteredEdges = append(filteredEdges, e)
		}
	}

	return models.AssetGraph{
		Nodes: filteredNodes,
		Edges: filteredEdges,
	}
}
