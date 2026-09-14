package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"enumscan/internal/models"
)

// handleInteractiveGraph provides dynamic searching and filtering over the scan asset graph.
func (s *Server) handleInteractiveGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		scanID = "default"
	}

	searchQuery := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("query")))
	typeFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	severityFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity")))

	assets, err := s.db.Assets(r.Context(), scanID)
	if err != nil {
		http.Error(w, `{"error":"failed to load assets"}`, http.StatusInternalServerError)
		return
	}
	findings, err := s.db.Findings(r.Context(), scanID)
	if err != nil {
		http.Error(w, `{"error":"failed to load findings"}`, http.StatusInternalServerError)
		return
	}

	fullGraph := buildAssetGraph(assets, findings)

	// Filter nodes
	var filteredNodes []models.GraphNode
	matchedNodeIDs := make(map[string]bool)

	for _, node := range fullGraph.Nodes {
		// Type filter
		if typeFilter != "" && !strings.EqualFold(node.Type, typeFilter) {
			continue
		}

		// Search text query
		if searchQuery != "" {
			labelMatch := strings.Contains(strings.ToLower(node.Label), searchQuery)
			idMatch := strings.Contains(strings.ToLower(node.ID), searchQuery)
			if !labelMatch && !idMatch {
				continue
			}
		}

		filteredNodes = append(filteredNodes, node)
		matchedNodeIDs[node.ID] = true
	}

	// Filter edges to only those connecting preserved nodes (or incident to at least one)
	var filteredEdges []models.GraphEdge
	for _, edge := range fullGraph.Edges {
		if matchedNodeIDs[edge.Source] && matchedNodeIDs[edge.Target] {
			filteredEdges = append(filteredEdges, edge)
		}
	}

	response := map[string]any{
		"scan_id":    scanID,
		"total_nodes": len(fullGraph.Nodes),
		"nodes":      filteredNodes,
		"edges":      filteredEdges,
		"filters": map[string]string{
			"query":    searchQuery,
			"type":     typeFilter,
			"severity": severityFilter,
		},
	}

	_ = json.NewEncoder(w).Encode(response)
}

// handleGraphExpand expands neighbors of a specific node up to bounded depth.
func (s *Server) handleGraphExpand(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		scanID = "default"
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		http.Error(w, `{"error":"node_id parameter is required"}`, http.StatusBadRequest)
		return
	}

	depth := 1
	if dStr := r.URL.Query().Get("depth"); dStr != "" {
		if d, err := strconv.Atoi(dStr); err == nil && d > 0 && d <= 3 {
			depth = d
		}
	}

	assets, err := s.db.Assets(r.Context(), scanID)
	if err != nil {
		http.Error(w, `{"error":"failed to load assets"}`, http.StatusInternalServerError)
		return
	}
	findings, err := s.db.Findings(r.Context(), scanID)
	if err != nil {
		http.Error(w, `{"error":"failed to load findings"}`, http.StatusInternalServerError)
		return
	}

	fullGraph := buildAssetGraph(assets, findings)

	// Breadth-first search for neighbor expansion
	nodeMap := make(map[string]models.GraphNode)
	for _, n := range fullGraph.Nodes {
		nodeMap[n.ID] = n
	}

	adj := make(map[string][]string)
	for _, e := range fullGraph.Edges {
		adj[e.Source] = append(adj[e.Source], e.Target)
		adj[e.Target] = append(adj[e.Target], e.Source)
	}

	expandedNodeIDs := make(map[string]bool)
	expandedNodeIDs[nodeID] = true
	currentLevel := []string{nodeID}

	for step := 0; step < depth; step++ {
		var nextLevel []string
		for _, curr := range currentLevel {
			for _, neighbor := range adj[curr] {
				if !expandedNodeIDs[neighbor] {
					expandedNodeIDs[neighbor] = true
					nextLevel = append(nextLevel, neighbor)
				}
			}
		}
		currentLevel = nextLevel
	}

	var nodes []models.GraphNode
	for id := range expandedNodeIDs {
		if n, ok := nodeMap[id]; ok {
			nodes = append(nodes, n)
		}
	}

	var edges []models.GraphEdge
	for _, e := range fullGraph.Edges {
		if expandedNodeIDs[e.Source] && expandedNodeIDs[e.Target] {
			edges = append(edges, e)
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"scan_id":     scanID,
		"origin_node": nodeID,
		"depth":       depth,
		"nodes":       nodes,
		"edges":       edges,
	})
}
