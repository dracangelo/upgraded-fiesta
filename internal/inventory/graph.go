package inventory

import (
	"encoding/json"
	"fmt"
	"strings"

	"enumscan/internal/store"
)

type GraphEngine struct {
	store *store.InventoryStore
}

func NewGraphEngine(invStore *store.InventoryStore) *GraphEngine {
	return &GraphEngine{store: invStore}
}

func (g *GraphEngine) BuildGraphJSON() ([]byte, error) {
	graph := g.store.GetGraph()
	return json.MarshalIndent(graph, "", "  ")
}

func (g *GraphEngine) BuildGraphDOT() string {
	graph := g.store.GetGraph()
	var b strings.Builder

	b.WriteString("digraph AssetRelationshipGraph {\n")
	b.WriteString("  node [shape=box, style=filled, color=lightgray];\n")

	for _, n := range graph.Nodes {
		fmt.Fprintf(&b, "  %q [label=%q];\n", n.ID, fmt.Sprintf("%s (%s)", n.Label, n.Type))
	}

	for _, e := range graph.Edges {
		fmt.Fprintf(&b, "  %q -> %q [label=%q];\n", e.Source, e.Target, e.Relation)
	}

	b.WriteString("}\n")
	return b.String()
}
