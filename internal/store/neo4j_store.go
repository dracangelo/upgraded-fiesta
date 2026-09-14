package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"enumscan/internal/models"
)

type Neo4jStore struct {
	uri      string
	username string
	password string
	client   *http.Client
}

func NewNeo4jStore(uri, username, password string) *Neo4jStore {
	return &Neo4jStore{
		uri:      uri,
		username: username,
		password: password,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

type cypherStatement struct {
	Statement string `json:"statement"`
}

type cypherPayload struct {
	Statements []cypherStatement `json:"statements"`
}

type cypherResponse struct {
	Results []struct {
		Data []struct {
			Row []any `json:"row"`
		} `json:"data"`
	} `json:"results"`
	Errors []struct{ Code, Message string } `json:"errors"`
}

// SyncScanToNeo4j transfers persisted assets and findings only when invoked by
// an explicit operator command. It does not run as part of enumeration.
func SyncScanToNeo4j(ctx context.Context, local RuntimeStore, remote *Neo4jStore, scanID string) (int, error) {
	if local == nil || remote == nil {
		return 0, fmt.Errorf("local and Neo4j stores are required")
	}
	assets, err := local.Assets(ctx, scanID)
	if err != nil {
		return 0, err
	}
	findings, err := local.Findings(ctx, scanID)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, asset := range assets {
		if err := remote.SyncAsset(ctx, asset); err != nil {
			return count, err
		}
		count++
	}
	for _, finding := range findings {
		if err := remote.SyncFinding(ctx, finding); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (n *Neo4jStore) SyncAsset(ctx context.Context, asset models.Asset) error {
	cypher := fmt.Sprintf(
		"MERGE (a:Asset {value: %s}) SET a.type = %s, a.scan_id = %s",
		neoQuote(asset.Value), neoQuote(asset.Type), neoQuote(asset.ScanID),
	)
	if asset.Parent != "" {
		cypher += fmt.Sprintf(
			" MERGE (p:Asset {value: %s}) MERGE (p)-[:PARENT_OF]->(a)",
			neoQuote(asset.Parent),
		)
	}

	return n.executeCypher(ctx, cypher)
}

func (n *Neo4jStore) SyncFinding(ctx context.Context, finding models.Finding) error {
	cypher := fmt.Sprintf(
		"MERGE (f:Finding {title: %s, scan_id: %s}) SET f.severity = %s, f.cve = %s MERGE (a:Asset {value: %s}) MERGE (a)-[:HAS_FINDING]->(f)",
		neoQuote(finding.Title), neoQuote(finding.ScanID), neoQuote(finding.Severity), neoQuote(finding.CVE), neoQuote(finding.Asset),
	)

	return n.executeCypher(ctx, cypher)
}

func (n *Neo4jStore) executeCypher(ctx context.Context, cypher string) error {
	_, err := n.queryCypher(ctx, cypher)
	return err
}

// LoadScanGraph runs one fixed, scan-scoped read query against a configured
// Neo4j store. No user-supplied Cypher is accepted by this API path.
func (n *Neo4jStore) LoadScanGraph(ctx context.Context, scanID string) (models.AssetGraph, error) {
	cypher := "MATCH (a:Asset {scan_id: " + neoQuote(scanID) + "}) OPTIONAL MATCH (a)-[r]->(b) RETURN a.value, a.type, type(r), b.value, coalesce(b.type, labels(b)[0])"
	response, err := n.queryCypher(ctx, cypher)
	if err != nil {
		return models.AssetGraph{}, err
	}
	nodes := make(map[string]models.GraphNode)
	edges := make([]models.GraphEdge, 0)
	for _, result := range response.Results {
		for _, item := range result.Data {
			if len(item.Row) < 5 {
				continue
			}
			source, _ := item.Row[0].(string)
			sourceType, _ := item.Row[1].(string)
			if source == "" {
				continue
			}
			nodes[source] = models.GraphNode{ID: source, Label: source, Type: sourceType}
			target, _ := item.Row[3].(string)
			if target == "" {
				continue
			}
			targetType, _ := item.Row[4].(string)
			nodes[target] = models.GraphNode{ID: target, Label: target, Type: targetType}
			relation, _ := item.Row[2].(string)
			if relation != "" {
				edges = append(edges, models.GraphEdge{Source: source, Target: target, Relation: relation})
			}
		}
	}
	graph := models.AssetGraph{Nodes: make([]models.GraphNode, 0, len(nodes)), Edges: edges}
	for _, node := range nodes {
		graph.Nodes = append(graph.Nodes, node)
	}
	return graph, nil
}

func (n *Neo4jStore) queryCypher(ctx context.Context, cypher string) (cypherResponse, error) {
	if n.uri == "" {
		return cypherResponse{}, fmt.Errorf("neo4j URI is not configured")
	}
	endpoint := n.uri
	if !strings.HasSuffix(endpoint, "/db/neo4j/tx/commit") && !strings.HasSuffix(endpoint, "/db/data/transaction/commit") {
		endpoint = strings.TrimRight(endpoint, "/") + "/db/neo4j/tx/commit"
	}
	bodyBytes, err := json.Marshal(cypherPayload{Statements: []cypherStatement{{Statement: cypher}}})
	if err != nil {
		return cypherResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return cypherResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.username != "" {
		req.SetBasicAuth(n.username, n.password)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return cypherResponse{}, fmt.Errorf("execute Neo4j Cypher: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return cypherResponse{}, fmt.Errorf("execute Neo4j Cypher: server returned %s", resp.Status)
	}
	var decoded cypherResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return cypherResponse{}, fmt.Errorf("decode Neo4j response: %w", err)
	}
	if len(decoded.Errors) > 0 {
		return cypherResponse{}, fmt.Errorf("Neo4j query error %s: %s", decoded.Errors[0].Code, decoded.Errors[0].Message)
	}
	return decoded, nil
}

func neoQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}
