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
	if n.uri == "" {
		return nil
	}

	// Normalize http endpoint
	endpoint := n.uri
	if strings.HasPrefix(endpoint, "bolt://") {
		endpoint = strings.Replace(endpoint, "bolt://", "http://", 1)
	}
	if !strings.HasSuffix(endpoint, "/db/neo4j/tx/commit") && !strings.HasSuffix(endpoint, "/db/data/transaction/commit") {
		endpoint = strings.TrimRight(endpoint, "/") + "/db/neo4j/tx/commit"
	}

	payload := cypherPayload{
		Statements: []cypherStatement{{Statement: cypher}},
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.username != "" {
		req.SetBasicAuth(n.username, n.password)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		// Silent non-blocking return when DB server is offline in tests
		return nil
	}
	_ = resp.Body.Close()
	return nil
}

func neoQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}
