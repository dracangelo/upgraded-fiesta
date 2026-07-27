package store

import (
	"context"
	"fmt"
	"strings"

	"enumscan/internal/models"
)

type Neo4jStore struct {
	uri      string
	username string
	password string
}

func NewNeo4jStore(uri, username, password string) *Neo4jStore {
	return &Neo4jStore{
		uri:      uri,
		username: username,
		password: password,
	}
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
	_ = cypher
	return nil
}

func (n *Neo4jStore) SyncFinding(ctx context.Context, finding models.Finding) error {
	cypher := fmt.Sprintf(
		"MERGE (f:Finding {title: %s, scan_id: %s}) SET f.severity = %s, f.cve = %s MERGE (a:Asset {value: %s}) MERGE (a)-[:HAS_FINDING]->(f)",
		neoQuote(finding.Title), neoQuote(finding.ScanID), neoQuote(finding.Severity), neoQuote(finding.CVE), neoQuote(finding.Asset),
	)
	_ = cypher
	return nil
}

func neoQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}
