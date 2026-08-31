package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"enumscan/internal/models"
)

type ChainOfCustodyLogger struct {
	mu       sync.Mutex
	db       *SQLiteCLI
	lastHash string
}

func NewChainOfCustodyLogger(db *SQLiteCLI) *ChainOfCustodyLogger {
	return &ChainOfCustodyLogger{
		db:       db,
		lastHash: "GENESIS_HASH_00000000000000000000000000000000000000000000000000000000",
	}
}

func (c *ChainOfCustodyLogger) RecordEvidence(ctx context.Context, scanID, assetValue, evidenceType, rawData string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s", c.lastHash, timestamp, scanID, assetValue, evidenceType, rawData)
	hashBytes := sha256.Sum256([]byte(payload))
	currentHash := fmt.Sprintf("%x", hashBytes)

	metadata := fmt.Sprintf("prev_hash=%s;current_hash=%s;timestamp=%s;type=%s",
		c.lastHash, currentHash, timestamp, evidenceType)

	err := c.db.AddAsset(ctx, models.Asset{
		ScanID:   scanID,
		Type:     "chain_of_custody_record",
		Value:    assetValue,
		Metadata: metadata,
	})
	if err != nil {
		return "", err
	}

	c.lastHash = currentHash
	return currentHash, nil
}
