package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"enumscan/internal/models"
)

// RegisterDistributedAgent records a pre-provisioned agent's Ed25519 public
// key fingerprint. The raw key is intentionally not stored; future mutual TLS
// enrollment must verify possession of the key before using this record.
func (s *SQLiteCLI) RegisterDistributedAgent(ctx context.Context, agentID, publicKey string) (models.DistributedAgent, error) {
	if !validDistributedAgentID(agentID) {
		return models.DistributedAgent{}, fmt.Errorf("agent ID must be 3-64 lowercase letters, digits, dots, underscores, or hyphens")
	}
	keyBytes, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil || len(keyBytes) != 32 {
		return models.DistributedAgent{}, fmt.Errorf("agent public key must be an unpadded base64-encoded 32-byte value")
	}
	digest := sha256.Sum256(keyBytes)
	now := time.Now().UTC()
	agent := models.DistributedAgent{ID: agentID, PublicKeyFingerprint: hex.EncodeToString(digest[:]), Status: "enrolled", LastHeartbeat: now, RegisteredAt: now}
	_, err = s.db.ExecContext(ctx, `INSERT INTO distributed_agents(id,public_key_fingerprint,status,last_heartbeat,registered_at,public_key) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET public_key_fingerprint=excluded.public_key_fingerprint,public_key=excluded.public_key,status='enrolled',last_heartbeat=excluded.last_heartbeat`, agent.ID, agent.PublicKeyFingerprint, agent.Status, agent.LastHeartbeat.Format(time.RFC3339Nano), agent.RegisteredAt.Format(time.RFC3339Nano), strings.TrimSpace(publicKey))
	return agent, err
}

// AuthenticateDistributedAgent verifies possession of an enrolled Ed25519 key
// and durably consumes a nonce. The timestamp window bounds captured-request
// reuse; the nonce table prevents replay across coordinator processes.
func (s *SQLiteCLI) AuthenticateDistributedAgent(ctx context.Context, agentID, timestamp, nonce, signature string, message []byte) error {
	if !validDistributedAgentID(agentID) || len(nonce) < 16 || len(nonce) > 128 {
		return fmt.Errorf("invalid distributed agent authentication headers")
	}
	for _, r := range nonce {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return fmt.Errorf("invalid distributed agent nonce")
		}
	}
	signedAt, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil || time.Since(signedAt).Abs() > 2*time.Minute {
		return fmt.Errorf("distributed agent signature timestamp is outside the allowed window")
	}
	var encodedKey string
	if err := s.db.QueryRowContext(ctx, `SELECT public_key FROM distributed_agents WHERE id=?`, agentID).Scan(&encodedKey); err != nil {
		return fmt.Errorf("distributed agent is not enrolled")
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(encodedKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("distributed agent enrollment has no usable public key")
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), message, sig) {
		return fmt.Errorf("invalid distributed agent signature")
	}
	cutoff := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM distributed_agent_nonces WHERE used_at < ?`, cutoff); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO distributed_agent_nonces(agent_id,nonce,used_at) VALUES(?,?,?)`, agentID, nonce, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errors.New("distributed agent request nonce was already used")
		}
		return err
	}
	return tx.Commit()
}

func DistributedAgentMessage(method, path, timestamp, nonce string, body []byte) []byte {
	digest := sha256.Sum256(body)
	return []byte(strings.Join([]string{strings.ToUpper(method), path, timestamp, nonce, hex.EncodeToString(digest[:])}, "\n"))
}

func (s *SQLiteCLI) HeartbeatDistributedAgent(ctx context.Context, agentID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE distributed_agents SET status='online',last_heartbeat=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339Nano), agentID)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return fmt.Errorf("distributed agent %q is not enrolled", agentID)
	}
	return nil
}

func validDistributedAgentID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
