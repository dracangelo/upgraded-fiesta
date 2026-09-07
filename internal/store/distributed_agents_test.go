package store

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"
)

func TestDistributedAgentEnrollmentAndHeartbeat(t *testing.T) {
	ctx := context.Background()
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "agents.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	agent, err := db.RegisterDistributedAgent(ctx, "agent-east-1", base64.RawStdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	if agent.Status != "enrolled" || len(agent.PublicKeyFingerprint) != 64 {
		t.Fatalf("unexpected enrolled agent: %#v", agent)
	}
	if err := db.HeartbeatDistributedAgent(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.HeartbeatDistributedAgent(ctx, "unknown-agent"); err == nil {
		t.Fatal("heartbeat must not enroll an unknown agent")
	}
	if _, err := db.RegisterDistributedAgent(ctx, "INVALID!", base64.RawStdEncoding.EncodeToString(key)); err == nil {
		t.Fatal("invalid agent ID must be rejected")
	}
}

func TestDistributedAgentAuthenticationRejectsTamperingAndReplay(t *testing.T) {
	ctx := context.Background()
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "agent-auth.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RegisterDistributedAgent(ctx, "agent-auth", base64.RawStdEncoding.EncodeToString(publicKey)); err != nil {
		t.Fatal(err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "nonce-authentication-1"
	message := DistributedAgentMessage("POST", "/api/v1/distributed/agent/heartbeat", timestamp, nonce, nil)
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	if err := db.AuthenticateDistributedAgent(ctx, "agent-auth", timestamp, nonce, signature, message); err != nil {
		t.Fatalf("valid proof of possession rejected: %v", err)
	}
	if err := db.AuthenticateDistributedAgent(ctx, "agent-auth", timestamp, nonce, signature, message); err == nil {
		t.Fatal("replayed nonce must be rejected")
	}
	tampered := DistributedAgentMessage("POST", "/api/v1/distributed/agent/lease", timestamp, "nonce-authentication-2", []byte(`{"lease_seconds":60}`))
	if err := db.AuthenticateDistributedAgent(ctx, "agent-auth", timestamp, "nonce-authentication-2", signature, tampered); err == nil {
		t.Fatal("signature must not authenticate a different request")
	}
}
