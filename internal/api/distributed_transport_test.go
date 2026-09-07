package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestAuthenticatedDistributedAgentLeaseLifecycle(t *testing.T) {
	ctx := context.Background()
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "coordinator.sqlite"))
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
	if _, err := db.RegisterDistributedAgent(ctx, "agent-remote", base64.RawStdEncoding.EncodeToString(publicKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnqueueDistributedScanJob(ctx, "remote-scan", "AUTH-REMOTE", strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, 8080)

	heartbeat := signedAgentRequest(t, privateKey, "agent-remote", "/api/v1/distributed/agent/heartbeat", "nonce-heartbeat-01", nil)
	heartbeatResponse := httptest.NewRecorder()
	srv.handleDistributedAgentHeartbeat(heartbeatResponse, heartbeat)
	if heartbeatResponse.Code != http.StatusOK {
		t.Fatalf("heartbeat status=%d body=%s", heartbeatResponse.Code, heartbeatResponse.Body.String())
	}

	leaseBody := []byte(`{"lease_seconds":60}`)
	lease := signedAgentRequest(t, privateKey, "agent-remote", "/api/v1/distributed/agent/lease", "nonce-lease-000001", leaseBody)
	leaseResponse := httptest.NewRecorder()
	srv.handleDistributedAgentLease(leaseResponse, lease)
	if leaseResponse.Code != http.StatusOK {
		t.Fatalf("lease status=%d body=%s", leaseResponse.Code, leaseResponse.Body.String())
	}
	var job models.DistributedScanJob
	if err := json.Unmarshal(leaseResponse.Body.Bytes(), &job); err != nil || job.ScanID != "remote-scan" || job.LeaseOwner != "agent-remote" {
		t.Fatalf("unexpected leased job: %#v error=%v", job, err)
	}
	evidenceBody, _ := json.Marshal(models.DistributedEvidence{
		JobID:    job.ID,
		Assets:   []models.Asset{{ScanID: job.ScanID, Type: "host", Value: "192.0.2.10"}},
		Findings: []models.Finding{{ScanID: job.ScanID, Severity: "info", Confidence: "high", Asset: "192.0.2.10", Title: "Remote observation"}},
		Events:   []models.Event{{ScanID: job.ScanID, Type: "target.discovered", Target: "192.0.2.10"}},
	})
	evidence := signedAgentRequest(t, privateKey, "agent-remote", "/api/v1/distributed/agent/evidence", "nonce-evidence-0001", evidenceBody)
	evidenceResponse := httptest.NewRecorder()
	srv.handleDistributedAgentEvidence(evidenceResponse, evidence)
	if evidenceResponse.Code != http.StatusOK {
		t.Fatalf("evidence status=%d body=%s", evidenceResponse.Code, evidenceResponse.Body.String())
	}
	assets, err := db.Assets(ctx, job.ScanID)
	if err != nil || len(assets) != 1 || assets[0].Value != "192.0.2.10" {
		t.Fatalf("coordinator did not persist remote evidence: %#v error=%v", assets, err)
	}

	completeBody, _ := json.Marshal(map[string]string{"job_id": job.ID, "status": "completed"})
	complete := signedAgentRequest(t, privateKey, "agent-remote", "/api/v1/distributed/agent/complete", "nonce-complete-001", completeBody)
	completeResponse := httptest.NewRecorder()
	srv.handleDistributedAgentComplete(completeResponse, complete)
	if completeResponse.Code != http.StatusOK {
		t.Fatalf("complete status=%d body=%s", completeResponse.Code, completeResponse.Body.String())
	}
	status, err := db.GetScanStatus(ctx, job.ScanID)
	if err != nil || status != "completed" {
		t.Fatalf("central scan status=%q error=%v", status, err)
	}
}

func signedAgentRequest(t *testing.T, privateKey ed25519.PrivateKey, agentID, path, nonce string, body []byte) *http.Request {
	t.Helper()
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	message := store.DistributedAgentMessage(http.MethodPost, path, timestamp, nonce, body)
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("X-Enumscan-Agent-ID", agentID)
	request.Header.Set("X-Enumscan-Timestamp", timestamp)
	request.Header.Set("X-Enumscan-Nonce", nonce)
	request.Header.Set("X-Enumscan-Signature", base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, message)))
	return request
}
