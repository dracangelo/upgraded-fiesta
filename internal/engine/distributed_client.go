package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

var ErrNoRemoteJob = errors.New("no remote scan job is available")

type DistributedAgentClient struct {
	agentID string
	baseURL *url.URL
	key     ed25519.PrivateKey
	client  *http.Client
}

func NewDistributedAgentClient(agentID, coordinatorURL, encodedPrivateKey string, client *http.Client) (*DistributedAgentClient, error) {
	endpoint, err := url.Parse(strings.TrimRight(strings.TrimSpace(coordinatorURL), "/"))
	if err != nil || endpoint.Host == "" {
		return nil, fmt.Errorf("invalid coordinator URL")
	}
	if endpoint.Scheme != "https" {
		host := endpoint.Hostname()
		ip := net.ParseIP(host)
		if endpoint.Scheme != "http" || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, fmt.Errorf("distributed coordinator URL must use HTTPS outside loopback development")
		}
	}
	key, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(encodedPrivateKey))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("agent private key must be an unpadded base64-encoded Ed25519 private key")
	}
	if client == nil {
		client = &http.Client{Timeout: 35 * time.Second}
	}
	return &DistributedAgentClient{agentID: agentID, baseURL: endpoint, key: ed25519.PrivateKey(key), client: client}, nil
}

func (c *DistributedAgentClient) Heartbeat(ctx context.Context) error {
	return c.post(ctx, "/api/v1/distributed/agent/heartbeat", nil, nil)
}

func (c *DistributedAgentClient) Lease(ctx context.Context, duration time.Duration) (models.DistributedScanJob, error) {
	var job models.DistributedScanJob
	body, _ := json.Marshal(map[string]int{"lease_seconds": int(duration.Seconds())})
	if err := c.post(ctx, "/api/v1/distributed/agent/lease", body, &job); err != nil {
		return job, err
	}
	return job, nil
}

func (c *DistributedAgentClient) SubmitEvidence(ctx context.Context, evidence models.DistributedEvidence) error {
	body, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	return c.post(ctx, "/api/v1/distributed/agent/evidence", body, nil)
}

func (c *DistributedAgentClient) Complete(ctx context.Context, jobID, status string) error {
	body, _ := json.Marshal(map[string]string{"job_id": jobID, "status": status})
	return c.post(ctx, "/api/v1/distributed/agent/complete", body, nil)
}

func (c *DistributedAgentClient) post(ctx context.Context, path string, body []byte, output any) error {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	message := store.DistributedAgentMessage(http.MethodPost, path, timestamp, nonce, body)
	endpoint := *c.baseURL
	endpoint.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Enumscan-Agent-ID", c.agentID)
	req.Header.Set("X-Enumscan-Timestamp", timestamp)
	req.Header.Set("X-Enumscan-Nonce", nonce)
	req.Header.Set("X-Enumscan-Signature", base64.RawStdEncoding.EncodeToString(ed25519.Sign(c.key, message)))
	response, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("contact distributed coordinator: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return ErrNoRemoteJob
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("distributed coordinator returned %s", response.Status)
	}
	if output != nil {
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output); err != nil {
			return fmt.Errorf("decode distributed coordinator response: %w", err)
		}
	}
	return nil
}
