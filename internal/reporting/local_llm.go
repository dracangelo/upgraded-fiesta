package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
}

// WriteLocalLLMAdvisory asks an explicitly configured local Ollama endpoint to
// summarize already-redacted, persisted evidence. The result is advisory text,
// not a finding, scanner decision, or assertion of compromise.
func WriteLocalLLMAdvisory(ctx context.Context, db *store.SQLiteCLI, scanID string, cfg models.ReportingConfig) (string, error) {
	endpoint, err := validateLocalLLMEndpoint(cfg.LocalLLMURL)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(cfg.LocalLLMModel) == "" {
		return "", fmt.Errorf("reporting.local_llm_model is required")
	}
	if cfg.LocalLLMTimeoutMS < 1000 || cfg.LocalLLMTimeoutMS > 120000 {
		return "", fmt.Errorf("reporting.local_llm_timeout_ms must be 1000-120000")
	}
	assets, err := db.Assets(ctx, scanID)
	if err != nil {
		return "", err
	}
	findings, err := db.Findings(ctx, scanID)
	if err != nil {
		return "", err
	}
	input := ExecutiveSummary(report{ScanID: scanID, Assets: assets, Findings: findings}) + "\n\n" + TriageReport(report{ScanID: scanID, Assets: assets, Findings: findings})
	if len(input) > 24*1024 {
		input = input[:24*1024]
	}
	prompt := "You are a local security reporting assistant. Use only the supplied evidence. Preserve uncertainty and verification labels. Do not claim compromise, exploitation, or business impact. Do not recommend exploitation, credential attacks, or out-of-scope activity. Produce a concise advisory for an authorized security team.\n\nEVIDENCE:\n" + input
	payload, err := json.Marshal(ollamaRequest{Model: cfg.LocalLLMModel, Prompt: prompt, Stream: false})
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: time.Duration(cfg.LocalLLMTimeoutMS) * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("call local Ollama endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("local Ollama endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return "", err
	}
	var result ollamaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decode local Ollama response: %w", err)
	}
	if strings.TrimSpace(result.Response) == "" {
		return "", fmt.Errorf("local Ollama response contained no advisory text")
	}
	if err := os.MkdirAll(cfg.OutputDir, 0700); err != nil {
		return "", err
	}
	if err := os.Chmod(cfg.OutputDir, 0700); err != nil {
		return "", fmt.Errorf("restrict advisory output directory permissions: %w", err)
	}
	path := filepath.Join(cfg.OutputDir, scanID+"-local-llm.md")
	content := "# Local LLM Advisory: " + scanID + "\n\n> Advisory output from the configured loopback model. It is not independently verified and does not modify scan findings.\n\n" + result.Response + "\n"
	return path, writePrivateFile(path, []byte(content))
}

func validateLocalLLMEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("local LLM endpoint must be an HTTP loopback URL without credentials or fragments")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return "", fmt.Errorf("local LLM endpoint must resolve to localhost or a loopback IP")
	}
	return parsed.String(), nil
}
