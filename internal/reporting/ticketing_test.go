package reporting

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"enumscan/internal/models"
)

func TestTicketingEvidenceSanitization(t *testing.T) {
	rawEvidence := "Server: Apache/2.4.41\npassword=super_secret_123\napi_key: abc-xyz-987\nHost: 10.0.0.1"
	sanitized := SanitizeEvidenceForTicketing(rawEvidence)

	if strings.Contains(sanitized, "super_secret_123") {
		t.Errorf("SanitizeEvidenceForTicketing leaked raw password: %s", sanitized)
	}
	if strings.Contains(sanitized, "abc-xyz-987") {
		t.Errorf("SanitizeEvidenceForTicketing leaked raw api_key: %s", sanitized)
	}
	if !strings.Contains(sanitized, "password=[REDACTED]") {
		t.Errorf("expected redacted password line, got: %s", sanitized)
	}
	if !strings.Contains(sanitized, "api_key: [REDACTED]") {
		t.Errorf("expected redacted api_key line, got: %s", sanitized)
	}
	if !strings.Contains(sanitized, "Server: Apache/2.4.41") {
		t.Errorf("expected non-sensitive content preserved, got: %s", sanitized)
	}
}

func TestTicketingJiraExport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/rest/api/2/issue" {
			t.Errorf("expected /rest/api/2/issue, got %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			t.Errorf("expected Basic auth header, got %s", auth)
		}

		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed unmarshaling payload: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"10001","key":"SEC-42"}`))
	}))
	defer server.Close()

	cfg := JiraConfig{
		BaseURL:    server.URL,
		UserEmail:  "auditor@example.com",
		APIToken:   "test-token",
		ProjectKey: "SEC",
		IssueType:  "Vulnerability",
	}

	finding := models.Finding{
		ID:          1,
		ScanID:      "scan-1",
		Title:       "Open SSH Default Credential",
		Asset:       "192.168.1.50:22",
		Severity:    "high",
		Confidence:  "confirmed",
		Evidence:    "Banner found\npassword=admin",
		Remediation: "Disable password auth",
		References:  []string{"https://example.com/cve-1"},
	}

	key, err := CreateJiraIssue(context.Background(), cfg, finding, server.Client())
	if err != nil {
		t.Fatalf("CreateJiraIssue failed: %v", err)
	}
	if key != "SEC-42" {
		t.Errorf("expected key SEC-42, got %s", key)
	}

	// Test insecure remote endpoint rejection
	insecureCfg := cfg
	insecureCfg.BaseURL = "http://remote-jira.corp:8080"
	if _, err := CreateJiraIssue(context.Background(), insecureCfg, finding, server.Client()); err != ErrInsecureTicketingURL {
		t.Errorf("expected ErrInsecureTicketingURL for http remote, got %v", err)
	}
}

func TestTicketingGitHubIssueExport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer ghp_secret" {
			t.Errorf("unexpected auth header: %s", auth)
		}

		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"number":108,"html_url":"https://github.com/org/repo/issues/108"}`))
	}))
	defer server.Close()

	cfg := GitHubIssueConfig{
		BaseURL:   server.URL,
		RepoOwner: "org",
		RepoName:  "repo",
		Token:     "ghp_secret",
		Labels:    []string{"triage"},
	}

	finding := models.Finding{
		ID:          2,
		ScanID:      "scan-2",
		Title:       "Exposed Admin Panel",
		Asset:       "admin.example.com",
		Severity:    "medium",
		Confidence:  "high",
		Evidence:    "HTTP 200 OK\ntoken=abcdef12345",
		Remediation: "Restrict access",
	}

	num, htmlURL, err := CreateGitHubIssue(context.Background(), cfg, finding, server.Client())
	if err != nil {
		t.Fatalf("CreateGitHubIssue failed: %v", err)
	}
	if num != 108 {
		t.Errorf("expected issue number 108, got %d", num)
	}
	if !strings.Contains(htmlURL, "issues/108") {
		t.Errorf("unexpected htmlURL: %s", htmlURL)
	}
}

func TestTicketingNormalizedPayload(t *testing.T) {
	f := models.Finding{
		ID:          99,
		ScanID:      "scan-99",
		Title:       "Test Vuln",
		Severity:    "CRITICAL",
		Confidence:  "high",
		Asset:       "10.0.0.5",
		CVE:         "CVE-2026-0001",
		CWE:         "CWE-79",
		CVSS:        9.8,
		EPSS:        0.95,
		Evidence:    "secret=leaked",
		Remediation: "Patch immediately",
	}

	payload := NormalizedTicketingPayload(f, "enumscan-production")
	if payload["source"] != "enumscan-production" {
		t.Errorf("expected source enumscan-production, got %v", payload["source"])
	}
	if payload["severity"] != "critical" {
		t.Errorf("expected lowercase severity critical, got %v", payload["severity"])
	}
	if strings.Contains(payload["evidence"].(string), "leaked") {
		t.Errorf("evidence was not sanitized: %v", payload["evidence"])
	}
}
